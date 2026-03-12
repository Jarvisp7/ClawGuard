type EventType =
  | "llm_call" | "tool_call" | "data_read" | "data_write"
  | "cred_access" | "net_call" | "skill_load" | "memory_read"
  | "memory_write" | "message_send" | "message_recv"
  | "auth_event" | "config_change" | "error" | "alert";

interface CapturedEvent {
  type: EventType;
  action: string;
  detail: string;
  timestamp: string;
  agentId: string;
  traceId: string;
  risk: number;
  payload?: Record<string, unknown>;
  network?: { method: string; url: string; statusCode?: number };
}

const SENSITIVE_PATTERNS = [
  /(?:api[_-]?key|token|secret|password|credential)\s*[=:]\s*\S+/gi,
  /AKIA[0-9A-Z]{16}/g,
  /(?:sk|pk)[-_][a-zA-Z0-9]{32,}/g,
  /(?:\.env|\.ssh|id_rsa|\.aws\/credentials|MEMORY\.md|SOUL\.md)/gi,
];

function containsSensitive(text: string): boolean {
  return SENSITIVE_PATTERNS.some(p => { p.lastIndex = 0; return p.test(text); });
}

function computeRisk(event: CapturedEvent): number {
  const detail = event.detail.toLowerCase();
  const action = event.action.toLowerCase();
  if (event.type === "cred_access" && event.network) return 5;
  if (event.type === "memory_write" && /soul\.md|identity/.test(detail)) return 5;
  if (event.type === "tool_call" && /shell|exec/.test(action) && detail.includes("clawhub")) return 4;
  if (event.type === "cred_access") return 3;
  if (event.type === "net_call" && containsSensitive(event.detail)) return 3;
  if (event.type === "skill_load" && /clawhub|marketplace/.test(detail)) return 2;
  if (containsSensitive(event.detail)) return 2;
  if (event.type === "net_call") return 1;
  return 0;
}

interface SequenceRule { name: string; sequence: EventType[]; riskLevel: number; message: string; }

const SEQUENCE_RULES: SequenceRule[] = [
  { name: "Credential Exfiltration", sequence: ["cred_access", "net_call"], riskLevel: 5, message: "CRITICAL: Credential access followed by external network call" },
  { name: "Memory Poisoning", sequence: ["data_read", "memory_write"], riskLevel: 4, message: "WARNING: External data read followed by memory modification" },
  { name: "Supply Chain Attack", sequence: ["skill_load", "cred_access"], riskLevel: 4, message: "WARNING: Skill load followed by credential access" },
];

class SequenceDetector {
  private recentEvents: CapturedEvent[] = [];
  check(event: CapturedEvent): SequenceRule | null {
    this.recentEvents.push(event);
    const cutoff = Date.now() - 60000;
    this.recentEvents = this.recentEvents.filter(e => new Date(e.timestamp).getTime() > cutoff);
    for (const rule of SEQUENCE_RULES) {
      const traceEvents = this.recentEvents.filter(e => e.traceId === event.traceId);
      let seqIdx = 0;
      for (const evt of traceEvents) {
        if (evt.type === rule.sequence[seqIdx]) { seqIdx++; if (seqIdx >= rule.sequence.length) return rule; }
      }
    }
    return null;
  }
}

class EventBuffer {
  private events: CapturedEvent[] = [];
  private outputPath: string;
  constructor(outputPath: string) { this.outputPath = outputPath; }
  add(event: CapturedEvent): void {
    this.events.push(event);
    if (this.events.length >= 50) this.flush();
  }
  flush(): void {
    if (this.events.length === 0) return;
    try {
      const fs = require("fs");
      fs.appendFileSync(this.outputPath, this.events.map(e => JSON.stringify(e)).join("\n") + "\n");
      this.events = [];
    } catch (err) { console.error("[ClawGuard] Write failed:", err); }
  }
  getRecent(count = 50): CapturedEvent[] { return this.events.slice(-count); }
}

const RISK_COLORS: Record<number, string> = { 0: "\x1b[90m", 1: "\x1b[32m", 2: "\x1b[33m", 3: "\x1b[31m", 4: "\x1b[91m", 5: "\x1b[41m\x1b[97m" };
const TYPE_ICONS: Record<string, string> = { llm_call: "🧠", tool_call: "🔧", data_read: "📄", cred_access: "🔑", net_call: "🌐", skill_load: "📦", memory_write: "💾", message_send: "📤", message_recv: "📥", error: "❌", alert: "🚨" };

function printEvent(event: CapturedEvent): void {
  const color = RISK_COLORS[event.risk] || "\x1b[90m";
  const icon = TYPE_ICONS[event.type] || "•";
  const ts = event.timestamp.split("T")[1]?.slice(0, 12) || "";
  const riskTag = event.risk >= 3 ? ` [RISK:${event.risk}]` : "";
  console.log(`${color}${icon} [${ts}] ${event.action} — ${event.detail}${riskTag}\x1b[0m`);
}

let buffer: EventBuffer;
let detector: SequenceDetector;
let traceCounter = 0;
let currentTraceId = "trace-0001";
let verbose = true;

function captureEvent(type: EventType, action: string, detail: string, extra?: Partial<CapturedEvent>): void {
  const event: CapturedEvent = { type, action, detail, timestamp: new Date().toISOString(), agentId: "default", traceId: currentTraceId, risk: 0, ...extra };
  event.risk = computeRisk(event);
  buffer.add(event);
  if (verbose) printEvent(event);
  const matched = detector.check(event);
  if (matched) {
    const alert: CapturedEvent = { type: "alert", action: matched.name, detail: matched.message, timestamp: new Date().toISOString(), agentId: event.agentId, traceId: event.traceId, risk: matched.riskLevel };
    buffer.add(alert);
    if (verbose) printEvent(alert);
  }
}

export default function clawguardPlugin(api: any) {
  buffer = new EventBuffer(api.config?.outputPath ?? "~/.openclaw/clawguard-events.ndjson");
  detector = new SequenceDetector();
  verbose = api.config?.verbose !== false;
  console.log("\x1b[36m◈ ClawGuard v0.1.0 — Runtime Observability Active\x1b[0m");

  api.on("agent:message", (d: any) => { traceCounter++; currentTraceId = `trace-${String(traceCounter).padStart(4,"0")}`; captureEvent("message_recv", "agent.message", `Received: "${String(d?.text||"").slice(0,100)}"`); });
  api.on("llm:request", (d: any) => { captureEvent("llm_call", `llm.request.${d?.provider||"unknown"}`, `Model: ${d?.model||"unknown"}`); });
  api.on("llm:response", (d: any) => { captureEvent("llm_call", `llm.response.${d?.provider||"unknown"}`, `Model: ${d?.model||"unknown"} | Tokens: ${d?.outputTokens||"?"}`); });
  api.on("tool:execute", (d: any) => {
    const tool = d?.tool||d?.name||"unknown", args = JSON.stringify(d?.args||{}).slice(0,200);
    let type: EventType = "tool_call";
    if (/read|file\.read/.test(tool)) type = "data_read";
    if (/fetch|http|curl/.test(tool)) type = "net_call";
    if (/env|secret|key|cred|token/.test(args.toLowerCase())) type = "cred_access";
    captureEvent(type, `tool.${tool}`, `Args: ${args}`, { network: /fetch|http|curl/.test(tool) ? { method: "GET", url: d?.args?.url||"" } : undefined });
  });
  api.on("skill:load", (d: any) => { captureEvent("skill_load", "skill.load", `Skill: ${d?.id||"unknown"} from ${d?.source||"local"}`); });
  api.on("memory:write", (d: any) => { captureEvent("memory_write", "memory.write", `File: ${d?.file||"unknown"}`); });
  api.on("message:send", (d: any) => { captureEvent("message_send", `message.${d?.channel||"unknown"}`, `To: ${d?.recipient||"unknown"}`); });
  api.on("error", (d: any) => { captureEvent("error", "system.error", `${d?.message||"Unknown error"}`); });
  api.on("gateway:shutdown", () => { buffer.flush(); console.log("\x1b[36m◈ ClawGuard — Shutdown.\x1b[0m"); });
}
