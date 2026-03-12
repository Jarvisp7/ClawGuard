/**
 * ClawGuard Event Collector
 * 
 * Captures agent activity by intercepting gateway events.
 * Designed to work as an OpenClaw plugin that hooks into the
 * gateway's request pipeline.
 * 
 * Architecture:
 * - Intercepts all agent-tool, agent-LLM, and agent-network interactions
 * - Classifies each event by type and assigns initial risk score
 * - Buffers events and flushes to configured outputs
 * - Feeds events to the TraceEngine for decision chain assembly
 */

import { v4 as uuidv4 } from "uuid";
import {
  ClawGuardEvent,
  EventType,
  RiskLevel,
  ClawGuardConfig,
} from "../types/events";

// ─── Sensitive Data Detector ───────────────────────────────────

const DEFAULT_SENSITIVE_PATTERNS = [
  // API keys & tokens
  /(?:api[_-]?key|token|secret|password|credential)\s*[=:]\s*\S+/gi,
  // AWS keys
  /AKIA[0-9A-Z]{16}/g,
  // Generic long hex/base64 secrets
  /(?:sk|pk|rk|ak)[-_][a-zA-Z0-9]{32,}/g,
  // Email addresses
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  // Credit card numbers
  /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
  // SSN
  /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  // Private file paths
  /(?:\.env|\.ssh|id_rsa|\.aws\/credentials|MEMORY\.md|SOUL\.md)/gi,
];

export class SensitiveDataDetector {
  private patterns: RegExp[];

  constructor(customPatterns: string[] = []) {
    this.patterns = [
      ...DEFAULT_SENSITIVE_PATTERNS,
      ...customPatterns.map((p) => new RegExp(p, "gi")),
    ];
  }

  detect(text: string): { found: boolean; labels: string[] } {
    const labels: string[] = [];
    for (const pattern of this.patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(text)) {
        labels.push(pattern.source.slice(0, 30));
      }
    }
    return { found: labels.length > 0, labels };
  }

  redact(text: string): string {
    let redacted = text;
    for (const pattern of this.patterns) {
      pattern.lastIndex = 0;
      redacted = redacted.replace(pattern, "[REDACTED]");
    }
    return redacted;
  }
}

// ─── Risk Scorer ───────────────────────────────────────────────

interface RiskContext {
  type: EventType;
  action: string;
  detail: string;
  hasSensitiveData: boolean;
  isExternalNetwork: boolean;
  isCredentialAccess: boolean;
  isMemoryModification: boolean;
  isSkillFromMarketplace: boolean;
}

export function computeRisk(ctx: RiskContext): { level: RiskLevel; reason: string } {
  // Emergency: credential access + external exfiltration
  if (ctx.isCredentialAccess && ctx.isExternalNetwork) {
    return { level: RiskLevel.EMERGENCY, reason: "Credential access followed by external network call — potential exfiltration" };
  }

  // Critical: memory/identity modification from external source
  if (ctx.isMemoryModification && ctx.type === "memory_write") {
    if (ctx.detail.toLowerCase().includes("soul.md") || ctx.detail.toLowerCase().includes("identity")) {
      return { level: RiskLevel.CRITICAL, reason: "Agent identity file modification detected" };
    }
  }

  // Critical: unknown skill executing shell commands
  if (ctx.isSkillFromMarketplace && ctx.action.includes("shell")) {
    return { level: RiskLevel.CRITICAL, reason: "Marketplace skill executing shell commands" };
  }

  // High: credential access
  if (ctx.isCredentialAccess) {
    return { level: RiskLevel.HIGH, reason: "Credential or secret access detected" };
  }

  // High: sensitive data in external call
  if (ctx.hasSensitiveData && ctx.isExternalNetwork) {
    return { level: RiskLevel.HIGH, reason: "Sensitive data detected in external network call" };
  }

  // Medium: skill load from marketplace
  if (ctx.isSkillFromMarketplace) {
    return { level: RiskLevel.MEDIUM, reason: "Skill loaded from external marketplace" };
  }

  // Medium: sensitive data access
  if (ctx.hasSensitiveData) {
    return { level: RiskLevel.MEDIUM, reason: "Sensitive data accessed" };
  }

  // Low: any external network call
  if (ctx.isExternalNetwork) {
    return { level: RiskLevel.LOW, reason: "External network request" };
  }

  return { level: RiskLevel.NONE, reason: "" };
}

// ─── Event Collector ───────────────────────────────────────────

export type EventHandler = (event: ClawGuardEvent) => void;

export class EventCollector {
  private config: ClawGuardConfig;
  private buffer: ClawGuardEvent[] = [];
  private handlers: EventHandler[] = [];
  private sensitiveDetector: SensitiveDataDetector;
  private flushTimer?: ReturnType<typeof setInterval>;
  private activeTraceId: string = "";

  constructor(config: ClawGuardConfig) {
    this.config = config;
    this.sensitiveDetector = new SensitiveDataDetector(config.sensitivePatterns);
  }

  /** Register an event handler (e.g., TraceEngine, PolicyEngine) */
  onEvent(handler: EventHandler): void {
    this.handlers.push(handler);
  }

  /** Start collecting events */
  start(): void {
    if (this.config.output.remote) {
      const interval = this.config.output.remote.flushIntervalMs || 5000;
      this.flushTimer = setInterval(() => this.flush(), interval);
    }
    this.log("ClawGuard collector started", "info");
  }

  /** Stop collecting and flush remaining events */
  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flush();
    this.log("ClawGuard collector stopped", "info");
  }

  /** Begin a new trace (called when agent starts a new task) */
  beginTrace(trigger: { type: string; source: string }): string {
    this.activeTraceId = `trace-${uuidv4().slice(0, 8)}`;
    return this.activeTraceId;
  }

  /** Capture a raw gateway event and transform it into a ClawGuardEvent */
  capture(raw: {
    type: EventType;
    action: string;
    detail: string;
    payload?: Record<string, unknown>;
    network?: { method: string; url: string; statusCode?: number };
    traceId?: string;
    parentEventId?: string;
  }): ClawGuardEvent {
    // Skip if event type not in capture list
    if (
      this.config.captureTypes.length > 0 &&
      !this.config.captureTypes.includes(raw.type)
    ) {
      return null as unknown as ClawGuardEvent;
    }

    // Detect sensitive data
    const sensitiveCheck = this.sensitiveDetector.detect(
      `${raw.action} ${raw.detail} ${JSON.stringify(raw.payload || {})}`
    );

    // Determine context for risk scoring
    const isExternalNetwork =
      raw.type === "net_call" ||
      (raw.network?.url && !raw.network.url.includes("localhost"));
    const isCredentialAccess =
      raw.type === "cred_access" ||
      /\.env|api.key|token|secret|credential|password/i.test(raw.detail);
    const isMemoryModification =
      raw.type === "memory_write" &&
      /memory\.md|soul\.md|identity/i.test(raw.detail);
    const isSkillFromMarketplace =
      raw.type === "skill_load" && /clawhub|marketplace/i.test(raw.detail);

    // Score risk
    const { level: riskLevel, reason: riskReason } = computeRisk({
      type: raw.type,
      action: raw.action,
      detail: raw.detail,
      hasSensitiveData: sensitiveCheck.found,
      isExternalNetwork: !!isExternalNetwork,
      isCredentialAccess,
      isMemoryModification,
      isSkillFromMarketplace,
    });

    // Build the event
    const event: ClawGuardEvent = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      type: raw.type,
      agentId: this.config.agentId,
      traceId: raw.traceId || this.activeTraceId || `trace-${uuidv4().slice(0, 8)}`,
      parentEventId: raw.parentEventId,
      action: raw.action,
      detail: this.config.captureLlmContent ? raw.detail : this.redactIfLlm(raw.type, raw.detail),
      risk: riskLevel,
      riskReason,
      payload: this.config.captureToolArgs ? raw.payload : undefined,
      dataFlow: sensitiveCheck.found
        ? {
            sources: [raw.action],
            destinations: raw.network?.url ? [raw.network.url] : [],
            containsSensitive: true,
            sensitivityLabels: sensitiveCheck.labels,
          }
        : undefined,
      network: raw.network,
      blocked: false,
    };

    // Buffer and dispatch
    this.buffer.push(event);
    this.handlers.forEach((h) => h(event));

    // Check buffer size
    if (this.buffer.length >= this.config.bufferSize) {
      this.flush();
    }

    // Stdout output
    if (this.config.output.stdout) {
      this.printEvent(event);
    }

    return event;
  }

  /** Flush buffered events to configured outputs */
  private flush(): void {
    if (this.buffer.length === 0) return;

    const events = [...this.buffer];
    this.buffer = [];

    // File output
    if (this.config.output.file) {
      this.writeToFile(events);
    }

    // Remote output
    if (this.config.output.remote) {
      this.sendToRemote(events);
    }
  }

  private writeToFile(events: ClawGuardEvent[]): void {
    // In real implementation: append NDJSON to file with rotation
    const ndjson = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
    // fs.appendFileSync(this.config.output.file!.path, ndjson);
    console.log(`[ClawGuard] Wrote ${events.length} events to file`);
  }

  private async sendToRemote(events: ClawGuardEvent[]): Promise<void> {
    // In real implementation: batch POST to dashboard API
    const remote = this.config.output.remote!;
    try {
      // await fetch(remote.endpoint, {
      //   method: 'POST',
      //   headers: { 'Authorization': `Bearer ${remote.apiKey}`, 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ events }),
      // });
      console.log(`[ClawGuard] Sent ${events.length} events to ${remote.endpoint}`);
    } catch (err) {
      console.error(`[ClawGuard] Failed to send events:`, err);
      // Re-buffer failed events
      this.buffer.unshift(...events);
    }
  }

  private redactIfLlm(type: EventType, detail: string): string {
    if (type === "llm_call") {
      return "[LLM content redacted — enable captureLlmContent to see]";
    }
    return detail;
  }

  private printEvent(event: ClawGuardEvent): void {
    const riskColors: Record<number, string> = {
      0: "\x1b[32m", 1: "\x1b[33m", 2: "\x1b[33m",
      3: "\x1b[31m", 4: "\x1b[91m", 5: "\x1b[41m\x1b[97m",
    };
    const reset = "\x1b[0m";
    const color = riskColors[event.risk] || "";
    const ts = event.timestamp.split("T")[1]?.slice(0, 12) || "";
    const icon = {
      llm_call: "🧠", tool_call: "🔧", data_read: "📄", data_write: "📝",
      cred_access: "🔑", net_call: "🌐", skill_load: "📦", memory_read: "💾",
      memory_write: "💾", message_send: "📤", message_recv: "📥",
      auth_event: "🔐", config_change: "⚙️", error: "❌", alert: "🚨",
    }[event.type] || "•";

    console.log(
      `${color}${icon} [${ts}] [${event.agentId}] ${event.action} — ${event.detail}${event.riskReason ? ` ⚠ ${event.riskReason}` : ""}${reset}`
    );
  }

  private log(message: string, level: string): void {
    const ts = new Date().toISOString();
    console.log(`[ClawGuard:${level}] ${ts} ${message}`);
  }
}
