/**
 * ClawGuard Trace Engine
 * 
 * Assembles raw events into semantic decision traces —
 * causal chains that show the agent's reasoning path from
 * input to action.
 * 
 * Key capabilities:
 * - Groups events by trace ID into ordered decision chains
 * - Detects known attack patterns (read-then-exfiltrate, memory poisoning, etc.)
 * - Computes anomaly scores by comparing traces against behavioral baselines
 * - Generates human-readable trace summaries
 */

import {
  ClawGuardEvent,
  Trace,
  TraceStatus,
  AttackPattern,
  RiskLevel,
  EventType,
} from "../types/events";

// ─── Known Attack Pattern Definitions ──────────────────────────

const ATTACK_PATTERNS: {
  id: string;
  name: string;
  description: string;
  mitreAtlasId?: string;
  owaspAsiCategory?: string;
  detect: (events: ClawGuardEvent[]) => { matched: boolean; confidence: number; matchingIds: string[] };
}[] = [
  {
    id: "AP-001",
    name: "Read-Then-Exfiltrate",
    description: "Agent reads sensitive data (credentials, files, emails) then sends it to an external endpoint. Primary attack vector for prompt injection.",
    mitreAtlasId: "AML.T0048",
    owaspAsiCategory: "ASI-03: Data Exfiltration",
    detect: (events) => {
      const credReads = events.filter(
        (e) => e.type === "cred_access" || (e.type === "data_read" && e.dataFlow?.containsSensitive)
      );
      const extCalls = events.filter(
        (e) => e.type === "net_call" && e.network?.url && !e.network.url.includes("localhost")
      );

      if (credReads.length > 0 && extCalls.length > 0) {
        // Check if any external call came after a credential read
        const firstRead = credReads[0];
        const postReadCalls = extCalls.filter((e) => e.timestamp > firstRead.timestamp);
        if (postReadCalls.length > 0) {
          return {
            matched: true,
            confidence: 0.92,
            matchingIds: [...credReads.map((e) => e.id), ...postReadCalls.map((e) => e.id)],
          };
        }
      }
      return { matched: false, confidence: 0, matchingIds: [] };
    },
  },
  {
    id: "AP-002",
    name: "Memory Poisoning",
    description: "External content attempts to modify the agent's persistent memory or identity files (MEMORY.md, SOUL.md). Enables long-term agent manipulation.",
    mitreAtlasId: "AML.T0051",
    owaspAsiCategory: "ASI-05: Agent Manipulation",
    detect: (events) => {
      const extInputs = events.filter(
        (e) => e.type === "message_recv" || e.type === "data_read"
      );
      const memWrites = events.filter(
        (e) =>
          e.type === "memory_write" &&
          /soul\.md|memory\.md|identity|persona/i.test(e.detail)
      );

      if (extInputs.length > 0 && memWrites.length > 0) {
        return {
          matched: true,
          confidence: 0.88,
          matchingIds: [...extInputs.map((e) => e.id), ...memWrites.map((e) => e.id)],
        };
      }
      return { matched: false, confidence: 0, matchingIds: [] };
    },
  },
  {
    id: "AP-003",
    name: "Supply Chain Skill Attack",
    description: "A loaded skill from an external marketplace executes privileged operations (shell, file system, network) shortly after installation.",
    mitreAtlasId: "AML.T0042",
    owaspAsiCategory: "ASI-07: Supply Chain",
    detect: (events) => {
      const skillLoads = events.filter((e) => e.type === "skill_load");
      const privilegedOps = events.filter(
        (e) =>
          (e.type === "tool_call" && /shell|exec|sudo/i.test(e.action)) ||
          e.type === "cred_access" ||
          (e.type === "net_call" && e.network?.method === "POST")
      );

      for (const skill of skillLoads) {
        const postSkillOps = privilegedOps.filter((e) => e.timestamp > skill.timestamp);
        if (postSkillOps.length > 0) {
          return {
            matched: true,
            confidence: 0.85,
            matchingIds: [skill.id, ...postSkillOps.map((e) => e.id)],
          };
        }
      }
      return { matched: false, confidence: 0, matchingIds: [] };
    },
  },
  {
    id: "AP-004",
    name: "Prompt Injection via Content",
    description: "Agent processes external content (email, webpage, message) that contains instruction-like patterns, followed by unexpected privileged actions.",
    owaspAsiCategory: "ASI-01: Prompt Injection",
    detect: (events) => {
      const contentReads = events.filter(
        (e) =>
          e.type === "data_read" &&
          /email|web|message|moltbook/i.test(e.detail)
      );
      const unexpectedActions = events.filter(
        (e) =>
          e.risk >= RiskLevel.HIGH &&
          (e.type === "tool_call" || e.type === "net_call" || e.type === "cred_access")
      );

      if (contentReads.length > 0 && unexpectedActions.length > 0) {
        return {
          matched: true,
          confidence: 0.78,
          matchingIds: [...contentReads.map((e) => e.id), ...unexpectedActions.map((e) => e.id)],
        };
      }
      return { matched: false, confidence: 0, matchingIds: [] };
    },
  },
  {
    id: "AP-005",
    name: "Lateral Movement via OAuth",
    description: "Agent uses OAuth tokens to access additional services beyond its original scope, potentially spreading compromise across connected systems.",
    owaspAsiCategory: "ASI-04: Privilege Escalation",
    detect: (events) => {
      const authEvents = events.filter((e) => e.type === "auth_event");
      const multiServiceCalls = events.filter(
        (e) => e.type === "tool_call" || e.type === "net_call"
      );

      const services = new Set(multiServiceCalls.map((e) => {
        const match = e.action.match(/^(\w+)\./);
        return match ? match[1] : e.action;
      }));

      if (authEvents.length > 0 && services.size > 3) {
        return {
          matched: true,
          confidence: 0.72,
          matchingIds: [...authEvents.map((e) => e.id), ...multiServiceCalls.slice(0, 5).map((e) => e.id)],
        };
      }
      return { matched: false, confidence: 0, matchingIds: [] };
    },
  },
];

// ─── Trace Engine ──────────────────────────────────────────────

export class TraceEngine {
  private activeTraces: Map<string, ClawGuardEvent[]> = new Map();
  private completedTraces: Map<string, Trace> = new Map();
  private traceTimeout: number; // ms before a trace is considered complete

  /** Callbacks for trace status changes */
  private onTraceComplete?: (trace: Trace) => void;
  private onAlert?: (trace: Trace, patterns: AttackPattern[]) => void;

  constructor(opts: {
    traceTimeoutMs?: number;
    onTraceComplete?: (trace: Trace) => void;
    onAlert?: (trace: Trace, patterns: AttackPattern[]) => void;
  } = {}) {
    this.traceTimeout = opts.traceTimeoutMs || 30000;
    this.onTraceComplete = opts.onTraceComplete;
    this.onAlert = opts.onAlert;
  }

  /** Process a new event — add to active trace or start new one */
  processEvent(event: ClawGuardEvent): void {
    const traceId = event.traceId;

    if (!this.activeTraces.has(traceId)) {
      this.activeTraces.set(traceId, []);
    }

    this.activeTraces.get(traceId)!.push(event);

    // Check for immediate high-risk patterns on each event
    if (event.risk >= RiskLevel.CRITICAL) {
      this.evaluateTrace(traceId);
    }
  }

  /** Evaluate a trace for attack patterns and compute anomaly score */
  evaluateTrace(traceId: string): Trace | null {
    const events = this.activeTraces.get(traceId);
    if (!events || events.length === 0) return null;

    // Detect attack patterns
    const detectedPatterns: AttackPattern[] = [];
    for (const patternDef of ATTACK_PATTERNS) {
      const result = patternDef.detect(events);
      if (result.matched) {
        detectedPatterns.push({
          patternId: patternDef.id,
          name: patternDef.name,
          description: patternDef.description,
          confidence: result.confidence,
          mitreAtlasId: patternDef.mitreAtlasId,
          owaspAsiCategory: patternDef.owaspAsiCategory,
          matchingEventIds: result.matchingIds,
        });
      }
    }

    // Compute anomaly score
    const maxEventRisk = Math.max(...events.map((e) => e.risk));
    const avgRisk = events.reduce((sum, e) => sum + e.risk, 0) / events.length;
    const patternBoost = detectedPatterns.reduce((max, p) => Math.max(max, p.confidence), 0);
    const anomalyScore = Math.min(1, (avgRisk / 5) * 0.3 + (maxEventRisk / 5) * 0.3 + patternBoost * 0.4);

    // Determine status
    let status: TraceStatus = "clean";
    if (anomalyScore >= 0.8 || detectedPatterns.length > 0) {
      status = "critical";
    } else if (anomalyScore >= 0.3) {
      status = "warning";
    }

    // Build trace
    const trace: Trace = {
      id: traceId,
      agentId: events[0].agentId,
      startTime: events[0].timestamp,
      endTime: events[events.length - 1].timestamp,
      status,
      anomalyScore: Math.round(anomalyScore * 100) / 100,
      summary: this.generateSummary(events, detectedPatterns),
      eventIds: events.map((e) => e.id),
      attackPatterns: detectedPatterns.length > 0 ? detectedPatterns : undefined,
      trigger: {
        type: this.inferTriggerType(events[0]),
        source: events[0].detail.slice(0, 100),
      },
    };

    // Store completed trace
    this.completedTraces.set(traceId, trace);

    // Fire callbacks
    if (this.onTraceComplete) {
      this.onTraceComplete(trace);
    }
    if (status === "critical" && detectedPatterns.length > 0 && this.onAlert) {
      this.onAlert(trace, detectedPatterns);
    }

    return trace;
  }

  /** Finalize and close a trace */
  finalizeTrace(traceId: string): Trace | null {
    const trace = this.evaluateTrace(traceId);
    this.activeTraces.delete(traceId);
    return trace;
  }

  /** Get all active traces */
  getActiveTraces(): Map<string, ClawGuardEvent[]> {
    return this.activeTraces;
  }

  /** Get a completed trace by ID */
  getTrace(traceId: string): Trace | undefined {
    return this.completedTraces.get(traceId);
  }

  /** Get all completed traces */
  getAllTraces(): Trace[] {
    return Array.from(this.completedTraces.values());
  }

  // ─── Private Helpers ───────────────────────────────────────

  private generateSummary(events: ClawGuardEvent[], patterns: AttackPattern[]): string {
    if (patterns.length > 0) {
      const topPattern = patterns.sort((a, b) => b.confidence - a.confidence)[0];
      return `${topPattern.name}: ${topPattern.description}`;
    }

    const types = events.map((e) => e.type);
    const uniqueTypes = [...new Set(types)];
    const actions = events.map((e) => e.action).slice(0, 3).join(", ");

    if (uniqueTypes.length === 1 && uniqueTypes[0] === "llm_call") {
      return `LLM conversation: ${actions}`;
    }

    return `Agent performed ${events.length} actions: ${actions}${events.length > 3 ? "..." : ""}`;
  }

  private inferTriggerType(firstEvent: ClawGuardEvent): "user_message" | "scheduled" | "webhook" | "skill" | "internal" {
    if (firstEvent.type === "message_recv") return "user_message";
    if (firstEvent.type === "skill_load") return "skill";
    if (/schedule|cron|timer/i.test(firstEvent.detail)) return "scheduled";
    if (/webhook|trigger/i.test(firstEvent.detail)) return "webhook";
    return "internal";
  }
}
