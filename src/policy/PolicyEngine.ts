/**
 * ClawGuard Policy Engine
 * 
 * Evaluates events against configurable security policies.
 * Supports sequence detection, threshold alerts, pattern matching,
 * and anomaly-based rules.
 * 
 * Default policies cover the most critical OpenClaw attack vectors
 * documented in OWASP ASI Top 10 and MITRE ATLAS.
 */

import {
  ClawGuardEvent,
  PolicyRule,
  PolicyAction,
  RiskLevel,
  EventType,
} from "../types/events";

// ─── Default Policies ──────────────────────────────────────────

export const DEFAULT_POLICIES: PolicyRule[] = [
  {
    id: "POL-001",
    name: "Credential Exfiltration",
    description: "Alert when credentials are accessed and then sent to an external endpoint within the same trace",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.EMERGENCY,
    condition: {
      type: "sequence",
      sequence: ["cred_access", "net_call"],
    },
  },
  {
    id: "POL-002",
    name: "Identity File Tampering",
    description: "Block any attempt to modify SOUL.md or agent identity configuration",
    enabled: true,
    action: "block",
    riskLevel: RiskLevel.CRITICAL,
    condition: {
      type: "pattern",
      pattern: { field: "detail", match: "SOUL\\.md|identity|persona" },
    },
  },
  {
    id: "POL-003",
    name: "Rapid Credential Access",
    description: "Alert when more than 3 credential accesses occur within 60 seconds",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.HIGH,
    condition: {
      type: "threshold",
      threshold: { eventType: "cred_access", count: 3, windowSeconds: 60 },
    },
  },
  {
    id: "POL-004",
    name: "Marketplace Skill Shell Execution",
    description: "Alert when a skill loaded from ClawHub executes shell commands",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.CRITICAL,
    condition: {
      type: "sequence",
      sequence: ["skill_load", "tool_call"],
    },
  },
  {
    id: "POL-005",
    name: "Sensitive Data to External",
    description: "Alert when sensitive data is detected in outbound network traffic",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.HIGH,
    condition: {
      type: "pattern",
      pattern: { field: "dataFlow.containsSensitive", match: "true" },
    },
  },
  {
    id: "POL-006",
    name: "High Volume Tool Calls",
    description: "Alert when agent makes more than 50 tool calls in 5 minutes (potential runaway agent)",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.MEDIUM,
    condition: {
      type: "threshold",
      threshold: { eventType: "tool_call", count: 50, windowSeconds: 300 },
    },
  },
  {
    id: "POL-007",
    name: "Memory Modification After External Content",
    description: "Alert when agent memory is modified after processing external content (potential prompt injection)",
    enabled: true,
    action: "alert",
    riskLevel: RiskLevel.CRITICAL,
    condition: {
      type: "sequence",
      sequence: ["data_read", "memory_write"],
    },
  },
];

// ─── Policy Evaluation Result ──────────────────────────────────

export interface PolicyViolation {
  policyId: string;
  policyName: string;
  action: PolicyAction;
  riskLevel: RiskLevel;
  description: string;
  matchingEventIds: string[];
  timestamp: string;
}

// ─── Policy Engine ─────────────────────────────────────────────

export class PolicyEngine {
  private policies: PolicyRule[];
  private eventWindow: ClawGuardEvent[] = [];
  private windowDuration: number = 600_000; // 10 minutes
  private violations: PolicyViolation[] = [];

  /** Callback when a policy is violated */
  onViolation?: (violation: PolicyViolation) => void;

  constructor(policies?: PolicyRule[]) {
    this.policies = policies || DEFAULT_POLICIES;
  }

  /** Add a custom policy */
  addPolicy(policy: PolicyRule): void {
    this.policies.push(policy);
  }

  /** Remove a policy by ID */
  removePolicy(policyId: string): void {
    this.policies = this.policies.filter((p) => p.id !== policyId);
  }

  /** Enable/disable a policy */
  togglePolicy(policyId: string, enabled: boolean): void {
    const policy = this.policies.find((p) => p.id === policyId);
    if (policy) policy.enabled = enabled;
  }

  /** Evaluate a new event against all active policies */
  evaluate(event: ClawGuardEvent): PolicyViolation[] {
    // Add to sliding window
    this.eventWindow.push(event);
    this.pruneWindow();

    const newViolations: PolicyViolation[] = [];

    for (const policy of this.policies) {
      if (!policy.enabled) continue;

      const result = this.checkPolicy(policy, event);
      if (result) {
        const violation: PolicyViolation = {
          policyId: policy.id,
          policyName: policy.name,
          action: policy.action,
          riskLevel: policy.riskLevel,
          description: policy.description,
          matchingEventIds: result.matchingIds,
          timestamp: new Date().toISOString(),
        };

        newViolations.push(violation);
        this.violations.push(violation);

        if (this.onViolation) {
          this.onViolation(violation);
        }
      }
    }

    return newViolations;
  }

  /** Get all recorded violations */
  getViolations(): PolicyViolation[] {
    return this.violations;
  }

  /** Get active policies */
  getPolicies(): PolicyRule[] {
    return this.policies;
  }

  // ─── Private: Policy Checking ────────────────────────────

  private checkPolicy(
    policy: PolicyRule,
    currentEvent: ClawGuardEvent
  ): { matchingIds: string[] } | null {
    const condition = policy.condition;

    switch (condition.type) {
      case "sequence":
        return this.checkSequence(condition.sequence!, currentEvent);

      case "threshold":
        return this.checkThreshold(condition.threshold!);

      case "pattern":
        return this.checkPattern(condition.pattern!, currentEvent);

      default:
        return null;
    }
  }

  private checkSequence(
    sequence: EventType[],
    currentEvent: ClawGuardEvent
  ): { matchingIds: string[] } | null {
    // Check if the current event completes a sequence
    if (currentEvent.type !== sequence[sequence.length - 1]) return null;

    // Look backward through the window for the preceding events in order
    const traceEvents = this.eventWindow.filter(
      (e) => e.traceId === currentEvent.traceId
    );

    let seqIndex = 0;
    const matchingIds: string[] = [];

    for (const evt of traceEvents) {
      if (evt.type === sequence[seqIndex]) {
        matchingIds.push(evt.id);
        seqIndex++;
        if (seqIndex >= sequence.length) {
          return { matchingIds };
        }
      }
    }

    return null;
  }

  private checkThreshold(threshold: {
    eventType: EventType;
    count: number;
    windowSeconds: number;
  }): { matchingIds: string[] } | null {
    const cutoff = new Date(Date.now() - threshold.windowSeconds * 1000).toISOString();
    const matching = this.eventWindow.filter(
      (e) => e.type === threshold.eventType && e.timestamp >= cutoff
    );

    if (matching.length >= threshold.count) {
      return { matchingIds: matching.map((e) => e.id) };
    }
    return null;
  }

  private checkPattern(
    pattern: { field: string; match: string },
    event: ClawGuardEvent
  ): { matchingIds: string[] } | null {
    const value = this.getNestedField(event, pattern.field);
    if (value === undefined) return null;

    const regex = new RegExp(pattern.match, "i");
    if (regex.test(String(value))) {
      return { matchingIds: [event.id] };
    }
    return null;
  }

  private getNestedField(obj: Record<string, any>, path: string): any {
    return path.split(".").reduce((current, key) => current?.[key], obj);
  }

  private pruneWindow(): void {
    const cutoff = new Date(Date.now() - this.windowDuration).toISOString();
    this.eventWindow = this.eventWindow.filter((e) => e.timestamp >= cutoff);
  }
}
