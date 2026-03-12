/**
 * ClawGuard Event Schema v0.1.0
 * 
 * Core types for agent activity observability.
 * Every action an agent takes is captured as a ClawGuardEvent.
 * Events are grouped into Traces — causal decision chains.
 */

// ─── Event Types ───────────────────────────────────────────────

export type EventType =
  | "llm_call"        // LLM prompt/response
  | "tool_call"       // Tool invocation (shell, file, API, etc.)
  | "data_read"       // Data access (file read, email parse, etc.)
  | "data_write"      // Data mutation (file write, DB update, etc.)
  | "cred_access"     // Credential/secret access
  | "net_call"        // External network request
  | "skill_load"      // Skill/plugin loaded
  | "memory_read"     // Agent memory read
  | "memory_write"    // Agent memory write/modify
  | "message_send"    // Outbound message (email, Slack, etc.)
  | "message_recv"    // Inbound message received
  | "auth_event"      // Authentication/authorization event
  | "config_change"   // Configuration modification
  | "error"           // Error/exception
  | "alert";          // ClawGuard-generated alert

// ─── Risk Levels ───────────────────────────────────────────────

export enum RiskLevel {
  NONE = 0,       // Normal operation
  LOW = 1,        // Slightly elevated (data access)
  MEDIUM = 2,     // Notable (credential access, confidential file read)
  HIGH = 3,       // Suspicious (credential + external call pattern)
  CRITICAL = 4,   // Active threat indicator
  EMERGENCY = 5,  // Confirmed attack / exfiltration
}

// ─── Core Event ────────────────────────────────────────────────

export interface ClawGuardEvent {
  /** Unique event ID (UUIDv4) */
  id: string;

  /** ISO 8601 timestamp */
  timestamp: string;

  /** Event type classification */
  type: EventType;

  /** Agent identifier */
  agentId: string;

  /** Trace ID — groups events into causal decision chains */
  traceId: string;

  /** Parent event ID (for causal linking within a trace) */
  parentEventId?: string;

  /** The action performed */
  action: string;

  /** Human-readable description */
  detail: string;

  /** Computed risk level */
  risk: RiskLevel;

  /** Risk explanation (why this risk level was assigned) */
  riskReason?: string;

  /** Raw data payload (tool args, LLM prompt snippet, etc.) */
  payload?: Record<string, unknown>;

  /** Data flow metadata */
  dataFlow?: {
    /** What data was accessed */
    sources: string[];
    /** Where data was sent */
    destinations: string[];
    /** Whether sensitive data was involved */
    containsSensitive: boolean;
    /** Sensitivity classifications detected */
    sensitivityLabels?: string[];
  };

  /** Network metadata (for net_call events) */
  network?: {
    method: string;
    url: string;
    statusCode?: number;
    requestSize?: number;
    responseSize?: number;
  };

  /** Duration in milliseconds */
  durationMs?: number;

  /** Whether ClawGuard blocked this action */
  blocked: boolean;

  /** Policy rule that triggered (if any) */
  triggeredPolicy?: string;
}

// ─── Trace ─────────────────────────────────────────────────────

export type TraceStatus = "clean" | "warning" | "critical" | "blocked";

export interface Trace {
  /** Trace ID */
  id: string;

  /** Agent ID */
  agentId: string;

  /** Trace start time */
  startTime: string;

  /** Trace end time (null if ongoing) */
  endTime?: string;

  /** Overall trace status */
  status: TraceStatus;

  /** Anomaly score (0.0 = normal, 1.0 = certain threat) */
  anomalyScore: number;

  /** Human-readable summary */
  summary: string;

  /** Ordered list of event IDs in this trace */
  eventIds: string[];

  /** Detected attack patterns */
  attackPatterns?: AttackPattern[];

  /** Trigger — what initiated this trace */
  trigger: {
    type: "user_message" | "scheduled" | "webhook" | "skill" | "internal";
    source: string;
  };
}

// ─── Attack Patterns ───────────────────────────────────────────

export interface AttackPattern {
  /** Pattern identifier (maps to OWASP ASI / MITRE ATLAS) */
  patternId: string;

  /** Human-readable name */
  name: string;

  /** Description */
  description: string;

  /** Confidence score (0.0 - 1.0) */
  confidence: number;

  /** MITRE ATLAS technique ID (if applicable) */
  mitreAtlasId?: string;

  /** OWASP ASI category (if applicable) */
  owaspAsiCategory?: string;

  /** Event IDs that match this pattern */
  matchingEventIds: string[];
}

// ─── Agent Profile ─────────────────────────────────────────────

export type AgentStatus = "healthy" | "warning" | "compromised" | "offline";

export interface AgentProfile {
  /** Agent identifier */
  id: string;

  /** Display name */
  name: string;

  /** Current status */
  status: AgentStatus;

  /** LLM model in use */
  model: string;

  /** First seen timestamp */
  firstSeen: string;

  /** Last activity timestamp */
  lastActivity: string;

  /** Total events recorded */
  totalEvents: number;

  /** Total alerts generated */
  totalAlerts: number;

  /** Active trace count */
  activeTraces: number;

  /** Loaded skills */
  skills: string[];

  /** Connected services */
  connectedServices: string[];

  /** Behavioral baseline (rolling averages) */
  baseline?: {
    avgEventsPerHour: number;
    avgToolCallsPerTrace: number;
    commonActions: string[];
    typicalDataSources: string[];
    typicalDestinations: string[];
  };
}

// ─── Policy Rule ───────────────────────────────────────────────

export type PolicyAction = "alert" | "block" | "log" | "quarantine";

export interface PolicyRule {
  /** Rule identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Description of what this rule detects */
  description: string;

  /** Whether the rule is active */
  enabled: boolean;

  /** What to do when triggered */
  action: PolicyAction;

  /** Risk level to assign */
  riskLevel: RiskLevel;

  /** Rule condition (simplified DSL) */
  condition: PolicyCondition;
}

export interface PolicyCondition {
  /** Match type */
  type: "sequence" | "threshold" | "pattern" | "anomaly";

  /** For sequence: ordered event types that trigger the rule */
  sequence?: EventType[];

  /** For threshold: count-based triggers */
  threshold?: {
    eventType: EventType;
    count: number;
    windowSeconds: number;
  };

  /** For pattern: regex or keyword match on event details */
  pattern?: {
    field: string;
    match: string;
  };
}

// ─── Config ────────────────────────────────────────────────────

export interface ClawGuardConfig {
  /** Agent ID to monitor */
  agentId: string;

  /** Output mode */
  output: {
    /** Write events to local file */
    file?: { path: string; maxSizeMb: number; rotateCount: number };
    /** Send events to remote ClawGuard dashboard */
    remote?: { endpoint: string; apiKey: string; batchSize: number; flushIntervalMs: number };
    /** Write to stdout */
    stdout?: boolean;
  };

  /** Policy rules */
  policies: PolicyRule[];

  /** Sensitive data patterns to flag */
  sensitivePatterns: string[];

  /** Event types to capture (empty = all) */
  captureTypes: EventType[];

  /** Max events to buffer before flushing */
  bufferSize: number;

  /** Whether to capture LLM prompt content (privacy consideration) */
  captureLlmContent: boolean;

  /** Whether to capture tool call arguments */
  captureToolArgs: boolean;
}
