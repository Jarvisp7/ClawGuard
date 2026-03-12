/**
 * ClawGuard - Runtime Observability & Threat Detection for AI Agents
 * 
 * The open-source agent activity monitor. Captures what your AI agent
 * does, detects when it's been compromised, and gives you full trace
 * replay of every decision chain.
 * 
 * @version 0.1.0-alpha
 * @license MIT
 */

export { EventCollector, SensitiveDataDetector, computeRisk } from "./collector/EventCollector";
export { TraceEngine } from "./trace/TraceEngine";
export { PolicyEngine, DEFAULT_POLICIES } from "./policy/PolicyEngine";
export * from "./types/events";

// ─── Quick Start ───────────────────────────────────────────────
//
// import { EventCollector, TraceEngine, PolicyEngine } from 'clawguard';
//
// const collector = new EventCollector({ agentId: 'my-agent', ... });
// const traces = new TraceEngine({ onAlert: (trace, patterns) => { ... } });
// const policies = new PolicyEngine();
//
// collector.onEvent((event) => {
//   traces.processEvent(event);
//   policies.evaluate(event);
// });
//
// collector.start();
