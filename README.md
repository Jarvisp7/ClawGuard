# ◈ ClawGuard

**Runtime Observability & Threat Detection for AI Agents**

ClawGuard is an open-source monitoring layer that captures *what your AI agent actually does*, detects when it's been compromised, and gives security teams full trace replay of every decision chain.

> Traditional security tools can tell you *an agent exists* in your environment.  
> ClawGuard tells you *what it's doing and whether that's safe.*

---

## The Problem

Autonomous AI agents like OpenClaw operate with broad system access — reading emails, executing shell commands, managing credentials, and calling external APIs. When these agents are compromised through prompt injection, malicious skills, or misconfiguration:

- **Network monitoring** sees HTTP 200. It can't distinguish legitimate email from data exfiltration.
- **EDR** sees process execution. It can't interpret agent reasoning or detect semantic manipulation.
- **IAM** sees OAuth grants. It doesn't flag when an agent acts beyond user intent.

**The result:** Agent-driven incidents are invisible to existing security stacks.

## How ClawGuard Works

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   OpenClaw   │────▶│  ClawGuard   │────▶│   Dashboard    │
│    Agent     │     │  Collector   │     │  (SaaS / Self) │
│              │     │              │     │                │
│  LLM Calls   │     │ Event Stream │     │ Live Feed      │
│  Tool Calls  │     │ Risk Scoring │     │ Trace Replay   │
│  File Access │     │ Trace Assembly│    │ Alert Engine   │
│  Net Calls   │     │ Policy Check │     │ Fleet Overview │
└─────────────┘     └──────────────┘     └────────────────┘
```

### Three Layers

1. **Agent Collector** (Open Source) — Lightweight proxy/plugin that intercepts all agent-tool interactions. Captures LLM calls, tool invocations, file access, credential use, and network requests. <50MB memory footprint.

2. **Trace Engine** — Assembles raw events into semantic *decision traces* — causal chains showing the agent's path from input to action. Detects known attack patterns (OWASP ASI, MITRE ATLAS mapped).

3. **Policy Engine** — Configurable security rules with sequence detection, threshold alerts, and pattern matching. Ships with defaults covering credential exfiltration, memory poisoning, supply chain attacks, and prompt injection.

## Quick Start

```bash
npm install clawguard
```

```typescript
import { EventCollector, TraceEngine, PolicyEngine } from 'clawguard';

// Initialize
const collector = new EventCollector({
  agentId: 'my-openclaw-agent',
  output: { stdout: true, file: { path: './clawguard.ndjson', maxSizeMb: 100, rotateCount: 5 } },
  policies: [],
  sensitivePatterns: [],
  captureTypes: [],
  bufferSize: 100,
  captureLlmContent: false,
  captureToolArgs: true,
});

const traces = new TraceEngine({
  onAlert: (trace, patterns) => {
    console.error(`🚨 ALERT: ${trace.id} — ${patterns[0].name}`);
    console.error(`   ${patterns[0].description}`);
    console.error(`   Confidence: ${patterns[0].confidence}`);
  }
});

const policies = new PolicyEngine();

// Wire together
collector.onEvent((event) => {
  traces.processEvent(event);
  const violations = policies.evaluate(event);
  violations.forEach(v => {
    console.error(`⚠ Policy violation: ${v.policyName} — ${v.description}`);
  });
});

// Start monitoring
collector.start();
```

## Attack Patterns Detected

| Pattern | OWASP ASI | MITRE ATLAS | Description |
|---------|-----------|-------------|-------------|
| Read-Then-Exfiltrate | ASI-03 | AML.T0048 | Agent reads credentials/sensitive data then sends to external endpoint |
| Memory Poisoning | ASI-05 | AML.T0051 | External content modifies agent identity files (SOUL.md, MEMORY.md) |
| Supply Chain Skill | ASI-07 | AML.T0042 | Marketplace skill executes privileged operations after install |
| Prompt Injection | ASI-01 | — | External content triggers unexpected privileged agent actions |
| Lateral Movement | ASI-04 | — | Agent uses OAuth tokens to access services beyond original scope |

## Default Policies

ClawGuard ships with 7 default policies covering the most critical OpenClaw attack vectors:

- **POL-001** Credential Exfiltration — credential access → external network call
- **POL-002** Identity File Tampering — any SOUL.md / identity modification (auto-block)
- **POL-003** Rapid Credential Access — >3 credential reads in 60 seconds
- **POL-004** Marketplace Skill Shell Execution — ClawHub skill → shell command
- **POL-005** Sensitive Data to External — sensitive data in outbound traffic
- **POL-006** High Volume Tool Calls — >50 tool calls in 5 minutes (runaway agent)
- **POL-007** Memory Modification After External Content — data read → memory write

## Roadmap

- [x] Event schema & type system
- [x] Event collector with risk scoring
- [x] Trace engine with attack pattern detection
- [x] Policy engine with configurable rules
- [ ] OpenClaw gateway plugin (direct integration)
- [ ] Terminal UI for local trace viewing
- [ ] Web dashboard (SaaS)
- [ ] Multi-agent fleet management
- [ ] Behavioral baseline learning
- [ ] SIEM/SOAR integrations (Splunk, Sentinel, etc.)
- [ ] Compliance reporting (SOC 2, HIPAA)

## Contributing

ClawGuard is in early alpha. We welcome contributions:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Commit your changes (`git commit -m 'Add amazing detection'`)
4. Push to the branch (`git push origin feature/amazing-detection`)
5. Open a Pull Request

## License

MIT — use it, fork it, build on it.

---

**ClawGuard** — Because your agent's decisions should be as visible as your server's logs.
