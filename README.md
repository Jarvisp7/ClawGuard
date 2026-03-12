<p align="center">
  <h1 align="center">◈ ClawGuard</h1>
  <p align="center"><strong>Runtime Observability & Threat Detection for AI Agents</strong></p>
  <p align="center">
    <em>Your AI agent's decisions should be as visible as your server's logs.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0--alpha-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/platform-macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/agent-OpenClaw-orange" alt="OpenClaw">
</p>
![ClawGuard Dashboard](https://raw.githubusercontent.com/Jarvisp7/ClawGuard/main/assets/clawguard-dashboard.png)

---

## The Problem

Autonomous AI agents like OpenClaw operate with broad system access — reading emails, executing shell commands, managing credentials, and calling external APIs. **When these agents are compromised, existing security tools are blind:**

- **Network monitoring** sees HTTP 200. It can't distinguish legitimate email from data exfiltration.
- **EDR** sees process execution. It can't interpret agent reasoning or detect semantic manipulation.
- **IAM** sees OAuth grants. It doesn't flag when an agent acts beyond user intent.

**ClawGuard fills this gap.** It captures what your AI agent actually does, detects when it's been compromised, and gives you full control — from passive monitoring to automatic threat neutralization.

---

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   AI Agent   │────▶│  ClawGuard   │────▶│   Desktop App  │
│  (OpenClaw)  │     │    Hook      │     │                │
│              │     │              │     │  Live Feed     │
│  LLM Calls   │     │ Event Capture│     │  Risk Scoring  │
│  Tool Calls  │     │ Risk Scoring │     │  Threat Alerts │
│  File Access │     │ Pattern Det. │     │  Kill Switch   │
│  Net Calls   │     │ NDJSON Log   │     │  Auto-Protect  │
└─────────────┘     └──────────────┘     └────────────────┘
```

ClawGuard operates as a **three-layer system**:

1. **Agent Hook** — Installs into the OpenClaw gateway and passively captures all agent activity: LLM calls, tool invocations, file access, credential use, network requests, skill loads, and memory operations. Zero performance impact.

2. **Threat Engine** — Scores every event for risk (0-5), assembles events into causal decision traces, and detects known attack patterns mapped to OWASP ASI and MITRE ATLAS frameworks.

3. **Desktop App** — Native Mac application showing real-time event streams, color-coded risk levels, and three protection modes.

---

## Three Protection Modes

### 👁 Monitor
Passive observation. ClawGuard watches and logs everything without intervening. Use this to learn what "normal" looks like for your agent before enabling protection.

### 🔔 Alert + Kill
Real-time threat alerts with a manual kill switch. When ClawGuard detects suspicious activity, you see it immediately and decide whether to stop the agent. The default for most users.

### 🛡 Auto-Protect
Policy-driven automatic response. When a critical attack pattern is detected — credential exfiltration, memory poisoning, supply chain attacks — ClawGuard stops the agent automatically before damage is done. No human in the loop required.

---

## Attack Patterns Detected

| Pattern | Framework | Description |
|------|-----------|-------------|
| Credential Exfiltration | OWASP ASI-03 | Agent reads credentials then sends to external endpoint |
| Memory Poisoning | OWASP ASI-05 | External content modifies agent identity files (SOUL.md) |
| Supply Chain Attack | OWASP ASI-07 | Marketplace skill executes privileged operations |
| Prompt Injection | OWASP ASI-01 | External content triggers unexpected agent actions |
| Lateral Movement | OWASP ASI-04 | Agent uses OAuth tokens beyond original scope |

---

## Quick Start

### Prerequisites
- Node.js ≥ 18
- OpenClaw installed (`npm install -g openclaw@latest`)
- Rust (for desktop app)

### Install the Hook

```bash
# Create the hook directory
mkdir -p ~/.openclaw/hooks/clawguard

# Copy hook files (HOOK.md and handler.ts)
# See /hooks directory in this repo

# Enable it
openclaw hooks enable clawguard

# Restart your gateway
openclaw gateway --allow-unconfigured
```

### Run the Desktop App

```bash
cd desktop-app
npm install
npm run tauri dev
```

The app reads from `~/.openclaw/clawguard-events.ndjson` and displays events in real time.

---

## Project Structure

```
clawguard/
├── src/
│   ├── types/          # Event schema & type definitions
│   ├── collector/      # Event capture & risk scoring engine
│   ├── trace/          # Decision chain assembly & attack detection
│   ├── policy/         # Configurable security rules (7 defaults)
│   └── plugin/         # OpenClaw gateway plugin
├── desktop-app/        # Tauri native Mac application
│   ├── index.html      # Dashboard UI
│   └── src-tauri/      # Rust backend (event reader, kill switch, auto-protect)
├── config/             # Default configuration
└── README.md
```

---

## Default Security Policies

ClawGuard ships with 7 policies covering the most critical agent attack vectors:

- **POL-001** Credential Exfiltration — credential access → external network call
- **POL-002** Identity File Tampering — SOUL.md / identity modification (auto-block)
- **POL-003** Rapid Credential Access — >3 credential reads in 60 seconds
- **POL-004** Marketplace Skill Shell Exec — ClawHub skill → shell command
- **POL-005** Sensitive Data to External — sensitive data in outbound traffic
- **POL-006** High Volume Tool Calls — >50 tool calls in 5 minutes (runaway agent)
- **POL-007** Memory Modification — data read → memory write chain

---

## Roadmap

- [x] Core event schema & type system
- [x] Event collector with real-time risk scoring
- [x] Trace engine with attack pattern detection (OWASP/MITRE mapped)
- [x] Policy engine with configurable rules
- [x] OpenClaw gateway hook (live event capture)
- [x] Native Mac desktop app
- [x] Three protection modes (Monitor / Alert+Kill / Auto-Protect)
- [x] Kill switch (manual + automatic)
- [ ] Behavioral baseline learning
- [ ] Threat replay (step through attack chains)
- [ ] Agent diff (compare behavior against baseline)
- [ ] Multi-agent fleet management
- [ ] Connectors for Claude Code, CrewAI, AutoGPT, LangGraph
- [ ] Windows & Linux desktop apps
- [ ] Web dashboard (SaaS)
- [ ] SIEM/SOAR integrations (Splunk, Sentinel, PagerDuty)
- [ ] Compliance reporting (SOC 2, HIPAA)

---

## Why ClawGuard Exists

In January 2026, OpenClaw went viral — 300K+ GitHub stars, 1.5M+ registered agents. Within weeks, security researchers found 135,000+ exposed instances, 12% of the skill marketplace compromised with malware, and critical RCE vulnerabilities being exploited in the wild. CrowdStrike called it "groundbreaking" from a capability perspective and "an absolute nightmare" from a security perspective.

Every existing security tool can tell you *an agent exists* in your environment. None of them can tell you *what the agent is doing, why it made a decision, or whether that decision chain was manipulated*.

ClawGuard closes that gap.

---

## Contributing

ClawGuard is in early alpha. Contributions welcome:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Commit your changes
4. Push and open a Pull Request

---

## License

MIT — use it, fork it, build on it.

---

<p align="center">
  Built by <a href="https://github.com/Jarvisp7">Jarvis Perdue</a>
</p>
