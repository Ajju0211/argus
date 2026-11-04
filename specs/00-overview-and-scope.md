# Module 00 — Overview, Challenge Compliance & MVP Scope

**Module ID:** `overview-and-scope`  
**Status:** Approved Specification  
**Primary Stakeholders:** Dev 1, Dev 2, Hackathon Judges  

---

## 1. Executive Summary & Product Positioning

**ARGUS** is an autonomous security-testing platform designed for authorized, isolated penetration-testing labs. A user supplies a target, an explicit scope document, and an assessment objective. ARGUS deterministically validates the scope, discovers permitted assets and services using real security tools, normalizes and interprets observations, plans and executes safe checks, recovers from unexpected failures, verifies potential findings, and produces a cryptographic, evidence-backed report.

### Core Product Principle
> **"Every action must be authorized, every confirmed finding must have verifiable evidence, and every assessment must be explainable through an inspectable execution history."**

### Positioning Slogan
> **"ARGUS — Autonomous Security Testing. Verified by Evidence."**

---

## 2. Challenge 03 Requirements & Compliance Matrix

The Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03) establishes specific evaluation criteria. The table below maps each requirement to its concrete ARGUS implementation:

| Challenge 03 Requirement | ARGUS Technical Implementation | Acceptance Evidence / Verification |
|---|---|---|
| **Authorized Enumeration** | Scope-aware network & web tool adapters executing inside isolated Docker networks. | Subprocess logs demonstrate zero packets transmitted to out-of-scope destinations. |
| **Tool Output Interpretation** | Parsers normalize raw XML/JSON output into structured, typed observations. | Agent reasoning logs reference parsed observation schemas rather than unstructured text. |
| **Autonomous Action Planning** | Stateful LangGraph agent creates structured action proposals with rationale and expected evidence. | Persistent SQLite audit log contains all proposed, approved, and executed actions. |
| **Adaptive Failure Recovery** | Bounded retry and replan policy that handles tool timeouts, non-zero exits, and malformed outputs. | Injected tool freeze (SIGSTOP) triggers automatic recovery and alternative tool selection. |
| **Lab Objective Completion** | Objective evaluator monitors discovered topology and stops when defined goals are satisfied. | Assessment cleanly concludes and transitions from `RUNNING` to `COMPLETED`. |
| **Strict Scope Compliance** | Two-tier firewall: Deterministic Python policy engine + Docker network isolation. | Out-of-scope probe is blocked immediately at the policy check point. |
| **Client-Ready Reporting** | Automated report engine compiling executive summary, topology, verified findings, and remediation. | Downloadable client-ready PDF and Markdown report with clickable evidence links. |
| **Meaningful Bifrost Integration** | 100% of LLM calls route through Bifrost gateway with multi-provider failover and token/cost telemetry. | Live dashboard telemetry bar displaying latency, token usage, and active provider. |
| **Meaningful Tavily Integration** | Queries Tavily for official vendor CVE advisories and mitigation steps for discovered service versions. | Report Section 6 contains authoritative Tavily URLs, publication dates, and citations. |

---

## 3. Scope of the Hackathon MVP

### 3.1 Strict In-Scope Capabilities
- **Shared Assessment Engine:** Full lifecycle management (`DRAFT` $\rightarrow$ `VALIDATING` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`).
- **Deterministic Scope Enforcement:** Application-level validation of target IP, FQDN, ports, protocols, and action categories before tool execution.
- **Controlled Tool Execution:** Pre-installed, pinned versions of Nmap, OWASP ZAP (baseline), and Nuclei (curated informational/CVE templates).
- **Evidence Vault:** Automatic raw artifact storage on disk, computed SHA-256 integrity digests, and sensitive data redaction.
- **Finding Verification:** 4-state finding classification (`POTENTIAL`, `CONFIRMED`, `REJECTED`, `UNVERIFIABLE`).
- **Sponsor Gateways:** Bifrost for LLM routing and failover; Tavily for CVE and patch intelligence.
- **Reporting:** Automated Markdown and PDF report generation.
- **Dashboard UI:** Next.js 15 web interface with real-time SSE audit stream.

### 3.2 Out-of-Scope (Prohibited for Hackathon MVP)
- Public Internet or unauthorized real-world targets.
- Unrestricted arbitrary terminal/bash command generation by the LLM.
- Denial-of-Service (DoS), stress testing, or resource exhaustion.
- Automated credential theft, dictionary brute-forcing, or password cracking.
- Malware deployment, reverse shells, or persistence mechanisms.
- Complex autonomous lateral movement across internal subnets.
- Distributed microservices, Kubernetes clusters, Celery, or Redis.
- Multi-agent swarm architectures.

### 3.3 Prioritization Framework

```
┌───────────────────────────────────────────────────────────┐
│ P0 (Must Have - Release Blocking)                         │
│ • Deterministic Scope Engine    • Nmap/ZAP/Nuclei Adapters│
│ • LangGraph Stateful Loop       • Evidence Vault (SHA-256)│
│ • Bifrost LLM Gateway           • Finding Verifier Engine │
│ • Tavily CVE Intelligence       • Client-Ready PDF Report │
└─────────────────────────────┬─────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────┐
│ P1 (Should Have - If Time Permits)                        │
│ • Live Next.js SSE Stream UI    • Injected Failure Demo   │
│ • Basic Credential Handling     • Multi-Host Lab Support  │
└─────────────────────────────┬─────────────────────────────┘
                              │
┌─────────────────────────────▼─────────────────────────────┐
│ P2 (Post-Hackathon Roadmap)                               │
│ • Autonomous Lateral Movement   • Team Collaboration/RBAC │
│ • Enterprise CI/CD Integrations • Scheduled Re-Testing    │
└───────────────────────────────────────────────────────────┘
```

---

## 4. User Personas & Primary Workflow

### 4.1 Target Users
1. **Hackathon Judge:** Needs to supply an unfamiliar, isolated lab target and scope, observe a transparent 3-minute assessment, and evaluate an evidence-backed report.
2. **Security Engineer:** Needs to perform repeatable, authorized vulnerability checks in an isolated lab and receive actionable remediation guidance.

### 4.2 Assessment Lifecycle State Machine

```
[DRAFT] ──(Supply Scope & Target)──→ [VALIDATING] ──(Valid)──→ [READY]
                                          │
                                       (Invalid)
                                          │
                                          ▼
                                       [FAILED]
                                          
[READY] ──(User / Judge Clicks Start)──→ [RUNNING]
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
           [PAUSED]                    [COMPLETED]                    [CANCELLED]
   (Manual Pause or Outage)        (Objective Achieved)           (User / Timeout)
```

---

## 5. The 3-Minute Hackathon Demo Script

To impress the judges, the live demonstration follows an exact, rehearsed path:

1. **Minute 1: Scope Ingestion & Safety Guarantee**
   - Judge supplies target: `http://lab-target:8080` and loads `scope.yaml`.
   - Live safety test: The presenter attempts to add an unapproved IP (`10.0.0.99`); ARGUS flags the violation and refuses to start.
   - Presenter clicks **Start Assessment**. Pre-flight scope check passes; status transitions to `RUNNING`.
2. **Minute 2: Autonomous Intelligence & Adaptive Recovery**
   - Next.js dashboard displays live SSE feed: Nmap discovers open port 8080 running `Apache 2.4.49`.
   - Tavily automatically queries CVE feeds and surfaces `CVE-2021-41773` (Path Traversal) with official patches.
   - **Injected Failure:** A simulated network timeout freezes the tool. The agent catches the timeout within 15s, records the error, replans, and selects a targeted Nuclei verification check.
   - Bifrost switches from Claude 3.5 Sonnet to GPT-4o on a simulated provider rate limit, updating the telemetry bar.
3. **Minute 3: Cryptographic Evidence & Executive Report**
   - Nuclei executes the path traversal check, captures raw HTTP request/response headers, and generates SHA-256 digest `sha256:8f4c...`.
   - Finding is upgraded from `POTENTIAL` to `CONFIRMED`.
   - Objective evaluator confirms goal completion; assessment stops cleanly.
   - Presenter clicks **Download PDF** — generating an executive-ready security report containing topology diagrams, verified findings, cryptographic evidence hashes, and Tavily-sourced vendor patches.

