# ARGUS — Modular Specifications Index

Welcome to the modular requirement and specification index for **ARGUS**, an autonomous security testing platform developed for **Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03)**.

These documents decompose the monolithic 1,300+ line specification into 10 focused, digestible modules. Each document defines its clear responsibilities, interfaces, data schemas, and acceptance criteria.

---

## Navigation Map & Module Index

```
specs/
├── README.md                              <- You are here (Master Index & Capability Map)
├── 00-overview-and-scope.md               <- Executive summary, Challenge 03 compliance & MVP boundaries
├── 01-safety-and-policy-engine.md         <- Scope YAML schema, 2-tier containment firewall & fail-closed engine
├── 02-agent-orchestrator-and-recovery.md  <- LangGraph state machine, typed action proposals & error recovery
├── 03-tool-engine-and-adapters.md         <- Docker runner, ToolAdapter contract, Nmap, ZAP & Nuclei parsers
├── 04-evidence-vault-and-verification.md  <- SHA-256 artifact hashing, 4-state finding lifecycle & redactor
├── 05-sponsor-integrations.md             <- Maxim AI Bifrost model routing/fallback & Tavily security intel
├── 06-api-contracts-and-persistence.md    <- FastAPI endpoints, SSE event streams & SQLite data models
├── 07-frontend-and-judge-dashboard.md     <- Next.js 15 UI, 5 core screens, live audit stream & demo runbook
├── 08-testing-evaluation-and-labs.md      <- 15 mandatory test scenarios, Docker test labs & M1 resource constraints
└── 09-team-plan-and-milestones.md         <- 2-person build plan (Dev 1 vs Dev 2), 11-day schedule & submission checklist
```

---

## Quick Reference Table

| Spec ID & Link | Core Responsibility | Key Technologies / Outputs | Primary Owner |
|---|---|---|---|
| **[00: Overview & Scope](file:///Users/ajaysingh/Documents/Open-source/argus/specs/00-overview-and-scope.md)** | Product vision, hackathon winning thesis, in-scope vs out-of-scope | Track A Brief, P0/P1/P2 priorities | Shared |
| **[01: Safety & Policy](file:///Users/ajaysingh/Documents/Open-source/argus/specs/01-safety-and-policy-engine.md)** | Zero out-of-scope guarantee, deterministic gating | Python Policy Engine, Docker Egress Rules | Dev 1 |
| **[02: Agent Orchestration](file:///Users/ajaysingh/Documents/Open-source/argus/specs/02-agent-orchestrator-and-recovery.md)** | Autonomous planning, execution loop, failure handling | LangGraph, `AssessmentState` TypedDict | Dev 1 |
| **[03: Tool Adapters](file:///Users/ajaysingh/Documents/Open-source/argus/specs/03-tool-engine-and-adapters.md)** | Sandboxed tool execution, typed argument validation | Nmap, OWASP ZAP, Nuclei, Docker bridge | Dev 1 |
| **[04: Evidence & Verification](file:///Users/ajaysingh/Documents/Open-source/argus/specs/04-evidence-vault-and-verification.md)** | Cryptographic proof, finding state machine | SHA-256 Vault, 4-State Lifecycle | Dev 1 |
| **[05: Sponsor Integrations](file:///Users/ajaysingh/Documents/Open-source/argus/specs/05-sponsor-integrations.md)** | Model gateway routing/failover, CVE intelligence | Maxim AI Bifrost, Tavily Search API | Dev 1 |
| **[06: API & Persistence](file:///Users/ajaysingh/Documents/Open-source/argus/specs/06-api-contracts-and-persistence.md)** | Backend REST endpoints, SSE streams, state storage | FastAPI, SQLite (WAL), Pydantic contracts | Dev 2 |
| **[07: Dashboard & Demo](file:///Users/ajaysingh/Documents/Open-source/argus/specs/07-frontend-and-judge-dashboard.md)** | Judge interface, live execution timeline, report viewer | Next.js 15, Tailwind, Radix UI, SSE hook | Dev 2 |
| **[08: Testing & Labs](file:///Users/ajaysingh/Documents/Open-source/argus/specs/08-testing-evaluation-and-labs.md)** | Automated test harness, safety regression, test labs | 15 Test Scenarios, Lab A (Juice Shop/Flask) | Shared |
| **[09: Milestones & Team](file:///Users/ajaysingh/Documents/Open-source/argus/specs/09-team-plan-and-milestones.md)** | 11-day delivery roadmap, division of labor | Nov 4–15 Milestones, First 48-Hour Slice | Shared |

---

## How to Use These Specs

1. **For Architecture Review:** Start with `00-overview-and-scope.md` and read in numerical order.
2. **For Implementation:** Implement strictly according to the build dependency order defined in `09-team-plan-and-milestones.md`.
3. **For Safety Audits:** Cross-reference `01-safety-and-policy-engine.md` and `08-testing-evaluation-and-labs.md` to verify the 15 mandatory safety gates.

