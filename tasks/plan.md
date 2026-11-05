# ARGUS Implementation Plan

**Target:** Geek Room / Global AI Hackathon 2026 (Track A: Challenge 03)  
**Architecture:** Ports-and-Adapters Modular Monolith  
**Living Document:** Tracks execution roadmap, milestones, and phase gates.

---

## Architecture Dependency Flow

```
core-scope (01) [DONE] ──┐
                         ├─→ tool-engine (03) ──┐
evidence-vault (04) ────────────────────────────┼─→ agent-orchestrator (02) ──→ api-lifecycle (06) ──┬─→ dashboard-ui (07)
bifrost-gateway (05) ───────────────────────────┤                                                    └─→ report-engine
tavily-intel (05) ──→ finding-verifier (04) ────┘
```

---

## Phase Breakdown

### Phase 1: Core Safety & Data Contracts (Module 01) — STATUS: COMPLETED
- [x] Pydantic models for Scope, Action Proposals, Policy Decisions, and Assessment Decisions (`packages/contracts/`).
- [x] Scope YAML parser, CIDR normalizer, and temporal expiry checker (`core/scope/validator.py`).
- [x] Deterministic 5-stage policy engine (`core/policy/policy_engine.py`).
- [x] 16 TDD security firewall tests with 90% coverage (`tests/security/test_scope_firewall.py`).

### Phase 2: Tool Engine & Docker Runner (Module 03)
- [ ] Abstract `ToolAdapter` base class and `NormalizedObservation` schema (`integrations/tools/base.py`).
- [ ] Tool runner Docker container (`infrastructure/docker/runner.Dockerfile`).
- [ ] Nmap port/service discovery adapter (`integrations/tools/nmap_adapter.py`) with `defusedxml` parser.
- [ ] Nuclei CVE template check adapter (`integrations/tools/nuclei_adapter.py`) with JSONL parser.
- [ ] Subprocess lifecycle manager with timeout and signal termination (`core/executor/docker_runner.py`).

### Phase 3: Evidence Vault & Finding Verifier (Module 04)
- [ ] File-based raw artifact storage with SHA-256 integrity calculation (`core/evidence/evidence_vault.py`).
- [ ] Sensitive credential and token redaction pipeline (`core/evidence/redactor.py`).
- [ ] 4-state finding classification engine (`POTENTIAL` $\rightarrow$ `CONFIRMED`) (`core/findings/finding_verifier.py`).

### Phase 4: Sponsor Gateways — Bifrost & Tavily (Module 05)
- [ ] Maxim AI Bifrost client with Claude 3.5 Sonnet $\rightarrow$ GPT-4o failover (`integrations/bifrost/bifrost_client.py`).
- [ ] Telemetry tracking: token counts, latency, and cost calculation.
- [ ] Tavily security intelligence search client (`integrations/tavily/tavily_client.py`).

### Phase 5: Agent Orchestrator & LangGraph Loop (Module 02)
- [ ] `AssessmentState` TypedDict and budget/cancellation models (`engine/state.py`).
- [ ] Dynamic tool selection via Module 03 `ToolRegistry`.
- [ ] LangGraph StateGraph builder with adaptive strategy pivoting (`engine/graph.py`).
- [ ] Bounded recovery node with exponential backoff on 429 rate limits (`engine/recovery.py`).
- [ ] Deterministic objective completion evaluator (`engine/nodes/evaluate_completion.py`).

### Phase 6: FastAPI Backend & SQLite SSE Streams (Module 06)
- [ ] FastAPI application entrypoint with CORS and error handling (`apps/api/main.py`).
- [ ] Assessment lifecycle routes (`/api/v1/assessments`, `/start`, `/pause`, `/cancel`).
- [ ] Server-Sent Events (SSE) live broadcaster (`apps/api/services/event_broadcaster.py`).
- [ ] SQLite persistence layer with WAL mode and foreign keys (`apps/api/database.py`).

### Phase 7: Next.js Frontend & Judge Dashboard (Module 07)
- [ ] Next.js 15 App Router setup with Tailwind CSS (`apps/web/`).
- [ ] App Header with Bifrost Telemetry Bar (active model, tokens, latency, cost indicator).
- [ ] Screen 1: Dashboard (`/`), Screen 2: Launcher (`/new`), Screen 3: Live Assessment Room (`/assessments/[id]`).
- [ ] Real-time SSE audit timeline and discovered topology cards.
- [ ] One-click PDF report generator (`/api/v1/assessments/{id}/report/pdf`).

### Phase 8: Testing, Hardening & Practice Labs (Module 08)
- [ ] Spin up Lab A (`infrastructure/labs/lab-a-web/`) with CVE-2021-41773 Apache target.
- [ ] Execute full 15-scenario automated security and recovery test suite.
- [ ] Verify zero out-of-scope executions and 100% evidence linkage.

### Phase 9: Evaluation & Demo Rehearsal (Module 09)
- [ ] 3-minute rehearsed live demo runbook.
- [ ] Feature freeze, documentation polish, and final submission.

