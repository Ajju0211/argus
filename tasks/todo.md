# ARGUS Execution Task List (Todo)

This checklist tracks concrete, implementable engineering tasks. Each task specifies explicit acceptance criteria, verification commands, and files touched.

---

## Completed Tasks

- [x] **Task 01.1: Project Setup & Package Scaffolding**
  - Acceptance: Python 3.12 environment initialized with `uv`, editable install of `argus` with dev dependencies.
  - Verify: `.venv/bin/python -c "import pydantic, pytest, yaml; print('OK')"`
  - Files: `pyproject.toml`, `README.md`, `.gitignore`

- [x] **Task 01.2: Scope & Action Pydantic Contracts**
  - Acceptance: Immutable, strictly validated contracts for ScopeDocument, ActionProposal, PolicyDecision, and AssessmentDecision.
  - Verify: `.venv/bin/mypy packages/contracts` passes with 0 errors.
  - Files: `packages/contracts/scope.py`, `packages/contracts/actions.py`, `packages/contracts/__init__.py`

- [x] **Task 01.3: Scope Parser & Expiry Validation**
  - Acceptance: Validates YAML scopes, enforces CIDR syntax, checks temporal expiration.
  - Verify: `.venv/bin/pytest tests/security/test_scope_firewall.py -k TestScopeValidator`
  - Files: `core/scope/validator.py`, `core/scope/__init__.py`

- [x] **Task 01.4: Deterministic Policy Engine (Safety Firewall)**
  - Acceptance: Blocks out-of-scope IPs, subnets, gateway (.1), cloud metadata (169.254...), loopback, denied ports, and shell injection.
  - Verify: `.venv/bin/pytest tests/security/test_scope_firewall.py -v` (16/16 passed, 90% coverage)
  - Files: `core/policy/policy_engine.py`, `core/policy/__init__.py`, `tests/security/test_scope_firewall.py`

- [x] **Task 02.1: LangGraph AssessmentState Schema & Budget Models**
  - Acceptance: Implements full TypedDict state with execution budget, cancellation, and recovery states.
  - Verify: `.venv/bin/mypy engine/state.py` passes with 0 errors.
  - Files: `engine/state.py`

- [x] **Task 02.2: LangGraph StateMachine Builder & Dynamic Node Wiring**
  - Acceptance: Compiles StateGraph with adaptive planning loop, policy gating, recovery nodes, and completion evaluation.
  - Verify: `.venv/bin/pytest tests/integration/test_orchestrator.py -k test_graph_compiles`
  - Files: `engine/graph.py`, `engine/nodes/`

- [x] **Task 02.3: Bounded Adaptive Recovery & Replan Policy**
  - Acceptance: Handles tool timeouts, empty outputs, and 429 provider rate limits with exponential backoff & jitter.
  - Verify: `.venv/bin/pytest tests/integration/test_orchestrator.py -k test_provider_rate_limit`
  - Files: `engine/recovery.py`

- [x] **Task 02.4: Deterministic Objective Completion Evaluator**
  - Acceptance: Validates completion against verified findings and evidence before declaring `SUCCESS`.
  - Verify: `.venv/bin/pytest tests/integration/test_orchestrator.py -k test_objective_completion`
  - Files: `engine/nodes/evaluate_completion.py`

- [x] **Task 02.5: System Prompt & Structured Output Formatting**
  - Acceptance: Injects dynamic tools, format instructions for AssessmentDecision, sandboxes untrusted observations.
  - Verify: `.venv/bin/mypy engine/prompts.py`
  - Files: `engine/prompts.py`

- [x] **Task 03.1: Abstract ToolAdapter Interface & Normalized Observation Schema**
  - Acceptance: Standard base class for all tools enforcing argument validation, command array building, and structured observation parsing.
  - Verify: `.venv/bin/mypy integrations/tools/base.py` (0 errors)
  - Files: `integrations/tools/base.py`, `integrations/tools/__init__.py`

- [x] **Task 03.2: Dynamic Tool Registry Subsystem**
  - Acceptance: Dynamic registry allowing tools to be queried by capability and exported as descriptors for LangGraph.
  - Verify: `.venv/bin/pytest tests/unit/test_tool_engine.py -k TestToolRegistry` (Passed)
  - Files: `core/executor/tool_registry.py`, `core/executor/__init__.py`

- [x] **Task 03.3: Nmap Discovery Adapter with defusedxml Parser**
  - Acceptance: Executes unprivileged TCP connect scan (`-sT -sV -T4 --open -oX -`) and parses open ports and versions safely using `defusedxml`.
  - Verify: `.venv/bin/pytest tests/unit/test_tool_engine.py -k TestNmapAdapter` (Passed)
  - Files: `integrations/tools/nmap_adapter.py`, `tests/fixtures/nmap_sample.xml`

- [x] **Task 03.4: Nuclei CVE Template Adapter with JSONL Parser**
  - Acceptance: Enforces pinned templates, rejects directory traversal, parses JSONL findings into typed observations.
  - Verify: `.venv/bin/pytest tests/unit/test_tool_engine.py -k TestNucleiAdapter` (Passed)
  - Files: `integrations/tools/nuclei_adapter.py`, `tests/fixtures/nuclei_sample.jsonl`

- [x] **Task 03.5: OWASP ZAP Baseline Adapter**
  - Acceptance: Baseline web application audit adapter with risk-level parsing and security observation extraction.
  - Verify: `.venv/bin/pytest tests/unit/test_tool_engine.py -k TestZapAdapter` (Passed)
  - Files: `integrations/tools/zap_adapter.py`, `tests/fixtures/zap_sample.json`

- [x] **Task 03.6: Subprocess Runner with Process Group Isolation & Timeouts**
  - Acceptance: Executes `argv` array without shell, creates OS process groups, terminates child processes cleanly on timeout (`SIGKILL`).
  - Verify: `.venv/bin/pytest tests/unit/test_tool_engine.py -k TestProcessRunner` (Passed)
  - Files: `core/executor/process_runner.py`, `infrastructure/docker/runner.Dockerfile`

- [x] **Task 04.1: Cryptographic Evidence Vault (SHA-256 Storage)**
  - Acceptance: Writes raw output to `/artifacts/{id}/{ev_id}.raw`, tracks metadata in `metadata.jsonl`, and verifies SHA-256 integrity against disk tampering.
  - Verify: `.venv/bin/pytest tests/unit/test_evidence_vault.py -k TestEvidenceVault` (Passed)
  - Files: `core/evidence/evidence_vault.py`, `core/evidence/__init__.py`

- [x] **Task 04.2: Sensitive Secret Redaction Pipeline**
  - Acceptance: Masks passwords, bearer tokens, API keys, and basic authorization headers with `[REDACTED_BY_ARGUS]` before storage.
  - Verify: `.venv/bin/pytest tests/unit/test_evidence_vault.py -k TestSecretRedaction` (Passed)
  - Files: `core/evidence/redactor.py`

- [x] **Task 04.3: Finding Verification State Machine & Zero-Hallucination Invariant**
  - Acceptance: Enforces typed `Finding` contract with Pydantic validator requiring non-empty `evidence_ids` for `CONFIRMED` status; transitions candidate findings across `POTENTIAL`, `CONFIRMED`, `REJECTED`, and `UNVERIFIABLE`.
  - Verify: `.venv/bin/pytest tests/unit/test_evidence_vault.py -k TestFindingContractsAndStateMachine` (Passed)
  - Files: `packages/contracts/findings.py`, `core/findings/finding_verifier.py`, `core/findings/__init__.py`

---

## Active & Upcoming Tasks

### Module 05: Sponsor Integrations (Bifrost & Tavily)
- [ ] **Task 05.1: Maxim AI Bifrost Client with Multi-Provider Failover**
  - Acceptance: Routes all model completions through Bifrost; automatically fails over from Claude 3.5 Sonnet to GPT-4o on provider error.
  - Verify: `.venv/bin/pytest tests/integration/test_bifrost_client.py`
  - Files: `integrations/bifrost/bifrost_client.py`

- [ ] **Task 05.2: Bifrost Telemetry & Cost Accounting**
  - Acceptance: Tracks prompt tokens, completion tokens, latency (ms), and active provider per request.
  - Verify: `.venv/bin/pytest tests/unit/test_bifrost_telemetry.py`
  - Files: `integrations/bifrost/telemetry.py`

- [ ] **Task 05.3: Tavily Security Intelligence Search**
  - Acceptance: Queries NVD/CVE sources for discovered service versions and parses remediation recommendations.
  - Verify: `.venv/bin/pytest tests/integration/test_tavily_intel.py`
  - Files: `integrations/tavily/tavily_client.py`


---

### Module 06: Backend API & SQLite Persistence
- [ ] **Task 06.1: SQLite Async Database & WAL Schema**
  - Acceptance: Persistent tables for assessments, events, findings, evidence artifacts, and graph checkpoints.
  - Verify: `.venv/bin/pytest tests/integration/test_database.py`
  - Files: `apps/api/database.py`, `apps/api/models.py`

- [ ] **Task 06.2: FastAPI Assessment Lifecycle Routes**
  - Acceptance: REST endpoints for creating, listing, starting, pausing, and cancelling assessments.
  - Verify: `.venv/bin/pytest tests/integration/test_api_routes.py`
  - Files: `apps/api/main.py`, `apps/api/routers/assessments.py`

- [ ] **Task 06.3: Server-Sent Events (SSE) Live Stream Broadcaster**
  - Acceptance: Streams real-time audit events to connected clients at `/api/v1/assessments/{id}/events`.
  - Verify: `.venv/bin/pytest tests/integration/test_sse_stream.py`
  - Files: `apps/api/services/event_broadcaster.py`

---

### Module 07: Next.js Dashboard & Header
- [x] **Task 07.1: Next.js 15 App Scaffolding with Tailwind & Radix UI**
  - Acceptance: Next.js 15 App Router project set up under `apps/web/` with dark mode theme.
  - Verify: `cd apps/web && npm run build`
  - Files: `apps/web/package.json`, `apps/web/src/app/layout.tsx`

- [x] **Task 07.2: Application Header & Bifrost Telemetry Bar**
  - Acceptance: Sticky header displaying target badge, timer, active Bifrost model, token usage, latency, and cost indicator.
  - Verify: Visual inspection and component unit test.
  - Files: `apps/web/src/components/layout/AppHeader.tsx`, `apps/web/src/components/navigation/BifrostHUD.tsx`

- [x] **Task 07.3: Live Assessment Room UI with SSE Stream**
  - Acceptance: Split screen with real-time audit timeline on the left and topology/findings board on the right.
  - Verify: End-to-end event stream display.
  - Files: `apps/web/src/app/assessments/[id]/page.tsx`, `apps/web/src/components/live/AuditTimeline.tsx`

- [x] **Task 07.4: Client-Ready PDF Report Generator**
  - Acceptance: Executive PDF report with topology diagram, findings matrix, SHA-256 evidence digests, and Tavily remediation citations.
  - Verify: `curl http://localhost:8000/api/v1/assessments/{id}/report/pdf -o report.pdf`
  - Files: `core/reporting/report_generator.py`, `core/reporting/pdf_exporter.py`

---

### Module 08: Testing, Evaluation & Lab Setups
- [x] **Task 08.1: 15 Mandatory Scenario Test Suite Verification**
  - Acceptance: 15 automated test cases passing 100% covering security, failure recovery, failover, and evidence integrity.
  - Verify: `.venv/bin/pytest tests/integration/test_scenarios.py -v` (15/15 passed)
  - Files: `tests/integration/test_scenarios.py`, `specs/08-testing-evaluation-and-labs.md`

- [x] **Task 08.2: Pre-Configured Test Lab A (Vulnerable Web App)**
  - Acceptance: Standardized Dockerized Apache 2.4.49 path traversal target (`CVE-2021-41773`) with scope fixture and verification probe.
  - Verify: `.venv/bin/pytest tests/integration/test_e2e_lab.py -v`
  - Files: `infrastructure/labs/lab-a-web/Dockerfile`, `infrastructure/labs/lab-a-web/server.py`, `infrastructure/labs/lab-a-web/scope.yaml`

- [x] **Task 08.3: Pre-Configured Test Lab B (Multi-Service Linux Host)**
  - Acceptance: Standardized multi-service target exposing FTP (`vsftpd 2.3.4`) and SSH (`OpenSSH 8.4p1`) with automated multi-port recon.
  - Verify: `.venv/bin/pytest tests/integration/test_lab_b_network.py -v`
  - Files: `infrastructure/labs/lab-b-network/Dockerfile`, `infrastructure/labs/lab-b-network/server.py`, `infrastructure/labs/lab-b-network/scope.yaml`

- [x] **Task 08.4: M1 Resource Budget & 10 MB Artifact Quota**
  - Acceptance: Strict per-file 10 MB evidence disk quota with clean truncation banner and cryptographic integrity preserved.
  - Verify: `.venv/bin/pytest tests/unit/test_evidence_quota.py -v`
  - Files: `core/evidence/evidence_vault.py`, `tests/unit/test_evidence_quota.py`

- [x] **Task 08.5: Full Suite Coverage Enforcement (80%+ Gate)**
  - Acceptance: 100% passing test suite across all modules with >80% total code coverage.
  - Verify: `.venv/bin/pytest tests --cov=core --cov=engine --cov=integrations` (256 passed, 87% coverage)
  - Files: `pyproject.toml`, `tests/`

---

### Module 11: Proof-Carrying Findings & Chain of Custody
- [x] **Task 11.1: Cryptographic Merkle Log Primitive**
  - Acceptance: Canonical JSON serialization, domain-separated leaf (`\x00`) and node (`\x01`) SHA-256 hashing, pairwise tree construction with odd-node promotion, and RFC-style inclusion proofs.
  - Verify: `.venv/bin/pytest tests/unit/test_merkle_log.py -v` (16/16 passed)
  - Files: `core/evidence/merkle_log.py`, `tests/unit/test_merkle_log.py`

- [x] **Task 11.2: Append-Only Assessment Ledger with T2 Attestation**
  - Acceptance: JSONL append-only log with strict monotonic sequence numbering, T2 executor attestation, and tree head tracking.
  - Verify: `.venv/bin/pytest tests/unit/test_ledger.py -v` (2/2 passed)
  - Files: `core/evidence/ledger.py`, `tests/unit/test_ledger.py`

- [x] **Task 11.3: Proof Capsule (.argusproof) Packaging & Security Hardening**
  - Acceptance: Self-contained ZIP bundle with `manifest.json`, `ledger.jsonl`, and redacted artifacts. Enforces zip-bomb ceilings (50MB) and path traversal protection.
  - Verify: `.venv/bin/pytest tests/unit/test_proof_capsule.py -v` (6/6 passed)
  - Files: `core/evidence/proof_capsule.py`, `tests/unit/test_proof_capsule.py`

- [x] **Task 11.4: Standalone Offline Verifier (`scripts/verify_proof.py`)**
  - Acceptance: Dependency-free, Python stdlib-only verification CLI validating Merkle roots, inclusion proofs, artifact hashes, and T2 attestation without trusting the agent.
  - Verify: `python scripts/verify_proof.py <capsule.argusproof>` returns `PROVEN`
  - Files: `scripts/verify_proof.py`

- [x] **Task 11.5: Orchestrator Integration & Zero-Hallucination Proof Binding**
  - Acceptance: Executor records T2 events into ledger on tool completion; finding verifier binds proof IDs and ledger roots to confirmed findings and rejects T1-only claims.
  - Verify: `tests/integration/test_scenarios.py` (15/15 passed)
  - Files: `engine/graph.py`, `packages/contracts/findings.py`, `core/findings/finding_verifier.py`

- [x] **Task 11.6: FastAPI Capsule Download & Verification Endpoints**
  - Acceptance: REST endpoints `GET /api/v1/assessments/{id}/proof` and `POST /api/v1/proof/verify`.
  - Verify: `.venv/bin/pytest tests/integration/test_proof_api.py -v`
  - Files: `apps/api/routers/assessments.py`, `apps/api/main.py`, `tests/integration/test_proof_api.py`



