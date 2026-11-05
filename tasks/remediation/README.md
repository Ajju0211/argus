# ARGUS Remediation Backlog & Subtask Plan

This folder breaks down all unsolved gaps identified in `specs/10-implementation-review-and-remediation-plan.md` into actionable, prioritized subtasks.

---

## Solved Status Summary

The following items from the review are now fully solved and verified:

| Item | Description | Status | Verification |
|---|---|---|---|
| **C-01 to C-05** | Integrity & execution wiring (no hardcoded recon/findings, real evidence vault) | **SOLVED** | `engine/graph.py`, `tests/security/test_integrity_wiring.py` |
| **S-01 to S-10** | Scope & safety policy hardening (DNS pinning, port allowlist `None`, redirect policy) | **SOLVED** | `core/policy/policy_engine.py`, `tests/security/test_scope_and_safety_hardening.py` |
| **E-01** | Evidence vault with cryptographic SHA-256 integrity & path traversal defense | **SOLVED** | `core/evidence/evidence_vault.py`, `tests/unit/test_evidence_vault.py` |
| **E-02** | Finding contract & Zero-Hallucination verification state machine | **SOLVED** | `packages/contracts/findings.py`, `core/findings/finding_verifier.py` |
| **E-04** | Secret redactor scrubbing Bearer tokens, passwords, API keys | **SOLVED** | `core/evidence/redactor.py`, `test_evidence_vault.py` |
| **I-01** | Maxim AI Bifrost LLM gateway with Sonnet primary & GPT-4o fallback | **SOLVED** | `integrations/bifrost/`, `tests/integration/test_bifrost_client.py` |
| **I-02** | Tavily authoritative CVE & security advisory search service | **SOLVED** | `integrations/tavily/`, `tests/integration/test_tavily_client.py` |
| **D-08** | Bifrost spec & `.env.example` alignment | **SOLVED** | `.env.example`, `core/config.py` |

---

## Active Remediation Tracks

Each track file below contains concrete subtasks with files to edit, acceptance criteria, and tests to write:

1. **[01-integrity-and-wiring.md](./01-integrity-and-wiring.md)** — **COMPLETED & VERIFIED (12/12 tests)**
   - C-01 to C-05: Hardcoded recon & findings eliminated, tool execution & cryptographic evidence wired.

2. **[02-scope-and-safety-hardening.md](./02-scope-and-safety-hardening.md)** — **COMPLETED & VERIFIED (28/28 tests)**
   - S-01 to S-10: DNS pinning, port allowlist on `None`, redirect policies, protocol restrictions, tool registry gate, duration timeouts.

3. **[03-lab-agnostic-targets.md](./03-lab-agnostic-targets.md)** — **COMPLETED & VERIFIED (46/46 tests)**
   - **L-01:** Extract arbitrary target host and port from assessment target URL (`http://host:3000/app`, IPv6 literals, bare IPs).
   - **L-02:** Flexible judge-supplied scope definitions (CIDRs, subnets, domains, wildcards, port ranges `"8000-8100"`) wired through the real parser.
   - **L-03:** Generic objective evaluation (`discover_services`, `flag`, `severity_threshold`, fail-closed unknown) with verified-evidence requirements.
   - **L-04:** Bounded, explicitly authorized multi-step verification with per-step evidence and target-safe provenance.

4. **[04-tool-adapters-hardening.md](./04-tool-adapters-hardening.md)** — **COMPLETED & VERIFIED (12/12 tests)**
   - **X-01:** Nmap adapter restricted to target port set from scope allowlist; fails closed against unconstrained default scans.
   - **X-02:** ZAP adapter collection of baseline scan reports into evidence vault with verified SHA-256 and deterministic cleanup.
   - **X-03:** Nuclei adapter explicitly disables out-of-band interaction (`-ni` / `-no-interactsh`) and update checks (`-duc`).
   - **X-04:** Strictly typed Pydantic argument schemas (`NmapArgs`, `NucleiArgs`, `ZapArgs`) rejecting unknown parameters.
   - **X-05:** Hardened Docker runner container sandbox controls (`--cap-drop=ALL`, `--read-only`, non-root user `argus:1000`).

5. **[05-reporting-and-deliverables.md](./05-reporting-and-deliverables.md)** — **COMPLETED & VERIFIED (11/11 report tests)**
   - **E-03:** Markdown executive report generator wired into `report_node()`, with vault re-verification of every evidence hash and explicit simulation/partial labels.
   - **E-05:** Dependency-free paginated PDF and styled HTML deliverables with redacted reproduction steps.

6. **[06-api-and-dashboard.md](./06-api-and-dashboard.md)** — **COMPLETED & VERIFIED (9/9 API tests)**
   - **A-01:** FastAPI backend with SQLite WAL persistence and SSE live telemetry.
   - **A-02:** Same-origin, dependency-free judge dashboard with live SSE state, findings, and report links (Next.js retained as long-term target design).
   - **A-03:** Reproducible one-command `docker compose up` stack (API, dashboard proxy, authorized mock lab).

7. **[07-test-matrix-and-adversarial.md](./07-test-matrix-and-adversarial.md)** — **COMPLETED & VERIFIED (15 scenario + 12 adversarial/zero-hallucination tests)**
   - **T-01:** 15 mandatory test scenarios implementation.
   - **T-02:** Adversarial bypass tests (scope escapes, prompt injections, DNS rebinding).
   - **T-03:** End-to-end integration test against controlled mock lab.
   - **T-06:** Negative verification test proving zero fabricated findings on unfamiliar targets.

8. **[08-documentation-and-cleanup.md](./08-documentation-and-cleanup.md)** — **COMPLETED & VERIFIED (D-01 through D-08)**
   - **D-01 to D-08:** Relative links, consistent status labels, reconciled policy snippet, multi-step scope clarification, unified timeline, canonical scope schema, single 15-test matrix, and verified Bifrost docs.

