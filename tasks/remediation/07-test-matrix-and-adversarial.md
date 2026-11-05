# Track 07 — Test Matrix & Adversarial Suite

**Priority:** P1 (Essential for verifying robustness and passing hackathon judge evaluation)  
**Status:** Complete (verified 2026-11-05)

---

## Subtask T-01: 15 Mandatory Evaluation Scenarios
- **File:** `tests/integration/test_scenarios.py`
- **Implemented:** Automated coverage for all 15 required scenarios
  (`TestFifteenMandatoryScenarios`):
  1. `test_authorized_recon_pass` — authorized recon completes.
  2. `test_expired_scope_blocks_all` — expired authorization blocks execution.
  3. `test_out_of_scope_ip_blocked` — out-of-scope address denied.
  4. `test_gateway_ip_protected` — default gateway/loopback protected.
  5. `test_ssrf_metadata_blocked` — cloud metadata endpoint denied.
  6. `test_redirect_outside_scope` — redirect outside scope blocked.
  7. `test_prohibited_action_category` — prohibited action categories denied.
  8. `test_tool_timeout_recovery` — tool timeout recovers safely.
  9. `test_malformed_output_resilience` — malformed tool output is handled.
  10. `test_bounded_retry_limit` — retries stay inside budget.
  11. `test_bifrost_provider_failover` — provider failover path works.
  12. `test_all_providers_down_pause` — all providers down stops safely.
  13. `test_user_cancellation_cleanup` — cancellation preserves state.
  14. `test_partial_report_on_budget` — budget exhaustion yields a partial report.
  15. `test_evidence_digest_completeness` — evidence digests are complete.
- **Acceptance evidence:** all 15 tests pass as part of the full suite.

---

## Subtask T-02: Adversarial Security Bypass Suite
- **File:** `tests/security/test_adversarial_bypasses.py`
- **Implemented coverage:**
  1. DNS rebinding to metadata service (`169.254.169.254`) is denied.
  2. Scope evasion via encoded URLs (`http://allowed.host%2f@attacker.com`),
     embedded credentials, and protocol/port mismatches is denied by
     `_validate_embedded_targets()` in `core/policy/policy_engine.py`.
  3. Prompt injection in target HTTP headers cannot alter scope or policy.
  4. Path traversal escaping the evidence vault (`../../etc/passwd`) is denied
     and cannot read or write outside the vault.
- **Acceptance evidence:** all adversarial tests pass; `ruff` clean.

---

## Subtask T-03: End-to-End Controlled Lab Integration Test
- **File:** `tests/integration/test_e2e_lab.py`
- **Implemented:** Starts a real local HTTP server with an Apache 2.4.49 banner
  and a deterministic traversal endpoint. The orchestrator discovers the
  service, performs Tavily research, runs a Nuclei-style verification probe,
  captures raw proof in the evidence vault, verifies integrity, and emits a
  client-ready report.
- **Assertions:** found asset/service, Tavily source reference, exactly one
  `CONFIRMED` HIGH finding, valid evidence hashes, raw `root:x:0:0` proof,
  every executed action on the authorized host, report references the CVE and
  evidence, and the report is labelled `SIMULATION MODE`.
- **Acceptance evidence:** end-to-end test passes.

---

## Subtask T-06: Negative Verification Test (Zero Fabrications)
- **File:** `tests/security/test_zero_hallucination.py`
- **Implemented:** Runs the orchestrator against a benign lab (nginx-like HTTP
  and OpenSSH-only surface) and asserts:
  1. No Apache 2.4.49 service is recorded.
  2. No CVE-2021-41773 finding is confirmed.
  3. Finding count is exactly 0.
- **Acceptance evidence:** zero-hallucination test passes.

---

## Track Verification Snapshot

| Check | Command | Result |
|---|---|---|
| Full suite (all tracks) | `.venv/bin/pytest -q` | **215 passed** |
| API + dashboard | `.venv/bin/pytest -q tests/integration/test_api.py` | **9 passed** |
| Lint | `.venv/bin/ruff check .` | clean |
| Types | `.venv/bin/mypy core engine integrations packages apps` | clean |
