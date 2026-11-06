# Track 08 Tasks — Testing, Evaluation & Lab Setups

**Goal:** Implement and verify the complete evaluation harness for ARGUS according to `specs/08-testing-evaluation-and-labs.md`. This includes passing all 15 mandatory automated test scenarios, standing up standardized test labs (Lab A: Apache 2.4.49 web traversal, Lab B: multi-service network host), enforcing M1 Pro development constraints (10 MB artifact quota, concurrency limits), and ensuring an 80%+ test coverage gate.

---

## Task Distribution & Subagent Checklist

| Task ID | Description | Target Files | Dependencies | Status |
|---|---|---|---|---|
| **TASK-08-01** | 15 Mandatory Scenario Test Suite Verification | `tests/integration/test_scenarios.py`, `tests/security/` | Spec 08 §2 | Done |
| **TASK-08-02** | 10 MB Evidence Disk Quota & Memory Constraints | `core/evidence/evidence_vault.py`, `tests/unit/test_evidence_quota.py` | Spec 08 §4 | Done |
| **TASK-08-03** | Standardized Test Lab A: Vulnerable Web App (`lab-a-web`) | `infrastructure/labs/lab-a-web/*`, `tests/integration/test_e2e_lab.py` | Spec 08 §3.1 | Done |
| **TASK-08-04** | Standardized Test Lab B: Multi-Service Host (`lab-b-network`) | `infrastructure/labs/lab-b-network/*`, `tests/integration/test_lab_b_network.py` | Spec 08 §3.2 | Done |
| **TASK-08-05** | Coverage Verification & Gate Enforcement (80%+ Gate) | `pyproject.toml`, test runner | All | Done |

---

### TASK-08-01: 15 Mandatory Scenario Test Suite Verification
- **Objective:** Verify 100% pass rate for the 15 mandatory test scenarios covering security boundaries, failure recovery, Bifrost provider failover, and evidence integrity.
- **Verification:** `.venv/bin/pytest tests/integration/test_scenarios.py -v` (15/15 passed).

### TASK-08-02: 10 MB Evidence Disk Quota & Truncation Guardrail
- **Objective:** Enforce per-file 10 MB storage quota on scanner outputs in `EvidenceVault`. Outputs exceeding 10 MB are truncated cleanly with a `[TRUNCATED: Exceeded 10MB artifact limit]` marker and tagged in metadata, while maintaining valid cryptographic hashes.
- **Verification:** `.venv/bin/pytest tests/unit/test_evidence_quota.py -v` (2/2 passed).

### TASK-08-03: Lab A Vulnerable Web App (`infrastructure/labs/lab-a-web/`)
- **Objective:** Deliver standardized Apache 2.4.49 path traversal test environment with Dockerfile, mock server (`server.py`), authorized `scope.yaml`, and documentation.
- **Verification:** `.venv/bin/pytest tests/integration/test_e2e_lab.py -v`.

### TASK-08-04: Lab B Multi-Service Host (`infrastructure/labs/lab-b-network/`)
- **Objective:** Deliver standardized multi-service host test environment with FTP (`vsftpd 2.3.4`), SSH (`OpenSSH 8.4p1`), and HTTP healthcheck.
- **Verification:** `.venv/bin/pytest tests/integration/test_lab_b_network.py -v` (2/2 passed).

### TASK-08-05: Test Coverage & Gate Verification
- **Objective:** Run full test suite with coverage reporting to guarantee >80% coverage across core, engine, and integration packages.
- **Verification:** `.venv/bin/pytest tests --cov=core --cov=engine --cov=integrations` (231/231 passed, 86% coverage).

