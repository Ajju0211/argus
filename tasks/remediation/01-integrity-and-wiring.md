# Track 01 — Core Integrity & Execution Wiring

**Priority:** P0 (Must be resolved before live testing or judge evaluation)  
**Status:** COMPLETED & VERIFIED (All 5 subtasks passing, 12/12 security tests in `tests/security/test_integrity_wiring.py`, 124/124 total suite passing)  

---

## Subtask C-01: Remove Hardcoded Reconnaissance Observations
- **Status:** **COMPLETED**
- **Files:** `engine/graph.py` (`recon_node`)
- **Implemented Changes:**
  1. Extracted target host and port via `_extract_target_host_and_port(state["target"])`.
  2. Built dynamic `recon_args` constrained to target and `scope.ports.allowed_ports`.
  3. Ran discovery tool adapter via `self.tool_executor` and saved raw scan output directly to `EvidenceVault`.
  4. Parsed real Nmap XML using `adapter.parse_output()`, deriving `discovered_assets`, `discovered_services`, and `observations` solely from verified parser observations.
  5. Completely removed hardcoded `target_port = 8080` and `Apache 2.4.49`.
- **Verification:**
  - `test_recon_uses_real_parsed_observations`: Passed.
  - `test_recon_does_not_invent_apache_when_absent`: Passed (SSH-only target produces only port 22; 0 Apache or 8080 observations).
  - `test_recon_records_empty_output_without_fabrication`: Passed.

---

## Subtask C-02: Eliminate Fabricated Findings in Finding Verification
- **Status:** **COMPLETED**
- **Files:** `engine/graph.py` (`verify_finding_node`)
- **Implemented Changes:**
  1. Completely removed hardcoded `Path Traversal (CVE-2021-41773)` from `verify_finding_node`.
  2. Iterates over actual `vuln_candidate` observations produced by active tool adapters.
  3. Validates evidence provenance: every finding requires a valid `raw_evidence_id` that is cryptographically verified against `EvidenceVault.verify_integrity()`.
  4. Promotes finding to `CONFIRMED` only when cryptographic digest matches and verification reproduction steps exist using `FindingVerifier`.
  5. Findings with missing or tampered evidence are rejected or ignored.
- **Verification:**
  - `test_cannot_confirm_finding_without_evidence`: Passed.
  - `test_cannot_confirm_finding_with_tampered_evidence`: Passed (tampered on-disk file fails SHA-256 check; 0 findings confirmed).
  - `test_unfamiliar_target_produces_zero_confirmed_findings`: Passed.

---

## Subtask C-03: Real Tool Execution Path Wiring
- **Status:** **COMPLETED**
- **Files:** `engine/graph.py` (`execute_tool_node`, `_default_tool_executor`)
- **Implemented Changes:**
  1. Implemented `_default_tool_executor` resolving tools dynamically via `ToolRegistry.get()`.
  2. Validates parameters with `adapter.validate_args()` and generates arguments via `adapter.build_command()`.
  3. Checks local system binary availability via `shutil.which()`.
  4. Runs subprocesses using hardened `run_tool_process` with detached process groups and `SIGKILL` on timeout.
  5. In `execute_tool_node`, streams raw output directly into `EvidenceVault`, parses observations with `adapter.parse_output()`, and attaches cryptographic `evidence_id`s to observations and evidence refs.
- **Verification:**
  - `test_execute_tool_wires_vault_and_observations`: Passed.
  - `test_failed_tool_execution_records_error_evidence`: Passed.

---

## Subtask C-04: Replace Placeholder Evidence IDs with Cryptographic Hashes
- **Status:** **COMPLETED**
- **Files:** `engine/graph.py`, `core/evidence/evidence_vault.py`
- **Implemented Changes:**
  1. Removed placeholder IDs like `"ev-001"`.
  2. All tool outputs are stored through `EvidenceVault.store_artifact()`, which generates unique IDs formatted `ev-YYYYMMDDHHMMSS-<8-char-sha256>`.
  3. Observations, findings, and evidence references strictly point to these verified SHA-256 artifact digests.
- **Verification:**
  - `test_recon_links_observations_to_cryptographic_evidence_id`: Passed (`vault.verify_integrity` verified).
  - `test_all_evidence_ids_are_cryptographically_verifiable`: Passed.

---

## Subtask C-05: Prevent Default Mocks from Producing False "Success"
- **Status:** **COMPLETED**
- **Files:** `core/config.py`, `engine/graph.py`
- **Implemented Changes:**
  1. Added `SIMULATION_MODE: bool = False` to `core/config.py` Settings.
  2. In production mode (`SIMULATION_MODE=False`), missing binaries return exit code 127 and clean stderr without inventing successful execution or findings.
  3. In simulation mode (`SIMULATION_MODE=True`), mock outputs are explicitly labeled with `[SIMULATION_MODE]`.
  4. **Model-gateway fail-closed selection:** if no `model_gateway` is injected, no `BIFROST_API_KEY` is configured, and simulation is off, the orchestrator selects `_fail_closed_model_gateway()`, which returns `DecisionType.BLOCKED` instead of a mock "objective achieved".
  5. The simulation mock planner now also prefixes its rationale and completion summary with `[SIMULATION_MODE]` so downstream artifacts cannot be mistaken for live model output.
- **Verification:**
  - `test_production_mode_rejects_missing_tool_execution`: Passed.
  - `test_simulation_mode_labeled_when_enabled`: Passed.
  - `test_missing_model_gateway_fails_closed_outside_simulation`: Passed (returns `BLOCKED`, no fabricated success).
  - `test_simulation_mode_model_gateway_is_labeled`: Passed (`[SIMULATION_MODE]` present).
