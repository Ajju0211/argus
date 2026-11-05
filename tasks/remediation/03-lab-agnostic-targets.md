# Track 03 — Lab-Agnostic Targets & Objectives

**Priority:** P1 (Essential for evaluating any judge-provided target environment)  
**Status:** COMPLETED & VERIFIED (46/46 Track 03 tests: 22 in `tests/unit/test_lab_agnostic_targets.py` + 24 in `tests/unit/test_track03_hardening.py`; full suite 160/160 passing)

---

## Subtask L-01: Extract Target Host and Port from Any Arbitrary Target Spec
- **Files:** `engine/graph.py`, `packages/contracts/scope.py`
- **Issue:** The workflow previously expected fixed targets or fell back to port `8080`.
- **Action Taken:**
  1. Implemented `extract_target_spec()` in `engine/graph.py` parsing arbitrary URLs (`http://host:3000/app`), explicit ports (`:3000`), IPv6 literals (`[2001:db8::1]:8080`), bare IPv6 addresses, host:port strings, scheme-less host/path strings, and bracket IPv6 with port/path (`[2001:db8::1]:9090/metrics`).
  2. Inferred scheme defaults (80 for http, 443 for https).
  3. Updated `_extract_target_host_and_port()` and `recon_node()` to dynamically bind and route scanning to target-specified ports (e.g. 3000) rather than defaulting to 8080.
- **Verification:** `test_extract_url_with_explicit_port_and_path`, `test_extract_ipv6_literal_with_port`, `test_extract_bare_ipv6_without_port`, `test_recon_node_routes_to_extracted_target_port`, `test_extract_scheme_less_ipv6_with_port_and_path`, and `test_extract_scheme_less_host_with_path` all pass.

---

## Subtask L-02: Flexible Judge-Supplied Scope Formats
- **Files:** `packages/contracts/scope.py`, `core/scope/validator.py`, `core/policy/policy_engine.py`
- **Issue:** Judges or evaluation harnesses may supply scopes using varying field formats (e.g., list of CIDRs, mixed hostnames and IPs, single URL string, flattened aliases, port ranges).
- **Action Taken:**
  1. Added `PortConfig` before-validator parsing port range strings (`"8000-8100"`), comma-separated strings (`"80,443"`), and integer lists. Invalid comma tokens now fail clearly instead of being silently dropped.
  2. Implemented `normalize_scope()` accepting dict, JSON, or YAML, extracting CIDR subnets, hostnames, ports, IPv6 literals, and aliases (`allowed_actions`, `permitted_actions`, `action_categories`, `allowed_ports`, `target_ports`, `allowed_hosts`, `allowed_subnets`, `denied_hosts`, `target`).
  3. `normalize_scope()` now accepts scalar `targets` strings, list targets, nested target dictionaries, and top-level target fields.
  4. **Wired normalization into the real parse path:** `ScopeValidator.parse_yaml_string()` and `parse_yaml_file()` now route through `normalize_scope()`, so judge YAML actually benefits from alias handling.
  5. Harmless metadata fields (`environment`, `description`, `tags`, `metadata`, `judge`, `lab`, etc.) are accepted. Unknown security-relevant fields are rejected with a clear `Unsupported scope field(s)` error instead of being silently ignored.
  6. Added wildcard hostname matching (`*.lab.internal`) in `PolicyEngine` with DNS rebinding and IP confinement checks.
  7. Exported `ScopeValidator.normalize_scope()`.
- **Verification:** `test_port_config_range_expansion`, `test_normalize_scope_minimal_dict`, `test_normalize_scope_with_aliases_and_subnets`, `test_normalize_scope_ipv6_literal`, `test_wildcard_hostname_matching_in_policy_engine`, `test_scalar_target_string_is_normalized`, `test_top_level_target_aliases_are_normalized`, `test_harmless_extra_metadata_is_accepted`, `test_unknown_security_field_fails_clearly`, `test_invalid_comma_port_token_is_rejected`, `test_parse_yaml_string_normalizes_aliases`, and `test_parse_yaml_string_accepts_harmless_metadata` all pass.

---

## Subtask L-03: Generic Objective Evaluation
- **Files:** `engine/nodes/evaluate_completion.py`, `engine/graph.py`, `packages/contracts/actions.py`
- **Issue:** `evaluate_completion` previously had rigid logic biased towards finding specific CVEs (`find_cve`).
- **Action Taken:**
  1. Upgraded `evaluate_completion()` to support typed objective evaluation:
     - `discover_services` / `reconnaissance_complete`: Completes when assets and services are discovered without requiring CVEs.
     - `flag` / `capture_the_flag`: Completes only when an explicit `flag{...}` pattern (or the exact expected flag) is present in flag-bearing observation fields, **and** the cited evidence ID is cryptographically verified.
     - `severity_threshold`: Completes when a verified finding meets or exceeds the required threshold (e.g., `HIGH` or `CRITICAL`).
     - Fail-closed handling for unknown or unsupported objective types (`outcome="FAILED"`).
  2. `evaluate_completion_node()` now passes a `verified_evidence_ids` set built from `EvidenceVault.verify_integrity()`. Flag goals fail closed if verification is unavailable or fails.
  3. Removed the previous false-positive behavior where any text containing the substring `"flag"` (for example, `"no flag present"`) counted as a capture.
- **Verification:** `test_discover_services_objective_succeeds_without_cve`, `test_flag_capture_objective_succeeds_when_flag_found`, `test_severity_threshold_objective`, `test_unknown_objective_type_fails_closed`, `test_flag_goal_does_not_treat_descriptive_text_as_capture`, `test_flag_goal_requires_a_matching_flag_pattern`, and `test_flag_goal_requires_verified_evidence` all pass.

---

## Subtask L-04: Multi-Step Chained Verification
- **Files:** `engine/graph.py`, `engine/state.py`, `packages/contracts/actions.py`, `packages/contracts/scope.py`, `core/policy/policy_engine.py`, `engine/nodes/evaluate_completion.py`, `engine/prompts.py`
- **Issue:** Confirming a complex finding requires linking follow-up verification actions to prior observations and preserving evidence provenance. The brief permits bounded multi-step movement only when explicitly authorized.
- **Action Taken:**
  1. Added `parent_action_id: str | None` and `step_index: int | None` to `ActionProposal`.
  2. Added an explicit `authorized_chain` scope envelope (`ChainConfig` / `ChainStepConfig`) with `enabled`, `max_steps`, and per-step `action_category`, `allowed_hosts`, and `allowed_ports`.
  3. `PolicyEngine` now refuses a proposal carrying chain metadata unless the scope explicitly enables the chain, the step is declared, and its category, host, and port match the declaration.
  4. `AssessmentState` now tracks `chain_progress` (per-step action, target, and evidence ID) and `chain_summary` (authorization and executed steps for reporting).
  5. `recon_node()` tags initial recon as step 1 for multi-step objectives, so an unauthorized chain is blocked before any tool runs.
  6. `execute_tool_node()` records per-step evidence progress only after successful execution.
  7. `evaluate_completion()` for `multi_step` / `chain` now requires a verified evidence ID for every required step. It no longer completes based on action arguments alone.
  8. `report_node()` now emits a `chain_summary` describing authorization, declared steps, and executed steps, ready for the Track 05 report generator.
  9. `ActionProposal.fingerprint()` now includes `action_category`, `parent_action_id`, and `step_index`, so a legitimate later chain step is not rejected as a duplicate.
  10. `verify_finding_node()` now chains discovery evidence only when it belongs to the same target; evidence tied to another host is never cited in the finding proof.
  11. Added planner guidance for bounded multi-step actions.
- **Verification:** `test_action_proposal_step_index_and_parent_action_id`, `test_multi_step_objective_evaluation`, `test_verify_finding_chains_discovery_and_active_evidence`, `test_fingerprint_distinguishes_chain_steps`, `test_chain_step_requires_explicit_scope_authorization`, `test_authorized_chain_steps_are_approved`, `test_chain_step_outside_declared_host_is_blocked`, `test_chain_step_outside_declared_step_count_is_blocked`, `test_chain_step_wrong_category_is_blocked`, `test_multi_step_completion_requires_verified_evidence_per_step`, `test_recon_for_multi_step_objective_is_blocked_without_chain_scope`, `test_report_node_includes_chain_authorization_summary`, and `test_finding_does_not_chain_evidence_from_another_target` all pass.

---

## Verification Commands

```bash
.venv/bin/pytest -q tests/unit/test_lab_agnostic_targets.py tests/unit/test_track03_hardening.py
.venv/bin/pytest -q
.venv/bin/ruff check packages/contracts/scope.py packages/contracts/actions.py \
  core/scope/validator.py core/policy/policy_engine.py \
  engine/nodes/evaluate_completion.py engine/graph.py engine/state.py engine/prompts.py \
  tests/unit/test_lab_agnostic_targets.py tests/unit/test_track03_hardening.py
.venv/bin/mypy core engine integrations packages
```

**Expected results:** 46 Track 03 tests pass, 160 total tests pass, targeted `ruff` clean, `mypy` clean.

---

## Scope Note

L-04 implements **bounded, explicitly authorized** multi-step verification. It does not introduce unrestricted shell access, tunneling, pivoting, or lateral movement. Any step outside the declared chain envelope is denied by the deterministic policy engine.
