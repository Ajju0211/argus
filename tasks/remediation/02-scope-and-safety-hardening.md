# Track 02 — Scope & Safety Policy Hardening

**Priority:** P0 (Deterministic safety firewall guarantees)  
**Status:** COMPLETED & VERIFIED (All 10 subtasks passing, 28/28 security tests in `tests/security/test_scope_and_safety_hardening.py`, 102/102 targeted suite, 124/124 total suite passing)  

---

## Subtask S-01: Port Allowlist Validation when Port is None
- **Status:** **COMPLETED**
- **Files:** `core/policy/policy_engine.py` (`_infer_target_port`, `_evaluate_internal`)
- **Implemented Changes:**
  1. Implemented `_infer_target_port()` to inspect `proposal.target_port`, `proposal.target_host` (e.g. `host:port`), and URL arguments (`target_url`, `url`, `target`, `matched_at`).
  2. For HTTP/HTTPS URLs without explicit ports, defaults to port 80/443.
  3. Validates inferred port against `scope.ports.denied_ports` and `scope.ports.allowed_ports`.
  4. Web/application actions with unspecified and non-inferrable ports fail closed when ports are restricted.
  5. Added `_parse_port_spec()` to expand and validate explicit port specs (ints, comma lists, ranges, mixed lists). Malformed or out-of-range specs (`0`, `65536`, `1-65536`, `abc`) are rejected.
  6. Recon actions that omit an explicit `ports` argument now fail closed whenever the scope restricts ports, so Nmap cannot fall back to its default top-1000 range.
- **Verification:**
  - `test_action_with_none_port_infers_from_url_and_blocks_unauthorized`: Passed (`http://192.168.100.5/` rejected when scope restricts to 8080).
  - `test_action_with_none_port_infers_from_url_and_approves_authorized`: Passed (`http://192.168.100.5:8080/` approved).
  - `test_web_action_without_port_fails_closed`: Passed.
  - `test_recon_port_range_outside_allowlist_is_blocked`: Passed (`1-65535` rejected against an 80/443 allowlist instead of being treated as "allowed").
  - `test_recon_without_explicit_ports_fails_closed`: Passed (missing `ports` is rejected).
  - `test_recon_with_allowlisted_comma_ports_is_approved`: Passed (`80,8080` accepted).

---

## Subtask S-02: Hostname DNS Pinning Against Rebinding Attacks
- **Status:** **COMPLETED**
- **Files:** `core/policy/policy_engine.py` (`_evaluate_internal`)
- **Implemented Changes:**
  1. Resolves hostname at validation time and records `resolved_ip` in `PolicyDecision`.
  2. When subnets are defined, verifies that `resolved_ip` is strictly within `allowed_subnets` or `allowed_hosts`.
  3. When an allowlisted hostname resolves to an unauthorized IP (e.g. `10.0.0.1` or `169.254.169.254`), blocks with DNS rebinding guard.
  4. Always blocks loopback, link-local, multicast, and reserved addresses.
  5. `AssessmentState` now carries `resolved_ip`. `policy_gate_node` stores the policy-approved IP, and `execute_tool_node` runs `_pin_proposal()` to re-resolve the hostname immediately before execution.
  6. If the hostname resolves to a different IP after approval, execution is blocked with a DNS-rebinding violation. For network recon, the approved IP is substituted as the scan target so the tool cannot independently re-resolve a different address.
- **Verification:**
  - `test_hostname_resolving_to_cloud_metadata_is_blocked`: Passed (`169.254.169.254` blocked).
  - `test_hostname_resolving_outside_scope_cidr_is_blocked`: Passed (`10.0.0.1` blocked).
  - `test_dns_rebinding_between_policy_and_execution_is_blocked`: Passed (approved `192.168.100.5`, re-resolved `10.0.0.1`; executor never invoked).

---

## Subtask S-03: Protocol Restriction Enforcement
- **Status:** **COMPLETED**
- **Files:** `core/policy/policy_engine.py` (`_extract_protocols`, `_evaluate_internal`)
- **Implemented Changes:**
  1. Extracts all protocols across URL arguments, hosts, and protocol fields via `_extract_protocols()`.
  2. Blocks protocols explicitly listed in `scope.protocols.denied`.
  3. Blocks any protocol not explicitly in `scope.protocols.allowed` (e.g. `file://`, `ftp://`, `gopher://`, `ssh://`).
  4. Added `_infer_protocols()` for scheme-less web actions: Nuclei/ZAP and web categories are treated as `http` or `https` based on the effective port (443/8443 -> HTTPS), preventing a bare-host action from bypassing an HTTPS-only scope.
- **Verification:**
  - `test_disallowed_protocols_blocked`: Passed (`file:///etc/passwd`, `ftp://`, `gopher://` blocked).
  - `test_schemeless_web_action_cannot_bypass_https_only_scope`: Passed (port 80 inferred as `http` and rejected when only `https` is allowed).

---

## Subtask S-04: HTTP Redirect Policy Enforcement
- **Status:** **COMPLETED**
- **Files:** `core/policy/policy_engine.py` (`validate_redirect`)
- **Implemented Changes:**
  1. Implemented `PolicyEngine.validate_redirect(initial_url, redirect_target_url)`.
  2. Enforces `scope.network_policy.redirect_policy`:
     - `strict_same_host`: Halts on differing host or port.
     - `in_scope_only`: Evaluates redirect target against scope CIDRs and allowed ports.
     - `block_all`: Halts on any HTTP redirect.
  3. Always blocks redirects to loopback, link-local, cloud metadata, or reserved IPs.
  4. Added `_preflight_http_redirects()` to the default executor: before running Nuclei or ZAP, it follows up to 5 redirect hops without auto-following and validates each hop with `validate_redirect()`. An out-of-policy hop blocks execution with exit code 126.
  5. Nuclei now runs with `-disable-redirects` so a redirect cannot be followed after preflight. ZAP remains protected by the preflight gate.
- **Verification:**
  - `test_redirect_strict_same_host_blocks_external_host`: Passed.
  - `test_redirect_strict_same_host_blocks_different_port`: Passed.
  - `test_redirect_to_cloud_metadata_is_blocked`: Passed.
  - `test_redirect_block_all_policy`: Passed.
  - `test_redirect_policy_is_enforced_before_http_tool_execution`: Passed (mock 302 to an out-of-policy port is rejected before the tool runs).

---

## Subtask S-05: Tool Registry Security Gate
- **Status:** **COMPLETED**
- **Files:** `core/executor/tool_registry.py` (`register`, `SecurityConfigurationError`)
- **Implemented Changes:**
  1. Added `SecurityConfigurationError` exception.
  2. `ToolRegistry.register()` enforces:
     - Non-empty `capabilities` and `categories`.
     - Valid `risk_level` (`LOW`, `MEDIUM`, `HIGH`).
     - Injection resistance test: validates that `adapter.validate_args()` rejects dangerous shell tokens.
- **Verification:**
  - `test_tool_registry_rejects_adapter_missing_capabilities`: Passed.
  - `test_tool_registry_rejects_adapter_allowing_shell_injection`: Passed.

---

## Subtask S-06: Rate Limits, Concurrency, and Timeouts
- **Status:** **COMPLETED**
- **Files:** `engine/nodes/evaluate_completion.py`, `core/executor/process_runner.py`, `core/executor/rate_limiter.py`, `engine/graph.py`
- **Implemented Changes:**
  1. Added `started_at` parameter to `evaluate_completion()`.
  2. If assessment duration exceeds `budget.max_duration_seconds`, completes assessment deterministically with `PARTIAL_SUCCESS` or `FAILED`.
  3. `run_tool_process` enforces per-tool execution timeouts with hard process group kill.
  4. Added `ToolRateLimiter` (thread-safe token-spacing limiter plus `BoundedSemaphore` concurrency cap). The default executor wraps every tool invocation in `limit()` using `scope.rate_limits.max_requests_per_second` and `max_concurrency`.
  5. Effective execution timeout is now `min(proposal.timeout_seconds, scope.tool_timeouts[tool] or scope.rate_limits.tool_timeout_seconds, DEFAULT_TOOL_TIMEOUT_SECONDS)`.
- **Verification:**
  - `test_global_assessment_duration_timeout_enforced`: Passed.
  - `test_rate_limiter_enforces_scope_interval`: Passed (two acquisitions at 5 rps take at least 150 ms).
  - `test_rate_limiter_enforces_concurrency_cap`: Passed (4 workers never exceed 2 concurrent slots).

---

## Subtask S-07: Process Group Isolation for Tool Cancellation
- **Status:** **COMPLETED**
- **Files:** `core/executor/process_runner.py` (`kill_process_group`)
- **Implemented Changes:**
  1. Spawns tools in independent process group sessions (`start_new_session=True`).
  2. Implemented `kill_process_group(pid)` sending `SIGTERM` followed by `SIGKILL` to `os.killpg(pgid)`.
  3. Handles non-existent processes and POSIX/Windows differences safely.
- **Verification:**
  - `test_kill_process_group_safe_on_invalid_pid`: Passed.

---

## Subtask S-08: Execution Exceptions and Timeout Connection to Recovery State
- **Status:** **COMPLETED**
- **Files:** `engine/graph.py` (`execute_tool_node`)
- **Implemented Changes:**
  1. Wrapped `tool_executor(proposal)` in try/except catching `TimeoutError` and unexpected exceptions.
  2. Formulates returncode 124 for timeouts, records error artifact in `EvidenceVault`, and increments `consecutive_failures` with `FailureType.RECOVERABLE_TIMEOUT`.
  3. Ensures LangGraph workflow never crashes on unexpected tool exceptions.
- **Verification:**
  - `test_execute_tool_timeout_transitions_to_adaptive_recovery`: Passed.
  - `test_execute_tool_unhandled_exception_transitions_to_recovery`: Passed.

---

## Subtask S-09: Action Deduplication and Retry Semantics
- **Status:** **COMPLETED**
- **Files:** `packages/contracts/actions.py` (`ActionProposal.fingerprint`)
- **Implemented Changes:**
  1. Uses `json.dumps(self.arguments, sort_keys=True, default=str)` for deterministic parameter hashing.
  2. Unchanged proposals generate identical fingerprints regardless of key ordering or complex types.
- **Verification:**
  - `test_action_fingerprint_deterministic_with_mixed_args`: Passed.

---

## Subtask S-10: Scope Conflict Detection & Default-Denied Infrastructure
- **Status:** **COMPLETED**
- **Files:** `core/scope/validator.py`, `core/policy/policy_engine.py`
- **Implemented Changes:**
  1. `ScopeValidator.validate_scope_document()` strictly rejects scope files attempting to authorize `127.0.0.0/8`, `169.254.0.0/16`, or `224.0.0.0/4` in `allowed_subnets`.
  2. `PolicyEngine` checks `denied_hosts` and `denied_ports` strictly before `allowed_hosts` and `allowed_ports`.
- **Verification:**
  - `test_scope_validator_rejects_authorizing_loopback_subnet`: Passed.
  - `test_scope_validator_rejects_authorizing_link_local_subnet`: Passed.
  - `test_denied_hosts_takes_precedence_over_allowed_hosts`: Passed.
