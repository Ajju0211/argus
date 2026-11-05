# Track 04 — Tool Adapters Hardening

**Priority:** P1 (Ensures tool invocations comply with sandbox and scope rules)  
**Status:** COMPLETED & VERIFIED (12/12 unit tests in `tests/unit/test_tool_adapters_hardening.py`, total suite 161/161 passing)

---

## Subtask X-01: Constrain Nmap Adapter to Scope Port Allowlist
- **Files:** `integrations/tools/nmap_adapter.py`
- **Issue:** Without port parameters, Nmap defaults to scanning top 1,000 ports, which may scan ports outside the scope allowlist.
- **Action Taken:**
  1. Configured `NmapAdapter` to accept `allowed_ports` at initialization or via `allowed_ports` argument.
  2. If explicit `ports` is omitted but allowlist is configured, dynamically builds `-p <ports>` using allowlisted ports.
  3. Rejects scans if requested ports fall outside the allowlist, or if no ports and no allowlist are provided (fail-closed against unconstrained 1,000-port scans).
- **Verification:** Verified via `test_nmap_without_ports_uses_allowed_ports_from_adapter`, `test_nmap_without_ports_and_no_allowed_ports_fails_closed`, `test_nmap_rejects_ports_outside_allowlist`, and `test_nmap_approves_ports_within_allowlist`.

---

## Subtask X-02: ZAP Adapter Baseline Report Collection
- **Files:** `integrations/tools/zap_adapter.py`, `core/evidence/evidence_vault.py`
- **Issue:** ZAP writes JSON report to a local temp file, which may be missed or deleted before raw evidence is archived.
- **Action Taken:**
  1. Added `collect_report_to_vault()` reading the local JSON report file, archiving raw report content directly into `EvidenceVault.store_artifact()`, and calculating verified SHA-256 hash.
  2. Guaranteed cleanup of local temporary report files in `finally` blocks.
  3. Automatically parsed normalized vulnerability observations linked to the stored evidence artifact.
- **Verification:** Verified via `test_zap_collect_report_to_vault_and_clean_temp`.

---

## Subtask X-03: Nuclei Out-of-Band Disabling (`-ni`)
- **Files:** `integrations/tools/nuclei_adapter.py`
- **Issue:** Nuclei templates may attempt out-of-band callback requests (Interactsh), generating external network traffic violating strict scope boundaries.
- **Action Taken:**
  1. Added `-ni` (`-no-interactsh`) to `build_command` to disable all out-of-band network callbacks.
  2. Added `-duc` (`-disable-update-check`) to suppress outbound ProjectDiscovery version check requests.
- **Verification:** Verified via `test_nuclei_command_contains_ni_and_duc` and updated `test_safe_command_building`.

---

## Subtask X-04: Tool Argument Schemas and Parameter Whitelisting
- **Files:** `integrations/tools/base.py`, `integrations/tools/nmap_adapter.py`, `integrations/tools/nuclei_adapter.py`, `integrations/tools/zap_adapter.py`
- **Issue:** Loosely typed argument dictionaries allow arbitrary or malformed arguments.
- **Action Taken:**
  1. Introduced `BaseToolArgs(BaseModel)` with `model_config = ConfigDict(frozen=True, extra="forbid")`.
  2. Implemented typed Pydantic models `NmapArgs`, `NucleiArgs`, and `ZapArgs` defining permitted parameters and strict validators (injection rejection, path traversal protection).
  3. Integrated `args_schema` property across adapters; `validate_args()` automatically rejects unknown or extra parameters before execution.
- **Verification:** Verified via `test_nmap_rejects_unknown_extra_parameters`, `test_nuclei_rejects_unknown_extra_parameters`, and `test_zap_rejects_unknown_extra_parameters`.

---

## Subtask X-05: Docker Runner Sandbox Lockdown
- **Files:** `infrastructure/docker/runner.Dockerfile`, `core/executor/process_runner.py`
- **Issue:** Runner container must operate with least privilege to prevent container breakout.
- **Action Taken:**
  1. Updated `infrastructure/docker/runner.Dockerfile` to create unprivileged `argus` user (UID 1000, GID 1000), make `/templates/pinned` read-only (`chmod 555`), set dedicated `/tmp` with sticky bit, and add security labels.
  2. Added `build_docker_sandbox_command()` in `core/executor/process_runner.py` enforcing `--cap-drop=ALL`, `--read-only`, `--security-opt=no-new-privileges:true`, `--user=1000:1000`, and dedicated tmpfs `--tmpfs=/tmp:rw,noexec,nosuid,size=64m`.
  3. Added `verify_docker_sandbox_security()` verifying compliance and flagging security violations (such as root user execution).
- **Verification:** Verified via `test_build_docker_sandbox_command_enforces_least_privilege`, `test_verify_docker_sandbox_security_detects_violations`, and `test_dockerfile_uses_unprivileged_user_and_read_only_templates`.

