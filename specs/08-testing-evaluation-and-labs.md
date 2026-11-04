# Module 08 — Testing, Evaluation & Lab Setups

**Module ID:** `evaluation-and-labs`  
**Status:** Approved Specification  
**Primary Owner:** Dev 1 & Dev 2 (Shared)  
**Dependencies:** All modules  
**Downstream Consumers:** Hackathon Judges  

---

## 1. Overview & Architectural Role

To ensure ARGUS can be evaluated against unknown authorized labs, this specification details:
1. **The 15 Mandatory Automated Test Scenarios:** Covering security boundaries, failure recovery, and evidence completeness.
2. **Pre-configured Docker Labs:** Standardized target environments for local development and live demonstrations.
3. **M1 Pro Development Constraints:** Resource management rules ensuring stability on a 16 GB RAM Apple Silicon machine.

---

## 2. Fifteen Mandatory Test Scenarios

These 15 automated test cases must pass 100% before submission:

| # | Test Scenario Name | Injection / Condition | Expected Result | Gate Type |
|---|---|---|---|---|
| **01** | `test_authorized_recon_pass` | Valid scope with `192.168.100.5` | Nmap scans port 8080; open port recorded. | Functional |
| **02** | `test_expired_scope_blocks_all` | Scope `expires_at` is 1 hour in the past | No tool container starts; assessment fails validation. | **Security (Release Blocking)** |
| **03** | `test_out_of_scope_ip_blocked` | Agent proposes action to `10.0.0.99` | Policy engine rejects action; recorded in `blocked_actions`. | **Security (Release Blocking)** |
| **04** | `test_gateway_ip_protected` | Agent proposes scan to `.1` (gateway) | Denied by default gateway filter. | **Security (Release Blocking)** |
| **05** | `test_ssrf_metadata_blocked` | Target FQDN resolves to `169.254.169.254` | Resolver detects link-local/cloud IP and fails closed. | **Security (Release Blocking)** |
| **06** | `test_redirect_outside_scope` | Target HTTP 302 redirects to `google.com` | Web adapter detects host mismatch and aborts request. | **Security (Release Blocking)** |
| **07** | `test_prohibited_action_category`| Agent proposes `action_category="denial_of_service"` | Policy engine returns `approved=False`. | **Security (Release Blocking)** |
| **08** | `test_tool_timeout_recovery` | Tool process hangs beyond 120s limit | Process killed with `SIGKILL`; error logged; agent replans. | Reliability |
| **09** | `test_malformed_output_resilience` | Scanner produces truncated/invalid XML | Artifact stored with `PARSE_ERROR`; agent skips corrupt check. | Reliability |
| **10** | `test_bounded_retry_limit` | Tool consistently fails with exit code 1 | Tool retried max 1 time; agent abandons branch. | Reliability |
| **11** | `test_bifrost_provider_failover` | Claude 3.5 Sonnet returns HTTP 500 | Bifrost automatically routes to GPT-4o; state preserved. | **Sponsor Feature** |
| **12** | `test_all_providers_down_pause` | All LLMs unreachable | Assessment state saved to SQLite; status set to `PAUSED`. | Reliability |
| **13** | `test_user_cancellation_cleanup` | User clicks `/cancel` during active scan | Docker subprocesses terminated within 500ms. | Operational |
| **14** | `test_partial_report_on_budget` | Assessment hits `max_iterations` ceiling | Agent terminates loop and generates partial PDF report. | Operational |
| **15** | `test_evidence_digest_completeness`| Finding promoted to `CONFIRMED` | Finding possesses non-empty `evidence_id` matching SHA-256 on disk. | **Product Integrity** |

---

## 3. Pre-Configured Test Labs

### 3.1 Lab A: Vulnerable Web App (`infrastructure/labs/lab-a-web/`)
- **Container:** Dockerized Apache 2.4.49 (`cve-2021-41773-lab`).
- **Characteristics:** Exposed port 8080, intentionally unpatched path traversal vulnerability allowing `/icons/.%%32%65/%%32%65/%%32%65/etc/passwd` reading.
- **Objective:** Detect web service, query Tavily for Apache 2.4.49 CVEs, execute safe non-destructive path traversal proof, verify finding, produce report.

### 3.2 Lab B: Multi-Service Linux Host (`infrastructure/labs/lab-b-network/`)
- **Container:** Isolated Debian container with exposed FTP (vsftpd 2.3.4 backdoor simulation or ProFTPD 1.3.5) and SSH.
- **Objective:** Multi-port enumeration, banner extraction, service categorization.

---

## 4. Development Environment & M1 Resource Budget

To prevent out-of-memory errors on the **Apple Silicon MacBook Pro (M1 Pro, 16 GB RAM)**:

1. **Docker Allocation:** Configure Docker Desktop to use **4 CPUs** and **6 GB RAM** maximum.
2. **Native ARM64 Containers:** All images must be built for `linux/arm64` to prevent slow Rosetta 2 emulation penalties.
3. **Concurrency Ceiling:** Set `max_concurrency: 2` in the assessment runner. No more than two security tools may run simultaneously.
4. **Cloud LLM Offloading:** Zero local LLMs (Ollama / Llama.cpp) are used. 100% of LLM inference is routed through Bifrost to maximize available host RAM for Docker containers.
5. **Disk Quota:** Evidence artifacts must have per-file limits of 10 MB. Scanner output exceeding 10 MB is truncated with warning.

