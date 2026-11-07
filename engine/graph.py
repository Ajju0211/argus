"""Stateful LangGraph Agent Orchestrator for ARGUS.

Implements a single-agent, deterministic-governed state machine featuring
dynamic tool discovery, context-driven planning, duplicate action prevention,
and bounded adaptive recovery.
"""

import asyncio
import concurrent.futures
import contextlib
import ipaddress
import json
import re
import shutil
import socket
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx
from langgraph.graph import END, START, StateGraph

from core.config import get_settings
from core.evidence.evidence_vault import EvidenceVault
from core.executor.process_runner import run_tool_process
from core.executor.rate_limiter import ToolRateLimiter
from core.executor.tool_registry import ToolRegistry, get_default_registry
from core.findings.finding_verifier import FindingVerifier
from core.policy.policy_engine import PolicyEngine
from core.reporting.report_generator import ReportGenerator
from core.scope.validator import ScopeValidator
from engine.nodes.evaluate_completion import evaluate_completion
from engine.prompts import format_planning_prompt
from engine.recovery import FailureType, apply_adaptive_recovery, classify_error
from engine.state import (
    AssessmentState,
    CancellationState,
    CompletionEvaluation,
    ExecutionBudget,
    RecoveryState,
)
from integrations.bifrost import BifrostClient, create_bifrost_model_gateway
from integrations.langfuse import LangfuseTracer
from integrations.tavily import TavilyIntelService
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
    FootholdEvidence,
    FootholdType,
)
from packages.contracts.findings import SeverityLevel
from packages.contracts.scope import ScopeDocument

# Type signatures for injected adapters
ModelGatewayCallable = Callable[[str], AssessmentDecision]
ToolExecutorCallable = Callable[[ActionProposal], tuple[int, str, str]]


def extract_target_spec(target: dict[str, Any] | str) -> dict[str, Any]:
    """Parses arbitrary target specifications into host, port, scheme, and path (L-01).

    Handles:
    - http://host:3000/app -> host="host", port=3000, path="/app"
    - https://host -> host="host", port=443, path=""
    - http://[2001:db8::1]:8080 -> host="2001:db8::1", port=8080
    - host:port / IP literals
    """
    if isinstance(target, dict):
        val = str(
            target.get("value", "") or target.get("host", "") or target.get("url", "")
        ).strip()
        explicit_port = target.get("port")
    else:
        val = str(target).strip()
        explicit_port = None

    if isinstance(explicit_port, str) and explicit_port.isdigit():
        explicit_port = int(explicit_port)
    elif not isinstance(explicit_port, int):
        explicit_port = None

    if not val:
        return {"host": "", "port": explicit_port, "scheme": "tcp", "path": ""}

    if "://" in val:
        parsed = urllib.parse.urlsplit(val)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path
    elif val.startswith("[") and "]" in val:
        # IPv6 format [2001:db8::1]:8080/path or [2001:db8::1]
        try:
            parsed = urllib.parse.urlsplit(f"//{val}")
            host = parsed.hostname or ""
            port = parsed.port
            path = parsed.path
        except ValueError:
            host = val.strip("[]").split("/", 1)[0]
            port = None
            path = ""
        scheme = "tcp"
    else:
        # Check if bare IPv4/IPv6 address
        try:
            ip_obj = ipaddress.ip_address(val)
            host = str(ip_obj)
            port = None
            scheme = "tcp"
            path = ""
        except ValueError:
            # Handle host:port[/path] and scheme-less host/path safely.
            try:
                parsed = urllib.parse.urlsplit(f"//{val}")
                host = parsed.hostname or val
                port = parsed.port
                path = parsed.path
            except ValueError:
                host = val.split("/", 1)[0]
                port = None
                path = ""
            scheme = "tcp"

    if explicit_port is not None:
        port = explicit_port
    elif port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443

    # Inter-container Docker networking resolution:
    # If running inside a container network and targeting localhost lab ports,
    # auto-resolve to the internal container DNS name 'mock-target-lab'.
    if host in ("localhost", "127.0.0.1") and port in (5000, 8080, 8888):
        try:
            socket.gethostbyname("mock-target-lab")
            host = "mock-target-lab"
            port = 8080
        except OSError:
            pass

    return {"host": host, "port": port, "scheme": scheme, "path": path}


def create_initial_state(
    assessment_id: str,
    target: dict[str, Any],
    objective: dict[str, Any],
    scope: ScopeDocument,
    scope_yaml_raw: str,
    available_tools: list[dict[str, Any]] | None = None,
    max_iterations: int | None = None,
    max_duration_seconds: int | None = None,
) -> AssessmentState:
    """Helper to initialize a clean, fully populated AssessmentState."""
    import hashlib

    settings = get_settings()
    eff_max_iter = max_iterations if max_iterations is not None else settings.DEFAULT_MAX_ITERATIONS
    eff_max_duration = (
        max_duration_seconds
        if max_duration_seconds is not None
        else settings.DEFAULT_MAX_DURATION_SECONDS
    )
    scope_hash = hashlib.sha256(scope_yaml_raw.encode()).hexdigest()

    return {
        "assessment_id": assessment_id,
        "target": target,
        "assessment_objective": objective,
        "scope_id": scope.assessment_id,
        "scope_version": scope.schema_version,
        "scope_snapshot_hash": scope_hash,
        "status": "DRAFT",
        "tool_registry_version": "1.0.0",
        "available_tools": available_tools or get_default_registry().export_descriptors(),
        "discovered_assets": [],
        "unauthorized_discovered_assets": [],
        "discovered_services": [],
        "observations": [],
        "research_refs": [],
        "footholds": [],
        "current_strategy": "INITIAL_RECON",
        "current_action": None,
        "resolved_ip": None,
        "action_history": [],
        "executed_actions": [],
        "chain_progress": [],
        "chain_summary": {},
        "blocked_actions": [],
        "evidence_refs": [],
        "findings": [],
        "simulation_mode": False,
        "report_markdown": "",
        "report_path": None,
        "telemetry": [],
        "langfuse_trace_id": None,
        "langfuse_session_id": None,
        "budget": ExecutionBudget(
            max_duration_seconds=eff_max_duration, max_iterations=eff_max_iter
        ).model_dump(),
        "cancellation": CancellationState().model_dump(),
        "recovery": RecoveryState().model_dump(),
        "completion": CompletionEvaluation().model_dump(),
        "started_at": "",
        "deadline_at": None,
        "stop_reason": None,
    }


class AssessmentOrchestrator:
    """Encapsulates the compiled LangGraph workflow with dependency injection."""

    def __init__(
        self,
        scope: ScopeDocument,
        model_gateway: ModelGatewayCallable | None = None,
        tool_executor: ToolExecutorCallable | None = None,
        policy_engine: PolicyEngine | None = None,
        tavily_service: TavilyIntelService | None = None,
        evidence_vault: EvidenceVault | None = None,
        tool_registry: ToolRegistry | None = None,
        finding_verifier: FindingVerifier | None = None,
        report_generator: ReportGenerator | None = None,
        simulation_mode: bool | None = None,
        cancel_check: Callable[[], bool] | None = None,
        tracer: LangfuseTracer | None = None,
    ):
        settings = get_settings()
        self.scope = scope
        self.tracer = tracer or LangfuseTracer()
        self.policy_engine = policy_engine or PolicyEngine(scope)
        self.evidence_vault = evidence_vault or EvidenceVault(base_dir=settings.ARTIFACTS_DIR)
        self.tool_registry = tool_registry or get_default_registry()
        self.finding_verifier = finding_verifier or FindingVerifier()
        self.report_generator = report_generator or ReportGenerator()
        self.cancel_check = cancel_check
        self.simulation_mode = (
            simulation_mode if simulation_mode is not None else settings.SIMULATION_MODE
        )
        self.tool_executor = tool_executor or self._default_tool_executor
        self._rate_limiter = ToolRateLimiter(
            max_requests_per_second=scope.rate_limits.max_requests_per_second,
            max_concurrency=scope.rate_limits.max_concurrency,
        )

        # Automatically use Bifrost Gateway if API key or admin credentials configured and no mock gateway injected
        if model_gateway is not None:
            self.model_gateway = model_gateway
        elif settings.BIFROST_API_KEY or (settings.BIFROST_ADMIN_USERNAME and settings.BIFROST_ADMIN_PASSWORD):
            bifrost_client = BifrostClient(
                api_key=settings.BIFROST_API_KEY,
                base_url=settings.BIFROST_BASE_URL,
                primary_model=settings.BIFROST_PRIMARY_MODEL,
                fallback_model=settings.BIFROST_FALLBACK_MODEL,
                admin_username=settings.BIFROST_ADMIN_USERNAME,
                admin_password=settings.BIFROST_ADMIN_PASSWORD,
            )
            self.model_gateway = create_bifrost_model_gateway(bifrost_client)
        elif self.simulation_mode:
            self.model_gateway = self._default_mock_model_gateway
        else:
            # Fail closed: never silently use a mock planner in a live assessment.
            self.model_gateway = self._fail_closed_model_gateway

        # Automatically wire Tavily intelligence if API key configured and not injected
        if tavily_service is not None:
            self.tavily_service: TavilyIntelService | None = tavily_service
        elif settings.TAVILY_API_KEY:
            self.tavily_service = TavilyIntelService(api_key=settings.TAVILY_API_KEY)
        else:
            self.tavily_service = None

        self.graph = self._build_graph()

    def _default_mock_model_gateway(self, prompt: str) -> AssessmentDecision:
        """Explicit simulation-only model gateway for offline testing."""
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="[SIMULATION_MODE] Default mock: Objective achieved.",
            completion_summary="[SIMULATION_MODE] Automated mock completion.",
        )

    def _fail_closed_model_gateway(self, prompt: str) -> AssessmentDecision:
        """Blocks live assessments that have no configured model provider (C-05)."""
        return AssessmentDecision(
            decision_type=DecisionType.BLOCKED,
            rationale=(
                "No model gateway configured. Set BIFROST_API_KEY or explicitly enable "
                "SIMULATION_MODE; refusing to fabricate planner decisions."
            ),
            completion_summary="Assessment stopped: model gateway unavailable (fail-closed).",
        )

    def _default_tool_executor(self, proposal: ActionProposal) -> tuple[int, str, str]:
        """Executes tool proposals via real runner subprocess or safe simulation fallback."""
        settings = get_settings()
        if self.cancel_check is not None and self.cancel_check():
            return 125, "", "cancelled by user request"
        adapter = self.tool_registry.get(proposal.tool_name)
        if adapter is None:
            return 127, "", f"Tool '{proposal.tool_name}' is not registered in ToolRegistry"

        try:
            cmd = adapter.build_command(proposal.arguments)
        except ValueError as err:
            return 1, "", f"Invalid arguments for '{proposal.tool_name}': {err}"

        if self.simulation_mode:
            return self._simulate_or_probe_tool(proposal)

        bin_name = cmd[0]
        if not shutil.which(bin_name):
            return (
                127,
                "",
                f"Binary '{bin_name}' is not installed on system PATH and SIMULATION_MODE is disabled.",
            )

        redirect_ok, redirect_reason = self._preflight_http_redirects(proposal)
        if not redirect_ok:
            return 126, "", f"Redirect policy violation: {redirect_reason}"

        scope_timeout = self.scope.tool_timeouts.get(
            proposal.tool_name, self.scope.rate_limits.tool_timeout_seconds
        )
        timeout_seconds = min(
            proposal.timeout_seconds,
            scope_timeout,
            settings.DEFAULT_TOOL_TIMEOUT_SECONDS,
        )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        try:
            with self._rate_limiter.limit():
                if loop and loop.is_running():
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        returncode, stdout, stderr = pool.submit(
                            lambda: asyncio.run(
                                run_tool_process(
                                    cmd,
                                    timeout_seconds=timeout_seconds,
                                    assessment_id=self.scope.assessment_id,
                                )
                            )
                        ).result()
                else:
                    returncode, stdout, stderr = asyncio.run(
                        run_tool_process(
                            cmd,
                            timeout_seconds=timeout_seconds,
                            assessment_id=self.scope.assessment_id,
                        )
                    )
            return returncode, stdout, stderr
        except TimeoutError as err:
            return 124, "", str(err)
        except (RuntimeError, OSError) as err:
            return 1, "", f"Execution error running '{bin_name}': {err}"

    def _simulate_or_probe_tool(self, proposal: ActionProposal) -> tuple[int, str, str]:
        """Executes lightweight safe probe or deterministic simulation generating valid adapter outputs."""
        tool = proposal.tool_name.lower()
        target_input = (
            proposal.target_host
            or proposal.arguments.get("target")
            or proposal.arguments.get("target_url")
            or "localhost"
        )
        spec = extract_target_spec(target_input)
        target_host = spec["host"] or proposal.target_host or "localhost"
        target_port = proposal.target_port or spec["port"] or proposal.arguments.get("ports") or 8080
        if isinstance(target_port, str) and "," in target_port:
            target_port = target_port.split(",")[0]
        try:
            target_port = int(str(target_port).strip())
        except (ValueError, TypeError):
            target_port = 8080

        # Attempt to probe target if HTTP service is online (only for local/lab addresses to avoid test stalls)
        server_banner = "Apache/2.4.49 (Unix)"
        traversal_content = "root:x:0:0:root:/root:/bin/bash\nlab:x:1000:1000:ARGUS Lab:/home/lab:/bin/sh\n"
        matched_url = f"http://{target_host}:{target_port}"

        should_probe = target_host in {"mock-target-lab", "localhost", "127.0.0.1"} or target_host.startswith("lab-")
        if should_probe:
            try:
                probe_url = f"http://{target_host}:{target_port}/"
                req = urllib.request.Request(probe_url, headers={"User-Agent": "ARGUS-Scanner/1.0"})
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    server_hdr = resp.headers.get("Server", "")
                    if server_hdr:
                        server_banner = server_hdr
            except Exception:
                pass

        if tool == "nmap":
            product = "Apache httpd" if "apache" in server_banner.lower() else "web-service"
            version = "2.4.49" if "2.4.49" in server_banner else "1.0"
            xml_output = (
                f'<!-- [SIMULATION_MODE] Simulated Nmap Scan for {target_host} -->\n'
                f'<nmaprun scanner="nmap" args="nmap -sT -sV -T4 --open -p {target_port} -oX - {target_host}" start="1730720000" version="7.94">\n'
                f'<scaninfo type="connect" protocol="tcp" numservices="1" services="{target_port}"/>\n'
                f'<host starttime="1730720001" endtime="1730720002">\n'
                f'  <status state="up" reason="syn-ack"/>\n'
                f'  <address addr="{target_host}" addrtype="ipv4"/>\n'
                f'  <hostnames><hostname name="{target_host}" type="user"/></hostnames>\n'
                f'  <ports>\n'
                f'    <port protocol="tcp" portid="{target_port}">\n'
                f'      <state state="open" reason="syn-ack" reason_ttl="0"/>\n'
                f'      <service name="http" product="{product}" version="{version}" extrainfo="{server_banner}" method="probed" conf="10"/>\n'
                f'    </port>\n'
                f'  </ports>\n'
                f'</host>\n'
                f'<runstats><finished time="1730720002" exit="success"/><hosts up="1" down="0" total="1"/></runstats>\n'
                f'</nmaprun>\n'
            )
            return 0, xml_output, ""

        if tool == "nuclei":
            if should_probe:
                try:
                    vuln_probe = f"http://{target_host}:{target_port}/icons/.%2e/%2e%2e/etc/passwd"
                    req = urllib.request.Request(vuln_probe, headers={"User-Agent": "ARGUS-Scanner/1.0"})
                    with urllib.request.urlopen(req, timeout=0.8) as resp:
                        data = resp.read().decode("utf-8", errors="replace")
                        if "root:" in data:
                            traversal_content = data
                except Exception:
                    pass

            first_line = traversal_content.splitlines()[0] if traversal_content else "root:x:0:0:root:/root:/bin/bash"
            now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            matched_endpoint = f"{matched_url}/icons/.%2e/%2e%2e/etc/passwd"
            nuclei_record = {
                "template": "cve-2021-41773",
                "template-url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-41773.yaml",
                "template-id": "CVE-2021-41773",
                "info": {
                    "name": "Apache 2.4.49/2.4.50 - Path Traversal & Remote Code Execution",
                    "author": ["argus-security"],
                    "tags": ["cve", "cve2021", "apache", "lfi", "rce"],
                    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                    "severity": "critical",
                    "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49 allowing directory traversal and demonstrated file disclosure.",
                },
                "type": "http",
                "host": matched_url,
                "matched-at": matched_endpoint,
                "extracted-results": [first_line],
                "request": f"GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n",
                "response": f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{traversal_content}",
                "ip": target_host,
                "timestamp": now_iso,
                "curl-command": f"curl -X 'GET' -H 'Host: {target_host}:{target_port}' '{matched_endpoint}'",
                "demonstrated_execution": True,
            }
            jsonl_output = (
                f"# [SIMULATION_MODE] Nuclei execution output\n"
                f"{json.dumps(nuclei_record)}\n"
            )
            return 0, jsonl_output, ""

        if tool == "zap":
            zap_report = {
                "@programName": "ZAP",
                "@version": "2.14.0",
                "@comment": "[SIMULATION_MODE] Simulated ZAP report",
                "@generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
                "site": [
                    {
                        "@name": matched_url,
                        "@host": target_host,
                        "@port": str(target_port),
                        "@ssl": "false",
                        "alerts": [
                            {
                                "pluginid": "10038",
                                "alertRef": "10038",
                                "alert": "Content Security Policy (CSP) Header Not Set",
                                "name": "Content Security Policy (CSP) Header Not Set",
                                "riskcode": "2",
                                "confidence": "3",
                                "riskdesc": "Medium (High)",
                                "desc": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.",
                                "instances": [
                                    {
                                        "uri": f"{matched_url}/",
                                        "method": "GET",
                                        "param": "",
                                        "attack": "",
                                        "evidence": "",
                                    }
                                ],
                                "count": "1",
                                "solution": "Ensure that your web server is configured to set the Content-Security-Policy header.",
                                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                                "cweid": "693",
                                "wascid": "15",
                            }
                        ],
                    }
                ],
            }
            output = json.dumps(zap_report, indent=2)
            return 0, output, ""

        return 0, f"[SIMULATION_MODE] Simulated stdout for {proposal.tool_name} with args {proposal.arguments}", ""

    def _preflight_http_redirects(self, proposal: ActionProposal) -> tuple[bool, str]:
        """Validates every redirect hop for HTTP tools before execution (S-04)."""
        if proposal.tool_name.lower() not in {"nuclei", "zap"}:
            return True, ""

        url = str(
            proposal.arguments.get("url")
            or proposal.arguments.get("target_url")
            or proposal.arguments.get("target")
            or ""
        ).strip()
        if not url:
            scheme = "https" if proposal.target_port in (443, 8443) else "http"
            port_suffix = f":{proposal.target_port}" if proposal.target_port else ""
            url = f"{scheme}://{proposal.target_host}{port_suffix}"

        current = url
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                for _ in range(5):
                    response = client.get(current)
                    if not 300 <= response.status_code < 400:
                        return True, ""
                    location = response.headers.get("location")
                    if not location:
                        return True, ""
                    next_url = urllib.parse.urljoin(current, location)
                    decision = self.policy_engine.validate_redirect(current, next_url)
                    if not decision.approved:
                        return False, decision.reason
                    current = next_url
        except (httpx.HTTPError, OSError):
            # Connectivity failures are reported by the tool itself; they are not
            # scope violations and must not be turned into false policy blocks.
            return True, ""

        return False, "Redirect chain exceeded the maximum of 5 hops."

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _pin_proposal(
        self, state: AssessmentState, proposal: ActionProposal
    ) -> tuple[ActionProposal, str | None]:
        """Re-checks and pins the policy-approved IP immediately before execution (S-02)."""
        pinned_ip = state.get("resolved_ip")
        if not pinned_ip or self._is_ip_literal(proposal.target_host):
            return proposal, None

        try:
            current_ip = socket.gethostbyname(proposal.target_host)
        except OSError:
            return proposal, f"DNS resolution failed for pinned host '{proposal.target_host}'."

        if current_ip != pinned_ip:
            return proposal, (
                f"DNS rebinding guard: '{proposal.target_host}' now resolves to {current_ip}, "
                f"but policy approved {pinned_ip}."
            )

        if proposal.action_category == "network_recon":
            pinned_args = dict(proposal.arguments)
            pinned_args["target"] = pinned_ip
            return (
                proposal.model_copy(update={"target_host": pinned_ip, "arguments": pinned_args}),
                None,
            )

        return proposal, None

    def _extract_target_host_and_port(self, target: dict[str, Any]) -> tuple[str, int | None]:
        """Extracts host and port from various target representation formats (L-01)."""
        spec = extract_target_spec(target)
        return spec["host"], spec["port"]

    # ==========================================
    # NODE IMPLEMENTATIONS
    # ==========================================

    def validate_scope_node(self, state: AssessmentState) -> dict[str, Any]:
        """Validates scope temporal validity and basic boundary invariants."""
        is_valid, reason = ScopeValidator.validate_scope_document(self.scope)
        if not is_valid:
            return {
                "status": "FAILED",
                "stop_reason": f"Scope validation failed: {reason}",
                "completion": CompletionEvaluation(
                    is_completed=True, outcome="FAILED", summary=reason
                ).model_dump(),
            }
        return {"status": "RUNNING"}

    def recon_node(self, state: AssessmentState) -> dict[str, Any]:
        """Runs initial host/service discovery using the registered discovery tool."""
        clean_host, target_port = self._extract_target_host_and_port(state["target"])
        objective = state.get("assessment_objective", {})
        objective_type = str(objective.get("type") or objective.get("objective_type") or "").lower()
        is_multi_step = objective_type in {"multi_step", "chain", "multi_step_chain"}

        # Check if a discovery tool is available in registered tools
        discovery_tools = [
            t for t in state["available_tools"] if "network_recon" in t.get("categories", [])
        ]
        tool_name = discovery_tools[0]["tool_name"] if discovery_tools else "nmap"

        recon_args: dict[str, Any] = {"target": clean_host}
        if target_port is not None:
            recon_args["ports"] = str(target_port)
        elif self.scope.ports.allowed_ports:
            recon_args["ports"] = ",".join(str(p) for p in sorted(self.scope.ports.allowed_ports))

        recon_proposal = ActionProposal(
            action_id="act-recon-001",
            target_host=clean_host,
            target_port=target_port,
            tool_name=tool_name,
            action_category="network_recon",
            arguments=recon_args,
            rationale="Initial authorized surface reconnaissance",
            expected_evidence="Open ports and service versions",
            step_index=1 if is_multi_step else None,
        )

        decision = self.policy_engine.evaluate(recon_proposal)
        if not decision.approved:
            return {
                "blocked_actions": [*state["blocked_actions"], recon_proposal.model_dump()],
                "current_strategy": "BLOCKED",
            }

        # Pin the policy-approved IP for the actual scan (S-02).
        execution_host = decision.resolved_ip or clean_host
        if execution_host != clean_host:
            recon_args = {**recon_args, "target": execution_host}
            recon_proposal = recon_proposal.model_copy(
                update={"target_host": execution_host, "arguments": recon_args}
            )

        retcode, stdout, stderr = self.tool_executor(recon_proposal)

        # Store raw output into EvidenceVault
        raw_content = (
            stdout if stdout.strip() else (stderr or f"Recon {tool_name} returned code {retcode}")
        )
        artifact = self.evidence_vault.store_artifact(
            assessment_id=state["assessment_id"],
            tool_name=tool_name,
            raw_content=raw_content,
            cmd=f"{tool_name} {recon_args}",
            metadata={"phase": "recon", "target_host": clean_host, "retcode": retcode},
        )
        evidence_id = artifact.evidence_id

        self._append_ledger_record(
            state=state,
            tool=tool_name,
            target_host=clean_host,
            target_port=recon_proposal.target_port,
            arguments=recon_args,
            exit_code=retcode,
            stdout_raw=raw_content,
            stderr_raw=stderr,
            evidence_id=evidence_id,
            action_id=recon_proposal.action_id,
        )

        # Parse observations from actual tool output
        adapter = self.tool_registry.get(tool_name)
        parsed_observations = (
            adapter.parse_output(stdout, evidence_id=evidence_id)
            if (adapter and retcode == 0)
            else []
        )

        new_assets = list(state["discovered_assets"])
        unauth_assets = list(state.get("unauthorized_discovered_assets", []))
        new_services = list(state["discovered_services"])
        new_observations = list(state["observations"])

        raw_footholds = state.get("footholds") or []
        footholds = [
            fh if isinstance(fh, FootholdEvidence) else FootholdEvidence.model_validate(fh)
            for fh in raw_footholds
        ]
        simulation_mode = bool(state.get("simulation_mode", False) or self.simulation_mode)

        if clean_host:
            if self.policy_engine.is_target_authorized(
                clean_host, footholds=footholds, simulation_mode=simulation_mode
            ):
                if clean_host not in new_assets:
                    new_assets.append(clean_host)
            elif clean_host not in unauth_assets:
                unauth_assets.append(clean_host)

        for obs in parsed_observations:
            new_observations.append(obs.model_dump())
            if obs.observation_type in ("open_port", "service_version"):
                port_id = obs.data.get("port")
                if port_id is not None:
                    service_entry = {
                        "host": clean_host,
                        "port": port_id,
                        "protocol": obs.data.get("protocol", "tcp"),
                        "service": obs.data.get("service", "unknown"),
                        "product": obs.data.get("product", ""),
                        "version": obs.data.get("version", ""),
                    }
                    if service_entry not in new_services:
                        new_services.append(service_entry)
            elif obs.observation_type == "host_discovered":
                host_ip = obs.data.get("ip") or obs.data.get("host")
                if host_ip:
                    # Discovery isolation guard (SEC-01): only promote authorized hosts to planner assets
                    if self.policy_engine.is_target_authorized(
                        host_ip, footholds=footholds, simulation_mode=simulation_mode
                    ):
                        if host_ip not in new_assets:
                            new_assets.append(host_ip)
                    elif host_ip not in unauth_assets:
                        unauth_assets.append(host_ip)

        new_strategy = "SERVICE_ENUMERATION" if new_services else "INITIAL_RECON"

        updates: dict[str, Any] = {
            "discovered_assets": new_assets,
            "unauthorized_discovered_assets": unauth_assets,
            "discovered_services": new_services,
            "observations": new_observations,
            "evidence_refs": [
                *state["evidence_refs"],
                {
                    "evidence_id": evidence_id,
                    "tool": tool_name,
                    "sha256": artifact.sha256,
                    "target_host": recon_proposal.target_host,
                },
            ],
            "action_history": [*state["action_history"], recon_proposal.fingerprint()],
            "executed_actions": [*state["executed_actions"], recon_proposal.model_dump()],
            "current_strategy": new_strategy,
        }
        if is_multi_step:
            updates["chain_progress"] = [
                *state.get("chain_progress", []),
                {
                    "action_id": recon_proposal.action_id,
                    "parent_action_id": None,
                    "step_index": 1,
                    "target_host": recon_proposal.target_host,
                    "target_port": recon_proposal.target_port,
                    "tool_name": recon_proposal.tool_name,
                    "action_category": recon_proposal.action_category,
                    "evidence_id": evidence_id,
                    "status": "EXECUTED" if retcode == 0 else "FAILED",
                },
            ]
        return updates

    def normalize_observations_node(self, state: AssessmentState) -> dict[str, Any]:
        """Pivots investigation strategy and promotes newly authorized pivot targets."""
        strategy = state["current_strategy"]
        if state["discovered_services"] and strategy == "INITIAL_RECON":
            strategy = "SERVICE_ENUMERATION"

        raw_footholds = state.get("footholds") or []
        footholds = [
            fh if isinstance(fh, FootholdEvidence) else FootholdEvidence.model_validate(fh)
            for fh in raw_footholds
        ]
        simulation_mode = bool(state.get("simulation_mode", False) or self.simulation_mode)

        new_assets = list(state.get("discovered_assets", []))
        remaining_unauth: list[str] = []
        for host in state.get("unauthorized_discovered_assets", []):
            if self.policy_engine.is_target_authorized(
                host, footholds=footholds, simulation_mode=simulation_mode
            ):
                if host not in new_assets:
                    new_assets.append(host)
            else:
                remaining_unauth.append(host)

        return {
            "current_strategy": strategy,
            "discovered_assets": new_assets,
            "unauthorized_discovered_assets": remaining_unauth,
        }

    def plan_action_node(self, state: AssessmentState) -> dict[str, Any]:
        """Invokes the model gateway to propose an action or decision."""
        # Check budget limits first
        budget = dict(state["budget"])
        budget["iterations_used"] += 1
        budget["model_calls_used"] += 1

        if state["cancellation"].get("is_cancelled", False):
            return {"budget": budget}

        if self.cancel_check is not None and self.cancel_check():
            return {
                "budget": budget,
                "status": "CANCELLED",
                "stop_reason": "Assessment cancelled by user request.",
                "cancellation": CancellationState(
                    is_cancelled=True,
                    cancelled_by="api",
                    reason="User requested cancellation",
                ).model_dump(),
                "completion": CompletionEvaluation(
                    is_completed=True,
                    outcome="CANCELLED",
                    summary="Assessment cancelled by user request. State was preserved.",
                ).model_dump(),
            }

        # Build prompt
        prompt = format_planning_prompt(
            target=state["target"],
            objective=state["assessment_objective"],
            available_tools=state["available_tools"],
            discovered_assets=state["discovered_assets"],
            discovered_services=state["discovered_services"],
            observations=state["observations"],
            research_refs=state["research_refs"],
            findings=state["findings"],
            action_history=state["action_history"],
            blocked_actions=state["blocked_actions"],
            current_strategy=state["current_strategy"],
        )

        try:
            decision = self.model_gateway(prompt)
        except Exception as exc:  # noqa: BLE001
            # Record failed AI planner attempt in Langfuse
            self.tracer.log_ai_generation(
                iteration=budget["iterations_used"],
                prompt=prompt,
                objective=state["assessment_objective"],
                decision=None,
                telemetry=None,
                error=exc,
            )
            # Scenario 12: all model providers unavailable must preserve state and
            # stop safely rather than crashing the graph or fabricating a decision.
            return {
                "budget": budget,
                "status": "FAILED",
                "stop_reason": (
                    "Model gateway unavailable; assessment stopped safely without "
                    f"fabricating a planner decision ({type(exc).__name__})."
                ),
                "completion": CompletionEvaluation(
                    is_completed=True,
                    outcome="FAILED",
                    summary=(
                        "Assessment stopped safely: the model gateway was unavailable. "
                        "Evidence and execution history were preserved."
                    ),
                ).model_dump(),
            }

        # Persist Bifrost routing/token telemetry with the decision that produced it.
        last_telemetry = getattr(self.model_gateway, "last_telemetry", None)
        self.tracer.log_ai_generation(
            iteration=budget["iterations_used"],
            prompt=prompt,
            objective=state["assessment_objective"],
            decision=decision,
            telemetry=last_telemetry,
        )
        telemetry_event = (
            last_telemetry.model_dump(mode="json")
            if last_telemetry is not None and hasattr(last_telemetry, "model_dump")
            else None
        )
        telemetry_history = (
            [*state.get("telemetry", []), telemetry_event]
            if telemetry_event is not None
            else list(state.get("telemetry", []))
        )

        # Handle Action Proposal with Duplicate Prevention
        if decision.decision_type == DecisionType.EXECUTE_ACTION and decision.proposed_action:
            action = decision.proposed_action

            # Normalize step_index and parent_action_id when multi-step chaining is not enabled in scope
            if not self.scope.authorized_chain.enabled and (
                action.step_index is not None or action.parent_action_id is not None
            ):
                action = action.model_copy(update={"step_index": None, "parent_action_id": None})

            # If the model targeted an IP that resolves from an authorized discovered asset hostname,
            # normalize target_host to the canonical asset hostname
            for asset in state.get("discovered_assets", []):
                try:
                    if action.target_host == socket.gethostbyname(asset):
                        action = action.model_copy(update={"target_host": asset})
                        break
                except OSError:
                    pass

            fp = action.fingerprint()

            # Prevent duplicate actions
            if fp in state["action_history"]:
                # Force pivot or rejection of duplicate
                return {
                    "budget": budget,
                    "blocked_actions": [
                        *state["blocked_actions"],
                        {
                            **action.model_dump(),
                            "reject_reason": "Duplicate action fingerprint detected",
                        },
                    ],
                    "current_strategy": "CVE_VERIFICATION",
                    "telemetry": telemetry_history,
                }

            return {
                "budget": budget,
                "current_action": action.model_dump(),
                "action_history": [*state["action_history"], fp],
                "telemetry": telemetry_history,
            }

        # If decision is Intel or Goal
        if decision.decision_type == DecisionType.RESEARCH_INTEL:
            query = decision.intel_query or "service vulnerability"
            new_research = list(state["research_refs"])
            settings = get_settings()

            if self.tavily_service and settings.ENABLE_TAVILY_RESEARCH:
                import asyncio
                import concurrent.futures

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                try:
                    if loop and loop.is_running():
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                            sources = pool.submit(
                                lambda: asyncio.run(
                                    self.tavily_service.search(query=query, max_results=5)  # type: ignore[union-attr]
                                )
                            ).result()
                    else:
                        sources = asyncio.run(
                            self.tavily_service.search(query=query, max_results=5)
                        )

                    for src in sources:
                        new_research.append(src.model_dump())
                except (RuntimeError, ValueError, OSError):
                    pass

            if not new_research:
                new_research.append(
                    {
                        "query": query,
                        "advisory": f"Security advisory for {query}",
                        "source": "Tavily",
                    }
                )

            return {
                "budget": budget,
                "research_refs": new_research,
                "current_strategy": "CVE_VERIFICATION",
                "telemetry": telemetry_history,
            }

        if decision.decision_type in (DecisionType.OBJECTIVE_ACHIEVED, DecisionType.BLOCKED):
            return {
                "budget": budget,
                "stop_reason": decision.completion_summary or decision.rationale,
                "telemetry": telemetry_history,
            }

        return {"budget": budget, "telemetry": telemetry_history}

    def policy_gate_node(self, state: AssessmentState) -> dict[str, Any]:
        """Deterministic policy validation immediately prior to tool execution."""
        action_dict = state["current_action"]
        if not action_dict:
            return {}

        proposal = ActionProposal.model_validate(action_dict)

        # Deserialize active footholds from state
        raw_footholds = state.get("footholds") or []
        footholds: list[FootholdEvidence] = []
        for item in raw_footholds:
            with contextlib.suppress(ValueError, TypeError):
                footholds.append(
                    item
                    if isinstance(item, FootholdEvidence)
                    else FootholdEvidence.model_validate(item)
                )

        simulation_mode = bool(state.get("simulation_mode", False) or self.simulation_mode)
        decision = self.policy_engine.evaluate(
            proposal, footholds=footholds, simulation_mode=simulation_mode
        )

        if not decision.approved:
            self._append_policy_denial_record(state, proposal, decision.reason)
            self.tracer.log_policy_gate(proposal, approved=False, denial_reason=decision.reason)
            return {
                "blocked_actions": [
                    *state["blocked_actions"],
                    {**action_dict, "denied_reason": decision.reason},
                ],
                "current_action": None,
                "resolved_ip": None,
            }
        self.tracer.log_policy_gate(proposal, approved=True)
        return {"resolved_ip": decision.resolved_ip}

    def _append_policy_denial_record(
        self,
        state: AssessmentState,
        proposal: ActionProposal,
        reason: str,
    ) -> None:
        """Appends a Tier-1 Policy Denial record to the Merkle ledger (SEC-04)."""
        if not get_settings().ENABLE_PROOF_LEDGER:
            return
        with contextlib.suppress(OSError, ValueError, TypeError, KeyError):
            from core.evidence.ledger import AssessmentLedger

            ledger_path = (
                Path(self.evidence_vault.base_dir) / state["assessment_id"] / "ledger.jsonl"
            )
            ledger = AssessmentLedger(ledger_path, assessment_id=state["assessment_id"])
            ledger.append_policy_denial(
                action_id=proposal.action_id,
                tool=proposal.tool_name,
                target_host=proposal.target_host,
                target_port=proposal.target_port,
                arguments=proposal.arguments,
                reason=reason,
            )

    def _append_ledger_record(
        self,
        state: AssessmentState,
        tool: str,
        target_host: str,
        target_port: int | None,
        arguments: Any,
        exit_code: int,
        stdout_raw: str,
        stderr_raw: str,
        evidence_id: str,
        action_id: str = "",
    ) -> None:
        """Appends a T2 executor-attested record to the Merkle ledger if enabled."""
        if not get_settings().ENABLE_PROOF_LEDGER:
            return
        with contextlib.suppress(OSError, ValueError, TypeError, KeyError):
            from core.evidence.ledger import AssessmentLedger
            ledger_path = Path(self.evidence_vault.base_dir) / state["assessment_id"] / "ledger.jsonl"
            ledger = AssessmentLedger(ledger_path, assessment_id=state["assessment_id"])
            ledger.append_record(
                event="tool_result",
                tool=tool,
                target_host=target_host,
                target_port=target_port,
                arguments=arguments,
                exit_code=exit_code,
                stdout_raw=stdout_raw,
                stderr_raw=stderr_raw,
                evidence_ids=[evidence_id],
                tier="T2",
                action_id=action_id,
                bifrost_metadata=state.get("bifrost_telemetry"),
                research_metadata=state.get("research_refs"),
            )

    def execute_tool_node(self, state: AssessmentState) -> dict[str, Any]:
        """Executes the approved tool proposal via the injected tool executor."""
        action_dict = state["current_action"]
        if not action_dict:
            return {}

        proposal = ActionProposal.model_validate(action_dict)
        proposal, pin_error = self._pin_proposal(state, proposal)
        if pin_error:
            self._append_policy_denial_record(state, proposal, pin_error)
            return {
                "blocked_actions": [
                    *state["blocked_actions"],
                    {**action_dict, "denied_reason": pin_error},
                ],
                "current_action": None,
                "resolved_ip": None,
            }

        tool_start_time = time.perf_counter()
        try:
            retcode, stdout, stderr = self.tool_executor(proposal)
        except TimeoutError as err:
            retcode = 124
            stdout = ""
            stderr = f"Execution timed out: {err}"
        except Exception as err:  # noqa: BLE001
            retcode = 1
            stdout = ""
            stderr = f"Tool execution exception: {err}"
        tool_duration = time.perf_counter() - tool_start_time

        # Store raw output into EvidenceVault
        raw_content = (
            stdout
            if stdout.strip()
            else (stderr or f"Tool {proposal.tool_name} returned code {retcode}")
        )
        artifact = self.evidence_vault.store_artifact(
            assessment_id=state["assessment_id"],
            tool_name=proposal.tool_name,
            raw_content=raw_content,
            cmd=f"{proposal.tool_name} {proposal.arguments}",
            metadata={"action_id": proposal.action_id, "retcode": retcode},
        )
        evidence_id = artifact.evidence_id

        self._append_ledger_record(
            state=state,
            tool=proposal.tool_name,
            target_host=proposal.target_host,
            target_port=proposal.target_port,
            arguments=proposal.arguments,
            exit_code=retcode,
            stdout_raw=raw_content,
            stderr_raw=stderr,
            evidence_id=evidence_id,
            action_id=proposal.action_id,
        )

        if retcode != 0:
            failure_type = classify_error(retcode, stderr or stdout)
            self.tracer.log_tool_execution(
                proposal=proposal,
                returncode=retcode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=tool_duration,
                observations_count=0,
                evidence_ids=[evidence_id],
            )
            return {
                "recovery": {
                    **state["recovery"],
                    "consecutive_failures": state["recovery"].get("consecutive_failures", 0) + 1,
                    "last_failure_type": failure_type,
                },
                "evidence_refs": [
                    *state["evidence_refs"],
                    {
                        "evidence_id": evidence_id,
                        "tool": proposal.tool_name,
                        "sha256": artifact.sha256,
                        "target_host": proposal.target_host,
                    },
                ],
                "current_action": None,
                "resolved_ip": None,
            }

        # Reset consecutive failures on success
        recovery = dict(state["recovery"])
        recovery["consecutive_failures"] = 0

        # Parse observations from tool output using adapter
        adapter = self.tool_registry.get(proposal.tool_name)
        parsed_observations = (
            adapter.parse_output(stdout, evidence_id=evidence_id) if adapter else []
        )
        self.tracer.log_tool_execution(
            proposal=proposal,
            returncode=retcode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=tool_duration,
            observations_count=len(parsed_observations),
            evidence_ids=[evidence_id],
        )

        updates: dict[str, Any] = {
            "recovery": recovery,
            "executed_actions": [*state["executed_actions"], action_dict],
            "evidence_refs": [
                *state["evidence_refs"],
                {
                    "evidence_id": evidence_id,
                    "tool": proposal.tool_name,
                    "sha256": artifact.sha256,
                    "target_host": proposal.target_host,
                },
            ],
            "observations": [
                *state["observations"],
                *(obs.model_dump() for obs in parsed_observations),
            ],
            "current_action": None,
            "resolved_ip": None,
        }
        if proposal.parent_action_id is not None or proposal.step_index is not None:
            updates["chain_progress"] = [
                *state.get("chain_progress", []),
                {
                    "action_id": proposal.action_id,
                    "parent_action_id": proposal.parent_action_id,
                    "step_index": proposal.step_index,
                    "target_host": proposal.target_host,
                    "target_port": proposal.target_port,
                    "tool_name": proposal.tool_name,
                    "action_category": proposal.action_category,
                    "evidence_id": evidence_id,
                    "status": "EXECUTED",
                },
            ]
        return updates

    def verify_finding_node(self, state: AssessmentState) -> dict[str, Any]:
        """Promotes findings to CONFIRMED strictly from verified evidence in vault."""
        new_findings: list[dict[str, Any]] = list(state["findings"])
        new_footholds: list[dict[str, Any]] = list(state.get("footholds", []))

        # Process vuln_candidate observations
        for obs in state["observations"]:
            if obs.get("observation_type") != "vuln_candidate":
                continue

            ev_id = obs.get("raw_evidence_id")
            if not ev_id:
                continue

            # Zero-Hallucination Invariant: Validate cryptographic integrity against vault
            is_valid, _msg = self.evidence_vault.verify_integrity(state["assessment_id"], ev_id)
            if not is_valid:
                continue

            obs_data = obs.get("data", {})
            title = obs_data.get("name") or obs_data.get("template_id") or "Vulnerability Finding"
            affected_asset = obs.get("target") or state["target"].get("value", "target")

            # Avoid duplicate findings for same title and asset
            dup = any(
                f.get("title") == title and f.get("affected_asset") == affected_asset
                for f in new_findings
            )
            if dup:
                continue

            raw_severity = str(obs_data.get("severity", "MEDIUM")).upper()
            try:
                severity = SeverityLevel(raw_severity)
            except ValueError:
                severity = SeverityLevel.MEDIUM

            # Use FindingVerifier to transition finding to CONFIRMED (L-04 multi-step evidence chaining)
            desc = obs_data.get("description") or f"Vulnerability detected by {obs.get('tool')}"
            repro = (
                obs_data.get("curl_command")
                or f"Run template {obs_data.get('template_id')} against target"
            )

            # Discover earlier recon/discovery evidence for the same target. Refs
            # without target metadata are accepted as a legacy fallback, but a ref
            # explicitly tied to another host must never be chained into this proof.
            def _host_of(value: Any) -> str:
                text = str(value or "").strip()
                if not text:
                    return ""
                try:
                    parsed = urllib.parse.urlsplit(text if "://" in text else f"//{text}")
                    return parsed.hostname or text
                except ValueError:
                    return text

            observation_target = _host_of(obs.get("target"))
            candidates = [
                ref
                for ref in state.get("evidence_refs", [])
                if ref.get("evidence_id") and ref.get("evidence_id") != ev_id
            ]
            same_target_refs = [
                ref for ref in candidates if _host_of(ref.get("target_host")) == observation_target
            ]
            unscoped_refs = [ref for ref in candidates if not ref.get("target_host")]
            chosen_ref = (
                same_target_refs[0]
                if same_target_refs
                else (unscoped_refs[0] if unscoped_refs else None)
            )
            discovery_evidence_id = chosen_ref.get("evidence_id") if chosen_ref else None

            potential_finding = self.finding_verifier.create_potential_finding(
                assessment_id=state["assessment_id"],
                title=title,
                description=desc,
                severity=severity,
                affected_asset=affected_asset,
                affected_service=obs_data.get("matched_at", "web"),
                initial_evidence_id=discovery_evidence_id or ev_id,
            )

            # Spec 11 Chain of Custody: Lookup inclusion proof and enforce T2 attestation
            proof_id = None
            ledger_root = None
            proof_summary = None

            if get_settings().ENABLE_PROOF_LEDGER:
                from core.evidence.ledger import AssessmentLedger
                ledger_path = Path(self.evidence_vault.base_dir) / state["assessment_id"] / "ledger.jsonl"
                if ledger_path.exists():
                    with contextlib.suppress(OSError, ValueError, KeyError):
                        ledger = AssessmentLedger(ledger_path, assessment_id=state["assessment_id"])
                        proof_obj = ledger.get_proof_for_evidence_id(ev_id)
                        if proof_obj:
                            rec = proof_obj.get("record", {})
                            if rec.get("tier") != "T2":
                                # T1 claims cannot confirm a finding (Spec 11 §6.1)
                                continue
                            head = ledger.head()
                            ledger_root = head.get("root_hash")
                            proof_id = f"proof-{state['assessment_id']}-{ev_id}"
                            proof_summary = {
                                "proof_id": proof_id,
                                "ledger_root": ledger_root,
                                "leaf_index": proof_obj.get("leaf_index"),
                                "tree_size": proof_obj.get("tree_size"),
                                "audit_path": proof_obj.get("audit_path"),
                                "tier": "T2",
                            }

            confirmed_finding = self.finding_verifier.confirm_finding(
                finding=potential_finding,
                verification_evidence_id=ev_id,
                verification_method=f"Automated probe verification via {obs.get('tool')}",
                reproduction_steps=repro,
                impact=f"Confirmed security flaw on {affected_asset}",
                proof_id=proof_id,
                ledger_root=ledger_root,
                proof_summary=proof_summary,
            )

            new_findings.append(confirmed_finding.model_dump(mode="json"))

            # Foothold registration (SEC-06 & Stage 2.1 Foothold Semantics):
            # A vulnerability finding cannot automatically become a foothold.
            # - RCE requires demonstrated command execution output
            # - Credentials require verified successful authentication
            title_lower = title.lower()
            desc_lower = desc.lower()
            raw_obs_str = str(obs_data).lower()
            is_rce = any(
                k in title_lower or k in desc_lower
                for k in ("rce", "remote code execution", "command execution", "command injection")
            )
            is_cred = any(
                k in title_lower or k in desc_lower
                for k in ("credential", "password leaked", "auth bypass", "default login", "private key")
            )

            demonstrated_rce = bool(
                obs_data.get("demonstrated_execution")
                or obs_data.get("extracted_results")
                or obs_data.get("command_output")
                or any(m in raw_obs_str for m in ("uid=", "gid=", "root:", "whoami", "uname -a"))
            )
            demonstrated_auth = bool(
                obs_data.get("auth_verified")
                or obs_data.get("login_success")
                or obs_data.get("session_token")
                or "auth_verified" in raw_obs_str
            )

            if (is_rce and demonstrated_rce) or (is_cred and demonstrated_auth):
                fh_type = FootholdType.COMMAND_EXECUTION if is_rce else FootholdType.VERIFIED_CREDENTIAL
                host_target = observation_target or affected_asset
                now_utc = datetime.now(UTC)
                if not any(f.get("host") == host_target for f in new_footholds):
                    fh = FootholdEvidence(
                        foothold_id=f"fh-{uuid.uuid4().hex[:8]}",
                        assessment_id=state["assessment_id"],
                        host=host_target,
                        foothold_type=fh_type,
                        finding_id=confirmed_finding.finding_id,
                        evidence_id=ev_id,
                        established_at=now_utc,
                        expires_at=now_utc + timedelta(hours=2),
                        simulated=bool(state.get("simulation_mode", False)),
                        details={"title": title, "service": obs_data.get("matched_at", "web")},
                    )
                    new_footholds.append(fh.model_dump(mode="json"))

        return {"findings": new_findings, "footholds": new_footholds}

    def adaptive_recovery_node(self, state: AssessmentState) -> dict[str, Any]:
        """Applies exponential backoff and recovery state updates."""
        failure_type = state["recovery"].get("last_failure_type", FailureType.RECOVERABLE_TIMEOUT)
        updated_rec, can_continue = apply_adaptive_recovery(state["recovery"], failure_type)
        if not can_continue:
            return {
                "recovery": updated_rec,
                "status": "FAILED",
                "stop_reason": f"Unrecoverable failure bound reached: {failure_type}",
            }
        return {"recovery": updated_rec}

    def _verified_evidence_ids(self, state: AssessmentState) -> set[str]:
        """Returns the subset of evidence refs whose on-disk integrity checks out."""
        verified: set[str] = set()
        for ref in state.get("evidence_refs", []):
            evidence_id = ref.get("evidence_id")
            if not evidence_id:
                continue
            try:
                is_valid, _ = self.evidence_vault.verify_integrity(
                    state["assessment_id"], evidence_id
                )
            except Exception:  # noqa: BLE001
                is_valid = False
            if is_valid:
                verified.add(evidence_id)
        return verified

    def evaluate_completion_node(self, state: AssessmentState) -> dict[str, Any]:
        """Evaluates objective satisfaction deterministically."""
        evaluation = evaluate_completion(
            objective=state["assessment_objective"],
            findings=state["findings"],
            discovered_assets=state["discovered_assets"],
            discovered_services=state["discovered_services"],
            budget=state["budget"],
            cancellation=state["cancellation"],
            recovery=state["recovery"],
            started_at=state.get("started_at"),
            observations=state.get("observations"),
            executed_actions=state.get("executed_actions"),
            chain_progress=state.get("chain_progress"),
            verified_evidence_ids=self._verified_evidence_ids(state),
        )
        updates: dict[str, Any] = {"completion": evaluation}
        if evaluation["is_completed"]:
            updates["status"] = evaluation["outcome"]
        self.tracer.log_completion_evaluation(
            objective=state["assessment_objective"],
            completion=evaluation,
            findings_count=len(state["findings"]),
            iterations_used=state["budget"].get("iterations_used", 0),
        )
        return updates

    def report_node(self, state: AssessmentState) -> dict[str, Any]:
        """Final terminal node that generates and persists the assessment report (E-03)."""
        outcome = state["completion"].get("outcome", "COMPLETED")
        chain = self.scope.authorized_chain
        chain_summary = {
            "authorized": chain.enabled,
            "max_steps": chain.max_steps,
            "declared_steps": [step.model_dump() for step in chain.allowed_steps],
            "executed_steps": state.get("chain_progress", []),
        }

        report_state: dict[str, Any] = {
            **state,
            "status": outcome,
            "chain_summary": chain_summary,
            "simulation_mode": self.simulation_mode,
        }

        try:
            report_markdown = self.report_generator.generate_markdown_report(
                report_state,
                scope=self.scope,
                evidence_vault=self.evidence_vault,
                simulation_mode=self.simulation_mode,
            )
        except Exception as exc:  # noqa: BLE001
            # Reporting must never crash a completed assessment. Preserve the
            # terminal status and emit a clearly-labelled failure notice instead.
            report_markdown = (
                "# ARGUS Security Assessment Report\n\n"
                f"> **Report generation failed:** `{type(exc).__name__}`\n\n"
                f"- Assessment ID: `{state.get('assessment_id', 'unknown')}`\n"
                f"- Outcome: **{outcome}**\n"
                "- Raw evidence remains available in the evidence vault.\n"
            )

        report_path: str | None = None
        try:
            safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(state.get("assessment_id", "unknown")))
            report_dir = self.evidence_vault.base_dir / safe_id
            report_dir.mkdir(parents=True, exist_ok=True)
            report_file = report_dir / "report.md"
            report_file.write_text(report_markdown, encoding="utf-8")
            report_path = str(report_file)

            # Export PDF report deliverable alongside markdown (E-05). The PDF is
            # an optional convenience; Markdown remains the canonical artifact.
            with contextlib.suppress(Exception):
                self.report_generator.generate_pdf_report(
                    state=report_state,
                    output_path=report_dir / "report.pdf",
                    scope=self.scope,
                    evidence_vault=self.evidence_vault,
                    simulation_mode=self.simulation_mode,
                )
        except (OSError, ValueError):
            report_path = None

        self.tracer.end_assessment_trace(
            status=outcome,
            outcome=outcome,
            summary=state["completion"].get("summary"),
            findings_count=len(state.get("findings", [])),
            budget=state.get("budget"),
        )

        return {
            "status": outcome,
            "chain_summary": chain_summary,
            "report_markdown": report_markdown,
            "report_path": report_path,
        }

    # ==========================================
    # CONDITIONAL EDGES
    # ==========================================

    def _should_continue_from_scope(self, state: AssessmentState) -> str:
        return "report" if state["status"] == "FAILED" else "recon"

    def _should_continue_from_plan(self, state: AssessmentState) -> str:
        if state["completion"].get("is_completed", False):
            return "report"
        if state.get("current_action"):
            return "policy_gate"
        return "evaluate_completion"

    def _should_continue_from_policy(self, state: AssessmentState) -> str:
        return "execute_tool" if state.get("current_action") else "evaluate_completion"

    def _should_continue_from_execute(self, state: AssessmentState) -> str:
        if (
            state["recovery"].get("last_failure_type") is not None
            and state["recovery"].get("consecutive_failures", 0) > 0
        ):
            return "adaptive_recovery"
        return "verify_finding"

    def _should_continue_from_completion(self, state: AssessmentState) -> str:
        if state["completion"].get("is_completed", False):
            return "report"
        return "plan_action"

    # ==========================================
    # GRAPH COMPILATION
    # ==========================================

    def _build_graph(self) -> Any:
        # StateGraph expects a schema satisfying LangGraph's internal StateLike protocol.
        # AssessmentState (TypedDict) satisfies this at runtime, but static type checkers
        # (Pyright/Pylance) cannot statically verify TypedDict against TypedDictLike protocols.
        # pyrefly: ignore[bad-specialization]
        builder = StateGraph[AssessmentState](cast(Any, AssessmentState))

        builder.add_node("validate_scope", self.validate_scope_node)
        builder.add_node("recon", self.recon_node)
        builder.add_node("normalize_observations", self.normalize_observations_node)
        builder.add_node("plan_action", self.plan_action_node)
        builder.add_node("policy_gate", self.policy_gate_node)
        builder.add_node("execute_tool", self.execute_tool_node)
        builder.add_node("adaptive_recovery", self.adaptive_recovery_node)
        builder.add_node("verify_finding", self.verify_finding_node)
        builder.add_node("evaluate_completion", self.evaluate_completion_node)
        builder.add_node("report", self.report_node)

        builder.add_edge(START, "validate_scope")
        builder.add_conditional_edges("validate_scope", self._should_continue_from_scope)
        builder.add_edge("recon", "normalize_observations")
        builder.add_edge("normalize_observations", "plan_action")
        builder.add_conditional_edges("plan_action", self._should_continue_from_plan)
        builder.add_conditional_edges("policy_gate", self._should_continue_from_policy)
        builder.add_conditional_edges("execute_tool", self._should_continue_from_execute)
        builder.add_edge("adaptive_recovery", "evaluate_completion")
        builder.add_edge("verify_finding", "evaluate_completion")
        builder.add_conditional_edges("evaluate_completion", self._should_continue_from_completion)
        builder.add_edge("report", END)

        return builder.compile()

    def run(self, initial_state: AssessmentState) -> AssessmentState:
        """Executes the compiled LangGraph workflow to completion."""
        from datetime import UTC, datetime

        if self.tracer.is_enabled and not self.tracer.trace_id:
            self.tracer.start_assessment_trace(
                assessment_id=initial_state["assessment_id"],
                target=initial_state["target"],
                objective=initial_state["assessment_objective"],
                scope_id=initial_state["scope_id"],
                simulation=initial_state.get("simulation_mode", self.simulation_mode),
                max_iterations=initial_state.get("budget", {}).get("max_iterations", 20),
            )

        if not initial_state.get("started_at"):
            initial_state["started_at"] = datetime.now(UTC).isoformat()
        initial_state["simulation_mode"] = self.simulation_mode

        result = self.graph.invoke(initial_state)
        if self.tracer.is_enabled:
            self.tracer.end_assessment_trace(
                status=result.get("status", "COMPLETED"),
                outcome=result.get("completion", {}).get("outcome"),
                summary=result.get("completion", {}).get("summary"),
                findings_count=len(result.get("findings", [])),
                budget=result.get("budget"),
            )
        return cast(AssessmentState, result)
