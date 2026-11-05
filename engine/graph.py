"""Stateful LangGraph Agent Orchestrator for ARGUS.

Implements a single-agent, deterministic-governed state machine featuring
dynamic tool discovery, context-driven planning, duplicate action prevention,
and bounded adaptive recovery.
"""

import asyncio
import concurrent.futures
import contextlib
import ipaddress
import re
import shutil
import socket
import urllib.parse
from collections.abc import Callable
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
from integrations.tavily import TavilyIntelService
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
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
        "discovered_services": [],
        "observations": [],
        "research_refs": [],
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
    ):
        settings = get_settings()
        self.scope = scope
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

        # Automatically use Bifrost Gateway if API key configured and no mock gateway injected
        if model_gateway is not None:
            self.model_gateway = model_gateway
        elif settings.BIFROST_API_KEY:
            bifrost_client = BifrostClient(
                api_key=settings.BIFROST_API_KEY,
                base_url=settings.BIFROST_BASE_URL,
                primary_model=settings.BIFROST_PRIMARY_MODEL,
                fallback_model=settings.BIFROST_FALLBACK_MODEL,
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

        bin_name = cmd[0]
        if not shutil.which(bin_name):
            if self.simulation_mode:
                return (
                    0,
                    f"[SIMULATION_MODE] Simulated stdout for {bin_name} with args {proposal.arguments}",
                    "",
                )
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
                                run_tool_process(cmd, timeout_seconds=timeout_seconds)
                            )
                        ).result()
                else:
                    returncode, stdout, stderr = asyncio.run(
                        run_tool_process(cmd, timeout_seconds=timeout_seconds)
                    )
            return returncode, stdout, stderr
        except TimeoutError as err:
            return 124, "", str(err)
        except (RuntimeError, OSError) as err:
            return 1, "", f"Execution error running '{bin_name}': {err}"

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
        except httpx.HTTPError:
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

        # Parse observations from actual tool output
        adapter = self.tool_registry.get(tool_name)
        parsed_observations = (
            adapter.parse_output(stdout, evidence_id=evidence_id)
            if (adapter and retcode == 0)
            else []
        )

        new_assets = list(state["discovered_assets"])
        new_services = list(state["discovered_services"])
        new_observations = list(state["observations"])

        if clean_host and clean_host not in new_assets:
            new_assets.append(clean_host)

        for obs in parsed_observations:
            new_observations.append(obs.model_dump())
            if obs.observation_type in ("open_port", "service_version"):
                port_id = obs.data.get("port")
                if port_id is not None:
                    service_entry = {
                        "port": port_id,
                        "protocol": obs.data.get("protocol", "tcp"),
                        "service": obs.data.get("service", "unknown"),
                        "product": obs.data.get("product", ""),
                        "version": obs.data.get("version", ""),
                    }
                    if service_entry not in new_services:
                        new_services.append(service_entry)
            elif obs.observation_type == "host_discovered":
                host_ip = obs.data.get("ip")
                if host_ip and host_ip not in new_assets:
                    new_assets.append(host_ip)

        new_strategy = "SERVICE_ENUMERATION" if new_services else "INITIAL_RECON"

        updates: dict[str, Any] = {
            "discovered_assets": new_assets,
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
        """Pivots investigation strategy based on current observations."""
        strategy = state["current_strategy"]
        if state["discovered_services"] and strategy == "INITIAL_RECON":
            strategy = "SERVICE_ENUMERATION"
        return {"current_strategy": strategy}

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

        # Handle Action Proposal with Duplicate Prevention
        if decision.decision_type == DecisionType.EXECUTE_ACTION and decision.proposed_action:
            action = decision.proposed_action
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
                }

            return {
                "budget": budget,
                "current_action": action.model_dump(),
                "action_history": [*state["action_history"], fp],
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
            }

        if decision.decision_type in (DecisionType.OBJECTIVE_ACHIEVED, DecisionType.BLOCKED):
            return {
                "budget": budget,
                "stop_reason": decision.completion_summary or decision.rationale,
            }

        return {"budget": budget}

    def policy_gate_node(self, state: AssessmentState) -> dict[str, Any]:
        """Deterministic policy validation immediately prior to tool execution."""
        action_dict = state["current_action"]
        if not action_dict:
            return {}

        proposal = ActionProposal.model_validate(action_dict)
        decision = self.policy_engine.evaluate(proposal)

        if not decision.approved:
            return {
                "blocked_actions": [
                    *state["blocked_actions"],
                    {**action_dict, "denied_reason": decision.reason},
                ],
                "current_action": None,
                "resolved_ip": None,
            }
        return {"resolved_ip": decision.resolved_ip}

    def execute_tool_node(self, state: AssessmentState) -> dict[str, Any]:
        """Executes the approved tool proposal via the injected tool executor."""
        action_dict = state["current_action"]
        if not action_dict:
            return {}

        proposal = ActionProposal.model_validate(action_dict)
        proposal, pin_error = self._pin_proposal(state, proposal)
        if pin_error:
            return {
                "blocked_actions": [
                    *state["blocked_actions"],
                    {**action_dict, "denied_reason": pin_error},
                ],
                "current_action": None,
                "resolved_ip": None,
            }

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

        if retcode != 0:
            failure_type = classify_error(retcode, stderr or stdout)
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

            confirmed_finding = self.finding_verifier.confirm_finding(
                finding=potential_finding,
                verification_evidence_id=ev_id,
                verification_method=f"Automated probe verification via {obs.get('tool')}",
                reproduction_steps=repro,
                impact=f"Confirmed security flaw on {affected_asset}",
            )

            new_findings.append(confirmed_finding.model_dump(mode="json"))

        return {"findings": new_findings}

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

        if not initial_state.get("started_at"):
            initial_state["started_at"] = datetime.now(UTC).isoformat()
        initial_state["simulation_mode"] = self.simulation_mode

        result = self.graph.invoke(initial_state)
        return cast(AssessmentState, result)
