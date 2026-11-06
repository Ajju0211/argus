"""Security and Safety Policy Hardening Test Suite (Track 02 / S-01 to S-10).

Verifies port allowlist enforcement on None/URLs, DNS pinning against rebinding,
protocol enforcement, redirect policy enforcement, tool registry security gates,
duration timeouts, process group isolation, and default-denied infrastructure guards.
"""

import time
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from core.executor.process_runner import kill_process_group
from core.executor.rate_limiter import ToolRateLimiter
from core.executor.tool_registry import SecurityConfigurationError, ToolRegistry
from core.policy.policy_engine import PolicyEngine
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, create_initial_state
from engine.nodes.evaluate_completion import evaluate_completion
from engine.recovery import FailureType
from integrations.tools.base import NormalizedObservation, ToolAdapter
from packages.contracts import ActionProposal, ScopeDocument

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def valid_scope() -> ScopeDocument:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    return ScopeValidator.parse_yaml_file(yaml_path)


@pytest.fixture
def valid_scope_raw() -> str:
    yaml_path = FIXTURES_DIR / "valid_scope.yaml"
    return yaml_path.read_text(encoding="utf-8")


@pytest.fixture
def policy_engine(valid_scope: ScopeDocument) -> PolicyEngine:
    return PolicyEngine(valid_scope)


class TestScopeAndSafetyHardening:
    """Security tests covering S-01 through S-10."""

    # -------------------------------------------------------------
    # S-01: Port Allowlist Validation when Port is None
    # -------------------------------------------------------------
    def test_action_with_none_port_infers_from_url_and_blocks_unauthorized(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-01: An action targeting http://192.168.100.5/ (port 80) when allowed_ports has no 80 is blocked."""
        # Create a scope where only port 8080 is allowed
        scope_dict = policy_engine.scope.model_dump()
        scope_dict["ports"]["allowed_ports"] = [8080]
        custom_scope = ScopeDocument.model_validate(scope_dict)
        engine = PolicyEngine(custom_scope)

        proposal = ActionProposal(
            action_id="act-s01-001",
            target_host="192.168.100.5",
            target_port=None,  # Port is None!
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"target": "http://192.168.100.5/"},  # Port 80 is implicit
            rationale="Testing implicit port 80 block",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False
        assert "port 80" in decision.reason.lower()

    def test_action_with_none_port_infers_from_url_and_approves_authorized(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-01: An action targeting http://192.168.100.5:8080/ infers 8080 and is approved."""
        proposal = ActionProposal(
            action_id="act-s01-002",
            target_host="192.168.100.5",
            target_port=None,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"target_url": "http://192.168.100.5:8080/login"},
            rationale="Testing inferred port 8080",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is True

    def test_web_action_without_port_fails_closed(self, policy_engine: PolicyEngine) -> None:
        """S-01: A web action with no port and no inferrable URL fails closed."""
        proposal = ActionProposal(
            action_id="act-s01-003",
            target_host="192.168.100.5",
            target_port=None,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={},
            rationale="Testing missing port fail closed",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "unspecified" in decision.reason.lower()

    # -------------------------------------------------------------
    # S-02: Hostname DNS Pinning Against Rebinding Attacks
    # -------------------------------------------------------------
    def test_hostname_resolving_to_cloud_metadata_is_blocked(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-02: Allowed hostname that dynamically resolves to 169.254.169.254 is deterministically blocked."""
        with patch.object(policy_engine, "_resolve_host", return_value="169.254.169.254"):
            proposal = ActionProposal(
                action_id="act-s02-001",
                target_host="lab-target.local",
                target_port=8080,
                tool_name="nuclei",
                action_category="active_template_check",
                arguments={},
                rationale="Testing DNS rebinding to metadata service",
                expected_evidence="None",
            )
            decision = policy_engine.evaluate(proposal)
            assert decision.approved is False
            assert any(term in decision.reason.lower() for term in ["link-local", "denied", "ssrf"])

    def test_hostname_resolving_outside_scope_cidr_is_blocked(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-02: Allowed hostname resolving to unpermitted IP (e.g. 10.0.0.1) is blocked by DNS rebinding guard."""
        with patch.object(policy_engine, "_resolve_host", return_value="10.0.0.1"):
            proposal = ActionProposal(
                action_id="act-s02-002",
                target_host="lab-target.local",
                target_port=8080,
                tool_name="nmap",
                action_category="network_recon",
                arguments={},
                rationale="Testing DNS rebinding outside authorized CIDR",
                expected_evidence="None",
            )
            decision = policy_engine.evaluate(proposal)
            assert decision.approved is False
            assert "outside" in decision.reason.lower()

    # -------------------------------------------------------------
    # S-03: Protocol Restriction Enforcement
    # -------------------------------------------------------------
    def test_disallowed_protocols_blocked(self, policy_engine: PolicyEngine) -> None:
        """S-03: file://, ftp://, and gopher:// are rejected when scope allows http/https/tcp."""
        for disallowed_uri in [
            "file:///etc/passwd",
            "ftp://192.168.100.5/pub",
            "gopher://192.168.100.5/",
            "ssh://192.168.100.5",
        ]:
            proposal = ActionProposal(
                action_id="act-s03-proto",
                target_host="192.168.100.5",
                target_port=8080,
                tool_name="nuclei",
                action_category="active_template_check",
                arguments={"url": disallowed_uri},
                rationale="Testing disallowed protocol",
                expected_evidence="None",
            )
            decision = policy_engine.evaluate(proposal)
            assert decision.approved is False
            assert (
                "not in allowed protocols" in decision.reason.lower()
                or "explicitly denied" in decision.reason.lower()
            )

    # -------------------------------------------------------------
    # S-04: HTTP Redirect Policy Enforcement
    # -------------------------------------------------------------
    def test_redirect_strict_same_host_blocks_external_host(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-04: strict_same_host policy blocks 302 redirect to another domain."""
        decision = policy_engine.validate_redirect(
            initial_url="http://192.168.100.5:8080/login",
            redirect_target_url="http://evil.com/callback",
        )
        assert decision.approved is False
        assert "violates strict_same_host" in decision.reason

    def test_redirect_strict_same_host_blocks_different_port(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-04: strict_same_host policy blocks redirect to a different port."""
        decision = policy_engine.validate_redirect(
            initial_url="http://192.168.100.5:8080/login",
            redirect_target_url="http://192.168.100.5:80/unauthorized",
        )
        assert decision.approved is False
        assert "violates strict_same_host" in decision.reason

    def test_redirect_to_cloud_metadata_is_blocked(self, policy_engine: PolicyEngine) -> None:
        """S-04: Redirect to 169.254.169.254 is blocked under all policies."""
        decision = policy_engine.validate_redirect(
            initial_url="http://192.168.100.5:8080/fetch?url=...",
            redirect_target_url="http://169.254.169.254/latest/meta-data/",
        )
        assert decision.approved is False
        assert any(term in decision.reason.lower() for term in ["loopback", "metadata", "reserved"])

    def test_redirect_block_all_policy(self, valid_scope: ScopeDocument) -> None:
        """S-04: block_all redirect policy halts on any redirect."""
        scope_dict = valid_scope.model_dump()
        scope_dict["network_policy"]["redirect_policy"] = "block_all"
        custom_scope = ScopeDocument.model_validate(scope_dict)
        engine = PolicyEngine(custom_scope)

        decision = engine.validate_redirect(
            initial_url="http://192.168.100.5:8080/a",
            redirect_target_url="http://192.168.100.5:8080/b",
        )
        assert decision.approved is False
        assert "prohibited" in decision.reason.lower()

    # -------------------------------------------------------------
    # S-05: Tool Registry Security Gate
    # -------------------------------------------------------------
    def test_tool_registry_rejects_adapter_missing_capabilities(self) -> None:
        """S-05: An adapter with empty capabilities fails registration."""
        registry = ToolRegistry()

        class IncompleteAdapter(ToolAdapter):
            @property
            def tool_name(self) -> str:
                return "incomplete"

            @property
            def capabilities(self) -> list[str]:
                return []

            @property
            def categories(self) -> list[str]:
                return ["network_recon"]

            @property
            def risk_level(self) -> str:
                return "LOW"

            def validate_args(self, args: dict[str, Any]) -> bool:
                return True

            def build_command(self, args: dict[str, Any]) -> list[str]:
                return ["test"]

            def parse_output(
                self, raw_output: str, evidence_id: str
            ) -> list[NormalizedObservation]:
                return []

        with pytest.raises(SecurityConfigurationError, match="must declare capabilities"):
            registry.register(IncompleteAdapter())

    def test_tool_registry_rejects_adapter_allowing_shell_injection(self) -> None:
        """S-05: An adapter whose validate_args permits shell injections fails registration."""
        registry = ToolRegistry()

        class InsecureAdapter(ToolAdapter):
            @property
            def tool_name(self) -> str:
                return "insecure"

            @property
            def capabilities(self) -> list[str]:
                return ["scan"]

            @property
            def categories(self) -> list[str]:
                return ["network_recon"]

            @property
            def risk_level(self) -> str:
                return "LOW"

            def validate_args(self, args: dict[str, Any]) -> bool:
                return True  # Permits everything including ; rm -rf /

            def build_command(self, args: dict[str, Any]) -> list[str]:
                return ["insecure", str(args.get("target"))]

            def parse_output(
                self, raw_output: str, evidence_id: str
            ) -> list[NormalizedObservation]:
                return []

        with pytest.raises(SecurityConfigurationError, match="shell injection"):
            registry.register(InsecureAdapter())

    # -------------------------------------------------------------
    # S-06: Global Assessment Duration Timeout
    # -------------------------------------------------------------
    def test_global_assessment_duration_timeout_enforced(self) -> None:
        """S-06: If assessment duration exceeds max_duration_seconds, evaluate_completion halts."""
        from datetime import UTC, datetime, timedelta

        # Started 2 hours ago
        past_time = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        evaluation = evaluate_completion(
            objective={"find_cve": True},
            findings=[],
            discovered_assets=["192.168.100.5"],
            discovered_services=[{"port": 8080}],
            budget={"max_duration_seconds": 1800, "max_iterations": 20, "iterations_used": 1},
            cancellation={"is_cancelled": False},
            recovery={"consecutive_failures": 0},
            started_at=past_time,
        )
        assert evaluation["is_completed"] is True
        assert evaluation["outcome"] == "FAILED"
        assert "duration limit" in evaluation["summary"].lower()

    # -------------------------------------------------------------
    # S-07: Process Group Isolation for Tool Cancellation
    # -------------------------------------------------------------
    def test_kill_process_group_safe_on_invalid_pid(self) -> None:
        """S-07: kill_process_group handles non-existent PIDs safely without crashing."""
        # Non-existent high PID
        kill_process_group(9999999)

    # -------------------------------------------------------------
    # S-08: Execution Exceptions and Timeout Connection to Recovery State
    # -------------------------------------------------------------
    def test_execute_tool_timeout_transitions_to_adaptive_recovery(
        self, valid_scope: ScopeDocument, valid_scope_raw: str
    ) -> None:
        """S-08: Tool execution TimeoutError is caught and increments consecutive_failures."""

        def timeout_executor(p: ActionProposal) -> tuple[int, str, str]:
            raise TimeoutError("Nmap process hung for 120s")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            tool_executor=timeout_executor,
        )
        state = create_initial_state(
            assessment_id="asm-s08-timeout",
            target={"type": "web", "value": "http://192.168.100.5:8080"},
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        proposal = ActionProposal(
            action_id="act-hung-001",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5"},
            rationale="Hung scan",
            expected_evidence="None",
        )
        state["current_action"] = proposal.model_dump()

        update = orchestrator.execute_tool_node(state)
        assert update["current_action"] is None
        assert update["recovery"]["consecutive_failures"] == 1
        assert update["recovery"]["last_failure_type"] == FailureType.RECOVERABLE_TIMEOUT

    def test_execute_tool_unhandled_exception_transitions_to_recovery(
        self, valid_scope: ScopeDocument, valid_scope_raw: str
    ) -> None:
        """S-08: Unexpected execution exception does not crash LangGraph; transitions to recovery."""

        def crash_executor(p: ActionProposal) -> tuple[int, str, str]:
            raise OSError("I/O device failure")

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            tool_executor=crash_executor,
        )
        state = create_initial_state(
            assessment_id="asm-s08-crash",
            target={"type": "web", "value": "http://192.168.100.5:8080"},
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        proposal = ActionProposal(
            action_id="act-crash-001",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5"},
            rationale="Crash scan",
            expected_evidence="None",
        )
        state["current_action"] = proposal.model_dump()

        update = orchestrator.execute_tool_node(state)
        assert update["current_action"] is None
        assert update["recovery"]["consecutive_failures"] == 1

    # -------------------------------------------------------------
    # S-09: Action Deduplication
    # -------------------------------------------------------------
    def test_action_fingerprint_deterministic_with_mixed_args(self) -> None:
        """S-09: Action proposals with same attributes produce identical fingerprints regardless of arg key order."""
        p1 = ActionProposal(
            action_id="act-1",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"a": 1, "b": "val"},
            rationale="Test",
            expected_evidence="None",
        )
        p2 = ActionProposal(
            action_id="act-2",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"b": "val", "a": 1},
            rationale="Different rationale",
            expected_evidence="Different expected",
        )
        assert p1.fingerprint() == p2.fingerprint()

    # -------------------------------------------------------------
    # S-10: Scope Conflict Detection & Default-Denied Infrastructure
    # -------------------------------------------------------------
    def test_scope_validator_rejects_authorizing_loopback_subnet(self) -> None:
        """S-10: Scope document containing 127.0.0.0/8 in allowed_subnets is rejected."""
        yaml_content = """
schema_version: "1.0"
assessment_id: "asm-s10-loopback"
name: "Loopback Scope"
created_at: "2026-11-04T12:00:00Z"
expires_at: "2027-11-05T12:00:00Z"
targets:
  allowed_hosts: []
  allowed_subnets: ["127.0.0.0/8"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        scope = ScopeValidator.parse_yaml_string(yaml_content)
        is_valid, reason = ScopeValidator.validate_scope_document(scope)
        assert is_valid is False
        assert "default-denied infrastructure" in reason.lower()

    def test_scope_validator_rejects_authorizing_link_local_subnet(self) -> None:
        """S-10: Scope document containing 169.254.0.0/16 in allowed_subnets is rejected."""
        yaml_content = """
schema_version: "1.0"
assessment_id: "asm-s10-linklocal"
name: "Metadata Scope"
created_at: "2026-11-04T12:00:00Z"
expires_at: "2027-11-05T12:00:00Z"
targets:
  allowed_hosts: []
  allowed_subnets: ["169.254.0.0/16"]
ports:
  allowed_ports: [80]
actions:
  allowed_categories: ["network_recon"]
"""
        scope = ScopeValidator.parse_yaml_string(yaml_content)
        is_valid, reason = ScopeValidator.validate_scope_document(scope)
        assert is_valid is False
        assert "default-denied infrastructure" in reason.lower()

    def test_denied_hosts_takes_precedence_over_allowed_hosts(self) -> None:
        """S-10: When a host is present in both allowed_hosts and denied_hosts, it is denied."""
        yaml_content = """
schema_version: "1.0"
assessment_id: "asm-s10-conflict"
name: "Conflict Scope"
created_at: "2026-11-04T12:00:00Z"
expires_at: "2027-11-05T12:00:00Z"
targets:
  allowed_hosts: ["192.168.100.5"]
  denied_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [8080]
actions:
  allowed_categories: ["network_recon"]
"""
        scope = ScopeValidator.parse_yaml_string(yaml_content)
        engine = PolicyEngine(scope)

        proposal = ActionProposal(
            action_id="act-s10-conflict",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={},
            rationale="Testing conflict precedence",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False
        assert "explicitly denied" in decision.reason

    # -------------------------------------------------------------
    # Regression tests for the gaps found in the Track 02 review
    # -------------------------------------------------------------
    def test_recon_port_range_outside_allowlist_is_blocked(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-01: '1-65535' cannot bypass a scope that only allows 80/443."""
        scope_dict = policy_engine.scope.model_dump()
        scope_dict["ports"]["allowed_ports"] = [80, 443]
        engine = PolicyEngine(ScopeDocument.model_validate(scope_dict))

        proposal = ActionProposal(
            action_id="act-range-bypass",
            target_host="192.168.100.5",
            target_port=None,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5", "ports": "1-65535"},
            rationale="Attempting a full-range scan outside the allowlist",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False
        assert "not in allowed ports" in decision.reason.lower()

    def test_recon_without_explicit_ports_fails_closed(self, policy_engine: PolicyEngine) -> None:
        """S-01: A scan with no port argument must not fall back to Nmap's default range."""
        proposal = ActionProposal(
            action_id="act-no-ports",
            target_host="192.168.100.5",
            target_port=None,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5"},
            rationale="Default Nmap port range would leave the allowlist",
            expected_evidence="None",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is False
        assert "explicit port set" in decision.reason.lower()

    def test_recon_with_allowlisted_comma_ports_is_approved(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-01: A comma-separated port list contained in the allowlist is approved."""
        proposal = ActionProposal(
            action_id="act-comma-ports",
            target_host="192.168.100.5",
            target_port=None,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"target": "192.168.100.5", "ports": "80,8080"},
            rationale="Scanning only allowlisted ports",
            expected_evidence="Open ports",
        )
        decision = policy_engine.evaluate(proposal)
        assert decision.approved is True

    def test_schemeless_web_action_cannot_bypass_https_only_scope(
        self, policy_engine: PolicyEngine
    ) -> None:
        """S-03: A bare host on port 80 is treated as HTTP and blocked when only HTTPS is allowed."""
        scope_dict = policy_engine.scope.model_dump()
        scope_dict["protocols"]["allowed"] = ["https"]
        scope_dict["protocols"]["denied"] = []
        engine = PolicyEngine(ScopeDocument.model_validate(scope_dict))

        proposal = ActionProposal(
            action_id="act-schemeless-proto",
            target_host="192.168.100.5",
            target_port=80,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={},
            rationale="Scheme-less HTTP action against an HTTPS-only scope",
            expected_evidence="None",
        )
        decision = engine.evaluate(proposal)
        assert decision.approved is False
        assert "not in allowed protocols" in decision.reason.lower()

    def test_dns_rebinding_between_policy_and_execution_is_blocked(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
    ) -> None:
        """S-02: A hostname that changes IP after approval must not execute."""
        executed: list[ActionProposal] = []

        def executor(proposal: ActionProposal) -> tuple[int, str, str]:
            executed.append(proposal)
            return 0, "", ""

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            tool_executor=executor,
            simulation_mode=True,
        )
        state = create_initial_state(
            assessment_id="asm-dns-pin",
            target={"type": "web", "value": "http://lab-target.local:8080"},
            objective={"find_cve": True},
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        proposal = ActionProposal(
            action_id="act-dns-pin",
            target_host="lab-target.local",
            target_port=8080,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"target": "http://lab-target.local:8080"},
            rationale="Pinned DNS verification",
            expected_evidence="None",
        )
        state["current_action"] = proposal.model_dump()
        state["resolved_ip"] = "192.168.100.5"

        with patch("engine.graph.socket.gethostbyname", return_value="10.0.0.1"):
            update = orchestrator.execute_tool_node(state)

        assert executed == []
        assert len(update["blocked_actions"]) == 1
        assert "dns rebinding" in update["blocked_actions"][0]["denied_reason"].lower()

    def test_redirect_policy_is_enforced_before_http_tool_execution(
        self, valid_scope: ScopeDocument
    ) -> None:
        """S-04: An out-of-policy redirect blocks the HTTP tool before it runs."""
        orchestrator = AssessmentOrchestrator(scope=valid_scope, simulation_mode=True)
        proposal = ActionProposal(
            action_id="act-redirect",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nuclei",
            action_category="active_template_check",
            arguments={"target": "http://192.168.100.5:8080/"},
            rationale="Redirect policy check",
            expected_evidence="None",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                302,
                headers={"location": "http://192.168.100.5:9090/out-of-policy"},
            )

        real_client = httpx.Client

        def client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client(*args, **kwargs)

        with patch("engine.graph.httpx.Client", side_effect=client_factory):
            allowed, reason = orchestrator._preflight_http_redirects(proposal)

        assert allowed is False
        assert "strict_same_host" in reason.lower() or "violates" in reason.lower()

    def test_rate_limiter_enforces_scope_interval(self) -> None:
        """S-06: The limiter spaces requests according to max_requests_per_second."""
        limiter = ToolRateLimiter(max_requests_per_second=5, max_concurrency=2)

        started = time.monotonic()
        with limiter.limit():
            pass
        with limiter.limit():
            pass
        elapsed = time.monotonic() - started

        assert elapsed >= 0.15

    def test_rate_limiter_enforces_concurrency_cap(self) -> None:
        """S-06: No more than max_concurrency tool slots may run at once."""
        limiter = ToolRateLimiter(max_requests_per_second=1000, max_concurrency=2)
        active = 0
        peak = 0
        lock = Lock()

        def worker() -> None:
            nonlocal active, peak
            with limiter.limit():
                with lock:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.05)
                with lock:
                    active -= 1

        threads = [Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert peak <= 2
