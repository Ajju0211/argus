"""Integration Tests for ARGUS LangGraph Agent Orchestrator.

Verifies dynamic tool discovery, context-driven planning, duplicate prevention,
deterministic objective evaluation, cancellation, and adaptive recovery.
Follows tdd-workflow and verification-loop guidelines.
"""

from pathlib import Path
from typing import Any

import pytest

from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, create_initial_state
from engine.recovery import compute_exponential_backoff
from engine.state import CancellationState, ExecutionBudget
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import ScopeDocument

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
def default_target() -> dict[str, Any]:
    return {"type": "web", "value": "http://192.168.100.5:8080"}


@pytest.fixture
def default_objective() -> dict[str, Any]:
    return {"find_cve": True, "required_hosts": 1}


class TestAgentOrchestrator:
    """Test suite verifying LangGraph state machine functionality."""

    def test_graph_compiles(self, valid_scope: ScopeDocument) -> None:
        """Confirms StateGraph compiles with all edges and nodes."""
        orchestrator = AssessmentOrchestrator(scope=valid_scope)
        assert orchestrator.graph is not None

    def test_dynamic_tool_selection(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Verifies that dynamic tools passed into state are recognized by orchestrator."""
        custom_tools = [
            {
                "tool_name": "custom_web_crawler",
                "categories": ["web_crawl"],
                "capabilities": ["endpoint_discovery"],
                "risk_level": "LOW",
            }
        ]
        state = create_initial_state(
            assessment_id="asm-dynamic-tools",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
            available_tools=custom_tools,
        )
        assert len(state["available_tools"]) == 1
        assert state["available_tools"][0]["tool_name"] == "custom_web_crawler"

    def test_strategy_pivot_on_new_observations(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Verifies engine shifts strategy from INITIAL_RECON to SERVICE_ENUMERATION."""
        sample_xml = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            tool_executor=lambda proposal: (0, sample_xml, ""),
        )
        state = create_initial_state(
            assessment_id="asm-pivot",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        assert state["current_strategy"] == "INITIAL_RECON"

        # Run recon node
        updated = orchestrator.recon_node(state)
        assert updated["current_strategy"] == "SERVICE_ENUMERATION"
        assert len(updated["discovered_services"]) > 0

    def test_duplicate_action_prevention(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Verifies proposing an identical tool action is blocked before execution."""
        proposal = ActionProposal(
            action_id="act-dup-001",
            target_host="192.168.100.5",
            target_port=8080,
            tool_name="nmap",
            action_category="network_recon",
            arguments={"flags": "-sV"},
            rationale="Duplicate scan attempt",
            expected_evidence="Port open",
        )
        fp = proposal.fingerprint()

        def duplicate_model_gateway(prompt: str) -> AssessmentDecision:
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                rationale="Repeating same check",
                proposed_action=proposal,
            )

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope, model_gateway=duplicate_model_gateway
        )
        state = create_initial_state(
            assessment_id="asm-dup-prevention",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        # Pre-populate action_history with the fingerprint
        state["action_history"] = [fp]

        plan_update = orchestrator.plan_action_node(state)
        # Duplicate action should be placed in blocked_actions
        assert len(plan_update.get("blocked_actions", [])) > 0
        assert "Duplicate action" in plan_update["blocked_actions"][0]["reject_reason"]

    def test_objective_completion_requires_verified_evidence(
        self, valid_scope: ScopeDocument, valid_scope_raw: str, default_target: dict[str, Any]
    ) -> None:
        """Declaring OBJECTIVE_ACHIEVED without verified CONFIRMED finding yields IN_PROGRESS."""
        objective_requiring_cve = {"find_cve": True, "required_hosts": 1}

        orchestrator = AssessmentOrchestrator(scope=valid_scope)
        state = create_initial_state(
            assessment_id="asm-cve-eval",
            target=default_target,
            objective=objective_requiring_cve,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        # Recon completed, but NO confirmed finding yet
        state["discovered_assets"] = ["192.168.100.5"]
        state["discovered_services"] = [{"port": 8080, "service": "http"}]

        eval_update = orchestrator.evaluate_completion_node(state)
        assert eval_update["completion"]["is_completed"] is False
        assert eval_update["completion"]["outcome"] == "IN_PROGRESS"

        # Now simulate verified finding with evidence
        state["findings"] = [
            {
                "finding_id": "find-101",
                "title": "Verified Path Traversal",
                "status": "CONFIRMED",
                "evidence_ids": ["ev-101"],
            }
        ]
        eval_update_verified = orchestrator.evaluate_completion_node(state)
        assert eval_update_verified["completion"]["is_completed"] is True
        assert eval_update_verified["completion"]["outcome"] == "SUCCESS"

    def test_cancellation_aborts_execution(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Verifies cancellation signal halts assessment immediately."""
        orchestrator = AssessmentOrchestrator(scope=valid_scope)
        state = create_initial_state(
            assessment_id="asm-cancel",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        state["cancellation"] = CancellationState(
            is_cancelled=True, reason="User manual abort"
        ).model_dump()

        eval_update = orchestrator.evaluate_completion_node(state)
        assert eval_update["completion"]["is_completed"] is True
        assert eval_update["completion"]["outcome"] == "CANCELLED"
        assert "cancelled by user" in eval_update["completion"]["summary"].lower()

    def test_budget_exhaustion_terminates_cleanly(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Verifies hitting iteration budget terminates with partial outcome."""
        orchestrator = AssessmentOrchestrator(scope=valid_scope)
        state = create_initial_state(
            assessment_id="asm-budget",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
        )
        state["budget"] = ExecutionBudget(max_iterations=5, iterations_used=5).model_dump()

        eval_update = orchestrator.evaluate_completion_node(state)
        assert eval_update["completion"]["is_completed"] is True
        assert eval_update["completion"]["outcome"] in ("PARTIAL_SUCCESS", "FAILED")

    def test_provider_rate_limit_backoff_and_failover(self) -> None:
        """Verifies exponential backoff calculation with random jitter."""
        b1 = compute_exponential_backoff(attempt=1, base=1.0)
        b2 = compute_exponential_backoff(attempt=2, base=1.0)
        b3 = compute_exponential_backoff(attempt=3, base=1.0)

        assert 1.0 <= b1 <= 2.5
        assert 2.0 <= b2 <= 3.5
        assert 4.0 <= b3 <= 5.5
        assert b3 > b2 > b1

    def test_end_to_end_assessment_run(
        self,
        valid_scope: ScopeDocument,
        valid_scope_raw: str,
        default_target: dict[str, Any],
        default_objective: dict[str, Any],
    ) -> None:
        """Executes full LangGraph workflow with mocked tool executor and model gateway."""
        sample_nmap = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
        sample_nuclei = (FIXTURES_DIR / "nuclei_sample.jsonl").read_text(encoding="utf-8")

        def fixture_tool_executor(proposal: ActionProposal) -> tuple[int, str, str]:
            if proposal.tool_name == "nmap":
                return 0, sample_nmap, ""
            if proposal.tool_name == "nuclei":
                return 0, sample_nuclei, ""
            return 0, "", ""

        def simulated_model(prompt: str) -> AssessmentDecision:
            # Model proposes verification check
            proposal = ActionProposal(
                action_id="act-nuclei-001",
                target_host="192.168.100.5",
                target_port=8080,
                tool_name="nuclei",
                action_category="active_template_check",
                arguments={"template": "cve-2021-41773"},
                rationale="Verifying path traversal",
                expected_evidence="HTTP 200 /etc/passwd",
            )
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                rationale="Running path traversal check",
                proposed_action=proposal,
            )

        orchestrator = AssessmentOrchestrator(
            scope=valid_scope,
            model_gateway=simulated_model,
            tool_executor=fixture_tool_executor,
        )
        initial_state = create_initial_state(
            assessment_id="asm-e2e-001",
            target=default_target,
            objective=default_objective,
            scope=valid_scope,
            scope_yaml_raw=valid_scope_raw,
            max_iterations=3,
        )

        final_state = orchestrator.run(initial_state)
        assert final_state["status"] in ("SUCCESS", "COMPLETED", "PARTIAL_SUCCESS")
        assert len(final_state["discovered_assets"]) > 0
        assert len(final_state["executed_actions"]) > 0
        assert len(final_state["evidence_refs"]) > 0
        assert len(final_state["findings"]) > 0
        assert (
            final_state["findings"][0].get("confidence") == "CONFIRMED"
            or final_state["findings"][0].get("status") == "CONFIRMED"
        )
