"""Unit tests for Langfuse observability integration in ARGUS."""

from typing import Any
from unittest.mock import MagicMock

from integrations.langfuse.tracer import LangfuseTracer
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)


def test_langfuse_tracer_disabled_without_credentials() -> None:
    """Tracer must gracefully disable when credentials are not configured."""
    tracer = LangfuseTracer(public_key="", secret_key="", enabled=True)
    assert not tracer.is_enabled
    assert tracer.trace_id is None
    assert tracer.session_id is None

    # All methods should safely execute as no-ops without error
    trace_id, session_id = tracer.start_assessment_trace(
        assessment_id="asm-test-01",
        target={"value": "http://127.0.0.1:8080"},
        objective={"type": "discover_services"},
    )
    assert trace_id is None
    assert session_id is None

    tracer.log_ai_generation(
        iteration=1,
        prompt="Sample planning prompt",
        objective={"type": "discover_services"},
        decision=AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="Services discovered",
            completion_summary="Done",
        ),
    )
    tracer.log_policy_gate(
        proposal=None,
        approved=True,
    )
    tracer.log_tool_execution(
        proposal=None,
        returncode=0,
        stdout="Sample output",
        stderr="",
    )
    tracer.log_completion_evaluation(
        objective={"type": "discover_services"},
        completion={"is_completed": True, "outcome": "SUCCESS"},
        findings_count=1,
        iterations_used=2,
    )
    tracer.end_assessment_trace(status="SUCCESS")


def test_langfuse_tracer_with_mock_client() -> None:
    """Tracer must properly record generations, tools, policy, and completions when active."""
    mock_client = MagicMock()
    mock_client.create_trace_id.return_value = "0123456789abcdef0123456789abcdef"

    mock_root_span = MagicMock()
    mock_root_span.id = "root-span-id-123"
    mock_client.start_observation.return_value = mock_root_span

    tracer = LangfuseTracer(client=mock_client, enabled=True)
    assert tracer.is_enabled

    # 1. Start Assessment Trace
    trace_id, session_id = tracer.start_assessment_trace(
        assessment_id="asm-langfuse-test",
        target={"type": "web", "value": "http://lab.local:8080"},
        objective={"find_flag": True},
        scope_id="scope-001",
        simulation=True,
        max_iterations=15,
    )
    assert trace_id == "0123456789abcdef0123456789abcdef"
    assert session_id == "asm-langfuse-test"
    assert mock_client.start_observation.called

    call_args = mock_client.start_observation.call_args[1]
    assert call_args["as_type"] == "agent"
    assert call_args["input"]["assessment_id"] == "asm-langfuse-test"
    assert call_args["input"]["target"]["value"] == "http://lab.local:8080"
    assert call_args["metadata"]["session_id"] == "asm-langfuse-test"

    # 2. Record AI Generation
    mock_gen_span = MagicMock()
    mock_client.start_observation.return_value = mock_gen_span

    mock_telemetry = MagicMock()
    mock_telemetry.model_used = "anthropic/claude-3-5-sonnet-20241022"
    mock_telemetry.provider_used = "anthropic"
    mock_telemetry.latency_ms = 420
    mock_telemetry.prompt_tokens = 500
    mock_telemetry.completion_tokens = 80
    mock_telemetry.total_tokens = 580
    mock_telemetry.fallback_triggered = False

    decision = AssessmentDecision(
        decision_type=DecisionType.EXECUTE_ACTION,
        rationale="Execute recon scan",
        proposed_action=ActionProposal(
            action_id="act-001",
            tool_name="nmap",
            action_category="recon",
            target_host="192.168.100.5",
            target_port=8080,
            arguments={"ports": "8080"},
            rationale="Probe target HTTP port",
            expected_evidence="Open port 8080",
        ),
    )

    tracer.log_ai_generation(
        iteration=1,
        prompt="Planning prompt with objective",
        objective={"find_flag": True},
        decision=decision,
        telemetry=mock_telemetry,
    )

    gen_call = mock_client.start_observation.call_args[1]
    assert gen_call["as_type"] == "generation"
    assert gen_call["name"] == "AI Planner - Step 1"
    assert gen_call["model"] == "anthropic/claude-3-5-sonnet-20241022"
    assert gen_call["input"]["objective"] == {"find_flag": True}
    assert gen_call["usage_details"]["total"] == 580
    assert gen_call["metadata"]["latency_ms"] == 420
    assert gen_call["metadata"]["proposed_tool"] == "nmap"
    assert mock_gen_span.end.called

    # 3. Record Policy Gate
    mock_gate_span = MagicMock()
    mock_client.start_observation.return_value = mock_gate_span

    tracer.log_policy_gate(
        proposal=decision.proposed_action,
        approved=True,
    )
    gate_call = mock_client.start_observation.call_args[1]
    assert gate_call["as_type"] == "guardrail"
    assert gate_call["output"]["decision"] == "APPROVED"
    assert mock_gate_span.end.called

    # 4. Record Tool Execution
    mock_tool_span = MagicMock()
    mock_client.start_observation.return_value = mock_tool_span

    tracer.log_tool_execution(
        proposal=decision.proposed_action,
        returncode=0,
        stdout="PORT 8080/tcp open http",
        stderr="",
        duration_seconds=1.25,
        observations_count=1,
        evidence_ids=["ev-001"],
    )
    tool_call = mock_client.start_observation.call_args[1]
    assert tool_call["as_type"] == "tool"
    assert tool_call["name"] == "Tool: nmap"
    assert tool_call["input"]["tool_name"] == "nmap"
    assert tool_call["input"]["target_host"] == "192.168.100.5"
    assert tool_call["output"]["returncode"] == 0
    assert tool_call["output"]["observations_count"] == 1
    assert tool_call["output"]["evidence_ids"] == ["ev-001"]
    assert mock_tool_span.end.called

    # 5. Record Objective Evaluation
    mock_eval_span = MagicMock()
    mock_client.start_observation.return_value = mock_eval_span

    tracer.log_completion_evaluation(
        objective={"find_flag": True},
        completion={"is_completed": True, "outcome": "SUCCESS", "summary": "Flag captured"},
        findings_count=1,
        iterations_used=1,
    )
    eval_call = mock_client.start_observation.call_args[1]
    assert eval_call["as_type"] == "evaluator"
    assert eval_call["input"]["objective"] == {"find_flag": True}
    assert eval_call["output"]["outcome"] == "SUCCESS"
    assert mock_eval_span.end.called

    # 6. Conclude Assessment Trace
    tracer.end_assessment_trace(
        status="SUCCESS",
        outcome="SUCCESS",
        summary="Objective achieved",
        findings_count=1,
        budget={"iterations_used": 1},
    )
    assert mock_root_span.update.called
    assert mock_root_span.end.called
    assert mock_client.flush.called


def test_langfuse_tracer_handles_exceptions_gracefully() -> None:
    """Tracer methods must never crash if Langfuse client throws exceptions."""
    mock_client = MagicMock()
    mock_client.create_trace_id.side_effect = RuntimeError("Langfuse API unavailable")
    mock_client.start_observation.side_effect = RuntimeError("Network error")
    mock_client.flush.side_effect = RuntimeError("Flush failed")

    tracer = LangfuseTracer(client=mock_client, enabled=True)
    assert tracer.is_enabled

    # Should not raise exception
    trace_id, session_id = tracer.start_assessment_trace(
        assessment_id="asm-fail",
        target="http://example.com",
        objective="test",
    )
    assert trace_id is None
    assert session_id is None

    tracer.log_ai_generation(iteration=1, prompt="", objective="", decision=None)
    tracer.log_tool_execution(proposal=None, returncode=0, stdout="", stderr="")
    tracer.end_assessment_trace(status="FAILED")


def test_database_persists_langfuse_ids(tmp_path: Any) -> None:
    """Database must store and retrieve langfuse_trace_id and langfuse_session_id."""
    from apps.api.database import Database

    db_path = tmp_path / "test_langfuse.db"
    db = Database(db_path)

    assessment_id = "asm-langfuse-db-test"
    db.create(
        assessment_id=assessment_id,
        name="Langfuse DB Test",
        target={"type": "web", "value": "http://127.0.0.1:8080"},
        objective={"type": "discover_services"},
        scope={"assessment_id": "scope-01"},
        scope_raw="schema_version: '1.0'\nassessment_id: scope-01\ntargets:\n  allowed_hosts: ['127.0.0.1']",
        simulation=True,
        max_iterations=5,
    )

    db.update_assessment(
        assessment_id,
        langfuse_trace_id="tr-trace-abc-123",
        langfuse_session_id="asm-langfuse-db-test",
    )

    record = db.get(assessment_id)
    assert record is not None
    assert record["langfuse_trace_id"] == "tr-trace-abc-123"
    assert record["langfuse_session_id"] == "asm-langfuse-db-test"


def test_orchestrator_works_with_langfuse_enabled(tmp_path: Any) -> None:
    """Orchestrator runs normally and tracks events when Langfuse is enabled."""
    from engine.graph import AssessmentOrchestrator, create_initial_state
    from packages.contracts.scope import normalize_scope

    mock_client = MagicMock()
    mock_client.create_trace_id.return_value = "trace-orchestrator-test-id"
    mock_root_span = MagicMock()
    mock_root_span.id = "root-span-orch"
    mock_client.start_observation.return_value = mock_root_span

    tracer = LangfuseTracer(client=mock_client, enabled=True)

    scope_yaml = """
schema_version: "1.0"
assessment_id: orch-test
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [8080]
actions:
  allowed_categories: ["network_recon"]
"""
    scope = normalize_scope(scope_yaml)
    state = create_initial_state(
        assessment_id="asm-orch-test",
        target={"type": "web", "value": "http://192.168.100.5:8080"},
        objective={"type": "discover_services"},
        scope=scope,
        scope_yaml_raw=scope_yaml,
        max_iterations=2,
    )

    def mock_gateway(prompt: str) -> AssessmentDecision:
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="Discovered all target services.",
            completion_summary="Assessment objective met.",
        )

    orch = AssessmentOrchestrator(
        scope=scope,
        model_gateway=mock_gateway,
        simulation_mode=True,
        tracer=tracer,
    )
    final_state = orch.run(state)
    assert final_state["status"] in ("SUCCESS", "COMPLETED", "PARTIAL_SUCCESS", "FAILED")
    assert tracer.trace_id == "trace-orchestrator-test-id"
    assert mock_root_span.update.called
    assert mock_client.flush.called


def test_orchestrator_works_without_langfuse_credentials(tmp_path: Any) -> None:
    """Orchestrator runs cleanly without errors when Langfuse has no credentials."""
    from engine.graph import AssessmentOrchestrator, create_initial_state
    from packages.contracts.scope import normalize_scope

    # Langfuse without credentials
    tracer = LangfuseTracer(public_key="", secret_key="", enabled=True)
    assert not tracer.is_enabled

    scope_yaml = """
schema_version: "1.0"
assessment_id: orch-test-nocreds
targets:
  allowed_hosts: ["192.168.100.5"]
ports:
  allowed_ports: [8080]
actions:
  allowed_categories: ["network_recon"]
"""
    scope = normalize_scope(scope_yaml)
    state = create_initial_state(
        assessment_id="asm-orch-nocreds",
        target={"type": "web", "value": "http://192.168.100.5:8080"},
        objective={"type": "discover_services"},
        scope=scope,
        scope_yaml_raw=scope_yaml,
        max_iterations=2,
    )

    def mock_gateway(prompt: str) -> AssessmentDecision:
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="Done",
            completion_summary="Done without Langfuse",
        )

    orch = AssessmentOrchestrator(
        scope=scope,
        model_gateway=mock_gateway,
        simulation_mode=True,
        tracer=tracer,
    )
    final_state = orch.run(state)
    assert final_state["status"] in ("SUCCESS", "COMPLETED", "PARTIAL_SUCCESS", "FAILED")
    assert final_state["completion"]["is_completed"] is True

