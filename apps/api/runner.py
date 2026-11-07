"""Background assessment worker and live event publisher (Spec 06).

The worker consumes the compiled LangGraph state machine node-by-node so the
dashboard can stream node transitions, tool actions, and findings in real time.
Supports clean execution pausing, checkpoint persistence, and resumption.
"""

import json
import logging
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from apps.api.database import TERMINAL_STATUSES, Database
from core.evidence.evidence_vault import EvidenceVault
from core.executor.process_runner import terminate_active_processes
from engine.graph import AssessmentOrchestrator, create_initial_state
from integrations.langfuse import LangfuseTracer
from packages.contracts.scope import ScopeDocument

logger = logging.getLogger(__name__)


def _action_summary(action: dict[str, Any] | None) -> dict[str, Any] | None:
    if not action:
        return None
    return {
        key: action.get(key)
        for key in (
            "action_id",
            "tool_name",
            "action_category",
            "target_host",
            "target_port",
            "step_index",
        )
        if action.get(key) is not None
    }


def _state_snapshot(state: dict[str, Any], node: str) -> dict[str, Any]:
    completion = state.get("completion") or {}
    budget = state.get("budget") or {}
    return {
        "node": node,
        "status": state.get("status"),
        "strategy": state.get("current_strategy"),
        "outcome": completion.get("outcome"),
        "assets": len(state.get("discovered_assets", [])),
        "services": len(state.get("discovered_services", [])),
        "observations": len(state.get("observations", [])),
        "findings": len(state.get("findings", [])),
        "evidence": len(state.get("evidence_refs", [])),
        "blocked_actions": len(state.get("blocked_actions", [])),
        "iterations_used": budget.get("iterations_used", 0),
        "current_action": _action_summary(state.get("current_action")),
        "latest_finding": (
            state.get("findings", [])[-1].get("title") if state.get("findings") else None
        ),
    }


class AssessmentRunner:
    """Launches assessments on daemon threads and persists every transition."""

    def __init__(
        self,
        database: Database,
        artifacts_dir: Path | str,
        *,
        simulation_default: bool = False,
        model_gateway: Any = None,
        tool_executor: Any = None,
    ) -> None:
        self.database = database
        self.artifacts_dir = Path(artifacts_dir)
        self.simulation_default = simulation_default
        self.model_gateway = model_gateway
        self.tool_executor = tool_executor
        self._active_assessments: set[str] = set()
        self._runner_lock = threading.Lock()

    def is_active(self, assessment_id: str) -> bool:
        """Return True while a worker thread is still executing this assessment."""
        with self._runner_lock:
            return assessment_id in self._active_assessments

    def launch(
        self,
        assessment_id: str,
        *,
        scope: ScopeDocument,
        scope_raw: str,
        target: dict[str, Any],
        objective: dict[str, Any],
        simulation: bool,
        max_iterations: int,
        initial_state: dict[str, Any] | None = None,
    ) -> None:
        with self._runner_lock:
            if assessment_id in self._active_assessments:
                logger.warning(
                    "Assessment %s already has an active worker thread; ignoring duplicate launch",
                    assessment_id,
                )
                return
            self._active_assessments.add(assessment_id)

        thread = threading.Thread(
            target=self._execute,
            args=(
                assessment_id,
                scope,
                scope_raw,
                target,
                objective,
                simulation,
                max_iterations,
                initial_state,
            ),
            name=f"argus-assessment-{assessment_id}",
            daemon=True,
        )
        thread.start()

    def _execute(
        self,
        assessment_id: str,
        scope: ScopeDocument,
        scope_raw: str,
        target: dict[str, Any],
        objective: dict[str, Any],
        simulation: bool,
        max_iterations: int,
        initial_state: dict[str, Any] | None = None,
    ) -> None:
        self.database.update_assessment(assessment_id, status="RUNNING")
        self.database.append_event(
            assessment_id, "assessment_started", data={"simulation": simulation}
        )

        existing_record = self.database.get(assessment_id) or {}
        existing_trace_id = existing_record.get("langfuse_trace_id")
        tracer = LangfuseTracer()
        trace_id, session_id = tracer.start_assessment_trace(
            assessment_id=assessment_id,
            target=target,
            objective=objective,
            scope_id=scope.assessment_id,
            simulation=simulation,
            max_iterations=max_iterations,
            trace_id=existing_trace_id,
        )
        if trace_id:
            self.database.update_assessment(
                assessment_id,
                langfuse_trace_id=trace_id,
                langfuse_session_id=session_id,
            )
            self.database.append_event(
                assessment_id,
                "langfuse_trace_linked",
                node="orchestrator",
                data={
                    "langfuse_trace_id": trace_id,
                    "langfuse_session_id": session_id,
                },
            )

        orchestrator = AssessmentOrchestrator(
            scope=scope,
            evidence_vault=EvidenceVault(base_dir=self.artifacts_dir),
            model_gateway=self.model_gateway,
            tool_executor=self.tool_executor,
            simulation_mode=simulation,
            cancel_check=lambda: self.database.is_cancel_requested(assessment_id),
            tracer=tracer,
        )

        if initial_state is None:
            state_dict = create_initial_state(
                assessment_id=assessment_id,
                target=target,
                objective=objective,
                scope=scope,
                scope_yaml_raw=scope_raw,
                max_iterations=max_iterations,
            )
            state = cast(dict[str, Any], dict(state_dict))
        else:
            state = dict(initial_state)

        paused = False
        emitted_findings: set[str] = set()
        active_action: dict[str, Any] | None = None
        try:
            for chunk in orchestrator.graph.stream(cast(Any, state), stream_mode="updates"):
                for node, update in chunk.items():
                    if isinstance(update, dict):
                        state.update(update)

                    # Persist state update
                    self.database.update_assessment(
                        assessment_id,
                        state_json=json.dumps(state, default=str),
                    )

                    # Append legacy node_transition event
                    self.database.append_event(
                        assessment_id,
                        "node_transition",
                        node=str(node),
                        data=_state_snapshot(state, str(node)),
                    )

                    # Append specific Spec 06 SSE events
                    if node == "validate_scope":
                        self.database.append_event(
                            assessment_id,
                            "scope_validated",
                            node=str(node),
                            data={"target": target, "scope_id": scope.assessment_id},
                        )
                        if state.get("status") != "FAILED":
                            self.database.append_event(
                                assessment_id,
                                "recon_started",
                                node=str(node),
                                data={
                                    "target": target,
                                    "message": "Running service discovery (nmap) against the target",
                                },
                            )
                    elif node == "recon":
                        self.database.append_event(
                            assessment_id,
                            "recon_completed",
                            node=str(node),
                            data={
                                "assets": state.get("discovered_assets", []),
                                "services": state.get("discovered_services", []),
                            },
                        )
                    elif node == "normalize_observations":
                        self.database.append_event(
                            assessment_id,
                            "planning_started",
                            node=str(node),
                            data={
                                "message": "Normalizing observations and asking the planner for the next action",
                                "observations": len(state.get("observations", [])),
                            },
                        )
                    elif node == "plan_action":
                        action = state.get("current_action")
                        if action:
                            active_action = _action_summary(action)
                            self.database.append_event(
                                assessment_id,
                                "action_proposed",
                                node=str(node),
                                data={
                                    "action": active_action,
                                    "rationale": action.get("rationale", ""),
                                    "tool_name": action.get("tool_name", ""),
                                    "target_host": action.get("target_host", ""),
                                },
                            )
                    elif node == "policy_gate":
                        action = state.get("current_action")
                        strategy = state.get("current_strategy")
                        if strategy == "BLOCKED":
                            self.database.append_event(
                                assessment_id,
                                "action_blocked",
                                node=str(node),
                                data={"action": _action_summary(action)},
                            )
                        elif action:
                            active_action = _action_summary(action)
                            self.database.append_event(
                                assessment_id,
                                "action_approved",
                                node=str(node),
                                data={"action": active_action},
                            )
                            self.database.append_event(
                                assessment_id,
                                "tool_started",
                                node=str(node),
                                data={
                                    "action": active_action,
                                    "message": "Executing policy-approved tool",
                                },
                            )
                    elif node == "execute_tool":
                        action = active_action or _action_summary(state.get("current_action"))
                        self.database.append_event(
                            assessment_id,
                            "tool_completed",
                            node=str(node),
                            data={
                                "action": action,
                                "message": "Tool execution finished; parsing observations",
                            },
                        )
                        # Sync evidence artifacts to DB
                        for ref in state.get("evidence_refs", []):
                            ev_id = ref.get("evidence_id") or ref.get("id")
                            if ev_id:
                                self.database.save_evidence_artifact(
                                    assessment_id=assessment_id,
                                    tool_name=ref.get("tool_name", "unknown"),
                                    sha256=ref.get("sha256", ""),
                                    file_path=ref.get("file_path", ""),
                                    artifact_id=ev_id,
                                )
                        recovery = state.get("recovery") or {}
                        recovering = bool(
                            recovery.get("last_failure_type")
                            and recovery.get("consecutive_failures", 0) > 0
                        )
                        next_event = "recovery_started" if recovering else "verification_started"
                        self.database.append_event(
                            assessment_id,
                            next_event,
                            node=str(node),
                            data={
                                "message": (
                                    "Analyzing the tool failure and planning a recovery action"
                                    if recovering
                                    else "Verifying observations and attaching evidence"
                                ),
                                "evidence": len(state.get("evidence_refs", [])),
                            },
                        )
                    elif node == "adaptive_recovery":
                        self.database.append_event(
                            assessment_id,
                            "recovery_started",
                            node=str(node),
                            data={"message": "Adaptive recovery is selecting a fallback strategy"},
                        )
                    elif node == "verify_finding":
                        findings = state.get("findings", [])
                        for f in findings:
                            finding_key = str(
                                f.get("finding_id") or f.get("id") or f.get("title") or ""
                            )
                            self.database.save_finding(assessment_id, f)
                            if finding_key and finding_key in emitted_findings:
                                continue
                            if finding_key:
                                emitted_findings.add(finding_key)
                            self.database.append_event(
                                assessment_id,
                                "finding_verified",
                                node=str(node),
                                data={"finding": f},
                            )
                    elif node == "evaluate_completion":
                        completion = state.get("completion") or {}
                        self.database.append_event(
                            assessment_id,
                            "completion_check",
                            node=str(node),
                            data={
                                "is_completed": completion.get("is_completed", False),
                                "outcome": completion.get("outcome"),
                                "message": "Evaluating whether the assessment objective is satisfied",
                            },
                        )
                    elif node == "report":
                        self.database.append_event(
                            assessment_id,
                            "report_generated",
                            node=str(node),
                            data={"report_path": state.get("report_path")},
                        )

                    # Pacing delay between node transitions for human-observable execution telemetry
                    time.sleep(0.3)

                    # Check for pause request at safe node boundary
                    if self.database.is_pause_requested(assessment_id):
                        checkpoint_id = f"chk-{uuid4().hex[:12]}"
                        checkpoint_blob = json.dumps(state, default=str).encode("utf-8")
                        self.database.save_checkpoint(
                            checkpoint_id=checkpoint_id,
                            assessment_id=assessment_id,
                            thread_id=f"thread-{assessment_id}",
                            checkpoint_blob=checkpoint_blob,
                        )
                        self.database.update_assessment(
                            assessment_id,
                            status="PAUSED",
                            state_json=json.dumps(state, default=str),
                        )
                        self.database.append_event(
                            assessment_id,
                            "assessment_paused",
                            node=str(node),
                            data={
                                "checkpoint_id": checkpoint_id,
                                "node": str(node),
                                "iterations_used": state.get("budget", {}).get(
                                    "iterations_used", 0
                                ),
                            },
                        )
                        paused = True
                        break

                if paused:
                    return

            if self.database.is_cancel_requested(assessment_id):
                terminate_active_processes(assessment_id)
                completion = dict(state.get("completion") or {})
                completion.update(
                    {
                        "is_completed": True,
                        "outcome": "CANCELLED",
                        "summary": "Assessment cancelled by user request. State was preserved.",
                    }
                )
                state["completion"] = completion
                state["status"] = "CANCELLED"
                try:
                    state.update(orchestrator.report_node(cast(Any, state)))
                except Exception as exc:  # noqa: BLE001 - report is best-effort
                    logger.warning(
                        "Report generation failed for cancelled assessment %s: %s",
                        assessment_id,
                        exc,
                    )

            now_iso = datetime.now(UTC).isoformat()
            status = str(state.get("status") or "FAILED")
            completion = state.get("completion") or {}
            report_path = state.get("report_path")
            report_pdf = None
            if report_path:
                candidate = Path(report_path).with_suffix(".pdf")
                if candidate.exists():
                    report_pdf = str(candidate)

            self.database.update_assessment(
                assessment_id,
                status=status if status in TERMINAL_STATUSES else "COMPLETED",
                outcome=completion.get("outcome"),
                summary=completion.get("summary"),
                report_markdown=state.get("report_markdown"),
                report_path_md=report_path,
                report_path_pdf=report_pdf,
                state_json=json.dumps(state, default=str),
                completed_at=now_iso,
            )
            self.database.append_event(
                assessment_id,
                "assessment_completed",
                data={
                    "status": status,
                    "outcome": completion.get("outcome"),
                    "summary": completion.get("summary"),
                    "report_available": bool(report_path),
                },
            )
        except Exception as exc:  # noqa: BLE001 - background worker must fail closed
            message = f"{type(exc).__name__}: {exc}"
            self.database.update_assessment(
                assessment_id,
                status="FAILED",
                outcome="FAILED",
                error=message,
                state_json=json.dumps(state, default=str),
                completed_at=datetime.now(UTC).isoformat(),
            )
            self.database.append_event(assessment_id, "assessment_failed", data={"error": message})
        finally:
            if tracer.is_enabled:
                tracer.end_assessment_trace(
                    status=str(state.get("status") or "FAILED"),
                    outcome=state.get("completion", {}).get("outcome"),
                    summary=state.get("completion", {}).get("summary"),
                    findings_count=len(state.get("findings", [])),
                    budget=state.get("budget"),
                )
            with self._runner_lock:
                self._active_assessments.discard(assessment_id)
            terminate_active_processes(assessment_id)
