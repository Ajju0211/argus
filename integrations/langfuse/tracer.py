"""Langfuse Observability & Telemetry Integration for ARGUS.

Tracks:
- AI requests & responses (prompts, rationale, decisions)
- Performance metrics (latency, token usage, fallback triggers)
- Objectives & inputs sent to the AI
- Tool usage (selected tool, arguments, target, duration, return codes, output, evidence)
- Policy evaluations and completion criteria checks

Graceful degradation:
If Langfuse credentials are not configured or LANGFUSE_ENABLED is false,
all methods safely operate as no-ops without any network calls or exceptions.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from core.config import get_settings

logger = logging.getLogger(__name__)

try:
    from langfuse import Langfuse
    HAS_LANGFUSE = True
except ImportError:
    Langfuse = None  # type: ignore
    HAS_LANGFUSE = False


class LangfuseTracer:
    """Manages Langfuse traces, generations, spans, and tool telemetry for assessments."""

    def __init__(
        self,
        public_key: str | None = None,
        secret_key: str | None = None,
        host: str | None = None,
        enabled: bool | None = None,
        client: Any = None,
    ) -> None:
        self._lock = threading.Lock()
        self.trace_id: str | None = None
        self.session_id: str | None = None
        self.root_span: Any = None

        if client is not None:
            self.client = client
            self.enabled = True if enabled is None else enabled
            return

        settings = get_settings()
        eff_enabled = settings.LANGFUSE_ENABLED if enabled is None else enabled
        pub_key = (public_key if public_key is not None else (settings.LANGFUSE_PUBLIC_KEY or "")).strip()
        sec_key = (secret_key if secret_key is not None else (settings.LANGFUSE_SECRET_KEY or "")).strip()
        host_url = (host if host is not None else (settings.LANGFUSE_HOST or "https://cloud.langfuse.com")).strip()

        if not HAS_LANGFUSE:
            logger.debug("Langfuse Python library is not installed; Langfuse tracing is disabled.")
            self.enabled = False
            self.client = None
            return

        if not eff_enabled or not pub_key or not sec_key:
            logger.debug(
                "Langfuse credentials missing or disabled; Langfuse tracing is inactive. "
                "(enabled=%s, has_public_key=%s, has_secret_key=%s)",
                eff_enabled,
                bool(pub_key),
                bool(sec_key),
            )
            self.enabled = False
            self.client = None
            return

        try:
            self.client = Langfuse(
                public_key=pub_key,
                secret_key=sec_key,
                host=host_url,
            )
            self.enabled = True
            logger.info("Langfuse tracer successfully initialized for host: %s", host_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to initialize Langfuse client (%s); falling back to no-op tracing: %s",
                type(exc).__name__,
                exc,
            )
            self.enabled = False
            self.client = None

    @property
    def is_enabled(self) -> bool:
        """Returns True if Langfuse is configured and active."""
        return self.enabled and self.client is not None

    def start_assessment_trace(
        self,
        assessment_id: str,
        target: dict[str, Any] | str,
        objective: dict[str, Any] | str,
        scope_id: str = "",
        simulation: bool = False,
        max_iterations: int = 20,
        trace_id: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Initializes a root agent observation and session trace in Langfuse."""
        if not self.is_enabled:
            return None, None

        with self._lock:
            try:
                self.session_id = assessment_id
                self.trace_id = trace_id or self.client.create_trace_id()
                target_val = (
                    target.get("value")
                    if isinstance(target, dict)
                    else str(target)
                )

                self.root_span = self.client.start_observation(
                    trace_context={"trace_id": self.trace_id},
                    name=f"ARGUS Assessment: {assessment_id}",
                    as_type="agent",
                    input={
                        "assessment_id": assessment_id,
                        "target": target,
                        "objective": objective,
                        "scope_id": scope_id,
                        "simulation": simulation,
                        "max_iterations": max_iterations,
                    },
                    metadata={
                        "session_id": self.session_id,
                        "assessment_id": assessment_id,
                        "target_value": target_val,
                        "scope_id": scope_id,
                        "simulation": simulation,
                    },
                )
                logger.info(
                    "Started Langfuse trace: trace_id=%s, session_id=%s",
                    self.trace_id,
                    self.session_id,
                )
                return self.trace_id, self.session_id
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse start_assessment_trace failed (non-fatal): %s", exc)
                return None, None

    def log_ai_generation(
        self,
        iteration: int,
        prompt: str,
        objective: Any,
        decision: Any,
        telemetry: Any = None,
        error: Exception | None = None,
    ) -> None:
        """Records an AI planner call, including the objective, prompt, performance metrics, and decision."""
        if not self.is_enabled or not self.trace_id or not self.root_span:
            return

        with self._lock:
            try:
                model_used = getattr(telemetry, "model_used", None) or "planner-model"
                provider_used = getattr(telemetry, "provider_used", "unknown")
                latency_ms = getattr(telemetry, "latency_ms", None)
                prompt_tokens = getattr(telemetry, "prompt_tokens", 0)
                completion_tokens = getattr(telemetry, "completion_tokens", 0)
                total_tokens = getattr(telemetry, "total_tokens", prompt_tokens + completion_tokens)
                fallback_triggered = getattr(telemetry, "fallback_triggered", False)

                decision_data: Any = None
                decision_type = "UNKNOWN"
                proposed_tool = None
                if decision is not None:
                    decision_type = str(getattr(decision, "decision_type", "UNKNOWN"))
                    if hasattr(decision, "model_dump"):
                        decision_data = decision.model_dump(mode="json")
                    elif isinstance(decision, dict):
                        decision_data = decision
                    else:
                        decision_data = str(decision)
                    if getattr(decision, "proposed_action", None):
                        proposed_tool = getattr(decision.proposed_action, "tool_name", None)

                gen_obs = self.client.start_observation(
                    trace_context={
                        "trace_id": self.trace_id,
                        "parent_span_id": self.root_span.id,
                    },
                    name=f"AI Planner - Step {iteration}",
                    as_type="generation",
                    model=model_used,
                    model_parameters={"temperature": 0.1},
                    input={
                        "objective": objective,
                        "prompt": prompt,
                    },
                    output=decision_data if not error else {"error": str(error)},
                    usage_details={
                        "input": prompt_tokens,
                        "output": completion_tokens,
                        "total": total_tokens,
                    },
                    metadata={
                        "session_id": self.session_id,
                        "step_index": iteration,
                        "provider": provider_used,
                        "latency_ms": latency_ms,
                        "fallback_triggered": fallback_triggered,
                        "decision_type": decision_type,
                        "proposed_tool": proposed_tool,
                        "objective": objective,
                    },
                    level="ERROR" if error else "DEFAULT",
                    status_message=str(error) if error else f"Decision: {decision_type}",
                )
                gen_obs.end()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse log_ai_generation failed (non-fatal): %s", exc)

    def log_policy_gate(
        self,
        proposal: Any,
        approved: bool,
        denial_reason: str = "",
    ) -> None:
        """Records policy evaluation for a proposed tool action."""
        if not self.is_enabled or not self.trace_id or not self.root_span:
            return

        with self._lock:
            try:
                tool_name = getattr(proposal, "tool_name", "unknown") if proposal else "unknown"
                arguments = getattr(proposal, "arguments", {}) if proposal else {}
                target_host = getattr(proposal, "target_host", "") if proposal else ""
                target_port = getattr(proposal, "target_port", None) if proposal else None

                gate_obs = self.client.start_observation(
                    trace_context={
                        "trace_id": self.trace_id,
                        "parent_span_id": self.root_span.id,
                    },
                    name=f"Policy Gate: {tool_name}",
                    as_type="guardrail",
                    input={
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "target_host": target_host,
                        "target_port": target_port,
                    },
                    output={
                        "decision": "APPROVED" if approved else "DENIED",
                        "denial_reason": denial_reason if not approved else None,
                    },
                    metadata={
                        "session_id": self.session_id,
                        "tool_name": tool_name,
                    },
                    level="DEFAULT" if approved else "WARNING",
                    status_message="Approved" if approved else f"Denied: {denial_reason}",
                )
                gate_obs.end()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse log_policy_gate failed (non-fatal): %s", exc)

    def log_tool_execution(
        self,
        proposal: Any,
        returncode: int,
        stdout: str,
        stderr: str,
        duration_seconds: float = 0.0,
        observations_count: int = 0,
        evidence_ids: list[str] | None = None,
    ) -> None:
        """Records a tool execution with input parameters, target, and output results."""
        if not self.is_enabled or not self.trace_id or not self.root_span:
            return

        with self._lock:
            try:
                tool_name = getattr(proposal, "tool_name", "unknown") if proposal else "unknown"
                arguments = getattr(proposal, "arguments", {}) if proposal else {}
                target_host = getattr(proposal, "target_host", "") if proposal else ""
                target_port = getattr(proposal, "target_port", None) if proposal else None
                action_category = getattr(proposal, "action_category", "general") if proposal else "general"
                rationale = getattr(proposal, "rationale", "") if proposal else ""
                tier = (
                    getattr(proposal.tier, "value", str(proposal.tier))
                    if hasattr(proposal, "tier") and proposal.tier is not None
                    else "T1_POLICY"
                )

                # Cap output strings to avoid excessive payload sizes
                stdout_snip = stdout[:4000] if stdout else ""
                stderr_snip = stderr[:4000] if stderr else ""

                tool_obs = self.client.start_observation(
                    trace_context={
                        "trace_id": self.trace_id,
                        "parent_span_id": self.root_span.id,
                    },
                    name=f"Tool: {tool_name}",
                    as_type="tool",
                    input={
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "target_host": target_host,
                        "target_port": target_port,
                        "action_category": action_category,
                        "rationale": rationale,
                        "risk_tier": tier,
                    },
                    output={
                        "returncode": returncode,
                        "stdout": stdout_snip,
                        "stderr": stderr_snip,
                        "observations_count": observations_count,
                        "evidence_ids": evidence_ids or [],
                    },
                    level="DEFAULT" if returncode == 0 else "WARNING",
                    status_message=f"Exit Code {returncode}",
                    metadata={
                        "session_id": self.session_id,
                        "tool_name": tool_name,
                        "target": f"{target_host}:{target_port}" if target_port else str(target_host),
                        "duration_seconds": round(duration_seconds, 3),
                        "observations_extracted": observations_count,
                    },
                )
                tool_obs.end()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse log_tool_execution failed (non-fatal): %s", exc)

    def log_completion_evaluation(
        self,
        objective: Any,
        completion: dict[str, Any],
        findings_count: int,
        iterations_used: int,
    ) -> None:
        """Records objective completion evaluation."""
        if not self.is_enabled or not self.trace_id or not self.root_span:
            return

        with self._lock:
            try:
                eval_obs = self.client.start_observation(
                    trace_context={
                        "trace_id": self.trace_id,
                        "parent_span_id": self.root_span.id,
                    },
                    name="Evaluate Objective Completion",
                    as_type="evaluator",
                    input={
                        "objective": objective,
                        "findings_count": findings_count,
                        "iterations_used": iterations_used,
                    },
                    output={
                        "is_completed": completion.get("is_completed", False),
                        "outcome": completion.get("outcome"),
                        "summary": completion.get("summary"),
                    },
                    metadata={
                        "session_id": self.session_id,
                        "is_completed": completion.get("is_completed", False),
                        "outcome": completion.get("outcome"),
                    },
                    level="DEFAULT" if completion.get("is_completed") else "DEBUG",
                    status_message=f"Outcome: {completion.get('outcome')}",
                )
                eval_obs.end()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse log_completion_evaluation failed (non-fatal): %s", exc)

    def end_assessment_trace(
        self,
        status: str,
        outcome: str | None = None,
        summary: str | None = None,
        findings_count: int = 0,
        budget: dict[str, Any] | None = None,
    ) -> None:
        """Concludes the root observation and flushes events to Langfuse."""
        if not self.is_enabled or not self.root_span:
            return

        with self._lock:
            try:
                self.root_span.update(
                    output={
                        "status": status,
                        "outcome": outcome,
                        "summary": summary,
                        "total_findings": findings_count,
                        "budget": budget or {},
                    },
                    metadata={
                        "session_id": self.session_id,
                        "final_status": status,
                        "final_outcome": outcome,
                        "total_findings": findings_count,
                    },
                    level="DEFAULT" if status in ("SUCCESS", "COMPLETED") else "WARNING",
                    status_message=f"Finished with status {status}",
                )
                self.root_span.end()
                if hasattr(self.client, "flush"):
                    self.client.flush()
                logger.info(
                    "Flushed Langfuse trace: trace_id=%s, session_id=%s",
                    self.trace_id,
                    self.session_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Langfuse end_assessment_trace failed (non-fatal): %s", exc)


def get_langfuse_tracer() -> LangfuseTracer:
    """Factory creating a LangfuseTracer configured from application settings."""
    return LangfuseTracer()
