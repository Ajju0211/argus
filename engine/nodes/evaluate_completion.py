"""Deterministic Objective Completion Evaluator for ARGUS.

Ensures that an assessment is never marked SUCCESS based on model claims alone;
requires verified evidence and objective fulfillment.
"""

import re
from datetime import UTC, datetime
from typing import Any

from engine.state import CompletionEvaluation

_FLAG_PATTERN = re.compile(r"flag\{[^}\s]{1,}\}", re.IGNORECASE)


def _flag_candidates(data: dict[str, Any]) -> list[str]:
    """Extracts only explicit flag-bearing values from observation data.

    Deliberately does not search arbitrary description/name fields, which caused
    false positives such as "no flag present" being treated as a capture.
    """
    candidates: list[str] = []
    raw_results = data.get("extracted_results")
    if isinstance(raw_results, (list, tuple, set)):
        candidates.extend(str(item) for item in raw_results)
    elif raw_results is not None:
        candidates.append(str(raw_results))
    for key in ("flag", "captured_flag", "flag_value"):
        if key in data:
            candidates.append(str(data[key]))
    return candidates


def evaluate_completion(
    objective: dict[str, Any],
    findings: list[dict[str, Any]],
    discovered_assets: list[str],
    discovered_services: list[dict[str, Any]],
    budget: dict[str, Any],
    cancellation: dict[str, Any],
    recovery: dict[str, Any],
    started_at: str | None = None,
    observations: list[dict[str, Any]] | None = None,
    executed_actions: list[dict[str, Any]] | None = None,
    chain_progress: list[dict[str, Any]] | None = None,
    verified_evidence_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Deterministically evaluates if the assessment objective has been achieved (L-03, L-04).

    ``verified_evidence_ids`` must contain evidence IDs whose cryptographic
    integrity has already been checked by the caller. Security-result goals fail
    closed when this set is missing or does not contain the cited evidence.
    """

    def is_verified(evidence_id: Any) -> bool:
        return (
            bool(evidence_id)
            and verified_evidence_ids is not None
            and str(evidence_id) in verified_evidence_ids
        )

    # 1. User Cancellation Check
    if cancellation.get("is_cancelled", False):
        return CompletionEvaluation(
            is_completed=True,
            outcome="CANCELLED",
            summary=f"Assessment cancelled by user: {cancellation.get('reason', 'User requested')}",
        ).model_dump()

    # 2. Global Assessment Duration Timeout Check (S-06)
    if started_at:
        try:
            st = datetime.fromisoformat(started_at)
            if st.tzinfo is None:
                st = st.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            elapsed = (now - st).total_seconds()
            max_duration = budget.get("max_duration_seconds", 1800)
            if elapsed >= max_duration:
                confirmed_count = sum(
                    1
                    for f in findings
                    if (f.get("confidence") == "CONFIRMED" or f.get("status") == "CONFIRMED")
                    and len(f.get("evidence_ids", [])) > 0
                )
                outcome = "PARTIAL_SUCCESS" if confirmed_count > 0 else "FAILED"
                return CompletionEvaluation(
                    is_completed=True,
                    outcome=outcome,
                    summary=f"Assessment exceeded maximum duration limit ({max_duration}s). Found {confirmed_count} confirmed findings.",
                ).model_dump()
        except ValueError:
            pass

    # 3. Execution Iteration Budget Exhaustion Check
    iterations_used = budget.get("iterations_used", 0)
    max_iterations = budget.get("max_iterations", 20)
    if iterations_used >= max_iterations:
        confirmed_count = sum(
            1
            for f in findings
            if (f.get("confidence") == "CONFIRMED" or f.get("status") == "CONFIRMED")
            and len(f.get("evidence_ids", [])) > 0
        )
        outcome = "PARTIAL_SUCCESS" if confirmed_count > 0 else "FAILED"
        return CompletionEvaluation(
            is_completed=True,
            outcome=outcome,
            summary=f"Assessment reached max iteration budget ({max_iterations}). Found {confirmed_count} confirmed findings.",
        ).model_dump()

    # 4. Excessive Consecutive Failures Check
    consecutive_failures = recovery.get("consecutive_failures", 0)
    max_consecutive_failures = recovery.get("max_consecutive_failures", 3)
    if consecutive_failures >= max_consecutive_failures:
        return CompletionEvaluation(
            is_completed=True,
            outcome="FAILED",
            summary=f"Assessment stopped due to {consecutive_failures} consecutive unrecoverable failures.",
        ).model_dump()

    # 5. Objective Evaluation by Goal Type (L-03, L-04)
    min_hosts = objective.get("required_hosts", 1)
    confirmed_findings = [
        f
        for f in findings
        if (f.get("confidence") == "CONFIRMED" or f.get("status") == "CONFIRMED")
        and len(f.get("evidence_ids", [])) > 0
    ]
    evidence_ids = [eid for f in confirmed_findings for eid in f.get("evidence_ids", [])]

    satisfied_goals: list[str] = []
    if len(discovered_assets) >= min_hosts:
        satisfied_goals.append("HOST_DISCOVERY_COMPLETED")
    if len(discovered_services) > 0:
        satisfied_goals.append("SERVICES_ENUMERATED")

    raw_obj_type = objective.get("type") or objective.get("objective_type")
    obj_type = str(raw_obj_type).strip().lower() if raw_obj_type else ""

    # Case A: Service enumeration / surface discovery
    if obj_type in (
        "discover_services",
        "reconnaissance_complete",
        "network_recon",
        "service_discovery",
    ):
        if (
            "HOST_DISCOVERY_COMPLETED" in satisfied_goals
            and "SERVICES_ENUMERATED" in satisfied_goals
        ):
            return CompletionEvaluation(
                is_completed=True,
                outcome="SUCCESS",
                satisfied_goals=satisfied_goals,
                verification_evidence_ids=evidence_ids,
                summary=f"Objective achieved: Discovered {len(discovered_assets)} host(s) and {len(discovered_services)} service(s) within scope.",
            ).model_dump()
        return CompletionEvaluation(
            is_completed=False,
            outcome="IN_PROGRESS",
            satisfied_goals=satisfied_goals,
            summary="Surface discovery in progress.",
        ).model_dump()

    # Case B: Flag / Capture the Flag objective
    if obj_type in ("flag", "capture_flag", "capture_the_flag"):
        target_flag = str(objective.get("flag", "")).strip()
        captured_flag_evidence: list[str] = []
        for obs in observations or []:
            evidence_id = obs.get("raw_evidence_id")
            if not is_verified(evidence_id):
                continue
            obs_data = obs.get("data", {}) or {}
            for candidate in _flag_candidates(obs_data):
                if target_flag:
                    matched = candidate.strip() == target_flag
                else:
                    matched = _FLAG_PATTERN.search(candidate) is not None
                if matched:
                    captured_flag_evidence.append(str(evidence_id))
                    break

        if captured_flag_evidence:
            satisfied_goals.append("FLAG_CAPTURED")
            return CompletionEvaluation(
                is_completed=True,
                outcome="SUCCESS",
                satisfied_goals=satisfied_goals,
                verification_evidence_ids=captured_flag_evidence,
                summary="Objective achieved: Target flag successfully captured with cryptographic evidence proof.",
            ).model_dump()
        return CompletionEvaluation(
            is_completed=False,
            outcome="IN_PROGRESS",
            satisfied_goals=satisfied_goals,
            summary="Target flag not yet captured. Active exploitation in progress.",
        ).model_dump()

    # Case C: Severity threshold goal
    if obj_type in ("severity_threshold", "vulnerability_severity"):
        min_severity = str(objective.get("min_severity", "HIGH")).upper()
        sev_rank = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        target_rank = sev_rank.get(min_severity, 3)
        matching_findings = [
            f
            for f in confirmed_findings
            if sev_rank.get(str(f.get("severity", "")).upper(), 0) >= target_rank
        ]
        if matching_findings:
            satisfied_goals.append(f"SEVERITY_THRESHOLD_MET_{min_severity}")
            return CompletionEvaluation(
                is_completed=True,
                outcome="SUCCESS",
                satisfied_goals=satisfied_goals,
                verification_evidence_ids=[
                    eid for f in matching_findings for eid in f.get("evidence_ids", [])
                ],
                summary=f"Objective achieved: Confirmed finding meeting severity threshold '{min_severity}'.",
            ).model_dump()
        return CompletionEvaluation(
            is_completed=False,
            outcome="IN_PROGRESS",
            satisfied_goals=satisfied_goals,
            summary=f"Pending confirmed finding meeting severity threshold '{min_severity}'.",
        ).model_dump()

    # Case D: Multi-step chain objective (L-04)
    if obj_type in ("multi_step", "chain", "multi_step_chain"):
        raw_required_steps = objective.get("required_steps", ["recon", "verify"])
        required_steps = (
            [str(step) for step in raw_required_steps]
            if isinstance(raw_required_steps, list) and raw_required_steps
            else ["recon", "verify"]
        )
        progress = chain_progress or []
        step_status: dict[str, bool] = {}
        step_evidence_ids: list[str] = []

        for index, step in enumerate(required_steps, start=1):
            step_name = step.lower()
            entry = next(
                (
                    item
                    for item in progress
                    if item.get("step_index") == index and is_verified(item.get("evidence_id"))
                ),
                None,
            )
            if step_name in ("recon", "discovery"):
                step_status[step] = entry is not None and "SERVICES_ENUMERATED" in satisfied_goals
            elif step_name in ("verify", "exploit", "cve"):
                verified_findings = [
                    finding
                    for finding in confirmed_findings
                    if any(is_verified(eid) for eid in finding.get("evidence_ids", []))
                ]
                step_status[step] = bool(verified_findings)
                if verified_findings:
                    step_evidence_ids.extend(
                        str(eid)
                        for finding in verified_findings
                        for eid in finding.get("evidence_ids", [])
                        if is_verified(eid)
                    )
            else:
                # Custom named step requires a verified chain-progress record.
                step_status[step] = entry is not None

            if entry is not None:
                step_evidence_ids.append(str(entry["evidence_id"]))

        if all(step_status.values()):
            satisfied_goals.append("MULTI_STEP_CHAIN_COMPLETED")
            return CompletionEvaluation(
                is_completed=True,
                outcome="SUCCESS",
                satisfied_goals=satisfied_goals,
                verification_evidence_ids=list(dict.fromkeys(step_evidence_ids)),
                summary=(
                    f"Objective achieved: All {len(required_steps)} multi-step chain "
                    "milestones satisfied with verified evidence."
                ),
            ).model_dump()

        unmet = [step for step, satisfied in step_status.items() if not satisfied]
        return CompletionEvaluation(
            is_completed=False,
            outcome="IN_PROGRESS",
            satisfied_goals=satisfied_goals,
            summary=(
                "Multi-step chain progression in progress. "
                f"Pending verified steps: {', '.join(unmet)}."
            ),
        ).model_dump()

    # Case E: Standard CVE verification objective (or legacy find_cve flag)
    requires_cve = objective.get("find_cve", False) or obj_type in (
        "find_cve",
        "cve",
        "vulnerability_verification",
    )
    if requires_cve:
        if len(confirmed_findings) > 0:
            satisfied_goals.append("VULNERABILITY_VERIFIED")
            return CompletionEvaluation(
                is_completed=True,
                outcome="SUCCESS",
                satisfied_goals=satisfied_goals,
                verification_evidence_ids=evidence_ids,
                summary=f"Objective achieved: {len(confirmed_findings)} confirmed vulnerability verified with cryptographic evidence.",
            ).model_dump()
        return CompletionEvaluation(
            is_completed=False,
            outcome="IN_PROGRESS",
            satisfied_goals=satisfied_goals,
            summary="Recon completed, active vulnerability verification pending.",
        ).model_dump()

    # Case F: Unknown objective type fails closed
    if raw_obj_type:
        return CompletionEvaluation(
            is_completed=True,
            outcome="FAILED",
            satisfied_goals=satisfied_goals,
            summary=f"Unknown or unsupported objective type '{raw_obj_type}' cannot be verified.",
        ).model_dump()

    # Case G: Fallback general discovery
    if "HOST_DISCOVERY_COMPLETED" in satisfied_goals and "SERVICES_ENUMERATED" in satisfied_goals:
        return CompletionEvaluation(
            is_completed=True,
            outcome="SUCCESS",
            satisfied_goals=satisfied_goals,
            summary="Objective achieved: Host and services enumerated within scope.",
        ).model_dump()

    return CompletionEvaluation(
        is_completed=False,
        outcome="IN_PROGRESS",
        satisfied_goals=satisfied_goals,
        summary="Assessment in progress.",
    ).model_dump()
