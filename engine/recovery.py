"""Bounded Adaptive Recovery Engine for ARGUS.

Implements failure taxonomy classification, exponential backoff with jitter,
loop detection, and graceful recovery branching.
"""

import random
from typing import Any

from engine.state import RecoveryState


class FailureType:
    RECOVERABLE_TIMEOUT = "RECOVERABLE_TIMEOUT"
    RECOVERABLE_EMPTY_OUTPUT = "RECOVERABLE_EMPTY_OUTPUT"
    RECOVERABLE_RATE_LIMIT = "RECOVERABLE_RATE_LIMIT"
    NON_RECOVERABLE_TARGET_DOWN = "NON_RECOVERABLE_TARGET_DOWN"
    NON_RECOVERABLE_DEPENDENCY = "NON_RECOVERABLE_DEPENDENCY"
    NON_RECOVERABLE_BUDGET_EXCEEDED = "NON_RECOVERABLE_BUDGET_EXCEEDED"
    HUMAN_INTERVENTION_SCOPE_EXPIRED = "HUMAN_INTERVENTION_SCOPE_EXPIRED"
    HUMAN_INTERVENTION_CANCELLED = "HUMAN_INTERVENTION_CANCELLED"


def classify_error(error_code: int | str, message: str) -> str:
    """Classifies an error string or status code into failure taxonomy."""
    msg = message.lower()
    if "429" in str(error_code) or "rate limit" in msg:
        return FailureType.RECOVERABLE_RATE_LIMIT
    if "timeout" in msg or error_code == 124:
        return FailureType.RECOVERABLE_TIMEOUT
    if "empty output" in msg or "no data" in msg:
        return FailureType.RECOVERABLE_EMPTY_OUTPUT
    if "expired" in msg:
        return FailureType.HUMAN_INTERVENTION_SCOPE_EXPIRED
    if "cancelled" in msg:
        return FailureType.HUMAN_INTERVENTION_CANCELLED
    if "connection refused" in msg or "host unreachable" in msg:
        return FailureType.NON_RECOVERABLE_TARGET_DOWN
    return FailureType.NON_RECOVERABLE_DEPENDENCY


def compute_exponential_backoff(
    attempt: int, base: float = 1.0, max_seconds: float = 30.0
) -> float:
    """Computes exponential backoff with uniform random jitter."""
    backoff = min(max_seconds, base * (2 ** max(0, attempt - 1)))
    jitter = random.uniform(0.1, 1.0)
    return float(round(backoff + jitter, 2))


def apply_adaptive_recovery(
    current_recovery: dict[str, Any], failure_type: str, action_fingerprint: str | None = None
) -> tuple[dict[str, Any], bool]:
    """Updates recovery state and evaluates whether the agent can continue."""
    rec = RecoveryState.model_validate(current_recovery)
    new_consecutive = rec.consecutive_failures + 1

    retry_counts = dict(rec.retry_counts_by_action)
    if action_fingerprint:
        retry_counts[action_fingerprint] = retry_counts.get(action_fingerprint, 0) + 1

    # Check bounds
    can_continue = True
    active_backoff = 0.0

    if (
        failure_type
        in (
            FailureType.NON_RECOVERABLE_TARGET_DOWN,
            FailureType.NON_RECOVERABLE_DEPENDENCY,
            FailureType.NON_RECOVERABLE_BUDGET_EXCEEDED,
            FailureType.HUMAN_INTERVENTION_SCOPE_EXPIRED,
            FailureType.HUMAN_INTERVENTION_CANCELLED,
        )
        or new_consecutive > rec.max_consecutive_failures
    ):
        can_continue = False
    elif failure_type == FailureType.RECOVERABLE_RATE_LIMIT:
        active_backoff = compute_exponential_backoff(new_consecutive)
    elif action_fingerprint and retry_counts[action_fingerprint] > 2:
        # Exceeded action retry bound
        can_continue = False

    updated_state = {
        "consecutive_failures": new_consecutive,
        "max_consecutive_failures": rec.max_consecutive_failures,
        "active_backoff_seconds": active_backoff,
        "last_failure_type": failure_type,
        "retry_counts_by_action": retry_counts,
    }
    return updated_state, can_continue
