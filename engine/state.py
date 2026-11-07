"""LangGraph Assessment State Schema for ARGUS.

Enforces strict typing, execution budget constraints, and deterministic
tracking of topology, findings, and recovery states.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import TypedDict


class ExecutionBudget(BaseModel):
    """Enforces execution boundaries and resource caps."""

    model_config = ConfigDict(frozen=True)

    max_duration_seconds: int = 1800
    max_iterations: int = 20
    max_model_calls: int = 40
    iterations_used: int = 0
    model_calls_used: int = 0
    total_tokens_used: int = 0


class CancellationState(BaseModel):
    """Tracks explicit user or system cancellation signals."""

    model_config = ConfigDict(frozen=True)

    is_cancelled: bool = False
    cancelled_at: datetime | None = None
    cancelled_by: str | None = None
    reason: str | None = None


class CompletionEvaluation(BaseModel):
    """Deterministic verdict on whether the assessment objective was achieved."""

    model_config = ConfigDict(frozen=True)

    is_completed: bool = False
    outcome: str = (
        "IN_PROGRESS"  # SUCCESS | PARTIAL_SUCCESS | PAUSED | BLOCKED | FAILED | CANCELLED
    )
    satisfied_goals: list[str] = Field(default_factory=list)
    verification_evidence_ids: list[str] = Field(default_factory=list)
    summary: str = ""


class RecoveryState(BaseModel):
    """Tracks error handling, bounded backoff, and action retry counters."""

    model_config = ConfigDict(frozen=True)

    consecutive_failures: int = 0
    max_consecutive_failures: int = 3
    active_backoff_seconds: float = 0.0
    last_failure_type: str | None = None
    retry_counts_by_action: dict[str, int] = Field(default_factory=dict)


class AssessmentState(TypedDict):
    """Complete LangGraph state dictionary."""

    # Assessment & Scope Identity
    assessment_id: str
    target: dict[str, Any]  # {"type": "web" | "network", "value": "http://lab:8080"}
    assessment_objective: dict[str, Any]  # e.g. {"find_cve": True, "required_hosts": 1}
    scope_id: str
    scope_version: str
    scope_snapshot_hash: str  # SHA-256 of active scope document
    status: str  # DRAFT | VALIDATING | READY | RUNNING | PAUSED | COMPLETED | FAILED | CANCELLED

    # Dynamic Capability Context
    tool_registry_version: str
    available_tools: list[dict[str, Any]]  # Tool descriptors from Module 03

    # Knowledge Base & Topology
    discovered_assets: list[str]  # ["192.168.100.5", "lab-target.local"]
    unauthorized_discovered_assets: list[str]  # Discovered hosts outside scope policy, segregated from planner
    discovered_services: list[
        dict[str, Any]
    ]  # [{"port": 8080, "service": "http", "version": "Apache 2.4.49"}]
    observations: list[dict[str, Any]]  # Normalized observation structures
    research_refs: list[dict[str, Any]]  # Tavily retrieved CVE intelligence & advisories
    footholds: list[dict[str, Any]]  # Serialized FootholdEvidence list proving compromised source hosts

    # Planning & Audit History
    current_strategy: str  # INITIAL_RECON | SERVICE_ENUMERATION | CVE_VERIFICATION
    current_action: dict[str, Any] | None  # Active ActionProposal
    resolved_ip: str | None  # Policy-approved DNS result pinned for execution (S-02)
    action_history: list[str]  # Fingerprints of dispatched actions
    executed_actions: list[dict[str, Any]]
    chain_progress: list[dict[str, Any]]  # Per-step evidence records for authorized chains (L-04)
    chain_summary: dict[str, Any]  # Chain authorization summary for reporting (L-04)
    blocked_actions: list[dict[str, Any]]

    # Findings & Integrity
    evidence_refs: list[dict[str, Any]]  # List of {"evidence_id": "...", "sha256": "..."}
    findings: list[dict[str, Any]]  # Verified & potential findings

    # Reporting & Telemetry
    simulation_mode: bool  # Whether the run used simulated tool output (C-05)
    report_markdown: str  # Final generated Markdown report (E-03)
    report_path: str | None  # On-disk report location, when written
    telemetry: list[dict[str, Any]]  # Bifrost provider/token/latency events
    langfuse_trace_id: str | None
    langfuse_session_id: str | None

    # Operational Controls & Budgets
    budget: dict[str, Any]  # Serialized ExecutionBudget
    cancellation: dict[str, Any]  # Serialized CancellationState
    recovery: dict[str, Any]  # Serialized RecoveryState
    completion: dict[str, Any]  # Serialized CompletionEvaluation
    started_at: str
    deadline_at: str | None
    stop_reason: str | None
