"""Findings and Cryptographic Evidence Contracts for ARGUS.

Defines immutable Pydantic contracts for raw evidence artifacts and structured
security findings, enforcing the zero-hallucination invariant: a finding cannot
be marked CONFIRMED without valid cryptographic evidence.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ConfidenceLevel(str, Enum):
    """Lifecycle confidence state of a security finding."""

    POTENTIAL = "POTENTIAL"  # Discovered by scanner or version banner match
    CONFIRMED = "CONFIRMED"  # Verified by independent reproducibility probe
    REJECTED = "REJECTED"  # Verification probe failed; proven false positive
    UNVERIFIABLE = "UNVERIFIABLE"  # Exploit requires actions prohibited by scope (e.g. DoS)


class SeverityLevel(str, Enum):
    """Standardized CVSS-aligned vulnerability severity levels."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceArtifact(BaseModel):
    """Metadata record for an immutable raw output artifact stored on disk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(..., description="Unique evidence ID (e.g. ev-20261104-001)")
    assessment_id: str = Field(..., description="Parent assessment identifier")
    tool_name: str = Field(..., description="Tool that generated this artifact (nmap, nuclei, zap)")
    tool_version: str = Field(default="1.0.0", description="Version of the executing tool")
    command_executed: str = Field(..., description="Redacted command array or string")
    sha256: str = Field(..., description="Cryptographic SHA-256 hex digest of the raw content")
    file_path: str = Field(..., description="Absolute local filesystem path to .raw file")
    captured_at: datetime = Field(..., description="UTC timestamp when artifact was written")
    content_type: str = Field(default="text/plain", description="MIME content type")
    redacted: bool = Field(default=False, description="Whether sensitive tokens were scrubbed")
    prev_hash: str = Field(
        default="0" * 64,
        description="Cryptographic SHA-256 digest of preceding artifact entry for tamper-evident chain of custody",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary execution context"
    )


class Finding(BaseModel):
    """Security finding contract linking discoveries to cryptographic proof."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(..., description="Unique finding ID (e.g. find-001)")
    assessment_id: str = Field(..., description="Parent assessment identifier")
    title: str = Field(..., description="Human-readable vulnerability title")
    description: str = Field(..., description="Technical summary of the vulnerability")
    severity: SeverityLevel = Field(..., description="Vulnerability severity rating")
    confidence: ConfidenceLevel = Field(..., description="Verification confidence state")
    affected_asset: str = Field(..., description="Target host, IP, or URL")
    affected_service: str = Field(..., description="Identified service name and version")
    verification_method: str = Field(
        ..., description="Description of the probe or template used to verify"
    )
    reproduction_steps: str = Field(
        ..., description="Safe reproduction commands (e.g. non-destructive curl)"
    )
    impact: str = Field(..., description="Technical and business impact analysis")
    remediation: str = Field(..., description="Actionable vendor patching guidance")
    evidence_ids: list[str] = Field(
        default_factory=list, description="SHA-256 evidence artifact pointers"
    )
    research_source_ids: list[str] = Field(
        default_factory=list, description="External intelligence / advisory IDs (Tavily/NVD)"
    )
    created_at: datetime = Field(..., description="UTC creation timestamp")

    @model_validator(mode="after")
    def validate_confirmed_finding_has_evidence(self) -> "Finding":
        """Zero-Hallucination Invariant: CONFIRMED findings must reference real evidence."""
        if self.confidence == ConfidenceLevel.CONFIRMED and not self.evidence_ids:
            raise ValueError(
                f"Zero-Hallucination Violation: CONFIRMED finding '{self.finding_id}' "
                "must have at least one valid evidence_id linking to verified proof."
            )
        return self
