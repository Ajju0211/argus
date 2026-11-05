"""Finding Verification State Machine for ARGUS.

Governs state transitions between POTENTIAL, CONFIRMED, REJECTED, and UNVERIFIABLE
findings, ensuring that scanner detections are never reported as confirmed without
active reproducibility proof.
"""

import uuid
from datetime import UTC, datetime

from packages.contracts.findings import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
)


class FindingVerifier:
    """Manages the verification lifecycle of security findings."""

    def create_potential_finding(
        self,
        assessment_id: str,
        title: str,
        description: str,
        severity: SeverityLevel,
        affected_asset: str,
        affected_service: str,
        initial_evidence_id: str | None = None,
        research_source_ids: list[str] | None = None,
        finding_id: str | None = None,
    ) -> Finding:
        """Initializes a new candidate finding with POTENTIAL confidence."""
        fid = finding_id or f"find-{uuid.uuid4().hex[:8]}"
        evidence_list = [initial_evidence_id] if initial_evidence_id else []

        return Finding(
            finding_id=fid,
            assessment_id=assessment_id,
            title=title,
            description=description,
            severity=severity,
            confidence=ConfidenceLevel.POTENTIAL,
            affected_asset=affected_asset,
            affected_service=affected_service,
            verification_method="Initial detection via automated scanner or service banner matching",
            reproduction_steps="Pending active verification probe",
            impact="Pending confirmation of exploitability",
            remediation="Review software patch levels and vendor advisories",
            evidence_ids=evidence_list,
            research_source_ids=research_source_ids or [],
            created_at=datetime.now(UTC),
        )

    def confirm_finding(
        self,
        finding: Finding,
        verification_evidence_id: str,
        verification_method: str,
        reproduction_steps: str,
        impact: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        """Promotes a finding to CONFIRMED based on verified reproducibility evidence."""
        if not verification_evidence_id:
            raise ValueError(
                f"Cannot confirm finding '{finding.finding_id}' without valid verification_evidence_id."
            )

        updated_evidence = list(dict.fromkeys([*finding.evidence_ids, verification_evidence_id]))

        return Finding(
            finding_id=finding.finding_id,
            assessment_id=finding.assessment_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=ConfidenceLevel.CONFIRMED,
            affected_asset=finding.affected_asset,
            affected_service=finding.affected_service,
            verification_method=verification_method,
            reproduction_steps=reproduction_steps,
            impact=impact or finding.impact,
            remediation=remediation or finding.remediation,
            evidence_ids=updated_evidence,
            research_source_ids=finding.research_source_ids,
            created_at=finding.created_at,
        )

    def reject_finding(
        self,
        finding: Finding,
        rejection_reason: str,
    ) -> Finding:
        """Marks a candidate finding as REJECTED (false positive or non-vulnerable)."""
        return Finding(
            finding_id=finding.finding_id,
            assessment_id=finding.assessment_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=ConfidenceLevel.REJECTED,
            affected_asset=finding.affected_asset,
            affected_service=finding.affected_service,
            verification_method=f"False positive rejected: {rejection_reason}",
            reproduction_steps="Probe verification failed or target patched",
            impact="None (Non-exploitable)",
            remediation="No remediation required",
            evidence_ids=finding.evidence_ids,
            research_source_ids=finding.research_source_ids,
            created_at=finding.created_at,
        )

    def mark_unverifiable(
        self,
        finding: Finding,
        reason: str,
        prohibited_action: str,
    ) -> Finding:
        """Classifies a finding as UNVERIFIABLE due to scope or safety policy restrictions."""
        return Finding(
            finding_id=finding.finding_id,
            assessment_id=finding.assessment_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=ConfidenceLevel.UNVERIFIABLE,
            affected_asset=finding.affected_asset,
            affected_service=finding.affected_service,
            verification_method=f"Assessment limitation: {reason}",
            reproduction_steps=f"Verification requires prohibited action category: {prohibited_action}",
            impact=finding.impact,
            remediation=finding.remediation,
            evidence_ids=finding.evidence_ids,
            research_source_ids=finding.research_source_ids,
            created_at=finding.created_at,
        )
