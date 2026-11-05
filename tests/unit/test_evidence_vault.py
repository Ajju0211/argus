"""Unit test suite for ARGUS Evidence Vault & Finding Verification (Module 04).

Verifies cryptographic SHA-256 artifact storage, secret redaction pipeline,
finding confidence state machine, and zero-hallucination invariant enforcement.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.evidence.evidence_vault import EvidenceVault
from core.evidence.redactor import SecretRedactor
from core.findings.finding_verifier import FindingVerifier
from packages.contracts.findings import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
)


class TestSecretRedaction:
    """Verifies scrubbing of credentials, API tokens, and authorization headers."""

    def test_redacts_bearer_tokens(self) -> None:
        redactor = SecretRedactor()
        raw = "GET /api/v1 HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken\n"
        cleaned, was_redacted = redactor.redact(raw)

        assert was_redacted is True
        assert "[REDACTED_BY_ARGUS]" in cleaned
        assert "doNotLeakThisToken" not in cleaned

    def test_redacts_passwords_and_api_keys(self) -> None:
        redactor = SecretRedactor()
        raw = "target=http://lab&password=superSecret123!&apikey=ak_live_99887766554433221100"
        cleaned, was_redacted = redactor.redact(raw)

        assert was_redacted is True
        assert "superSecret123!" not in cleaned
        assert "ak_live_99887766554433221100" not in cleaned
        assert cleaned.count("[REDACTED_BY_ARGUS]") >= 2

    def test_redacts_basic_auth(self) -> None:
        redactor = SecretRedactor()
        raw = "Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM="
        cleaned, was_redacted = redactor.redact(raw)

        assert was_redacted is True
        assert "YWRtaW46cGFzc3dvcmQxMjM=" not in cleaned
        assert "[REDACTED_BY_ARGUS]" in cleaned

    def test_clean_input_remains_unchanged(self) -> None:
        redactor = SecretRedactor()
        raw = "PORT 80/tcp open http nginx 1.24.0"
        cleaned, was_redacted = redactor.redact(raw)

        assert was_redacted is False
        assert cleaned == raw


class TestEvidenceVault:
    """Verifies storage hierarchy, cryptographic integrity, and tampering detection."""

    def test_store_and_retrieve_artifact(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path)
        raw_output = "PORT 8080/tcp open http Apache 2.4.49\nAuthorization: Bearer secretToken1234567890abcdef"
        cmd = "nmap -sT -sV -p 8080 192.168.100.5"

        artifact = vault.store_artifact(
            assessment_id="asm-test-01",
            tool_name="nmap",
            raw_content=raw_output,
            cmd=cmd,
        )

        assert artifact.assessment_id == "asm-test-01"
        assert artifact.tool_name == "nmap"
        assert artifact.redacted is True
        assert "secretToken" not in artifact.sha256

        # Read back from disk
        saved_text = vault.read_artifact_content(
            assessment_id="asm-test-01",
            evidence_id=artifact.evidence_id,
        )
        assert saved_text is not None
        assert "[REDACTED_BY_ARGUS]" in saved_text
        assert "secretToken1234567890abcdef" not in saved_text

    def test_sha256_integrity_verification(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path)
        raw_output = "HTTP/1.1 200 OK\nroot:x:0:0:root:/root:/bin/bash"

        artifact = vault.store_artifact(
            assessment_id="asm-test-02",
            tool_name="nuclei",
            raw_content=raw_output,
            cmd="nuclei -t cve-2021-41773.yaml",
        )

        # Integrity check on pristine artifact
        is_valid, msg = vault.verify_integrity(
            assessment_id="asm-test-02",
            evidence_id=artifact.evidence_id,
        )
        assert is_valid is True
        assert "matched" in msg.lower()

        # Simulate file tampering on disk
        file_path = Path(artifact.file_path)
        file_path.write_text("TAMPERED_CONTENT_BY_ATTACKER", encoding="utf-8")

        # Integrity check must detect tampering
        is_tampered_valid, tamper_msg = vault.verify_integrity(
            assessment_id="asm-test-02",
            evidence_id=artifact.evidence_id,
        )
        assert is_tampered_valid is False
        assert "mismatch" in tamper_msg.lower()

    def test_prevents_path_traversal_in_ids(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path)

        with pytest.raises(ValueError, match="path traversal"):
            vault.store_artifact(
                assessment_id="../../etc",
                tool_name="nmap",
                raw_content="clean",
                cmd="nmap",
            )


class TestFindingContractsAndStateMachine:
    """Verifies finding schema, confidence transitions, and zero-hallucination invariant."""

    def test_confirmed_finding_requires_evidence_ids(self) -> None:
        """A finding with CONFIRMED confidence MUST have non-empty evidence_ids."""
        now = datetime.now(UTC)

        # Valid CONFIRMED finding with evidence
        valid_finding = Finding(
            finding_id="find-001",
            assessment_id="asm-001",
            title="Path Traversal in Apache 2.4.49",
            description="Arbitrary file disclosure via path normalization bypass",
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
            affected_asset="http://192.168.100.5:8080",
            affected_service="Apache 2.4.49",
            verification_method="Nuclei HTTP 200 /etc/passwd reproduction",
            reproduction_steps="curl -v 'http://192.168.100.5:8080/icons/.%2e/etc/passwd'",
            impact="Full host compromise via configuration disclosure",
            remediation="Upgrade to Apache HTTP Server 2.4.51 or higher",
            evidence_ids=["ev-valid-hash-01"],
            research_source_ids=["tavily-cve-2021-41773"],
            created_at=now,
        )
        assert valid_finding.confidence == ConfidenceLevel.CONFIRMED

        # Attempt to create CONFIRMED finding WITHOUT evidence must raise ValidationError
        with pytest.raises(ValidationError, match="Zero-Hallucination Violation"):
            Finding(
                finding_id="find-hallucinated",
                assessment_id="asm-001",
                title="Hallucinated RCE",
                description="LLM hallucinated this without running any tool",
                severity=SeverityLevel.CRITICAL,
                confidence=ConfidenceLevel.CONFIRMED,
                affected_asset="http://192.168.100.5:8080",
                affected_service="Apache 2.4.49",
                verification_method="None",
                reproduction_steps="None",
                impact="None",
                remediation="None",
                evidence_ids=[],  # Hallucinated: No evidence!
                research_source_ids=[],
                created_at=now,
            )

    def test_state_machine_transitions(self) -> None:
        verifier = FindingVerifier()

        # 1. Scanner match starts as POTENTIAL
        finding = verifier.create_potential_finding(
            assessment_id="asm-001",
            title="Potential Apache Path Traversal",
            description="Banner indicates vulnerable version",
            severity=SeverityLevel.HIGH,
            affected_asset="http://192.168.100.5:8080",
            affected_service="Apache 2.4.49",
            initial_evidence_id="ev-banner-01",
        )
        assert finding.confidence == ConfidenceLevel.POTENTIAL

        # 2. Promote to CONFIRMED with reproduction evidence
        confirmed = verifier.confirm_finding(
            finding=finding,
            verification_evidence_id="ev-nuclei-verified-02",
            verification_method="Nuclei CVE-2021-41773 template match",
            reproduction_steps="curl http://192.168.100.5:8080/icons/.%2e/etc/passwd",
        )
        assert confirmed.confidence == ConfidenceLevel.CONFIRMED
        assert "ev-nuclei-verified-02" in confirmed.evidence_ids

        # 3. Reject false positive
        rejected = verifier.reject_finding(
            finding=finding,
            rejection_reason="Target returns 403 Forbidden on traversal payload",
        )
        assert rejected.confidence == ConfidenceLevel.REJECTED
        assert "False positive" in rejected.verification_method

    def test_unverifiable_downgrade_for_prohibited_actions(self) -> None:
        verifier = FindingVerifier()
        finding = verifier.create_potential_finding(
            assessment_id="asm-001",
            title="Potential Slowloris DoS",
            description="Web server may be vulnerable to connection exhaustion",
            severity=SeverityLevel.MEDIUM,
            affected_asset="http://192.168.100.5:8080",
            affected_service="Apache 2.4.49",
        )

        unverifiable = verifier.mark_unverifiable(
            finding=finding,
            reason="Verification requires slow connection exhaustion which violates scope policy",
            prohibited_action="denial_of_service",
        )

        assert unverifiable.confidence == ConfidenceLevel.UNVERIFIABLE
        assert "denial_of_service" in unverifiable.reproduction_steps
