"""Unit tests for Spec 08 M1 resource constraint: 10 MB evidence artifact quota.

Spec 08 Section 4:
'Disk Quota: Evidence artifacts must have per-file limits of 10 MB. Scanner output
exceeding 10 MB is truncated with warning.'
"""

from pathlib import Path

import pytest

from core.evidence.evidence_vault import MAX_ARTIFACT_SIZE_BYTES, EvidenceVault


class TestEvidenceArtifactQuota:
    def test_evidence_under_limit_is_not_truncated(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        normal_content = "Normal tool output from nmap scan\n" * 100

        artifact = vault.store_artifact(
            assessment_id="asm-quota-01",
            tool_name="nmap",
            raw_content=normal_content,
            cmd="nmap -sV 192.168.100.5",
        )

        saved = vault.read_artifact_content("asm-quota-01", artifact.evidence_id)
        assert saved == normal_content
        assert artifact.metadata.get("truncated") is not True

    def test_evidence_exceeding_10mb_is_truncated_with_warning(self, tmp_path: Path) -> None:
        vault = EvidenceVault(base_dir=tmp_path / "vault")
        # Generate 10.5 MB of dummy scanner output
        chunk = "A" * 1024 * 1024  # 1 MB
        oversized_content = chunk * 10 + "EXTRA_BYTES_BEYOND_10MB" * 30000

        artifact = vault.store_artifact(
            assessment_id="asm-quota-02",
            tool_name="gobuster",
            raw_content=oversized_content,
            cmd="gobuster dir -u http://192.168.100.5",
        )

        saved = vault.read_artifact_content("asm-quota-02", artifact.evidence_id)
        assert saved is not None
        assert len(saved.encode("utf-8")) <= MAX_ARTIFACT_SIZE_BYTES + 256
        assert "[TRUNCATED:" in saved
        assert artifact.metadata.get("truncated") is True
        assert artifact.metadata.get("original_size_bytes") > MAX_ARTIFACT_SIZE_BYTES

        # Cryptographic integrity verification must succeed on the stored artifact
        valid, _ = vault.verify_integrity("asm-quota-02", artifact.evidence_id)
        assert valid is True

