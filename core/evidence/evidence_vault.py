"""Cryptographic Evidence Vault for ARGUS.

Provides secure, append-only disk storage for raw tool outputs with SHA-256
tamper-detection and sensitive secret redaction.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.evidence.redactor import SecretRedactor
from packages.contracts.findings import EvidenceArtifact

# Whitelist safe identifier syntax to block directory traversal attacks
SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


class EvidenceVault:
    """Manages raw evidence file persistence, cryptographic hashing, and integrity checks."""

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir).resolve()
        self._redactor = SecretRedactor()

    def _validate_id(self, identifier: str, param_name: str) -> None:
        """Guards against directory traversal by verifying identifier characters."""
        if not identifier or not SAFE_ID_REGEX.match(identifier):
            raise ValueError(
                f"Invalid {param_name} '{identifier}': Potential path traversal detected."
            )

    def store_artifact(
        self,
        assessment_id: str,
        tool_name: str,
        raw_content: str,
        cmd: str,
        tool_version: str = "1.0.0",
        content_type: str = "text/plain",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceArtifact:
        """Redacts secrets, writes raw output to disk, and logs cryptographic metadata."""
        self._validate_id(assessment_id, "assessment_id")

        # 1. Redact secrets
        redacted_content, was_redacted = self._redactor.redact(raw_content)

        # 2. Compute SHA-256 hash of the redacted artifact
        sha256_hash = hashlib.sha256(redacted_content.encode("utf-8")).hexdigest()

        # 3. Form unique evidence ID and destination paths
        now = datetime.now(UTC)
        time_part = now.strftime("%Y%m%d%H%M%S")
        evidence_id = f"ev-{time_part}-{sha256_hash[:8]}"

        artifact_dir = self.base_dir / assessment_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        file_path = artifact_dir / f"{evidence_id}.raw"

        # 4. Write payload to disk
        file_path.write_text(redacted_content, encoding="utf-8")

        # 5. Build immutable EvidenceArtifact record
        artifact = EvidenceArtifact(
            evidence_id=evidence_id,
            assessment_id=assessment_id,
            tool_name=tool_name,
            tool_version=tool_version,
            command_executed=cmd,
            sha256=sha256_hash,
            file_path=str(file_path),
            captured_at=now,
            content_type=content_type,
            redacted=was_redacted,
            metadata=metadata or {},
        )

        # 6. Append to metadata.jsonl
        metadata_file = artifact_dir / "metadata.jsonl"
        with open(metadata_file, "a", encoding="utf-8") as f:
            f.write(artifact.model_dump_json() + "\n")

        return artifact

    def read_artifact_content(self, assessment_id: str, evidence_id: str) -> str | None:
        """Reads raw content of an artifact from disk."""
        self._validate_id(assessment_id, "assessment_id")
        self._validate_id(evidence_id, "evidence_id")

        file_path = self.base_dir / assessment_id / f"{evidence_id}.raw"
        if not file_path.exists():
            return None

        return file_path.read_text(encoding="utf-8")

    def get_artifact(self, assessment_id: str, evidence_id: str) -> EvidenceArtifact | None:
        """Retrieves an EvidenceArtifact from the assessment's metadata log."""
        self._validate_id(assessment_id, "assessment_id")
        self._validate_id(evidence_id, "evidence_id")

        metadata_file = self.base_dir / assessment_id / "metadata.jsonl"
        if not metadata_file.exists():
            return None

        with open(metadata_file, encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if not clean:
                    continue
                data = json.loads(clean)
                if data.get("evidence_id") == evidence_id:
                    return EvidenceArtifact.model_validate(data)

        return None

    def verify_integrity(self, assessment_id: str, evidence_id: str) -> tuple[bool, str]:
        """Validates that on-disk raw file matches the recorded cryptographic digest."""
        artifact = self.get_artifact(assessment_id, evidence_id)
        if artifact is None:
            return False, f"Evidence record '{evidence_id}' not found in metadata"

        content = self.read_artifact_content(assessment_id, evidence_id)
        if content is None:
            return False, f"Raw file for '{evidence_id}' missing on disk"

        current_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if current_digest == artifact.sha256:
            return (
                True,
                f"Cryptographic integrity verified: SHA-256 digest matched ({current_digest})",
            )

        return False, (
            f"Integrity violation (mismatch) detected for '{evidence_id}': "
            f"expected SHA-256 {artifact.sha256}, calculated {current_digest}."
        )
