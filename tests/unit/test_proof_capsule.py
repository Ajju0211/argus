"""Unit tests for Proof Capsule builder and offline verifier (Spec 11 Section 6.3, 16.2)."""

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from core.evidence.ledger import AssessmentLedger
from core.evidence.merkle_log import format_hash
from core.evidence.proof_capsule import ProofCapsuleBuilder, verify_capsule_archive


def _build_test_capsule(
    tmp_path: Path,
    tier: str = "T2",
    tamper_artifact: bool = False,
    tamper_root: bool = False,
    missing_artifact: bool = False,
) -> Path:
    assessment_id = "asm-capsule-test-01"
    ledger_file = tmp_path / "ledger.jsonl"
    ledger = AssessmentLedger(ledger_file, assessment_id)

    raw_evidence_1 = "HTTP/1.1 200 OK\nServer: Apache/2.4.49\n\nroot:x:0:0:root"
    raw_evidence_2 = "OpenSSH_8.4p1 Debian-5+deb11u3"

    ev1_sha = format_hash(hashlib.sha256(raw_evidence_1.encode("utf-8")).digest())
    ev2_sha = format_hash(hashlib.sha256(raw_evidence_2.encode("utf-8")).digest())

    seq1, tree1, proof1 = ledger.append_record(
        event="tool_result",
        tool="nmap",
        target_host="192.168.100.5",
        target_port=8080,
        arguments={"target": "192.168.100.5"},
        exit_code=0,
        stdout_raw=raw_evidence_1,
        evidence_ids=["ev-test-01"],
        tier=tier,
    )

    seq2, tree2, proof2 = ledger.append_record(
        event="tool_result",
        tool="nuclei",
        target_host="192.168.100.5",
        target_port=8080,
        arguments={"target": "http://192.168.100.5:8080"},
        exit_code=0,
        stdout_raw=raw_evidence_2,
        evidence_ids=["ev-test-02"],
        tier=tier,
    )

    head = ledger.head()
    if tamper_root:
        head["root_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    proof_obj1 = ledger.get_proof_for_evidence_id("ev-test-01")
    proof_obj2 = ledger.get_proof_for_evidence_id("ev-test-02")
    assert proof_obj1 and proof_obj2

    artifacts = [
        {
            "evidence_id": "ev-test-01",
            "content": "TAMPERED_CONTENT" if tamper_artifact else raw_evidence_1,
            "sha256": ev1_sha,
        },
    ]

    if not missing_artifact:
        artifacts.append(
            {
                "evidence_id": "ev-test-02",
                "content": raw_evidence_2,
                "sha256": ev2_sha,
            }
        )

    builder = ProofCapsuleBuilder(
        assessment_id=assessment_id,
        finding={
            "finding_id": "F-001",
            "title": "Apache 2.4.49 Path Traversal",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "affected_asset": "192.168.100.5:8080",
            "evidence_ids": ["ev-test-01", "ev-test-02"],
        },
        ledger_head=head,
        proofs=[
            {
                "evidence_id": "ev-test-01",
                "leaf_index": proof_obj1["leaf_index"],
                "tree_size": proof_obj1["tree_size"],
                "audit_path": proof_obj1["audit_path"],
            },
            {
                "evidence_id": "ev-test-02",
                "leaf_index": proof_obj2["leaf_index"],
                "tree_size": proof_obj2["tree_size"],
                "audit_path": proof_obj2["audit_path"],
            },
        ],
        artifacts=artifacts,
        ledger_records=ledger.records(),
        bifrost_telemetry={"provider": "anthropic", "model": "claude-3-5-sonnet-20241022", "fallback_used": False},
        research_citations=[{"source_id": "tavily-1", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}],
        simulation=True,
    )

    capsule_zip = tmp_path / "test.argusproof"
    return builder.write_capsule_zip(capsule_zip)


class TestProofCapsule:
    def test_capsule_round_trip_is_proven(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path)
        assert capsule_file.exists()

        result = verify_capsule_archive(capsule_file)
        assert result["verdict"] == "PROVEN"
        assert result["reasons"] == []
        assert all(chk["ok"] for chk in result["checks"])

    def test_capsule_rejects_tampered_artifact(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path, tamper_artifact=True)
        result = verify_capsule_archive(capsule_file)

        assert result["verdict"] == "FAILED"
        assert any("Artifact hash mismatch" in r for r in result["reasons"])

    def test_capsule_rejects_t1_only_evidence(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path, tier="T1")
        result = verify_capsule_archive(capsule_file)

        assert result["verdict"] == "UNPROVEN"
        assert any("requires T2 executor attestation" in r for r in result["reasons"])

    def test_capsule_rejects_missing_artifact(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path, missing_artifact=True)
        result = verify_capsule_archive(capsule_file)

        assert result["verdict"] == "FAILED"
        assert any("missing" in r.lower() for r in result["reasons"])

    def test_capsule_rejects_tampered_root(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path, tamper_root=True)
        result = verify_capsule_archive(capsule_file)

        assert result["verdict"] == "FAILED"
        assert any("root" in r.lower() for r in result["reasons"])

    def test_standalone_verifier_script_cli(self, tmp_path: Path) -> None:
        capsule_file = _build_test_capsule(tmp_path)
        script_path = Path(__file__).parents[2] / "scripts" / "verify_proof.py"

        cmd = [sys.executable, str(script_path), str(capsule_file)]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        assert proc.returncode == 0
        assert "VERDICT: PROVEN" in proc.stdout
        assert "Ledger Root  : sha256:" in proc.stdout
        assert "Bifrost Model: anthropic" in proc.stdout
