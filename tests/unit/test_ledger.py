"""Unit tests for AssessmentLedger (Spec 11 Section 8.1 & 9.6)."""

from pathlib import Path

import pytest

from core.evidence.ledger import AssessmentLedger
from core.evidence.merkle_log import canonical_json, leaf_hash, verify_inclusion


class TestAssessmentLedger:
    def test_ledger_append_and_proof(self, tmp_path: Path) -> None:
        ledger_path = tmp_path / "ledger.jsonl"
        ledger = AssessmentLedger(ledger_path, assessment_id="asm-test-ledger-01")

        seq, tree, proof = ledger.append_record(
            event="tool_result",
            tool="nmap",
            target_host="192.168.100.5",
            target_port=8080,
            arguments={"target": "192.168.100.5", "ports": "8080"},
            exit_code=0,
            stdout_raw="Nmap scan report for 192.168.100.5",
            evidence_ids=["ev-001"],
            tier="T2",
        )

        assert seq == 0
        assert tree.tree_size == 1
        assert len(proof) == 0  # 1-leaf tree has no siblings

        recs = ledger.records()
        assert len(recs) == 1
        assert recs[0]["seq"] == 0
        assert recs[0]["tier"] == "T2"
        assert recs[0]["evidence_ids"] == ["ev-001"]

        # Append second record
        seq2, tree2, proof2 = ledger.append_record(
            event="tool_result",
            tool="nuclei",
            target_host="192.168.100.5",
            target_port=8080,
            arguments={"target": "http://192.168.100.5:8080"},
            exit_code=0,
            stdout_raw="[cve-2021-41773] matched",
            evidence_ids=["ev-002"],
            tier="T2",
        )

        assert seq2 == 1
        assert tree2.tree_size == 2
        assert len(proof2) == 1

        # Verify inclusion proof for ev-002
        proof_obj = ledger.get_proof_for_evidence_id("ev-002")
        assert proof_obj is not None
        assert proof_obj["leaf_index"] == 1
        assert proof_obj["tree_size"] == 2

        leaf = leaf_hash(canonical_json(proof_obj["record"]))
        valid = verify_inclusion(
            leaf=leaf,
            index=1,
            tree_size=2,
            audit_path=proof_obj["audit_path"],
            root=tree2.root,
        )
        assert valid is True

    def test_ledger_seq_tampering_detected(self, tmp_path: Path) -> None:
        ledger_path = tmp_path / "ledger.jsonl"
        ledger = AssessmentLedger(ledger_path, assessment_id="asm-tamper")

        ledger.append_record(
            event="tool_result",
            tool="nmap",
            target_host="192.168.100.5",
            target_port=80,
            arguments={},
            exit_code=0,
            stdout_raw="output",
        )

        # Manually alter the seq in the file
        raw = ledger_path.read_text(encoding="utf-8")
        tampered = raw.replace('"seq":0', '"seq":99')
        ledger_path.write_text(tampered, encoding="utf-8")

        valid, msg = ledger.verify_ledger_integrity()
        assert valid is False
        assert "Broken seq continuity" in msg

