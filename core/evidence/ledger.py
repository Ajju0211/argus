"""Append-only Merkle ledger for ARGUS assessments.

Spec Reference: specs/11-proof-carrying-findings-and-chain-of-custody.md (Section 8.1 & 9.6)
Enforces append-only semantics, monotonic seq assignment, T2 executor attestation,
and provides inclusion proof generation against the ledger tree head.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.evidence.merkle_log import (
    MerkleTree,
    canonical_json,
    format_hash,
    leaf_hash,
)

LEDGER_VERSION: str = "argus.ledger.v1"


class AssessmentLedger:
    """Manages an append-only JSONL ledger and its corresponding Merkle tree."""

    def __init__(self, ledger_file: Path | str, assessment_id: str) -> None:
        self.ledger_file = Path(ledger_file).resolve()
        self.assessment_id = assessment_id
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)

    def records(self) -> list[dict[str, Any]]:
        """Reads all records in sequence from the ledger file."""
        if not self.ledger_file.exists():
            return []

        results: list[dict[str, Any]] = []
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                clean = line.strip()
                if not clean:
                    continue
                try:
                    record = json.loads(clean)
                    results.append(record)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON on line {line_num} in ledger: {exc}")
        return results

    def build_tree(self) -> MerkleTree:
        """Constructs a Merkle tree from all leaf hashes in the ledger."""
        recs = self.records()
        leaf_hashes = [leaf_hash(canonical_json(r)) for r in recs]
        return MerkleTree(leaf_hashes)

    def head(self) -> dict[str, Any]:
        """Returns the current tree head metadata."""
        tree = self.build_tree()
        recs = self.records()
        last_ts = recs[-1]["timestamp"] if recs else datetime.now(UTC).isoformat()
        return {
            "tree_size": tree.tree_size,
            "root_hash": tree.root_hex,
            "head_timestamp": last_ts,
        }

    def append_record(
        self,
        event: str,
        tool: str,
        target_host: str,
        target_port: int | None,
        arguments: dict[str, Any] | Any,
        exit_code: int,
        stdout_raw: str,
        stderr_raw: str = "",
        evidence_ids: list[str] | None = None,
        tier: str = "T2",
        action_id: str = "",
        bifrost_metadata: dict[str, Any] | None = None,
        research_metadata: list[dict[str, Any]] | None = None,
    ) -> tuple[int, MerkleTree, list[str]]:
        """Appends an executor-attested record with monotonic seq.

        Returns tuple of (seq, tree, inclusion_proof).
        """
        existing = self.records()
        seq = len(existing)

        # Hash arguments, stdout, and stderr canonically
        args_bytes = canonical_json(arguments) if isinstance(arguments, dict) else str(arguments).encode("utf-8")
        args_hash = format_hash(hashlib.sha256(args_bytes).digest())
        stdout_hash = format_hash(hashlib.sha256(stdout_raw.encode("utf-8")).digest())
        stderr_hash = format_hash(hashlib.sha256(stderr_raw.encode("utf-8")).digest())

        record: dict[str, Any] = {
            "version": LEDGER_VERSION,
            "seq": seq,
            "assessment_id": self.assessment_id,
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tier": tier,
            "event": event,
            "action_id": action_id or f"act-{seq:04d}",
            "tool": tool,
            "target_host": target_host,
            "target_port": target_port,
            "arguments_sha256": args_hash,
            "exit_code": exit_code,
            "stdout_sha256": stdout_hash,
            "stderr_sha256": stderr_hash,
            "evidence_ids": list(evidence_ids or []),
        }

        if bifrost_metadata:
            record["bifrost"] = bifrost_metadata
        if research_metadata:
            record["research"] = research_metadata

        # Append canonical line
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        # Build updated tree and generate proof for this new leaf
        tree = self.build_tree()
        proof = tree.generate_inclusion_proof(seq)
        return seq, tree, proof

    def get_proof_for_evidence_id(self, evidence_id: str) -> dict[str, Any] | None:
        """Finds the ledger record containing evidence_id and returns its inclusion proof."""
        recs = self.records()
        for i, rec in enumerate(recs):
            if evidence_id in rec.get("evidence_ids", []):
                tree = self.build_tree()
                audit_path = tree.generate_inclusion_proof(i)
                return {
                    "evidence_id": evidence_id,
                    "leaf_index": i,
                    "tree_size": tree.tree_size,
                    "audit_path": audit_path,
                    "record": rec,
                }
        return None

    def verify_ledger_integrity(self) -> tuple[bool, str]:
        """Validates sequential integrity, seq continuity, and canonical parsing."""
        if not self.ledger_file.exists():
            return True, "Ledger empty"

        recs = self.records()
        for expected_seq, rec in enumerate(recs):
            actual_seq = rec.get("seq")
            if actual_seq != expected_seq:
                return False, f"Broken seq continuity: expected {expected_seq}, found {actual_seq}"
            if rec.get("assessment_id") != self.assessment_id:
                return False, f"Assessment ID mismatch at seq {actual_seq}"
        return True, f"Ledger verified with {len(recs)} valid records"

