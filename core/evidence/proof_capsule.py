"""Proof Capsule builder and verifier for ARGUS.

Spec Reference: specs/11-proof-carrying-findings-and-chain-of-custody.md (Section 6.3, 8.4, 18)
Builds self-contained .argusproof ZIP packages containing:
  - manifest.json (Finding, tree head, inclusion proofs, sponsor telemetry)
  - ledger.jsonl (Canonical Merkle ledger)
  - artifacts/ (Redacted evidence files)

Includes strict security hardening:
  - Zip-bomb defense (decompressed size ceilings)
  - Path traversal defense on archive members
  - Constant-time hash verification
  - Strict T2 executor attestation requirement
"""

import hashlib
import hmac
import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.evidence.merkle_log import (
    canonical_json,
    format_hash,
    leaf_hash,
    parse_hash,
    verify_inclusion,
)

CAPSULE_VERSION: str = "argus.proof.v1"

# Security Caps: Max 50 MB decompressed size and 100 files max to prevent zip bombs
MAX_CAPSULE_TOTAL_BYTES: int = 50 * 1024 * 1024
MAX_CAPSULE_ENTRIES: int = 100


class ProofCapsuleBuilder:
    """Constructs a .argusproof ZIP archive from verified findings, ledger, and artifacts."""

    def __init__(
        self,
        assessment_id: str,
        finding: dict[str, Any],
        ledger_head: dict[str, Any],
        proofs: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        ledger_records: list[dict[str, Any]],
        bifrost_telemetry: dict[str, Any] | None = None,
        research_citations: list[dict[str, Any]] | None = None,
        simulation: bool = False,
    ) -> None:
        self.assessment_id = assessment_id
        self.finding = finding
        self.ledger_head = ledger_head
        self.proofs = proofs
        self.artifacts = artifacts
        self.ledger_records = ledger_records
        self.bifrost_telemetry = bifrost_telemetry or {}
        self.research_citations = research_citations or []
        self.simulation = simulation

    def build_manifest(self) -> dict[str, Any]:
        """Constructs canonical manifest dictionary."""
        return {
            "capsule_version": CAPSULE_VERSION,
            "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "assessment_id": self.assessment_id,
            "simulation": self.simulation,
            "finding": {
                "finding_id": self.finding.get("finding_id", "F-UNKNOWN"),
                "title": self.finding.get("title", ""),
                "severity": self.finding.get("severity", "UNKNOWN"),
                "confidence": self.finding.get("confidence", "UNKNOWN"),
                "affected_asset": self.finding.get("affected_asset") or self.finding.get("target_host", ""),
                "evidence_ids": list(self.finding.get("evidence_ids", [])),
            },
            "ledger": {
                "tree_size": self.ledger_head.get("tree_size", 0),
                "root_hash": self.ledger_head.get("root_hash", ""),
                "head_timestamp": self.ledger_head.get("head_timestamp", ""),
            },
            "proofs": self.proofs,
            "artifacts": [
                {
                    "evidence_id": a["evidence_id"],
                    "path": f"artifacts/{a['evidence_id']}.raw",
                    "sha256": a["sha256"],
                }
                for a in self.artifacts
            ],
            "bifrost": self.bifrost_telemetry,
            "research": self.research_citations,
        }

    def write_capsule_zip(self, output_path: Path | str) -> Path:
        """Writes .argusproof ZIP archive to output_path."""
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)

        manifest = self.build_manifest()
        manifest_json_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

        # Canonical ledger lines
        ledger_lines = [
            json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            for r in self.ledger_records
        ]
        ledger_bytes = ("\n".join(ledger_lines) + "\n").encode("utf-8")

        with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest_json_bytes)
            zf.writestr("ledger.jsonl", ledger_bytes)

            for art in self.artifacts:
                art_content = art.get("content", "")
                if isinstance(art_content, str):
                    raw_bytes = art_content.encode("utf-8")
                else:
                    raw_bytes = bytes(art_content)
                zf.writestr(f"artifacts/{art['evidence_id']}.raw", raw_bytes)

        return out_file


def verify_capsule_archive(capsule_path: Path | str) -> dict[str, Any]:
    """Verifies a .argusproof ZIP capsule offline.

    Returns dict with verdict (PROVEN | UNPROVEN | FAILED), individual check results,
    and explanatory reasons.
    """
    path = Path(capsule_path).resolve()
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []

    if not path.exists():
        return {
            "verdict": "FAILED",
            "checks": [{"name": "file_exists", "ok": False}],
            "reasons": [f"Capsule file not found: {path}"],
        }

    # 1. Zip integrity and zip-bomb check
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_CAPSULE_ENTRIES:
                return {
                    "verdict": "FAILED",
                    "checks": [{"name": "zip_safe", "ok": False}],
                    "reasons": [f"Capsule exceeds entry limit: {len(infolist)} entries"],
                }

            total_decompressed = sum(info.file_size for info in infolist)
            if total_decompressed > MAX_CAPSULE_TOTAL_BYTES:
                return {
                    "verdict": "FAILED",
                    "checks": [{"name": "zip_safe", "ok": False}],
                    "reasons": [f"Capsule exceeds size limit: {total_decompressed} bytes"],
                }

            # Guard against path traversal member names
            for info in infolist:
                norm_name = os.path.normpath(info.filename)
                if norm_name.startswith("..") or os.path.isabs(norm_name):
                    return {
                        "verdict": "FAILED",
                        "checks": [{"name": "zip_safe", "ok": False}],
                        "reasons": [f"Path traversal detected in archive entry: {info.filename}"],
                    }

            namelist = set(zf.namelist())
            if "manifest.json" not in namelist:
                return {
                    "verdict": "FAILED",
                    "checks": [{"name": "manifest_present", "ok": False}],
                    "reasons": ["manifest.json missing from capsule"],
                }

            manifest_bytes = zf.read("manifest.json")
            ledger_bytes = zf.read("ledger.jsonl") if "ledger.jsonl" in namelist else b""
            artifact_files = {name: zf.read(name) for name in namelist if name.startswith("artifacts/")}
    except zipfile.BadZipFile as exc:
        return {
            "verdict": "FAILED",
            "checks": [{"name": "valid_zip", "ok": False}],
            "reasons": [f"Invalid or corrupted ZIP file: {exc}"],
        }

    checks.append({"name": "capsule_archive_safe", "ok": True})

    # 2. Parse and validate manifest schema
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if manifest.get("capsule_version") != CAPSULE_VERSION:
            reasons.append(f"Unsupported capsule version: {manifest.get('capsule_version')}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}
    except Exception as exc:
        return {
            "verdict": "FAILED",
            "checks": checks + [{"name": "manifest_schema", "ok": False}],
            "reasons": [f"Malformed manifest JSON: {exc}"],
        }
    checks.append({"name": "manifest_schema", "ok": True})

    # 3. Parse and verify ledger records
    ledger_records: list[dict[str, Any]] = []
    if ledger_bytes:
        for idx, line in enumerate(ledger_bytes.decode("utf-8").splitlines()):
            clean = line.strip()
            if clean:
                try:
                    rec = json.loads(clean)
                    ledger_records.append(rec)
                except Exception as exc:
                    return {
                        "verdict": "FAILED",
                        "checks": checks + [{"name": "ledger_syntax", "ok": False}],
                        "reasons": [f"Malformed JSON on ledger line {idx + 1}: {exc}"],
                    }

    # 4. Check ledger root reconstruction
    claimed_root = manifest.get("ledger", {}).get("root_hash", "")
    claimed_size = manifest.get("ledger", {}).get("tree_size", 0)

    if ledger_records:
        if len(ledger_records) != claimed_size:
            reasons.append(f"Ledger record count {len(ledger_records)} does not match claimed tree_size {claimed_size}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

        from core.evidence.merkle_log import MerkleTree
        rebuilt_tree = MerkleTree([leaf_hash(canonical_json(r)) for r in ledger_records])
        if not hmac.compare_digest(rebuilt_tree.root_hex, claimed_root):
            reasons.append(f"Reconstructed ledger root {rebuilt_tree.root_hex} != claimed root {claimed_root}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}
        checks.append({"name": "ledger_root", "ok": True})
    else:
        checks.append({"name": "ledger_root", "ok": False})
        reasons.append("Ledger records missing from capsule")

    # 5. Check artifact integrity
    finding_ev_ids = set(manifest.get("finding", {}).get("evidence_ids", []))
    manifest_art_ids = {a["evidence_id"] for a in manifest.get("artifacts", [])}

    for required_ev in finding_ev_ids:
        if required_ev not in manifest_art_ids:
            reasons.append(f"Finding claims evidence {required_ev} which is missing from capsule artifacts")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

    for art_meta in manifest.get("artifacts", []):
        rel_path = art_meta["path"]
        ev_id = art_meta["evidence_id"]
        expected_sha = art_meta["sha256"]
        if expected_sha.startswith("sha256:"):
            expected_sha = expected_sha[7:]

        if rel_path not in artifact_files:
            reasons.append(f"Missing artifact file {rel_path} for evidence {ev_id}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

        actual_sha = hashlib.sha256(artifact_files[rel_path]).hexdigest()
        if not hmac.compare_digest(actual_sha, expected_sha):
            reasons.append(f"Artifact hash mismatch for {ev_id}: {actual_sha} != {expected_sha}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

    checks.append({"name": "artifact_hashes", "ok": True})

    # 6. Check inclusion proofs and T2 executor attestation
    proofs = manifest.get("proofs", [])
    if not proofs:
        reasons.append("No cryptographic inclusion proofs found in manifest")
        return {"verdict": "UNPROVEN", "checks": checks, "reasons": reasons}

    ledger_map: dict[str, dict[str, Any]] = {}
    for r in ledger_records:
        for eid in r.get("evidence_ids", []):
            ledger_map[eid] = r

    for proof in proofs:
        ev_id = proof["evidence_id"]
        leaf_idx = proof["leaf_index"]
        tree_size = proof["tree_size"]
        audit_path = proof["audit_path"]

        # Ensure record exists in ledger and is T2
        rec = ledger_map.get(ev_id)
        if not rec:
            reasons.append(f"Evidence {ev_id} has no matching ledger record")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

        if rec.get("tier") != "T2":
            reasons.append(f"Evidence {ev_id} backed only by tier '{rec.get('tier')}' (requires T2 executor attestation)")
            return {"verdict": "UNPROVEN", "checks": checks, "reasons": reasons}

        # Verify inclusion proof mathematically
        target_leaf = leaf_hash(canonical_json(rec))
        if not verify_inclusion(
            leaf=target_leaf,
            index=leaf_idx,
            tree_size=tree_size,
            audit_path=audit_path,
            root=claimed_root,
        ):
            reasons.append(f"Inclusion proof verification failed for evidence {ev_id}")
            return {"verdict": "FAILED", "checks": checks, "reasons": reasons}

    checks.append({"name": "inclusion_proofs", "ok": True})
    checks.append({"name": "t2_attestation", "ok": True})

    return {
        "verdict": "PROVEN",
        "checks": checks,
        "reasons": [],
        "manifest": manifest,
    }
