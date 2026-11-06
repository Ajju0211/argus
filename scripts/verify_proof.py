#!/usr/bin/env python3
"""Standalone, offline Proof Capsule Verifier for ARGUS.

Spec Reference: specs/11-proof-carrying-findings-and-chain-of-custody.md (Section 6.4)
Requirements:
  - Python standard library only (NO external dependencies, NO ARGUS imports)
  - Zero network access required
  - Validates Merkle tree, inclusion proofs, artifact hashes, and T2 attestation
  - Prints clear verdict: PROVEN, UNPROVEN, or FAILED with diagnostic reasons.

Usage:
  python scripts/verify_proof.py <path-to-capsule.argusproof>
"""

import hashlib
import hmac
import json
import os
import sys
import zipfile
from typing import Any

LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"
EMPTY_TREE_ROOT: bytes = hashlib.sha256(b"").digest()

MAX_ENTRIES: int = 100
MAX_DECOMPRESSED_BYTES: int = 50 * 1024 * 1024


def canonical_json(data: Any) -> bytes:
    """Serializes Python dictionary/primitive to deterministic JSON bytes."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def leaf_hash(data_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def format_hash(b: bytes) -> str:
    return f"sha256:{b.hex()}"


def parse_hash(s: str) -> bytes:
    if s.startswith("sha256:"):
        s = s[7:]
    return bytes.fromhex(s)


def build_merkle_tree(leaf_hashes: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Constructs Merkle tree with odd-node promotion."""
    if not leaf_hashes:
        return EMPTY_TREE_ROOT, [[EMPTY_TREE_ROOT]]

    levels = [list(leaf_hashes)]
    current = list(leaf_hashes)

    while len(current) > 1:
        next_level = []
        n = len(current)
        i = 0
        while i < n:
            if i + 1 < n:
                next_level.append(node_hash(current[i], current[i + 1]))
                i += 2
            else:
                next_level.append(current[i])
                i += 1
        levels.append(next_level)
        current = next_level

    return levels[-1][0], levels


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    audit_path: list[str],
    root: bytes,
) -> bool:
    """Verifies leaf inclusion in tree of tree_size."""
    if index < 0 or index >= tree_size:
        return False

    h = leaf
    idx = index
    level_size = tree_size
    siblings_iter = iter(audit_path)

    while level_size > 1:
        if idx % 2 == 0 and idx + 1 < level_size:
            sib_str = next(siblings_iter, None)
            if sib_str is None:
                return False
            h = node_hash(h, parse_hash(sib_str))
        elif idx % 2 == 1:
            sib_str = next(siblings_iter, None)
            if sib_str is None:
                return False
            h = node_hash(parse_hash(sib_str), h)

        idx //= 2
        level_size = (level_size + 1) // 2

    return next(siblings_iter, None) is None and hmac.compare_digest(h, root)


def verify_proof_capsule(capsule_path: str) -> tuple[str, list[str], dict[str, Any]]:
    """Evaluates proof capsule and returns (verdict, reasons, manifest)."""
    if not os.path.exists(capsule_path):
        return "FAILED", [f"File not found: {capsule_path}"], {}

    reasons: list[str] = []

    try:
        with zipfile.ZipFile(capsule_path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ENTRIES:
                return "FAILED", [f"Too many archive entries: {len(infolist)}"], {}

            total_size = sum(info.file_size for info in infolist)
            if total_size > MAX_DECOMPRESSED_BYTES:
                return "FAILED", [f"Decompressed size {total_size} exceeds quota"], {}

            for info in infolist:
                norm = os.path.normpath(info.filename)
                if norm.startswith("..") or os.path.isabs(norm):
                    return "FAILED", [f"Path traversal detected: {info.filename}"], {}

            namelist = set(zf.namelist())
            if "manifest.json" not in namelist:
                return "FAILED", ["manifest.json missing from capsule"], {}

            manifest_raw = zf.read("manifest.json")
            ledger_raw = zf.read("ledger.jsonl") if "ledger.jsonl" in namelist else b""
            artifact_files = {name: zf.read(name) for name in namelist if name.startswith("artifacts/")}
    except Exception as exc:
        return "FAILED", [f"Corrupted or invalid ZIP archive: {exc}"], {}

    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except Exception as exc:
        return "FAILED", [f"Malformed manifest JSON: {exc}"], {}

    # Validate version
    if manifest.get("capsule_version") != "argus.proof.v1":
        return "FAILED", [f"Unsupported capsule version: {manifest.get('capsule_version')}"], manifest

    # Parse ledger
    ledger_records = []
    if ledger_raw:
        for line_no, line in enumerate(ledger_raw.decode("utf-8").splitlines(), start=1):
            line_str = line.strip()
            if line_str:
                try:
                    ledger_records.append(json.loads(line_str))
                except Exception as exc:
                    return "FAILED", [f"Malformed ledger JSON on line {line_no}: {exc}"], manifest

    # Reconstruct Merkle tree
    claimed_root_str = manifest.get("ledger", {}).get("root_hash", "")
    claimed_size = manifest.get("ledger", {}).get("tree_size", 0)

    if not ledger_records:
        return "FAILED", ["No ledger records found in capsule"], manifest

    if len(ledger_records) != claimed_size:
        return "FAILED", [f"Record count {len(ledger_records)} != claimed tree_size {claimed_size}"], manifest

    leaf_hashes = [leaf_hash(canonical_json(r)) for r in ledger_records]
    root_bytes, _ = build_merkle_tree(leaf_hashes)
    reconstructed_root_str = format_hash(root_bytes)

    if not hmac.compare_digest(reconstructed_root_str, claimed_root_str):
        return "FAILED", [f"Root mismatch: {reconstructed_root_str} != {claimed_root_str}"], manifest

    # Check artifacts
    finding_ev_ids = set(manifest.get("finding", {}).get("evidence_ids", []))
    manifest_art_ids = {a["evidence_id"] for a in manifest.get("artifacts", [])}

    for req_ev in finding_ev_ids:
        if req_ev not in manifest_art_ids:
            return "FAILED", [f"Finding claims evidence {req_ev} which is missing from capsule artifacts"], manifest

    for art in manifest.get("artifacts", []):
        path = art["path"]
        ev_id = art["evidence_id"]
        exp_sha = art["sha256"]
        if exp_sha.startswith("sha256:"):
            exp_sha = exp_sha[7:]

        if path not in artifact_files:
            return "FAILED", [f"Missing artifact file {path} for evidence {ev_id}"], manifest

        calc_sha = hashlib.sha256(artifact_files[path]).hexdigest()
        if not hmac.compare_digest(calc_sha, exp_sha):
            return "FAILED", [f"Hash mismatch for {ev_id}: {calc_sha} != {exp_sha}"], manifest

    # Check proofs and T2 attestation
    proofs = manifest.get("proofs", [])
    if not proofs:
        return "UNPROVEN", ["Finding contains no cryptographic inclusion proofs"], manifest

    ledger_map = {}
    for r in ledger_records:
        for eid in r.get("evidence_ids", []):
            ledger_map[eid] = r

    for proof in proofs:
        ev_id = proof["evidence_id"]
        rec = ledger_map.get(ev_id)
        if not rec:
            return "FAILED", [f"Evidence {ev_id} missing from ledger records"], manifest

        if rec.get("tier") != "T2":
            return "UNPROVEN", [f"Evidence {ev_id} backed by tier '{rec.get('tier')}' (T2 required)"], manifest

        target_leaf = leaf_hash(canonical_json(rec))
        if not verify_inclusion(
            leaf=target_leaf,
            index=proof["leaf_index"],
            tree_size=proof["tree_size"],
            audit_path=proof["audit_path"],
            root=root_bytes,
        ):
            return "FAILED", [f"Inclusion proof verification failed for {ev_id}"], manifest

    return "PROVEN", [], manifest


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/verify_proof.py <path-to-capsule.argusproof>")
        return 1

    path = sys.argv[1]
    verdict, reasons, manifest = verify_proof_capsule(path)

    print("=" * 60)
    print(f"ARGUS Standalone Proof Capsule Verifier")
    print("=" * 60)
    print(f"Capsule Path : {path}")

    if manifest:
        finding = manifest.get("finding", {})
        ledger = manifest.get("ledger", {})
        bifrost = manifest.get("bifrost", {})

        print(f"Finding ID   : {finding.get('finding_id')} - {finding.get('title')}")
        print(f"Severity     : {finding.get('severity')}")
        print(f"Confidence   : {finding.get('confidence')}")
        print(f"Ledger Root  : {ledger.get('root_hash')}")
        print(f"Tree Size    : {ledger.get('tree_size')} records")
        if manifest.get("simulation"):
            print("Mode         : [SIMULATION_MODE]")
        if bifrost:
            print(f"Bifrost Model: {bifrost.get('provider')} / {bifrost.get('model')} (fallback: {bifrost.get('fallback_used')})")

    print("-" * 60)
    print(f"VERDICT: {verdict}")
    if reasons:
        print("Reasons:")
        for r in reasons:
            print(f"  - {r}")
    print("=" * 60)

    return 0 if verdict == "PROVEN" else 1


if __name__ == "__main__":
    sys.exit(main())
