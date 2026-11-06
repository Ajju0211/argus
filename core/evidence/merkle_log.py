"""Cryptographic Merkle Tree and Audit Log primitive for ARGUS.

Spec Reference: specs/11-proof-carrying-findings-and-chain-of-custody.md (Section 9)
Provides canonical JSON serialization, domain-separated leaf/node hashing,
pairwise tree construction with odd-node promotion, and RFC-style inclusion proofs.
"""

import hashlib
import hmac
import json
from typing import Any

# Domain separation prefixes to prevent leaf/node preimage attacks (RFC 6962 / Spec 11 §9.2)
LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"

# Empty tree root is sha256(b"")
EMPTY_TREE_ROOT: bytes = hashlib.sha256(b"").digest()


def canonical_json(data: Any) -> bytes:
    """Serializes data to canonical JSON (sorted keys, compact separators, UTF-8).

    Guards against float NaN/Infinity and non-deterministic formatting.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def leaf_hash(canonical_bytes: bytes) -> bytes:
    """Computes SHA-256 leaf hash with domain separation prefix 0x00."""
    return hashlib.sha256(LEAF_PREFIX + canonical_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Computes SHA-256 internal node hash with domain separation prefix 0x01."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def format_hash(digest_bytes: bytes) -> str:
    """Formats raw binary digest to lowercase hex with sha256: prefix."""
    return f"sha256:{digest_bytes.hex()}"


def parse_hash(formatted: str) -> bytes:
    """Parses sha256:<hex> string into binary digest bytes."""
    if formatted.startswith("sha256:"):
        formatted = formatted[7:]
    return bytes.fromhex(formatted)


class MerkleTree:
    """In-memory Merkle tree constructed over canonical record leaf hashes."""

    def __init__(self, leaf_hashes: list[bytes] | None = None) -> None:
        self.leaf_hashes: list[bytes] = list(leaf_hashes or [])
        self.levels: list[list[bytes]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaf_hashes:
            self.levels = [[EMPTY_TREE_ROOT]]
            return

        current_level = list(self.leaf_hashes)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level: list[bytes] = []
            n = len(current_level)
            i = 0
            while i < n:
                if i + 1 < n:
                    # Pairwise combine left and right
                    next_level.append(node_hash(current_level[i], current_level[i + 1]))
                    i += 2
                else:
                    # Odd node: promote last node unchanged to next level
                    next_level.append(current_level[i])
                    i += 1
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> bytes:
        """Returns binary root hash."""
        if not self.levels:
            return EMPTY_TREE_ROOT
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        """Returns formatted sha256:<hex> root hash."""
        return format_hash(self.root)

    @property
    def tree_size(self) -> int:
        """Returns number of leaves."""
        return len(self.leaf_hashes)

    def generate_inclusion_proof(self, leaf_index: int) -> list[str]:
        """Generates audit path for leaf at index.

        Returns list of sha256:<hex> sibling hashes from leaf to root.
        Skips levels where a promoted node has no sibling.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self.leaf_hashes)})")

        audit_path: list[str] = []
        idx = leaf_index

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            level_len = len(level)

            if idx % 2 == 0:
                # Even index: right sibling is idx + 1
                if idx + 1 < level_len:
                    audit_path.append(format_hash(level[idx + 1]))
                # If idx + 1 >= level_len, node is promoted; no sibling at this level
            else:
                # Odd index: left sibling is idx - 1
                audit_path.append(format_hash(level[idx - 1]))

            idx //= 2

        return audit_path


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    audit_path: list[bytes | str],
    root: bytes | str,
) -> bool:
    """Verifies that a leaf at index is included in a Merkle tree with the given root.

    Spec 11 §9.5: Only levels with an actual sibling consume a proof element.
    Uses constant-time comparison to prevent timing attacks.
    """
    if index < 0 or index >= tree_size:
        return False

    expected_root = parse_hash(root) if isinstance(root, str) else root
    binary_path = [parse_hash(p) if isinstance(p, str) else p for p in audit_path]

    h = leaf
    idx = index
    level_size = tree_size
    siblings_iter = iter(binary_path)

    while level_size > 1:
        if idx % 2 == 0 and idx + 1 < level_size:
            sibling = next(siblings_iter, None)
            if sibling is None:
                return False
            h = node_hash(h, sibling)
        elif idx % 2 == 1:
            sibling = next(siblings_iter, None)
            if sibling is None:
                return False
            h = node_hash(sibling, h)
        # else: last node promoted, no sibling at this level

        idx //= 2
        level_size = (level_size + 1) // 2

    # Verify all siblings consumed and computed root equals expected root (constant time)
    return next(siblings_iter, None) is None and hmac.compare_digest(h, expected_root)

