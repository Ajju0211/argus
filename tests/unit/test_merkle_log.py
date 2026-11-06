"""Unit tests for Merkle Log cryptographic primitive (Spec 11 Section 9 & 16.1)."""

import hashlib
import json
import pytest

from core.evidence.merkle_log import (
    EMPTY_TREE_ROOT,
    MerkleTree,
    canonical_json,
    format_hash,
    leaf_hash,
    parse_hash,
    verify_inclusion,
)


class TestCanonicalJson:
    def test_key_sorting_is_deterministic(self) -> None:
        dict_a = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        dict_b = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
        assert canonical_json(dict_a) == canonical_json(dict_b)
        assert canonical_json(dict_a) == b'{"a":2,"m":{"a":4,"b":3},"z":1}'

    def test_separators_have_no_whitespace(self) -> None:
        raw = canonical_json({"tool": "nmap", "port": 8080})
        assert b" " not in raw
        assert b"\n" not in raw

    def test_rejects_nan_and_infinity(self) -> None:
        with pytest.raises(ValueError):
            canonical_json({"score": float("nan")})
        with pytest.raises(ValueError):
            canonical_json({"score": float("inf")})


class TestMerkleTreeConstructionAndProofs:
    def _make_leaves(self, count: int) -> list[bytes]:
        return [
            leaf_hash(canonical_json({"seq": i, "payload": f"data_{i}"}))
            for i in range(count)
        ]

    def test_empty_tree(self) -> None:
        tree = MerkleTree([])
        assert tree.tree_size == 0
        assert tree.root == EMPTY_TREE_ROOT
        assert tree.root_hex == format_hash(EMPTY_TREE_ROOT)

    @pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 16, 17])
    def test_inclusion_proof_for_all_leaves(self, size: int) -> None:
        """Spec 11 §9.3 & §16.1: Tests tree sizes 1, 2, 3, 5, 8, 16, 17."""
        leaves = self._make_leaves(size)
        tree = MerkleTree(leaves)

        assert tree.tree_size == size
        assert len(tree.root) == 32

        for i in range(size):
            proof = tree.generate_inclusion_proof(i)
            valid = verify_inclusion(
                leaf=leaves[i],
                index=i,
                tree_size=size,
                audit_path=proof,
                root=tree.root,
            )
            assert valid is True, f"Failed inclusion proof for leaf {i} in tree of size {size}"

    def test_tampered_leaf_fails_verification(self) -> None:
        leaves = self._make_leaves(8)
        tree = MerkleTree(leaves)

        proof = tree.generate_inclusion_proof(3)
        fake_leaf = leaf_hash(canonical_json({"seq": 3, "payload": "TAMPERED_DATA"}))

        valid = verify_inclusion(
            leaf=fake_leaf,
            index=3,
            tree_size=8,
            audit_path=proof,
            root=tree.root,
        )
        assert valid is False

    def test_tampered_audit_path_fails(self) -> None:
        leaves = self._make_leaves(8)
        tree = MerkleTree(leaves)

        proof = tree.generate_inclusion_proof(2)
        # Tamper with first sibling
        tampered_proof = list(proof)
        tampered_proof[0] = format_hash(hashlib.sha256(b"corrupt").digest())

        valid = verify_inclusion(
            leaf=leaves[2],
            index=2,
            tree_size=8,
            audit_path=tampered_proof,
            root=tree.root,
        )
        assert valid is False

    def test_wrong_tree_size_fails(self) -> None:
        leaves = self._make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.generate_inclusion_proof(0)

        # Claiming tree_size 4 or 9 must fail (different proof length/path)
        assert verify_inclusion(leaves[0], 0, 4, proof, tree.root) is False
        assert verify_inclusion(leaves[0], 0, 9, proof, tree.root) is False

    def test_out_of_bounds_index_rejected(self) -> None:
        leaves = self._make_leaves(5)
        tree = MerkleTree(leaves)

        with pytest.raises(IndexError):
            tree.generate_inclusion_proof(-1)
        with pytest.raises(IndexError):
            tree.generate_inclusion_proof(5)

        assert verify_inclusion(leaves[0], -1, 5, [], tree.root) is False
        assert verify_inclusion(leaves[0], 5, 5, [], tree.root) is False

    def test_reordered_leaves_change_root(self) -> None:
        leaves = self._make_leaves(4)
        tree_original = MerkleTree(leaves)

        # Swap elements 1 and 2
        reordered = [leaves[0], leaves[2], leaves[1], leaves[3]]
        tree_swapped = MerkleTree(reordered)

        assert tree_original.root != tree_swapped.root
