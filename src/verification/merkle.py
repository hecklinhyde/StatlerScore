"""
Merkle tree over the attestation log.

A single HMAC proves one record hasn't been modified. A Merkle tree proves
the entire log hasn't been pruned or reordered, and lets you hand a third
party a compact inclusion proof (O(log n) hashes) so they can independently
verify a specific attestation without seeing any other records.

Same primitive used by Certificate Transparency logs (RFC 6962).

Tree structure:
  Level 0 (leaves): SHA-256(0x00 || leaf_data)     — domain-separated leaf hash
  Level 1+:         SHA-256(0x01 || left || right)  — domain-separated internal hash
  Root:             single hash representing the entire log state

Domain separation (RFC 6962) prevents second-preimage attacks: without distinct
prefixes, a crafted proof could pass an internal node hash off as a valid leaf.

Odd-length levels are padded by duplicating the last node (Bitcoin-style).
"""

import hashlib
import hmac
import json
from typing import Optional


# Domain-separation prefixes per RFC 6962 (Certificate Transparency).
LEAF_PREFIX     = b'\x00'
INTERNAL_PREFIX = b'\x01'


def hashLeaf(data: bytes) -> str:
    """Hash a leaf value with the RFC 6962 leaf domain prefix (0x00)."""
    return hashlib.sha256(LEAF_PREFIX + data).hexdigest()

def hashPair(left: str, right: str) -> str:
    """Hash two child hashes into a parent with the RFC 6962 internal domain prefix (0x01)."""
    return hashlib.sha256(INTERNAL_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

def recordHash(record: dict) -> str:
    """Domain-separated leaf hash of a full attestation record. Keys are sorted for a stable hash."""
    return hashLeaf(json.dumps(record, sort_keys=True, default=str).encode())


def buildLevels(leaves: list[str]) -> list[list[str]]:
    """Build the full tree bottom-up. Returns a list of levels, leaves first."""
    if not leaves:
        return []

    levels  = [leaves[:]]
    current = leaves[:]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]  # pad odd length
        current = [hashPair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        levels.append(current)

    return levels


EMPTY_ROOT = "0" * 64


def merkleRoot(records: list[dict]) -> str:
    if not records:
        return EMPTY_ROOT
    leaves = [recordHash(r) for r in records]
    return buildLevels(leaves)[-1][0]


def merkleProof(records: list[dict], attestationId: str) -> Optional[dict]:
    """
    Return the inclusion proof for one attestation.

    The proof is a list of {hash, direction} sibling hashes. Starting from
    the leaf and working up, combine each sibling in the given direction to
    reproduce the root. If it matches the published root, the attestation is
    proven to be in the log.
    """
    ids = [r["attestation_id"] for r in records]
    if attestationId not in ids:
        return None

    index  = ids.index(attestationId)
    leaves = [recordHash(r) for r in records]
    levels = buildLevels(leaves)

    proof = []
    idx   = index

    for level in levels[:-1]:
        padded = level + ([level[-1]] if len(level) % 2 == 1 else [])

        if idx % 2 == 0:
            proof.append({"hash": padded[idx + 1], "direction": "right"})
        else:
            proof.append({"hash": padded[idx - 1], "direction": "left"})

        idx //= 2

    return {
        "leaf_hash":    leaves[index],
        "proof_steps":  proof,
        "root":         levels[-1][0],
        "leaf_index":   index,
        "total_leaves": len(leaves),
    }


def verifyProof(leafHash: str, proofSteps: list[dict], expectedRoot: str) -> bool:
    """
    Recompute the root from a leaf hash + proof steps and compare against a
    trusted root. Can be run by any third party without access to the full log.
    """
    current = leafHash
    for step in proofSteps:
        if step["direction"] == "right":
            current = hashPair(current, step["hash"])
        else:
            current = hashPair(step["hash"], current)
    return hmac.compare_digest(current, expectedRoot)
