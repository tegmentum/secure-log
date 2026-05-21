//! Binary Merkle tree over entry hashes.
//!
//! The tree is unbalanced-right: when a level has an odd number of
//! nodes, the final node is carried up unchanged (no self-pairing).
//! This matches the RFC 6962 Certificate Transparency convention and
//! avoids the "double-hash attack" that affects Bitcoin-style trees
//! where odd nodes are paired with themselves.
//!
//! Inclusion proofs are produced and verified with exactly the same
//! layering. [`build_root`] returns just the root; [`build_proof`]
//! returns a proof path for a specific leaf index.

use super::hash::{sha256, EntryDigest, HASH_LEN};
use super::model::ProofStep;

/// Build the Merkle root over a list of entry hashes.
///
/// - Empty list: returns an all-zero root. Callers should reject
///   empty segments before this is reached.
/// - Single leaf: returns the leaf unchanged (no hashing).
/// - Odd-size levels: the trailing unpaired node is promoted
///   unchanged to the next level.
pub fn build_root(leaves: &[EntryDigest]) -> EntryDigest {
    if leaves.is_empty() {
        return [0u8; HASH_LEN];
    }
    let mut level: Vec<EntryDigest> = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

fn next_level(level: &[EntryDigest]) -> Vec<EntryDigest> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < level.len() {
        next.push(hash_pair(&level[i], &level[i + 1]));
        i += 2;
    }
    if i < level.len() {
        next.push(level[i]);
    }
    next
}

fn hash_pair(left: &EntryDigest, right: &EntryDigest) -> EntryDigest {
    let mut buf = [0u8; HASH_LEN * 2];
    buf[..HASH_LEN].copy_from_slice(left);
    buf[HASH_LEN..].copy_from_slice(right);
    sha256(&buf)
}

/// Build an inclusion proof for the leaf at `leaf_index`.
///
/// Returns the root alongside the proof path so callers can persist
/// both atomically. Panics if `leaf_index` is out of bounds.
pub fn build_proof(
    leaves: &[EntryDigest],
    leaf_index: usize,
) -> (EntryDigest, Vec<ProofStep>) {
    assert!(!leaves.is_empty(), "build_proof on empty leaves");
    assert!(
        leaf_index < leaves.len(),
        "leaf_index {} out of range (len={})",
        leaf_index,
        leaves.len()
    );

    let mut path: Vec<ProofStep> = Vec::new();
    let mut level: Vec<EntryDigest> = leaves.to_vec();
    let mut index = leaf_index;

    while level.len() > 1 {
        let is_left = index % 2 == 0;
        // The sibling is the other node in the pair containing `index`.
        // If `index` is the last element of an odd-length level, there
        // is no sibling and `index` is promoted unchanged.
        let sibling_idx = if is_left { index + 1 } else { index - 1 };
        if sibling_idx < level.len() {
            path.push(ProofStep {
                sibling_hash: level[sibling_idx],
                // `right` = the sibling is on the right side of the pair
                right: is_left,
            });
        }
        level = next_level(&level);
        index /= 2;
    }

    (level[0], path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_inclusion_proof;
    use crate::model::InclusionProof;

    fn h(n: u8) -> EntryDigest {
        sha256(&[n])
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let leaves = vec![h(1)];
        assert_eq!(build_root(&leaves), h(1));
    }

    #[test]
    fn two_leaf_root_is_pair_hash() {
        let leaves = vec![h(1), h(2)];
        let expected = hash_pair(&h(1), &h(2));
        assert_eq!(build_root(&leaves), expected);
    }

    #[test]
    fn odd_level_promotes_last_node_unchanged() {
        // 3 leaves: [a, b, c]
        // level 1:  [H(ab), c]
        // level 2:  [H(H(ab)||c)]
        let leaves = vec![h(1), h(2), h(3)];
        let ab = hash_pair(&h(1), &h(2));
        let expected = hash_pair(&ab, &h(3));
        assert_eq!(build_root(&leaves), expected);
    }

    #[test]
    fn inclusion_proof_roundtrip_four_leaves() {
        let leaves: Vec<EntryDigest> = (1u8..=4).map(h).collect();
        for i in 0..leaves.len() {
            let (root, path) = build_proof(&leaves, i);
            let proof = InclusionProof {
                seqno: i as u64 + 1,
                entry_hash: leaves[i],
                segment_id: 1,
                merkle_root: root,
                path,
            };
            verify_inclusion_proof(&proof, &root).unwrap();
        }
    }

    #[test]
    fn inclusion_proof_roundtrip_odd_sizes() {
        // Exercise the promoted-node branch.
        for size in [1, 3, 5, 7, 9, 11, 13] {
            let leaves: Vec<EntryDigest> = (1u8..=size as u8).map(h).collect();
            for i in 0..leaves.len() {
                let (root, path) = build_proof(&leaves, i);
                let proof = InclusionProof {
                    seqno: i as u64 + 1,
                    entry_hash: leaves[i],
                    segment_id: 1,
                    merkle_root: root,
                    path,
                };
                verify_inclusion_proof(&proof, &root).unwrap_or_else(|e| {
                    panic!("size={} index={}: {}", size, i, e);
                });
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<EntryDigest> = (1u8..=4).map(h).collect();
        let (root, path) = build_proof(&leaves, 0);
        let tampered = InclusionProof {
            seqno: 1,
            entry_hash: h(99), // wrong leaf value
            segment_id: 1,
            merkle_root: root,
            path,
        };
        assert!(verify_inclusion_proof(&tampered, &root).is_err());
    }
}
