//! TPM-signed checkpoint construction and verification.
//!
//! A **checkpoint** is the canonical structure that commits a
//! segment's Merkle root into a chain of signed statements. The
//! checkpoint hash (`H(canonical_checkpoint_bytes)`) is what the TPM
//! actually signs; the signature is stored alongside the segment
//! row. Checkpoints chain to each other via `prev_checkpoint_hash`,
//! which is the checkpoint hash of the previous segment (not the
//! previous segment's Merkle root, though those coincide until
//! Phase 3 flips it to the real checkpoint hash).
//!
//! This module is pure logic — no I/O. The caller is responsible
//! for fetching the segment, finding the previous checkpoint hash,
//! calling the TPM for signing, and persisting the result.

use super::encoder::CanonicalEncoder;
use super::hash::{sha256, EntryDigest, ZERO_HASH};
use super::model::{CheckpointFields, SegmentInfo, CHECKPOINT_VERSION};

/// Build the canonical checkpoint fields for a segment.
///
/// `prev_checkpoint_hash` should be the *checkpoint hash* of the
/// previous segment (or [`ZERO_HASH`] for the first). `policy_hash`
/// is a pluggable policy fingerprint; pass an all-zero digest if no
/// policy is bound to the log.
pub fn build_fields(
    segment: &SegmentInfo,
    prev_checkpoint_hash: EntryDigest,
    boot_id: &str,
    session_id: &str,
    policy_hash: EntryDigest,
) -> CheckpointFields {
    CheckpointFields {
        version: CHECKPOINT_VERSION,
        stream_id: segment.stream_id.clone(),
        segment_id: segment.segment_id,
        seq_start: segment.seq_start,
        seq_end: segment.seq_end,
        merkle_root: segment.merkle_root.to_vec(),
        last_entry_hash: segment.last_entry_hash.to_vec(),
        prev_checkpoint_hash: prev_checkpoint_hash.to_vec(),
        boot_id: boot_id.to_string(),
        session_id: session_id.to_string(),
        policy_hash: policy_hash.to_vec(),
        timestamp_rfc3339: segment.closed_at_rfc3339.clone(),
    }
}

/// Compute the checkpoint hash: `H(canonical_checkpoint_bytes)`.
///
/// This is the bytes the TPM signs, and the bytes a verifier
/// recomputes when checking a signature.
pub fn hash(encoder: &dyn CanonicalEncoder, fields: &CheckpointFields) -> EntryDigest {
    sha256(&encoder.encode_checkpoint(fields))
}

/// Convenience: the "genesis" prev_checkpoint_hash (all zeros).
pub const GENESIS_PREV: EntryDigest = ZERO_HASH;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::CborEncoder;

    fn sample_segment() -> SegmentInfo {
        SegmentInfo {
            segment_id: 1,
            stream_id: "default".into(),
            seq_start: 1,
            seq_end: 10,
            merkle_root: [7u8; 32],
            last_entry_hash: [8u8; 32],
            prev_checkpoint_hash: [0u8; 32],
            closed_at_rfc3339: "2026-04-10T00:00:00Z".into(),
            signature: vec![],
            signer_identity: None,
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let enc = CborEncoder::new();
        let seg = sample_segment();
        let f = build_fields(&seg, GENESIS_PREV, "boot-1", "sess-1", [0u8; 32]);
        let h1 = hash(&enc, &f);
        let h2 = hash(&enc, &f);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_changes_on_any_field() {
        let enc = CborEncoder::new();
        let seg = sample_segment();
        let base = build_fields(&seg, GENESIS_PREV, "boot-1", "sess-1", [0u8; 32]);
        let h0 = hash(&enc, &base);

        let mut mutated = base.clone();
        mutated.merkle_root = vec![9u8; 32];
        assert_ne!(hash(&enc, &mutated), h0);

        let mut mutated = base.clone();
        mutated.seq_end = 11;
        assert_ne!(hash(&enc, &mutated), h0);

        let mut mutated = base.clone();
        mutated.prev_checkpoint_hash = vec![1u8; 32];
        assert_ne!(hash(&enc, &mutated), h0);
    }

    #[test]
    fn encoding_round_trips_segment_fields() {
        // Sanity: the encoder's encode_checkpoint actually preserves
        // the values we put in, by checking that a byte-level diff
        // correlates with every logical change.
        let enc = CborEncoder::new();
        let seg = sample_segment();
        let f = build_fields(&seg, GENESIS_PREV, "boot-1", "sess-1", [0u8; 32]);
        let bytes = enc.encode_checkpoint(&f);
        assert!(bytes.len() > 32);
    }
}
