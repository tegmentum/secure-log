//! Data types for the secure log subsystem.
//!
//! These types are 1:1 mirrors of the `record` definitions in
//! `wit/secure-log.wit`. Field names use snake_case in Rust and
//! kebab-case in the WIT.

use serde::{Deserialize, Serialize};

use super::hash::{EntryDigest, HASH_LEN};

/// Current entry format version. Bump when the canonical byte layout
/// (as implemented by any [`CanonicalEncoder`](super::CanonicalEncoder))
/// changes in a way that breaks existing verification.
pub const ENTRY_VERSION: u32 = 1;

/// Current checkpoint format version.
pub const CHECKPOINT_VERSION: u32 = 1;

/// Structural form of a log entry.
///
/// The canonical byte form is whatever [`CanonicalEncoder::encode_entry`](super::CanonicalEncoder::encode_entry)
/// produces for this struct. The hash chain link is computed over the
/// canonical form, *not* over this struct directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFields {
    pub version: u32,
    pub stream_id: String,
    pub session_id: String,
    pub boot_id: String,
    pub seqno: u64,
    pub timestamp_rfc3339: String,
    pub event_type: String,
    pub severity: String,
    pub producer: String,
    /// Identifies the encoding used for `payload`. Matches the
    /// `name()` return of the [`CanonicalEncoder`](super::CanonicalEncoder)
    /// used. For encrypted payloads this embeds the AEAD name, e.g.
    /// `"cbor+aead-chacha20poly1305"`.
    pub payload_encoding: String,
    pub payload: Vec<u8>,
    pub prev_entry_hash: Vec<u8>,
}

/// Structural form of a segment checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointFields {
    pub version: u32,
    pub stream_id: String,
    pub segment_id: u64,
    pub seq_start: u64,
    pub seq_end: u64,
    pub merkle_root: Vec<u8>,
    pub last_entry_hash: Vec<u8>,
    pub prev_checkpoint_hash: Vec<u8>,
    pub boot_id: String,
    pub session_id: String,
    pub policy_hash: Vec<u8>,
    pub timestamp_rfc3339: String,
}

/// Result of a successful [`SecureLog::append`](super::SecureLog::append).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendResult {
    pub seqno: u64,
    pub entry_hash: EntryDigest,
}

/// A closed segment with its Merkle root and optional TPM signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub segment_id: u64,
    pub stream_id: String,
    pub seq_start: u64,
    pub seq_end: u64,
    pub merkle_root: EntryDigest,
    pub last_entry_hash: EntryDigest,
    pub prev_checkpoint_hash: EntryDigest,
    pub closed_at_rfc3339: String,
    /// Phase 3: raw TPM signature over the canonical checkpoint bytes.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Phase 3: identifier of the signing identity (UUID string).
    #[serde(default)]
    pub signer_identity: Option<String>,
}

/// One step of a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling_hash: EntryDigest,
    /// `true` if the sibling is on the right side of the pair at this
    /// level of the tree (i.e. the running hash goes on the left).
    pub right: bool,
}

/// Merkle inclusion proof for a single log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub seqno: u64,
    pub entry_hash: EntryDigest,
    pub segment_id: u64,
    pub merkle_root: EntryDigest,
    pub path: Vec<ProofStep>,
}

/// Errors returned by [`SecureLog`](super::SecureLog) implementations.
///
/// These map to the WIT `result<_, string>` return type but carry
/// structured context so the CLI can format them as diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum SecureLogError {
    #[error("secure log entry not found: seqno={0}")]
    EntryNotFound(u64),

    #[error("stream not found: {0}")]
    StreamNotFound(String),

    #[error("chain broken at seqno {seqno}: {reason}")]
    ChainBroken { seqno: u64, reason: String },

    #[error("inclusion proof does not reconstruct expected root (seqno={seqno}, segment_id={segment_id})")]
    InclusionMismatch { seqno: u64, segment_id: u64 },

    #[error("segment not found: {0}")]
    SegmentNotFound(u64),

    #[error("segment already closed: {0}")]
    SegmentAlreadyClosed(u64),

    #[error("no entries since last segment close for stream '{0}'")]
    EmptySegment(String),

    #[error("this operation is not implemented until a later phase")]
    NotImplemented,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Convert a `Vec<u8>` of the wrong length into a fixed-size
/// [`EntryDigest`], or return a structured error.
pub fn digest_from_vec(v: Vec<u8>, context: &str) -> Result<EntryDigest, SecureLogError> {
    if v.len() != HASH_LEN {
        return Err(SecureLogError::Invalid(format!(
            "{}: expected {}-byte digest, got {}",
            context,
            HASH_LEN,
            v.len()
        )));
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&v);
    Ok(out)
}
