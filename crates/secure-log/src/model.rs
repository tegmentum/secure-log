//! Data types for the secure log subsystem.
//!
//! These types are 1:1 mirrors of the `record` definitions in
//! `wit/secure-log.wit`. Field names use snake_case in Rust and
//! kebab-case in the WIT.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::hash::{EntryDigest, HASH_LEN};

/// Current entry format version. Bump when the canonical byte layout
/// (as implemented by any [`CanonicalEncoder`](super::CanonicalEncoder))
/// changes in a way that breaks existing verification.
pub const ENTRY_VERSION: u32 = 1;

/// Current checkpoint format version.
pub const CHECKPOINT_VERSION: u32 = 1;

/// Severity of a log entry, RFC 5424 / POSIX syslog ordering. Lower
/// ordinal = more urgent. Mirrors the `severity` enum in
/// `wit/log.wit` (which matches `wasmos:log/logger.severity`).
///
/// The lowercase spelling of each variant name (`"emergency"`,
/// `"info"`, ...) is the canonical string form used everywhere at a
/// serialization boundary that isn't a WIT enum:
///
/// - The [`CanonicalEncoder`](super::CanonicalEncoder) writes
///   `Value::Text(<lowercase name>)` into the CBOR entry array.
///   Same bytes as the string-era encoder emitted when callers passed
///   `"info"`, `"warning"`, ...
/// - The SQLite / file / remote store backends persist and read the
///   lowercase name in their `severity TEXT NOT NULL` column.
/// - The JSON-RPC wire format ([`secure-log-rpc`](../secure_log_rpc/index.html))
///   and the JSONL append-only file format both encode via
///   `#[serde(rename_all = "lowercase")]`.
///
/// The `TryFrom<&str>` impl is strict — unknown severity strings
/// become [`SecureLogError::Invalid`]; there is no legacy fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// 0 — system is unusable.
    Emergency,
    /// 1 — action must be taken immediately.
    Alert,
    /// 2 — critical conditions.
    Critical,
    /// 3 — error conditions.
    Error,
    /// 4 — warning conditions.
    Warning,
    /// 5 — normal but significant condition.
    Notice,
    /// 6 — informational.
    Info,
    /// 7 — debug-level messages.
    Debug,
}

impl Severity {
    /// Return the canonical lowercase string form of this severity.
    /// Stable across versions: the persisted / hashed / on-wire form
    /// is `self.as_str()` at every boundary.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Severity::Emergency => "emergency",
            Severity::Alert => "alert",
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Info => "info",
            Severity::Debug => "debug",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Severity> for String {
    fn from(s: Severity) -> String {
        s.as_str().to_string()
    }
}

impl TryFrom<&str> for Severity {
    type Error = SecureLogError;

    fn try_from(s: &str) -> Result<Self, SecureLogError> {
        match s {
            "emergency" => Ok(Severity::Emergency),
            "alert" => Ok(Severity::Alert),
            "critical" => Ok(Severity::Critical),
            "error" => Ok(Severity::Error),
            "warning" => Ok(Severity::Warning),
            "notice" => Ok(Severity::Notice),
            "info" => Ok(Severity::Info),
            "debug" => Ok(Severity::Debug),
            other => Err(SecureLogError::Invalid(format!(
                "unknown severity: {:?} (expected one of \
                 emergency, alert, critical, error, warning, notice, info, debug)",
                other
            ))),
        }
    }
}

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
    pub severity: Severity,
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

/// Public metadata for a stream, surfaced by
/// [`SecureLog::list_streams`](super::SecureLog::list_streams).
///
/// This is the caller-visible projection of a
/// [`SecureLogStreamRow`](super::store::SecureLogStreamRow) — the row
/// carries store-facing detail (RFC3339 `created_at`, on-disk column
/// order) that lifecycle callers don't need. `deprecated_at` is
/// surfaced as an `Option<u64>` unix-seconds timestamp so consumers
/// can trivially filter live vs archived without RFC3339 parsing.
///
/// Fields:
/// - `name` — the stream identifier as passed to `append` / `head`.
/// - `tier` — the confidentiality tier as a stable string
///   (`"public"`, `"protected"`, `"highly-restricted"`).
/// - `description` — free-form human note captured at
///   `create_stream` time, if any.
/// - `deprecated_at` — unix seconds when the stream was deprecated,
///   or `None` for live streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamInfo {
    pub name: String,
    pub tier: String,
    pub description: Option<String>,
    pub deprecated_at: Option<u64>,
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
