//! Persistence trait for the secure log.
//!
//! Implementations supply storage for entries, segments, witnesses,
//! and stream metadata. The companion `secure-log-sqlite` crate ships
//! a SQLite-backed implementation. Implementations are required to be
//! `Send` so that [`NativeSecureLog`](crate::native::NativeSecureLog)
//! can be moved across threads; they do not need to be `Sync` (SQLite
//! connections are `!Sync`).
//!
//! All methods return `anyhow::Error` for storage-layer failures.
//! Logical errors (e.g. an entry hash mismatch) are surfaced as
//! [`SecureLogError`](crate::SecureLogError) higher up the stack.

use serde::{Deserialize, Serialize};

/// A raw row from the `secure_log_streams` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureLogStreamRow {
    pub name: String,
    /// `"public"`, `"protected"`, or `"highly-restricted"`.
    pub tier: String,
    pub description: Option<String>,
    pub created_at_rfc3339: String,
    /// RFC3339 timestamp when the stream was deprecated, or None
    /// for active streams. Deprecated streams reject new appends.
    #[serde(default)]
    pub deprecated_at_rfc3339: Option<String>,
}

/// A raw row from the `witness_log` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessLogRow {
    pub id: Option<i64>,
    pub stream_id: String,
    pub segment_id: u64,
    pub seq_start: u64,
    pub seq_end: u64,
    pub checkpoint_hash_hex: String,
    pub signature_hex: String,
    pub signer_identity: String,
    pub received_at_rfc3339: String,
}

/// A raw row from the `secure_log_segments` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureLogSegmentRow {
    /// `None` when inserting (the store assigns), `Some` when reading.
    pub segment_id: Option<u64>,
    pub stream_id: String,
    pub seq_start: u64,
    pub seq_end: u64,
    pub merkle_root: Vec<u8>,
    pub last_entry_hash: Vec<u8>,
    pub prev_checkpoint_hash: Vec<u8>,
    pub closed_at_rfc3339: String,
    pub signature: Option<Vec<u8>>,
    pub signer_identity: Option<String>,
}

/// A raw row from the `secure_log` table.
///
/// On-disk representation. [`EntryFields`](crate::EntryFields) is the
/// logical representation exchanged with encoders and verifiers; the
/// conversion is done by the secure log implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureLogRow {
    /// `None` when inserting (the store assigns), `Some` when reading.
    pub seqno: Option<u64>,
    pub stream_id: String,
    pub session_id: String,
    pub boot_id: String,
    pub timestamp_rfc3339: String,
    pub event_type: String,
    pub severity: String,
    pub producer: String,
    pub payload_encoding: String,
    pub payload: Vec<u8>,
    pub prev_entry_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
}

/// Persistence backend for the secure log.
///
/// Methods are partitioned by phase. Implementations may panic if
/// asked for a phase they don't support, but the canonical
/// `SqliteSecureLogStore` implements all of them.
pub trait SecureLogStore: Send {
    // -- Phase 1: entries --

    /// Insert a fully-formed secure log row.
    ///
    /// The caller (typically
    /// [`NativeSecureLog`](crate::native::NativeSecureLog)) is
    /// responsible for computing `seqno`, `prev_entry_hash`, and
    /// `entry_hash` before calling. The store enforces no integrity
    /// invariants beyond PRIMARY KEY uniqueness. `row.seqno` MUST be
    /// `Some`.
    fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64>;

    /// Return the globally-highest seqno across all streams, or None.
    ///
    /// `secure_log_head` returns the max for a single stream; this
    /// returns the max across the whole workspace. Used to compute
    /// the next sequence number at append time so seqnos are
    /// monotonic and unique workspace-wide.
    fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>>;

    /// Read a single secure log row by seqno.
    fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>>;

    /// Read secure log rows in `[from, to]` order, inclusive.
    fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>>;

    /// Return the highest seqno for the given stream, or None.
    fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>>;

    /// Return the most recent row for the given stream.
    fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>>;

    // -- Phase 2: segments --

    /// Insert a new segment row. Returns the assigned segment_id.
    /// The caller also passes the per-entry leaf index list, which
    /// is written to the underlying segment-entries table.
    fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)], // (seqno, leaf_index)
    ) -> anyhow::Result<u64>;

    /// Fetch a single segment by id.
    fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>>;

    /// List segments for a stream, ordered by segment_id.
    fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>>;

    /// Return the highest seqno already covered by a closed segment
    /// for the given stream, or None if the stream has no segments.
    fn secure_log_segment_last_seqno(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Option<u64>>;

    /// Return the seqnos belonging to a segment, ordered by leaf_index.
    fn secure_log_segment_entry_seqnos(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Vec<u64>>;

    /// Find the segment a given seqno belongs to (if any).
    fn secure_log_segment_for_seqno(
        &self,
        seqno: u64,
    ) -> anyhow::Result<Option<u64>>;

    /// Update a segment with a signature. Used by Phase 3. Returns
    /// an error if the segment does not exist.
    fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()>;

    // -- Phase 4: witness log --

    /// Append a witness receipt. The caller is responsible for the
    /// equivocation check — this method only enforces uniqueness at
    /// the row level.
    fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64>;

    /// Return the most recent witness receipt for a stream, if any.
    fn witness_log_latest(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Option<WitnessLogRow>>;

    /// Return all witness receipts for a stream, ordered by
    /// received_at (ascending). Used by replay/audit tooling.
    fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>>;

    /// Return the distinct stream IDs that have at least one witness receipt.
    fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>>;

    /// Delete witness receipts older than `older_than_rfc3339` and/or
    /// keep only the most recent `keep_latest` per stream.
    ///
    /// Returns the number of rows deleted. Pass `stream_id = None`
    /// to apply to all streams.
    fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize>;

    // -- Stream metadata --

    /// Upsert a stream record.
    fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()>;

    /// Look up a stream by name.
    fn secure_log_stream_get(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<SecureLogStreamRow>>;

    /// List all streams, ordered by name.
    fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>>;

    /// Set a stream's confidentiality tier.
    fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()>;

    /// Mark a stream deprecated. Idempotent. Returns an error if
    /// the stream does not exist.
    fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()>;
}
