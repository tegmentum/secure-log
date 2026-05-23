//! Shared JSON-RPC wire contract for the secure-log remote store.
//!
//! The `secure-log-store-remote` component turns each of the 23 store
//! operations into one `transport.rpc(method, params-json)` call. This
//! crate defines the two halves of that contract that both ends MUST
//! agree on:
//!
//! 1. [`method`] — the canonical method-name strings.
//! 2. The `Wire*` records — serde mirrors of the store row types.
//!    (The component converts these to/from its WIT-bindgen records;
//!    a native server converts them to/from `secure_log` row structs.)
//!
//! ## Wire format
//!
//! The transport performs one request/response round trip per call:
//!
//! - **method** — one of the [`method`] constants.
//! - **params-json** — a JSON array of the call's arguments, in
//!   declaration order. For example `secure-log-range` sends
//!   `["default", 1, 10]`.
//! - **result** — the JSON encoding of the return value on success,
//!   or a transport-level `err(message)` on failure.
//!
//! `Vec<u8>` fields (hashes, payloads) serialize as JSON arrays of
//! byte integers, matching `serde_json`'s default. Both ends use
//! `serde_json`, so the encoding is symmetric.

use serde::{Deserialize, Serialize};

/// Canonical method-name strings. Both the remote provider and the
/// server reference these so a rename can't desynchronize them.
pub mod method {
    pub const INIT: &str = "init";

    // Phase 1: entries
    pub const SECURE_LOG_INSERT: &str = "secure-log-insert";
    pub const SECURE_LOG_GLOBAL_HEAD: &str = "secure-log-global-head";
    pub const SECURE_LOG_GET: &str = "secure-log-get";
    pub const SECURE_LOG_RANGE: &str = "secure-log-range";
    pub const SECURE_LOG_HEAD: &str = "secure-log-head";
    pub const SECURE_LOG_LAST: &str = "secure-log-last";

    // Phase 2: segments
    pub const SECURE_LOG_SEGMENT_INSERT: &str = "secure-log-segment-insert";
    pub const SECURE_LOG_SEGMENT_GET: &str = "secure-log-segment-get";
    pub const SECURE_LOG_SEGMENTS_LIST: &str = "secure-log-segments-list";
    pub const SECURE_LOG_SEGMENT_LAST_SEQNO: &str = "secure-log-segment-last-seqno";
    pub const SECURE_LOG_SEGMENT_ENTRY_SEQNOS: &str = "secure-log-segment-entry-seqnos";
    pub const SECURE_LOG_SEGMENT_FOR_SEQNO: &str = "secure-log-segment-for-seqno";
    pub const SECURE_LOG_SEGMENT_SET_SIGNATURE: &str = "secure-log-segment-set-signature";

    // Phase 4: witness log
    pub const WITNESS_LOG_INSERT: &str = "witness-log-insert";
    pub const WITNESS_LOG_LATEST: &str = "witness-log-latest";
    pub const WITNESS_LOG_LIST: &str = "witness-log-list";
    pub const WITNESS_LOG_STREAM_IDS: &str = "witness-log-stream-ids";
    pub const WITNESS_LOG_GC: &str = "witness-log-gc";

    // Stream metadata
    pub const SECURE_LOG_STREAM_UPSERT: &str = "secure-log-stream-upsert";
    pub const SECURE_LOG_STREAM_GET: &str = "secure-log-stream-get";
    pub const SECURE_LOG_STREAM_LIST: &str = "secure-log-stream-list";
    pub const SECURE_LOG_STREAM_SET_TIER: &str = "secure-log-stream-set-tier";
    pub const SECURE_LOG_STREAM_DEPRECATE: &str = "secure-log-stream-deprecate";
}

/// JSON envelope carried in the HTTP request body: `{"method":...,
/// "params":...}`. `params` is kept as raw JSON so the transport does
/// not have to re-parse the already-serialized argument array.
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub params: serde_json::Value,
}

/// Serde mirror of `secure-log-row`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireRow {
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

/// Serde mirror of `secure-log-segment-row`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireSegment {
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

/// Serde mirror of `secure-log-stream-row`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireStream {
    pub name: String,
    pub tier: String,
    pub description: Option<String>,
    pub created_at_rfc3339: String,
    pub deprecated_at_rfc3339: Option<String>,
}

/// Serde mirror of `witness-log-row`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireWitness {
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
