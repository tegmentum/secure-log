//! secure-log:store provider that forwards every operation to a
//! remote machine as a JSON-RPC call over the pluggable `transport`
//! interface.
//!
//! Each store method serializes its arguments to JSON, calls
//! `transport.rpc(method-name, params-json)`, and deserializes the
//! JSON result. The remote endpoint is expected to implement the
//! same 23 operations against its own storage. The transport itself
//! (wasi:http, a host function, a message queue, ...) is supplied by
//! whatever component fulfills the `transport` import, so this
//! backend is network-agnostic.
//!
//! Wire protocol (proposed default — see repo README):
//!   method      = the store function name, e.g. "secure-log-insert"
//!   params-json = JSON array of the call's arguments, in order
//!   result      = JSON encoding of the return value

#[allow(warnings)]
mod bindings;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use bindings::secure_log::log::transport;

use bindings::exports::secure_log::log::store::{
    Guest, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, SegmentEntry, WitnessLogRow,
};

struct Component;

// ---------------------------------------------------------------------
// Serde mirrors of the store records (bindgen records lack serde).
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct MRow {
    seqno: Option<u64>,
    stream_id: String,
    session_id: String,
    boot_id: String,
    timestamp_rfc3339: String,
    event_type: String,
    severity: String,
    producer: String,
    payload_encoding: String,
    payload: Vec<u8>,
    prev_entry_hash: Vec<u8>,
    entry_hash: Vec<u8>,
}

impl From<SecureLogRow> for MRow {
    fn from(r: SecureLogRow) -> Self {
        MRow {
            seqno: r.seqno,
            stream_id: r.stream_id,
            session_id: r.session_id,
            boot_id: r.boot_id,
            timestamp_rfc3339: r.timestamp_rfc3339,
            event_type: r.event_type,
            severity: r.severity,
            producer: r.producer,
            payload_encoding: r.payload_encoding,
            payload: r.payload,
            prev_entry_hash: r.prev_entry_hash,
            entry_hash: r.entry_hash,
        }
    }
}

impl From<MRow> for SecureLogRow {
    fn from(r: MRow) -> Self {
        SecureLogRow {
            seqno: r.seqno,
            stream_id: r.stream_id,
            session_id: r.session_id,
            boot_id: r.boot_id,
            timestamp_rfc3339: r.timestamp_rfc3339,
            event_type: r.event_type,
            severity: r.severity,
            producer: r.producer,
            payload_encoding: r.payload_encoding,
            payload: r.payload,
            prev_entry_hash: r.prev_entry_hash,
            entry_hash: r.entry_hash,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MSegment {
    segment_id: Option<u64>,
    stream_id: String,
    seq_start: u64,
    seq_end: u64,
    merkle_root: Vec<u8>,
    last_entry_hash: Vec<u8>,
    prev_checkpoint_hash: Vec<u8>,
    closed_at_rfc3339: String,
    signature: Option<Vec<u8>>,
    signer_identity: Option<String>,
}

impl From<SecureLogSegmentRow> for MSegment {
    fn from(s: SecureLogSegmentRow) -> Self {
        MSegment {
            segment_id: s.segment_id,
            stream_id: s.stream_id,
            seq_start: s.seq_start,
            seq_end: s.seq_end,
            merkle_root: s.merkle_root,
            last_entry_hash: s.last_entry_hash,
            prev_checkpoint_hash: s.prev_checkpoint_hash,
            closed_at_rfc3339: s.closed_at_rfc3339,
            signature: s.signature,
            signer_identity: s.signer_identity,
        }
    }
}

impl From<MSegment> for SecureLogSegmentRow {
    fn from(s: MSegment) -> Self {
        SecureLogSegmentRow {
            segment_id: s.segment_id,
            stream_id: s.stream_id,
            seq_start: s.seq_start,
            seq_end: s.seq_end,
            merkle_root: s.merkle_root,
            last_entry_hash: s.last_entry_hash,
            prev_checkpoint_hash: s.prev_checkpoint_hash,
            closed_at_rfc3339: s.closed_at_rfc3339,
            signature: s.signature,
            signer_identity: s.signer_identity,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MStream {
    name: String,
    tier: String,
    description: Option<String>,
    created_at_rfc3339: String,
    deprecated_at_rfc3339: Option<String>,
}

impl From<SecureLogStreamRow> for MStream {
    fn from(s: SecureLogStreamRow) -> Self {
        MStream {
            name: s.name,
            tier: s.tier,
            description: s.description,
            created_at_rfc3339: s.created_at_rfc3339,
            deprecated_at_rfc3339: s.deprecated_at_rfc3339,
        }
    }
}

impl From<MStream> for SecureLogStreamRow {
    fn from(s: MStream) -> Self {
        SecureLogStreamRow {
            name: s.name,
            tier: s.tier,
            description: s.description,
            created_at_rfc3339: s.created_at_rfc3339,
            deprecated_at_rfc3339: s.deprecated_at_rfc3339,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MWitness {
    id: Option<i64>,
    stream_id: String,
    segment_id: u64,
    seq_start: u64,
    seq_end: u64,
    checkpoint_hash_hex: String,
    signature_hex: String,
    signer_identity: String,
    received_at_rfc3339: String,
}

impl From<WitnessLogRow> for MWitness {
    fn from(w: WitnessLogRow) -> Self {
        MWitness {
            id: w.id,
            stream_id: w.stream_id,
            segment_id: w.segment_id,
            seq_start: w.seq_start,
            seq_end: w.seq_end,
            checkpoint_hash_hex: w.checkpoint_hash_hex,
            signature_hex: w.signature_hex,
            signer_identity: w.signer_identity,
            received_at_rfc3339: w.received_at_rfc3339,
        }
    }
}

impl From<MWitness> for WitnessLogRow {
    fn from(w: MWitness) -> Self {
        WitnessLogRow {
            id: w.id,
            stream_id: w.stream_id,
            segment_id: w.segment_id,
            seq_start: w.seq_start,
            seq_end: w.seq_end,
            checkpoint_hash_hex: w.checkpoint_hash_hex,
            signature_hex: w.signature_hex,
            signer_identity: w.signer_identity,
            received_at_rfc3339: w.received_at_rfc3339,
        }
    }
}

// ---------------------------------------------------------------------
// JSON-RPC helper.
// ---------------------------------------------------------------------

fn call<P: Serialize, R: DeserializeOwned>(method: &str, params: &P) -> Result<R, String> {
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    let result_json = transport::rpc(method, &params_json)?;
    serde_json::from_str(&result_json)
        .map_err(|e| format!("decode result of {}: {}", method, e))
}

// ---------------------------------------------------------------------
// Store implementation: each call forwards over the transport.
// ---------------------------------------------------------------------

impl Guest for Component {
    fn init(config: String) -> Result<(), String> {
        if config.is_empty() {
            return Err("remote store: init config is empty".into());
        }
        call("init", &(config,))
    }

    fn secure_log_insert(row: SecureLogRow) -> Result<u64, String> {
        call("secure-log-insert", &(MRow::from(row),))
    }

    fn secure_log_global_head() -> Result<Option<u64>, String> {
        call::<(), _>("secure-log-global-head", &())
    }

    fn secure_log_get(seqno: u64) -> Result<Option<SecureLogRow>, String> {
        let r: Option<MRow> = call("secure-log-get", &(seqno,))?;
        Ok(r.map(Into::into))
    }

    fn secure_log_range(
        stream_id: String,
        from_seqno: u64,
        to_seqno: u64,
    ) -> Result<Vec<SecureLogRow>, String> {
        let rows: Vec<MRow> = call("secure-log-range", &(stream_id, from_seqno, to_seqno))?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    fn secure_log_head(stream_id: String) -> Result<Option<u64>, String> {
        call("secure-log-head", &(stream_id,))
    }

    fn secure_log_last(stream_id: String) -> Result<Option<SecureLogRow>, String> {
        let r: Option<MRow> = call("secure-log-last", &(stream_id,))?;
        Ok(r.map(Into::into))
    }

    fn secure_log_segment_insert(
        row: SecureLogSegmentRow,
        entries: Vec<SegmentEntry>,
    ) -> Result<u64, String> {
        call("secure-log-segment-insert", &(MSegment::from(row), entries))
    }

    fn secure_log_segment_get(segment_id: u64) -> Result<Option<SecureLogSegmentRow>, String> {
        let s: Option<MSegment> = call("secure-log-segment-get", &(segment_id,))?;
        Ok(s.map(Into::into))
    }

    fn secure_log_segments_list(stream_id: String) -> Result<Vec<SecureLogSegmentRow>, String> {
        let segs: Vec<MSegment> = call("secure-log-segments-list", &(stream_id,))?;
        Ok(segs.into_iter().map(Into::into).collect())
    }

    fn secure_log_segment_last_seqno(stream_id: String) -> Result<Option<u64>, String> {
        call("secure-log-segment-last-seqno", &(stream_id,))
    }

    fn secure_log_segment_entry_seqnos(segment_id: u64) -> Result<Vec<u64>, String> {
        call("secure-log-segment-entry-seqnos", &(segment_id,))
    }

    fn secure_log_segment_for_seqno(seqno: u64) -> Result<Option<u64>, String> {
        call("secure-log-segment-for-seqno", &(seqno,))
    }

    fn secure_log_segment_set_signature(
        segment_id: u64,
        signature: Vec<u8>,
        signer_identity: String,
    ) -> Result<(), String> {
        call(
            "secure-log-segment-set-signature",
            &(segment_id, signature, signer_identity),
        )
    }

    fn witness_log_insert(row: WitnessLogRow) -> Result<u64, String> {
        call("witness-log-insert", &(MWitness::from(row),))
    }

    fn witness_log_latest(stream_id: String) -> Result<Option<WitnessLogRow>, String> {
        let w: Option<MWitness> = call("witness-log-latest", &(stream_id,))?;
        Ok(w.map(Into::into))
    }

    fn witness_log_list(stream_id: String) -> Result<Vec<WitnessLogRow>, String> {
        let ws: Vec<MWitness> = call("witness-log-list", &(stream_id,))?;
        Ok(ws.into_iter().map(Into::into).collect())
    }

    fn witness_log_stream_ids() -> Result<Vec<String>, String> {
        call::<(), _>("witness-log-stream-ids", &())
    }

    fn witness_log_gc(
        stream_id: Option<String>,
        keep_latest: Option<u32>,
        older_than_rfc3339: Option<String>,
    ) -> Result<u32, String> {
        call(
            "witness-log-gc",
            &(stream_id, keep_latest, older_than_rfc3339),
        )
    }

    fn secure_log_stream_upsert(row: SecureLogStreamRow) -> Result<(), String> {
        call("secure-log-stream-upsert", &(MStream::from(row),))
    }

    fn secure_log_stream_get(name: String) -> Result<Option<SecureLogStreamRow>, String> {
        let s: Option<MStream> = call("secure-log-stream-get", &(name,))?;
        Ok(s.map(Into::into))
    }

    fn secure_log_stream_list() -> Result<Vec<SecureLogStreamRow>, String> {
        let streams: Vec<MStream> = call::<(), _>("secure-log-stream-list", &())?;
        Ok(streams.into_iter().map(Into::into).collect())
    }

    fn secure_log_stream_set_tier(name: String, tier: String) -> Result<(), String> {
        call("secure-log-stream-set-tier", &(name, tier))
    }

    fn secure_log_stream_deprecate(
        name: String,
        deprecated_at_rfc3339: String,
    ) -> Result<(), String> {
        call(
            "secure-log-stream-deprecate",
            &(name, deprecated_at_rfc3339),
        )
    }
}

bindings::export!(Component with_types_in bindings);
