//! secure-log:store provider that forwards every operation to a
//! remote machine as a JSON-RPC call over the pluggable `transport`
//! interface.
//!
//! Each store method serializes its arguments to JSON, calls
//! `transport.rpc(method-name, params-json)`, and deserializes the
//! JSON result. The wire contract — method names and row shapes — is
//! shared with the server via the [`secure_log_rpc`] crate, so the two
//! ends cannot drift. The transport itself (wasi:http, a host
//! function, a message queue, ...) is supplied by whatever component
//! fulfills the `transport` import, so this backend is
//! network-agnostic; see `secure-log-transport-http` for the default
//! wasi:http provider and `secure-log-rpc-server` for the endpoint.

#[allow(warnings)]
mod bindings;

use serde::de::DeserializeOwned;
use serde::Serialize;

use secure_log_rpc::{method as m, WireRow, WireSegment, WireStream, WireWitness};

use bindings::secure_log::log::transport;

use bindings::exports::secure_log::log::store::{
    Guest, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, SegmentEntry, WitnessLogRow,
};

struct Component;

// ---------------------------------------------------------------------
// Conversions between the WIT-bindgen records and the shared wire
// types. Free functions rather than `From` impls: both the bindgen
// types (local) and the wire types (foreign) would otherwise trip the
// orphan rule.
// ---------------------------------------------------------------------

fn row_to_wire(r: SecureLogRow) -> WireRow {
    WireRow {
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

fn row_from_wire(r: WireRow) -> SecureLogRow {
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

fn seg_to_wire(s: SecureLogSegmentRow) -> WireSegment {
    WireSegment {
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

fn seg_from_wire(s: WireSegment) -> SecureLogSegmentRow {
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

fn stream_to_wire(s: SecureLogStreamRow) -> WireStream {
    WireStream {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn stream_from_wire(s: WireStream) -> SecureLogStreamRow {
    SecureLogStreamRow {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn witness_to_wire(w: WitnessLogRow) -> WireWitness {
    WireWitness {
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

fn witness_from_wire(w: WireWitness) -> WitnessLogRow {
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

// ---------------------------------------------------------------------
// JSON-RPC helper.
// ---------------------------------------------------------------------

fn call<P: Serialize, R: DeserializeOwned>(method: &str, params: &P) -> Result<R, String> {
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    let result_json = transport::rpc(method, &params_json)?;
    serde_json::from_str(&result_json).map_err(|e| format!("decode result of {}: {}", method, e))
}

// ---------------------------------------------------------------------
// Store implementation: each call forwards over the transport.
// ---------------------------------------------------------------------

impl Guest for Component {
    fn init(config: String) -> Result<(), String> {
        if config.is_empty() {
            return Err("remote store: init config is empty".into());
        }
        call(m::INIT, &(config,))
    }

    fn secure_log_insert(row: SecureLogRow) -> Result<u64, String> {
        call(m::SECURE_LOG_INSERT, &(row_to_wire(row),))
    }

    fn secure_log_global_head() -> Result<Option<u64>, String> {
        call::<(), _>(m::SECURE_LOG_GLOBAL_HEAD, &())
    }

    fn secure_log_get(seqno: u64) -> Result<Option<SecureLogRow>, String> {
        let r: Option<WireRow> = call(m::SECURE_LOG_GET, &(seqno,))?;
        Ok(r.map(row_from_wire))
    }

    fn secure_log_range(
        stream_id: String,
        from_seqno: u64,
        to_seqno: u64,
    ) -> Result<Vec<SecureLogRow>, String> {
        let rows: Vec<WireRow> = call(m::SECURE_LOG_RANGE, &(stream_id, from_seqno, to_seqno))?;
        Ok(rows.into_iter().map(row_from_wire).collect())
    }

    fn secure_log_head(stream_id: String) -> Result<Option<u64>, String> {
        call(m::SECURE_LOG_HEAD, &(stream_id,))
    }

    fn secure_log_last(stream_id: String) -> Result<Option<SecureLogRow>, String> {
        let r: Option<WireRow> = call(m::SECURE_LOG_LAST, &(stream_id,))?;
        Ok(r.map(row_from_wire))
    }

    fn secure_log_segment_insert(
        row: SecureLogSegmentRow,
        entries: Vec<SegmentEntry>,
    ) -> Result<u64, String> {
        call(m::SECURE_LOG_SEGMENT_INSERT, &(seg_to_wire(row), entries))
    }

    fn secure_log_segment_get(segment_id: u64) -> Result<Option<SecureLogSegmentRow>, String> {
        let s: Option<WireSegment> = call(m::SECURE_LOG_SEGMENT_GET, &(segment_id,))?;
        Ok(s.map(seg_from_wire))
    }

    fn secure_log_segments_list(stream_id: String) -> Result<Vec<SecureLogSegmentRow>, String> {
        let segs: Vec<WireSegment> = call(m::SECURE_LOG_SEGMENTS_LIST, &(stream_id,))?;
        Ok(segs.into_iter().map(seg_from_wire).collect())
    }

    fn secure_log_segment_last_seqno(stream_id: String) -> Result<Option<u64>, String> {
        call(m::SECURE_LOG_SEGMENT_LAST_SEQNO, &(stream_id,))
    }

    fn secure_log_segment_entry_seqnos(segment_id: u64) -> Result<Vec<u64>, String> {
        call(m::SECURE_LOG_SEGMENT_ENTRY_SEQNOS, &(segment_id,))
    }

    fn secure_log_segment_for_seqno(seqno: u64) -> Result<Option<u64>, String> {
        call(m::SECURE_LOG_SEGMENT_FOR_SEQNO, &(seqno,))
    }

    fn secure_log_segment_set_signature(
        segment_id: u64,
        signature: Vec<u8>,
        signer_identity: String,
    ) -> Result<(), String> {
        call(
            m::SECURE_LOG_SEGMENT_SET_SIGNATURE,
            &(segment_id, signature, signer_identity),
        )
    }

    fn witness_log_insert(row: WitnessLogRow) -> Result<u64, String> {
        call(m::WITNESS_LOG_INSERT, &(witness_to_wire(row),))
    }

    fn witness_log_latest(stream_id: String) -> Result<Option<WitnessLogRow>, String> {
        let w: Option<WireWitness> = call(m::WITNESS_LOG_LATEST, &(stream_id,))?;
        Ok(w.map(witness_from_wire))
    }

    fn witness_log_list(stream_id: String) -> Result<Vec<WitnessLogRow>, String> {
        let ws: Vec<WireWitness> = call(m::WITNESS_LOG_LIST, &(stream_id,))?;
        Ok(ws.into_iter().map(witness_from_wire).collect())
    }

    fn witness_log_stream_ids() -> Result<Vec<String>, String> {
        call::<(), _>(m::WITNESS_LOG_STREAM_IDS, &())
    }

    fn witness_log_gc(
        stream_id: Option<String>,
        keep_latest: Option<u32>,
        older_than_rfc3339: Option<String>,
    ) -> Result<u32, String> {
        call(
            m::WITNESS_LOG_GC,
            &(stream_id, keep_latest, older_than_rfc3339),
        )
    }

    fn secure_log_stream_upsert(row: SecureLogStreamRow) -> Result<(), String> {
        call(m::SECURE_LOG_STREAM_UPSERT, &(stream_to_wire(row),))
    }

    fn secure_log_stream_get(name: String) -> Result<Option<SecureLogStreamRow>, String> {
        let s: Option<WireStream> = call(m::SECURE_LOG_STREAM_GET, &(name,))?;
        Ok(s.map(stream_from_wire))
    }

    fn secure_log_stream_list() -> Result<Vec<SecureLogStreamRow>, String> {
        let streams: Vec<WireStream> = call::<(), _>(m::SECURE_LOG_STREAM_LIST, &())?;
        Ok(streams.into_iter().map(stream_from_wire).collect())
    }

    fn secure_log_stream_set_tier(name: String, tier: String) -> Result<(), String> {
        call(m::SECURE_LOG_STREAM_SET_TIER, &(name, tier))
    }

    fn secure_log_stream_deprecate(
        name: String,
        deprecated_at_rfc3339: String,
    ) -> Result<(), String> {
        call(
            m::SECURE_LOG_STREAM_DEPRECATE,
            &(name, deprecated_at_rfc3339),
        )
    }
}

bindings::export!(Component with_types_in bindings);
