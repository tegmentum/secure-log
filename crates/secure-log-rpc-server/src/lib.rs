//! Remote-store endpoint as a `wasi:http` guest component.
//!
//! The `secure-log-store-remote` provider forwards each store operation
//! as a JSON-RPC POST; this component is the peer that terminates that
//! wire protocol and runs each call against the *imported*
//! `secure-log:log/store`. Compose it with a store provider (e.g.
//! store-sqlite) and run it with `wasmtime serve`.
//!
//! `wasi:http` handlers are request-scoped — a fresh instance per
//! request — so the store cannot hold state in memory across calls. It
//! is opened (idempotently) at the start of each request from a
//! *server-side* config (`SECURE_LOG_STORE_CONFIG`, default
//! `secure-log.db`), and must therefore be file-backed so state lives on
//! the filesystem. The client's `init` config is a handshake only; the
//! server owns its storage location.

wit_bindgen::generate!({
    path: "wit",
    world: "server",
    generate_all,
});

use exports::wasi::http::incoming_handler::Guest;
use secure_log::log::store as wstore;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
use wasi::io::streams::StreamError;

use secure_log_rpc::{method as m, Request, WireRow, WireSegment, WireStream, WireWitness};
use serde_json::Value;

struct Component;

const STORE_CONFIG_ENV: &str = "SECURE_LOG_STORE_CONFIG";
const DEFAULT_STORE_CONFIG: &str = "secure-log.db";
const WRITE_CHUNK: usize = 4096;

thread_local! {
    static INITED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Open the backing store once per instance, from the server-side config.
fn ensure_store() -> Result<(), String> {
    if INITED.with(|c| c.get()) {
        return Ok(());
    }
    let config = std::env::var(STORE_CONFIG_ENV).unwrap_or_else(|_| DEFAULT_STORE_CONFIG.into());
    wstore::init(&config)?;
    INITED.with(|c| c.set(true));
    Ok(())
}

impl Guest for Component {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        let (status, body) = match run(request) {
            Ok(body) => (200u16, body),
            Err((code, msg)) => (code, msg.into_bytes()),
        };
        respond(response_out, status, &body);
    }
}

/// Read the request, dispatch it, and return the response body — or a
/// `(status, message)` on failure.
fn run(request: IncomingRequest) -> Result<Vec<u8>, (u16, String)> {
    let body = read_request_body(&request).map_err(|e| (400u16, e))?;
    let req: Request = serde_json::from_slice(&body)
        .map_err(|e| (400u16, format!("malformed request envelope: {e}")))?;
    dispatch(&req.method, req.params)
        .map(String::into_bytes)
        .map_err(|e| (500u16, e))
}

/// Execute one JSON-RPC call against the imported store.
fn dispatch(method: &str, params: Value) -> Result<String, String> {
    ensure_store()?;
    use m as k;
    match method {
        // `init` is a handshake: the store is already opened server-side.
        k::INIT => enc(&()),

        // Phase 1: entries
        k::SECURE_LOG_INSERT => {
            let (row,): (WireRow,) = decode(params)?;
            enc(&wstore::secure_log_insert(&to_store_row(row))?)
        }
        k::SECURE_LOG_GLOBAL_HEAD => enc(&wstore::secure_log_global_head()?),
        k::SECURE_LOG_GET => {
            let (seqno,): (u64,) = decode(params)?;
            enc(&wstore::secure_log_get(seqno)?.map(to_wire_row))
        }
        k::SECURE_LOG_RANGE => {
            let (stream_id, from, to): (String, u64, u64) = decode(params)?;
            let rows = wstore::secure_log_range(&stream_id, from, to)?;
            enc(&rows.into_iter().map(to_wire_row).collect::<Vec<_>>())
        }
        k::SECURE_LOG_HEAD => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&wstore::secure_log_head(&stream_id)?)
        }
        k::SECURE_LOG_LAST => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&wstore::secure_log_last(&stream_id)?.map(to_wire_row))
        }

        // Phase 2: segments
        k::SECURE_LOG_SEGMENT_INSERT => {
            let (seg, entries): (WireSegment, Vec<(u64, u64)>) = decode(params)?;
            enc(&wstore::secure_log_segment_insert(&to_store_seg(seg), &entries)?)
        }
        k::SECURE_LOG_SEGMENT_GET => {
            let (segment_id,): (u64,) = decode(params)?;
            enc(&wstore::secure_log_segment_get(segment_id)?.map(to_wire_seg))
        }
        k::SECURE_LOG_SEGMENTS_LIST => {
            let (stream_id,): (String,) = decode(params)?;
            let segs = wstore::secure_log_segments_list(&stream_id)?;
            enc(&segs.into_iter().map(to_wire_seg).collect::<Vec<_>>())
        }
        k::SECURE_LOG_SEGMENT_LAST_SEQNO => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&wstore::secure_log_segment_last_seqno(&stream_id)?)
        }
        k::SECURE_LOG_SEGMENT_ENTRY_SEQNOS => {
            let (segment_id,): (u64,) = decode(params)?;
            enc(&wstore::secure_log_segment_entry_seqnos(segment_id)?)
        }
        k::SECURE_LOG_SEGMENT_FOR_SEQNO => {
            let (seqno,): (u64,) = decode(params)?;
            enc(&wstore::secure_log_segment_for_seqno(seqno)?)
        }
        k::SECURE_LOG_SEGMENT_SET_SIGNATURE => {
            let (segment_id, signature, signer_identity): (u64, Vec<u8>, String) = decode(params)?;
            enc(&wstore::secure_log_segment_set_signature(
                segment_id,
                &signature,
                &signer_identity,
            )?)
        }

        // Phase 4: witness log
        k::WITNESS_LOG_INSERT => {
            let (w,): (WireWitness,) = decode(params)?;
            enc(&wstore::witness_log_insert(&to_store_witness(w))?)
        }
        k::WITNESS_LOG_LATEST => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&wstore::witness_log_latest(&stream_id)?.map(to_wire_witness))
        }
        k::WITNESS_LOG_LIST => {
            let (stream_id,): (String,) = decode(params)?;
            let ws = wstore::witness_log_list(&stream_id)?;
            enc(&ws.into_iter().map(to_wire_witness).collect::<Vec<_>>())
        }
        k::WITNESS_LOG_STREAM_IDS => enc(&wstore::witness_log_stream_ids()?),
        k::WITNESS_LOG_GC => {
            let (stream_id, keep_latest, older_than): (Option<String>, Option<u32>, Option<String>) =
                decode(params)?;
            enc(&wstore::witness_log_gc(
                stream_id.as_deref(),
                keep_latest,
                older_than.as_deref(),
            )?)
        }

        // Stream metadata
        k::SECURE_LOG_STREAM_UPSERT => {
            let (s,): (WireStream,) = decode(params)?;
            enc(&wstore::secure_log_stream_upsert(&to_store_stream(s))?)
        }
        k::SECURE_LOG_STREAM_GET => {
            let (name,): (String,) = decode(params)?;
            enc(&wstore::secure_log_stream_get(&name)?.map(to_wire_stream))
        }
        k::SECURE_LOG_STREAM_LIST => {
            let streams = wstore::secure_log_stream_list()?;
            enc(&streams.into_iter().map(to_wire_stream).collect::<Vec<_>>())
        }
        k::SECURE_LOG_STREAM_SET_TIER => {
            let (name, tier): (String, String) = decode(params)?;
            enc(&wstore::secure_log_stream_set_tier(&name, &tier)?)
        }
        k::SECURE_LOG_STREAM_DEPRECATE => {
            let (name, deprecated_at): (String, String) = decode(params)?;
            enc(&wstore::secure_log_stream_deprecate(&name, &deprecated_at)?)
        }

        other => Err(format!("unknown method {other:?}")),
    }
}

// ---------------------------------------------------------------------
// JSON helpers.
// ---------------------------------------------------------------------

fn decode<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|e| format!("decode params: {e}"))
}

fn enc<T: serde::Serialize>(v: &T) -> Result<String, String> {
    serde_json::to_string(v).map_err(|e| format!("encode result: {e}"))
}

// ---------------------------------------------------------------------
// Wire (serde) <-> store (bindgen) row conversions.
// ---------------------------------------------------------------------

fn to_store_row(r: WireRow) -> wstore::SecureLogRow {
    wstore::SecureLogRow {
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

fn to_wire_row(r: wstore::SecureLogRow) -> WireRow {
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

fn to_store_seg(s: WireSegment) -> wstore::SecureLogSegmentRow {
    wstore::SecureLogSegmentRow {
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

fn to_wire_seg(s: wstore::SecureLogSegmentRow) -> WireSegment {
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

fn to_store_stream(s: WireStream) -> wstore::SecureLogStreamRow {
    wstore::SecureLogStreamRow {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn to_wire_stream(s: wstore::SecureLogStreamRow) -> WireStream {
    WireStream {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn to_store_witness(w: WireWitness) -> wstore::WitnessLogRow {
    wstore::WitnessLogRow {
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

fn to_wire_witness(w: wstore::WitnessLogRow) -> WireWitness {
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

// ---------------------------------------------------------------------
// wasi:http request/response plumbing.
// ---------------------------------------------------------------------

/// Read the full incoming request body.
fn read_request_body(request: &IncomingRequest) -> Result<Vec<u8>, String> {
    let incoming = request
        .consume()
        .map_err(|_| "consume request body failed".to_string())?;
    let stream = incoming
        .stream()
        .map_err(|_| "request body stream failed".to_string())?;
    let mut buf = Vec::new();
    loop {
        match stream.blocking_read(WRITE_CHUNK as u64) {
            Ok(chunk) => buf.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => return Err(format!("read request body: {e:?}")),
        }
    }
    Ok(buf)
}

/// Send the response: status + body.
fn respond(response_out: ResponseOutparam, status: u16, body: &[u8]) {
    let headers = Fields::new();
    let response = OutgoingResponse::new(headers);
    let _ = response.set_status_code(status);
    let out_body = response.body().expect("outgoing-response body");

    ResponseOutparam::set(response_out, Ok(response));

    {
        let stream = out_body.write().expect("outgoing-body stream");
        for chunk in body.chunks(WRITE_CHUNK) {
            // Best-effort: if the peer hangs up mid-write, drop the rest.
            if stream.blocking_write_and_flush(chunk).is_err() {
                break;
            }
        }
    }
    let _ = OutgoingBody::finish(out_body, None);
}

export!(Component);
