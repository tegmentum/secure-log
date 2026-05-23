//! Wire-protocol dispatch: decode one JSON-RPC call and run it against
//! a [`SecureLogStore`].
//!
//! This is transport-agnostic — [`Server::dispatch`] takes a method
//! name and a JSON params value and returns the JSON result string (or
//! an error string). The HTTP loop in `main.rs` is just one caller;
//! the unit tests below call it directly.

use std::path::Path;
use std::sync::Mutex;

use secure_log::store::{
    SecureLogRow, SecureLogSegmentRow, SecureLogStore, SecureLogStreamRow, WitnessLogRow,
};
use secure_log_rpc::{method, WireRow, WireSegment, WireStream, WireWitness};
use secure_log_sqlite::SqliteSecureLogStore;
use serde::Serialize;
use serde_json::Value;

/// Server state: the backing store, opened lazily by the `init` call.
pub struct Server {
    store: Mutex<Option<Box<dyn SecureLogStore>>>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Server {
            store: Mutex::new(None),
        }
    }

    /// Decode and execute one call. `params` is the JSON value from the
    /// request envelope (a JSON array of arguments, or null for the
    /// no-arg methods). Returns the JSON-encoded result on success.
    pub fn dispatch(&self, method_name: &str, params: Value) -> Result<String, String> {
        // `init` manages the store slot itself; everything else runs
        // against an already-opened store.
        if method_name == method::INIT {
            let (config,): (String,) = decode(params)?;
            let store = open_store(&config)?;
            *self.store.lock().unwrap() = Some(store);
            return enc(&());
        }

        let guard = self.store.lock().unwrap();
        let store = guard
            .as_deref()
            .ok_or_else(|| "rpc server: store not initialized; call init first".to_string())?;
        run(store, method_name, params)
    }
}

/// Open a store for the given `init` config: `":memory:"` for an
/// ephemeral database, otherwise a file path.
fn open_store(config: &str) -> Result<Box<dyn SecureLogStore>, String> {
    if config.is_empty() {
        return Err("rpc server: init config is empty".into());
    }
    let store = if config == ":memory:" {
        SqliteSecureLogStore::open_in_memory()
    } else {
        SqliteSecureLogStore::open(Path::new(config))
    }
    .map_err(|e| e.to_string())?;
    Ok(Box::new(store))
}

/// Dispatch every method other than `init`. Kept as a free function so
/// the borrow of `store` is explicit.
fn run(store: &dyn SecureLogStore, method_name: &str, params: Value) -> Result<String, String> {
    use method as m;
    match method_name {
        // -- Phase 1: entries --
        m::SECURE_LOG_INSERT => {
            let (row,): (WireRow,) = decode(params)?;
            enc(&se(store.secure_log_insert(&row_in(row)))?)
        }
        m::SECURE_LOG_GLOBAL_HEAD => enc(&se(store.secure_log_global_head())?),
        m::SECURE_LOG_GET => {
            let (seqno,): (u64,) = decode(params)?;
            enc(&se(store.secure_log_get(seqno))?.map(row_out))
        }
        m::SECURE_LOG_RANGE => {
            let (stream_id, from, to): (String, u64, u64) = decode(params)?;
            let rows = se(store.secure_log_range(&stream_id, from, to))?;
            enc(&rows.into_iter().map(row_out).collect::<Vec<_>>())
        }
        m::SECURE_LOG_HEAD => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&se(store.secure_log_head(&stream_id))?)
        }
        m::SECURE_LOG_LAST => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&se(store.secure_log_last(&stream_id))?.map(row_out))
        }

        // -- Phase 2: segments --
        m::SECURE_LOG_SEGMENT_INSERT => {
            let (seg, entries): (WireSegment, Vec<(u64, u64)>) = decode(params)?;
            enc(&se(store.secure_log_segment_insert(&seg_in(seg), &entries))?)
        }
        m::SECURE_LOG_SEGMENT_GET => {
            let (segment_id,): (u64,) = decode(params)?;
            enc(&se(store.secure_log_segment_get(segment_id))?.map(seg_out))
        }
        m::SECURE_LOG_SEGMENTS_LIST => {
            let (stream_id,): (String,) = decode(params)?;
            let segs = se(store.secure_log_segments_list(&stream_id))?;
            enc(&segs.into_iter().map(seg_out).collect::<Vec<_>>())
        }
        m::SECURE_LOG_SEGMENT_LAST_SEQNO => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&se(store.secure_log_segment_last_seqno(&stream_id))?)
        }
        m::SECURE_LOG_SEGMENT_ENTRY_SEQNOS => {
            let (segment_id,): (u64,) = decode(params)?;
            enc(&se(store.secure_log_segment_entry_seqnos(segment_id))?)
        }
        m::SECURE_LOG_SEGMENT_FOR_SEQNO => {
            let (seqno,): (u64,) = decode(params)?;
            enc(&se(store.secure_log_segment_for_seqno(seqno))?)
        }
        m::SECURE_LOG_SEGMENT_SET_SIGNATURE => {
            let (segment_id, signature, signer_identity): (u64, Vec<u8>, String) = decode(params)?;
            enc(&se(store.secure_log_segment_set_signature(
                segment_id,
                &signature,
                &signer_identity,
            ))?)
        }

        // -- Phase 4: witness log --
        m::WITNESS_LOG_INSERT => {
            let (w,): (WireWitness,) = decode(params)?;
            enc(&se(store.witness_log_insert(&witness_in(w)))?)
        }
        m::WITNESS_LOG_LATEST => {
            let (stream_id,): (String,) = decode(params)?;
            enc(&se(store.witness_log_latest(&stream_id))?.map(witness_out))
        }
        m::WITNESS_LOG_LIST => {
            let (stream_id,): (String,) = decode(params)?;
            let ws = se(store.witness_log_list(&stream_id))?;
            enc(&ws.into_iter().map(witness_out).collect::<Vec<_>>())
        }
        m::WITNESS_LOG_STREAM_IDS => enc(&se(store.witness_log_stream_ids())?),
        m::WITNESS_LOG_GC => {
            let (stream_id, keep_latest, older_than): (Option<String>, Option<u32>, Option<String>) =
                decode(params)?;
            let n = se(store.witness_log_gc(
                stream_id.as_deref(),
                keep_latest.map(|k| k as usize),
                older_than.as_deref(),
            ))?;
            enc(&(n as u32))
        }

        // -- Stream metadata --
        m::SECURE_LOG_STREAM_UPSERT => {
            let (s,): (WireStream,) = decode(params)?;
            enc(&se(store.secure_log_stream_upsert(&stream_in(s)))?)
        }
        m::SECURE_LOG_STREAM_GET => {
            let (name,): (String,) = decode(params)?;
            enc(&se(store.secure_log_stream_get(&name))?.map(stream_out))
        }
        m::SECURE_LOG_STREAM_LIST => {
            let streams = se(store.secure_log_stream_list())?;
            enc(&streams.into_iter().map(stream_out).collect::<Vec<_>>())
        }
        m::SECURE_LOG_STREAM_SET_TIER => {
            let (name, tier): (String, String) = decode(params)?;
            enc(&se(store.secure_log_stream_set_tier(&name, &tier))?)
        }
        m::SECURE_LOG_STREAM_DEPRECATE => {
            let (name, deprecated_at): (String, String) = decode(params)?;
            enc(&se(store.secure_log_stream_deprecate(&name, &deprecated_at))?)
        }

        other => Err(format!("rpc server: unknown method {:?}", other)),
    }
}

// ---------------------------------------------------------------------
// JSON helpers.
// ---------------------------------------------------------------------

/// Decode a params array into a typed tuple. A JSON `null` (sent by the
/// no-arg helpers) decodes to `()` cleanly.
fn decode<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|e| format!("decode params: {}", e))
}

/// Encode a successful return value to its JSON string.
fn enc<T: Serialize>(v: &T) -> Result<String, String> {
    serde_json::to_string(v).map_err(|e| format!("encode result: {}", e))
}

/// Map a storage-layer `anyhow::Result` into the wire error string.
fn se<T>(r: anyhow::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Wire <-> core row conversions.
// ---------------------------------------------------------------------

fn row_in(r: WireRow) -> SecureLogRow {
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

fn row_out(r: SecureLogRow) -> WireRow {
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

fn seg_in(s: WireSegment) -> SecureLogSegmentRow {
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

fn seg_out(s: SecureLogSegmentRow) -> WireSegment {
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

fn stream_in(s: WireStream) -> SecureLogStreamRow {
    SecureLogStreamRow {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn stream_out(s: SecureLogStreamRow) -> WireStream {
    WireStream {
        name: s.name,
        tier: s.tier,
        description: s.description,
        created_at_rfc3339: s.created_at_rfc3339,
        deprecated_at_rfc3339: s.deprecated_at_rfc3339,
    }
}

fn witness_in(w: WireWitness) -> WitnessLogRow {
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

fn witness_out(w: WitnessLogRow) -> WireWitness {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server() -> Server {
        let s = Server::new();
        s.dispatch(method::INIT, json!([":memory:"])).unwrap();
        s
    }

    #[test]
    fn requires_init_first() {
        let s = Server::new();
        let err = s
            .dispatch(method::SECURE_LOG_GLOBAL_HEAD, Value::Null)
            .unwrap_err();
        assert!(err.contains("not initialized"), "{err}");
    }

    #[test]
    fn init_seeds_default_stream() {
        let s = server();
        // M4 seeds a "default" stream.
        let got = s
            .dispatch(method::SECURE_LOG_STREAM_GET, json!(["default"]))
            .unwrap();
        let parsed: Option<WireStream> = serde_json::from_str(&got).unwrap();
        assert_eq!(parsed.unwrap().tier, "public");
    }

    #[test]
    fn insert_then_read_round_trips() {
        let s = server();
        let row = WireRow {
            seqno: Some(1),
            stream_id: "default".into(),
            session_id: "sess".into(),
            boot_id: "boot".into(),
            timestamp_rfc3339: "2026-05-21T00:00:00Z".into(),
            event_type: "ev".into(),
            severity: "info".into(),
            producer: "p".into(),
            payload_encoding: "cbor".into(),
            payload: vec![1, 2, 3],
            prev_entry_hash: vec![0u8; 32],
            entry_hash: vec![9u8; 32],
        };
        let inserted = s
            .dispatch(method::SECURE_LOG_INSERT, json!([row]))
            .unwrap();
        assert_eq!(inserted, "1");

        let head = s
            .dispatch(method::SECURE_LOG_GLOBAL_HEAD, Value::Null)
            .unwrap();
        assert_eq!(head, "1");

        let got = s.dispatch(method::SECURE_LOG_GET, json!([1])).unwrap();
        let back: Option<WireRow> = serde_json::from_str(&got).unwrap();
        let back = back.unwrap();
        assert_eq!(back.payload, vec![1, 2, 3]);
        assert_eq!(back.entry_hash, vec![9u8; 32]);
    }

    #[test]
    fn unknown_method_is_rejected() {
        let s = server();
        let err = s.dispatch("bogus-method", Value::Null).unwrap_err();
        assert!(err.contains("unknown method"), "{err}");
    }
}
