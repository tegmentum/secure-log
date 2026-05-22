//! secure-log:store provider backed by an append-only file.
//!
//! Each mutation is appended to a JSON-lines file on the WASI
//! filesystem; the queryable state is rebuilt in memory when the
//! component instance first touches the store. Reads are served from
//! memory. The append-only structure means the file is itself a
//! tamper-evident operation log (on top of the secure-log hash
//! chain that the core component layers over it).
//!
//! File path is set explicitly via `store.init(config)`, which must
//! be called once before any other method.

#[allow(warnings)]
mod bindings;

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;

use serde::{Deserialize, Serialize};

use bindings::exports::secure_log::log::store::{
    Guest, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, SegmentEntry, WitnessLogRow,
};

struct Component;

// ---------------------------------------------------------------------
// Serializable mirrors of the store records (the bindgen types don't
// derive serde, so we keep our own and convert).
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct FRow {
    seqno: u64,
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

#[derive(Serialize, Deserialize, Clone)]
struct FSegment {
    segment_id: u64,
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

#[derive(Serialize, Deserialize, Clone)]
struct FStream {
    name: String,
    tier: String,
    description: Option<String>,
    created_at_rfc3339: String,
    deprecated_at_rfc3339: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FWitness {
    id: i64,
    stream_id: String,
    segment_id: u64,
    seq_start: u64,
    seq_end: u64,
    checkpoint_hash_hex: String,
    signature_hex: String,
    signer_identity: String,
    received_at_rfc3339: String,
}

/// One appended operation. The file is a sequence of these, one JSON
/// object per line.
#[derive(Serialize, Deserialize)]
enum Op {
    InsertEntry(FRow),
    InsertSegment {
        segment: FSegment,
        entries: Vec<(u64, u64)>,
    },
    SetSegmentSignature {
        segment_id: u64,
        signature: Vec<u8>,
        signer_identity: String,
    },
    InsertWitness(FWitness),
    DeleteWitness(i64),
    StreamUpsert(FStream),
    StreamSetTier {
        name: String,
        tier: String,
    },
    StreamDeprecate {
        name: String,
        deprecated_at_rfc3339: String,
    },
}

// ---------------------------------------------------------------------
// In-memory model.
// ---------------------------------------------------------------------

#[derive(Default)]
struct Model {
    path: String,
    entries: Vec<FRow>,
    segments: Vec<FSegment>,
    segment_entries: Vec<(u64, u64, u64)>, // (segment_id, seqno, leaf_index)
    witnesses: Vec<FWitness>,
    streams: Vec<FStream>,
    next_segment_id: u64,
    next_witness_id: i64,
}

impl Model {
    fn apply(&mut self, op: &Op) {
        match op {
            Op::InsertEntry(r) => self.entries.push(r.clone()),
            Op::InsertSegment { segment, entries } => {
                self.next_segment_id = self.next_segment_id.max(segment.segment_id + 1);
                for (seqno, leaf) in entries {
                    self.segment_entries.push((segment.segment_id, *seqno, *leaf));
                }
                self.segments.push(segment.clone());
            }
            Op::SetSegmentSignature {
                segment_id,
                signature,
                signer_identity,
            } => {
                if let Some(s) = self.segments.iter_mut().find(|s| s.segment_id == *segment_id) {
                    s.signature = Some(signature.clone());
                    s.signer_identity = Some(signer_identity.clone());
                }
            }
            Op::InsertWitness(w) => {
                self.next_witness_id = self.next_witness_id.max(w.id + 1);
                self.witnesses.push(w.clone());
            }
            Op::DeleteWitness(id) => self.witnesses.retain(|w| w.id != *id),
            Op::StreamUpsert(s) => {
                if let Some(existing) = self.streams.iter_mut().find(|x| x.name == s.name) {
                    *existing = s.clone();
                } else {
                    self.streams.push(s.clone());
                }
            }
            Op::StreamSetTier { name, tier } => {
                if let Some(s) = self.streams.iter_mut().find(|x| x.name == *name) {
                    s.tier = tier.clone();
                }
            }
            Op::StreamDeprecate {
                name,
                deprecated_at_rfc3339,
            } => {
                if let Some(s) = self.streams.iter_mut().find(|x| x.name == *name) {
                    s.deprecated_at_rfc3339 = Some(deprecated_at_rfc3339.clone());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Singleton state (wasip2 is single-threaded).
// ---------------------------------------------------------------------

thread_local! {
    static STATE: RefCell<Option<Model>> = const { RefCell::new(None) };
}

fn init_store(config: &str) -> Result<(), String> {
    if config.is_empty() {
        return Err("file store: init config is empty; pass a log file path".into());
    }
    let mut model = Model {
        path: config.to_string(),
        ..Model::default()
    };
    match std::fs::read_to_string(config) {
        Ok(contents) => {
            for (i, line) in contents.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let op: Op = serde_json::from_str(line)
                    .map_err(|e| format!("corrupt log at line {}: {}", i + 1, e))?;
                model.apply(&op);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read {}: {}", config, e)),
    }
    // Seed the default stream to match the sqlite backend.
    if !model.streams.iter().any(|s| s.name == "default") {
        let seed = FStream {
            name: "default".into(),
            tier: "public".into(),
            description: Some("Default stream created automatically at init.".into()),
            created_at_rfc3339: String::new(),
            deprecated_at_rfc3339: None,
        };
        append_op(&model.path, &Op::StreamUpsert(seed.clone()))?;
        model.apply(&Op::StreamUpsert(seed));
    }
    STATE.with(|cell| *cell.borrow_mut() = Some(model));
    Ok(())
}

fn append_op(path: &str, op: &Op) -> Result<(), String> {
    let line = serde_json::to_string(op).map_err(|e| format!("serialize: {}", e))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    writeln!(f, "{}", line).map_err(|e| format!("append {}: {}", path, e))?;
    Ok(())
}

/// Run `f` against the in-memory model. Errors if `init` has not run.
fn with_model<R>(f: impl FnOnce(&mut Model) -> Result<R, String>) -> Result<R, String> {
    STATE.with(|cell| {
        let mut opt = cell.borrow_mut();
        let model = opt
            .as_mut()
            .ok_or_else(|| "file store not initialized: call init first".to_string())?;
        f(model)
    })
}

/// Append `op` to the file, then apply it to the in-memory model.
fn commit(model: &mut Model, op: Op) -> Result<(), String> {
    append_op(&model.path, &op)?;
    model.apply(&op);
    Ok(())
}

// ---------------------------------------------------------------------
// Conversions between bindgen records and serde mirrors.
// ---------------------------------------------------------------------

fn frow_to_w(r: &FRow) -> SecureLogRow {
    SecureLogRow {
        seqno: Some(r.seqno),
        stream_id: r.stream_id.clone(),
        session_id: r.session_id.clone(),
        boot_id: r.boot_id.clone(),
        timestamp_rfc3339: r.timestamp_rfc3339.clone(),
        event_type: r.event_type.clone(),
        severity: r.severity.clone(),
        producer: r.producer.clone(),
        payload_encoding: r.payload_encoding.clone(),
        payload: r.payload.clone(),
        prev_entry_hash: r.prev_entry_hash.clone(),
        entry_hash: r.entry_hash.clone(),
    }
}

fn fseg_to_w(s: &FSegment) -> SecureLogSegmentRow {
    SecureLogSegmentRow {
        segment_id: Some(s.segment_id),
        stream_id: s.stream_id.clone(),
        seq_start: s.seq_start,
        seq_end: s.seq_end,
        merkle_root: s.merkle_root.clone(),
        last_entry_hash: s.last_entry_hash.clone(),
        prev_checkpoint_hash: s.prev_checkpoint_hash.clone(),
        closed_at_rfc3339: s.closed_at_rfc3339.clone(),
        signature: s.signature.clone(),
        signer_identity: s.signer_identity.clone(),
    }
}

fn fstream_to_w(s: &FStream) -> SecureLogStreamRow {
    SecureLogStreamRow {
        name: s.name.clone(),
        tier: s.tier.clone(),
        description: s.description.clone(),
        created_at_rfc3339: s.created_at_rfc3339.clone(),
        deprecated_at_rfc3339: s.deprecated_at_rfc3339.clone(),
    }
}

fn fwitness_to_w(w: &FWitness) -> WitnessLogRow {
    WitnessLogRow {
        id: Some(w.id),
        stream_id: w.stream_id.clone(),
        segment_id: w.segment_id,
        seq_start: w.seq_start,
        seq_end: w.seq_end,
        checkpoint_hash_hex: w.checkpoint_hash_hex.clone(),
        signature_hex: w.signature_hex.clone(),
        signer_identity: w.signer_identity.clone(),
        received_at_rfc3339: w.received_at_rfc3339.clone(),
    }
}

// ---------------------------------------------------------------------
// Store implementation.
// ---------------------------------------------------------------------

impl Guest for Component {
    fn init(config: String) -> Result<(), String> {
        init_store(&config)
    }

    fn secure_log_insert(row: SecureLogRow) -> Result<u64, String> {
        let seqno = row
            .seqno
            .ok_or_else(|| "secure_log_insert requires row.seqno to be Some".to_string())?;
        with_model(|m| {
            if m.entries.iter().any(|r| r.seqno == seqno) {
                return Err(format!("UNIQUE constraint failed: secure_log.seqno ({})", seqno));
            }
            commit(
                m,
                Op::InsertEntry(FRow {
                    seqno,
                    stream_id: row.stream_id,
                    session_id: row.session_id,
                    boot_id: row.boot_id,
                    timestamp_rfc3339: row.timestamp_rfc3339,
                    event_type: row.event_type,
                    severity: row.severity,
                    producer: row.producer,
                    payload_encoding: row.payload_encoding,
                    payload: row.payload,
                    prev_entry_hash: row.prev_entry_hash,
                    entry_hash: row.entry_hash,
                }),
            )?;
            Ok(seqno)
        })
    }

    fn secure_log_global_head() -> Result<Option<u64>, String> {
        with_model(|m| Ok(m.entries.iter().map(|r| r.seqno).max()))
    }

    fn secure_log_get(seqno: u64) -> Result<Option<SecureLogRow>, String> {
        with_model(|m| Ok(m.entries.iter().find(|r| r.seqno == seqno).map(frow_to_w)))
    }

    fn secure_log_range(
        stream_id: String,
        from_seqno: u64,
        to_seqno: u64,
    ) -> Result<Vec<SecureLogRow>, String> {
        with_model(|m| {
            let mut rows: Vec<&FRow> = m
                .entries
                .iter()
                .filter(|r| r.stream_id == stream_id && r.seqno >= from_seqno && r.seqno <= to_seqno)
                .collect();
            rows.sort_by_key(|r| r.seqno);
            Ok(rows.into_iter().map(frow_to_w).collect())
        })
    }

    fn secure_log_head(stream_id: String) -> Result<Option<u64>, String> {
        with_model(|m| {
            Ok(m.entries
                .iter()
                .filter(|r| r.stream_id == stream_id)
                .map(|r| r.seqno)
                .max())
        })
    }

    fn secure_log_last(stream_id: String) -> Result<Option<SecureLogRow>, String> {
        with_model(|m| {
            Ok(m.entries
                .iter()
                .filter(|r| r.stream_id == stream_id)
                .max_by_key(|r| r.seqno)
                .map(frow_to_w))
        })
    }

    fn secure_log_segment_insert(
        row: SecureLogSegmentRow,
        entries: Vec<SegmentEntry>,
    ) -> Result<u64, String> {
        with_model(|m| {
            let segment_id = m.next_segment_id.max(1);
            let seg = FSegment {
                segment_id,
                stream_id: row.stream_id,
                seq_start: row.seq_start,
                seq_end: row.seq_end,
                merkle_root: row.merkle_root,
                last_entry_hash: row.last_entry_hash,
                prev_checkpoint_hash: row.prev_checkpoint_hash,
                closed_at_rfc3339: row.closed_at_rfc3339,
                signature: row.signature,
                signer_identity: row.signer_identity,
            };
            commit(
                m,
                Op::InsertSegment {
                    segment: seg,
                    entries: entries.clone(),
                },
            )?;
            Ok(segment_id)
        })
    }

    fn secure_log_segment_get(segment_id: u64) -> Result<Option<SecureLogSegmentRow>, String> {
        with_model(|m| {
            Ok(m.segments
                .iter()
                .find(|s| s.segment_id == segment_id)
                .map(fseg_to_w))
        })
    }

    fn secure_log_segments_list(stream_id: String) -> Result<Vec<SecureLogSegmentRow>, String> {
        with_model(|m| {
            let mut segs: Vec<&FSegment> =
                m.segments.iter().filter(|s| s.stream_id == stream_id).collect();
            segs.sort_by_key(|s| s.segment_id);
            Ok(segs.into_iter().map(fseg_to_w).collect())
        })
    }

    fn secure_log_segment_last_seqno(stream_id: String) -> Result<Option<u64>, String> {
        with_model(|m| {
            Ok(m.segments
                .iter()
                .filter(|s| s.stream_id == stream_id)
                .map(|s| s.seq_end)
                .max())
        })
    }

    fn secure_log_segment_entry_seqnos(segment_id: u64) -> Result<Vec<u64>, String> {
        with_model(|m| {
            let mut rows: Vec<&(u64, u64, u64)> =
                m.segment_entries.iter().filter(|(sid, _, _)| *sid == segment_id).collect();
            rows.sort_by_key(|(_, _, leaf)| *leaf);
            Ok(rows.into_iter().map(|(_, seqno, _)| *seqno).collect())
        })
    }

    fn secure_log_segment_for_seqno(seqno: u64) -> Result<Option<u64>, String> {
        with_model(|m| {
            Ok(m.segment_entries
                .iter()
                .find(|(_, s, _)| *s == seqno)
                .map(|(sid, _, _)| *sid))
        })
    }

    fn secure_log_segment_set_signature(
        segment_id: u64,
        signature: Vec<u8>,
        signer_identity: String,
    ) -> Result<(), String> {
        with_model(|m| {
            if !m.segments.iter().any(|s| s.segment_id == segment_id) {
                return Err(format!("segment not found: {}", segment_id));
            }
            commit(
                m,
                Op::SetSegmentSignature {
                    segment_id,
                    signature,
                    signer_identity,
                },
            )
        })
    }

    fn witness_log_insert(row: WitnessLogRow) -> Result<u64, String> {
        with_model(|m| {
            let id = m.next_witness_id.max(1);
            commit(
                m,
                Op::InsertWitness(FWitness {
                    id,
                    stream_id: row.stream_id,
                    segment_id: row.segment_id,
                    seq_start: row.seq_start,
                    seq_end: row.seq_end,
                    checkpoint_hash_hex: row.checkpoint_hash_hex,
                    signature_hex: row.signature_hex,
                    signer_identity: row.signer_identity,
                    received_at_rfc3339: row.received_at_rfc3339,
                }),
            )?;
            Ok(id as u64)
        })
    }

    fn witness_log_latest(stream_id: String) -> Result<Option<WitnessLogRow>, String> {
        with_model(|m| {
            Ok(m.witnesses
                .iter()
                .filter(|w| w.stream_id == stream_id)
                .max_by_key(|w| w.id)
                .map(fwitness_to_w))
        })
    }

    fn witness_log_list(stream_id: String) -> Result<Vec<WitnessLogRow>, String> {
        with_model(|m| {
            let mut ws: Vec<&FWitness> =
                m.witnesses.iter().filter(|w| w.stream_id == stream_id).collect();
            ws.sort_by_key(|w| w.id);
            Ok(ws.into_iter().map(fwitness_to_w).collect())
        })
    }

    fn witness_log_stream_ids() -> Result<Vec<String>, String> {
        with_model(|m| {
            let mut ids: Vec<String> =
                m.witnesses.iter().map(|w| w.stream_id.clone()).collect();
            ids.sort();
            ids.dedup();
            Ok(ids)
        })
    }

    fn witness_log_gc(
        stream_id: Option<String>,
        keep_latest: Option<u32>,
        older_than_rfc3339: Option<String>,
    ) -> Result<u32, String> {
        with_model(|m| {
            let streams: Vec<String> = match &stream_id {
                Some(s) => vec![s.clone()],
                None => {
                    let mut ids: Vec<String> =
                        m.witnesses.iter().map(|w| w.stream_id.clone()).collect();
                    ids.sort();
                    ids.dedup();
                    ids
                }
            };
            let mut to_delete: Vec<i64> = Vec::new();
            for sid in &streams {
                let mut ws: Vec<&FWitness> =
                    m.witnesses.iter().filter(|w| w.stream_id == *sid).collect();
                ws.sort_by_key(|w| w.id);
                let keep: HashSet<i64> = match keep_latest {
                    Some(k) => ws.iter().rev().take(k as usize).map(|w| w.id).collect(),
                    None => HashSet::new(),
                };
                if keep.is_empty() && older_than_rfc3339.is_none() {
                    continue;
                }
                for w in &ws {
                    if keep.contains(&w.id) {
                        continue;
                    }
                    if let Some(cutoff) = &older_than_rfc3339 {
                        if &w.received_at_rfc3339 >= cutoff {
                            continue;
                        }
                    }
                    to_delete.push(w.id);
                }
            }
            let mut deleted = 0u32;
            for id in to_delete {
                commit(m, Op::DeleteWitness(id))?;
                deleted += 1;
            }
            Ok(deleted)
        })
    }

    fn secure_log_stream_upsert(row: SecureLogStreamRow) -> Result<(), String> {
        with_model(|m| {
            commit(
                m,
                Op::StreamUpsert(FStream {
                    name: row.name,
                    tier: row.tier,
                    description: row.description,
                    created_at_rfc3339: row.created_at_rfc3339,
                    deprecated_at_rfc3339: row.deprecated_at_rfc3339,
                }),
            )
        })
    }

    fn secure_log_stream_get(name: String) -> Result<Option<SecureLogStreamRow>, String> {
        with_model(|m| Ok(m.streams.iter().find(|s| s.name == name).map(fstream_to_w)))
    }

    fn secure_log_stream_list() -> Result<Vec<SecureLogStreamRow>, String> {
        with_model(|m| {
            let mut streams: Vec<&FStream> = m.streams.iter().collect();
            streams.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(streams.into_iter().map(fstream_to_w).collect())
        })
    }

    fn secure_log_stream_set_tier(name: String, tier: String) -> Result<(), String> {
        with_model(|m| {
            if !m.streams.iter().any(|s| s.name == name) {
                return Err(format!("stream not found: {}", name));
            }
            commit(m, Op::StreamSetTier { name, tier })
        })
    }

    fn secure_log_stream_deprecate(
        name: String,
        deprecated_at_rfc3339: String,
    ) -> Result<(), String> {
        with_model(|m| {
            if !m.streams.iter().any(|s| s.name == name) {
                return Err(format!("stream not found: {}", name));
            }
            commit(
                m,
                Op::StreamDeprecate {
                    name,
                    deprecated_at_rfc3339,
                },
            )
        })
    }
}

bindings::export!(Component with_types_in bindings);
