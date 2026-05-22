//! secure-log:store provider backed by the sqlite:wasm component.
//!
//! Implements the 23-method store contract over the imported SQLite
//! high-level API. Schema is identical to the native
//! `secure-log-sqlite` crate; migrations run once per database in a
//! private `_secure_log_migrations` table.
//!
//! Database location is set explicitly via `store.init(config)`,
//! which must be called once before any other method:
//!   - `":memory:"` opens an ephemeral in-memory database (tests).
//!   - any other non-empty value is treated as a file path.

#[allow(warnings)]
mod bindings;

use std::cell::RefCell;

use bindings::sqlite::wasm::high_level as sql;
use bindings::sqlite::wasm::high_level::{Connection, Value};

use bindings::exports::secure_log::log::store::{
    Guest, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, SegmentEntry, WitnessLogRow,
};

struct Component;

// ---------------------------------------------------------------------
// Connection singleton (wasip2 is single-threaded).
// ---------------------------------------------------------------------

thread_local! {
    static CONN: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

fn init_conn(config: &str) -> Result<(), String> {
    if config.is_empty() {
        return Err("sqlite store: init config is empty; pass a database path or \":memory:\"".into());
    }
    let conn = if config == ":memory:" {
        sql::open_memory().map_err(dberr)?
    } else {
        sql::open_file(config).map_err(dberr)?
    };
    migrate(&conn)?;
    CONN.with(|cell| *cell.borrow_mut() = Some(conn));
    Ok(())
}

fn with_conn<R>(f: impl FnOnce(&Connection) -> Result<R, String>) -> Result<R, String> {
    CONN.with(|cell| {
        let opt = cell.borrow();
        let conn = opt
            .as_ref()
            .ok_or_else(|| "sqlite store not initialized: call init first".to_string())?;
        f(conn)
    })
}

fn dberr(e: sql::DatabaseError) -> String {
    format!("sqlite error {} ({}): {}", e.code, e.extended_code, e.message)
}

fn exec(conn: &Connection, sql_text: &str, params: &[Value]) -> Result<sql::ExecResult, String> {
    conn.execute_with_params(sql_text, params).map_err(dberr)
}

fn query(conn: &Connection, sql_text: &str, params: &[Value]) -> Result<sql::QueryResult, String> {
    conn.query_with_params(sql_text, params).map_err(dberr)
}

// ---------------------------------------------------------------------
// Migrations (mirror secure-log-sqlite M1..M4).
// ---------------------------------------------------------------------

const MIGRATIONS: &[(i64, &str)] = &[
    (1, M1_SECURE_LOG),
    (2, M2_SEGMENTS),
    (3, M3_WITNESS_LOG),
    (4, M4_STREAMS),
];

const M1_SECURE_LOG: &str = "
CREATE TABLE secure_log (
    seqno             INTEGER PRIMARY KEY,
    stream_id         TEXT NOT NULL,
    session_id        TEXT NOT NULL,
    boot_id           TEXT NOT NULL,
    timestamp         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    severity          TEXT NOT NULL,
    producer          TEXT NOT NULL,
    payload_encoding  TEXT NOT NULL,
    payload           BLOB NOT NULL,
    prev_entry_hash   BLOB NOT NULL,
    entry_hash        BLOB NOT NULL
);
CREATE INDEX idx_secure_log_stream ON secure_log(stream_id, seqno);
CREATE INDEX idx_secure_log_type   ON secure_log(event_type);
";

const M2_SEGMENTS: &str = "
CREATE TABLE secure_log_segments (
    segment_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id            TEXT NOT NULL,
    seq_start            INTEGER NOT NULL,
    seq_end              INTEGER NOT NULL,
    merkle_root          BLOB NOT NULL,
    last_entry_hash      BLOB NOT NULL,
    prev_checkpoint_hash BLOB NOT NULL,
    closed_at            TEXT NOT NULL,
    signature            BLOB,
    signer_identity      TEXT
);
CREATE INDEX idx_secure_log_segments_stream
    ON secure_log_segments(stream_id, segment_id);
CREATE TABLE secure_log_segment_entries (
    segment_id   INTEGER NOT NULL REFERENCES secure_log_segments(segment_id),
    seqno        INTEGER NOT NULL,
    leaf_index   INTEGER NOT NULL,
    PRIMARY KEY (segment_id, seqno)
);
CREATE INDEX idx_secure_log_segment_entries_seqno
    ON secure_log_segment_entries(seqno);
";

const M3_WITNESS_LOG: &str = "
CREATE TABLE witness_log (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id            TEXT NOT NULL,
    segment_id           INTEGER NOT NULL,
    seq_start            INTEGER NOT NULL,
    seq_end              INTEGER NOT NULL,
    checkpoint_hash_hex  TEXT NOT NULL,
    signature_hex        TEXT NOT NULL,
    signer_identity      TEXT NOT NULL,
    received_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_witness_log_stream
    ON witness_log(stream_id, segment_id);
";

const M4_STREAMS: &str = "
CREATE TABLE secure_log_streams (
    name           TEXT PRIMARY KEY,
    tier           TEXT NOT NULL DEFAULT 'public',
    description    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    deprecated_at  TEXT
);
INSERT INTO secure_log_streams (name, tier, description)
VALUES ('default', 'public', 'Default stream created automatically at init.');
";

fn migrate(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _secure_log_migrations (
            version INTEGER PRIMARY KEY,
            applied TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .map_err(dberr)?;
    for (version, ddl) in MIGRATIONS {
        let qr = query(
            conn,
            "SELECT version FROM _secure_log_migrations WHERE version = ?1",
            &[Value::Integer(*version)],
        )?;
        if !qr.rows.is_empty() {
            continue;
        }
        // The high-level `execute` runs a single statement; our DDL
        // blocks contain several, so split on ';'.
        for stmt in ddl.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            conn.execute(trimmed).map_err(dberr)?;
        }
        exec(
            conn,
            "INSERT INTO _secure_log_migrations (version) VALUES (?1)",
            &[Value::Integer(*version)],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Value helpers.
// ---------------------------------------------------------------------

fn vi(n: u64) -> Value {
    Value::Integer(n as i64)
}
fn vt(s: &str) -> Value {
    Value::Text(s.to_string())
}
fn vb(b: &[u8]) -> Value {
    Value::Blob(b.to_vec())
}
fn v_opt_text(o: &Option<String>) -> Value {
    match o {
        Some(s) => Value::Text(s.clone()),
        None => Value::Null,
    }
}
fn v_opt_blob(o: &Option<Vec<u8>>) -> Value {
    match o {
        Some(b) => Value::Blob(b.clone()),
        None => Value::Null,
    }
}

fn as_u64(v: &Value) -> Result<u64, String> {
    match v {
        Value::Integer(i) => Ok(*i as u64),
        _ => Err("expected integer column".into()),
    }
}
fn as_opt_u64(v: &Value) -> Result<Option<u64>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Integer(i) => Ok(Some(*i as u64)),
        _ => Err("expected integer or null column".into()),
    }
}
fn as_i64(v: &Value) -> Result<i64, String> {
    match v {
        Value::Integer(i) => Ok(*i),
        _ => Err("expected integer column".into()),
    }
}
fn as_text(v: &Value) -> Result<String, String> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err("expected text column".into()),
    }
}
fn as_opt_text(v: &Value) -> Result<Option<String>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s.clone())),
        _ => Err("expected text or null column".into()),
    }
}
fn as_blob(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::Blob(b) => Ok(b.clone()),
        Value::Text(s) => Ok(s.clone().into_bytes()),
        _ => Err("expected blob column".into()),
    }
}
fn as_opt_blob(v: &Value) -> Result<Option<Vec<u8>>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Blob(b) => Ok(Some(b.clone())),
        _ => Err("expected blob or null column".into()),
    }
}

// ---------------------------------------------------------------------
// Row mappers (SELECT column order must match these).
// ---------------------------------------------------------------------

fn to_secure_log_row(cols: &[Value]) -> Result<SecureLogRow, String> {
    Ok(SecureLogRow {
        seqno: Some(as_u64(&cols[0])?),
        stream_id: as_text(&cols[1])?,
        session_id: as_text(&cols[2])?,
        boot_id: as_text(&cols[3])?,
        timestamp_rfc3339: as_text(&cols[4])?,
        event_type: as_text(&cols[5])?,
        severity: as_text(&cols[6])?,
        producer: as_text(&cols[7])?,
        payload_encoding: as_text(&cols[8])?,
        payload: as_blob(&cols[9])?,
        prev_entry_hash: as_blob(&cols[10])?,
        entry_hash: as_blob(&cols[11])?,
    })
}

const SECURE_LOG_COLS: &str =
    "seqno, stream_id, session_id, boot_id, timestamp, event_type, severity, \
     producer, payload_encoding, payload, prev_entry_hash, entry_hash";

fn to_segment_row(cols: &[Value]) -> Result<SecureLogSegmentRow, String> {
    Ok(SecureLogSegmentRow {
        segment_id: Some(as_u64(&cols[0])?),
        stream_id: as_text(&cols[1])?,
        seq_start: as_u64(&cols[2])?,
        seq_end: as_u64(&cols[3])?,
        merkle_root: as_blob(&cols[4])?,
        last_entry_hash: as_blob(&cols[5])?,
        prev_checkpoint_hash: as_blob(&cols[6])?,
        closed_at_rfc3339: as_text(&cols[7])?,
        signature: as_opt_blob(&cols[8])?,
        signer_identity: as_opt_text(&cols[9])?,
    })
}

const SEGMENT_COLS: &str =
    "segment_id, stream_id, seq_start, seq_end, merkle_root, last_entry_hash, \
     prev_checkpoint_hash, closed_at, signature, signer_identity";

fn to_stream_row(cols: &[Value]) -> Result<SecureLogStreamRow, String> {
    Ok(SecureLogStreamRow {
        name: as_text(&cols[0])?,
        tier: as_text(&cols[1])?,
        description: as_opt_text(&cols[2])?,
        created_at_rfc3339: as_text(&cols[3])?,
        deprecated_at_rfc3339: as_opt_text(&cols[4])?,
    })
}

const STREAM_COLS: &str = "name, tier, description, created_at, deprecated_at";

fn to_witness_row(cols: &[Value]) -> Result<WitnessLogRow, String> {
    Ok(WitnessLogRow {
        id: Some(as_i64(&cols[0])?),
        stream_id: as_text(&cols[1])?,
        segment_id: as_u64(&cols[2])?,
        seq_start: as_u64(&cols[3])?,
        seq_end: as_u64(&cols[4])?,
        checkpoint_hash_hex: as_text(&cols[5])?,
        signature_hex: as_text(&cols[6])?,
        signer_identity: as_text(&cols[7])?,
        received_at_rfc3339: as_text(&cols[8])?,
    })
}

const WITNESS_COLS: &str =
    "id, stream_id, segment_id, seq_start, seq_end, checkpoint_hash_hex, \
     signature_hex, signer_identity, received_at";

fn one_aggregate(qr: &sql::QueryResult) -> Result<Option<u64>, String> {
    match qr.rows.first() {
        Some(row) => as_opt_u64(&row.columns[0]),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------
// Store implementation.
// ---------------------------------------------------------------------

impl Guest for Component {
    fn init(config: String) -> Result<(), String> {
        init_conn(&config)
    }

    fn secure_log_insert(row: SecureLogRow) -> Result<u64, String> {
        let seqno = row
            .seqno
            .ok_or_else(|| "secure_log_insert requires row.seqno to be Some".to_string())?;
        with_conn(|conn| {
            exec(
                conn,
                "INSERT INTO secure_log (
                    seqno, stream_id, session_id, boot_id, timestamp,
                    event_type, severity, producer, payload_encoding,
                    payload, prev_entry_hash, entry_hash
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                &[
                    vi(seqno),
                    vt(&row.stream_id),
                    vt(&row.session_id),
                    vt(&row.boot_id),
                    vt(&row.timestamp_rfc3339),
                    vt(&row.event_type),
                    vt(&row.severity),
                    vt(&row.producer),
                    vt(&row.payload_encoding),
                    vb(&row.payload),
                    vb(&row.prev_entry_hash),
                    vb(&row.entry_hash),
                ],
            )?;
            Ok(seqno)
        })
    }

    fn secure_log_global_head() -> Result<Option<u64>, String> {
        with_conn(|conn| {
            let qr = query(conn, "SELECT MAX(seqno) FROM secure_log", &[])?;
            one_aggregate(&qr)
        })
    }

    fn secure_log_get(seqno: u64) -> Result<Option<SecureLogRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!("SELECT {SECURE_LOG_COLS} FROM secure_log WHERE seqno = ?1"),
                &[vi(seqno)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(to_secure_log_row(&r.columns)?)),
                None => Ok(None),
            }
        })
    }

    fn secure_log_range(
        stream_id: String,
        from_seqno: u64,
        to_seqno: u64,
    ) -> Result<Vec<SecureLogRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {SECURE_LOG_COLS} FROM secure_log
                     WHERE stream_id = ?1 AND seqno BETWEEN ?2 AND ?3 ORDER BY seqno"
                ),
                &[vt(&stream_id), vi(from_seqno), vi(to_seqno)],
            )?;
            qr.rows.iter().map(|r| to_secure_log_row(&r.columns)).collect()
        })
    }

    fn secure_log_head(stream_id: String) -> Result<Option<u64>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                "SELECT MAX(seqno) FROM secure_log WHERE stream_id = ?1",
                &[vt(&stream_id)],
            )?;
            one_aggregate(&qr)
        })
    }

    fn secure_log_last(stream_id: String) -> Result<Option<SecureLogRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {SECURE_LOG_COLS} FROM secure_log
                     WHERE stream_id = ?1 ORDER BY seqno DESC LIMIT 1"
                ),
                &[vt(&stream_id)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(to_secure_log_row(&r.columns)?)),
                None => Ok(None),
            }
        })
    }

    fn secure_log_segment_insert(
        row: SecureLogSegmentRow,
        entries: Vec<SegmentEntry>,
    ) -> Result<u64, String> {
        with_conn(|conn| {
            conn.begin_transaction().map_err(dberr)?;
            let res = (|| {
                let r = exec(
                    conn,
                    "INSERT INTO secure_log_segments (
                        stream_id, seq_start, seq_end, merkle_root,
                        last_entry_hash, prev_checkpoint_hash, closed_at,
                        signature, signer_identity
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    &[
                        vt(&row.stream_id),
                        vi(row.seq_start),
                        vi(row.seq_end),
                        vb(&row.merkle_root),
                        vb(&row.last_entry_hash),
                        vb(&row.prev_checkpoint_hash),
                        vt(&row.closed_at_rfc3339),
                        v_opt_blob(&row.signature),
                        v_opt_text(&row.signer_identity),
                    ],
                )?;
                let segment_id = r.last_insert_rowid as u64;
                for (seqno, leaf_index) in &entries {
                    exec(
                        conn,
                        "INSERT INTO secure_log_segment_entries (segment_id, seqno, leaf_index)
                         VALUES (?1,?2,?3)",
                        &[vi(segment_id), vi(*seqno), vi(*leaf_index)],
                    )?;
                }
                Ok::<u64, String>(segment_id)
            })();
            match res {
                Ok(id) => {
                    conn.commit().map_err(dberr)?;
                    Ok(id)
                }
                Err(e) => {
                    let _ = conn.rollback();
                    Err(e)
                }
            }
        })
    }

    fn secure_log_segment_get(segment_id: u64) -> Result<Option<SecureLogSegmentRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {SEGMENT_COLS} FROM secure_log_segments WHERE segment_id = ?1"
                ),
                &[vi(segment_id)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(to_segment_row(&r.columns)?)),
                None => Ok(None),
            }
        })
    }

    fn secure_log_segments_list(stream_id: String) -> Result<Vec<SecureLogSegmentRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {SEGMENT_COLS} FROM secure_log_segments
                     WHERE stream_id = ?1 ORDER BY segment_id"
                ),
                &[vt(&stream_id)],
            )?;
            qr.rows.iter().map(|r| to_segment_row(&r.columns)).collect()
        })
    }

    fn secure_log_segment_last_seqno(stream_id: String) -> Result<Option<u64>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                "SELECT MAX(seq_end) FROM secure_log_segments WHERE stream_id = ?1",
                &[vt(&stream_id)],
            )?;
            one_aggregate(&qr)
        })
    }

    fn secure_log_segment_entry_seqnos(segment_id: u64) -> Result<Vec<u64>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                "SELECT seqno FROM secure_log_segment_entries
                 WHERE segment_id = ?1 ORDER BY leaf_index",
                &[vi(segment_id)],
            )?;
            qr.rows.iter().map(|r| as_u64(&r.columns[0])).collect()
        })
    }

    fn secure_log_segment_for_seqno(seqno: u64) -> Result<Option<u64>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                "SELECT segment_id FROM secure_log_segment_entries WHERE seqno = ?1",
                &[vi(seqno)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(as_u64(&r.columns[0])?)),
                None => Ok(None),
            }
        })
    }

    fn secure_log_segment_set_signature(
        segment_id: u64,
        signature: Vec<u8>,
        signer_identity: String,
    ) -> Result<(), String> {
        with_conn(|conn| {
            let r = exec(
                conn,
                "UPDATE secure_log_segments
                 SET signature = ?2, signer_identity = ?3 WHERE segment_id = ?1",
                &[vi(segment_id), vb(&signature), vt(&signer_identity)],
            )?;
            if r.changes == 0 {
                return Err(format!("segment not found: {}", segment_id));
            }
            Ok(())
        })
    }

    fn witness_log_insert(row: WitnessLogRow) -> Result<u64, String> {
        with_conn(|conn| {
            let r = exec(
                conn,
                "INSERT INTO witness_log (
                    stream_id, segment_id, seq_start, seq_end,
                    checkpoint_hash_hex, signature_hex, signer_identity, received_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                &[
                    vt(&row.stream_id),
                    vi(row.segment_id),
                    vi(row.seq_start),
                    vi(row.seq_end),
                    vt(&row.checkpoint_hash_hex),
                    vt(&row.signature_hex),
                    vt(&row.signer_identity),
                    vt(&row.received_at_rfc3339),
                ],
            )?;
            Ok(r.last_insert_rowid as u64)
        })
    }

    fn witness_log_latest(stream_id: String) -> Result<Option<WitnessLogRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {WITNESS_COLS} FROM witness_log
                     WHERE stream_id = ?1 ORDER BY id DESC LIMIT 1"
                ),
                &[vt(&stream_id)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(to_witness_row(&r.columns)?)),
                None => Ok(None),
            }
        })
    }

    fn witness_log_list(stream_id: String) -> Result<Vec<WitnessLogRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {WITNESS_COLS} FROM witness_log
                     WHERE stream_id = ?1 ORDER BY id ASC"
                ),
                &[vt(&stream_id)],
            )?;
            qr.rows.iter().map(|r| to_witness_row(&r.columns)).collect()
        })
    }

    fn witness_log_stream_ids() -> Result<Vec<String>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                "SELECT DISTINCT stream_id FROM witness_log ORDER BY stream_id",
                &[],
            )?;
            qr.rows.iter().map(|r| as_text(&r.columns[0])).collect()
        })
    }

    fn witness_log_gc(
        stream_id: Option<String>,
        keep_latest: Option<u32>,
        older_than_rfc3339: Option<String>,
    ) -> Result<u32, String> {
        with_conn(|conn| {
            let streams: Vec<String> = if let Some(sid) = &stream_id {
                vec![sid.clone()]
            } else {
                let qr = query(conn, "SELECT DISTINCT stream_id FROM witness_log", &[])?;
                qr.rows
                    .iter()
                    .map(|r| as_text(&r.columns[0]))
                    .collect::<Result<_, _>>()?
            };

            let mut total: u32 = 0;
            for sid in &streams {
                let keep_ids: Vec<i64> = if let Some(k) = keep_latest {
                    let qr = query(
                        conn,
                        "SELECT id FROM witness_log WHERE stream_id = ?1 ORDER BY id DESC LIMIT ?2",
                        &[vt(sid), Value::Integer(k as i64)],
                    )?;
                    qr.rows
                        .iter()
                        .map(|r| as_i64(&r.columns[0]))
                        .collect::<Result<_, _>>()?
                } else {
                    Vec::new()
                };

                if keep_ids.is_empty() && older_than_rfc3339.is_none() {
                    continue;
                }

                let candidates: Vec<i64> = if let Some(cutoff) = &older_than_rfc3339 {
                    let qr = query(
                        conn,
                        "SELECT id FROM witness_log WHERE stream_id = ?1 AND received_at < ?2",
                        &[vt(sid), vt(cutoff)],
                    )?;
                    qr.rows
                        .iter()
                        .map(|r| as_i64(&r.columns[0]))
                        .collect::<Result<_, _>>()?
                } else {
                    let qr = query(
                        conn,
                        "SELECT id FROM witness_log WHERE stream_id = ?1",
                        &[vt(sid)],
                    )?;
                    qr.rows
                        .iter()
                        .map(|r| as_i64(&r.columns[0]))
                        .collect::<Result<_, _>>()?
                };

                for id in candidates {
                    if keep_ids.contains(&id) {
                        continue;
                    }
                    exec(conn, "DELETE FROM witness_log WHERE id = ?1", &[Value::Integer(id)])?;
                    total += 1;
                }
            }
            Ok(total)
        })
    }

    fn secure_log_stream_upsert(row: SecureLogStreamRow) -> Result<(), String> {
        with_conn(|conn| {
            exec(
                conn,
                "INSERT INTO secure_log_streams (name, tier, description, created_at, deprecated_at)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(name) DO UPDATE SET
                    tier = excluded.tier,
                    description = excluded.description,
                    deprecated_at = excluded.deprecated_at",
                &[
                    vt(&row.name),
                    vt(&row.tier),
                    v_opt_text(&row.description),
                    vt(&row.created_at_rfc3339),
                    v_opt_text(&row.deprecated_at_rfc3339),
                ],
            )?;
            Ok(())
        })
    }

    fn secure_log_stream_get(name: String) -> Result<Option<SecureLogStreamRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!(
                    "SELECT {STREAM_COLS} FROM secure_log_streams WHERE name = ?1"
                ),
                &[vt(&name)],
            )?;
            match qr.rows.first() {
                Some(r) => Ok(Some(to_stream_row(&r.columns)?)),
                None => Ok(None),
            }
        })
    }

    fn secure_log_stream_list() -> Result<Vec<SecureLogStreamRow>, String> {
        with_conn(|conn| {
            let qr = query(
                conn,
                &format!("SELECT {STREAM_COLS} FROM secure_log_streams ORDER BY name"),
                &[],
            )?;
            qr.rows.iter().map(|r| to_stream_row(&r.columns)).collect()
        })
    }

    fn secure_log_stream_set_tier(name: String, tier: String) -> Result<(), String> {
        with_conn(|conn| {
            let r = exec(
                conn,
                "UPDATE secure_log_streams SET tier = ?2 WHERE name = ?1",
                &[vt(&name), vt(&tier)],
            )?;
            if r.changes == 0 {
                return Err(format!("stream not found: {}", name));
            }
            Ok(())
        })
    }

    fn secure_log_stream_deprecate(
        name: String,
        deprecated_at_rfc3339: String,
    ) -> Result<(), String> {
        with_conn(|conn| {
            let r = exec(
                conn,
                "UPDATE secure_log_streams SET deprecated_at = ?2 WHERE name = ?1",
                &[vt(&name), vt(&deprecated_at_rfc3339)],
            )?;
            if r.changes == 0 {
                return Err(format!("stream not found: {}", name));
            }
            Ok(())
        })
    }
}

bindings::export!(Component with_types_in bindings);
