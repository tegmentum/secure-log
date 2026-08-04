//! SQLite-backed storage for the [`secure_log`] crate.
//!
//! [`SqliteSecureLogStore`] owns a [`sqlite_component_core::db::Connection`]
//! (wrapped in a [`Mutex`] because the raw handle is `Send + !Sync`) and
//! implements the [`SecureLogStore`] trait by translating each method
//! into the appropriate SQL.
//!
//! ## Schema
//!
//! The store manages its own schema in a private
//! `_secure_log_migrations` table, so it can coexist with other
//! schema-management code on the same database file. Migrations are
//! idempotent: calling [`open`](SqliteSecureLogStore::open) on an
//! up-to-date database is a no-op.
//!
//! Migrations as of v0.1.0:
//!
//! - **M1** `secure_log` — entries, hash-chained per stream.
//! - **M2** `secure_log_segments` + `secure_log_segment_entries` —
//!   Merkle-sealed segments and their leaf-index records.
//! - **M3** `witness_log` — externally-witnessed checkpoint receipts.
//! - **M4** `secure_log_streams` — per-stream metadata (tier,
//!   description, soft-delete).
//!
//! ## Substrate
//!
//! Built on sqlink's [`sqlite-component-core`] rather than `rusqlite`
//! so this crate can be linked alongside sqlink-derived SQLite code
//! (e.g. wasmos-chronos) in the same binary without tripping Cargo's
//! `links = "sqlite3"` uniqueness rule. Both crates share a single
//! `libsqlite3-sys 0.38` pin via sqlink.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use sqlite_component_core::db::{
    Connection, Error as SqliteError, OpenFlags, Statement, StepResult, Value as SqliteValue,
};

use secure_log::store::{
    SecureLogRow, SecureLogSegmentRow, SecureLogStore, SecureLogStreamRow, WitnessLogRow,
};
use secure_log::Severity;

const MIGRATIONS: &[(u32, &str)] = &[
    (1, M1_SECURE_LOG),
    (2, M2_SEGMENTS),
    (3, M3_WITNESS_LOG),
    (4, M4_STREAMS),
];

const M1_SECURE_LOG: &str = r#"
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
"#;

const M2_SEGMENTS: &str = r#"
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
"#;

const M3_WITNESS_LOG: &str = r#"
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
"#;

const M4_STREAMS: &str = r#"
CREATE TABLE secure_log_streams (
    name           TEXT PRIMARY KEY,
    tier           TEXT NOT NULL DEFAULT 'public',
    description    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    deprecated_at  TEXT
);

INSERT INTO secure_log_streams (name, tier, description)
VALUES ('default', 'public', 'Default stream created automatically at init.');
"#;

/// SQLite-backed [`SecureLogStore`].
pub struct SqliteSecureLogStore {
    conn: Mutex<Connection>,
}

impl SqliteSecureLogStore {
    /// Open a store at the given path, creating it and running
    /// migrations if necessary.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // No-op on native targets; registers the WASI-backed VFS on
        // wasm32-wasip2 so file-backed opens actually persist. Safe
        // to call many times.
        sqlite_component_core::db::init_wasivfs().map_err(anyhow_err)?;
        let path_str = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("path is not valid UTF-8: {}", path.display()))?;
        let conn = Connection::open(path_str, OpenFlags::DEFAULT).map_err(anyhow_err)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(anyhow_err)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory SQLite store (for tests).
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().map_err(anyhow_err)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(anyhow_err)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Build a store from an existing connection. The caller is
    /// responsible for any PRAGMA configuration; migrations run
    /// automatically.
    pub fn from_connection(conn: Connection) -> anyhow::Result<Self> {
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _secure_log_migrations (
                version INTEGER PRIMARY KEY,
                applied TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .map_err(anyhow_err)?;
        for (version, sql) in MIGRATIONS {
            let exists = {
                let mut stmt = conn
                    .prepare("SELECT version FROM _secure_log_migrations WHERE version = ?1")
                    .map_err(anyhow_err)?;
                stmt.bind(1, &SqliteValue::Integer(*version as i64))
                    .map_err(anyhow_err)?;
                matches!(stmt.step().map_err(anyhow_err)?, StepResult::Row)
            };
            if exists {
                continue;
            }
            conn.execute_batch(sql).map_err(anyhow_err)?;
            let mut ins = conn
                .prepare("INSERT INTO _secure_log_migrations (version) VALUES (?1)")
                .map_err(anyhow_err)?;
            ins.bind(1, &SqliteValue::Integer(*version as i64))
                .map_err(anyhow_err)?;
            step_done(&mut ins, "INSERT INTO _secure_log_migrations")?;
        }
        Ok(())
    }

    fn lock(&self) -> anyhow::Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("secure-log sqlite mutex poisoned"))
    }
}

// ---------------------------------------------------------------------
// SecureLogStore impl
// ---------------------------------------------------------------------

impl SecureLogStore for SqliteSecureLogStore {
    fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64> {
        let seqno = row
            .seqno
            .ok_or_else(|| anyhow::anyhow!("secure_log_insert requires row.seqno to be Some"))?;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO secure_log (
                    seqno, stream_id, session_id, boot_id, timestamp,
                    event_type, severity, producer, payload_encoding,
                    payload, prev_entry_hash, entry_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(seqno as i64))
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(2, &row.stream_id).map_err(anyhow_err)?;
        stmt.bind_text_ref(3, &row.session_id).map_err(anyhow_err)?;
        stmt.bind_text_ref(4, &row.boot_id).map_err(anyhow_err)?;
        stmt.bind_text_ref(5, &row.timestamp_rfc3339)
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(6, &row.event_type).map_err(anyhow_err)?;
        stmt.bind_text_ref(7, row.severity.as_str())
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(8, &row.producer).map_err(anyhow_err)?;
        stmt.bind_text_ref(9, &row.payload_encoding)
            .map_err(anyhow_err)?;
        stmt.bind_blob_ref(10, &row.payload).map_err(anyhow_err)?;
        stmt.bind_blob_ref(11, &row.prev_entry_hash)
            .map_err(anyhow_err)?;
        stmt.bind_blob_ref(12, &row.entry_hash)
            .map_err(anyhow_err)?;
        step_done(&mut stmt, "INSERT INTO secure_log")?;
        Ok(seqno)
    }

    fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT MAX(seqno) FROM secure_log")
            .map_err(anyhow_err)?;
        read_max_u64(&mut stmt)
    }

    fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        let conn = self.lock()?;
        let tx = Tx::begin(&conn)?;

        {
            let mut stmt = conn
                .prepare(
                    "INSERT INTO secure_log_segments (
                        stream_id, seq_start, seq_end, merkle_root,
                        last_entry_hash, prev_checkpoint_hash, closed_at,
                        signature, signer_identity
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .map_err(anyhow_err)?;
            stmt.bind_text_ref(1, &row.stream_id).map_err(anyhow_err)?;
            stmt.bind(2, &SqliteValue::Integer(row.seq_start as i64))
                .map_err(anyhow_err)?;
            stmt.bind(3, &SqliteValue::Integer(row.seq_end as i64))
                .map_err(anyhow_err)?;
            stmt.bind_blob_ref(4, &row.merkle_root)
                .map_err(anyhow_err)?;
            stmt.bind_blob_ref(5, &row.last_entry_hash)
                .map_err(anyhow_err)?;
            stmt.bind_blob_ref(6, &row.prev_checkpoint_hash)
                .map_err(anyhow_err)?;
            stmt.bind_text_ref(7, &row.closed_at_rfc3339)
                .map_err(anyhow_err)?;
            bind_opt_blob(&mut stmt, 8, row.signature.as_deref())?;
            bind_opt_text(&mut stmt, 9, row.signer_identity.as_deref())?;
            step_done(&mut stmt, "INSERT INTO secure_log_segments")?;
        }
        let segment_id = conn.last_insert_rowid() as u64;

        {
            let mut stmt = conn
                .prepare(
                    "INSERT INTO secure_log_segment_entries (segment_id, seqno, leaf_index)
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(anyhow_err)?;
            for (seqno, leaf_index) in entries {
                stmt.reset().map_err(anyhow_err)?;
                stmt.clear_bindings().map_err(anyhow_err)?;
                stmt.bind(1, &SqliteValue::Integer(segment_id as i64))
                    .map_err(anyhow_err)?;
                stmt.bind(2, &SqliteValue::Integer(*seqno as i64))
                    .map_err(anyhow_err)?;
                stmt.bind(3, &SqliteValue::Integer(*leaf_index as i64))
                    .map_err(anyhow_err)?;
                step_done(&mut stmt, "INSERT INTO secure_log_segment_entries")?;
            }
        }

        tx.commit()?;
        Ok(segment_id)
    }

    fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT segment_id, stream_id, seq_start, seq_end,
                        merkle_root, last_entry_hash, prev_checkpoint_hash,
                        closed_at, signature, signer_identity
                 FROM secure_log_segments WHERE segment_id = ?1",
            )
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(segment_id as i64))
            .map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(row_to_segment_row(&stmt)?)),
            StepResult::Done => Ok(None),
        }
    }

    fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT segment_id, stream_id, seq_start, seq_end,
                        merkle_root, last_entry_hash, prev_checkpoint_hash,
                        closed_at, signature, signer_identity
                 FROM secure_log_segments WHERE stream_id = ?1 ORDER BY segment_id",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            out.push(row_to_segment_row(&stmt)?);
        }
        Ok(out)
    }

    fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT MAX(seq_end) FROM secure_log_segments WHERE stream_id = ?1")
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        read_max_u64(&mut stmt)
    }

    fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT seqno FROM secure_log_segment_entries
                 WHERE segment_id = ?1 ORDER BY leaf_index",
            )
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(segment_id as i64))
            .map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            let n = read_i64(stmt.column_value(0))?;
            out.push(n as u64);
        }
        Ok(out)
    }

    fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT segment_id FROM secure_log_segment_entries WHERE seqno = ?1")
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(seqno as i64))
            .map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(read_i64(stmt.column_value(0))? as u64)),
            StepResult::Done => Ok(None),
        }
    }

    fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "UPDATE secure_log_segments
                 SET signature = ?2, signer_identity = ?3
                 WHERE segment_id = ?1",
            )
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(segment_id as i64))
            .map_err(anyhow_err)?;
        stmt.bind_blob_ref(2, signature).map_err(anyhow_err)?;
        stmt.bind_text_ref(3, signer_identity).map_err(anyhow_err)?;
        step_done(&mut stmt, "UPDATE secure_log_segments")?;
        if conn.changes() == 0 {
            anyhow::bail!("segment not found: {}", segment_id);
        }
        Ok(())
    }

    fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO witness_log (
                    stream_id, segment_id, seq_start, seq_end,
                    checkpoint_hash_hex, signature_hex, signer_identity,
                    received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, &row.stream_id).map_err(anyhow_err)?;
        stmt.bind(2, &SqliteValue::Integer(row.segment_id as i64))
            .map_err(anyhow_err)?;
        stmt.bind(3, &SqliteValue::Integer(row.seq_start as i64))
            .map_err(anyhow_err)?;
        stmt.bind(4, &SqliteValue::Integer(row.seq_end as i64))
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(5, &row.checkpoint_hash_hex)
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(6, &row.signature_hex)
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(7, &row.signer_identity)
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(8, &row.received_at_rfc3339)
            .map_err(anyhow_err)?;
        step_done(&mut stmt, "INSERT INTO witness_log")?;
        Ok(conn.last_insert_rowid() as u64)
    }

    fn witness_log_latest(&self, stream_id: &str) -> anyhow::Result<Option<WitnessLogRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, stream_id, segment_id, seq_start, seq_end,
                        checkpoint_hash_hex, signature_hex, signer_identity,
                        received_at
                 FROM witness_log WHERE stream_id = ?1
                 ORDER BY id DESC LIMIT 1",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(row_to_witness_log_row(&stmt)?)),
            StepResult::Done => Ok(None),
        }
    }

    fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, stream_id, segment_id, seq_start, seq_end,
                        checkpoint_hash_hex, signature_hex, signer_identity,
                        received_at
                 FROM witness_log WHERE stream_id = ?1 ORDER BY id ASC",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            out.push(row_to_witness_log_row(&stmt)?);
        }
        Ok(out)
    }

    fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT stream_id FROM witness_log ORDER BY stream_id")
            .map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            out.push(read_text(stmt.column_value(0))?);
        }
        Ok(out)
    }

    fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        let conn = self.lock()?;

        let streams: Vec<String> = if let Some(sid) = stream_id {
            vec![sid.to_string()]
        } else {
            let mut stmt = conn
                .prepare("SELECT DISTINCT stream_id FROM witness_log")
                .map_err(anyhow_err)?;
            let mut out = Vec::new();
            while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
                out.push(read_text(stmt.column_value(0))?);
            }
            out
        };

        let mut total_deleted = 0usize;

        for sid in &streams {
            let keep_ids: HashSet<i64> = if let Some(k) = keep_latest {
                let mut stmt = conn
                    .prepare(
                        "SELECT id FROM witness_log WHERE stream_id = ?1
                         ORDER BY id DESC LIMIT ?2",
                    )
                    .map_err(anyhow_err)?;
                stmt.bind_text_ref(1, sid).map_err(anyhow_err)?;
                stmt.bind(2, &SqliteValue::Integer(k as i64))
                    .map_err(anyhow_err)?;
                let mut out = HashSet::new();
                while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
                    out.insert(read_i64(stmt.column_value(0))?);
                }
                out
            } else {
                HashSet::new()
            };

            if keep_ids.is_empty() && older_than_rfc3339.is_none() {
                continue;
            }

            let candidates: Vec<i64> = if let Some(cutoff) = older_than_rfc3339 {
                let mut stmt = conn
                    .prepare(
                        "SELECT id FROM witness_log
                         WHERE stream_id = ?1 AND received_at < ?2",
                    )
                    .map_err(anyhow_err)?;
                stmt.bind_text_ref(1, sid).map_err(anyhow_err)?;
                stmt.bind_text_ref(2, cutoff).map_err(anyhow_err)?;
                let mut out = Vec::new();
                while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
                    out.push(read_i64(stmt.column_value(0))?);
                }
                out
            } else {
                let mut stmt = conn
                    .prepare("SELECT id FROM witness_log WHERE stream_id = ?1")
                    .map_err(anyhow_err)?;
                stmt.bind_text_ref(1, sid).map_err(anyhow_err)?;
                let mut out = Vec::new();
                while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
                    out.push(read_i64(stmt.column_value(0))?);
                }
                out
            };

            let mut del_stmt = conn
                .prepare("DELETE FROM witness_log WHERE id = ?1")
                .map_err(anyhow_err)?;
            for id in candidates {
                if keep_ids.contains(&id) {
                    continue;
                }
                del_stmt.reset().map_err(anyhow_err)?;
                del_stmt.clear_bindings().map_err(anyhow_err)?;
                del_stmt
                    .bind(1, &SqliteValue::Integer(id))
                    .map_err(anyhow_err)?;
                step_done(&mut del_stmt, "DELETE FROM witness_log")?;
                total_deleted += 1;
            }
        }

        Ok(total_deleted)
    }

    fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                        event_type, severity, producer, payload_encoding,
                        payload, prev_entry_hash, entry_hash
                 FROM secure_log WHERE seqno = ?1",
            )
            .map_err(anyhow_err)?;
        stmt.bind(1, &SqliteValue::Integer(seqno as i64))
            .map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(row_to_secure_log_row(&stmt)?)),
            StepResult::Done => Ok(None),
        }
    }

    fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                        event_type, severity, producer, payload_encoding,
                        payload, prev_entry_hash, entry_hash
                 FROM secure_log
                 WHERE stream_id = ?1 AND seqno BETWEEN ?2 AND ?3
                 ORDER BY seqno",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        stmt.bind(2, &SqliteValue::Integer(from as i64))
            .map_err(anyhow_err)?;
        stmt.bind(3, &SqliteValue::Integer(to as i64))
            .map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            out.push(row_to_secure_log_row(&stmt)?);
        }
        Ok(out)
    }

    fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT MAX(seqno) FROM secure_log WHERE stream_id = ?1")
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        read_max_u64(&mut stmt)
    }

    fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                        event_type, severity, producer, payload_encoding,
                        payload, prev_entry_hash, entry_hash
                 FROM secure_log
                 WHERE stream_id = ?1
                 ORDER BY seqno DESC
                 LIMIT 1",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, stream_id).map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(row_to_secure_log_row(&stmt)?)),
            StepResult::Done => Ok(None),
        }
    }

    fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "INSERT INTO secure_log_streams
                    (name, tier, description, created_at, deprecated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(name) DO UPDATE SET
                    tier = excluded.tier,
                    description = excluded.description,
                    deprecated_at = excluded.deprecated_at",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, &row.name).map_err(anyhow_err)?;
        stmt.bind_text_ref(2, &row.tier).map_err(anyhow_err)?;
        bind_opt_text(&mut stmt, 3, row.description.as_deref())?;
        stmt.bind_text_ref(4, &row.created_at_rfc3339)
            .map_err(anyhow_err)?;
        bind_opt_text(&mut stmt, 5, row.deprecated_at_rfc3339.as_deref())?;
        step_done(&mut stmt, "INSERT INTO secure_log_streams")?;
        Ok(())
    }

    fn secure_log_stream_get(&self, name: &str) -> anyhow::Result<Option<SecureLogStreamRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, tier, description, created_at, deprecated_at
                 FROM secure_log_streams WHERE name = ?1",
            )
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, name).map_err(anyhow_err)?;
        match stmt.step().map_err(anyhow_err)? {
            StepResult::Row => Ok(Some(row_to_stream_row(&stmt)?)),
            StepResult::Done => Ok(None),
        }
    }

    fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, tier, description, created_at, deprecated_at
                 FROM secure_log_streams ORDER BY name",
            )
            .map_err(anyhow_err)?;
        let mut out = Vec::new();
        while let StepResult::Row = stmt.step().map_err(anyhow_err)? {
            out.push(row_to_stream_row(&stmt)?);
        }
        Ok(out)
    }

    fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("UPDATE secure_log_streams SET tier = ?2 WHERE name = ?1")
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, name).map_err(anyhow_err)?;
        stmt.bind_text_ref(2, tier).map_err(anyhow_err)?;
        step_done(&mut stmt, "UPDATE secure_log_streams tier")?;
        if conn.changes() == 0 {
            anyhow::bail!("stream not found: {}", name);
        }
        Ok(())
    }

    fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("UPDATE secure_log_streams SET deprecated_at = ?2 WHERE name = ?1")
            .map_err(anyhow_err)?;
        stmt.bind_text_ref(1, name).map_err(anyhow_err)?;
        stmt.bind_text_ref(2, deprecated_at_rfc3339)
            .map_err(anyhow_err)?;
        step_done(&mut stmt, "UPDATE secure_log_streams deprecated_at")?;
        if conn.changes() == 0 {
            anyhow::bail!("stream not found: {}", name);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Transaction RAII guard
// ---------------------------------------------------------------------

struct Tx<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> Tx<'a> {
    fn begin(conn: &'a Connection) -> anyhow::Result<Self> {
        conn.execute_batch("BEGIN;").map_err(anyhow_err)?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    fn commit(mut self) -> anyhow::Result<()> {
        self.conn.execute_batch("COMMIT;").map_err(anyhow_err)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback; if the conn is already toast SQLite
            // will refuse and we have nowhere to report it from Drop.
            let _ = self.conn.execute_batch("ROLLBACK;");
        }
    }
}

// ---------------------------------------------------------------------
// Error + column helpers
// ---------------------------------------------------------------------

fn anyhow_err(e: SqliteError) -> anyhow::Error {
    // extended_code carries the finer discrimination (e.g. 2067
    // UNIQUE, 1555 PRIMARY KEY) callers may want to distinguish;
    // include it in the message so it survives the Debug bag.
    anyhow::anyhow!("sqlite ({}/{}): {}", e.code, e.extended_code, e.message)
}

fn step_done(stmt: &mut Statement<'_>, what: &str) -> anyhow::Result<()> {
    match stmt.step().map_err(anyhow_err)? {
        StepResult::Done => Ok(()),
        StepResult::Row => Err(anyhow::anyhow!("{} unexpectedly produced a row", what)),
    }
}

/// Read the single-row scalar result of a `SELECT MAX(...)` query
/// (or any other query that yields at most one row whose sole column
/// is either an INTEGER or NULL). MAX always returns exactly one row
/// even for empty tables, with the value NULL — mirror that here.
fn read_max_u64(stmt: &mut Statement<'_>) -> anyhow::Result<Option<u64>> {
    match stmt.step().map_err(anyhow_err)? {
        StepResult::Row => match stmt.column_value(0) {
            SqliteValue::Null => Ok(None),
            SqliteValue::Integer(n) => Ok(Some(n as u64)),
            other => Err(anyhow::anyhow!(
                "expected INTEGER or NULL scalar, got {other:?}"
            )),
        },
        StepResult::Done => Ok(None),
    }
}

fn bind_opt_text(stmt: &mut Statement<'_>, idx: i32, v: Option<&str>) -> anyhow::Result<()> {
    match v {
        Some(s) => stmt.bind_text_ref(idx, s).map_err(anyhow_err),
        None => stmt.bind(idx, &SqliteValue::Null).map_err(anyhow_err),
    }
}

fn bind_opt_blob(stmt: &mut Statement<'_>, idx: i32, v: Option<&[u8]>) -> anyhow::Result<()> {
    match v {
        Some(b) => stmt.bind_blob_ref(idx, b).map_err(anyhow_err),
        None => stmt.bind(idx, &SqliteValue::Null).map_err(anyhow_err),
    }
}

fn read_text(v: SqliteValue) -> anyhow::Result<String> {
    match v {
        SqliteValue::Text(s) => Ok(s),
        other => Err(anyhow::anyhow!("expected TEXT column, got {other:?}")),
    }
}

fn read_text_opt(v: SqliteValue) -> anyhow::Result<Option<String>> {
    match v {
        SqliteValue::Null => Ok(None),
        SqliteValue::Text(s) => Ok(Some(s)),
        other => Err(anyhow::anyhow!(
            "expected nullable TEXT column, got {other:?}"
        )),
    }
}

fn read_i64(v: SqliteValue) -> anyhow::Result<i64> {
    match v {
        SqliteValue::Integer(i) => Ok(i),
        other => Err(anyhow::anyhow!("expected INTEGER column, got {other:?}")),
    }
}

fn read_blob(v: SqliteValue) -> anyhow::Result<Vec<u8>> {
    match v {
        SqliteValue::Blob(b) => Ok(b),
        // SQLite is happy to hand back a BLOB column as an empty text
        // when the underlying value is zero-length — accept the empty
        // TEXT arm as an empty blob for robustness.
        SqliteValue::Text(s) if s.is_empty() => Ok(Vec::new()),
        other => Err(anyhow::anyhow!("expected BLOB column, got {other:?}")),
    }
}

fn read_blob_opt(v: SqliteValue) -> anyhow::Result<Option<Vec<u8>>> {
    match v {
        SqliteValue::Null => Ok(None),
        SqliteValue::Blob(b) => Ok(Some(b)),
        SqliteValue::Text(s) if s.is_empty() => Ok(Some(Vec::new())),
        other => Err(anyhow::anyhow!(
            "expected nullable BLOB column, got {other:?}"
        )),
    }
}

// ---------------------------------------------------------------------
// Row decoders
// ---------------------------------------------------------------------

fn row_to_stream_row(stmt: &Statement<'_>) -> anyhow::Result<SecureLogStreamRow> {
    Ok(SecureLogStreamRow {
        name: read_text(stmt.column_value(0))?,
        tier: read_text(stmt.column_value(1))?,
        description: read_text_opt(stmt.column_value(2))?,
        created_at_rfc3339: read_text(stmt.column_value(3))?,
        deprecated_at_rfc3339: read_text_opt(stmt.column_value(4))?,
    })
}

fn row_to_witness_log_row(stmt: &Statement<'_>) -> anyhow::Result<WitnessLogRow> {
    Ok(WitnessLogRow {
        id: Some(read_i64(stmt.column_value(0))?),
        stream_id: read_text(stmt.column_value(1))?,
        segment_id: read_i64(stmt.column_value(2))? as u64,
        seq_start: read_i64(stmt.column_value(3))? as u64,
        seq_end: read_i64(stmt.column_value(4))? as u64,
        checkpoint_hash_hex: read_text(stmt.column_value(5))?,
        signature_hex: read_text(stmt.column_value(6))?,
        signer_identity: read_text(stmt.column_value(7))?,
        received_at_rfc3339: read_text(stmt.column_value(8))?,
    })
}

fn row_to_segment_row(stmt: &Statement<'_>) -> anyhow::Result<SecureLogSegmentRow> {
    Ok(SecureLogSegmentRow {
        segment_id: Some(read_i64(stmt.column_value(0))? as u64),
        stream_id: read_text(stmt.column_value(1))?,
        seq_start: read_i64(stmt.column_value(2))? as u64,
        seq_end: read_i64(stmt.column_value(3))? as u64,
        merkle_root: read_blob(stmt.column_value(4))?,
        last_entry_hash: read_blob(stmt.column_value(5))?,
        prev_checkpoint_hash: read_blob(stmt.column_value(6))?,
        closed_at_rfc3339: read_text(stmt.column_value(7))?,
        signature: read_blob_opt(stmt.column_value(8))?,
        signer_identity: read_text_opt(stmt.column_value(9))?,
    })
}

fn row_to_secure_log_row(stmt: &Statement<'_>) -> anyhow::Result<SecureLogRow> {
    let seqno = read_i64(stmt.column_value(0))?;
    let severity_text = read_text(stmt.column_value(6))?;
    let severity = Severity::try_from(severity_text.as_str())
        .map_err(|e| anyhow::anyhow!("bad severity in secure_log column 6: {e}"))?;
    Ok(SecureLogRow {
        seqno: Some(seqno as u64),
        stream_id: read_text(stmt.column_value(1))?,
        session_id: read_text(stmt.column_value(2))?,
        boot_id: read_text(stmt.column_value(3))?,
        timestamp_rfc3339: read_text(stmt.column_value(4))?,
        event_type: read_text(stmt.column_value(5))?,
        severity,
        producer: read_text(stmt.column_value(7))?,
        payload_encoding: read_text(stmt.column_value(8))?,
        payload: read_blob(stmt.column_value(9))?,
        prev_entry_hash: read_blob(stmt.column_value(10))?,
        entry_hash: read_blob(stmt.column_value(11))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_runs_migrations_idempotently() {
        let store = SqliteSecureLogStore::open_in_memory().unwrap();
        // Default stream is seeded by M4.
        let default = store.secure_log_stream_get("default").unwrap().unwrap();
        assert_eq!(default.tier, "public");
        // Running migrate() again must be a no-op.
        store.migrate().unwrap();
    }

    #[test]
    fn round_trip_secure_log_row() {
        let store = SqliteSecureLogStore::open_in_memory().unwrap();
        let row = SecureLogRow {
            seqno: Some(1),
            stream_id: "default".into(),
            session_id: "s".into(),
            boot_id: "b".into(),
            timestamp_rfc3339: "2026-05-21T00:00:00Z".into(),
            event_type: "ev".into(),
            severity: Severity::Info,
            producer: "p".into(),
            payload_encoding: "cbor".into(),
            payload: vec![1, 2, 3],
            prev_entry_hash: vec![0u8; 32],
            entry_hash: vec![9u8; 32],
        };
        let id = store.secure_log_insert(&row).unwrap();
        assert_eq!(id, 1);
        let back = store.secure_log_get(1).unwrap().unwrap();
        assert_eq!(back, row);
    }
}
