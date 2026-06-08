//! SQLite-backed storage for the [`secure_log`] crate.
//!
//! [`SqliteSecureLogStore`] owns a [`rusqlite::Connection`] and
//! implements the [`SecureLogStore`] trait by translating each
//! method into the appropriate SQL.
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

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use secure_log::store::{
    SecureLogRow, SecureLogSegmentRow, SecureLogStore, SecureLogStreamRow, WitnessLogRow,
};

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
    conn: Connection,
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
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory SQLite store (for tests).
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Build a store from an existing connection. The caller is
    /// responsible for any PRAGMA configuration; migrations run
    /// automatically.
    pub fn from_connection(conn: Connection) -> anyhow::Result<Self> {
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _secure_log_migrations (
                version INTEGER PRIMARY KEY,
                applied TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        for (version, sql) in MIGRATIONS {
            let exists: Option<i64> = self
                .conn
                .query_row(
                    "SELECT version FROM _secure_log_migrations WHERE version = ?1",
                    params![*version as i64],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_some() {
                continue;
            }
            self.conn.execute_batch(sql)?;
            self.conn.execute(
                "INSERT INTO _secure_log_migrations (version) VALUES (?1)",
                params![*version as i64],
            )?;
        }
        Ok(())
    }
}

impl SecureLogStore for SqliteSecureLogStore {
    fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64> {
        let seqno = row
            .seqno
            .ok_or_else(|| anyhow::anyhow!("secure_log_insert requires row.seqno to be Some"))?;
        self.conn.execute(
            "INSERT INTO secure_log (
                seqno, stream_id, session_id, boot_id, timestamp,
                event_type, severity, producer, payload_encoding,
                payload, prev_entry_hash, entry_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                seqno as i64,
                row.stream_id,
                row.session_id,
                row.boot_id,
                row.timestamp_rfc3339,
                row.event_type,
                row.severity,
                row.producer,
                row.payload_encoding,
                row.payload,
                row.prev_entry_hash,
                row.entry_hash,
            ],
        )?;
        Ok(seqno)
    }

    fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        self.conn
            .query_row("SELECT MAX(seqno) FROM secure_log", [], |row| {
                let v: Option<i64> = row.get(0)?;
                Ok(v.map(|n| n as u64))
            })
            .optional()
            .map(|r| r.flatten())
            .map_err(Into::into)
    }

    fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO secure_log_segments (
                stream_id, seq_start, seq_end, merkle_root,
                last_entry_hash, prev_checkpoint_hash, closed_at,
                signature, signer_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                row.stream_id,
                row.seq_start as i64,
                row.seq_end as i64,
                row.merkle_root,
                row.last_entry_hash,
                row.prev_checkpoint_hash,
                row.closed_at_rfc3339,
                row.signature,
                row.signer_identity,
            ],
        )?;
        let segment_id = tx.last_insert_rowid() as u64;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO secure_log_segment_entries (segment_id, seqno, leaf_index)
                 VALUES (?1, ?2, ?3)",
            )?;
            for (seqno, leaf_index) in entries {
                stmt.execute(params![
                    segment_id as i64,
                    *seqno as i64,
                    *leaf_index as i64
                ])?;
            }
        }
        tx.commit()?;
        Ok(segment_id)
    }

    fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>> {
        self.conn
            .query_row(
                "SELECT segment_id, stream_id, seq_start, seq_end,
                        merkle_root, last_entry_hash, prev_checkpoint_hash,
                        closed_at, signature, signer_identity
                 FROM secure_log_segments WHERE segment_id = ?1",
                params![segment_id as i64],
                row_to_segment_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT segment_id, stream_id, seq_start, seq_end,
                    merkle_root, last_entry_hash, prev_checkpoint_hash,
                    closed_at, signature, signer_identity
             FROM secure_log_segments WHERE stream_id = ?1 ORDER BY segment_id",
        )?;
        let rows = stmt.query_map(params![stream_id], row_to_segment_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT MAX(seq_end) FROM secure_log_segments WHERE stream_id = ?1",
                params![stream_id],
                |row| {
                    let v: Option<i64> = row.get(0)?;
                    Ok(v.map(|n| n as u64))
                },
            )
            .optional()
            .map(|r| r.flatten())
            .map_err(Into::into)
    }

    fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT seqno FROM secure_log_segment_entries
             WHERE segment_id = ?1 ORDER BY leaf_index",
        )?;
        let rows = stmt.query_map(params![segment_id as i64], |row| {
            let n: i64 = row.get(0)?;
            Ok(n as u64)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT segment_id FROM secure_log_segment_entries WHERE seqno = ?1",
                params![seqno as i64],
                |row| {
                    let n: i64 = row.get(0)?;
                    Ok(n as u64)
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE secure_log_segments
             SET signature = ?2, signer_identity = ?3
             WHERE segment_id = ?1",
            params![segment_id as i64, signature, signer_identity],
        )?;
        if count == 0 {
            anyhow::bail!("segment not found: {}", segment_id);
        }
        Ok(())
    }

    fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64> {
        self.conn.execute(
            "INSERT INTO witness_log (
                stream_id, segment_id, seq_start, seq_end,
                checkpoint_hash_hex, signature_hex, signer_identity,
                received_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.stream_id,
                row.segment_id as i64,
                row.seq_start as i64,
                row.seq_end as i64,
                row.checkpoint_hash_hex,
                row.signature_hex,
                row.signer_identity,
                row.received_at_rfc3339,
            ],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    fn witness_log_latest(&self, stream_id: &str) -> anyhow::Result<Option<WitnessLogRow>> {
        self.conn
            .query_row(
                "SELECT id, stream_id, segment_id, seq_start, seq_end,
                        checkpoint_hash_hex, signature_hex, signer_identity,
                        received_at
                 FROM witness_log WHERE stream_id = ?1
                 ORDER BY id DESC LIMIT 1",
                params![stream_id],
                row_to_witness_log_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, stream_id, segment_id, seq_start, seq_end,
                    checkpoint_hash_hex, signature_hex, signer_identity,
                    received_at
             FROM witness_log WHERE stream_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![stream_id], row_to_witness_log_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT stream_id FROM witness_log ORDER BY stream_id")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        let streams: Vec<String> = if let Some(sid) = stream_id {
            vec![sid.to_string()]
        } else {
            let mut stmt = self
                .conn
                .prepare("SELECT DISTINCT stream_id FROM witness_log")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };

        let mut total_deleted = 0usize;

        for sid in &streams {
            let keep_ids: std::collections::HashSet<i64> = if let Some(k) = keep_latest {
                let mut stmt = self.conn.prepare(
                    "SELECT id FROM witness_log WHERE stream_id = ?1
                     ORDER BY id DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![sid, k as i64], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            } else {
                std::collections::HashSet::new()
            };

            if keep_ids.is_empty() && older_than_rfc3339.is_none() {
                continue;
            }

            let candidates: Vec<i64> = if let Some(cutoff) = older_than_rfc3339 {
                let mut stmt = self.conn.prepare(
                    "SELECT id FROM witness_log
                     WHERE stream_id = ?1 AND received_at < ?2",
                )?;
                let rows = stmt.query_map(params![sid, cutoff], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            } else {
                let mut stmt = self
                    .conn
                    .prepare("SELECT id FROM witness_log WHERE stream_id = ?1")?;
                let rows = stmt.query_map(params![sid], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };

            for id in candidates {
                if keep_ids.contains(&id) {
                    continue;
                }
                self.conn
                    .execute("DELETE FROM witness_log WHERE id = ?1", params![id])?;
                total_deleted += 1;
            }
        }

        Ok(total_deleted)
    }

    fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>> {
        self.conn
            .query_row(
                "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                        event_type, severity, producer, payload_encoding,
                        payload, prev_entry_hash, entry_hash
                 FROM secure_log WHERE seqno = ?1",
                params![seqno as i64],
                row_to_secure_log_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                    event_type, severity, producer, payload_encoding,
                    payload, prev_entry_hash, entry_hash
             FROM secure_log
             WHERE stream_id = ?1 AND seqno BETWEEN ?2 AND ?3
             ORDER BY seqno",
        )?;
        let rows = stmt.query_map(
            params![stream_id, from as i64, to as i64],
            row_to_secure_log_row,
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT MAX(seqno) FROM secure_log WHERE stream_id = ?1",
                params![stream_id],
                |row| {
                    let v: Option<i64> = row.get(0)?;
                    Ok(v.map(|n| n as u64))
                },
            )
            .optional()
            .map(|r| r.flatten())
            .map_err(Into::into)
    }

    fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>> {
        self.conn
            .query_row(
                "SELECT seqno, stream_id, session_id, boot_id, timestamp,
                        event_type, severity, producer, payload_encoding,
                        payload, prev_entry_hash, entry_hash
                 FROM secure_log
                 WHERE stream_id = ?1
                 ORDER BY seqno DESC
                 LIMIT 1",
                params![stream_id],
                row_to_secure_log_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO secure_log_streams
                (name, tier, description, created_at, deprecated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                tier = excluded.tier,
                description = excluded.description,
                deprecated_at = excluded.deprecated_at",
            params![
                row.name,
                row.tier,
                row.description,
                row.created_at_rfc3339,
                row.deprecated_at_rfc3339,
            ],
        )?;
        Ok(())
    }

    fn secure_log_stream_get(&self, name: &str) -> anyhow::Result<Option<SecureLogStreamRow>> {
        self.conn
            .query_row(
                "SELECT name, tier, description, created_at, deprecated_at
                 FROM secure_log_streams WHERE name = ?1",
                params![name],
                row_to_stream_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, tier, description, created_at, deprecated_at
             FROM secure_log_streams ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_stream_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE secure_log_streams SET tier = ?2 WHERE name = ?1",
            params![name, tier],
        )?;
        if count == 0 {
            anyhow::bail!("stream not found: {}", name);
        }
        Ok(())
    }

    fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE secure_log_streams SET deprecated_at = ?2 WHERE name = ?1",
            params![name, deprecated_at_rfc3339],
        )?;
        if count == 0 {
            anyhow::bail!("stream not found: {}", name);
        }
        Ok(())
    }
}

fn row_to_stream_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureLogStreamRow> {
    Ok(SecureLogStreamRow {
        name: row.get(0)?,
        tier: row.get(1)?,
        description: row.get(2)?,
        created_at_rfc3339: row.get(3)?,
        deprecated_at_rfc3339: row.get(4)?,
    })
}

fn row_to_witness_log_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WitnessLogRow> {
    Ok(WitnessLogRow {
        id: Some(row.get::<_, i64>(0)?),
        stream_id: row.get(1)?,
        segment_id: row.get::<_, i64>(2)? as u64,
        seq_start: row.get::<_, i64>(3)? as u64,
        seq_end: row.get::<_, i64>(4)? as u64,
        checkpoint_hash_hex: row.get(5)?,
        signature_hex: row.get(6)?,
        signer_identity: row.get(7)?,
        received_at_rfc3339: row.get(8)?,
    })
}

fn row_to_segment_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureLogSegmentRow> {
    Ok(SecureLogSegmentRow {
        segment_id: Some(row.get::<_, i64>(0)? as u64),
        stream_id: row.get(1)?,
        seq_start: row.get::<_, i64>(2)? as u64,
        seq_end: row.get::<_, i64>(3)? as u64,
        merkle_root: row.get(4)?,
        last_entry_hash: row.get(5)?,
        prev_checkpoint_hash: row.get(6)?,
        closed_at_rfc3339: row.get(7)?,
        signature: row.get(8)?,
        signer_identity: row.get(9)?,
    })
}

fn row_to_secure_log_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureLogRow> {
    let seqno: i64 = row.get(0)?;
    Ok(SecureLogRow {
        seqno: Some(seqno as u64),
        stream_id: row.get(1)?,
        session_id: row.get(2)?,
        boot_id: row.get(3)?,
        timestamp_rfc3339: row.get(4)?,
        event_type: row.get(5)?,
        severity: row.get(6)?,
        producer: row.get(7)?,
        payload_encoding: row.get(8)?,
        payload: row.get(9)?,
        prev_entry_hash: row.get(10)?,
        entry_hash: row.get(11)?,
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
            severity: "info".into(),
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
