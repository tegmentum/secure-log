//! Anti-rollback head file + witness protocol types.
//!
//! ## Anti-rollback via sealed head file
//!
//! The highest checkpoint hash the daemon has ever signed for a
//! given stream is persisted to a small JSON "head file" alongside
//! the store database. On startup and before every append, the
//! daemon reads the head file; after every successful signature it
//! writes the new head. A rolled-back database will present a
//! `secure_log_segments` list that terminates at a checkpoint
//! *earlier* than the head file records, which is detectable.
//!
//! In Phase 4 we use a plain JSON file; Phase 5 could seal it
//! under a TPM-protected KEK so an attacker with filesystem access
//! can't easily rewrite both the database and the head file
//! atomically. For now, just the filesystem barrier.
//!
//! ## Witness protocol
//!
//! A **witness** is an independent service that stores received
//! `(stream_id, segment_id, checkpoint_hash, signature)` tuples in
//! an append-only log. `tpmd` exposes `POST /v1/audit/witness` for
//! this role; `tpm audit publish --witness URL` pushes the current
//! head to it; `tpm audit verify --witness URL` fetches the remote
//! record and compares.
//!
//! Equivocation — the daemon showing different histories to
//! different parties — is detectable because the witness remembers
//! the first head it accepted for a stream. If the daemon later
//! presents a divergent history whose checkpoint chain doesn't
//! extend that witnessed head, verification fails.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::hash::{hex, EntryDigest};

/// The per-stream head record persisted to the head file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadRecord {
    pub stream_id: String,
    pub segment_id: u64,
    pub seq_end: u64,
    /// Hex-encoded checkpoint hash.
    pub checkpoint_hash_hex: String,
    /// RFC 3339 timestamp when the head was last updated.
    pub updated_at_rfc3339: String,
}

impl HeadRecord {
    pub fn checkpoint_hash(&self) -> Option<EntryDigest> {
        let bytes = (0..self.checkpoint_hash_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.checkpoint_hash_hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }
}

/// The on-disk head-file format. Maps stream_id → HeadRecord.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadFile {
    pub version: u32,
    #[serde(default)]
    pub records: Vec<HeadRecord>,
}

impl HeadFile {
    /// Version of the head file format.
    pub const VERSION: u32 = 1;

    /// Derive the head file path from the store database path.
    /// Uses the same directory with a fixed `.heads.json` suffix.
    pub fn path_for_store(store_path: &Path) -> PathBuf {
        let mut p = store_path.to_path_buf();
        let stem = p
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tpm.db".into());
        p.set_file_name(format!("{}.heads.json", stem));
        p
    }

    /// Load from disk. If the file does not exist, returns an empty
    /// head file. Any parse error is surfaced so the caller can
    /// refuse to continue rather than silently losing anti-rollback
    /// state.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self {
                version: Self::VERSION,
                records: Vec::new(),
            });
        }
        let text = std::fs::read_to_string(path)?;
        let head: HeadFile = serde_json::from_str(&text)?;
        if head.version != Self::VERSION {
            anyhow::bail!(
                "unsupported head file version: {} (expected {})",
                head.version,
                Self::VERSION
            );
        }
        Ok(head)
    }

    /// Atomically write to disk: write to a sibling `.tmp` file,
    /// fsync, then rename. This avoids leaving the head file in a
    /// partially-written state if the process is killed.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            // Best-effort fsync on the temp file so the contents
            // hit disk before the rename. Ignore errors on weird
            // filesystems.
            if let Ok(f) = OpenOptions::new().write(true).open(&tmp) {
                let _ = f.sync_all();
            }
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Insert or update the record for a given stream.
    pub fn upsert(&mut self, record: HeadRecord) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|r| r.stream_id == record.stream_id)
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
    }

    /// Look up the head for a stream.
    pub fn get(&self, stream_id: &str) -> Option<&HeadRecord> {
        self.records.iter().find(|r| r.stream_id == stream_id)
    }
}

/// Convert a digest to its hex representation used in [`HeadRecord`].
pub fn digest_to_hex(digest: &EntryDigest) -> String {
    hex(digest)
}

// -- Witness protocol envelopes -------------------------------------

/// Payload published to a witness via HTTP POST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSubmission {
    pub stream_id: String,
    pub segment_id: u64,
    pub seq_start: u64,
    pub seq_end: u64,
    pub checkpoint_hash_hex: String,
    pub signature_hex: String,
    pub signer_identity: String,
}

/// Receipt returned by a witness after accepting (or rejecting) a
/// submission. A witness refuses to accept a submission whose
/// `checkpoint_hash` does not extend (or equal) the one it already
/// remembered for this stream — that's the equivocation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessReceipt {
    pub stream_id: String,
    pub segment_id: u64,
    pub checkpoint_hash_hex: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub received_at_rfc3339: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn head_file_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db.heads.json");

        let mut hf = HeadFile::load(&path).unwrap();
        assert!(hf.records.is_empty());

        hf.upsert(HeadRecord {
            stream_id: "default".into(),
            segment_id: 1,
            seq_end: 5,
            checkpoint_hash_hex: "aa".repeat(32),
            updated_at_rfc3339: "2026-04-10T00:00:00Z".into(),
        });
        hf.version = HeadFile::VERSION;
        hf.save(&path).unwrap();

        let reloaded = HeadFile::load(&path).unwrap();
        assert_eq!(reloaded.records.len(), 1);
        assert_eq!(
            reloaded.get("default").unwrap().checkpoint_hash_hex,
            "aa".repeat(32)
        );
    }

    #[test]
    fn upsert_replaces_existing_stream_record() {
        let mut hf = HeadFile::default();
        hf.version = HeadFile::VERSION;
        hf.upsert(HeadRecord {
            stream_id: "a".into(),
            segment_id: 1,
            seq_end: 3,
            checkpoint_hash_hex: "aa".repeat(32),
            updated_at_rfc3339: "2026-04-10T00:00:00Z".into(),
        });
        hf.upsert(HeadRecord {
            stream_id: "a".into(),
            segment_id: 2,
            seq_end: 6,
            checkpoint_hash_hex: "bb".repeat(32),
            updated_at_rfc3339: "2026-04-10T01:00:00Z".into(),
        });
        assert_eq!(hf.records.len(), 1);
        assert_eq!(hf.get("a").unwrap().segment_id, 2);
    }

    #[test]
    fn path_for_store_appends_heads_suffix() {
        let p = HeadFile::path_for_store(Path::new("/tmp/tpm.db"));
        assert_eq!(p, Path::new("/tmp/tpm.db.heads.json"));
    }
}
