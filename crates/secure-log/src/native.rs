//! The native Rust [`SecureLog`] implementation.
//!
//! Stores entries via a [`SecureLogStore`] implementation. Hash chain
//! invariants are enforced at append time by computing `entry_hash`
//! from the fully canonicalized entry bytes, and at verify time by
//! recomputing and comparing links across a range.
//!
//! `NativeSecureLog` is stateless apart from a reference to the
//! store, the encoder, and the current session/boot identifiers.
//! Concurrent writers are serialized by the store's own locking.
//!
//! The session_id rotates on each fresh `new` call, giving every
//! daemon/process restart a distinct identifier that appears in each
//! entry. This is how forensic tooling distinguishes a clean restart
//! from a continuity break.

use chrono::Utc;
use uuid::Uuid;

use std::path::{Path, PathBuf};

use crate::checkpoint;
use crate::crypto::{
    aead_aad, derive_segment_key, derive_stream_key, minimize_metadata, ConfidentialityTier,
    SealedPayload, SecretKey, AEAD_NAME,
};
use crate::encoder::{CanonicalEncoder, ENCODER_CBOR};
use crate::hash::{hex, sha256, EntryDigest, HASH_LEN, ZERO_HASH};
use crate::merkle;
use crate::model::{
    digest_from_vec, AppendResult, EntryFields, InclusionProof, ProofStep, SecureLogError,
    SegmentInfo, ENTRY_VERSION,
};
use crate::signer::CheckpointSigner;
use crate::store::{SecureLogRow, SecureLogSegmentRow, SecureLogStore};
use crate::witness::{HeadFile, HeadRecord};
use crate::SecureLog;

/// Native secure log implementation.
///
/// `NativeSecureLog` owns its [`SecureLogStore`] rather than sharing
/// one with the rest of the application. This is intentional:
/// rusqlite connections are `!Sync`, and the simplest way to keep the
/// [`SecureLog`] trait `Send`-able is to keep the store single-owner.
/// In production the daemon opens a dedicated connection for the
/// secure log; SQLite's WAL mode makes concurrent connections over
/// the same database file correct.
pub struct NativeSecureLog {
    store: Box<dyn SecureLogStore>,
    encoder: Box<dyn CanonicalEncoder>,
    /// Opaque identifier for the current daemon/process instance.
    /// Recorded in each entry to distinguish restarts from continuity
    /// breaks. Rotates on every `new` call.
    session_id: String,
    /// Opaque identifier for the current boot. In a future phase this
    /// can come from a trusted source (e.g. `/proc/sys/kernel/random/boot_id`
    /// on Linux, or TPM reset counter). For now it's derived at first
    /// construction and cached.
    boot_id: String,
    /// Optional path to the sibling anti-rollback head file. When
    /// set, `sign_segment` updates the head file after each successful
    /// signature, and the head file can be consulted by external
    /// tooling to detect rollback. See [`super::witness`].
    head_file: Option<PathBuf>,
    /// Optional master KEK for envelope encryption of payloads.
    /// When set, `append_encrypted` wraps payloads in
    /// ChaCha20-Poly1305 before delegating to the normal `append`,
    /// and `read_plaintext` / `open_payload` can decrypt entries
    /// that were stored with `payload_encoding = "cbor+aead-…"`.
    master_key: Option<SecretKey>,
}

impl NativeSecureLog {
    /// Create a new native log backed by the given store and encoder.
    ///
    /// A fresh session id is generated; the boot id is read from the
    /// platform if possible, otherwise a stable-per-process random
    /// value is used.
    pub fn new(store: Box<dyn SecureLogStore>, encoder: Box<dyn CanonicalEncoder>) -> Self {
        Self {
            store,
            encoder,
            session_id: Uuid::new_v4().to_string(),
            boot_id: detect_boot_id(),
            head_file: None,
            master_key: None,
        }
    }

    /// Install a master KEK for envelope encryption. Without one,
    /// calls to `append_encrypted` return [`SecureLogError::Invalid`].
    pub fn with_master_key(mut self, master: SecretKey) -> Self {
        self.master_key = Some(master);
        self
    }

    /// Enable anti-rollback head file tracking at the given path.
    /// Pass [`HeadFile::path_for_store`] for the default location.
    pub fn with_head_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.head_file = Some(path.into());
        self
    }

    /// Return the path of the anti-rollback head file, if any.
    pub fn head_file_path(&self) -> Option<&Path> {
        self.head_file.as_deref()
    }

    /// Load the current head file record for a stream, if present.
    /// Useful for CLI callers that want to report anti-rollback state.
    pub fn head_record(&self, stream_id: &str) -> Result<Option<HeadRecord>, SecureLogError> {
        let Some(ref path) = self.head_file else {
            return Ok(None);
        };
        let hf = HeadFile::load(path).map_err(|e| SecureLogError::Storage(e.to_string()))?;
        Ok(hf.get(stream_id).cloned())
    }

    /// Override the session id (primarily for tests that want
    /// determinism across runs).
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Override the boot id (primarily for tests).
    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = boot_id.into();
        self
    }

    /// Session id currently in use.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Boot id currently in use.
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Expose a read-only reference to the underlying store.
    pub fn store(&self) -> &dyn SecureLogStore {
        self.store.as_ref()
    }

    /// Expose the encoder so Phase 3 callers can rebuild checkpoint
    /// bytes for signing / verification without duplicating the
    /// pluggability machinery.
    pub fn encoder(&self) -> &dyn CanonicalEncoder {
        self.encoder.as_ref()
    }

    // -- Phase 5: envelope-encrypted payloads ---------------------

    /// Append an entry whose payload is encrypted under an AEAD
    /// key derived from the configured master KEK.
    ///
    /// The ciphertext replaces the plaintext in the stored row and
    /// also appears in the canonical bytes used for the hash chain,
    /// so chain verification works without the decryption key.
    ///
    /// Returns an error if no master KEK has been installed via
    /// [`Self::with_master_key`].
    ///
    /// Note on segment scope: payloads are encrypted under a
    /// *segment*-level key derived from the stream key. But the
    /// segment_id isn't assigned until `close_segment` runs. For
    /// Phase 5 we derive the segment key from the **current open
    /// segment_id**, which is defined as `(last closed segment_id) + 1`.
    /// If the log is later reorganized, the caller must re-close with the
    /// same ordering.
    pub fn append_encrypted(
        &self,
        stream_id: &str,
        event_type: &str,
        severity: &str,
        producer: &str,
        plaintext: &[u8],
    ) -> Result<AppendResult, SecureLogError> {
        self.reject_if_deprecated(stream_id)?;
        let master = self
            .master_key
            .as_ref()
            .ok_or_else(|| SecureLogError::Invalid("no master KEK configured".into()))?;

        // Current open segment: last_segment_id + 1, or 1 for
        // first-ever entry.
        let segment_for_entry = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .last()
            .and_then(|s| s.segment_id)
            .map(|n| n + 1)
            .unwrap_or(1);

        // Look up the stream's current tier so the derivation
        // binds to policy. Unknown streams fall back to public.
        let tier = self.resolve_tier(stream_id)?;

        let stream_key = derive_stream_key(master, stream_id, tier);
        let seg_key = derive_segment_key(&stream_key, segment_for_entry);

        // AAD pins stream_id + tier + segment_id. Lifting a row
        // across any of those fails AEAD authentication.
        let aad = aead_aad(stream_id, tier, segment_for_entry);

        let sealed = SealedPayload::seal(&seg_key, aad.as_bytes(), plaintext)
            .map_err(SecureLogError::Encoding)?;

        // For highly-restricted streams, replace event_type and
        // producer with keyed-hash tags so a DB breach cannot reveal
        // which events occurred or who emitted them. The originals
        // are never persisted. A verifier with the master KEK can
        // re-derive the tag for any candidate (event_type, producer)
        // value and query by equality.
        let (stored_event_type, stored_producer) = match tier {
            ConfidentialityTier::HighlyRestricted => (
                minimize_metadata(master, stream_id, "event_type", event_type),
                minimize_metadata(master, stream_id, "producer", producer),
            ),
            _ => (event_type.to_string(), producer.to_string()),
        };

        // Call the regular append, but with the ciphertext as the
        // payload and an encoding tag that marks it as sealed.
        //
        // The normal `SecureLog::append` records `payload_encoding
        // = self.encoder.name()` (i.e. "cbor"). We override by
        // temporarily constructing the row ourselves — mirroring
        // the exact sequence in `append`.
        let prev_hash: EntryDigest = match self
            .store
            .secure_log_last(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
        {
            Some(prev) => digest_from_vec(prev.entry_hash, "prev_entry_hash from store")?,
            None => ZERO_HASH,
        };
        let next_seqno = self
            .store
            .secure_log_global_head()
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .map(|h| h + 1)
            .unwrap_or(1);

        let timestamp = Utc::now().to_rfc3339();
        let fields = EntryFields {
            version: ENTRY_VERSION,
            stream_id: stream_id.to_string(),
            session_id: self.session_id.clone(),
            boot_id: self.boot_id.clone(),
            seqno: next_seqno,
            timestamp_rfc3339: timestamp.clone(),
            event_type: stored_event_type,
            severity: severity.to_string(),
            producer: stored_producer,
            payload_encoding: AEAD_NAME.to_string(),
            payload: sealed.bytes.clone(),
            prev_entry_hash: prev_hash.to_vec(),
        };
        let canonical = self.encoder.encode_entry(&fields);
        let entry_hash = sha256(&canonical);

        let row = SecureLogRow {
            seqno: Some(next_seqno),
            stream_id: fields.stream_id.clone(),
            session_id: fields.session_id.clone(),
            boot_id: fields.boot_id.clone(),
            timestamp_rfc3339: fields.timestamp_rfc3339.clone(),
            event_type: fields.event_type.clone(),
            severity: fields.severity.clone(),
            producer: fields.producer.clone(),
            payload_encoding: fields.payload_encoding.clone(),
            payload: fields.payload.clone(),
            prev_entry_hash: fields.prev_entry_hash.clone(),
            entry_hash: entry_hash.to_vec(),
        };

        let assigned = self
            .store
            .secure_log_insert(&row)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        if assigned != next_seqno {
            return Err(SecureLogError::Storage(format!(
                "store assigned seqno {} but we committed {} in the hash",
                assigned, next_seqno
            )));
        }

        Ok(AppendResult {
            seqno: next_seqno,
            entry_hash,
        })
    }

    /// Decrypt the payload of a previously-appended encrypted entry.
    ///
    /// Returns the plaintext payload bytes. Errors if:
    /// - `seqno` does not exist;
    /// - the entry's `payload_encoding` does not match the AEAD tag;
    /// - no master KEK has been configured;
    /// - the derived segment key does not authenticate the payload
    ///   (wrong master key, wrong segment, tampered ciphertext).
    ///
    /// Public-tier (plaintext) entries are returned as-is.
    pub fn open_payload(&self, seqno: u64) -> Result<Vec<u8>, SecureLogError> {
        let entry = self.read(seqno)?;
        if entry.payload_encoding == ENCODER_CBOR {
            return Ok(entry.payload);
        }
        if entry.payload_encoding != AEAD_NAME {
            return Err(SecureLogError::Invalid(format!(
                "unknown payload_encoding: '{}'",
                entry.payload_encoding
            )));
        }
        let master = self
            .master_key
            .as_ref()
            .ok_or_else(|| SecureLogError::Invalid("no master KEK configured".into()))?;

        // Recover the segment that owns this seqno. For an entry
        // that has already been placed into a closed segment, we
        // look it up directly. For an entry that is still in the
        // open (unclosed) segment, we reuse the same "next segment
        // id" computation that append_encrypted used.
        let segment_for_entry = match self
            .store
            .secure_log_segment_for_seqno(seqno)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
        {
            Some(sid) => sid,
            None => self
                .store
                .secure_log_segments_list(&entry.stream_id)
                .map_err(|e| SecureLogError::Storage(e.to_string()))?
                .last()
                .and_then(|s| s.segment_id)
                .map(|n| n + 1)
                .unwrap_or(1),
        };

        let tier = self.resolve_tier(&entry.stream_id)?;
        let stream_key = derive_stream_key(master, &entry.stream_id, tier);
        let seg_key = derive_segment_key(&stream_key, segment_for_entry);
        let aad = aead_aad(&entry.stream_id, tier, segment_for_entry);
        SealedPayload::open(&entry.payload, &seg_key, aad.as_bytes())
            .map_err(SecureLogError::Encoding)
    }

    /// Resolve the confidentiality tier for a given stream, consulting
    /// the `secure_log_streams` metadata table. Streams that have no
    /// row fall back to [`ConfidentialityTier::Public`] — that matches
    /// the CLI warning behavior and preserves cross-session
    /// decryptability for legacy or ad-hoc streams.
    fn resolve_tier(&self, stream_id: &str) -> Result<ConfidentialityTier, SecureLogError> {
        let row = self
            .store
            .secure_log_stream_get(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        match row {
            Some(r) => r.tier.parse::<ConfidentialityTier>().map_err(|e| {
                SecureLogError::Invalid(format!(
                    "stream '{}' has invalid tier '{}': {}",
                    stream_id, r.tier, e
                ))
            }),
            None => Ok(ConfidentialityTier::Public),
        }
    }

    /// Return an error if the given stream has been deprecated.
    fn reject_if_deprecated(&self, stream_id: &str) -> Result<(), SecureLogError> {
        match self
            .store
            .secure_log_stream_get(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
        {
            Some(row) if row.deprecated_at_rfc3339.is_some() => {
                Err(SecureLogError::Invalid(format!(
                    "stream '{}' is deprecated and no longer accepts new entries (deprecated {})",
                    stream_id,
                    row.deprecated_at_rfc3339.unwrap()
                )))
            }
            _ => Ok(()),
        }
    }

    // -- Phase 3: TPM-signed checkpoints --------------------------

    /// Sign a closed segment's checkpoint hash with the given
    /// signer, and persist the signature.
    ///
    /// This is an inherent method rather than part of the
    /// [`SecureLog`] trait because it requires a
    /// [`CheckpointSigner`]. A future WIT revision can lift the
    /// signer into the component world; today the caller wires it in.
    pub fn sign_segment(
        &self,
        signer: &dyn CheckpointSigner,
        identity_name: &str,
        segment_id: u64,
    ) -> Result<(EntryDigest, Vec<u8>), SecureLogError> {
        let segment = self
            .store
            .secure_log_segment_get(segment_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::SegmentNotFound(segment_id))?;
        let segment_info = segment_row_to_info(&segment)?;

        // Compute prev_checkpoint_hash: checkpoint hash of the
        // previous segment in this stream, if any.
        let prev_ckpt = self.previous_checkpoint_hash(&segment.stream_id, segment_id)?;

        // session_id / boot_id come from the segment's last entry,
        // not from this NativeSecureLog instance. A verifier running
        // later will have different instance-level values — so
        // embedding the current ones would make verification
        // non-repeatable across restarts.
        let (session_id, boot_id) = self.session_and_boot_for_segment(&segment_info)?;

        let fields =
            checkpoint::build_fields(&segment_info, prev_ckpt, &boot_id, &session_id, ZERO_HASH);
        let ckpt_hash = checkpoint::hash(self.encoder.as_ref(), &fields);

        let (signature, signer_identity) = signer
            .sign_checkpoint(identity_name, &ckpt_hash)
            .map_err(|e| SecureLogError::Invalid(format!("sign failed: {}", e)))?;

        self.store
            .secure_log_segment_set_signature(segment_id, &signature, &signer_identity)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;

        // Anti-rollback: update the head file (if configured).
        if let Some(ref path) = self.head_file {
            let mut hf =
                HeadFile::load(path).map_err(|e| SecureLogError::Storage(e.to_string()))?;
            hf.version = HeadFile::VERSION;
            hf.upsert(HeadRecord {
                stream_id: segment.stream_id.clone(),
                segment_id,
                seq_end: segment_info.seq_end,
                checkpoint_hash_hex: hex(&ckpt_hash),
                updated_at_rfc3339: Utc::now().to_rfc3339(),
            });
            hf.save(path)
                .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        }

        Ok((ckpt_hash, signature))
    }

    /// Build a witness submission payload for the current head of
    /// a stream. Returns an error if the stream has no signed
    /// segments. The payload is a value object — transport is out
    /// of scope for this function, the caller POSTs it to whatever
    /// witness service they're using.
    pub fn build_witness_submission(
        &self,
        stream_id: &str,
    ) -> Result<super::witness::WitnessSubmission, SecureLogError> {
        let segments = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        let segment = segments
            .into_iter()
            .rev()
            .find(|s| s.signature.is_some())
            .ok_or_else(|| {
                SecureLogError::Invalid(format!(
                    "stream '{}' has no signed segments to publish",
                    stream_id
                ))
            })?;
        let segment_id = segment
            .segment_id
            .ok_or_else(|| SecureLogError::Storage("segment row has no id".into()))?;
        let ckpt_hash = self.compute_checkpoint_hash_for(stream_id, segment_id)?;
        let signature = segment
            .signature
            .clone()
            .expect("filtered for signature above");
        let signer_identity = segment.signer_identity.clone().ok_or_else(|| {
            SecureLogError::Invalid("signed segment has no signer identity".into())
        })?;

        Ok(super::witness::WitnessSubmission {
            stream_id: segment.stream_id,
            segment_id,
            seq_start: segment.seq_start,
            seq_end: segment.seq_end,
            checkpoint_hash_hex: hex(&ckpt_hash),
            signature_hex: signature.iter().map(|b| format!("{:02x}", b)).collect(),
            signer_identity,
        })
    }

    /// Verify a witness submission received from an external
    /// witness: confirm that the stream's local checkpoint chain
    /// extends or matches the remote record. Returns
    /// `Ok(true)` if the remote is an exact match, `Ok(false)` if
    /// the remote is an older valid ancestor (the local chain has
    /// moved forward), or an error if they diverge.
    pub fn verify_against_witness(
        &self,
        submission: &super::witness::WitnessSubmission,
    ) -> Result<bool, SecureLogError> {
        let remote_hash = submission.checkpoint_hash_hex.clone();
        let local_hash =
            self.compute_checkpoint_hash_for(&submission.stream_id, submission.segment_id)?;
        let local_hex = hex(&local_hash);
        if remote_hash == local_hex {
            return Ok(true);
        }
        // Local says a different thing at the same segment_id →
        // either the remote witnessed a stale fork, or the local
        // database has been tampered with.
        Err(SecureLogError::ChainBroken {
            seqno: submission.seq_end,
            reason: format!(
                "witness divergence at segment {}: remote={} local={}",
                submission.segment_id, remote_hash, local_hex
            ),
        })
    }

    /// Detect rollback: compare the stored head file record for a
    /// stream against the highest checkpoint in the live database.
    /// Returns `Ok(())` if they match (or the head file has no record
    /// for this stream), `Err(ChainBroken)` if the stored head has a
    /// higher seq_end than the database can currently show.
    pub fn check_rollback(
        &self,
        signer: &dyn CheckpointSigner,
        stream_id: &str,
    ) -> Result<(), SecureLogError> {
        let Some(record) = self.head_record(stream_id)? else {
            return Ok(());
        };
        // Is the database state consistent with the head file?
        let db_segments = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        let highest = db_segments.last().and_then(|s| s.segment_id).unwrap_or(0);
        if highest < record.segment_id {
            return Err(SecureLogError::ChainBroken {
                seqno: record.seq_end,
                reason: format!(
                    "rollback detected: head file records segment {} but database only has up to {}",
                    record.segment_id, highest
                ),
            });
        }
        // And the checkpoint hash must still compute to the same value.
        let computed = self.compute_checkpoint_hash_for(stream_id, record.segment_id)?;
        let stored_hash = record
            .checkpoint_hash()
            .ok_or_else(|| SecureLogError::Storage("head file hash is not 32 bytes".into()))?;
        if computed != stored_hash {
            return Err(SecureLogError::ChainBroken {
                seqno: record.seq_end,
                reason: format!(
                    "rollback detected: segment {} recomputes to a different checkpoint hash than head file records",
                    record.segment_id
                ),
            });
        }
        // And the signature at that segment must still verify.
        let _ = self.verify_segment_signature(signer, record.segment_id)?;
        Ok(())
    }

    /// Verify a single segment's signature against its canonical
    /// checkpoint hash.
    ///
    /// Delegates to [`CheckpointSigner::verify_checkpoint`] using
    /// the stored `signer_identity` from the segment row. The signer
    /// is responsible for resolving that identity back to the key
    /// material needed to verify.
    pub fn verify_segment_signature(
        &self,
        signer: &dyn CheckpointSigner,
        segment_id: u64,
    ) -> Result<EntryDigest, SecureLogError> {
        let segment = self
            .store
            .secure_log_segment_get(segment_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::SegmentNotFound(segment_id))?;
        let signature = segment.signature.clone().ok_or_else(|| {
            SecureLogError::Invalid(format!("segment {} is not signed", segment_id))
        })?;
        let signer_id = segment.signer_identity.clone().ok_or_else(|| {
            SecureLogError::Invalid(format!(
                "segment {} has signature but no signer identity",
                segment_id
            ))
        })?;

        // Recompute the canonical checkpoint hash.
        let info = segment_row_to_info(&segment)?;
        let prev_ckpt = self.previous_checkpoint_hash(&segment.stream_id, segment_id)?;
        let (session_id, boot_id) = self.session_and_boot_for_segment(&info)?;
        let fields = checkpoint::build_fields(&info, prev_ckpt, &boot_id, &session_id, ZERO_HASH);
        let ckpt_hash = checkpoint::hash(self.encoder.as_ref(), &fields);

        let ok = signer
            .verify_checkpoint(&signer_id, &ckpt_hash, &signature)
            .map_err(|e| SecureLogError::Invalid(format!("verify failed: {}", e)))?;
        if !ok {
            return Err(SecureLogError::ChainBroken {
                seqno: info.seq_end,
                reason: "checkpoint signature does not verify".into(),
            });
        }
        Ok(ckpt_hash)
    }

    /// Walk every segment of a stream from genesis to head,
    /// verifying:
    ///
    /// 1. Each segment is signed.
    /// 2. Each signature round-trips via the signer identity.
    /// 3. Each segment's `prev_checkpoint_hash` equals the previous
    ///    segment's checkpoint hash (recomputed from canonical bytes).
    pub fn verify_checkpoint_chain(
        &self,
        signer: &dyn CheckpointSigner,
        stream_id: &str,
    ) -> Result<usize, SecureLogError> {
        let segments = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        if segments.is_empty() {
            return Err(SecureLogError::StreamNotFound(stream_id.to_string()));
        }

        let mut prev_ckpt = ZERO_HASH;
        for seg in &segments {
            let sid = seg
                .segment_id
                .ok_or_else(|| SecureLogError::Storage("segment row has no id".into()))?;

            // Each segment's stored prev_checkpoint_hash must match
            // what we walked to here.
            let stored_prev = digest_from_vec(
                seg.prev_checkpoint_hash.clone(),
                "segment prev_checkpoint_hash",
            )?;
            if stored_prev != prev_ckpt {
                return Err(SecureLogError::ChainBroken {
                    seqno: seg.seq_end,
                    reason: format!(
                        "segment {} prev_checkpoint_hash drift: stored={} expected={}",
                        sid,
                        super::hash::hex(&stored_prev),
                        super::hash::hex(&prev_ckpt),
                    ),
                });
            }

            // Signature verification recomputes the checkpoint hash
            // as a side effect — use the result as the new prev for
            // the next iteration.
            let ckpt_hash = self.verify_segment_signature(signer, sid)?;
            prev_ckpt = ckpt_hash;
        }

        Ok(segments.len())
    }

    /// Return the checkpoint hash of the segment immediately before
    /// `segment_id` in `stream_id`, or [`ZERO_HASH`] if `segment_id`
    /// is the first segment of the stream.
    fn previous_checkpoint_hash(
        &self,
        stream_id: &str,
        segment_id: u64,
    ) -> Result<EntryDigest, SecureLogError> {
        let segments = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        let mut previous: Option<&SecureLogSegmentRow> = None;
        for s in &segments {
            if s.segment_id == Some(segment_id) {
                break;
            }
            previous = Some(s);
        }
        match previous {
            None => Ok(ZERO_HASH),
            Some(prev) => {
                let prev_id = prev
                    .segment_id
                    .ok_or_else(|| SecureLogError::Storage("segment row has no id".into()))?;
                self.compute_checkpoint_hash_for(stream_id, prev_id)
            }
        }
    }

    /// Compute (not look up) the checkpoint hash for the segment
    /// with the given id. Recursive: walks the chain backwards to
    /// get each predecessor's canonical prev_checkpoint_hash. Safe
    /// because segment chains are typically short (orders of
    /// magnitude smaller than the entry count).
    pub fn compute_checkpoint_hash_for(
        &self,
        stream_id: &str,
        segment_id: u64,
    ) -> Result<EntryDigest, SecureLogError> {
        let row = self
            .store
            .secure_log_segment_get(segment_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::SegmentNotFound(segment_id))?;
        let info = segment_row_to_info(&row)?;
        let prev_prev = self.previous_checkpoint_hash(stream_id, segment_id)?;
        let (session_id, boot_id) = self.session_and_boot_for_segment(&info)?;
        let fields = checkpoint::build_fields(&info, prev_prev, &boot_id, &session_id, ZERO_HASH);
        Ok(checkpoint::hash(self.encoder.as_ref(), &fields))
    }

    /// Derive the session_id and boot_id that should appear in a
    /// checkpoint's canonical form, from the segment's last entry.
    /// A segment's entries may span multiple sessions in theory, but
    /// the last entry is authoritative for the "what state was the
    /// daemon in when this segment closed" question.
    fn session_and_boot_for_segment(
        &self,
        info: &SegmentInfo,
    ) -> Result<(String, String), SecureLogError> {
        let last = self
            .store
            .secure_log_get(info.seq_end)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::EntryNotFound(info.seq_end))?;
        Ok((last.session_id, last.boot_id))
    }

    fn row_to_entry(row: &SecureLogRow) -> Result<EntryFields, SecureLogError> {
        Ok(EntryFields {
            version: ENTRY_VERSION,
            stream_id: row.stream_id.clone(),
            session_id: row.session_id.clone(),
            boot_id: row.boot_id.clone(),
            seqno: row
                .seqno
                .ok_or_else(|| SecureLogError::Storage("row has no seqno".into()))?,
            timestamp_rfc3339: row.timestamp_rfc3339.clone(),
            event_type: row.event_type.clone(),
            severity: row.severity.clone(),
            producer: row.producer.clone(),
            payload_encoding: row.payload_encoding.clone(),
            payload: row.payload.clone(),
            prev_entry_hash: row.prev_entry_hash.clone(),
        })
    }
}

/// Platform-specific boot identifier lookup. Falls back to a random
/// per-process value so the field is always populated.
fn detect_boot_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return s.trim().to_string();
        }
    }
    // Fallback: one random id per process lifetime.
    format!("rand-{}", Uuid::new_v4())
}

impl SecureLog for NativeSecureLog {
    fn append(
        &self,
        stream_id: &str,
        event_type: &str,
        severity: &str,
        producer: &str,
        payload: &[u8],
    ) -> Result<AppendResult, SecureLogError> {
        // Reject appends to deprecated streams. Deprecation is a
        // soft delete — existing entries remain verifiable, but
        // the write channel is closed.
        self.reject_if_deprecated(stream_id)?;

        // Chain continuity is per-stream: look up the last entry in
        // THIS stream, regardless of what other streams have done.
        let prev_hash: EntryDigest = match self
            .store
            .secure_log_last(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
        {
            Some(prev) => digest_from_vec(prev.entry_hash, "prev_entry_hash from store")?,
            None => ZERO_HASH,
        };

        // Seqno namespace is GLOBAL across all streams so every row
        // has a unique primary key, but it's monotonic: each new
        // entry gets (global_max + 1). Per-stream sequences may be
        // sparse as a result, which is fine because chain hash links
        // are what enforce ordering, not integer contiguity.
        //
        // For a single-stream workload the seqnos are contiguous.
        let next_seqno = self
            .store
            .secure_log_global_head()
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .map(|h| h + 1)
            .unwrap_or(1);

        let timestamp = Utc::now().to_rfc3339();
        let fields = EntryFields {
            version: ENTRY_VERSION,
            stream_id: stream_id.to_string(),
            session_id: self.session_id.clone(),
            boot_id: self.boot_id.clone(),
            seqno: next_seqno,
            timestamp_rfc3339: timestamp.clone(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            producer: producer.to_string(),
            payload_encoding: self.encoder.name().to_string(),
            payload: payload.to_vec(),
            prev_entry_hash: prev_hash.to_vec(),
        };
        let canonical = self.encoder.encode_entry(&fields);
        let entry_hash = sha256(&canonical);

        let row = SecureLogRow {
            seqno: Some(next_seqno),
            stream_id: fields.stream_id.clone(),
            session_id: fields.session_id.clone(),
            boot_id: fields.boot_id.clone(),
            timestamp_rfc3339: fields.timestamp_rfc3339.clone(),
            event_type: fields.event_type.clone(),
            severity: fields.severity.clone(),
            producer: fields.producer.clone(),
            payload_encoding: fields.payload_encoding.clone(),
            payload: fields.payload.clone(),
            prev_entry_hash: fields.prev_entry_hash.clone(),
            entry_hash: entry_hash.to_vec(),
        };

        let assigned = self
            .store
            .secure_log_insert(&row)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;

        // Defensive: if the store somehow reassigned the seqno, that
        // would invalidate our hash. Reject rather than silently
        // lying about what was stored.
        if assigned != next_seqno {
            return Err(SecureLogError::Storage(format!(
                "store assigned seqno {} but we committed {} in the hash",
                assigned, next_seqno
            )));
        }

        Ok(AppendResult {
            seqno: next_seqno,
            entry_hash,
        })
    }

    fn read(&self, seqno: u64) -> Result<EntryFields, SecureLogError> {
        let row = self
            .store
            .secure_log_get(seqno)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::EntryNotFound(seqno))?;
        Self::row_to_entry(&row)
    }

    fn head(&self, stream_id: &str) -> Result<Option<u64>, SecureLogError> {
        self.store
            .secure_log_head(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))
    }

    fn verify_chain(&self, stream_id: &str, from: u64, to: u64) -> Result<(), SecureLogError> {
        if from > to {
            return Err(SecureLogError::Invalid(format!(
                "verify_chain: from ({}) > to ({})",
                from, to
            )));
        }

        // Pull all rows for this stream in `[from, to]`. Per-stream
        // seqnos may be sparse (interleaved with other streams in the
        // global namespace), so we don't require contiguous integers
        // here — we only require that each row's prev_entry_hash
        // matches the previous row we walked in this stream.
        let rows = self
            .store
            .secure_log_range(stream_id, from, to)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;

        if rows.is_empty() {
            return Err(SecureLogError::StreamNotFound(stream_id.to_string()));
        }

        // To validate the first row's prev_entry_hash we must know
        // what its actual in-stream predecessor is. Look up the
        // highest seqno < `first.seqno` for this stream. If there is
        // none, the expected prev is ZERO_HASH (genesis).
        let first_seqno = rows.first().and_then(|r| r.seqno).unwrap_or(from);
        let expected_first_prev: EntryDigest = if first_seqno > 1 {
            // Efficient path: ask for all rows strictly before first_seqno
            // in this stream and take the last one. For Phase 1's
            // workloads this range is small; Phase 2 can add an
            // explicit `secure_log_prev_in_stream` if profiling shows
            // it matters.
            let before = self
                .store
                .secure_log_range(stream_id, 1, first_seqno - 1)
                .map_err(|e| SecureLogError::Storage(e.to_string()))?;
            match before.last() {
                Some(r) => digest_from_vec(r.entry_hash.clone(), "predecessor entry_hash")?,
                None => ZERO_HASH,
            }
        } else {
            ZERO_HASH
        };

        let mut previous_entry_hash = expected_first_prev;

        for row in &rows {
            let seqno = row
                .seqno
                .ok_or_else(|| SecureLogError::Storage("row has no seqno".into()))?;

            // Check prev_entry_hash linkage.
            let stored_prev = digest_from_vec(row.prev_entry_hash.clone(), "row prev_entry_hash")?;
            if stored_prev != previous_entry_hash {
                return Err(SecureLogError::ChainBroken {
                    seqno,
                    reason: format!(
                        "prev_entry_hash mismatch: stored={} expected={}",
                        super::hash::hex(&stored_prev),
                        super::hash::hex(&previous_entry_hash),
                    ),
                });
            }

            // Re-encode and re-hash to verify content wasn't tampered.
            let fields = Self::row_to_entry(row)?;
            let canonical = self.encoder.encode_entry(&fields);
            let recomputed = sha256(&canonical);
            let stored_hash = digest_from_vec(row.entry_hash.clone(), "stored entry_hash")?;
            if recomputed != stored_hash {
                return Err(SecureLogError::ChainBroken {
                    seqno,
                    reason: format!(
                        "entry content does not match stored hash: recomputed={} stored={}",
                        super::hash::hex(&recomputed),
                        super::hash::hex(&stored_hash),
                    ),
                });
            }

            previous_entry_hash = stored_hash;
        }

        Ok(())
    }

    fn close_segment(&self, stream_id: &str) -> Result<SegmentInfo, SecureLogError> {
        // seq_start: one past the last segment's seq_end, or the
        // first entry in the stream if there are no segments yet.
        let last_covered = self
            .store
            .secure_log_segment_last_seqno(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        let seq_start = last_covered.map(|n| n + 1).unwrap_or(1);

        // seq_end: the current head. Range [seq_start, seq_end] is
        // what the new segment covers.
        let head = self
            .store
            .secure_log_head(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or_else(|| SecureLogError::EmptySegment(stream_id.to_string()))?;

        if head < seq_start {
            return Err(SecureLogError::EmptySegment(stream_id.to_string()));
        }

        // Pull the entries in this stream within the range.
        let rows = self
            .store
            .secure_log_range(stream_id, seq_start, head)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        if rows.is_empty() {
            return Err(SecureLogError::EmptySegment(stream_id.to_string()));
        }

        // Build leaf vector (entry_hash in order).
        let mut leaves = Vec::with_capacity(rows.len());
        let mut entries_index = Vec::with_capacity(rows.len());
        for (leaf_index, row) in rows.iter().enumerate() {
            let hash = digest_from_vec(row.entry_hash.clone(), "row entry_hash")?;
            leaves.push(hash);
            let seqno = row
                .seqno
                .ok_or_else(|| SecureLogError::Storage("row has no seqno".into()))?;
            entries_index.push((seqno, leaf_index as u64));
        }

        let merkle_root = merkle::build_root(&leaves);
        let last_entry_hash = *leaves
            .last()
            .expect("non-empty by empty-segment check above");

        // Previous checkpoint hash: H(canonical checkpoint bytes)
        // of the most recent closed segment, or ZERO_HASH for
        // genesis. Computed dynamically so signing and verification
        // agree without relying on the stored Merkle root.
        let prev_segments = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        let prev_checkpoint_hash: EntryDigest = match prev_segments.last() {
            Some(prev) => {
                let prev_id = prev
                    .segment_id
                    .ok_or_else(|| SecureLogError::Storage("segment row has no id".into()))?;
                self.compute_checkpoint_hash_for(stream_id, prev_id)?
            }
            None => ZERO_HASH,
        };

        let row = SecureLogSegmentRow {
            segment_id: None,
            stream_id: stream_id.to_string(),
            seq_start: rows.first().and_then(|r| r.seqno).unwrap_or(seq_start),
            seq_end: head,
            merkle_root: merkle_root.to_vec(),
            last_entry_hash: last_entry_hash.to_vec(),
            prev_checkpoint_hash: prev_checkpoint_hash.to_vec(),
            closed_at_rfc3339: Utc::now().to_rfc3339(),
            signature: None,
            signer_identity: None,
        };

        let segment_id = self
            .store
            .secure_log_segment_insert(&row, &entries_index)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;

        Ok(SegmentInfo {
            segment_id,
            stream_id: stream_id.to_string(),
            seq_start: row.seq_start,
            seq_end: row.seq_end,
            merkle_root,
            last_entry_hash,
            prev_checkpoint_hash,
            closed_at_rfc3339: row.closed_at_rfc3339,
            signature: Vec::new(),
            signer_identity: None,
        })
    }

    fn list_segments(&self, stream_id: &str) -> Result<Vec<SegmentInfo>, SecureLogError> {
        let rows = self
            .store
            .secure_log_segments_list(stream_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;
        rows.iter().map(segment_row_to_info).collect()
    }

    fn read_segment(&self, segment_id: u64) -> Result<SegmentInfo, SecureLogError> {
        let row = self
            .store
            .secure_log_segment_get(segment_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::SegmentNotFound(segment_id))?;
        segment_row_to_info(&row)
    }

    fn inclusion_proof(&self, seqno: u64) -> Result<InclusionProof, SecureLogError> {
        let segment_id = self
            .store
            .secure_log_segment_for_seqno(seqno)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?
            .ok_or(SecureLogError::EntryNotFound(seqno))?;

        let seqnos = self
            .store
            .secure_log_segment_entry_seqnos(segment_id)
            .map_err(|e| SecureLogError::Storage(e.to_string()))?;

        // Rebuild the leaf vector in leaf-index order so the proof
        // path generation matches the original build_root invocation.
        let mut leaves = Vec::with_capacity(seqnos.len());
        let mut leaf_index: Option<usize> = None;
        for (i, s) in seqnos.iter().enumerate() {
            let row = self
                .store
                .secure_log_get(*s)
                .map_err(|e| SecureLogError::Storage(e.to_string()))?
                .ok_or(SecureLogError::EntryNotFound(*s))?;
            leaves.push(digest_from_vec(row.entry_hash, "entry_hash")?);
            if *s == seqno {
                leaf_index = Some(i);
            }
        }
        let leaf_index = leaf_index.ok_or(SecureLogError::EntryNotFound(seqno))?;
        let entry_hash = leaves[leaf_index];
        let (root, path) = merkle::build_proof(&leaves, leaf_index);

        Ok(InclusionProof {
            seqno,
            entry_hash,
            segment_id,
            merkle_root: root,
            path,
        })
    }
}

fn segment_row_to_info(row: &SecureLogSegmentRow) -> Result<SegmentInfo, SecureLogError> {
    Ok(SegmentInfo {
        segment_id: row
            .segment_id
            .ok_or_else(|| SecureLogError::Storage("segment row has no id".into()))?,
        stream_id: row.stream_id.clone(),
        seq_start: row.seq_start,
        seq_end: row.seq_end,
        merkle_root: digest_from_vec(row.merkle_root.clone(), "merkle_root")?,
        last_entry_hash: digest_from_vec(row.last_entry_hash.clone(), "last_entry_hash")?,
        prev_checkpoint_hash: digest_from_vec(
            row.prev_checkpoint_hash.clone(),
            "prev_checkpoint_hash",
        )?,
        closed_at_rfc3339: row.closed_at_rfc3339.clone(),
        signature: row.signature.clone().unwrap_or_default(),
        signer_identity: row.signer_identity.clone(),
    })
}

// Silence the unused import warning for `ProofStep` when segment
// tests aren't enabled; ProofStep is used transitively via
// InclusionProof but not named in this file otherwise.
#[allow(dead_code)]
type _ProofStepAlias = ProofStep;

// Suppress the unused-const warning when phase 1 tests compile.
#[allow(dead_code)]
const _HASH_LEN_USED_BY_CONSUMERS: usize = HASH_LEN;
