//! Tamper-evident audit log.
//!
//! This crate provides the Rust-native implementation of the
//! `secure-log:log@0.1.0` WIT contract defined in `wit/log.wit`.
//! Every trait here mirrors a WIT interface function 1:1, so a WASM
//! component implementing the WIT world is a drop-in replacement.
//!
//! ## Pluggability axes
//!
//! - [`CanonicalEncoder`] mirrors the WIT `encoder` interface.
//!   Implementations produce deterministic byte sequences for entries
//!   and checkpoints. [`CborEncoder`] is the default.
//!
//! - [`SecureLog`] mirrors the WIT `log` interface. Implementations
//!   own storage and integrity enforcement. [`NativeSecureLog`] is
//!   the default native implementation; it requires a backing store
//!   that implements [`SecureLogStore`].
//!
//! - [`SecureLogStore`] is the persistence trait. The companion
//!   `secure-log-sqlite` crate ships a SQLite implementation.
//!
//! - [`CheckpointSigner`] abstracts Phase 3 checkpoint signing.
//!   Consumers wire in their own implementation (TPM, HSM, file-based
//!   Ed25519, etc.).
//!
//! ## Layering
//!
//! ```text
//! canonical event → per-entry hash chain → Merkle-sealed segments →
//!   signed checkpoint chain → external witnessing → anti-rollback
//! ```
//!
//! Phase 1 implements entry + hash chain.
//! Phase 2 adds Merkle segments and inclusion proofs.
//! Phase 3 adds checkpoint signing via [`CheckpointSigner`].
//! Phase 4 adds witness + anti-rollback head file.
//! Phase 5 adds optional payload AEAD encryption.
//!
//! The WIT file is the authoritative contract. Changing these traits
//! without updating the WIT (and bumping the package version) is a bug.

pub mod checkpoint;
pub mod crypto;
pub mod encoder;
pub mod hash;
pub mod merkle;
pub mod model;
pub mod native;
pub mod signer;
pub mod store;
#[cfg(feature = "wasm-encoder")]
pub mod wasm_encoder;
pub mod witness;

pub use encoder::{CanonicalEncoder, CborEncoder, ENCODER_CBOR};
pub use hash::{sha256, EntryDigest, HASH_LEN, ZERO_HASH};
pub use model::{
    AppendResult, CheckpointFields, EntryFields, InclusionProof, ProofStep, SecureLogError,
    SegmentInfo, Severity, StreamInfo, CHECKPOINT_VERSION, ENTRY_VERSION,
};
pub use native::NativeSecureLog;
pub use signer::{CheckpointSigner, SignerError};
pub use store::{
    SecureLogRow, SecureLogSegmentRow, SecureLogStore, SecureLogStreamRow, WitnessLogRow,
};

/// The pluggable secure log backend.
///
/// Mirrors the WIT `log` interface. Phase 1 implementations must
/// support `append`, `read`, `head`, and `verify_chain`. Phase 2
/// adds segment and inclusion-proof methods.
///
/// Only `Send` is required — callers that need concurrent access
/// should wrap the backend in a [`std::sync::Mutex`]. SQLite-backed
/// stores are `!Sync`, so mandating `Sync` here would exclude them.
pub trait SecureLog: Send {
    /// Append a new entry to the given stream.
    ///
    /// Implementations assign the sequence number, compute the
    /// chain-hash link, and persist. The returned [`AppendResult`]
    /// reflects what was actually stored.
    fn append(
        &self,
        stream_id: &str,
        event_type: &str,
        severity: Severity,
        producer: &str,
        payload: &[u8],
    ) -> Result<AppendResult, SecureLogError>;

    /// Append with an explicit `payload_encoding` override. The
    /// stamped tag lands verbatim in the sealed row (and is hashed
    /// into the chain), instead of the default value derived from
    /// the impl's canonical encoder identity.
    ///
    /// Consumers that layer their own on-payload encoding (e.g.
    /// `wasmos:audit@0.1.0/audit` which wraps events in the ADR-0016
    /// `wasmos-audit-cbor-v1` envelope before calling `append`)
    /// pass the wire tag here so verifiers can dispatch decoding on
    /// the appropriate schema.
    ///
    /// The default impl ignores `payload_encoding` and delegates to
    /// [`append`](Self::append) — backwards-compatible with impls
    /// that predate this method. Impls that want to honor the
    /// override MUST override this method.
    ///
    /// # Errors
    ///
    /// Same failure surface as [`append`](Self::append).
    fn append_with_encoding(
        &self,
        stream_id: &str,
        event_type: &str,
        severity: Severity,
        producer: &str,
        payload: &[u8],
        _payload_encoding: &str,
    ) -> Result<AppendResult, SecureLogError> {
        // Default: ignore the override, delegate to append.
        // NativeSecureLog overrides this method to honor the tag.
        self.append(stream_id, event_type, severity, producer, payload)
    }

    /// Read a single entry by sequence number.
    fn read(&self, seqno: u64) -> Result<EntryFields, SecureLogError>;

    /// Highest sequence number in the given stream, or `None` if empty.
    fn head(&self, stream_id: &str) -> Result<Option<u64>, SecureLogError>;

    /// Verify the hash chain between `from` and `to` (inclusive).
    ///
    /// Returns `Ok(())` if every link resolves, or an error identifying
    /// the first broken link.
    fn verify_chain(&self, stream_id: &str, from: u64, to: u64) -> Result<(), SecureLogError>;

    /// Close the current open segment and build a Merkle root.
    fn close_segment(&self, stream_id: &str) -> Result<SegmentInfo, SecureLogError>;

    /// List all closed segments for a stream.
    fn list_segments(&self, stream_id: &str) -> Result<Vec<SegmentInfo>, SecureLogError>;

    /// Read a single segment by id.
    fn read_segment(&self, segment_id: u64) -> Result<SegmentInfo, SecureLogError>;

    /// Build an inclusion proof for an entry within its segment.
    fn inclusion_proof(&self, seqno: u64) -> Result<InclusionProof, SecureLogError>;

    /// Create or update a stream's metadata (tier + description).
    ///
    /// If the stream doesn't exist, it's created; if it does, the row
    /// is updated. Idempotent — calling twice with the same
    /// (`tier`, `description`) is a no-op on the resulting state.
    ///
    /// Streams also come into existence lazily on first
    /// [`append`](Self::append), but the row created that way defaults
    /// to `tier = "public"` and no description. Explicit
    /// `create_stream` lets an operator pin a tier BEFORE any appends
    /// land — which drives Phase-5 AEAD derivation for encrypted
    /// streams (`highly-restricted` binds the derived segment key to a
    /// different KDF label than `public`, and a mid-stream tier flip
    /// would silently invalidate every prior entry's decrypt key).
    ///
    /// Default impl returns
    /// `Err(Invalid("stream lifecycle not supported"))`; backends that
    /// expose stream metadata (as the SQLite-backed
    /// [`NativeSecureLog`] does) override.
    fn create_stream(
        &self,
        stream_id: &str,
        tier: &str,
        description: Option<&str>,
    ) -> Result<(), SecureLogError> {
        let _ = (stream_id, tier, description);
        Err(SecureLogError::Invalid(
            "stream lifecycle not supported by this backend".into(),
        ))
    }

    /// Enumerate every stream known to the backend, including
    /// deprecated ones.
    ///
    /// Callers isolate live vs archived by filtering on
    /// `deprecated_at.is_some()`. Order is backend-defined; the
    /// canonical native impl returns rows in the order the store
    /// returns them (typically creation order for the SQLite backend).
    ///
    /// Default impl returns `Ok(vec![])` — the safest fallback for
    /// backends that don't track streams. Following the
    /// `append_with_encoding` pattern, backends that DO track streams
    /// override; older backends compiled against a pre-lifecycle
    /// trait keep working.
    fn list_streams(&self) -> Result<Vec<StreamInfo>, SecureLogError> {
        Ok(Vec::new())
    }

    /// Soft-delete a stream: subsequent appends are rejected with
    /// `Invalid("stream '<id>' is deprecated ...")`. Existing entries
    /// remain readable and their hash chain is unchanged, so
    /// verification continues to work; only new appends are blocked.
    ///
    /// The deprecation timestamp is stamped by the backend at call
    /// time (backends record it in whatever wall-clock form they
    /// prefer; the trait doesn't dictate the format).
    ///
    /// Default impl returns
    /// `Err(Invalid("stream lifecycle not supported"))`.
    fn deprecate_stream(&self, stream_id: &str) -> Result<(), SecureLogError> {
        let _ = stream_id;
        Err(SecureLogError::Invalid(
            "stream lifecycle not supported by this backend".into(),
        ))
    }
}

/// Verify a standalone inclusion proof against an expected Merkle root.
///
/// This is a pure function rather than a trait method because
/// verification does not require any backend state — it's a property
/// of the proof alone.
pub fn verify_inclusion_proof(
    proof: &InclusionProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), SecureLogError> {
    let mut running = proof.entry_hash;
    for step in &proof.path {
        let pair = if step.right {
            let mut buf = [0u8; HASH_LEN * 2];
            buf[..HASH_LEN].copy_from_slice(&running);
            buf[HASH_LEN..].copy_from_slice(&step.sibling_hash);
            sha256(&buf)
        } else {
            let mut buf = [0u8; HASH_LEN * 2];
            buf[..HASH_LEN].copy_from_slice(&step.sibling_hash);
            buf[HASH_LEN..].copy_from_slice(&running);
            sha256(&buf)
        };
        running = pair;
    }
    if &running == expected_root {
        Ok(())
    } else {
        Err(SecureLogError::InclusionMismatch {
            seqno: proof.seqno,
            segment_id: proof.segment_id,
        })
    }
}
