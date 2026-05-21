//! Checkpoint signing abstraction.
//!
//! Phase 3 of the secure log signs each closed segment's canonical
//! checkpoint hash. The signing backend is decoupled from this crate:
//! consumers implement [`CheckpointSigner`] over whatever key
//! material they have — a TPM, an HSM, an Ed25519 keypair on disk,
//! a cloud KMS, etc.
//!
//! The trait is intentionally narrow:
//!
//! - [`sign_checkpoint`](CheckpointSigner::sign_checkpoint) takes an
//!   identity name and a message; returns the signature and a
//!   stable signer identity string that gets persisted alongside the
//!   signature (typically the identity's UUID or DN).
//! - [`verify_checkpoint`](CheckpointSigner::verify_checkpoint) takes
//!   the stored signer identity, message, and signature, and reports
//!   whether the signature verifies.
//!
//! Key resolution (identity → key handle) is the signer's
//! responsibility. The secure log does not look at keys.

use thiserror::Error;

/// Errors a signer may raise.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The requested identity is unknown or has no usable key.
    #[error("signer identity '{0}' not found")]
    UnknownIdentity(String),

    /// The signing backend rejected the request.
    #[error("signing failed: {0}")]
    SignFailed(String),

    /// The verification backend rejected the request.
    #[error("verification failed: {0}")]
    VerifyFailed(String),

    /// A storage / lookup operation failed.
    #[error("storage: {0}")]
    Storage(String),
}

/// Sign and verify canonical checkpoint bytes.
///
/// Implementations are typically thin adapters over a TPM, HSM, or
/// software signer. They are responsible for:
///
/// 1. Resolving an identity name (or other handle) to a usable
///    signing key.
/// 2. Producing a deterministic-or-not signature over the supplied
///    bytes — the secure log treats the signature as opaque.
/// 3. Verifying a previously-produced signature, given the stable
///    signer-identity string that was persisted at sign time.
///
/// Returning a stable identifier from `sign_checkpoint` allows the
/// log to record exactly which key signed a segment without baking a
/// specific identity model into this crate.
pub trait CheckpointSigner: Send + Sync {
    /// Sign `message` with the key bound to `identity_name`.
    ///
    /// Returns `(signature, signer_identity)`. The `signer_identity`
    /// string is what gets stored in the segment row and is later
    /// passed back to [`verify_checkpoint`](Self::verify_checkpoint).
    /// A common choice is the underlying key's UUID as a string.
    fn sign_checkpoint(
        &self,
        identity_name: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, String), SignerError>;

    /// Verify a signature against `message` using the key referenced
    /// by `signer_identity` (the value previously returned from
    /// `sign_checkpoint`). Returns `true` if the signature verifies.
    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError>;
}
