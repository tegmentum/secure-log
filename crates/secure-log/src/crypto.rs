//! Envelope encryption for secure log payloads.
//!
//! ## Hierarchy
//!
//! ```text
//! master KEK          (root; 32 bytes; held in a sealed file,
//!                      eventually sealed by a TPM-protected key)
//!    │
//!    ├── per-stream key = HKDF(KEK, info="tpm:secure-log:stream:<stream_id>")
//!    │       │
//!    │       └── per-segment key = HKDF(stream_key, info="segment:<segment_id>")
//!    │                │
//!    │                └── AEAD(per-entry nonce, aad = canonical entry header)
//!    │
//!    └── (… other streams …)
//! ```
//!
//! Only the master KEK is sealed. Stream and segment keys are
//! derived on demand so they never need persisting. A compromised
//! segment key only exposes that segment's entries.
//!
//! ## What is and isn't encrypted
//!
//! Only the payload bytes are encrypted. All metadata — stream id,
//! session id, event type, severity, producer, timestamp, sequence
//! number, `prev_entry_hash`, `entry_hash` — remains in plaintext so
//! verifiers can walk the hash chain and Merkle tree without
//! possessing any decryption key.
//!
//! Integrity of the stored ciphertext is enforced by the same
//! entry-hash chain as plaintext entries. The canonical bytes that
//! feed into the hash include the ciphertext, not the plaintext.
//! Therefore tampering with ciphertext breaks the chain even
//! without a decryption key.
//!
//! ## AEAD choice
//!
//! ChaCha20-Poly1305 (RFC 8439). Constant-time on all platforms,
//! no dependency on hardware AES-NI, and 256-bit key.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::hash::HASH_LEN;

/// Length of the per-entry nonce for ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;

/// The AEAD algorithm name we embed in `payload_encoding`.
/// Verifiers use this to pick the right decryptor. The `v1` suffix
/// is the key-derivation version — changing the derivation formula
/// in a way that breaks compatibility must bump this.
pub const AEAD_NAME: &str = "cbor+aead-chacha20poly1305-v1";

/// Current key-derivation version embedded in HKDF info and AEAD
/// AAD. Bump when changing the derivation formula or binding.
pub const DERIVATION_VERSION: u32 = 1;

/// Confidentiality tier for a log stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidentialityTier {
    /// Plaintext. No encryption applied. Default.
    Public,
    /// Payload encrypted, metadata visible. Audit records.
    Protected,
    /// Payload encrypted, minimal metadata, stricter key access.
    HighlyRestricted,
}

impl std::fmt::Display for ConfidentialityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Public => "public",
            Self::Protected => "protected",
            Self::HighlyRestricted => "highly-restricted",
        })
    }
}

impl std::str::FromStr for ConfidentialityTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "public" => Ok(Self::Public),
            "protected" => Ok(Self::Protected),
            "highly-restricted" | "highly_restricted" => Ok(Self::HighlyRestricted),
            _ => Err(format!(
                "unknown confidentiality tier: '{}' (expected: public, protected, highly-restricted)",
                s
            )),
        }
    }
}

/// A 256-bit key that zeroes itself on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; HASH_LEN]);

impl SecretKey {
    pub fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a random master KEK from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; HASH_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").field("bytes", &"<redacted>").finish()
    }
}

/// Derive a per-stream key from a master KEK via HKDF-SHA256.
///
/// The derivation is bound to:
///
/// - the derivation format version (so a future format bump
///   produces different keys without reusing old material);
/// - the stream name (per-stream isolation);
/// - the confidentiality tier (so a policy change rotates the
///   effective key and ciphertext can't be lifted across tiers).
///
/// Changing any of these three produces a different stream key.
pub fn derive_stream_key(
    master: &SecretKey,
    stream_id: &str,
    tier: ConfidentialityTier,
) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = [0u8; HASH_LEN];
    let info = format!(
        "tpm:secure-log:v{}:stream={}:tier={}",
        DERIVATION_VERSION, stream_id, tier
    );
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF expand to 32 bytes cannot fail");
    SecretKey(out)
}

/// Derive a per-segment key from a per-stream key via HKDF-SHA256.
///
/// The segment_id is part of the info so per-segment compromise
/// does not extend across the stream's history.
pub fn derive_segment_key(stream_key: &SecretKey, segment_id: u64) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(None, stream_key.as_bytes());
    let mut out = [0u8; HASH_LEN];
    let info = format!("v{}:segment:{}", DERIVATION_VERSION, segment_id);
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF expand to 32 bytes cannot fail");
    SecretKey(out)
}

/// Build the canonical AAD for a payload AEAD.
///
/// The AAD pins ciphertext to its full policy context so lifting a
/// row from one stream/tier/segment to another fails authentication.
pub fn aead_aad(stream_id: &str, tier: ConfidentialityTier, segment_id: u64) -> String {
    format!(
        "tpm:secure-log:v{}:stream={}:tier={}:segment={}",
        DERIVATION_VERSION, stream_id, tier, segment_id
    )
}

/// Prefix that marks a field as a minimized (keyed-hashed) tag so
/// `audit show` can render it distinctively and tooling can
/// recognize that the plaintext is not stored.
pub const MINIMIZED_TAG_PREFIX: &str = "min:";

/// Build a deterministic, keyed-hash minimization tag for a metadata
/// field (event_type, producer, etc.) in a highly-restricted stream.
///
/// The tag is `min:<8-hex>` where the hex is the first 8 bytes of
/// HMAC-HKDF(master_kek || stream_id || field_kind || value). It's
/// deterministic under a fixed KEK (so a verifier can re-derive it
/// for query) but reveals nothing to a DB breach because the KEK
/// is sealed under the TPM.
pub fn minimize_metadata(
    master: &SecretKey,
    stream_id: &str,
    field_kind: &str,
    value: &str,
) -> String {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = [0u8; HASH_LEN];
    let info = format!(
        "tpm:secure-log:v{}:minimize:stream={}:field={}:value={}",
        DERIVATION_VERSION, stream_id, field_kind, value
    );
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF expand to 32 bytes cannot fail");
    let mut hex = String::with_capacity(MINIMIZED_TAG_PREFIX.len() + 16);
    hex.push_str(MINIMIZED_TAG_PREFIX);
    for b in &out[..8] {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Returns true if `s` starts with the minimization tag prefix.
pub fn is_minimized_tag(s: &str) -> bool {
    s.starts_with(MINIMIZED_TAG_PREFIX)
}

/// A ciphertext payload as stored in the `secure_log.payload` column.
///
/// Layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// This keeps the stored bytes self-describing: a verifier can
/// parse out the nonce without any side channel, which matters for
/// the append-only guarantee.
pub struct SealedPayload {
    pub bytes: Vec<u8>,
}

impl SealedPayload {
    /// Encrypt `plaintext` under `key` with random nonce and AAD.
    pub fn seal(
        key: &SecretKey,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, String> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| format!("aead seal failed: {}", e))?;
        let mut bytes = Vec::with_capacity(NONCE_LEN + ct.len());
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&ct);
        Ok(Self { bytes })
    }

    /// Decrypt back to plaintext.
    pub fn open(
        bytes: &[u8],
        key: &SecretKey,
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if bytes.len() < NONCE_LEN + 16 {
            return Err(format!(
                "sealed payload too short: {} bytes",
                bytes.len()
            ));
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let nonce = Nonce::from_slice(&bytes[..NONCE_LEN]);
        let ct = &bytes[NONCE_LEN..];
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad,
                },
            )
            .map_err(|e| format!("aead open failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let master = SecretKey::generate();
        let stream = derive_stream_key(&master, "default", ConfidentialityTier::Public);
        let seg = derive_segment_key(&stream, 1);

        let plaintext = b"confidential payload";
        let aad = aead_aad("default", ConfidentialityTier::Public, 1);
        let sealed = SealedPayload::seal(&seg, aad.as_bytes(), plaintext).unwrap();
        let out = SealedPayload::open(&sealed.bytes, &seg, aad.as_bytes()).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn open_fails_with_wrong_key() {
        let seg1 = derive_segment_key(&SecretKey::generate(), 1);
        let seg2 = derive_segment_key(&SecretKey::generate(), 1);
        let sealed = SealedPayload::seal(&seg1, b"", b"msg").unwrap();
        assert!(SealedPayload::open(&sealed.bytes, &seg2, b"").is_err());
    }

    #[test]
    fn open_fails_with_wrong_aad() {
        let seg = derive_segment_key(&SecretKey::generate(), 1);
        let sealed = SealedPayload::seal(&seg, b"aad1", b"msg").unwrap();
        assert!(SealedPayload::open(&sealed.bytes, &seg, b"aad2").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let seg = derive_segment_key(&SecretKey::generate(), 1);
        let mut sealed = SealedPayload::seal(&seg, b"", b"msg").unwrap();
        // Flip a byte in the middle of the ciphertext.
        let idx = NONCE_LEN + 2;
        sealed.bytes[idx] ^= 0x01;
        assert!(SealedPayload::open(&sealed.bytes, &seg, b"").is_err());
    }

    #[test]
    fn derived_keys_are_deterministic() {
        let master = SecretKey::new([7u8; 32]);
        let a = derive_stream_key(&master, "x", ConfidentialityTier::Public);
        let b = derive_stream_key(&master, "x", ConfidentialityTier::Public);
        assert_eq!(a.as_bytes(), b.as_bytes());

        let c = derive_stream_key(&master, "y", ConfidentialityTier::Public);
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn tier_change_rotates_stream_key() {
        let master = SecretKey::new([7u8; 32]);
        let public = derive_stream_key(&master, "x", ConfidentialityTier::Public);
        let protected = derive_stream_key(&master, "x", ConfidentialityTier::Protected);
        let restricted =
            derive_stream_key(&master, "x", ConfidentialityTier::HighlyRestricted);
        assert_ne!(public.as_bytes(), protected.as_bytes());
        assert_ne!(protected.as_bytes(), restricted.as_bytes());
        assert_ne!(public.as_bytes(), restricted.as_bytes());
    }

    #[test]
    fn aad_pins_all_policy_fields() {
        // Lifting a ciphertext across tiers or segments must fail.
        let master = SecretKey::new([11u8; 32]);
        let stream = derive_stream_key(&master, "s", ConfidentialityTier::Protected);
        let seg = derive_segment_key(&stream, 1);
        let aad_ok = aead_aad("s", ConfidentialityTier::Protected, 1);
        let sealed = SealedPayload::seal(&seg, aad_ok.as_bytes(), b"msg").unwrap();

        let aad_wrong_tier = aead_aad("s", ConfidentialityTier::Public, 1);
        assert!(
            SealedPayload::open(&sealed.bytes, &seg, aad_wrong_tier.as_bytes()).is_err()
        );
        let aad_wrong_seg = aead_aad("s", ConfidentialityTier::Protected, 2);
        assert!(
            SealedPayload::open(&sealed.bytes, &seg, aad_wrong_seg.as_bytes()).is_err()
        );
        let aad_wrong_stream = aead_aad("t", ConfidentialityTier::Protected, 1);
        assert!(
            SealedPayload::open(&sealed.bytes, &seg, aad_wrong_stream.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn minimize_metadata_is_deterministic_and_kek_bound() {
        let a = SecretKey::new([1u8; 32]);
        let b = SecretKey::new([2u8; 32]);

        // Same KEK + same inputs → same tag.
        let t1 = minimize_metadata(&a, "default", "event_type", "user.login");
        let t2 = minimize_metadata(&a, "default", "event_type", "user.login");
        assert_eq!(t1, t2);
        assert!(is_minimized_tag(&t1));
        assert!(t1.starts_with(MINIMIZED_TAG_PREFIX));

        // Different KEK → different tag (prevents cross-deployment
        // correlation).
        let t3 = minimize_metadata(&b, "default", "event_type", "user.login");
        assert_ne!(t1, t3);

        // Different value → different tag.
        let t4 = minimize_metadata(&a, "default", "event_type", "user.logout");
        assert_ne!(t1, t4);

        // Different stream → different tag.
        let t5 = minimize_metadata(&a, "other", "event_type", "user.login");
        assert_ne!(t1, t5);

        // Different field kind → different tag.
        let t6 = minimize_metadata(&a, "default", "producer", "user.login");
        assert_ne!(t1, t6);
    }

    #[test]
    fn tiers_parse() {
        use std::str::FromStr;
        assert_eq!(
            ConfidentialityTier::from_str("public").unwrap(),
            ConfidentialityTier::Public
        );
        assert_eq!(
            ConfidentialityTier::from_str("PROTECTED").unwrap(),
            ConfidentialityTier::Protected
        );
        assert_eq!(
            ConfidentialityTier::from_str("highly-restricted").unwrap(),
            ConfidentialityTier::HighlyRestricted
        );
        assert!(ConfidentialityTier::from_str("bogus").is_err());
    }
}
