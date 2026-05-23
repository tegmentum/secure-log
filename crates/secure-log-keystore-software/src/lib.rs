//! Pure-software `keys:keystore/signer` provider.
//!
//! The default in-graph signing backend for the secure-log stacks (the
//! softhsm/pkcs11 keystore is the production alternative). Keys are held
//! in-process — no token, no PIN. They are derived *deterministically*
//! from the label, so the same label yields the same key (hence the same
//! public key) across runs within a build; this keeps checkpoint
//! verification stable without persistent storage.
//!
//! The algorithm is chosen by the `SECURE_LOG_KEYSTORE_ALG` environment
//! variable: `ed25519` (default), `ecdsa-p256`, or `rsa-pss-sha256`.
//!
//! Signing conventions match the verifier in `secure-log-component`:
//! ed25519 signs the message bytes (EdDSA); ecdsa-p256 and
//! rsa-pss-sha256 hash the message with SHA-256 internally.

#[allow(warnings)]
mod bindings;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use bindings::exports::keys::keystore::signer::{Error, Guest, GuestKey, Key};

struct Component;

const ALG_ENV: &str = "SECURE_LOG_KEYSTORE_ALG";

/// The private half of a resolved key.
enum Secret {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    RsaPss {
        key: Box<rsa::RsaPrivateKey>,
        salt_seed: [u8; 32],
    },
}

/// An exported `key` resource.
pub struct SoftKey {
    algorithm: String,
    public_key: Vec<u8>,
    secret: Secret,
}

/// Deterministic 32-byte seed for (algorithm, label).
fn seed_for(algorithm: &str, label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"secure-log-keystore-software:");
    h.update(algorithm.as_bytes());
    h.update(b":");
    h.update(label.as_bytes());
    h.finalize().into()
}

impl SoftKey {
    fn derive(algorithm: &str, label: &str) -> Result<SoftKey, Error> {
        let seed = seed_for(algorithm, label);
        match algorithm {
            "ed25519" => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public_key = sk.verifying_key().to_bytes().to_vec();
                Ok(SoftKey {
                    algorithm: algorithm.into(),
                    public_key,
                    secret: Secret::Ed25519(Box::new(sk)),
                })
            }
            "ecdsa-p256" => {
                let mut rng = ChaCha20Rng::from_seed(seed);
                let sk = p256::ecdsa::SigningKey::random(&mut rng);
                let public_key = sk.verifying_key().to_sec1_bytes().to_vec();
                Ok(SoftKey {
                    algorithm: algorithm.into(),
                    public_key,
                    secret: Secret::EcdsaP256(Box::new(sk)),
                })
            }
            "rsa-pss-sha256" => {
                use rsa::pkcs1::EncodeRsaPublicKey;
                let mut rng = ChaCha20Rng::from_seed(seed);
                let key = rsa::RsaPrivateKey::new(&mut rng, 2048)
                    .map_err(|e| Error::Backend(format!("rsa keygen: {e}")))?;
                let public_key = key
                    .to_public_key()
                    .to_pkcs1_der()
                    .map_err(|e| Error::Backend(format!("rsa public key encode: {e}")))?
                    .as_bytes()
                    .to_vec();
                // A distinct seed for PSS salt so it is independent of the key seed.
                let salt_seed = seed_for("rsa-pss-sha256-salt", label);
                Ok(SoftKey {
                    algorithm: algorithm.into(),
                    public_key,
                    secret: Secret::RsaPss {
                        key: Box::new(key),
                        salt_seed,
                    },
                })
            }
            other => Err(Error::UnsupportedAlgorithm(other.into())),
        }
    }
}

impl GuestKey for SoftKey {
    fn algorithm(&self) -> String {
        self.algorithm.clone()
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, Error> {
        match &self.secret {
            Secret::Ed25519(sk) => {
                use ed25519_dalek::Signer;
                Ok(sk.sign(&message).to_bytes().to_vec())
            }
            Secret::EcdsaP256(sk) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = sk.sign(&message);
                Ok(sig.to_bytes().to_vec())
            }
            Secret::RsaPss { key, salt_seed } => {
                use rsa::signature::RandomizedSigner;
                let signing_key = rsa::pss::SigningKey::<Sha256>::new((**key).clone());
                let mut rng = ChaCha20Rng::from_seed(*salt_seed);
                let sig = signing_key.sign_with_rng(&mut rng, &message);
                Ok(rsa::signature::SignatureEncoding::to_vec(&sig))
            }
        }
    }
}

impl Guest for Component {
    type Key = SoftKey;

    fn get_key(label: String) -> Result<Key, Error> {
        let algorithm = std::env::var(ALG_ENV).unwrap_or_else(|_| "ed25519".to_string());
        let key = SoftKey::derive(&algorithm, &label)?;
        Ok(Key::new(key))
    }
}

bindings::export!(Component with_types_in bindings);
