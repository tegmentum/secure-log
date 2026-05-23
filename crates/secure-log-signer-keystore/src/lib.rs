//! A [`CheckpointSigner`] backed by the `keys:keystore/signer` interface.
//!
//! Phase 3 of the secure log signs each closed segment's checkpoint
//! hash through a [`CheckpointSigner`]. This crate implements that trait
//! over a *composed* `keys:keystore` component (the `keystore-pkcs11`
//! adapter + `pkcs11-provider` + `softhsm`, all wasm), driven in-process
//! with wasmtime.
//!
//! The signing key lives inside the wasm sandbox (a software HSM); its
//! private bytes never cross the component boundary. The host resolves a
//! key by label, calls `sign(message)` for each checkpoint, and caches
//! the public key + algorithm so verification can be done locally — the
//! `keys:keystore` interface deliberately omits verification, since
//! checking a signature needs only the public key.
//!
//! Today only ed25519 keys are supported (what `keystore-pkcs11`
//! provisions); verification uses `ed25519-dalek`.
//!
//! ```no_run
//! use secure_log_signer_keystore::{KeystoreSigner, KeystoreSignerConfig};
//! let signer = KeystoreSigner::open(&KeystoreSignerConfig {
//!     component_path: "keystore-softhsm.wasm".into(),
//!     conf_path: "softhsm2-wasi.conf".into(),
//!     token_dir: ".secure-log/pkcs11".into(),
//!     pin: "1234".into(),
//!     so_pin: "1234".into(),
//! })?;
//! // pass `&signer` to NativeSecureLog::sign_segment / verify_checkpoint_chain
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use secure_log::{CheckpointSigner, SignerError};
use wasmtime::component::{Component, Linker, ResourceAny, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    path: "wit",
    world: "keystore-host",
});

use exports::keys::keystore::signer::Error as KsError;

/// Stable algorithm identifier for ed25519 keys.
const ALG_ED25519: &str = "ed25519";

/// Configuration for opening a [`KeystoreSigner`].
#[derive(Debug, Clone)]
pub struct KeystoreSignerConfig {
    /// Path to the composed `keys:keystore` component
    /// (e.g. `keystore-softhsm.wasm`).
    pub component_path: PathBuf,
    /// Path to the SoftHSM2 config exposed to the component. Its
    /// `directories.tokendir` must be `/data/tokens`.
    pub conf_path: PathBuf,
    /// Host directory for token storage; mapped to `/data` in the
    /// sandbox so keys persist across runs.
    pub token_dir: PathBuf,
    /// User PIN for the token.
    pub pin: String,
    /// Security-officer PIN (used only when provisioning a fresh token).
    pub so_pin: String,
}

impl Default for KeystoreSignerConfig {
    fn default() -> Self {
        Self {
            component_path: PathBuf::from("keystore-softhsm.wasm"),
            conf_path: PathBuf::from("softhsm2-wasi.conf"),
            token_dir: PathBuf::from(".secure-log/pkcs11"),
            pin: "1234".to_string(),
            so_pin: "1234".to_string(),
        }
    }
}

/// Host state for the keystore component instance.
struct KsState {
    wasi_ctx: WasiCtx,
    wasi_table: ResourceTable,
}

impl WasiView for KsState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.wasi_table,
        }
    }
}

// The component imports a pkcs11:util pin-provider (referenced by the
// credential type). The keystore flow only passes inline PINs, so these
// are never invoked — they exist solely to satisfy the import.
use pkcs11::util::util::PinProvider;
impl pkcs11::util::util::Host for KsState {}
impl pkcs11::util::util::HostPinProvider for KsState {
    fn request_secret(
        &mut self,
        _self_: wasmtime::component::Resource<PinProvider>,
        _label: Option<String>,
        _attempts_remaining: Option<u8>,
    ) -> Vec<u8> {
        Vec::new()
    }
    fn clear(&mut self, _self_: wasmtime::component::Resource<PinProvider>) {}
    fn drop(&mut self, _rep: wasmtime::component::Resource<PinProvider>) -> wasmtime::Result<()> {
        Ok(())
    }
}

struct HasSelf<T>(std::marker::PhantomData<T>);
impl<T: 'static> wasmtime::component::HasData for HasSelf<T> {
    type Data<'a> = &'a mut T;
}

/// A resolved signing key: its sandbox handle plus the public material
/// needed for local verification.
struct KeyEntry {
    handle: ResourceAny,
    algorithm: String,
    public_key: Vec<u8>,
}

struct Inner {
    store: Store<KsState>,
    bindings: KeystoreHost,
    /// label -> resolved key. Keys are resolved (and provisioned on
    /// first use by the adapter) lazily and cached.
    keys: HashMap<String, KeyEntry>,
}

/// A [`CheckpointSigner`] whose private key lives in a software HSM
/// inside the wasm sandbox, accessed through `keys:keystore/signer`.
///
/// `wasmtime::Store` is `!Sync`, so the instance is held behind a
/// `Mutex`; the trait's `&self` methods lock it per call.
pub struct KeystoreSigner {
    inner: Mutex<Inner>,
}

impl KeystoreSigner {
    /// Instantiate the composed keystore component and prepare it for
    /// signing. Keys are resolved lazily by label on first use.
    pub fn open(config: &KeystoreSignerConfig) -> anyhow::Result<Self> {
        let mut engine_cfg = Config::new();
        engine_cfg.wasm_component_model(true);
        let engine = Engine::new(&engine_cfg)?;
        let component = Component::from_file(&engine, &config.component_path).map_err(|e| {
            anyhow::anyhow!(
                "loading keystore component {}: {e}",
                config.component_path.display()
            )
        })?;

        // Sandbox filesystem: /config/softhsm2-wasi.conf (RO) + /data
        // (RW, holds the token store under /data/tokens).
        let config_dir = config.token_dir.join("config");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(config.token_dir.join("tokens"))?;
        let conf = std::fs::read(&config.conf_path).map_err(|e| {
            anyhow::anyhow!("reading softhsm conf {}: {e}", config.conf_path.display())
        })?;
        std::fs::write(config_dir.join("softhsm2-wasi.conf"), conf)?;

        let mut wasi = WasiCtxBuilder::new();
        wasi.env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
            .env("KEYSTORE_PIN", &config.pin)
            .env("KEYSTORE_SO_PIN", &config.so_pin)
            .preopened_dir(&config_dir, "/config", DirPerms::READ, FilePerms::READ)?
            .preopened_dir(&config.token_dir, "/data", DirPerms::all(), FilePerms::all())?;

        let mut linker: Linker<KsState> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        pkcs11::util::util::add_to_linker::<KsState, HasSelf<KsState>>(&mut linker, |s| s)?;

        let state = KsState {
            wasi_ctx: wasi.build(),
            wasi_table: ResourceTable::new(),
        };
        let mut store = Store::new(&engine, state);
        let bindings = KeystoreHost::instantiate(&mut store, &component, &linker)
            .map_err(|e| anyhow::anyhow!("instantiate keystore component: {e}"))?;

        Ok(Self {
            inner: Mutex::new(Inner {
                store,
                bindings,
                keys: HashMap::new(),
            }),
        })
    }
}

/// Resolve `label` to a cached [`KeyEntry`], provisioning it via the
/// adapter on first use.
fn ensure_key(inner: &mut Inner, label: &str) -> Result<(), SignerError> {
    if inner.keys.contains_key(label) {
        return Ok(());
    }
    let Inner {
        store,
        bindings,
        keys,
    } = inner;
    let signer = bindings.keys_keystore_signer();
    let handle = signer
        .call_get_key(&mut *store, label)
        .map_err(|t| SignerError::Storage(format!("keystore get-key trap: {t}")))?
        .map_err(map_ks_err)?;
    let algorithm = signer
        .key()
        .call_algorithm(&mut *store, handle)
        .map_err(|t| SignerError::Storage(format!("key.algorithm trap: {t}")))?;
    let public_key = signer
        .key()
        .call_public_key(&mut *store, handle)
        .map_err(|t| SignerError::Storage(format!("key.public-key trap: {t}")))?;
    keys.insert(
        label.to_string(),
        KeyEntry {
            handle,
            algorithm,
            public_key,
        },
    );
    Ok(())
}

/// Map a `keys:keystore` error to a [`SignerError`].
fn map_ks_err(e: KsError) -> SignerError {
    match e {
        KsError::KeyNotFound(s) => SignerError::UnknownIdentity(s),
        KsError::UnsupportedAlgorithm(s) => SignerError::SignFailed(format!("unsupported: {s}")),
        KsError::AccessDenied(s) => SignerError::SignFailed(format!("access denied: {s}")),
        KsError::Backend(s) => SignerError::Storage(s),
    }
}

impl CheckpointSigner for KeystoreSigner {
    fn sign_checkpoint(
        &self,
        identity_name: &str,
        message: &[u8],
    ) -> Result<(Vec<u8>, String), SignerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SignerError::Storage("keystore signer mutex poisoned".into()))?;
        ensure_key(&mut inner, identity_name)?;
        let Inner {
            store,
            bindings,
            keys,
        } = &mut *inner;
        let handle = keys[identity_name].handle;
        let signature = bindings
            .keys_keystore_signer()
            .key()
            .call_sign(&mut *store, handle, message)
            .map_err(|t| SignerError::SignFailed(format!("keystore sign trap: {t}")))?
            .map_err(map_ks_err)?;
        // The persisted signer identity is the key label, so verification
        // can re-resolve the same key.
        Ok((signature, identity_name.to_string()))
    }

    fn verify_checkpoint(
        &self,
        signer_identity: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SignerError::Storage("keystore signer mutex poisoned".into()))?;
        ensure_key(&mut inner, signer_identity)?;
        let entry = &inner.keys[signer_identity];

        if entry.algorithm != ALG_ED25519 {
            return Err(SignerError::VerifyFailed(format!(
                "unsupported algorithm '{}' (only {ALG_ED25519})",
                entry.algorithm
            )));
        }

        let pk: [u8; 32] = entry.public_key.as_slice().try_into().map_err(|_| {
            SignerError::VerifyFailed(format!(
                "ed25519 public key is {} bytes, expected 32",
                entry.public_key.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&pk)
            .map_err(|e| SignerError::VerifyFailed(format!("bad ed25519 public key: {e}")))?;

        // A wrong-length or otherwise malformed signature is simply an
        // invalid signature, not a backend error.
        let Ok(sig) = Signature::from_slice(signature) else {
            return Ok(false);
        };
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}
