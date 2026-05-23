//! End-to-end Phase 3 checkpoint signing through the PKCS#11 keystore.
//!
//! Drives the full stack: `NativeSecureLog` (SQLite store) ->
//! `sign_segment` -> `KeystoreSigner` -> the composed `keys:keystore`
//! component (keystore-pkcs11 + pkcs11-provider + softhsm) under
//! wasmtime, with the ed25519 key living inside the wasm sandbox.
//!
//! Requires the composed component + a SoftHSM config. Set
//! `SECURE_LOG_KEYSTORE_WASM` and `SECURE_LOG_SOFTHSM_CONF`, or have
//! them at the default `~/git/softhsm-wasm/...` locations; the test
//! skips (does not fail) when they are absent.

use std::path::PathBuf;

use secure_log::{CborEncoder, CheckpointSigner, NativeSecureLog, SecureLog};
use secure_log_signer_keystore::{KeystoreSigner, KeystoreSignerConfig};
use secure_log_sqlite::SqliteSecureLogStore;

/// Resolve the composed component + softhsm config, or `None` to skip.
fn keystore_paths() -> Option<(PathBuf, PathBuf)> {
    let home = std::env::var("HOME").ok()?;
    let wasm = std::env::var("SECURE_LOG_KEYSTORE_WASM")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(&home)
                .join("git/softhsm-wasm/keystore-pkcs11/target/wasm32-wasip2/release/keystore-softhsm.wasm")
        });
    let conf = std::env::var("SECURE_LOG_SOFTHSM_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(&home).join("git/softhsm-wasm/tests/softhsm2-wasi.conf"));
    (wasm.exists() && conf.exists()).then_some((wasm, conf))
}

fn open_signer() -> Option<(KeystoreSigner, PathBuf)> {
    let (component_path, conf_path) = keystore_paths()?;
    let token_dir = std::env::temp_dir().join(format!("sl-keystore-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&token_dir);
    let signer = KeystoreSigner::open(&KeystoreSignerConfig {
        component_path,
        conf_path,
        token_dir: token_dir.clone(),
        pin: "1234".into(),
        so_pin: "1234".into(),
    })
    .expect("open keystore signer");
    Some((signer, token_dir))
}

#[test]
fn sign_verify_round_trips() {
    let Some((signer, token_dir)) = open_signer() else {
        eprintln!("skipping: keystore-softhsm.wasm / softhsm conf not found");
        return;
    };

    let (sig, identity) = signer.sign_checkpoint("attest", b"hello").expect("sign");
    assert_eq!(identity, "attest");
    assert!(
        signer.verify_checkpoint(&identity, b"hello", &sig).expect("verify"),
        "correct message must verify"
    );
    assert!(
        !signer.verify_checkpoint(&identity, b"tampered", &sig).expect("verify"),
        "wrong message must not verify"
    );

    let _ = std::fs::remove_dir_all(&token_dir);
}

#[test]
fn signs_and_verifies_a_checkpoint_chain() {
    let Some((signer, token_dir)) = open_signer() else {
        eprintln!("skipping: keystore-softhsm.wasm / softhsm conf not found");
        return;
    };

    let store = SqliteSecureLogStore::open_in_memory().expect("open store");
    let log = NativeSecureLog::new(Box::new(store), Box::new(CborEncoder::new()));

    for i in 0..3 {
        log.append("default", "test.event", "info", "unit", format!("payload-{i}").as_bytes())
            .expect("append");
    }

    let seg = log.close_segment("default").expect("close segment");
    let (ckpt_hash, signature) = log
        .sign_segment(&signer, "attest", seg.segment_id)
        .expect("sign segment");
    assert_eq!(ckpt_hash.len(), 32);
    assert!(!signature.is_empty());

    // The segment's stored signature verifies against its checkpoint hash...
    log.verify_segment_signature(&signer, seg.segment_id)
        .expect("verify segment signature");
    // ...and the whole stream's checkpoint chain validates.
    let verified = log
        .verify_checkpoint_chain(&signer, "default")
        .expect("verify checkpoint chain");
    assert_eq!(verified, 1, "exactly one signed segment");

    let _ = std::fs::remove_dir_all(&token_dir);
}
