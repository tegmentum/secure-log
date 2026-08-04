//! End-to-end runtime verification of `WasmCanonicalEncoder`.
//!
//! Only compiles under `--features wasm-encoder`. Loads a composed
//! secure-log component through the wasmtime host wrapper and asserts
//! that every canonical field — including the `severity` enum passed
//! via the untyped `Val::Enum` call surface — produces byte-identical
//! output to the native `CborEncoder`. That equality is the whole
//! point of the pluggable encoder: two implementations of the same
//! WIT interface must yield the same bytes for the same input, or the
//! hash chain stops reproducing.
//!
//! **Skips** (does not fail) when the composed component isn't built.
//! Resolves the path in this order:
//!
//! 1. `$SECURE_LOG_WASM_ENCODER_COMPONENT` if set.
//! 2. `<workspace>/dist/secure-log-file.wasm` (built by
//!    `./scripts/build-components.sh`).
//!
//! Any composed component that exports `secure-log:log/encoder@0.1.0`
//! and can be instantiated with only the WASI import set works —
//! `secure-log-file.wasm` is chosen as the default because it has the
//! shortest import surface (no `wasi:http`, no pkcs11 pin provider).

#![cfg(feature = "wasm-encoder")]

use std::path::PathBuf;

use secure_log::{
    encoder::CborEncoder, hash::ZERO_HASH, model::ENTRY_VERSION,
    wasm_encoder::WasmCanonicalEncoder, CanonicalEncoder, CheckpointFields, EntryFields, Severity,
};

fn locate_component() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SECURE_LOG_WASM_ENCODER_COMPONENT") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    // `<crate>/tests/…` → `<crate>` → workspace root is two up.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let default = workspace.join("dist").join("secure-log-file.wasm");
    default.exists().then_some(default)
}

fn sample_entry(severity: Severity) -> EntryFields {
    EntryFields {
        version: ENTRY_VERSION,
        stream_id: "default".into(),
        session_id: "sess-1".into(),
        boot_id: "boot-1".into(),
        seqno: 0,
        timestamp_rfc3339: "2026-04-10T00:00:00Z".into(),
        event_type: "test.event".into(),
        severity,
        producer: "unit-test".into(),
        payload_encoding: "cbor".into(),
        payload: b"hello".to_vec(),
        prev_entry_hash: ZERO_HASH.to_vec(),
    }
}

const ALL_SEVERITIES: &[Severity] = &[
    Severity::Emergency,
    Severity::Alert,
    Severity::Critical,
    Severity::Error,
    Severity::Warning,
    Severity::Notice,
    Severity::Info,
    Severity::Debug,
];

#[test]
fn wasm_encoder_matches_native_for_every_severity() {
    let Some(path) = locate_component() else {
        eprintln!(
            "skipping: no composed component at $SECURE_LOG_WASM_ENCODER_COMPONENT \
             or dist/secure-log-file.wasm (run ./scripts/build-components.sh)"
        );
        return;
    };
    let wasm = WasmCanonicalEncoder::new(&path)
        .unwrap_or_else(|e| panic!("failed to load {}: {e}", path.display()));
    assert_eq!(
        wasm.name(),
        "cbor",
        "composed component's encoder should identify as `cbor`"
    );

    let native = CborEncoder::new();
    for &severity in ALL_SEVERITIES {
        let entry = sample_entry(severity);
        let wasm_bytes = wasm.encode_entry(&entry);
        let native_bytes = native.encode_entry(&entry);
        assert_eq!(
            wasm_bytes,
            native_bytes,
            "severity {severity:?}: wasm encoder produced different bytes than native \
             (wasm={} bytes, native={} bytes) — the hash chain would not reproduce",
            wasm_bytes.len(),
            native_bytes.len(),
        );
    }
}

#[test]
fn wasm_encoder_matches_native_for_checkpoints() {
    let Some(path) = locate_component() else {
        eprintln!(
            "skipping: no composed component at $SECURE_LOG_WASM_ENCODER_COMPONENT \
             or dist/secure-log-file.wasm (run ./scripts/build-components.sh)"
        );
        return;
    };
    let wasm = WasmCanonicalEncoder::new(&path).expect("load component");
    let native = CborEncoder::new();

    let cp = CheckpointFields {
        version: 1,
        stream_id: "default".into(),
        segment_id: 1,
        seq_start: 0,
        seq_end: 9,
        merkle_root: ZERO_HASH.to_vec(),
        last_entry_hash: ZERO_HASH.to_vec(),
        prev_checkpoint_hash: ZERO_HASH.to_vec(),
        boot_id: "boot-1".into(),
        session_id: "sess-1".into(),
        policy_hash: vec![0u8; 32],
        timestamp_rfc3339: "2026-04-10T00:00:00Z".into(),
    };
    assert_eq!(wasm.encode_checkpoint(&cp), native.encode_checkpoint(&cp));
}
