//! WASM-component-backed canonical encoder.
//!
//! Loads an external `.wasm` component that implements the
//! `encoder` interface of `wit/secure-log.wit` and delegates
//! `encode_entry` / `encode_checkpoint` / `name` to it. A verifier
//! in a different process using the same component will produce
//! byte-identical output, which is the whole point of deterministic
//! canonical encoding.
//!
//! Enable via `--features secure-log-wasm`. This feature shares the
//! `wasmtime` dependency with `vtpm`, so it only costs a feature
//! flag when both are off.
//!
//! ## What a component must export
//!
//! The component must export the `encoder` interface from
//! `tpm:secure-log@0.1.0`. A minimal Rust implementation using
//! `wit-bindgen` would look like:
//!
//! ```no_run
//! // Cargo.toml:
//! //   [lib]
//! //   crate-type = ["cdylib"]
//! //   [dependencies]
//! //   wit-bindgen = "0.x"
//! //
//! // lib.rs:
//! // wit_bindgen::generate!({
//! //     path: ".../wit/secure-log.wit",
//! //     world: "secure-log-host",
//! // });
//! //
//! // struct Component;
//! // impl exports::tpm::secure_log::encoder::Guest for Component { ... }
//! // export!(Component);
//! ```
//!
//! Building with `cargo component build --release` produces a
//! `.wasm` component file that can be loaded here.
//!
//! ## Stability guarantee
//!
//! The host-side wrapper is not the canonical definition; the
//! authoritative contract is the WIT file. Two components with the
//! same WIT version MUST produce the same bytes for the same input.
//! If they don't, that's a component bug and verification will fail.

use std::path::Path;
use std::sync::Mutex;

use wasmtime::component::{Component, ComponentExportIndex, Func, Linker, Val};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use super::encoder::CanonicalEncoder;
use super::model::{CheckpointFields, EntryFields};

/// Fully-qualified WIT interface name that a plugin component must
/// export. Matches `wit/log.wit` at package `secure-log:log@0.1.0`.
const ENCODER_INTERFACE: &str = "secure-log:log/encoder@0.1.0";

struct WasmState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
}

impl WasiView for WasmState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// A canonical encoder implemented by an external WASM component.
///
/// The component is loaded once per `WasmCanonicalEncoder::new`
/// call; subsequent `encode_*` / `name` calls reuse the same
/// instance. Thread-safety: internal state is wrapped in a
/// `Mutex` so the trait bound `CanonicalEncoder: Send + Sync` holds.
pub struct WasmCanonicalEncoder {
    inner: Mutex<Inner>,
    /// Cached from the component's `name()` export so the trait
    /// method can return `&'static str` — the component is loaded
    /// before the trait is ever used, so we leak the string into
    /// a `Box` of `'static` lifetime at construction time.
    cached_name: &'static str,
}

struct Inner {
    store: Store<WasmState>,
    /// Resolved `Func` handles for the three encoder-interface
    /// exports. The component model requires navigating into the
    /// interface's export index before looking up its functions —
    /// a flat `instance.get_func("encode-entry")` returns `None`
    /// because the function lives under `secure-log:log/encoder@0.1.0`,
    /// not at the top of the world's exports. We resolve once at
    /// construction time and reuse the handles for every call.
    encode_entry: Func,
    encode_checkpoint: Func,
}

impl WasmCanonicalEncoder {
    /// Load a component from the given `.wasm` path. Returns an
    /// error if the file does not exist, the bytes are not a valid
    /// component, or the component does not export the `encoder`
    /// interface.
    pub fn new(wasm_path: &Path) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;

        let component = Component::from_file(&engine, wasm_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to load secure-log WASM component from {}: {}",
                wasm_path.display(),
                e
            )
        })?;

        let mut linker: Linker<WasmState> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

        let wasi = WasiCtxBuilder::new().inherit_stdio().build();
        let mut store = Store::new(
            &engine,
            WasmState {
                wasi,
                table: wasmtime::component::ResourceTable::new(),
            },
        );

        // Navigate to the encoder interface's export index BEFORE
        // instantiation — component-model export indexes are computed
        // from the `Component` metadata, and looking them up on the
        // instance requires threading the parent index through
        // `get_export_index`.
        let iface_idx = component
            .get_export_index(None, ENCODER_INTERFACE)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "component at {} does not export interface `{}`",
                    wasm_path.display(),
                    ENCODER_INTERFACE
                )
            })?;
        let encode_entry_idx = require_iface_export(&component, &iface_idx, "encode-entry")?;
        let encode_checkpoint_idx =
            require_iface_export(&component, &iface_idx, "encode-checkpoint")?;
        let name_idx = require_iface_export(&component, &iface_idx, "name")?;

        let instance = linker.instantiate(&mut store, &component)?;

        let encode_entry = instance
            .get_func(&mut store, encode_entry_idx)
            .ok_or_else(|| anyhow::anyhow!("encode-entry export vanished after instantiation"))?;
        let encode_checkpoint = instance
            .get_func(&mut store, encode_checkpoint_idx)
            .ok_or_else(|| {
                anyhow::anyhow!("encode-checkpoint export vanished after instantiation")
            })?;
        let name_func = instance
            .get_func(&mut store, name_idx)
            .ok_or_else(|| anyhow::anyhow!("name export vanished after instantiation"))?;

        // Call name() once and leak the String into a 'static
        // reference. This is OK: a single encoder instance exists
        // for the life of the program, and the name is a short,
        // bounded string.
        let mut name_results = vec![Val::Bool(false)];
        name_func.call(&mut store, &[], &mut name_results)?;
        let name_str = match name_results.into_iter().next().expect("one result") {
            Val::String(s) => s,
            other => {
                anyhow::bail!("encoder.name() returned unexpected value: {:?}", other)
            }
        };
        let cached_name: &'static str = Box::leak(name_str.into_boxed_str());

        Ok(Self {
            inner: Mutex::new(Inner {
                store,
                encode_entry,
                encode_checkpoint,
            }),
            cached_name,
        })
    }
}

fn require_iface_export(
    component: &Component,
    iface: &ComponentExportIndex,
    name: &str,
) -> anyhow::Result<ComponentExportIndex> {
    component
        .get_export_index(Some(iface), name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "component's `{}` interface does not export `{}`",
                ENCODER_INTERFACE,
                name
            )
        })
}

impl CanonicalEncoder for WasmCanonicalEncoder {
    fn encode_entry(&self, fields: &EntryFields) -> Vec<u8> {
        let mut guard = self.inner.lock().unwrap();
        let Inner {
            store,
            encode_entry,
            ..
        } = &mut *guard;
        let record = entry_to_val(fields);
        call_bytes_returning(store, *encode_entry, "encode-entry", record)
    }

    fn encode_checkpoint(&self, fields: &CheckpointFields) -> Vec<u8> {
        let mut guard = self.inner.lock().unwrap();
        let Inner {
            store,
            encode_checkpoint,
            ..
        } = &mut *guard;
        let record = checkpoint_to_val(fields);
        call_bytes_returning(store, *encode_checkpoint, "encode-checkpoint", record)
    }

    fn name(&self) -> &'static str {
        self.cached_name
    }
}

/// Invoke a `func(record) -> list<u8>` and decode the return.
/// Byte-list-typed encoder outputs are the only shape we call, so
/// the extraction is inlined here rather than made generic.
fn call_bytes_returning(
    store: &mut Store<WasmState>,
    func: Func,
    name: &'static str,
    arg: Val,
) -> Vec<u8> {
    let mut results = vec![Val::Bool(false)];
    match func.call(&mut *store, &[arg], &mut results) {
        Ok(()) => {}
        Err(e) => panic!("{name} call failed: {e}"),
    }
    match results.into_iter().next().expect("one result") {
        Val::List(list) => list
            .into_iter()
            .map(|v| match v {
                Val::U8(b) => b,
                other => panic!("{name} returned non-u8 element: {other:?}"),
            })
            .collect(),
        other => panic!("{name} returned unexpected value: {other:?}"),
    }
}

// -- Val translation helpers ---------------------------------------

fn entry_to_val(fields: &EntryFields) -> Val {
    let fields_pairs = vec![
        ("version".to_string(), Val::U32(fields.version)),
        (
            "stream-id".to_string(),
            Val::String(fields.stream_id.clone()),
        ),
        (
            "session-id".to_string(),
            Val::String(fields.session_id.clone()),
        ),
        ("boot-id".to_string(), Val::String(fields.boot_id.clone())),
        ("seqno".to_string(), Val::U64(fields.seqno)),
        (
            "timestamp-rfc3339".to_string(),
            Val::String(fields.timestamp_rfc3339.clone()),
        ),
        (
            "event-type".to_string(),
            Val::String(fields.event_type.clone()),
        ),
        // The WIT contract defines `severity` as an enum; the
        // untyped wasmtime call surface encodes enum values as
        // `Val::Enum(case_name)`. The case name is the exact
        // lowercase spelling of the WIT variant, which
        // `Severity::as_str` produces.
        (
            "severity".to_string(),
            Val::Enum(fields.severity.as_str().to_string()),
        ),
        ("producer".to_string(), Val::String(fields.producer.clone())),
        (
            "payload-encoding".to_string(),
            Val::String(fields.payload_encoding.clone()),
        ),
        ("payload".to_string(), bytes_to_val_list(&fields.payload)),
        (
            "prev-entry-hash".to_string(),
            bytes_to_val_list(&fields.prev_entry_hash),
        ),
    ];
    Val::Record(fields_pairs)
}

fn checkpoint_to_val(fields: &CheckpointFields) -> Val {
    let pairs = vec![
        ("version".to_string(), Val::U32(fields.version)),
        (
            "stream-id".to_string(),
            Val::String(fields.stream_id.clone()),
        ),
        ("segment-id".to_string(), Val::U64(fields.segment_id)),
        ("seq-start".to_string(), Val::U64(fields.seq_start)),
        ("seq-end".to_string(), Val::U64(fields.seq_end)),
        (
            "merkle-root".to_string(),
            bytes_to_val_list(&fields.merkle_root),
        ),
        (
            "last-entry-hash".to_string(),
            bytes_to_val_list(&fields.last_entry_hash),
        ),
        (
            "prev-checkpoint-hash".to_string(),
            bytes_to_val_list(&fields.prev_checkpoint_hash),
        ),
        ("boot-id".to_string(), Val::String(fields.boot_id.clone())),
        (
            "session-id".to_string(),
            Val::String(fields.session_id.clone()),
        ),
        (
            "policy-hash".to_string(),
            bytes_to_val_list(&fields.policy_hash),
        ),
        (
            "timestamp-rfc3339".to_string(),
            Val::String(fields.timestamp_rfc3339.clone()),
        ),
    ];
    Val::Record(pairs)
}

fn bytes_to_val_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|b| Val::U8(*b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_wasm_file_errors_cleanly() {
        let res = WasmCanonicalEncoder::new(Path::new("/definitely/does/not/exist.wasm"));
        let Err(err) = res else {
            panic!("expected error for missing wasm file");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("failed to load secure-log WASM component"),
            "got: {}",
            msg
        );
    }
}
