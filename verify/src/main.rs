//! Host harness: instantiate a composed secure-log component under
//! wasmtime and exercise the exported `secure-log:log/log` interface
//! end-to-end.
//!
//! Usage: secure-log-verify [path-to-composed.wasm]
//! Default: ../dist/secure-log-sqlite.wasm

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::Result;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

/// Holds the `wasmtime serve` subprocess that backs the remote stack and
/// kills it on drop.
struct RpcServer(Child);
impl Drop for RpcServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the composed remote endpoint (`secure-log-rpc-server.wasm`) under
/// `wasmtime serve`, returning the guard + its URL. Returns `None` if the
/// artifact isn't built — the non-remote stacks don't need it.
fn spawn_rpc_server() -> Option<(RpcServer, String)> {
    let artifact = "../dist/secure-log-rpc-server.wasm";
    if !std::path::Path::new(artifact).exists() {
        return None;
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .ok()?
        .local_addr()
        .ok()?
        .port();
    let data = std::env::temp_dir().join(format!("secure-log-verify-rpc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).ok()?;
    let child = Command::new("wasmtime")
        .args([
            "serve",
            "-S",
            "cli",
            "--addr",
            &format!("127.0.0.1:{port}"),
            "--dir",
            &format!("{}::/data", data.display()),
            "--env",
            "SECURE_LOG_STORE_CONFIG=/data/secure-log.db",
            artifact,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Wait for the listener to come up.
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Some((RpcServer(child), format!("http://127.0.0.1:{port}")))
}

wasmtime::component::bindgen!({
    path: "wit",
    world: "verify-host",
});

struct Host {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    table: ResourceTable,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: Default::default(),
        }
    }
}

// The softhsm-backed pkcs11 stack imports a pkcs11:util pin-provider
// (the credential type references it). It uses inline PINs only, so this
// host stub is never invoked — it just satisfies the import.
use pkcs11::util::util::PinProvider;
impl pkcs11::util::util::Host for Host {}
impl pkcs11::util::util::HostPinProvider for Host {
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

// ─────────────────────────────────────────────────────────────────────
// sqlite:wasm/{extension-loader, dispatch} — compile-only stubs.
//
// The composed secure-log-sqlite.wasm bundles the in-WASM sqlite
// component, which imports these two interfaces so that runtime
// `.load` of a third extension is possible. The verify harness never
// exercises `.load` — it opens a db, appends log entries, and checks
// the chain — so the extension loader and dispatch surfaces are dead
// code from our POV. These impls exist ONLY to satisfy the linker.
//
// Every function returns "not supported" for result-typed calls, and
// the "safest empty" default for non-result calls (empty list / empty
// string / false / 0 / ignore-authorize / true-allow-commit). If any
// of these ever fires at runtime the guest is asking for functionality
// the harness deliberately doesn't provide — either wire it up
// properly or investigate why `.load` is being invoked here.
// ─────────────────────────────────────────────────────────────────────
use sqlite::extension::metadata::Manifest;
use sqlite::extension::policy::LoadOptions;
use sqlite::extension::types::{AuthAction, AuthResult, SqlValue, UpdateOperation};
use sqlite::extension::vtab::{IndexInfo, IndexPlan};
use sqlite::wasm::extension_loader::{
    CacheMergeStats, CacheStats, ComponentCacheStatsSnapshot, DescribedResult, DotCommandResult,
    LoaderError, UriCacheEntry,
};

fn unsupported() -> LoaderError {
    LoaderError {
        code: -1,
        message: "not supported by verify harness".to_string(),
    }
}

impl sqlite::wasm::extension_loader::Host for Host {
    fn load_extension(
        &mut self,
        _path: String,
        _options: LoadOptions,
    ) -> Result<Manifest, LoaderError> {
        Err(unsupported())
    }
    fn unload_extension(&mut self, _name: String) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn extension_digest(&mut self, _name: String) -> String {
        String::new()
    }
    fn load_extension_from_bytes(
        &mut self,
        _name_hint: String,
        _bytes: Vec<u8>,
        _options: LoadOptions,
    ) -> Result<Manifest, LoaderError> {
        Err(unsupported())
    }
    fn dispatch_dot_command(
        &mut self,
        _name: String,
        _args: String,
        _cli_state: Vec<(String, String)>,
    ) -> Result<DotCommandResult, LoaderError> {
        Err(unsupported())
    }
    fn fetch_cas_uri(
        &mut self,
        _uri: String,
        _expected_digest: String,
    ) -> Result<Vec<u8>, LoaderError> {
        Err(unsupported())
    }
    fn describe_extension(&mut self, _path: String) -> Result<DescribedResult, LoaderError> {
        Err(unsupported())
    }
    fn describe_extension_from_uri(
        &mut self,
        _uri: String,
    ) -> Result<DescribedResult, LoaderError> {
        Err(unsupported())
    }
    fn component_cache_stats(&mut self) -> ComponentCacheStatsSnapshot {
        ComponentCacheStatsSnapshot {
            c1_hits: 0,
            c2_hits: 0,
            cold_parses: 0,
            parse_ms: 0,
            serialize_ms: 0,
            deserialize_ms: 0,
            bypassed: 0,
            row_count: 0,
            total_bytes: 0,
            max_bytes: 0,
        }
    }
    fn component_cache_purge(&mut self) -> u64 {
        0
    }
    fn list_extensions(&mut self) -> Vec<Manifest> {
        Vec::new()
    }
    fn is_extension_loaded(&mut self, _name: String) -> bool {
        false
    }
    fn load_extension_from_uri(
        &mut self,
        _uri: String,
        _options: LoadOptions,
    ) -> Result<Manifest, LoaderError> {
        Err(unsupported())
    }
    fn register_resolver(
        &mut self,
        _scheme: String,
        _path: String,
        _options: LoadOptions,
    ) -> Result<String, LoaderError> {
        Err(unsupported())
    }
    fn unregister_resolver(&mut self, _scheme: String) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn list_resolvers(&mut self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn list_cache_uris(&mut self) -> Vec<UriCacheEntry> {
        Vec::new()
    }
    fn purge_cache(&mut self) -> u64 {
        0
    }
    fn get_cache_stats(&mut self) -> Result<CacheStats, LoaderError> {
        Err(unsupported())
    }
    fn cache_set_max_bytes(&mut self, _max: u64) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn cache_gc(&mut self) -> Result<u64, LoaderError> {
        Err(unsupported())
    }
    fn cache_evict(&mut self, _target_bytes: u64) -> Result<u64, LoaderError> {
        Err(unsupported())
    }
    fn cache_export(&mut self, _path: String) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn do_cache_import(&mut self, _path: String) -> Result<CacheMergeStats, LoaderError> {
        Err(unsupported())
    }
    fn cache_use_external(&mut self, _path: String) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn cache_use_internal(&mut self, _db_path: String) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn cache_migrate_to_external(
        &mut self,
        _path: String,
    ) -> Result<CacheMergeStats, LoaderError> {
        Err(unsupported())
    }
    fn cache_migrate_to_internal(
        &mut self,
        _db_path: String,
    ) -> Result<CacheMergeStats, LoaderError> {
        Err(unsupported())
    }
    fn run_wasm(
        &mut self,
        _path: String,
        _options: LoadOptions,
    ) -> Result<String, LoaderError> {
        Err(unsupported())
    }
    fn register_wasm_provider(
        &mut self,
        _id: String,
        _path: String,
    ) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn register_runtime(
        &mut self,
        _ext: String,
        _flavor: String,
        _path: String,
        _options: LoadOptions,
    ) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn unregister_runtime(
        &mut self,
        _ext: String,
        _flavor: String,
    ) -> Result<(), LoaderError> {
        Err(unsupported())
    }
    fn list_runtimes(&mut self) -> Vec<(String, String, String)> {
        Vec::new()
    }
    fn run_source(&mut self, _path: String, _flavor: String) -> Result<String, LoaderError> {
        Err(unsupported())
    }
}

impl sqlite::wasm::dispatch::Host for Host {
    fn scalar_call(
        &mut self,
        _ext_name: String,
        _func_id: u64,
        _args: Vec<SqlValue>,
    ) -> Result<SqlValue, String> {
        Err("not supported by verify harness".to_string())
    }
    fn aggregate_step(
        &mut self,
        _ext_name: String,
        _func_id: u64,
        _context_id: u64,
        _args: Vec<SqlValue>,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn aggregate_finalize(
        &mut self,
        _ext_name: String,
        _func_id: u64,
        _context_id: u64,
    ) -> Result<SqlValue, String> {
        Err("not supported by verify harness".to_string())
    }
    fn aggregate_value(
        &mut self,
        _ext_name: String,
        _func_id: u64,
        _context_id: u64,
    ) -> Result<SqlValue, String> {
        Err("not supported by verify harness".to_string())
    }
    fn aggregate_inverse(
        &mut self,
        _ext_name: String,
        _func_id: u64,
        _context_id: u64,
        _args: Vec<SqlValue>,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn collation_compare(
        &mut self,
        _ext_name: String,
        _collation_id: u64,
        _a: String,
        _b: String,
    ) -> i32 {
        0
    }
    fn authorize(
        &mut self,
        _ext_name: String,
        _action: AuthAction,
        _arg1: Option<String>,
        _arg2: Option<String>,
        _database: Option<String>,
        _trigger: Option<String>,
    ) -> AuthResult {
        AuthResult::Ignore
    }
    fn on_update(
        &mut self,
        _ext_name: String,
        _operation: UpdateOperation,
        _database: String,
        _table: String,
        _rowid: i64,
    ) {
    }
    fn on_commit(&mut self, _ext_name: String) -> bool {
        // WIT doc: "Returning false converts the commit to a rollback."
        // Return true to allow commit through (verify shouldn't trigger
        // this at all — no extensions are loaded).
        true
    }
    fn on_rollback(&mut self, _ext_name: String) {}
    fn vtab_create(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _db_name: String,
        _table_name: String,
        _args: Vec<String>,
    ) -> Result<String, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_connect(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _db_name: String,
        _table_name: String,
        _args: Vec<String>,
    ) -> Result<String, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_destroy(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_disconnect(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_best_index(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _info: IndexInfo,
    ) -> Result<IndexPlan, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_open(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _cursor_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_close(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_filter(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
        _idx_num: i32,
        _idx_str: Option<String>,
        _args: Vec<SqlValue>,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_next(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_eof(&mut self, _ext_name: String, _vtab_id: u64, _cursor_id: u64) -> bool {
        // True so any accidental iteration terminates immediately.
        true
    }
    fn vtab_column(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
        _col: i32,
    ) -> Result<SqlValue, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_rowid(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
    ) -> Result<i64, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_fetch_batch(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _cursor_id: u64,
        _max_rows: u32,
    ) -> Result<Vec<sqlite::wasm::dispatch::VtabRow>, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_update(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _args: Vec<SqlValue>,
    ) -> Result<i64, String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_begin(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_sync(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_commit(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_rollback(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_rename(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _new_name: String,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_savepoint(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _savepoint: i32,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_release(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _savepoint: i32,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_rollback_to(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _savepoint: i32,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
    fn vtab_is_shadow_name(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _name: String,
    ) -> bool {
        false
    }
    fn vtab_integrity(
        &mut self,
        _ext_name: String,
        _vtab_id: u64,
        _instance_id: u64,
        _schema: String,
        _table_name: String,
        _mode_flags: u32,
    ) -> Result<(), String> {
        Err("not supported by verify harness".to_string())
    }
}

struct HasSelf<T>(std::marker::PhantomData<T>);
impl<T: 'static> wasmtime::component::HasData for HasSelf<T> {
    type Data<'a> = &'a mut T;
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../dist/secure-log-sqlite.wasm".to_string());
    println!("loading composed component: {path}");

    let engine = Engine::default();
    let component = Component::from_file(&engine, &path)?;

    let mut linker: Linker<Host> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    // wasi:http for the remote backend. add_only_* avoids re-adding the
    // proxy interfaces that the full wasi linker already registered.
    wasmtime_wasi_http::p2::add_only_http_to_linker_sync(&mut linker)?;
    // pkcs11:util pin-provider for the softhsm-backed pkcs11 stack.
    pkcs11::util::util::add_to_linker::<Host, HasSelf<Host>>(&mut linker, |s| s)?;
    // sqlite:wasm/{extension-loader, dispatch} for the sqlite-backed
    // stack. Stubs — verify never invokes `.load`. See impls above.
    sqlite::wasm::extension_loader::add_to_linker::<Host, HasSelf<Host>>(&mut linker, |s| s)?;
    sqlite::wasm::dispatch::add_to_linker::<Host, HasSelf<Host>>(&mut linker, |s| s)?;

    // Run the composed remote endpoint (a wasi:http guest) under
    // `wasmtime serve` so the remote backend has somewhere to talk to.
    // Unused (but harmless) for the sqlite/file backends. The guard kills
    // the subprocess when it drops at the end of main.
    let rpc = spawn_rpc_server();
    let rpc_url = rpc
        .as_ref()
        .map(|(_, url)| url.clone())
        .unwrap_or_default();
    if let Some((_, url)) = &rpc {
        println!("rpc-server (wasmtime serve) at {url}");
    }
    let _rpc_guard = rpc;

    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio()
        .inherit_env()
        .env("SECURE_LOG_RPC_URL", &rpc_url);
    // Preopen the current directory so the append-only file backend
    // (wasi:filesystem) can read/write its log. Harmless for sqlite.
    if std::path::Path::new(".").exists() {
        wasi.preopened_dir(".", ".", DirPerms::all(), FilePerms::all())?;
    }
    // For the softhsm-backed pkcs11 stack: stage the SoftHSM config and a
    // token dir, mapped to /config and /data (its tokendir is
    // /data/tokens). Skipped if no conf is available — software stacks
    // don't need it.
    if let Some(conf) = softhsm_conf() {
        let run = std::env::temp_dir().join(format!("secure-log-verify-{}", std::process::id()));
        let cfg_dir = run.join("config");
        let data_dir = run.join("data");
        std::fs::create_dir_all(&cfg_dir)?;
        std::fs::create_dir_all(data_dir.join("tokens"))?;
        std::fs::write(cfg_dir.join("softhsm2-wasi.conf"), std::fs::read(&conf)?)?;
        wasi.env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
            .env("KEYSTORE_PIN", "1234")
            .env("KEYSTORE_SO_PIN", "1234")
            .preopened_dir(&cfg_dir, "/config", DirPerms::READ, FilePerms::READ)?
            .preopened_dir(&data_dir, "/data", DirPerms::all(), FilePerms::all())?;
    }
    let mut store = Store::new(
        &engine,
        Host {
            wasi: wasi.build(),
            http: WasiHttpCtx::new(),
            table: ResourceTable::new(),
        },
    );

    let bindings = VerifyHost::instantiate(&mut store, &component, &linker)?;
    let log = bindings.secure_log_log_log();

    // open the backing store explicitly (no implicit default).
    // Override with arg 2; default to an in-memory sqlite db.
    let config = std::env::args().nth(2).unwrap_or_else(|| ":memory:".to_string());
    println!("open store with config: {config:?}");
    log.call_open(&mut store, &config)?.map_err(anyhow::Error::msg)?;

    // append three entries across two streams
    use exports::secure_log::log::encoder::Severity;
    let a = log
        .call_append(&mut store, "default", "user.login", Severity::Info, "authd", b"alice")?.map_err(anyhow::Error::msg)?;
    println!("append #1 -> seqno={} hash_len={}", a.seqno, a.entry_hash.len());
    let b = log
        .call_append(&mut store, "default", "user.logout", Severity::Info, "authd", b"alice")?.map_err(anyhow::Error::msg)?;
    println!("append #2 -> seqno={}", b.seqno);
    let c = log
        .call_append(&mut store, "audit", "policy.change", Severity::Warning, "ops", b"rotate")?.map_err(anyhow::Error::msg)?;
    println!("append #3 (audit) -> seqno={}", c.seqno);

    // read back #1
    let e = log.call_read(&mut store, a.seqno)?.map_err(anyhow::Error::msg)?;
    println!(
        "read #1 -> stream={} event={} producer={}",
        e.stream_id, e.event_type, e.producer
    );
    assert_eq!(e.stream_id, "default");
    assert_eq!(e.event_type, "user.login");

    // heads
    let dh = log.call_head(&mut store, "default")?.map_err(anyhow::Error::msg)?;
    let ah = log.call_head(&mut store, "audit")?.map_err(anyhow::Error::msg)?;
    println!("head default={dh:?} audit={ah:?}");
    assert_eq!(dh, Some(b.seqno));

    // verify chain
    log.call_verify_chain(&mut store, "default", 1, b.seqno)?.map_err(anyhow::Error::msg)?;
    println!("verify-chain default 1..{} -> OK", b.seqno);

    // close a segment, build + verify an inclusion proof
    let seg = log.call_close_segment(&mut store, "default")?.map_err(anyhow::Error::msg)?;
    println!(
        "close-segment default -> id={} [{}..{}] root_len={}",
        seg.segment_id,
        seg.seq_start,
        seg.seq_end,
        seg.merkle_root.len()
    );
    let proof = log.call_build_inclusion_proof(&mut store, a.seqno)?.map_err(anyhow::Error::msg)?;
    log.call_verify_inclusion_proof(&mut store, &proof, &seg.merkle_root)?.map_err(anyhow::Error::msg)?;
    println!(
        "inclusion-proof seqno={} steps={} -> verified",
        proof.seqno,
        proof.path.len()
    );

    // tamper check: a wrong root must fail verification
    let bad_root = vec![0u8; seg.merkle_root.len()];
    let tampered = log.call_verify_inclusion_proof(&mut store, &proof, &bad_root)?;
    assert!(tampered.is_err(), "verification should reject a wrong root");
    println!("tamper check: wrong root correctly rejected");

    // in-graph checkpoint signing: the keystore (software or softhsm) is
    // composed into the stack, so this never leaves the wasm sandbox.
    let checkpoint = bindings.secure_log_log_checkpoint();
    let (ckpt_hash, sig) = checkpoint
        .call_sign_segment(&mut store, "attest", seg.segment_id)?
        .map_err(anyhow::Error::msg)?;
    println!(
        "sign-segment attest seg={} -> hash_len={} sig_len={}",
        seg.segment_id,
        ckpt_hash.len(),
        sig.len()
    );
    let signed = checkpoint
        .call_verify_checkpoint_chain(&mut store, "default")?
        .map_err(anyhow::Error::msg)?;
    println!("verify-checkpoint-chain default -> {signed} signed segment(s)");
    assert_eq!(signed, 1, "exactly one signed segment");

    println!("\nALL CHECKS PASSED");
    Ok(())
}

/// Resolve the SoftHSM config for the pkcs11 stack: `SECURE_LOG_SOFTHSM_CONF`,
/// else the default `~/git/softhsm-wasm/tests/softhsm2-wasi.conf`. Returns
/// `None` if absent — software-keystore stacks don't need it.
fn softhsm_conf() -> Option<std::path::PathBuf> {
    let p = std::env::var("SECURE_LOG_SOFTHSM_CONF")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join("git/softhsm-wasm/tests/softhsm2-wasi.conf")
        });
    p.exists().then_some(p)
}
