//! Host harness: instantiate a composed secure-log component under
//! wasmtime and exercise the exported `secure-log:log/log` interface
//! end-to-end.
//!
//! Usage: secure-log-verify [path-to-composed.wasm]
//! Default: ../dist/secure-log-sqlite.wasm

use anyhow::Result;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

wasmtime::component::bindgen!({
    path: "../wit",
    world: "secure-log-host",
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

    // Embed the reference JSON-RPC server on an ephemeral port so the
    // remote backend has an endpoint to talk to. Unused (but harmless)
    // for the sqlite/file backends.
    let (rpc_addr, _rpc_thread) = secure_log_rpc_server::spawn("127.0.0.1:0")?;
    let rpc_url = format!("http://{rpc_addr}");
    println!("embedded rpc server at {rpc_url}");

    // Preopen the current directory so the append-only file backend
    // (which uses wasi:filesystem) can read/write its log. Harmless
    // for the sqlite in-memory backend. SECURE_LOG_RPC_URL is read by
    // the wasi:http transport provider in the remote stack.
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio()
        .inherit_env()
        .env("SECURE_LOG_RPC_URL", &rpc_url);
    if std::path::Path::new(".").exists() {
        wasi.preopened_dir(".", ".", DirPerms::all(), FilePerms::all())?;
    }
    let mut store = Store::new(
        &engine,
        Host {
            wasi: wasi.build(),
            http: WasiHttpCtx::new(),
            table: ResourceTable::new(),
        },
    );

    let bindings = SecureLogHost::instantiate(&mut store, &component, &linker)?;
    let log = bindings.secure_log_log_log();

    // open the backing store explicitly (no implicit default).
    // Override with arg 2; default to an in-memory sqlite db.
    let config = std::env::args().nth(2).unwrap_or_else(|| ":memory:".to_string());
    println!("open store with config: {config:?}");
    log.call_open(&mut store, &config)?.map_err(anyhow::Error::msg)?;

    // append three entries across two streams
    let a = log
        .call_append(&mut store, "default", "user.login", "info", "authd", b"alice")?.map_err(anyhow::Error::msg)?;
    println!("append #1 -> seqno={} hash_len={}", a.seqno, a.entry_hash.len());
    let b = log
        .call_append(&mut store, "default", "user.logout", "info", "authd", b"alice")?.map_err(anyhow::Error::msg)?;
    println!("append #2 -> seqno={}", b.seqno);
    let c = log
        .call_append(&mut store, "audit", "policy.change", "warn", "ops", b"rotate")?.map_err(anyhow::Error::msg)?;
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

    println!("\nALL CHECKS PASSED");
    Ok(())
}
