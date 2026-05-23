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

    // Embed the reference JSON-RPC server on an ephemeral port so the
    // remote backend has an endpoint to talk to. Unused (but harmless)
    // for the sqlite/file backends.
    let (rpc_addr, _rpc_thread) = secure_log_rpc_server::spawn("127.0.0.1:0")?;
    let rpc_url = format!("http://{rpc_addr}");
    println!("embedded rpc server at {rpc_url}");

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
