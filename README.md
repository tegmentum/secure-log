# secure-log

Tamper-evident audit log for Rust. Hash-chained entries, Merkle-sealed
segments, externally-signed checkpoints, witness anti-equivocation,
and optional AEAD payload sealing.

## Crates

Native (build with `cargo build` / `cargo test`):

- **`secure-log`**: core types, `SecureLog` trait, `NativeSecureLog`
  implementation, canonical CBOR encoder, hash chain, Merkle tree,
  inclusion proofs, witness submission format, payload AEAD, the
  `SecureLogStore` persistence trait, and the `CheckpointSigner`
  abstraction.
- **`secure-log-sqlite`**: `SqliteSecureLogStore` — SQLite-backed
  storage (rusqlite) that implements `SecureLogStore`. Manages its
  own migrations.
- **`secure-log-rpc`**: the JSON-RPC wire contract (row mirror types +
  method-name constants) shared by the remote store provider and the
  server, so the two ends cannot drift.
- **`secure-log-rpc-server`**: the reference JSON-RPC server. Terminates
  the remote wire protocol and dispatches each of the 23 store ops to a
  native `SecureLogStore` (SQLite-backed). The host-side peer of the
  remote backend.
- **`secure-log-signer-keystore`**: a `CheckpointSigner` backed by the
  `keys:keystore/signer` interface (PKCS#11 via `softhsm-wasm`), driven
  in-process with wasmtime. The ed25519 signing key never leaves the
  wasm sandbox. Workspace member but not a default member (pulls
  wasmtime); build/test with `-p secure-log-signer-keystore`.

WASI Preview 2 components (build with
`cargo component build --target wasm32-wasip2`):

- **`secure-log-component`**: the core, packaged as a component.
  Imports `secure-log:log/store` + `keys:keystore/signer`, exports
  `secure-log:log/{encoder,log,checkpoint}`. Checkpoint signing happens
  in-graph; verification dispatches on the key's algorithm (ed25519 /
  ecdsa-p256 / rsa-pss-sha256).
- **`secure-log-store-sqlite`**: a `secure-log:store` provider backed
  by the [`sqlite:wasm`](../sqlite-wasm) component.
- **`secure-log-store-file`**: a `secure-log:store` provider backed by
  an append-only JSON-lines file on the WASI filesystem.
- **`secure-log-store-remote`**: a `secure-log:store` provider that
  forwards each operation as JSON-RPC over a pluggable `transport`
  interface (network-agnostic).
- **`secure-log-transport-http`**: the default `transport` provider,
  backed by `wasi:http`. Each `rpc` call becomes an HTTP POST to the URL
  in `SECURE_LOG_RPC_URL`. Swap it for any other `transport` provider
  (host function, message queue, ...) without touching the store.
- **`secure-log-keystore-software`**: a `keys:keystore/signer` provider,
  pure software (ed25519 / ecdsa-p256 / rsa-pss-sha256, chosen via
  `SECURE_LOG_KEYSTORE_ALG`). The default in-graph signing backend; the
  composed softhsm keystore (`keys:keystore` over PKCS#11) is the
  production alternative.

## Component architecture (pluggable persistence)

```text
                    secure-log-component (core)
                    exports secure-log:log/{encoder,log,checkpoint}
                    imports secure-log:log/store + keys:keystore/signer
                              │                         │
        store ┌──────────────┼───────────────┐        │ keys:keystore/signer
              ▼              ▼                ▼         ▼
       store-sqlite     store-file      store-remote   ├── keystore-software
       imports          (wasi:fs)       imports        │   (ed25519/ecdsa/rsa)
       sqlite:wasm                      transport      └── keystore (softhsm)
              │                            │               keystore-pkcs11
              ▼                            ▼               + pkcs11-provider
       sqlite-wasm                  transport-http         + softhsm2.component
       (build/sqlite.wasm)          (wasi:http) -> secure-log-rpc-server
```

Both persistence and signing are pluggable at two levels: the Rust
traits (`SecureLogStore`, `CheckpointSigner`) for native use, and the
`secure-log:log/store` + `keys:keystore/signer` WIT interfaces for
components, chosen at composition time via `wac plug`.

### Build & compose

```bash
# builds the component crates and composes each stack (storage + keystore)
./scripts/build-components.sh
# -> dist/secure-log-sqlite.wasm        core + store-sqlite + sqlite + software keystore
# -> dist/secure-log-file.wasm          core + store-file + software keystore
# -> dist/secure-log-remote.wasm        core + store-remote + transport-http + software keystore
# -> dist/secure-log-sqlite-pkcs11.wasm core + store-sqlite + sqlite + softhsm keystore
```

Since the core signs in-graph, every stack bundles a keystore. The
sqlite/file/remote stacks bundle the software keystore and import only
WASI (remote additionally imports `wasi:http`; set `SECURE_LOG_RPC_URL`
and run `secure-log-rpc-server`). The pkcs11 stack bundles the composed
softhsm keystore (from [`softhsm-wasm`](../softhsm-wasm), via
`KEYSTORE_SOFTHSM`) and additionally imports `pkcs11:util` + needs a
SoftHSM config; it is skipped if that artifact is absent.

### Configuration

The backing store is opened explicitly: call `log.open(config)` (which
forwards to `store.init(config)`) exactly once before any other
operation. There is no implicit default — an empty config is an error.

| backend | `config` value |
| ------- | -------------- |
| sqlite  | SQLite database path, or `":memory:"` (tests only) |
| file    | path to the append-only JSON-lines log file |
| remote  | the **server-side** store locator (forwarded to the server's own `init`); the endpoint URL comes from `SECURE_LOG_RPC_URL` |

> Note: file-backed sqlite requires the `sqlite:wasm` component to
> select its WASI VFS for file opens (it defaults to an in-memory
> VFS). This is fixed upstream as of sqlite-wasm commit `19c6ac7`;
> with that build, a path under a preopened directory produces a real
> on-disk `SQLite format 3` database that survives reopening. Both the
> `sqlite` (file) and `file` backends now persist across instances.

### Remote transport protocol

The remote backend calls `transport.rpc(method, params-json)` once per
store operation. The contract (method names + row shapes) is the
`secure-log-rpc` crate, shared by both ends:

- `method` — the store function name (e.g. `secure-log-insert`).
- `params-json` — a JSON array of the call's arguments, in order.
- the returned string — a JSON encoding of the return value, or the
  call returns `err(message)`.

The default `transport-http` provider sends each call as an HTTP POST
to `SECURE_LOG_RPC_URL` with body `{"method": ..., "params": ...}`; a
2xx response body is the result, any other status is the error. The
`transport` interface is itself swappable (host function, message
queue, ...) — only this one provider depends on `wasi:http`.

`secure-log-rpc-server` is the reference endpoint:

```bash
# start the server (defaults to 127.0.0.1:8787)
cargo run -p secure-log-rpc-server -- --addr 127.0.0.1:8787
```

It opens its own `SecureLogStore` (SQLite) when it receives the `init`
call, using the `config` the client passed to `log.open(...)`.

### End-to-end verification

`verify/` is a standalone wasmtime host harness (excluded from the
component workspace) that instantiates a composed component and
exercises append / read / verify-chain / segment / inclusion-proof.
For the remote stack it also embeds `secure-log-rpc-server` on an
ephemeral port and provides `wasi:http`, so no external process is
needed:

```bash
cd verify
# args: <composed.wasm> [store-config]; the harness also exercises
# checkpoint sign + verify-checkpoint-chain in-graph.
cargo run --release -- ../dist/secure-log-sqlite.wasm ":memory:"
cargo run --release -- ../dist/secure-log-file.wasm   "audit.jsonl"
cargo run --release -- ../dist/secure-log-remote.wasm ":memory:"
# choose the software keystore algorithm:
SECURE_LOG_KEYSTORE_ALG=ecdsa-p256 cargo run --release -- ../dist/secure-log-sqlite.wasm ":memory:"
# pkcs11/softhsm signing entirely in-graph (needs the softhsm config):
cargo run --release -- ../dist/secure-log-sqlite-pkcs11.wasm ":memory:"
```

### Checkpoint signing (`keys:keystore`)

Phase 3 signs each closed segment's checkpoint hash through a keystore
that exposes `keys:keystore/signer`. The signing key never leaves the
keystore; verification needs only the public key, so it dispatches on
the key's algorithm — **ed25519**, **ecdsa-p256**, or
**rsa-pss-sha256**. Two integration paths share this contract:

**In-graph (component).** The core component imports
`keys:keystore/signer` and exports a `checkpoint` interface; the
keystore is composed into the stack via `wac plug`. Signing happens
entirely inside the wasm graph:

```text
checkpoint.sign-segment(identity, segment-id)   (secure-log-component)
  -> keys:keystore/signer
       ├─ keystore-software (ed25519 / ecdsa-p256 / rsa-pss-sha256), or
       └─ softhsm: keystore-pkcs11 -> pkcs11:* -> softhsm:pkcs11
```

**Host-side (native).** `secure-log-signer-keystore` implements the
`CheckpointSigner` trait by driving the composed `keystore-softhsm.wasm`
in-process with wasmtime — for daemons/CLIs using `NativeSecureLog`
directly. The key stays in the softhsm sandbox; verification is local
(`ed25519-dalek` / `p256` / `rsa`).

```rust,no_run
use secure_log::{CborEncoder, NativeSecureLog};
use secure_log_signer_keystore::{KeystoreSigner, KeystoreSignerConfig};
use secure_log_sqlite::SqliteSecureLogStore;

let signer = KeystoreSigner::open(&KeystoreSignerConfig {
    component_path: "keystore-softhsm.wasm".into(),
    conf_path: "softhsm2-wasi.conf".into(),
    token_dir: ".secure-log/pkcs11".into(),
    pin: "1234".into(),
    so_pin: "1234".into(),
})?;
let log = NativeSecureLog::new(
    Box::new(SqliteSecureLogStore::open("audit.db")?),
    Box::new(CborEncoder::new()),
);
// ... append entries ...
let seg = secure_log::SecureLog::close_segment(&log, "default")?;
log.sign_segment(&signer, "attest", seg.segment_id)?;     // key in the HSM
log.verify_checkpoint_chain(&signer, "default")?;          // ed25519, local
# Ok::<(), Box<dyn std::error::Error>>(())
```

The composed `keystore-softhsm.wasm` and SoftHSM config come from the
[`softhsm-wasm`](../softhsm-wasm) project. The end-to-end test points at
them via `SECURE_LOG_KEYSTORE_WASM` / `SECURE_LOG_SOFTHSM_CONF` (and
falls back to their default `~/git/softhsm-wasm/...` locations), and
skips when they are absent:

```bash
cargo test -p secure-log-signer-keystore
```

## Architecture

```text
canonical event → per-entry hash chain → Merkle-sealed segments →
  signed checkpoint chain → external witnessing → anti-rollback
```

- **Phase 1** — entries + per-stream hash chain.
- **Phase 2** — Merkle-sealed segments + inclusion proofs.
- **Phase 3** — checkpoint signatures (via `CheckpointSigner` trait;
  consumers wire in TPM, HSM, file-based Ed25519, etc.).
- **Phase 4** — anti-rollback head file + witness submission.
- **Phase 5** — optional payload envelope encryption with
  per-segment AEAD keys.

The WIT contract in `wit/log.wit` is the authoritative interface —
implementations in other languages must conform to it.

## Quick start

```rust,no_run
use secure_log::{CborEncoder, NativeSecureLog, SecureLog};
use secure_log_sqlite::SqliteSecureLogStore;

let store = SqliteSecureLogStore::open("audit.db")?;
let encoder = Box::new(CborEncoder::new());
let log = NativeSecureLog::new(Box::new(store), encoder);

log.append("default", "user.login", "info", "authd", b"{\"u\":\"alice\"}")?;
log.verify_chain("default", 1, 1)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

Apache-2.0.
