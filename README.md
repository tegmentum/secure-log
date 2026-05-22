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

WASI Preview 2 components (build with
`cargo component build --target wasm32-wasip2`):

- **`secure-log-component`**: the core, packaged as a component.
  Imports `secure-log:log/store`, exports `secure-log:log/{encoder,log}`.
- **`secure-log-store-sqlite`**: a `secure-log:store` provider backed
  by the [`sqlite:wasm`](../sqlite-wasm) component.
- **`secure-log-store-file`**: a `secure-log:store` provider backed by
  an append-only JSON-lines file on the WASI filesystem.
- **`secure-log-store-remote`**: a `secure-log:store` provider that
  forwards each operation as JSON-RPC over a pluggable `transport`
  interface (network-agnostic).

## Component architecture (pluggable persistence)

```text
                    secure-log-component (core)
                    exports secure-log:log/{encoder,log}
                    imports secure-log:log/store
                              │
              ┌───────────────┼────────────────────┐
              ▼               ▼                     ▼
       store-sqlite      store-file           store-remote
       exports store     exports store        exports store
       imports           (wasi:filesystem)    imports
       sqlite:wasm                            secure-log:log/transport
              │
              ▼
       sqlite-wasm (build/sqlite.wasm)
```

Persistence is pluggable at two levels: the `SecureLogStore` Rust
trait (native), and the `secure-log:log/store` WIT interface
(components, chosen at composition time via `wac plug`).

### Build & compose

```bash
# builds all four component crates and composes each backend stack
./scripts/build-components.sh
# -> dist/secure-log-sqlite.wasm   (core + store-sqlite + sqlite engine)
# -> dist/secure-log-file.wasm     (core + store-file)
# -> dist/secure-log-remote.wasm   (core + store-remote; imports transport)
```

`secure-log-sqlite.wasm` and `secure-log-file.wasm` import only WASI
and export `secure-log:log`. `secure-log-remote.wasm` additionally
imports `secure-log:log/transport`; supply a provider for it before
running.

### Configuration

The backing store is opened explicitly: call `log.open(config)` (which
forwards to `store.init(config)`) exactly once before any other
operation. There is no implicit default — an empty config is an error.

| backend | `config` value |
| ------- | -------------- |
| sqlite  | SQLite database path, or `":memory:"` (tests only) |
| file    | path to the append-only JSON-lines log file |
| remote  | endpoint locator, forwarded to the transport |

> Note: file-backed sqlite requires the `sqlite:wasm` component to
> select its WASI VFS for file opens (it defaults to an in-memory
> VFS). This is fixed upstream as of sqlite-wasm commit `19c6ac7`;
> with that build, a path under a preopened directory produces a real
> on-disk `SQLite format 3` database that survives reopening. Both the
> `sqlite` (file) and `file` backends now persist across instances.

### Remote transport protocol (proposed default)

The remote backend calls `transport.rpc(method, params-json)` once per
store operation:

- `method` — the store function name (e.g. `secure-log-insert`).
- `params-json` — a JSON array of the call's arguments, in order.
- the returned string — a JSON encoding of the return value, or the
  call returns `err(message)`.

A `transport` provider can be backed by `wasi:http`, a host function,
a message queue, etc. — that choice is itself swappable.

### End-to-end verification

`verify/` is a standalone wasmtime host harness (excluded from the
component workspace) that instantiates a composed component and
exercises append / read / verify-chain / segment / inclusion-proof:

```bash
cd verify
# args: <composed.wasm> [store-config]
cargo run --release -- ../dist/secure-log-sqlite.wasm ":memory:"
cargo run --release -- ../dist/secure-log-file.wasm   "audit.jsonl"
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
