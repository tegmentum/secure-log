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
  remote endpoint, so the two ends cannot drift. Pure serde; compiles to
  both wasm and native.

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
- **`secure-log-rpc-server`**: the remote store's endpoint as a
  `wasi:http` guest — imports `secure-log:log/store`, exports
  `wasi:http/incoming-handler`. Compose with a store provider and run
  with `wasmtime serve`. Handlers are request-scoped, so it opens a
  file-backed store per request (`SECURE_LOG_STORE_CONFIG`).

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
       (build/sqlite.wasm)          (wasi:http)
                                         │ POST $SECURE_LOG_RPC_URL
                                         ▼
                                  secure-log-rpc-server (wasi:http guest)
                                  + store-sqlite  —  `wasmtime serve`
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
# -> dist/secure-log-rpc-server.wasm    rpc-server + store-sqlite + sqlite (remote endpoint)
```

Everything is a wasm guest — there is no host-side secure-log. Since the
core signs in-graph, every stack bundles a keystore. The
sqlite/file/remote client stacks bundle the software keystore and import
only WASI (remote additionally imports `wasi:http`; point
`SECURE_LOG_RPC_URL` at a running `secure-log-rpc-server.wasm`). The
pkcs11 stack bundles the composed softhsm keystore (from
[`softhsm-wasm`](../softhsm-wasm), via `KEYSTORE_SOFTHSM`) and imports
`pkcs11:util` + needs a SoftHSM config; it is skipped if that artifact is
absent.

### Configuration

The backing store is opened explicitly: call `log.open(config)` (which
forwards to `store.init(config)`) exactly once before any other
operation. There is no implicit default — an empty config is an error.

| backend | `config` value |
| ------- | -------------- |
| sqlite  | SQLite database path, or `":memory:"` (tests only) |
| file    | path to the append-only JSON-lines log file |
| remote  | a handshake value (the endpoint URL comes from `SECURE_LOG_RPC_URL`; the server owns its storage via `SECURE_LOG_STORE_CONFIG`) |

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

`secure-log-rpc-server.wasm` is the endpoint — itself a `wasi:http`
guest, run with `wasmtime serve`:

```bash
# -S cli enables filesystem + environment for the wasm guest
wasmtime serve -S cli --addr 127.0.0.1:8787 \
  --dir ./state::/data --env SECURE_LOG_STORE_CONFIG=/data/secure-log.db \
  dist/secure-log-rpc-server.wasm
```

`wasi:http` handlers are request-scoped, so the server holds no state
between requests: it opens the file-backed store named by
`SECURE_LOG_STORE_CONFIG` on each request, runs the op, and the
filesystem persists it. The client's `init` is a handshake; the server
owns its storage location.

### End-to-end verification

`verify/` is a standalone wasmtime host harness (excluded from the
component workspace) that instantiates a composed component and
exercises append / read / verify-chain / segment / inclusion-proof /
checkpoint signing. For the remote stack it launches the
`secure-log-rpc-server.wasm` endpoint with `wasmtime serve` (a
subprocess) and provides `wasi:http`, so no external setup is needed:

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
that exposes `keys:keystore/signer`. Signing is **in-graph**: the core
component imports `keys:keystore/signer` and exports a `checkpoint`
interface, and a keystore provider is composed into the stack via
`wac plug`. The signing key never leaves the keystore (for softhsm, it
never leaves the wasm sandbox); verification needs only the public key,
so it dispatches on the key's algorithm — **ed25519**, **ecdsa-p256**,
or **rsa-pss-sha256**.

```text
checkpoint.sign-segment(identity, segment-id)   (secure-log-component)
  -> keys:keystore/signer
       ├─ keystore-software (ed25519 / ecdsa-p256 / rsa-pss-sha256), or
       └─ softhsm: keystore-pkcs11 -> pkcs11:* -> softhsm:pkcs11
```

The softhsm keystore (`keystore-softhsm.wasm`) and its SoftHSM config
come from the [`softhsm-wasm`](../softhsm-wasm) project; the pkcs11
stack composes it guest-side. The verify harness above exercises
`sign-segment` + `verify-checkpoint-chain` for every stack.

Native consumers that embed `NativeSecureLog` as a library can still
plug their own `CheckpointSigner` (the trait remains the seam) — for a
backend that genuinely cannot be a wasm guest, e.g. a hardware HSM via
native PKCS#11, a TPM, or a cloud KMS. A wasm keystore like softhsm
belongs in the graph instead.

## Architecture

```text
canonical event → per-entry hash chain → Merkle-sealed segments →
  signed checkpoint chain → external witnessing → anti-rollback
```

- **Phase 1** — entries + per-stream hash chain.
- **Phase 2** — Merkle-sealed segments + inclusion proofs.
- **Phase 3** — checkpoint signatures, signed in-graph via a composed
  `keys:keystore/signer` (software or softhsm/PKCS#11), verified by
  algorithm (ed25519 / ecdsa-p256 / rsa-pss-sha256).
- **Phase 4** — anti-rollback head file + witness submission.
- **Phase 5** — optional payload envelope encryption with
  per-segment AEAD keys.

The WIT contract in `wit/log.wit` is the authoritative interface —
implementations in other languages must conform to it.

## Quick start

secure-log runs as a composed wasm component — storage and the signing
keystore are plugged in at composition time, and the core logic (the
`secure-log` crate, compiled into `secure-log-component`) never runs
host-side.

```bash
# 1. Build + compose the stacks (storage + keystore).
./scripts/build-components.sh

# 2. Run one end-to-end under wasmtime: append, verify the chain, close
#    a segment, build an inclusion proof, and sign + verify a checkpoint
#    — all inside the wasm graph.
cd verify
cargo run --release -- ../dist/secure-log-sqlite.wasm ":memory:"
```

A component implementing the `secure-log:log` world (see `wit/`) is a
drop-in for the whole subsystem; embedders host it with any wasi:p2
runtime (wasmtime, `wasmtime serve`, jco, …).

## License

Apache-2.0.
