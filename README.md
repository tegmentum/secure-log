# secure-log

Tamper-evident audit log for Rust. Hash-chained entries, Merkle-sealed
segments, externally-signed checkpoints, witness anti-equivocation,
and optional AEAD payload sealing.

## Crates

- **`secure-log`**: core types, `SecureLog` trait, `NativeSecureLog`
  implementation, canonical CBOR encoder, hash chain, Merkle tree,
  inclusion proofs, witness submission format, payload AEAD.
- **`secure-log-sqlite`**: `SqliteSecureLogStore` — SQLite-backed
  storage that implements the `SecureLogStore` trait. Manages its own
  migrations.

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
