#!/usr/bin/env bash
#
# Build the secure-log WASI Preview 2 components and compose each stack
# via `wac plug`. The core now signs checkpoints in-graph, so every stack
# bundles BOTH a storage provider and a keystore (signer) provider.
#
# Outputs land in dist/:
#   secure-log-sqlite.wasm        core + store-sqlite + sqlite + software keystore
#   secure-log-file.wasm          core + store-file + software keystore
#   secure-log-remote.wasm        core + store-remote + transport-http + software keystore
#   secure-log-sqlite-pkcs11.wasm core + store-sqlite + sqlite + softhsm keystore
#   secure-log-rpc-server.wasm    rpc-server + store-sqlite + sqlite
#                                 (the remote endpoint; `wasmtime serve` it)
#
# The sqlite stack embeds the prebuilt sqlite:wasm component (SQLITE_WASM).
# The pkcs11 stack embeds the composed keys:keystore softhsm component
# (KEYSTORE_SOFTHSM); both are skipped if their artifact is absent.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"
TARGET="$REPO/target/wasm32-wasip2/release"
DIST="$REPO/dist"
SQLITE_WASM="${SQLITE_WASM:-$REPO/../sqlite-wasm/build/sqlite.wasm}"
KEYSTORE_SOFTHSM="${KEYSTORE_SOFTHSM:-$REPO/../softhsm-wasm/keystore-pkcs11/target/wasm32-wasip2/release/keystore-softhsm.wasm}"

mkdir -p "$DIST"

echo "==> Building components (wasm32-wasip2, release)"
for crate in \
    secure-log-component \
    secure-log-store-sqlite \
    secure-log-store-file \
    secure-log-store-remote \
    secure-log-transport-http \
    secure-log-keystore-software
do
    echo "    - $crate"
    ( cd "crates/$crate" && cargo component build --release --target wasm32-wasip2 )
done

# secure-log-rpc-server uses wit_bindgen::generate! (scans wit/deps), so it
# builds with plain cargo + the wasip2 component linker, not cargo-component.
echo "    - secure-log-rpc-server"
cargo build --release --target wasm32-wasip2 -p secure-log-rpc-server

CORE="$TARGET/secure_log_component.wasm"
STORE_SQLITE="$TARGET/secure_log_store_sqlite.wasm"
STORE_FILE="$TARGET/secure_log_store_file.wasm"
STORE_REMOTE="$TARGET/secure_log_store_remote.wasm"
TRANSPORT_HTTP="$TARGET/secure_log_transport_http.wasm"
KEYSTORE_SW="$TARGET/secure_log_keystore_software.wasm"
RPC_SERVER="$TARGET/secure_log_rpc_server.wasm"

# Pre-plug the sqlite engine into the sqlite store provider (reused by the
# plain and pkcs11 sqlite stacks).
SQLITE_STORE=""
if [[ -f "$SQLITE_WASM" ]]; then
    wac plug --plug "$SQLITE_WASM" "$STORE_SQLITE" -o "$DIST/.store-sqlite.plugged.wasm"
    SQLITE_STORE="$DIST/.store-sqlite.plugged.wasm"
fi

echo "==> Composing sqlite stack (+ software keystore)"
if [[ -n "$SQLITE_STORE" ]]; then
    wac plug --plug "$KEYSTORE_SW" --plug "$SQLITE_STORE" "$CORE" -o "$DIST/secure-log-sqlite.wasm"
    echo "    -> dist/secure-log-sqlite.wasm"
else
    echo "    !! sqlite:wasm not found at $SQLITE_WASM; skipping sqlite stacks."
fi

echo "==> Composing file stack (+ software keystore)"
wac plug --plug "$KEYSTORE_SW" --plug "$STORE_FILE" "$CORE" -o "$DIST/secure-log-file.wasm"
echo "    -> dist/secure-log-file.wasm"

echo "==> Composing remote-store endpoint (rpc-server + store-sqlite)"
if [[ -n "$SQLITE_STORE" ]]; then
    # The server imports the store; plug the sqlite store stack into it.
    wac plug --plug "$SQLITE_STORE" "$RPC_SERVER" -o "$DIST/secure-log-rpc-server.wasm"
    echo "    -> dist/secure-log-rpc-server.wasm (exports wasi:http/incoming-handler;"
    echo "       run with: wasmtime serve dist/secure-log-rpc-server.wasm)"
else
    echo "    !! sqlite:wasm not found; skipping rpc-server endpoint."
fi

echo "==> Composing remote stack (store-remote + transport-http + software keystore)"
wac plug --plug "$TRANSPORT_HTTP" "$STORE_REMOTE" -o "$DIST/.store-remote.plugged.wasm"
wac plug --plug "$KEYSTORE_SW" --plug "$DIST/.store-remote.plugged.wasm" "$CORE" -o "$DIST/secure-log-remote.wasm"
rm -f "$DIST/.store-remote.plugged.wasm"
echo "    -> dist/secure-log-remote.wasm (imports wasi:http; run secure-log-rpc-server)"

echo "==> Composing pkcs11 sqlite stack (+ softhsm keystore)"
if [[ -n "$SQLITE_STORE" && -f "$KEYSTORE_SOFTHSM" ]]; then
    wac plug --plug "$KEYSTORE_SOFTHSM" --plug "$SQLITE_STORE" "$CORE" -o "$DIST/secure-log-sqlite-pkcs11.wasm"
    echo "    -> dist/secure-log-sqlite-pkcs11.wasm (imports pkcs11:util + wasi; needs softhsm config)"
else
    echo "    !! softhsm keystore not found at $KEYSTORE_SOFTHSM (or no sqlite); skipping pkcs11 stack."
fi

rm -f "$DIST/.store-sqlite.plugged.wasm"

echo "==> Done. Artifacts in dist/:"
ls -lh "$DIST"/*.wasm 2>/dev/null | awk '{print "    " $9 "  " $5}'
