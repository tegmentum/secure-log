#!/usr/bin/env bash
#
# Build the secure-log WASI Preview 2 components and compose them with
# each storage backend via `wac plug`.
#
# Outputs land in dist/:
#   secure-log-sqlite.wasm  — core + store-sqlite + sqlite:wasm engine
#   secure-log-file.wasm    — core + store-file (append-only file)
#   secure-log-remote.wasm  — core + store-remote + transport-http
#                             (forwards over wasi:http to a JSON-RPC server)
#
# The sqlite stack embeds the prebuilt sqlite:wasm component. Point
# SQLITE_WASM at it if it is not at the default location.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"
TARGET="$REPO/target/wasm32-wasip2/release"
DIST="$REPO/dist"
SQLITE_WASM="${SQLITE_WASM:-$REPO/../sqlite-wasm/build/sqlite.wasm}"

mkdir -p "$DIST"

echo "==> Building components (wasm32-wasip2, release)"
for crate in \
    secure-log-component \
    secure-log-store-sqlite \
    secure-log-store-file \
    secure-log-store-remote \
    secure-log-transport-http
do
    echo "    - $crate"
    ( cd "crates/$crate" && cargo component build --release --target wasm32-wasip2 )
done

CORE="$TARGET/secure_log_component.wasm"
STORE_SQLITE="$TARGET/secure_log_store_sqlite.wasm"
STORE_FILE="$TARGET/secure_log_store_file.wasm"
STORE_REMOTE="$TARGET/secure_log_store_remote.wasm"
TRANSPORT_HTTP="$TARGET/secure_log_transport_http.wasm"

echo "==> Composing sqlite stack"
if [[ -f "$SQLITE_WASM" ]]; then
    wac plug --plug "$SQLITE_WASM" "$STORE_SQLITE" -o "$DIST/.store-sqlite.plugged.wasm"
    wac plug --plug "$DIST/.store-sqlite.plugged.wasm" "$CORE" -o "$DIST/secure-log-sqlite.wasm"
    rm -f "$DIST/.store-sqlite.plugged.wasm"
    echo "    -> dist/secure-log-sqlite.wasm"
else
    echo "    !! sqlite:wasm component not found at $SQLITE_WASM; skipping."
    echo "       Build it in ../sqlite-wasm or set SQLITE_WASM=<path>."
fi

echo "==> Composing file stack"
wac plug --plug "$STORE_FILE" "$CORE" -o "$DIST/secure-log-file.wasm"
echo "    -> dist/secure-log-file.wasm"

echo "==> Composing remote stack (store-remote + transport-http + core)"
# 1) transport-http's `transport` export satisfies store-remote's import.
wac plug --plug "$TRANSPORT_HTTP" "$STORE_REMOTE" -o "$DIST/.store-remote.plugged.wasm"
# 2) the resulting `store` export satisfies core's import.
wac plug --plug "$DIST/.store-remote.plugged.wasm" "$CORE" -o "$DIST/secure-log-remote.wasm"
rm -f "$DIST/.store-remote.plugged.wasm"
echo "    -> dist/secure-log-remote.wasm (imports wasi:http; set SECURE_LOG_RPC_URL"
echo "       and run secure-log-rpc-server as the endpoint)"

echo "==> Done. Artifacts in dist/:"
ls -lh "$DIST"/*.wasm 2>/dev/null | awk '{print "    " $9 "  " $5}'
