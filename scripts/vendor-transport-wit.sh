#!/usr/bin/env bash
#
# Regenerate crates/secure-log-transport-http/wit-vendor/.
#
# cargo-component 0.21 resolves a component's target WIT only from
# [package.metadata.component.target.dependencies] (it does not scan
# wit/deps), and it parses each listed dependency in isolation. So every
# package in the import closure must be listed, and each dependency dir
# must be self-contained (carry its own deps/). This script fetches the
# official wasi@0.2.6 packages with `wkg` and assembles that layout:
#
#   wit-vendor/<pkg>/package.wit
#   wit-vendor/<pkg>/deps/<other-pkg>/...   (every other closure package)
#
# wasi@0.2.6 matches the wasmtime-wasi-http 44 host used by verify/.
#
# Requires: wkg (https://github.com/bytecodealliance/wasm-pkg-tools).
set -euo pipefail

cd "$(dirname "$0")/.."
CRATE="crates/secure-log-transport-http"
VENDOR="$CRATE/wit-vendor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1) Fetch the wasi@0.2.6 closure. `wkg wit fetch` resolves a world, but
#    it can't resolve the local secure-log:log package, so fetch against a
#    temporary world that imports only the wasi interfaces we use.
mkdir -p "$TMP/wit"
cat > "$TMP/wit/world.wit" <<'EOF'
package secure-log:transport-http-fetch@0.1.0;
world fetch {
    import wasi:http/outgoing-handler@0.2.6;
    import wasi:cli/environment@0.2.6;
}
EOF
( cd "$TMP" && wkg wit fetch >/dev/null 2>&1 )

# 2) Stage every closure package as <name> -> source dir.
mkdir -p "$TMP/src/secure-log-log"
cp wit/log.wit wit/store.wit "$TMP/src/secure-log-log/"
for d in "$TMP"/wit/deps/wasi-*-0.2.6; do
    name="$(basename "$d")"; name="${name#wasi-}"; name="${name%-0.2.6}"
    mkdir -p "$TMP/src/$name"
    cp "$d"/*.wit "$TMP/src/$name/"
done

PKGS=()
for d in "$TMP"/src/*; do PKGS+=("$(basename "$d")"); done

# 3) Build the self-contained cross-product tree.
rm -rf "$VENDOR"; mkdir -p "$VENDOR"
for p in "${PKGS[@]}"; do
    mkdir -p "$VENDOR/$p"
    cp "$TMP/src/$p"/*.wit "$VENDOR/$p/"
    for q in "${PKGS[@]}"; do
        if [ "$q" != "$p" ]; then
            mkdir -p "$VENDOR/$p/deps/$q"
            cp "$TMP/src/$q"/*.wit "$VENDOR/$p/deps/$q/"
        fi
    done
done

echo "Regenerated $VENDOR ($(find "$VENDOR" -name '*.wit' | wc -l | tr -d ' ') files, ${#PKGS[@]} packages)."
echo "Listed packages: ${PKGS[*]}"
echo "Remember to keep [package.metadata.component.target.dependencies] in"
echo "$CRATE/Cargo.toml in sync with these package names."
