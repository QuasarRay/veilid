#!/bin/bash
# Build the JavaScript/TypeScript wasm bundle for veilid-wasm.
#
# Pipeline: cargo build → wasm-bindgen → wasm-opt (release only).
#
# Usage:
#   ./wasm_build_js.sh                 # debug build (debug-api, wasm-bindgen --keep-debug)
#   ./wasm_build_js.sh release         # size profile + wasm-opt -Oz
#   ./wasm_build_js.sh release --features=foo
#   ./wasm_build_js.sh release --no-wasm-opt   # release build, skip the slow wasm-opt pass
#
# Extra args after the optional `release` token are forwarded to cargo build.

set -eo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR" &>/dev/null

if [ $# -ge 1 ] && [ "$1" = "release" ]; then
    echo "Release build enabled."
    RELEASE=1
    shift
else
    RELEASE=0
fi

SKIP_WASM_OPT=0
CARGO_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-wasm-opt|--skip-wasm-opt)
            SKIP_WASM_OPT=1
            ;;
        *)
            CARGO_ARGS+=("$arg")
            ;;
    esac
done
set -- "${CARGO_ARGS[@]}"

OUTPUTDIR="$SCRIPTDIR/pkg"
WORKSPACE_TARGET="$SCRIPTDIR/../target/wasm32-unknown-unknown"

# --- cargo build -------------------------------------------------------------
# A RUSTFLAGS in the environment replaces the `[target.wasm32-unknown-unknown]` rustflags in
# the workspace `.cargo/config.toml` wholesale rather than adding to them, so re-add the
# `--cfg=web_sys_unstable_apis` that the web-sys WebTransport bindings need.
if [ -n "$RUSTFLAGS" ]; then
    export RUSTFLAGS="$RUSTFLAGS --cfg=web_sys_unstable_apis"
fi

if [ "$RELEASE" -eq 1 ]; then
    cargo build --target wasm32-unknown-unknown --profile size "$@"
    WASM_IN="$WORKSPACE_TARGET/size/veilid_wasm.wasm"
else
    cargo build --target wasm32-unknown-unknown --features debug-api "$@"
    WASM_IN="$WORKSPACE_TARGET/debug/veilid_wasm.wasm"
fi

# --- wasm-bindgen ------------------------------------------------------------
mkdir -p "$OUTPUTDIR"
# -r because wasm-bindgen emits a snippets/ directory that must not accumulate stale copies
rm -rf "$OUTPUTDIR"/*
if [ "$RELEASE" -eq 1 ]; then
    wasm-bindgen --target web --weak-refs --out-dir "$OUTPUTDIR" "$WASM_IN"
else
    wasm-bindgen --target web --weak-refs --out-dir "$OUTPUTDIR" --keep-debug --debug "$WASM_IN"
fi

# --- wasm-opt (release only) ------------------------------------------------
if [ "$RELEASE" -eq 1 ] && [ "$SKIP_WASM_OPT" -eq 1 ]; then
    echo "Skipping wasm-opt (--no-wasm-opt); release bundle is unoptimized."
fi
if [ "$RELEASE" -eq 1 ] && [ "$SKIP_WASM_OPT" -eq 0 ]; then
    wasm-opt \
        --converge \
        --low-memory-unused \
        --flatten \
        --rereloop \
        -Oz \
        "$OUTPUTDIR/veilid_wasm_bg.wasm" \
        -o "$OUTPUTDIR/veilid_wasm_bg.wasm.opt"
    mv "$OUTPUTDIR/veilid_wasm_bg.wasm.opt" "$OUTPUTDIR/veilid_wasm_bg.wasm"
fi

# --- error classes -----------------------------------------------------------
# The bridge snippet in pkg/snippets reaches back to these, so the glue and package
# consumers share one class identity and `instanceof` holds for errors from wasm.
cp -f "$SCRIPTDIR/js/veilid_errors.js" "$OUTPUTDIR/veilid_errors.js"
cp -f "$SCRIPTDIR/js/veilid_errors.d.ts" "$OUTPUTDIR/veilid_errors.d.ts"
echo "export * from './veilid_errors.js';" >> "$OUTPUTDIR/veilid_wasm.js"
echo "export * from './veilid_errors.js';" >> "$OUTPUTDIR/veilid_wasm.d.ts"

# --- package.json + license + readme ----------------------------------------
VERSION="$(awk -F'"' '/^version = "/ {print $2; exit}' "$SCRIPTDIR/Cargo.toml")"
sed "s/{{VERSION}}/$VERSION/" "$SCRIPTDIR/pkg.template.json" > "$OUTPUTDIR/package.json"
cp -f "$SCRIPTDIR/LICENSE.md" "$OUTPUTDIR/LICENSE.md" 2>/dev/null || true
cp -f "$SCRIPTDIR/README.md" "$OUTPUTDIR/README.md" 2>/dev/null || true

popd &>/dev/null

echo "Built veilid-wasm $VERSION ($( [ $RELEASE -eq 1 ] && echo release || echo debug ))"
echo "Output: $OUTPUTDIR"
