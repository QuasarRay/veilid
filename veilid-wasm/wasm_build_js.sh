#!/bin/bash
set -eo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR" &> /dev/null


if [ $# -ge 1 ] && [ "$1" = "release" ] ; then
    echo "Release build enabled."
    RELEASE=1
    shift
else
    RELEASE=0
fi

if [ "$RELEASE" -eq 1 ]; then
  WASM_PACK_FLAGS="--release"
else
  WASM_PACK_FLAGS="--dev"
fi

# Build wasm into an npm package, output into ./pkg
wasm-pack build $WASM_PACK_FLAGS --target bundler $@
