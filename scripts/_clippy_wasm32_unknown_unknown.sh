#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

if [ $# -ge 1 ] && [ "$1" = "--cleanup" ] ; then
    echo "Cleanup enabled for clippy."
    CLEANUP=1
    shift
else
    CLEANUP=0
fi

echo "Running clippy for wasm32-unknown-unknown..."
cargo clippy --manifest-path=veilid-wasm/Cargo.toml --target wasm32-unknown-unknown --features=js,dart --all-targets --locked $@
if [ $CLEANUP -eq 1 ] ; then
    rm -rf target/wasm32-unknown-unknown
fi

popd >/dev/null
