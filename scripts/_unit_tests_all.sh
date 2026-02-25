#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

if ! command -v cargo-nextest > /dev/null 2>&1; then
    echo "cargo-nextest is not installed. Please install it with: cargo install cargo-nextest --locked"
    exit 1
fi

TARGET=${DEFAULT_CARGO_TARGET:-$(rustup default | cut -d- -f2- | cut -d' ' -f1)}

echo "Running unit tests for target $TARGET..."
cargo nextest run --locked --tests --target $TARGET --workspace --all-targets 

popd >/dev/null
