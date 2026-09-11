#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

if ! command -v cargo-msrv > /dev/null 2>&1; then
    echo "cargo-msrv is not installed. Please install it with: cargo install cargo-msrv --locked"
    exit 1
fi

#echo "Checking MSRV for veilid-tools"
#cargo msrv verify --manifest-path=veilid-tools/Cargo.toml

#echo "Checking MSRV for veilid-core-optimized"
#cargo msrv verify --manifest-path=veilid-core-optimized/Cargo.toml

#echo "Checking MSRV for veilid-core"
#cargo msrv verify --manifest-path=veilid-core/Cargo.toml

# Collected so each job's exit status is actually checked. A bare `wait` returns 0 whatever the
# jobs did, so `set -e` never fired and a failing `cargo msrv verify` printed "[FAIL] Is
# incompatible" and exited 0.
pids=()

echo "Checking MSRV for veilid-server"
cargo msrv verify --manifest-path=veilid-server/Cargo.toml &
pids+=($!)

# echo "Checking MSRV for veilid-cli"
# cargo msrv verify --manifest-path=veilid-cli/Cargo.toml &
# pids+=($!)

# echo "Checking MSRV for veilid-flutter"
# cargo msrv verify --manifest-path=veilid-flutter/rust/Cargo.toml &
# pids+=($!)

status=0
# `${pids[@]+...}` so an empty array does not trip `set -u` on bash 3.2, which is what macOS ships
for pid in ${pids[@]+"${pids[@]}"}; do
    if ! wait "$pid"; then
        status=1
    fi
done

popd >/dev/null
exit $status
