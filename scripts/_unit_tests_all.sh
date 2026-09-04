#!/bin/bash
# nounset + pipefail; no `set -e` — failures are handled explicitly so this
# script returns the exit code of the first failing test step.
set -uo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR/.." >/dev/null || exit 1

if ! command -v cargo-nextest > /dev/null 2>&1; then
    echo "cargo-nextest is not installed. Please install it with: cargo install cargo-nextest --locked"
    popd >/dev/null
    exit 1
fi

TARGET=${DEFAULT_CARGO_TARGET:-$(rustup default | cut -d- -f2- | cut -d' ' -f1)}

echo "Running unit tests for target $TARGET..."
status=0
if [ "$TARGET" = "wasm32-unknown-unknown" ]; then
    # Uses cargo nextest but launches with their own chromedriver helper script internally
    echo "Running veilid-tools tests for target $TARGET..."
    ( cd veilid-tools && ./run_tests.sh wasm ) \
        && { echo "Running veilid-core tests for target $TARGET..."; ( cd veilid-core && ./run_tests.sh wasm ); } \
        && { echo "Running veilid-wasm tests for target $TARGET..."; ( cd veilid-wasm && ./wasm_test_js.sh --mock ); }
    status=$?
else
    # run_test_attachment_manager and run_test_resolver_live are the native tests that reach the
    # network. The mock pass below covers the attachment lifecycle and run_test_resolver covers
    # the resolver against a loopback nameserver, so both are excluded to keep this script offline.
    echo "Skipping run_test_attachment_manager and run_test_resolver_live (need the network)"
    cargo nextest run --tests --target $TARGET --all-targets --locked --features=debug-locks -p veilid-server -p veilid-cli -p veilid-tools -p veilid-core -p veilid-remote-api \
        -E 'not (test(=tests::native::run_test_attachment_manager) + test(=tests::native::run_test_resolver_live))'
    status=$?

    # A second pass over veilid-core against the mock, where the DHT and transaction suites run.
    # Additive, not a replacement: mock-api compiles out the subsystem unit tests.
    if [ $status -eq 0 ]; then
        echo "Running mock-api unit tests for target $TARGET..."
        cargo nextest run --tests --target $TARGET --all-targets --locked \
            -p veilid-core --no-default-features \
            --features=default-tokio,debug-api,backtrace,debug-locks,mock-api
        status=$?
    fi
fi
if [ $status -eq 0 ]; then
    echo "Finished running unit tests for target $TARGET..."
fi

popd >/dev/null
exit $status
