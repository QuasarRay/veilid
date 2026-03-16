#!/bin/bash
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR" &> /dev/null

TEST_NAME="should create transaction, add sets, gets, and commit"
SPEC_FILE="./src/VeilidRoutingContext.test.ts"

if [ $# -ge 1 ]; then

    if [[ "$1" == "empty-transaction-commit" ]]; then
        TEST_NAME="should create empty transaction and commit"
    elif [[ "$1" == "create-set-get-commit" ]]; then
        TEST_NAME="should create transaction, add sets, gets, and commit"
    elif [[ "$1" == "create-fail-set-rollback" ]]; then
        TEST_NAME="should create empty transaction, fail non-transactional sets and then rollback"
    elif [[ "$1" == "create-set-commit-create-get-commit" ]]; then
        TEST_NAME="should create transaction, inspect, add sets to subkey 1, inspect, and commit. Then a new transaction inspect, and gets, and commit"
    else
        TEST_NAME="$1"
    fi
fi

OUTFILE=~/testout/debug-single-test-$(date +%Y%m%d-%H%M%S).log
echo "Writing output to $OUTFILE"
./wasm_test_js.sh --debug --verbose-tracing -- --spec "./src/VeilidRoutingContext.test.ts" --mochaOpts.grep "$TEST_NAME" 2>&1 | tee "$OUTFILE"
echo "Output written to $OUTFILE"

popd &> /dev/null