#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

if [ $# -ge 1 ] && [ "$1" = "--cleanup" ] ; then
    CLEANUP="--cleanup"
    shift
else
    CLEANUP=""
fi

echo "Running all tests..."

./scripts/_check_public_api.sh
./scripts/_msrv_all.sh
./scripts/_check_wasm_builds.sh dart # skip cleanup here because WASM is done first in the clippy script and will clean up there
./scripts/_check_wasm_builds.sh js # skip cleanup here because WASM is done first in the clippy script and will clean up there
./scripts/_lint_all.sh $CLEANUP
./scripts/_build_docs.sh $CLEANUP
./scripts/_unit_tests_all.sh
DEFAULT_CARGO_TARGET=wasm32-unknown-unknown ./scripts/_unit_tests_all.sh 

popd >/dev/null