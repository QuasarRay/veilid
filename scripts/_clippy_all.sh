#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

scripts/_clippy_wasm32_unknown_unknown.sh $@
scripts/_clippy_x86_64_pc_windows_gnu.sh $@
scripts/_clippy_aarch64_apple_darwin.sh $@
scripts/_clippy_x86_64_unknown_linux_gnu.sh $@
scripts/_clippy_x86_64_unknown_linux_gnu_async_std.sh $@

popd >/dev/null
