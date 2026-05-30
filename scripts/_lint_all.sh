#!/bin/bash
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $SCRIPTDIR/.. >/dev/null

# Rust clippy across all platforms
scripts/_clippy_wasm32_unknown_unknown.sh $@
scripts/_clippy_x86_64_pc_windows_gnu.sh $@
scripts/_clippy_aarch64_apple_darwin.sh $@
scripts/_clippy_x86_64_unknown_linux_gnu.sh $@
scripts/_clippy_x86_64_unknown_linux_gnu_async_std.sh $@

# Flutter analyze for every dart/flutter package in the workspace
for pkg in \
    veilid-flutter \
    veilid-flutter/example \
    veilid-flutter/packages/veilid_test \
    veilid-flutter/packages/veilid_integration_test ; do
    echo "==> flutter analyze $pkg"
    (cd "$pkg" && flutter analyze)
done

popd >/dev/null
