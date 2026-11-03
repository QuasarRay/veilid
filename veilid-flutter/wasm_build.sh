#!/bin/bash
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -eo pipefail

get_abs_filename() {
    # $1 : relative filename
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}

pushd $SCRIPTDIR &> /dev/null

if [ $# -ge 1 ] && [ "$1" = "release" ] ; then
    echo "Release build enabled."
    RELEASE=1
    shift
else
    RELEASE=0
fi

# A RUSTFLAGS in the environment replaces the `[target.wasm32-unknown-unknown]` rustflags in
# the workspace `.cargo/config.toml` wholesale rather than adding to them, so re-add the
# `--cfg=web_sys_unstable_apis` that the web-sys WebTransport bindings need. Both cargo
# invocations below set RUSTFLAGS themselves, so the config entry never applies on its own;
# unlike wasm_build_js.sh, this has to happen unconditionally.
export RUSTFLAGS="--cfg=web_sys_unstable_apis${RUSTFLAGS:+ $RUSTFLAGS}"

# Output filenames: veilid_flutter.js + veilid_flutter_bg.wasm.
if [ "$RELEASE" -eq 1 ]; then
    OUTPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/size/pkg
    INPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/size

    ./wasm_remap_paths.sh cargo build --target wasm32-unknown-unknown --profile size --no-default-features --features=default-wasm -p veilid-flutter $@
    mkdir -p $OUTPUTDIR
    wasm-bindgen --out-dir $OUTPUTDIR --target web $INPUTDIR/veilid_flutter.wasm
    wasm-opt \
        --converge \
        --low-memory-unused \
        --flatten \
        --rereloop \
        -Oz \
        $OUTPUTDIR/veilid_flutter_bg.wasm \
        -o $OUTPUTDIR/veilid_flutter_bg.wasm.optimized
    mv $OUTPUTDIR/veilid_flutter_bg.wasm.optimized $OUTPUTDIR/veilid_flutter_bg.wasm
else
    OUTPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/debug/pkg
    INPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/debug

    RUSTFLAGS="-O -g $RUSTFLAGS" cargo build --target wasm32-unknown-unknown --no-default-features --features=default-wasm,debug-api -p veilid-flutter $@
    mkdir -p $OUTPUTDIR
    wasm-bindgen --out-dir $OUTPUTDIR --target web --keep-debug --debug $INPUTDIR/veilid_flutter.wasm
fi

popd &> /dev/null

# Print for use with scripts
echo SUCCESS:OUTPUTDIR=$(get_abs_filename $OUTPUTDIR)
