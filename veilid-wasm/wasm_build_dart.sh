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

if [ "$RELEASE" -eq 1 ]; then  
    OUTPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/release/pkg
    INPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/release

    ./wasm_remap_paths.sh cargo build --target wasm32-unknown-unknown --release --no-default-features --features=default-dart $@
    mkdir -p $OUTPUTDIR
    wasm-bindgen --out-dir $OUTPUTDIR --target web $INPUTDIR/veilid_wasm.wasm
    wasm-opt -O $OUTPUTDIR/veilid_wasm_bg.wasm -o $OUTPUTDIR/veilid_wasm_bg.wasm.optimized
    mv $OUTPUTDIR/veilid_wasm_bg.wasm.optimized $OUTPUTDIR/veilid_wasm_bg.wasm
else
    OUTPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/debug/pkg
    INPUTDIR=$SCRIPTDIR/../target/wasm32-unknown-unknown/debug

    RUSTFLAGS="-O -g $RUSTFLAGS" cargo build --target wasm32-unknown-unknown --no-default-features --features=default-dart $@
    mkdir -p $OUTPUTDIR
    wasm-bindgen --out-dir $OUTPUTDIR --target web --keep-debug --debug $INPUTDIR/veilid_wasm.wasm
fi

popd &> /dev/null

# Print for use with scripts
echo SUCCESS:OUTPUTDIR=$(get_abs_filename $OUTPUTDIR)
