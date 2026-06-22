#!/bin/bash
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
# pipefail keeps pipe exit codes; no `set -e` — failures are handled explicitly
# so this script returns the test command's exit code.
set -o pipefail

pushd "$SCRIPTDIR" >/dev/null || exit 1
status=0
if [[ "$1" == "wasm" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPTDIR/../scripts/_chromedriver_helper.sh"
    CHROMEDRIVER="$(chromedriver_binary_path)" || { echo "Failed to resolve chromedriver"; popd >/dev/null; exit 1; }
    export CHROMEDRIVER
    WASM_BINDGEN_TEST_TIMEOUT=120 cargo nextest run --target wasm32-unknown-unknown --no-default-features --features=rt-wasm-bindgen,test-util,debug-locks
    status=$?
elif [[ "$1" == "ios" ]]; then
    SYMROOT=/tmp/testout
    APPNAME=veilidtools-tests
    BUNDLENAME=com.veilid.veilidtools-tests
    ID="$2"
    if [[ "$ID" == "" ]]; then
        echo "No emulator ID specified"
        popd >/dev/null
        exit 1
    fi

    # Build for simulator
    xcrun xcodebuild -project src/tests/ios/$APPNAME/$APPNAME.xcodeproj/ -scheme $APPNAME -destination "generic/platform=iOS Simulator" SYMROOT=$SYMROOT || { status=$?; popd >/dev/null; exit $status; }

    # Run in temporary simulator
    xcrun simctl install $ID $SYMROOT/Debug-iphonesimulator/$APPNAME.app || { status=$?; popd >/dev/null; exit $status; }
    xcrun simctl spawn $ID log stream --level debug --predicate "subsystem == \"$BUNDLENAME\"" &
    xcrun simctl launch --console $ID $BUNDLENAME
    status=$?
    sleep 1 # Ensure the last log lines print
    kill -INT %1

    # Clean up build output
    rm -rf /tmp/testout

elif [[ "$1" == "android" ]]; then
    ID="$2"
    if [[ "$ID" == "" ]]; then
        echo "No emulator ID specified"
        popd >/dev/null
        exit 1
    fi
    APPNAME=veilid_tools_android_tests
    APPID=com.veilid.veilid_tools_android_tests
    ACTIVITYNAME=MainActivity
    pushd src/tests/android/$APPNAME >/dev/null || { popd >/dev/null; exit 1; }
    # Build apk
    ./gradlew assembleDebug || { status=$?; popd >/dev/null; popd >/dev/null; exit $status; }
    # Wait for boot
    adb -s $ID wait-for-device
    # Install app
    adb -s $ID install -r ./app/build/outputs/apk/debug/app-debug.apk || { status=$?; popd >/dev/null; popd >/dev/null; exit $status; }
    # Start activity
    adb -s $ID shell am start-activity -W $APPID/.$ACTIVITYNAME
    # Get the pid of the program
    APP_PID=`adb -s $ID shell pidof -s $APPID`
    # Print the logcat
    adb -s $ID shell logcat --pid=$APP_PID veilid_tools:V *:S &
    # Wait for the pid to be done
    while [ "$(adb -s $ID shell pidof -s $APPID)" != "" ]; do
        sleep 1
    done
    # Terminate logcat
    kill %1
    # Finished
    popd >/dev/null

else
    RUST_LOG=#common=debug cargo nextest run --features=debug-locks \
        && RUST_LOG=#common=debug cargo nextest run --features=tracing,debug-locks \
        && RUST_LOG=#common=debug cargo nextest run --no-default-features --features=rt-async-std,debug-locks \
        && RUST_LOG=#common=debug cargo nextest run --no-default-features --features=rt-async-std,tracing,debug-locks \
        && cargo test --doc
    status=$?
fi
popd >/dev/null
exit $status
