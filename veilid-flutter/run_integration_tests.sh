#!/bin/bash
pushd example 2>/dev/null

# Deadlock detection (debug-locks) is opt-in: VEILID_DEBUG_LOCKS=1 enables it.
# Off by default because its per-lock-acquire overhead inflates latency on these
# throughput-heavy tests. macos_build.sh / ios_build.sh forward
# VEILID_CARGO_EXTRA_OPTIONS through to cargo.
if [ "${VEILID_DEBUG_LOCKS:-}" = "1" ]; then
    export VEILID_CARGO_EXTRA_OPTIONS="--features=veilid-flutter/debug-locks ${VEILID_CARGO_EXTRA_OPTIONS:-}"
fi

flutter test -r github integration_test/app_test.dart $@
popd 2>/dev/null
