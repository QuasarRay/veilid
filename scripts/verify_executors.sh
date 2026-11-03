#!/bin/bash
set -uo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPTDIR/.."

FAIL=0

echo ">>> Check 1: async-std build (no WebTransport) must contain no tokio crate ..."
CHECK1_ERR_FILE="$(mktemp)"
CHECK1_OUT="$(cargo tree -p veilid-core --no-default-features --features default-async-std -i tokio 2>"$CHECK1_ERR_FILE")"
CHECK1_STATUS=$?
if [ "$CHECK1_STATUS" -ne 0 ]; then
    echo "!!! Check 1 FAILED: 'cargo tree' did not run successfully:"
    sed 's/^/      /' "$CHECK1_ERR_FILE"
    FAIL=1
elif [ -n "$CHECK1_OUT" ]; then
    echo "!!! Check 1 FAILED: tokio is present in the async-std (no WebTransport) build:"
    echo "$CHECK1_OUT" | sed 's/^/      /'
    FAIL=1
else
    echo ">>> Check 1 PASSED: no tokio in the async-std (no WebTransport) dependency tree."
fi
rm -f "$CHECK1_ERR_FILE"

echo ">>> Check 2: async-std + WebTransport build must resolve tokio with only the allowed feature set ..."
# web-transport-quinn 0.13.5 requires quinn's runtime-tokio, so tokio's rt, time and net (with
# the libc, mio and socket2 that net brings) are compiled into the async-std build, but nothing
# starts a tokio runtime.
ALLOWED_FEATURES="bytes default io-util libc mio net rt socket2 sync time"
SORTED_ALLOWED="$(printf '%s\n' $ALLOWED_FEATURES | sort -u)"

CHECK2_ERR_FILE="$(mktemp)"
CHECK2_OUT="$(cargo tree -p veilid-core --no-default-features \
        --features default-async-std,enable-protocol-webtransport \
        -e features -i tokio 2>"$CHECK2_ERR_FILE")"
CHECK2_STATUS=$?

if [ "$CHECK2_STATUS" -eq 0 ]; then
    if [ -z "$CHECK2_OUT" ]; then
        echo ">>> Check 2 PASSED: no tokio reachable from veilid-core in the async-std + WebTransport build (stronger than the allowed set)."
    else
        ROOT_COUNT="$(printf '%s\n' "$CHECK2_OUT" | grep -c '^tokio v' || true)"
        if [ "$ROOT_COUNT" -gt 1 ]; then
            echo "!!! Check 2 FAILED: multiple tokio packages resolved for spec 'tokio'; manual inspection required:"
            printf '%s\n' "$CHECK2_OUT" | grep '^tokio v' | sed 's/^/      /'
            FAIL=1
        else
            FEATURES="$(printf '%s\n' "$CHECK2_OUT" | sed -n 's/.*tokio feature "\([^"]*\)".*/\1/p' | sort -u)"
            EXTRA="$(comm -23 <(printf '%s\n' "$FEATURES") <(printf '%s\n' "$SORTED_ALLOWED"))"
            MISSING="$(comm -13 <(printf '%s\n' "$FEATURES") <(printf '%s\n' "$SORTED_ALLOWED"))"
            if [ -n "$EXTRA" ]; then
                echo "!!! Check 2 FAILED: tokio resolved with disallowed feature(s):"
                echo "$EXTRA" | sed 's/^/      /'
                echo "    Resolved features: $(printf '%s ' $FEATURES)"
                echo "    Allowed features:  $(printf '%s ' $SORTED_ALLOWED)"
                FAIL=1
            elif [ -n "$MISSING" ]; then
                echo "!!! Check 2 FAILED: tokio resolved without expected feature(s):"
                echo "$MISSING" | sed 's/^/      /'
                echo "    Resolved features: $(printf '%s ' $FEATURES)"
                echo "    Allowed features:  $(printf '%s ' $SORTED_ALLOWED)"
                FAIL=1
            else
                echo ">>> Check 2 PASSED: tokio resolved with exactly {$(printf '%s ' $SORTED_ALLOWED)}."
            fi
        fi
    fi
elif [ "$CHECK2_STATUS" -eq 101 ] && grep -q 'did not match any packages' "$CHECK2_ERR_FILE"; then
    echo ">>> Check 2 PASSED: tokio does not exist anywhere in the workspace lock (stronger than the allowed set)."
else
    echo "!!! Check 2 FAILED: 'cargo tree' did not run successfully:"
    sed 's/^/      /' "$CHECK2_ERR_FILE"
    FAIL=1
fi
rm -f "$CHECK2_ERR_FILE"

# web-transport-quinn spawns its session tasks on quinn::default_runtime(), which finds async-std
# only through quinn's runtime-async-std. Without it the async-std build still compiles, then
# panics with "no async runtime found" on every session, and no CI job runs WebTransport on
# async-std to catch that.
echo ">>> Check 3: async-std + WebTransport build must resolve quinn with runtime-async-std ..."
CHECK3_ERR_FILE="$(mktemp)"
CHECK3_OUT="$(cargo tree -p veilid-core --no-default-features \
        --features default-async-std,enable-protocol-webtransport \
        -e features -i quinn 2>"$CHECK3_ERR_FILE")"
CHECK3_STATUS=$?
if [ "$CHECK3_STATUS" -ne 0 ]; then
    echo "!!! Check 3 FAILED: 'cargo tree' did not run successfully:"
    sed 's/^/      /' "$CHECK3_ERR_FILE"
    FAIL=1
elif [ -z "$CHECK3_OUT" ]; then
    echo "!!! Check 3 FAILED: quinn is not reachable from veilid-core in the async-std + WebTransport build."
    FAIL=1
elif ! printf '%s\n' "$CHECK3_OUT" | grep -q 'quinn feature "runtime-async-std"'; then
    echo "!!! Check 3 FAILED: quinn resolved without runtime-async-std:"
    echo "    Resolved features: $(printf '%s\n' "$CHECK3_OUT" | sed -n 's/.*quinn feature "\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ')"
    FAIL=1
else
    echo ">>> Check 3 PASSED: quinn resolved with runtime-async-std."
fi
rm -f "$CHECK3_ERR_FILE"

if [ "$FAIL" -ne 0 ]; then
    echo "!!! Executor check FAILED."
    exit 1
fi
echo ">>> Executor check PASSED."
exit 0
