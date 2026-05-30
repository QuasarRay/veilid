#!/usr/bin/env bash
# Build the dart-flavored veilid-flutter wasm blob and run the example
# integration tests against Chrome headless via `flutter drive -d chrome`.
#
# Mirrors the option surface of veilid-wasm/wasm_test_js.sh.

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
set -eo pipefail

print_help() {
    cat <<EOF
Usage: $0 [options] [-- flutter-drive args...]

Options:
  --release-build      Build veilid-flutter wasm in release mode (default: debug)
  --verbose-tracing    Enable veilid-core/verbose-tracing cargo feature (rebuilds wasm)
  --debug              Enable LOG_LEVEL=debug for veilid logs.
                       Also forwards \$LOG_DIRECTIVES if set in the shell env.
  --help, -h           Show this help

Env:
  SKIP_WASM_BUILD=1    Skip the wasm rebuild step (dart-only iteration)
  LOG_DIRECTIVES=...   Forwarded as --dart-define=LOG_DIRECTIVES when set

This example has no test-group gating; all tests always run.
EOF
}

RELEASE_BUILD=0
VERBOSE_TRACING=0
DEBUG=0
PASSTHROUGH=()
while [ $# -gt 0 ]; do
    case "$1" in
        --release-build)   RELEASE_BUILD=1 ;;
        --verbose-tracing) VERBOSE_TRACING=1 ;;
        --debug)           DEBUG=1 ;;
        --help|-h)         print_help; exit 0 ;;
        --)                shift; PASSTHROUGH+=("$@"); break ;;
        *)                 PASSTHROUGH+=("$1") ;;
    esac
    shift
done

WASM_BUILD_ARGS=()
if [ "$RELEASE_BUILD" -eq 1 ]; then
    WASM_BUILD_ARGS+=("release")
fi
# Deadlock detection (debug-locks) is opt-in via VEILID_DEBUG_LOCKS=1; off by
# default because its per-lock-acquire overhead inflates latency on these tests.
if [ "${VEILID_DEBUG_LOCKS:-}" = "1" ]; then
    WASM_BUILD_ARGS+=("--features=veilid-flutter/debug-locks")
fi
if [ "$VERBOSE_TRACING" -eq 1 ]; then
    WASM_BUILD_ARGS+=("--features=veilid-core/verbose-tracing")
fi

DEFINES=()
if [ "$DEBUG" -eq 1 ]; then
    DEFINES+=(--dart-define=LOG_LEVEL=debug)
fi
if [ -n "${LOG_DIRECTIVES:-}" ]; then
    DEFINES+=(--dart-define=LOG_DIRECTIVES="$LOG_DIRECTIVES")
fi

if [ "${SKIP_WASM_BUILD:-0}" != "1" ]; then
    "$SCRIPTDIR/wasm_build.sh" "${WASM_BUILD_ARGS[@]}"
fi

VEILIDDIR="$(cd "$SCRIPTDIR/.." && pwd)"

# shellcheck disable=SC1091
source "$VEILIDDIR/scripts/_chromedriver_helper.sh"
trap stop_chromedriver EXIT
start_chromedriver
start_chromedriver_log_poller

pushd "$SCRIPTDIR/example" >/dev/null
# -d chrome (NOT -d web-server): integration_test's FlutterDriver protocol
# requires the dart VM service which `-d chrome` exposes; `-d web-server` mode
# silently no-ops test bodies. chromedriver is still needed for the webdriver
# bridge. A Chrome window pops up; `--web-run-headless` would suppress it but
# triggers a Chrome 132+ port-mismatch bug — see flutter#160434 — so leave it
# visible for now. Browser console is forwarded by start_chromedriver_log_poller.
run_flutter_drive_for_web_tests \
    --driver=test_driver/integration_test.dart \
    --target=integration_test/app_test.dart \
    -d chrome \
    --verbose \
    "${DEFINES[@]}" \
    "${PASSTHROUGH[@]}"
popd >/dev/null
