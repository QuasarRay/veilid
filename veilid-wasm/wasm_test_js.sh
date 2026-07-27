#!/bin/bash
# pipefail so `cmd | tee` returns cmd's code; no `set -e` — exit codes are
# handled explicitly so the wdio test result is what this script returns.
set -o pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR" &> /dev/null

# Defaults
BUILD_MODE=""
CARGO_FEATURES=""
FEATURE_LIST=""
TESTS=""
CONTEXTS=""
DEBUG_MODE=""

# Parse arguments
for arg in "$@"; do
  case "$arg" in

    release)
      BUILD_MODE="release"
      ;;
    --release-build)
      BUILD_MODE="release"
      ;;
    --tests=*)
      TESTS="${arg#--tests=}"
      ;;
    --context=*)
      CONTEXTS="${arg#--context=}"
      ;;
    --verbose-tracing)
      FEATURE_LIST="$FEATURE_LIST,veilid-core/verbose-tracing"
      ;;
    --aimd)
      FEATURE_LIST="$FEATURE_LIST,veilid-core/aimd-dht"
      ;;
    --debug)
      DEBUG_MODE=1
      ;;
    --help|-h)
      echo "Usage: $0 [options] [-- wdio args...]"
      echo ""
      echo "Options:"
      echo "  --release-build     Build in release mode (default: dev)"
      echo "  --tests=LIST        Comma-separated list of test suites to run."
      echo "                      If omitted, all suites are run."
      echo "                      Available suites:"
      echo "                        client         - veilidClient tests"
      echo "                        crypto         - veilidCrypto tests"
      echo "                        table          - VeilidTable tests"
      echo "                        pstore         - ProtectedStore tests"
      echo "                        routing        - VeilidRoutingContext tests"
      echo "                        dht            - DHT kitchen sink tests"
      echo "                        transactions   - DHT transaction tests"
      echo "  --context=LIST      Comma-separated list of JS contexts to run the suites in,"
      echo "                      each in turn. If omitted, only 'window' is used."
      echo "                      Available contexts:"
      echo "                        window         - the page's main thread"
      echo "                        dedicated      - a dedicated worker"
      echo "                        shared         - a shared worker"
      echo "                        service        - a service worker"
      echo "                        extension      - an MV3 extension background worker."
      echo "                                         Uses its own Chrome build, downloaded"
      echo "                                         on first use."
      echo "                      Suites needing an attached node are skipped, with a notice,"
      echo "                      in the service and extension contexts: they have no usable"
      echo "                      WebSocket. Those need a secure context and will be enabled"
      echo "                      when WebTransport support lands."
      echo "  --verbose-tracing   Enable verbose-tracing cargo feature"
      echo "  --aimd              Enable the aimd-dht cargo feature"
      echo "  --debug             Set DEBUG=1 environment variable"
      echo "  -- [args]           Pass remaining arguments to wdio"
      echo ""
      echo "Examples:"
      echo "  $0                                          # All suites, window context"
      echo "  $0 --tests=transactions --debug             # DHT transaction tests, with debug output"
      echo "  $0 --tests=client,crypto                    # Client and crypto suites"
      echo "  $0 --tests=pstore --context=window,dedicated,shared,service,extension"
      echo "  $0 --context=dedicated                      # Every suite, in a dedicated worker"
      echo "  $0 --release-build --tests=routing          # Release build, routing suite only"
      popd &> /dev/null
      exit 0
      ;;
    --)
      # Stop parsing arguments if -- is encountered
      shift
      break 
      ;;
    --*)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
  shift
done

if [ -n "$FEATURE_LIST" ]; then
  CARGO_FEATURES="--features ${FEATURE_LIST#,}"
fi

# Build wasm into an npm package, output into ./pkg
./wasm_build_js.sh $BUILD_MODE $CARGO_FEATURES $CARGO_OPTIONS || { echo "wasm build failed" >&2; exit 1; }

# Install test deps and run test suite
cd tests || exit 1
npm install || { echo "npm install failed" >&2; exit 1; }
original_tmpdir=$TMPDIR
mkdir -p ~/tmp
export TMPDIR=~/tmp

ALL_SUITES="client,crypto,table,pstore,routing,dht,transactions"

# Suites are selected by name and run inside each requested context; the runner spec reads both
# out of the environment.
if [[ -z "$TESTS" ]]; then
  TESTS="$ALL_SUITES"
fi
IFS=',' read -ra TEST_LIST <<< "$TESTS"
for test in "${TEST_LIST[@]}"; do
  case ",$ALL_SUITES," in
    *",$test,"*) ;;
    *)
      echo "Unknown test suite: $test" >&2
      echo "Available suites: $ALL_SUITES" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$CONTEXTS" ]]; then
  CONTEXTS="window"
fi
IFS=',' read -ra CONTEXT_LIST <<< "$CONTEXTS"
for context in "${CONTEXT_LIST[@]}"; do
  case "$context" in
    window|dedicated|shared|service|extension) ;;
    *)
      echo "Unknown context: $context" >&2
      echo "Available contexts: window, dedicated, shared, service, extension" >&2
      exit 1
      ;;
  esac
done

# Set DEBUG if requested
if [[ -n "$DEBUG_MODE" ]]; then
  export DEBUG=1
fi

# macOS quarantines a freshly-installed/updated chromedriver, which blocks wdio from launching it
if [[ "$(uname)" == "Darwin" ]] && command -v chromedriver >/dev/null; then
  xattr -d com.apple.quarantine "$(command -v chromedriver)" 2>/dev/null || true
fi

# The service worker and the extension load pre-bundled static builds, not the dev server's
# module output, which cannot start in either.
if [[ " ${CONTEXT_LIST[*]} " == *" service "* ]]; then
  npm run build:sw || { echo "service worker bundle build failed" >&2; exit 1; }
fi
if [[ " ${CONTEXT_LIST[*]} " == *" extension "* ]]; then
  npm run build:ext || { echo "extension bundle build failed" >&2; exit 1; }
fi

export VEILID_TEST_SUITES="$TESTS"

status=0
for context in "${CONTEXT_LIST[@]}"; do
  echo ""
  echo "=== veilid-wasm tests: [$TESTS] in context '$context' ==="
  export VEILID_TEST_CONTEXT="$context"

  if [[ "$context" == "extension" ]]; then
    WDIO_CONFIG="./wdio.ext.conf.ts"
  else
    WDIO_CONFIG="./wdio.conf.ts"
  fi

  WDIO_HEADLESS=true npx wdio run "$WDIO_CONFIG" $@
  context_status=$?
  if [[ $context_status -ne 0 ]]; then
    status=$context_status
    echo "=== context '$context' FAILED ($context_status) ===" >&2
  fi
done

export TMPDIR=$original_tmpdir

popd &> /dev/null
exit $status
