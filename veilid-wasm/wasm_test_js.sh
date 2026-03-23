#!/bin/bash
set -eo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR" &> /dev/null

# Defaults
WASM_PACK_FLAGS="--dev"
CARGO_FEATURES=""
TESTS=""
DEBUG_MODE=""

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    
    release)
      WASM_PACK_FLAGS="--release"
      ;;
    --release-build)
      WASM_PACK_FLAGS="--release"
      ;;
    --tests=*)
      TESTS="${arg#--tests=}"
      ;;
    --verbose-tracing)
      CARGO_FEATURES="--features veilid-core/verbose-tracing"
      ;;
    --debug)
      DEBUG_MODE=1
      ;;
    --help|-h)
      echo "Usage: $0 [options] [-- wdio args...]"
      echo ""
      echo "Options:"
      echo "  --release-build     Build in release mode (default: dev)"
      echo "  --tests=LIST        Comma-separated list of test groups to run."
      echo "                      If omitted, all tests are run."
      echo "                      Available groups:"
      echo "                        client         - veilidClient tests"
      echo "                        crypto         - veilidCrypto tests"
      echo "                        table          - VeilidTable tests"
      echo "                        routing        - VeilidRoutingContext tests"
      echo "                        dht            - DHT kitchen sink tests"
      echo "                        transactions   - DHT transaction tests"
      echo "  --verbose-tracing   Enable verbose-tracing cargo feature"
      echo "  --debug             Set DEBUG=1 environment variable"
      echo "  -- [args]           Pass remaining arguments to wdio"
      echo ""
      echo "Examples:"
      echo "  $0                                    # Run all tests"
      echo "  $0 --tests=transactions --debug       # Run DHT transaction tests with debugging output"
      echo "  $0 --tests=client,crypto              # Run client and crypto tests"
      echo "  $0 --release-build --tests=routing    # Release build, routing tests only"
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

# Build wasm into an npm package, output into ./pkg
wasm-pack build $WASM_PACK_FLAGS --target bundler $CARGO_FEATURES $CARGO_OPTIONS

# Install test deps and run test suite
cd tests
npm install
original_tmpdir=$TMPDIR
mkdir -p ~/tmp
export TMPDIR=~/tmp

# Build wdio arguments based on --tests selection
WDIO_ARGS=()

if [[ -n "$TESTS" ]]; then
  SPEC_ARGS=()
  GREP_PATTERNS=()

  IFS=',' read -ra TEST_LIST <<< "$TESTS"
  for test in "${TEST_LIST[@]}"; do
    case "$test" in
      client)
        SPEC_ARGS+=("./src/veilidClient.test.ts")
        ;;
      crypto)
        SPEC_ARGS+=("./src/veilidCrypto.test.ts")
        ;;
      table)
        SPEC_ARGS+=("./src/VeilidTable.test.ts")
        ;;
      routing)
        SPEC_ARGS+=("./src/VeilidRoutingContext.test.ts")
        ;;
      dht)
        SPEC_ARGS+=("./src/VeilidRoutingContext.test.ts")
        GREP_PATTERNS+=("DHT kitchen sink")
        ;;
      transactions)
        SPEC_ARGS+=("./src/VeilidRoutingContext.test.ts")
        GREP_PATTERNS+=("DHT transactions")
        ;;
      *)
        echo "Unknown test group: $test" >&2
        echo "Available groups: client, crypto, table, routing, dht, transactions" >&2
        exit 1
        ;;
    esac
  done

  # Deduplicate spec files
  UNIQUE_SPECS=($(printf '%s\n' "${SPEC_ARGS[@]}" | sort -u))
  for spec in "${UNIQUE_SPECS[@]}"; do
    WDIO_ARGS+=("--spec" "$spec")
  done

  # Combine grep patterns with | for OR matching
  if [[ ${#GREP_PATTERNS[@]} -gt 0 ]]; then
    GREP_COMBINED=$(IFS='|'; echo "${GREP_PATTERNS[*]}")
    WDIO_ARGS+=("--mochaOpts.grep" "$GREP_COMBINED")
  fi
fi

# Set DEBUG if requested
if [[ -n "$DEBUG_MODE" ]]; then
  export DEBUG=1
fi

WDIO_HEADLESS=true npx wdio run ./wdio.conf.ts "${WDIO_ARGS[@]}" $@

export TMPDIR=$original_tmpdir

popd &> /dev/null
