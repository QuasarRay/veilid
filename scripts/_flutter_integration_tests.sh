#!/usr/bin/env bash
# Headless mock veilid-flutter integration tests for this host's desktop.
# Called by check_all.sh and by CI; nothing here is macOS/Linux/Windows specific.
#
# Requires the Flutter SDK on PATH at FLUTTER_MIN_VERSION or newer. With
# --install-flutter it installs the pinned FLUTTER_VERSION when the host has
# none or an older one; without it a stale SDK is an error, so a dev's own
# checkout is never replaced behind their back.

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
VEILIDDIR="$( cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd )"

INSTALL_FLUTTER=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --install-flutter) INSTALL_FLUTTER=1 ;;
        *)                 ARGS+=("$arg") ;;
    esac
done

# shellcheck source=../.dagger/versions.env
. "$VEILIDDIR/.dagger/versions.env" || exit 1
# shellcheck source=../dev-setup/_dep.sh
. "$VEILIDDIR/dev-setup/_dep.sh" || exit 1
# shellcheck source=../dev-setup/_flutter_install.sh
. "$VEILIDDIR/dev-setup/_flutter_install.sh" || exit 1

have="$(ver_of "$(flutter_ver)")"
if [ -z "$have" ] || ! ver_ge "$have" "$FLUTTER_MIN_VERSION"; then
    if [ "$INSTALL_FLUTTER" = 1 ]; then
        i_flutter || exit 1
        have="$(ver_of "$(flutter_ver)")"
    fi
    if [ -z "$have" ] || ! ver_ge "$have" "$FLUTTER_MIN_VERSION"; then
        echo "Flutter ${have:-(not installed)} is below the required $FLUTTER_MIN_VERSION." >&2
        echo "  Install it with: ./dev-setup/setup_$(uname -s | tr '[:upper:]' '[:lower:]').sh --install --flutter" >&2
        exit 1
    fi
fi
echo "Using Flutter $have."

exec "$VEILIDDIR/veilid-flutter/run_integration_tests.sh" --headless \
    ${ARGS[@]+"${ARGS[@]}"}
