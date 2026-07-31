#!/bin/bash
pushd example 2>/dev/null

# Cargo features come from the `hooks: user_defines:` block in example/pubspec.yaml;
# hooks run under a fixed environment allowlist, so nothing can be passed from here.

# Default to the #common=debug log tag group unless the caller overrides LOG_DIRECTIVES
case "$*" in
    *LOG_DIRECTIVES*) ;;
    *) set -- --dart-define=LOG_DIRECTIVES='#common=debug' "$@" ;;
esac

flutter test -r github integration_test/app_test.dart "$@"
status=$?
popd 2>/dev/null
exit $status
