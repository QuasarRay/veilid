#!/usr/bin/env bash
# Format every Dart source scripts/check_format.sh checks, then `cargo fmt` the Rust side.
# Run it, then commit the result.
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/_dart_sources.sh

files=$(dart_source_files)
if [ -z "$files" ]; then
    echo "fmt: no Dart sources found; the roots in scripts/_dart_sources.sh are wrong" >&2
    exit 1
fi

echo "$files" | xargs dart format --language-version="$DART_FORMAT_LANGUAGE_VERSION" --
cargo fmt --all
