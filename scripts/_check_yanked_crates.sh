#!/bin/bash
# Fails when a crates.io package pinned by any Cargo.lock in the tree has been yanked. cargo
# itself only reports a yanked pin during `cargo publish`, after the release is tagged.
set -eou pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd "$SCRIPTDIR/.." >/dev/null

INDEX_URL="${CRATES_INDEX_URL:-https://index.crates.io}"
USER_AGENT="veilid-check-yanked-crates (https://gitlab.com/veilid/veilid)"
PARALLEL=16

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# Every lockfile in the tree, build output excluded
find . \( -name target -o -name node_modules -o -name .dart_tool -o -name build -o -name .git \) -prune \
    -o -name Cargo.lock -print | sort > "$WORKDIR/lockfiles"
if [ ! -s "$WORKDIR/lockfiles" ]; then
    echo "no Cargo.lock found" >&2
    exit 2
fi

# "name version lockfile" for every crates.io pin; name and version precede source in a block
while read -r lock; do
    awk -v lock="$lock" '
        /^name = / { name = $3; gsub(/"/, "", name) }
        /^version = / { version = $3; gsub(/"/, "", version) }
        /^source = "registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index"$/ { print name, version, lock }
    ' "$lock"
done < "$WORKDIR/lockfiles" > "$WORKDIR/pins"

# One index fetch per crate, checking every version pinned for it
cut -d' ' -f1,2 "$WORKDIR/pins" | sort -u \
    | awk '{ versions[$1] = versions[$1] " " $2 } END { for (name in versions) print name versions[name] }' \
    | sort > "$WORKDIR/crates"

# Sparse index layout: 1/<n>, 2/<n>, 3/<c>/<n>, else <ab>/<cd>/<n>, all lowercase
index_path() {
    local name
    name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case ${#name} in
        1) echo "1/$name" ;;
        2) echo "2/$name" ;;
        3) echo "3/${name:0:1}/$name" ;;
        *) echo "${name:0:2}/${name:2:2}/$name" ;;
    esac
}

# Prints one line per problem: YANKED, MISSING (not in the index) or FETCH_FAILED
check_crate() {
    local name=$1 body version line
    shift
    if ! body=$(curl -fsL --retry 3 --retry-connrefused -A "$USER_AGENT" "$INDEX_URL/$(index_path "$name")"); then
        echo "FETCH_FAILED $name"
        return 0
    fi
    for version in "$@"; do
        line=$(printf '%s\n' "$body" | grep -F "\"vers\":\"$version\"" || true)
        if [ -z "$line" ]; then
            echo "MISSING $name $version"
        elif printf '%s\n' "$line" | grep -q '"yanked":true'; then
            echo "YANKED $name $version"
        fi
    done
}
export -f check_crate index_path
export INDEX_URL USER_AGENT

echo "Checking $(wc -l < "$WORKDIR/pins" | tr -d ' ') crate pins in $(wc -l < "$WORKDIR/lockfiles" | tr -d ' ') lockfiles against $INDEX_URL..."
xargs -P "$PARALLEL" -L 1 bash -c 'check_crate "$@"' _ < "$WORKDIR/crates" | sort > "$WORKDIR/problems"

status=0
if grep -q '^FETCH_FAILED' "$WORKDIR/problems"; then
    echo "could not read the index for $(grep -c '^FETCH_FAILED' "$WORKDIR/problems") crates, including: $(grep '^FETCH_FAILED' "$WORKDIR/problems" | head -5 | cut -d' ' -f2 | tr '\n' ' ')" >&2
    status=2
fi
if grep -q -E '^(YANKED|MISSING)' "$WORKDIR/problems"; then
    echo "yanked or unknown crate pins:" >&2
    while read -r kind name version; do
        locks=$(awk -v n="$name" -v v="$version" '$1 == n && $2 == v { print $3 }' "$WORKDIR/pins" | tr '\n' ' ')
        echo "  $name $version: $kind in $locks" >&2
    done < <(grep -E '^(YANKED|MISSING)' "$WORKDIR/problems")
    echo "Update each with \`cargo update -p <crate>\` in that lockfile's directory." >&2
    status=1
fi
if [ "$status" -eq 0 ]; then
    echo "No yanked crate pins."
fi

popd >/dev/null
exit "$status"
