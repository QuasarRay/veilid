#!/bin/sh
# Run inside the Dagger container. Only mirror-owned refs are modified.
set -eu

: "${UPSTREAM_URL:?UPSTREAM_URL is required}"
: "${DESTINATION_URL:?DESTINATION_URL is required}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"

# A fresh bare clone preserves Git commits and annotated tag objects without
# checking out (or executing) any code supplied by upstream.
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
git clone --mirror -- "$UPSTREAM_URL" "$workdir/upstream.git"
cd "$workdir/upstream.git"

# GitHub rejects oversized Git blobs, even in old commits. Filter a
# temporary clone only; the original GitLab repository is never modified.
git filter-repo --strip-blobs-bigger-than "${MIRROR_MAX_BLOB_SIZE:-95M}" --force

git remote add destination "$DESTINATION_URL"

# Scoped, forced refspecs mirror upstream non-fast-forward updates and remove
# upstream-deleted refs. They never touch the destination's 'main' branch or
# unprefixed tags. Keep the token out of the remote URL and command logs.
git -c 'credential.helper=!f() { if [ "$1" = get ]; then printf "username=x-access-token\npassword=%s\n" "$GITHUB_TOKEN"; fi; }; f' \
  push --prune destination \
  '+refs/heads/*:refs/heads/mirror/*' \
  '+refs/tags/*:refs/tags/upstream/*'
