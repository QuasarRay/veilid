# Veilid GitLab mirror

This GitHub repository contains a **Dagger-powered, scheduled Git mirror** of [Veilid's canonical GitLab repository](https://gitlab.com/veilid/veilid). The destination `main` branch holds the automation and its existing license; it is deliberately not overwritten by upstream source.

## Mirrored refs

- Upstream branches `refs/heads/NAME` become GitHub branches `refs/heads/mirror/NAME` (for example, `mirror/main`).
- Upstream tags `refs/tags/NAME` become GitHub tags `refs/tags/upstream/NAME`.
- GitHub rejects Git blobs over 100 MiB. The pipeline removes blobs larger than **95 MiB** from a temporary copy using `git filter-repo`; the original GitLab repository is never modified. Mirrored commit and annotated-tag IDs can differ from upstream, so this is a **filtered content mirror**, not a byte-for-byte history replica. Upstream force-pushes and deletions are reflected **only** within these prefixed namespaces.
- Files and commits from upstream are **not executed** during mirroring.

The workflow requests synchronization **every five minutes** (UTC), also starts after changes to its mirroring controller files on `main`, and can be run manually using **Actions → Mirror Veilid from GitLab → Run workflow**. GitHub Actions cron jobs can start late or be skipped under load. **Until an Actions run finishes successfully, the `mirror/*` branches and `upstream/*` tags will not exist.** To browse the source after a successful run, open the repository's branch selector and choose `mirror/main` (not the default `main` control branch). It uses GitHub Actions' short-lived `GITHUB_TOKEN` with `contents: write`; no personal access token is required.

## Pipeline and testing

- `scripts/mirror.py`: isolated Dagger container pipeline, pinned to Dagger **v0.21.11**.
- `scripts/mirror.sh`: size-filtered Git refspec mirroring logic (`MIRROR_MAX_BLOB_SIZE`, default `95M`).
- `.github/workflows/mirror.yml`: GitHub Actions schedule and Dagger invocation.
- `tests/test_mirror.py`: local bare-Git integration test.
- `tests/test_oversize.py`: regression test for GitHub oversized Git blobs.

To run tests locally, install `git-filter-repo`, then run `python3 -m unittest discover -s tests -v`.

**Scope:** Git commits, branches and tags are mirrored. GitLab issues, merge requests, releases, CI artifacts, and Git LFS binary objects are *not* copied. For large upstream histories, the initial synchronization may exceed the configured 120-minute job timeout. GitHub Actions must be enabled in this repository.
