# Veilid GitLab mirror

This GitHub repository contains a **Dagger-powered, scheduled Git mirror** of [Veilid's canonical GitLab repository](https://gitlab.com/veilid/veilid). The destination `main` branch holds the automation and its existing license; it is deliberately not overwritten by upstream source.

## Mirrored refs

- Upstream branches `refs/heads/NAME` become GitHub branches `refs/heads/mirror/NAME` (for example, `mirror/main`).
- Upstream tags `refs/tags/NAME` become GitHub tags `refs/tags/upstream/NAME`.
- Original commit identities, Git history, and annotated tag objects are retained. Upstream force-pushes and deletions are reflected **only** within these prefixed namespaces.
- Files and commits from upstream are **not executed** during mirroring.

The workflow runs four times daily (00:17, 06:17, 12:17, 18:17 UTC) and can also be run using **Actions → Mirror Veilid from GitLab → Run workflow**. It uses GitHub Actions' short-lived `GITHUB_TOKEN` with `contents: write`; no personal access token is required.

## Pipeline and testing

- `scripts/mirror.py`: isolated Dagger container pipeline, pinned to Dagger **v0.21.11**.
- `scripts/mirror.sh`: Git refspec mirroring logic.
- `.github/workflows/mirror.yml`: GitHub Actions schedule and Dagger invocation.
- `tests/test_mirror.py`: local bare-Git integration test.

To run tests locally: `python -m unittest discover -s tests -v`.

**Scope:** Git commits, branches and tags are mirrored. GitLab issues, merge requests, releases, CI artifacts, and Git LFS binary objects are *not* copied. For large upstream histories, the initial synchronization may exceed the configured 120-minute job timeout. GitHub Actions must be enabled in this repository.
