"""Dagger pipeline to mirror Veilid Git refs into a protected namespace."""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import anyio
import dagger
from dagger import dag


async def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN must have contents:write access")

    script = Path(__file__).with_name("mirror.sh").read_text(encoding="utf-8")
    async with dagger.connection(dagger.Config(log_output=sys.stderr)):
        mirror = (
            dag.container()
            .from_("alpine:3.21")
            .with_exec(["apk", "add", "--no-cache", "git", "git-filter-repo", "ca-certificates"])
            .with_env_variable("UPSTREAM_URL", "https://gitlab.com/veilid/veilid.git")
            .with_env_variable("DESTINATION_URL", "https://github.com/QuasarRay/veilid.git")
            .with_env_variable("GIT_TERMINAL_PROMPT", "0")
            # Fetch source again on every run, including when Dagger has cache hits.
            .with_env_variable("MIRROR_RUN_NONCE", datetime.now(timezone.utc).isoformat())
            .with_secret_variable("GITHUB_TOKEN", dag.set_secret("github-token", token))
            .with_new_file("/mirror.sh", contents=script, permissions=0o700)
            .with_exec(["sh", "/mirror.sh"])
        )
        print(await mirror.stdout())


if __name__ == "__main__":
    anyio.run(main)
