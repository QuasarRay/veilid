"""Regression test for GitHub's 100 MiB file-size cap."""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/mirror.sh"


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, text=True, check=True, capture_output=True).stdout.strip()


class OversizeTests(unittest.TestCase):
    def test_drops_oversized_blob_without_modifying_upstream(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            upstream = root / "upstream.git"
            destination = root / "destination.git"
            worktree = root / "worktree"
            git("init", "--bare", str(upstream))
            git("init", "--bare", str(destination))
            git("init", str(worktree))
            git("config", "user.email", "test@example.org", cwd=worktree)
            git("config", "user.name", "Mirror Test", cwd=worktree)
            git("checkout", "-b", "main", cwd=worktree)
            (worktree / "source.rs").write_text("fn main() {}\n")
            (worktree / "huge.data").write_bytes(b"x" * (2 * 1024 * 1024))
            git("add", ".", cwd=worktree)
            git("commit", "-m", "include oversized file", cwd=worktree)
            git("push", str(upstream), "HEAD:refs/heads/main", cwd=worktree)

            env = {
                **os.environ,
                "UPSTREAM_URL": str(upstream),
                "DESTINATION_URL": str(destination),
                "GITHUB_TOKEN": "test",
                "MIRROR_MAX_BLOB_SIZE": "1M",
            }
            subprocess.run(["sh", str(SCRIPT)], check=True, env=env, capture_output=True, text=True)
            mirrored = git("--git-dir", str(destination), "ls-tree", "-r", "--name-only", "refs/heads/mirror/main")
            original = git("--git-dir", str(upstream), "ls-tree", "-r", "--name-only", "refs/heads/main")
            self.assertIn("source.rs", mirrored)
            self.assertNotIn("huge.data", mirrored)
            self.assertIn("huge.data", original)


if __name__ == "__main__":
    unittest.main()
