"""Integration test for branch/tag synchronization against temporary bare repos."""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/mirror.sh"


def git(*args, cwd=None):
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


class MirrorTests(unittest.TestCase):
    def test_preserves_control_branch_and_tracks_upstream_refs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            origin = root / "origin.git"
            destination = root / "destination.git"
            source = root / "source"
            git("init", "--bare", str(origin))
            git("init", "--bare", str(destination))
            git("init", str(source))
            git("config", "user.email", "test@example.org", cwd=source)
            git("config", "user.name", "Mirror Test", cwd=source)
            git("checkout", "-b", "main", cwd=source)
            (source / "data").write_text("v1\n")
            git("add", ".", cwd=source)
            git("commit", "-m", "first", cwd=source)
            first = git("rev-parse", "HEAD", cwd=source)
            git("tag", "-a", "v1", "-m", "release v1", cwd=source)
            git("branch", "feature", cwd=source)
            git("remote", "add", "origin", str(origin), cwd=source)
            git("push", "origin", "main", "feature", "--tags", cwd=source)
            # Local 'main' stands in for the control branch and must survive.
            git("push", str(destination), "HEAD:refs/heads/main", cwd=source)
            before = git("--git-dir", str(destination), "rev-parse", "refs/heads/main")
            env = {
                **os.environ,
                "UPSTREAM_URL": str(origin),
                "DESTINATION_URL": str(destination),
                "GITHUB_TOKEN": "test",
            }
            subprocess.run(["sh", str(SCRIPT)], check=True, env=env, capture_output=True)
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/heads/mirror/main"),
                first,
            )
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/heads/mirror/feature"),
                first,
            )
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/tags/upstream/v1"),
                git("--git-dir", str(origin), "rev-parse", "refs/tags/v1"),
            )
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/heads/main"), before
            )
            (source / "data").write_text("v2\n")
            git("add", ".", cwd=source)
            git("commit", "-m", "second", cwd=source)
            second = git("rev-parse", "HEAD", cwd=source)
            git("push", "origin", "main", cwd=source)
            git("push", "origin", "--delete", "feature", cwd=source)
            git("tag", "-d", "v1", cwd=source)
            git("push", "origin", ":refs/tags/v1", cwd=source)
            subprocess.run(["sh", str(SCRIPT)], check=True, env=env, capture_output=True)
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/heads/mirror/main"),
                second,
            )
            self.assertEqual(
                git("--git-dir", str(destination), "rev-parse", "refs/heads/main"), before
            )
            refs = git("--git-dir", str(destination), "show-ref")
            self.assertNotIn("refs/heads/mirror/feature", refs)
            self.assertNotIn("refs/tags/upstream/v1", refs)


if __name__ == "__main__":
    unittest.main()
