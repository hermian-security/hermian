"""The destructive harness scripts must refuse to run on an unmarked host.

Non-root and read-only: every script under test exits at the guard, before
it touches anything. Skipped where no POSIX sh exists or the host really is
marked disposable.
"""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
MARKER = Path("/etc/hermian-disposable-host")
SH = shutil.which("sh")


@unittest.skipIf(SH is None, "needs a POSIX sh")
@unittest.skipIf(MARKER.exists(), "this host is marked disposable")
class DisposableHostGuardTests(unittest.TestCase):
    def run_script(self, *args, **env):
        clean = {k: v for k, v in os.environ.items() if k != "HERMIAN_DISPOSABLE_HOST"}
        clean.update(env)
        return subprocess.run(
            [SH, *map(str, args)],
            env=clean,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_scripts_refuse_without_the_marker(self):
        for script, args in [
            (TESTS / "run_suite.sh", ["--skip-fp"]),
            (TESTS / "attacks" / "run_attack.sh", ["ld-preload", "ld.so.preload"]),
            (TESTS / "false_positives" / "run_false_positive.sh", ["idle", "1"]),
            (TESTS / "soak" / "start.sh", []),
        ]:
            with self.subTest(script=script.name):
                r = self.run_script(script, *args)
                if script.name == "start.sh" and r.returncode == 1:
                    # start.sh checks root first; non-root never gets further.
                    self.assertIn("run as root", r.stderr)
                    continue
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertIn("disposable", r.stderr)

    def test_guard_accepts_the_opt_in(self):
        guard = TESTS / "helpers" / "disposable_host.sh"
        cmd = '. "$1"; require_disposable_host; echo ok'
        refused = self.run_script("-c", cmd, "sh", guard)
        self.assertEqual(refused.returncode, 3)
        allowed = self.run_script("-c", cmd, "sh", guard, HERMIAN_DISPOSABLE_HOST="1")
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertEqual(allowed.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
