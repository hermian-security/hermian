"""How packaging/install.sh picks local vs remote mode.

Everything runs with --dry-run (no root, nothing changes) and with curl and
wget replaced by stubs that fail, so the remote path stops at its first
download without touching the network.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

INSTALL = Path(__file__).resolve().parent.parent.parent / "packaging" / "install.sh"
SH = shutil.which("sh")


@unittest.skipIf(SH is None, "needs a POSIX sh")
class InstallModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        for tool in ("curl", "wget"):
            stub = stubs / tool
            stub.write_text("#!/bin/sh\necho stub-download-refused >&2\nexit 1\n")
            stub.chmod(0o755)
        self.env = dict(os.environ, PATH=str(stubs) + os.pathsep + os.environ["PATH"])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tarball(self, name="tarball"):
        d = self.tmp / name
        d.mkdir()
        (d / "hermian").write_text("not a real binary\n")
        shutil.copy(INSTALL, d / "install.sh")
        return d

    def run_sh(self, args, cwd, stdin=None):
        return subprocess.run(
            [SH] + args,
            cwd=str(cwd),
            env=self.env,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=60,
        )

    def test_piped_install_ignores_a_hermian_file_in_the_cwd(self):
        # `curl ... | sudo sh` from a directory that happens to hold a file
        # named hermian used to install that file as root, unverified.
        cwd = self.tmp / "somewhere"
        cwd.mkdir()
        (cwd / "hermian").write_text("attacker controlled\n")
        out = self.run_sh(["-s", "--", "--dry-run"], cwd, stdin=INSTALL.read_text()).stdout
        self.assertIn("fetching SHA256SUMS", out)
        self.assertNotIn("installing the tarball", out)

    def test_script_inside_a_tarball_installs_its_own_files(self):
        d = self.tarball()
        out = self.run_sh(["install.sh", "--dry-run"], d).stdout
        self.assertIn("installing the tarball at", out)
        self.assertIn("(dry-run) install -m 0755 ./hermian /usr/local/bin/hermian", out)

    def test_tarball_is_found_from_another_directory(self):
        self.tarball("unpacked")
        # A POSIX path on every OS (Windows paths use backslashes).
        out = self.run_sh(["unpacked/install.sh", "--dry-run"], self.tmp).stdout
        self.assertIn("installing the tarball at", out)
        self.assertNotIn("fetching", out)

    def test_version_is_refused_for_a_local_tarball(self):
        d = self.tarball()
        res = self.run_sh(["install.sh", "--dry-run", "--version", "v0.0.1"], d)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("extracted tarball", res.stdout)


if __name__ == "__main__":
    unittest.main()
