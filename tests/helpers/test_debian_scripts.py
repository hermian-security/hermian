"""Checks on the Debian maintainer scripts. Nothing is run as root: the PAM
cleanup filter is exercised on a scratch copy of a pam.d file."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DEBIAN = ROOT / "packaging" / "debian"
SED = shutil.which("sed")


def case_block(text, label):
    return text.split(label, 1)[1].split(";;", 1)[0]


def unit_paths():
    """Every systemd unit path `hermian enable` writes, from paths.rs."""
    src = (ROOT / "hermian" / "src" / "paths.rs").read_text()
    found = re.findall(r'"(/etc/systemd/system/[^"]+)"', src)
    assert found, "no unit paths found in paths.rs"
    return found


def apt_paths():
    """The APT repository entry and key, from paths.rs."""
    src = (ROOT / "hermian" / "src" / "paths.rs").read_text()
    found = [re.search(r'%s: &str = "([^"]+)"' % name, src).group(1)
             for name in ("APT_SOURCES_PATH", "APT_KEYRING_PATH")]
    return found


class DebianScriptTests(unittest.TestCase):
    def test_purge_and_the_installer_agree_on_the_apt_repo_paths(self):
        purge = case_block((DEBIAN / "postrm").read_text(), "purge)")
        installer = (ROOT / "packaging" / "install.sh").read_text()
        for path in apt_paths():
            self.assertIn(path, purge)
            self.assertIn(path, installer)
        self.assertNotIn("hermian.sources", case_block((DEBIAN / "postrm").read_text(), "remove)"),
                         "a plain remove keeps the repo, so reinstalling works")

    def test_prerm_lifts_isolation_on_remove_only(self):
        text = (DEBIAN / "prerm").read_text()
        remove_block = text.split("remove|deconfigure)", 1)[1].split(";;", 1)[0]
        self.assertIn("nft delete table inet hermian", remove_block)
        self.assertNotIn("upgrade)", text)

    def test_prerm_stops_the_watchdog_before_the_daemon(self):
        # Left running after removal, the timer ran a missing binary every
        # minute (and could restart the daemon mid-remove).
        block = case_block((DEBIAN / "prerm").read_text(), "remove|deconfigure)")
        timer = block.find("disable --now hermian-watchdog.timer")
        daemon = block.find("disable --now hermian.service")
        self.assertNotEqual(timer, -1, block)
        self.assertNotEqual(daemon, -1, block)
        self.assertLess(timer, daemon)
        self.assertIn("nft delete table inet hermian_block", block)

    def test_postrm_removes_every_unit_enable_writes(self):
        text = (DEBIAN / "postrm").read_text()
        helper = text.split("remove_units() {", 1)[1].split("\n}", 1)[0]
        for path in unit_paths():
            self.assertIn(path, helper)
        for label in ("remove)", "purge)"):
            self.assertIn("remove_units", case_block(text, label))
        self.assertIn("/etc/sysctl.d/60-hermian.conf", case_block(text, "purge)"))

    def test_postrm_cleans_pam_on_remove_and_purge(self):
        text = (DEBIAN / "postrm").read_text()
        remove_block = text.split("remove)", 1)[1].split(";;", 1)[0]
        purge_block = text.split("purge)", 1)[1].split(";;", 1)[0]
        self.assertIn("remove_pam_hook", remove_block)
        self.assertIn("remove_pam_hook", purge_block)
        self.assertIn("sshd.hermian-bak", purge_block)

    @unittest.skipIf(SED is None, "needs sed")
    def test_pam_filter_removes_every_hermian_line(self):
        text = (DEBIAN / "postrm").read_text()
        expr = re.findall(r"sed -i (-e '[^']+' -e '[^']+')", text)[0]
        args = re.findall(r"'([^']+)'", expr)
        pam = (
            "@include common-auth\n"
            "# HERMIAN: passive auth telemetry (never affects the auth decision)\n"
            "auth    optional    /usr/lib/security/pam_hermian.so\n"
            "session optional    pam_hermian.so\n"
            "session required pam_loginuid.so\n"
        )
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "sshd"
            f.write_text(pam)
            cmd = [SED, "-i"]
            for a in args:
                cmd += ["-e", a]
            subprocess.run(cmd + [str(f)], check=True)
            self.assertEqual(
                f.read_text(),
                "@include common-auth\nsession required pam_loginuid.so\n",
            )


if __name__ == "__main__":
    unittest.main()
