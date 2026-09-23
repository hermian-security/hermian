"""Checks on the Debian maintainer scripts. Nothing is run as root: the PAM
cleanup filter is exercised on a scratch copy of a pam.d file."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DEBIAN = Path(__file__).resolve().parent.parent.parent / "packaging" / "debian"
SED = shutil.which("sed")


class DebianScriptTests(unittest.TestCase):
    def test_prerm_lifts_isolation_on_remove_only(self):
        text = (DEBIAN / "prerm").read_text()
        remove_block = text.split("remove|deconfigure)", 1)[1].split(";;", 1)[0]
        self.assertIn("nft delete table inet hermian", remove_block)
        self.assertNotIn("upgrade)", text)

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
