"""The apt.hermian.me landing page: packaging/apt/index.html is a template
that publish.sh fills in and ships with the files it links to."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
APT = ROOT / "packaging" / "apt"


class AptPageTests(unittest.TestCase):
    def test_every_placeholder_is_filled(self):
        page = (APT / "index.html").read_text()
        publish = (APT / "publish.sh").read_text()
        found = set(re.findall(r"@[A-Z]+@", page))
        self.assertEqual(found, {"@VERSION@", "@BETA@", "@STABLE@", "@FINGERPRINT@"})
        for p in found:
            self.assertIn("s|%s|" % p, publish, p)

    def test_linked_files_are_shipped(self):
        page = (APT / "index.html").read_text()
        publish = (APT / "publish.sh").read_text()
        local = [s for s in re.findall(r'src="([^"]+)"', page) if "://" not in s]
        self.assertTrue(local)
        for name in local:
            self.assertIn(name, publish, "%s is linked but not copied" % name)
        for src in re.findall(r'cp "\$ROOT/([^"]+)"', publish):
            self.assertTrue((ROOT / src).is_file(), src)

    def test_commands_match_what_the_installer_writes(self):
        page = (APT / "index.html").read_text()
        installer = (ROOT / "packaging" / "install.sh").read_text()
        for path in ("/usr/share/keyrings/hermian-archive-keyring.gpg",
                     "/etc/apt/sources.list.d/hermian.sources"):
            self.assertIn(path, page)
            self.assertIn(path, installer)


if __name__ == "__main__":
    unittest.main()
