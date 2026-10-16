"""The README's early testers wall takes pull requests from outside, so it
only ever accepts one exact line per tester: a GitHub avatar linking to that
GitHub profile, nothing else."""

import re
import unittest
from pathlib import Path

README = Path(__file__).resolve().parent.parent.parent / "README.md"

# GitHub usernames: letters, digits, single hyphens, at most 39 characters.
USER = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}"
LINE = re.compile(
    r'<a href="https://github\.com/(?P<u>%s)" title="(?P=u)">'
    r'<img src="https://github\.com/(?P=u)\.png\?size=96" width="48" height="48" alt="(?P=u)"></a>' % USER
)


def wall(text):
    start = text.index("<!-- testers:start")
    start = text.index("-->", start) + 3
    end = text.index("<!-- testers:end -->")
    return [l.strip() for l in text[start:end].splitlines() if l.strip()]


class TestersWallTests(unittest.TestCase):
    def test_every_line_is_one_avatar(self):
        lines = wall(README.read_text(encoding="utf-8"))
        users = []
        for l in lines:
            m = LINE.fullmatch(l)
            self.assertIsNotNone(m, "not an avatar line: %r" % l)
            users.append(m.group("u").lower())
        self.assertEqual(len(users), len(set(users)), "someone is listed twice")

    def test_the_pattern(self):
        ok = ('<a href="https://github.com/mhdgning131" title="mhdgning131"><img src="https://github.com/'
              'mhdgning131.png?size=96" width="48" height="48" alt="mhdgning131"></a>')
        self.assertTrue(LINE.fullmatch(ok))
        for bad in [
            ok.replace('title="mhdgning131"', 'title="someone-else"'),
            ok.replace("https://github.com/mhdgning131.png", "https://evil.example/x.png"),
            ok.replace("></a>", ' onerror="x()"></a>'),
            ok + '<img src="https://evil.example/pixel.gif">',
            ok.replace("mhdgning131", "-bad"),
        ]:
            self.assertIsNone(LINE.fullmatch(bad), bad)


if __name__ == "__main__":
    unittest.main()
