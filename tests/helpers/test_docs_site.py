"""The docs site (docs/site/, rendered on hermian.me/docs) stays complete:
every config setting, command, flag and alert title in the code is
documented, every page in the table of contents exists, and links between
pages resolve, anchors included."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "docs" / "site"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def nav():
    """[(slug, path)] from docs/site/_nav.txt."""
    pages = []
    for line in (SITE / "_nav.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or not line.startswith(" "):
            continue
        slug, file = line.split()[:2]
        pages.append((slug, (SITE / file).resolve()))
    return pages


def in_site(path):
    return SITE in path.parents


def slugify(text):
    """The heading id the site generates (build_site.py's slugify)."""
    text = re.sub(r"\]\([^)]*\)", "", text)
    text = re.sub(r"[`*\[\]]", "", text).lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def headings(md):
    return {slugify(m.group(1)) for m in re.finditer(r"^#{1,4} (.+)$", md, re.M)}


def strip_code(md):
    return re.sub(r"```.*?```", "", md, flags=re.S)


class DocsSite(unittest.TestCase):
    def test_every_page_exists_and_has_metadata(self):
        for slug, path in nav():
            self.assertTrue(path.is_file(), "%s: %s missing" % (slug, path))
            text = path.read_text(encoding="utf-8")
            if in_site(path):
                self.assertTrue(text.startswith("---\n"), "%s: no front matter" % path.name)
                self.assertRegex(text, r"\ntitle: .+\n", path.name)
                self.assertRegex(text, r"\ndescription: .{40,}\n", path.name)
            self.assertRegex(text, r"(?m)^# .+$", "%s: no title heading" % path.name)

    def test_links_between_pages_resolve(self):
        pages = dict(nav())
        anchors = {slug: headings(p.read_text(encoding="utf-8")) for slug, p in pages.items()}
        for slug, path in pages.items():
            if not in_site(path):
                continue  # FLEET, EVIDENCE and BETA keep their GitHub-relative links
            md = strip_code(path.read_text(encoding="utf-8"))
            for target in re.findall(r"\]\(([^)\s]+)\)", md):
                if re.match(r"[a-z]+:", target):
                    continue
                page, _, anchor = target.partition("#")
                page = page or slug
                self.assertIn(page, anchors, "%s links to unknown page %r" % (slug, target))
                if anchor:
                    self.assertIn(anchor, anchors[page], "%s: no #%s on %s" % (slug, anchor, page))

    def test_every_config_setting_is_documented(self):
        cfg = read("hermian-core/src/config.rs")
        tpl = cfg[cfg.index("DEFAULT_CONFIG_TOML"):]
        tpl = tpl[: tpl.index('"#;')]
        doc = read("docs/site/configuration.md")
        section, missing = "", []
        for line in tpl.splitlines():
            m = re.match(r"^\[([a-z_.]+)\]", line)
            if m:
                section = m.group(1)
                if section != "allowlist":
                    self.assertIn("`[%s]`" % section, doc, "no section for [%s]" % section)
                continue
            m = re.match(r"^#? ?([a-z_0-9]+) *= ", line)
            if m and section != "allowlist" and "`%s`" % m.group(1) not in doc:
                missing.append("%s.%s" % (section, m.group(1)))
        self.assertEqual(missing, [], "settings missing from configuration.md")
        for entry in re.findall(r"\[\[allowlist\.([a-z_]+)\]\]", tpl):
            self.assertIn("allowlist.%s" % entry, doc)

    def test_every_command_and_flag_is_documented(self):
        cli = read("hermian/src/cli.rs")
        doc = read("docs/site/cli.md")
        enum = cli[cli.index("pub enum Cmd {"):]
        enum = enum[: enum.index("\n}")]
        for name in re.findall(r"^\s+([A-Z][A-Za-z]+)(?:\(|,)", enum, re.M):
            cmd = re.sub(r"(?<!^)([A-Z])", r"-\1", name).lower()
            self.assertRegex(doc, r"`(hermian )?%s\b" % cmd, "command %s missing from cli.md" % cmd)
        args = cli[cli.index("#[derive(clap::Args)]"):]
        for attrs, field in re.findall(r"#\[arg\(([^\]]*)\)\]\s*pub ([a-z_]+):", args):
            if "long" not in attrs:
                continue
            long = re.search(r'long = "([a-z-]+)"', attrs)
            flag = "--" + (long.group(1) if long else field.replace("_", "-"))
            self.assertIn(flag, doc, "%s missing from cli.md" % flag)

    def test_every_alert_title_is_documented(self):
        index = read("docs/site/detections/index.md")
        titles = set()
        # The title argument ends where the signature starts (a "dN|..." literal
        # or a *_SIG constant), and in any case before .what(.
        signature = re.compile(r'&?(?:format!\(\s*)?"(?:d\d|selfprotect|summary|\{\})\||_SIG\b|\.what\(')
        for path in sorted((ROOT / "hermian-core/src/detect").glob("*.rs")):
            src = path.read_text(encoding="utf-8").split("#[cfg(test)]")[0]
            # Literals between Finding::new( and its signature, if/else blocks included.
            for m in re.finditer(r"Finding::new\(", src):
                rest = src[m.end():]
                end = signature.search(rest)
                span = rest[: end.start()] if end else ""
                titles |= set(re.findall(r'"([^"{}\\]+)"', span))
            # Titles chosen ahead of the call (account and group changes).
            for m in re.finditer(r'title: (?:if [^{]+\{\s*)?"([^"]+)"(?:\s*\} else \{\s*"([^"]+)")?', src):
                titles |= {t for t in m.groups() if t}
        for path in sorted((ROOT / "hermian/src").glob("*.rs")):
            src = path.read_text(encoding="utf-8").split("#[cfg(test)]")[0]
            titles |= set(re.findall(r'^\s+"(Hermian [^"{}]+)",?$', src, re.M))
            # Alert titles start with a capital; daemon log lines don't.
            titles |= set(re.findall(r'Severity::\w+,\s*"([A-Z][^"{}]+)",', src))
        missing = sorted(t for t in titles if t not in index)
        self.assertEqual(missing, [], "alert titles missing from detections/index.md")


if __name__ == "__main__":
    unittest.main()
