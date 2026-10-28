# Hermian

**Silent by default. Loud when it matters.**

[![CI](https://github.com/hermian-security/hermian/actions/workflows/ci.yml/badge.svg)](https://github.com/hermian-security/hermian/actions/workflows/ci.yml)
[![Release](https://github.com/hermian-security/hermian/actions/workflows/release.yml/badge.svg)](https://github.com/hermian-security/hermian/releases)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Hermian is a small security daemon for Linux servers. It stays quiet until
something looks like a real compromise, then tells you in your logs, Telegram,
email, or a webhook. There's no dashboard, no account, and no server to run.

It judges what happens in context (who started it, from where, and whether
someone was logged in) across five rule families:

- **Process chains:** web shells, RCE, code run from /tmp or from memory.
- **SSH and accounts:** new sources, root logins, brute force, new privileged accounts.
- **Persistence:** cron, systemd units, shell profiles, authorized_keys, ld.so.preload, PAM.
- **Privilege escalation:** setuid files, sudoers and shadow edits, LD_PRELOAD, ptrace.
- **Network:** C2 from a flagged chain, new destinations, new listening ports.

It learns the host's normal for 24 hours, folds repeats into one page, reports
on itself if it's stopped or tampered with, and can block a source or isolate
the host when you turn that on.

> [!NOTE]
> **It's beta.** Validated on Ubuntu 22.04 and 24.04 so far. Try it on a test
> host first. What's verified is in [docs/EVIDENCE.md](docs/EVIDENCE.md).

## Install

Linux with systemd and kernel 5.4+ (eBPF needs 5.8+), amd64 or arm64.

```bash
curl -fsSL https://github.com/hermian-security/hermian/releases/download/v0.1.0-beta.12/install.sh | sudo sh
```

It installs the `.deb` on Debian/Ubuntu (and adds the signed APT repository
`apt.hermian.me`) or the tarball elsewhere, and always checks `SHA256SUMS`.
`--dry-run` shows what would change. Then run `sudo hermian status`.

By hand on Debian/Ubuntu:

```bash
VER=v0.1.0-beta.12
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
DEB=$(grep -o "hermian_.*_$(dpkg --print-architecture)\.deb" SHA256SUMS)
curl -fsSLO "$BASE/$DEB" && sha256sum -c SHA256SUMS --ignore-missing
sudo apt install "./$DEB"
```

Hermian runs as root. Out of the box it only logs: add a channel to get
alerts, and nothing leaves the host until you do. Other distros, provenance
checks, what setup changes, upgrades, uninstall and building from source are
in the [install guide](https://hermian.me/docs/install/).

## Limits

- **Ubuntu only so far.** RHEL with SELinux, the older-kernel fallback, and
  arm64 are untested.
- **The dead-man switch is local.** It isn't an out-of-band monitor.

The full threat model is in [Limits](https://hermian.me/docs/limits/).

## Docs

- [hermian.me/docs](https://hermian.me/docs/): quickstart, every detection,
  notifications, response, CLI, configuration, troubleshooting.
- [Beta testing](docs/BETA.md) and [several servers](docs/FLEET.md).
- [Evidence](docs/EVIDENCE.md), [project notes](PROJECT.md),
  [changelog](CHANGELOG.md).
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md) (report
  vulnerabilities privately).

Found a bug or a false positive? Open an issue with `hermian show <ref> --json`,
secrets removed.

## Early testers

Thanks to everyone running the beta. To join, follow
[docs/BETA.md](docs/BETA.md), then add your avatar between the markers below
in a PR linking your [beta report](https://github.com/hermian-security/hermian/issues/new?template=beta-report.yml):

<!-- testers:start (one line per tester; see "Early testers" above) -->
<!-- testers:end -->

```html
<a href="https://github.com/YOU" title="YOU"><img src="https://github.com/YOU.png?size=96" width="48" height="48" alt="YOU"></a>
```

---

Made by [Hermian Security](https://hermian.me), licensed under
[Apache-2.0](LICENSE). Parts are written with AI help; merges and releases are
done by hand, never by AI ([AGENTS.md](AGENTS.md)).
