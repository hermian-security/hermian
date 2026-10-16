<!-- The #gh-*-mode-only fragments follow GitHub's theme setting; <picture>
     follows the OS, which showed the white logo on GitHub's light theme. -->
<p>
  <a href="https://hermian.me#gh-light-mode-only"><img src="docs/brand/lockup-light.svg#gh-light-mode-only" alt="Hermian" height="56"></a>
  <a href="https://hermian.me#gh-dark-mode-only"><img src="docs/brand/lockup-dark.svg#gh-dark-mode-only" alt="Hermian" height="56"></a>
</p>

**Silent by default. Loud when it matters.**

[![CI](https://github.com/hermian-security/hermian/actions/workflows/ci.yml/badge.svg)](https://github.com/hermian-security/hermian/actions/workflows/ci.yml)
[![Release](https://github.com/hermian-security/hermian/actions/workflows/release.yml/badge.svg)](https://github.com/hermian-security/hermian/releases)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Hermian is a small security daemon for Linux servers. It watches process
chains, SSH logins, persistence changes, privilege escalation, and network
activity, and stays quiet until something looks like a real compromise. Then
it tells you in your logs, Telegram, email, or a webhook. There's no dashboard,
no account, and no server to run.

Here's an alert in Telegram:

```
◉◉◉◉  CRITICAL · Process chain
Web server chain ran downloaded code

┃ nginx started a shell that downloaded a file and is now running it as
┃ www-data.

host   web-01
chain  nginx › sh › curl
rule   D1 · Suspicious process chain
time   6 Oct 2026 · 03:14 UTC

┃ Risk · Next steps   (tap to expand)

hermian show HER-2026-1006-415
```

The meter counts up with severity (`◉○○○` INFO to `◉◉◉◉` CRITICAL). The push
stays short: the risk and next steps sit in a collapsed section. `hermian show`
and the email carry the full record, process chain and evidence included.

> [!NOTE]
> **It's beta.** Two Ubuntu 22.04 hosts have passed the full attack suite, one
> of them running Hermian since September 2026. Other distros and longer runs
> are still to come. Try it on a test host first. What's been verified is
> in [docs/EVIDENCE.md](docs/EVIDENCE.md), and what it can't do is under
> [Limits](#limits). Running it for a week? [Become an early tester](#early-testers).

## Is it for you?

It's a good fit for:

- a VPS, a homelab, or a handful of servers you look after yourself;
- getting alerts in chat or your logs instead of another dashboard;
- optional response without a control plane: block a source or cut a session
  straight from the alert, or isolate the host automatically on CRITICAL.

It's not built for:

- **containers and Kubernetes**: it watches the host, not what's inside pods;
- **fleets**: there's no central console, policy management, or compliance
  reporting;
- **hosts you can't debug**: the burn-in matrix isn't finished yet.

## Install

You need Linux with systemd and kernel 5.4+. eBPF needs 5.8+; older kernels
run with reduced coverage. Builds are for amd64 and arm64.

```bash
curl -fsSL https://github.com/hermian-security/hermian/releases/download/v0.1.0-beta.11/install.sh | sudo sh
```

The script comes from the release it installs. On Debian/Ubuntu it installs
the `.deb` (apt starts the daemon); elsewhere it uses the tarball. It always
checks `SHA256SUMS`, and if `cosign` or the GitHub CLI is installed it also
verifies where the release was built. Without either, it tells you and goes on
with the checksum alone.

`--dry-run` downloads and verifies, then shows what would change.
`--version vX.Y.Z` picks another release. The same command installs and
upgrades.

On Debian and Ubuntu, when the release ships the repository key, the
installer also adds the signed APT repository `apt.hermian.me`, so
`sudo apt upgrade` keeps Hermian current from then on. The key comes with the
release and is checked like the `.deb` itself. `--no-apt-repo` skips it.

Rather read it first? Grab `install.sh` from the
[release](https://github.com/hermian-security/hermian/releases) assets, look it
over, then run it.

<details>
<summary>Install by hand</summary>

Pin a release tag (the newest is on the
[releases page](https://github.com/hermian-security/hermian/releases)); don't
script against `latest`. These steps work for installing and upgrading.

### Debian / Ubuntu, from the APT repository

```bash
curl -fsSL https://apt.hermian.me/hermian-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/hermian-archive-keyring.gpg >/dev/null
printf 'Types: deb\nURIs: https://apt.hermian.me\nSuites: beta\nComponents: main\nSigned-By: /usr/share/keyrings/hermian-archive-keyring.gpg\n' \
  | sudo tee /etc/apt/sources.list.d/hermian.sources
sudo apt update && sudo apt install hermian
```

`beta` gets every prerelease; `stable` starts with v0.1.0. apt checks every
download against that key. To compare the key with the one a release ships,
download `hermian-archive-keyring.gpg` from the release and diff the two.

### Debian / Ubuntu, one release by hand

```bash
VER=v0.1.0-beta.11
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
DEB=$(grep -o "hermian_.*_$(dpkg --print-architecture)\.deb" SHA256SUMS)
curl -fsSLO "$BASE/$DEB" && sha256sum -c SHA256SUMS --ignore-missing
sudo apt install "./$DEB"
sudo hermian status
```

The package starts the daemon. `/tmp` is only there because apt's sandbox user
can read it; from your home directory apt still installs, with a warning.

### Other systemd distros

```bash
VER=v0.1.0-beta.11
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
TGZ=$(grep -o "hermian-.*-linux-$ARCH\.tar\.gz" SHA256SUMS)
curl -fsSLO "$BASE/$TGZ" && sha256sum -c SHA256SUMS --ignore-missing
tar xzf "$TGZ" && cd "${TGZ%.tar.gz}"
sudo sh install.sh
```

This installs `/usr/local/bin/hermian` and the optional PAM module, then runs
`hermian enable`.

### Check where it came from (optional)

`sha256sum -c` catches a broken download, but `SHA256SUMS` sits right next to
the files it describes. To confirm this repository's release workflow built
them, verify with whichever tool you have.

With the [GitHub CLI](https://cli.github.com/) (releases from v0.1.0-beta.5 on;
needs `gh auth login`):

```bash
gh attestation verify "$DEB" --repo hermian-security/hermian   # or "$TGZ"
```

With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
curl -fsSLO "$BASE/SHA256SUMS.sigstore"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity "https://github.com/hermian-security/hermian/.github/workflows/release.yml@refs/tags/$VER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Run it before `sha256sum -c`: once `SHA256SUMS` is verified, it vouches for
every file it lists.

</details>

### What setup changes

Hermian runs as root. Setup creates its config, state, logs, and systemd unit,
and raises inotify limits if they're too low. Out of the box it logs and
notifies; automatic isolation is off until you turn it on. `hermian status`
shows reduced coverage or delivery errors. The full list is in the
[project notes](PROJECT.md), section 5.

### Upgrade

With the APT repository set up (above), upgrades come with
`sudo apt update && sudo apt upgrade`. Otherwise, rerun the installer with
`--version vX.Y.Z`, or set `VER=vX.Y.Z` in the steps above. Either way, read
the notes for the new release first: they list any one-time steps.

### Uninstall

`sudo hermian uninstall` asks first, then lifts isolation and removes the
daemon, unit, config, stored alerts, logs, PAM hook, APT repository entry,
and binary. Back up any
alerts you want to keep. If you installed the package, `sudo apt purge hermian`
does the same.

### From source

On Debian/Ubuntu, with Rust installed:

```bash
sudo apt install -y build-essential pkg-config libpam0g-dev
cargo build --release --locked
cargo test --locked
sudo make install
```

A prebuilt eBPF object is included. Rebuilding it takes a few extra tools; see
[the build notes](PROJECT.md), section 7.

## Get notified

Alerts always go to journald and `/var/log/hermian/alerts.log`. To get them
somewhere you'll actually see them, add a channel in `/etc/hermian/config.toml`.
Valid changes reload on their own, and the change itself raises an alert. Keep
the file root-only (0600).

For Telegram, create a bot with [@BotFather](https://t.me/BotFather), send it a
message, then find your chat ID in the Bot API's
[`getUpdates`](https://core.telegram.org/bots/api#getupdates) response:

```toml
[notifications]
channels = ["journald", "file", "telegram"]

[notifications.telegram]
bot_token = "123456789:AAH..."
chat_id = "-1001234567890"
```

Email (SMTP or sendmail) and webhooks (Slack, Discord, ntfy, or plain JSON)
work too, configured in the same file. HIGH and CRITICAL alerts notify by
default.

Then make sure it works:

```bash
sudo hermian notify-test
```

### Response buttons (optional)

Telegram alerts can carry buttons: **Block** on the brute-force digest, and
**Ignore**, **Disconnect session**, or **Disconnect and block** on suspicious
SSH logins. They act right away, so only allow people you trust:

```toml
[notifications.telegram]
actions = true
allowed_user_ids = [123456789]   # your Telegram user id (ask @userinfobot)

[response]
block_duration_hours = 24
```

Run `sudo hermian enable` once afterwards to grant the firewall and kill
capabilities. Presses from anyone else are refused and logged. See or lift
blocks with `sudo hermian blocked` and `sudo hermian unblock <ip>`.

## Day to day

```bash
sudo hermian status                  # coverage and delivery health
sudo hermian alerts                  # recent alerts, LOW and up (--all adds INFO)
sudo hermian alerts -s high          # only HIGH and CRITICAL
sudo hermian show 1                  # today's alert 001
sudo hermian collect HER-2026-0921-001
sudo hermian test                    # synthetic engine checks, not live coverage
sudo hermian report                  # a week's summary to share, nothing private
```

`status`, `alerts`, `show`, `test`, and `report` take `--json` for scripts.
`collect` gathers local context for an alert and never uploads anything.
`report` counts alerts by rule and severity with versions and coverage, and
leaves out host names, addresses, users, paths and commands: if you're
testing the beta, that's the thing to send.

For the first 24 hours Hermian learns your normal SSH sources and network
activity. After that, a source or destination counts as new the first time it
shows up, not every time it comes back (destinations are grouped by /24, or
/64 for IPv6). Put exceptions in the config's allowlist, each with a `reason`.

Network isolation needs your management CIDRs configured first. Read the
response settings and limits in [PROJECT.md](PROJECT.md), section 6, before you
turn it on.

## Limits

- **One distro so far.** Only Ubuntu 22.04 has run it in the field. RHEL with
  SELinux, the older-kernel fallback, and arm64 are untested.
- **It only sees what it hooks.** Detection runs on kernel and log sources;
  anything outside them is invisible, and one incident can trip more than one
  rule.
- **Delivery is at-least-once.** Pending alerts queue on disk per channel (500
  each) and survive a restart; a crash mid-send can send one twice.
- **The dead-man switch is local.** A systemd timer checks the daemon's
  heartbeat, pages you when it goes stale, and restarts it. A killed daemon is
  reported when it next starts. It isn't an out-of-band monitor.
- **Isolation isn't a full cutoff.** `hermian isolate` installs an nftables
  ruleset with documented exceptions, and auto-isolation reverts on a timer.
  Connections outside your management CIDRs are cut, but alert endpoints
  (Telegram, webhook, SMTP) stay reachable for anything on the host.
- **Root still owns the box.** Local hashes catch changes; they don't stop
  someone who already has root.

How it works under the hood is in [PROJECT.md](PROJECT.md), and what's left
before production is in [docs/EVIDENCE.md](docs/EVIDENCE.md).

## How it's built

Parts of the code, tests, and docs are written with AI help, and we'd rather
say so than hide it. AI-assisted work can branch, test, commit, push, and open
a PR; merges and releases are done by hand, never by AI. For now there's one
maintainer, who owns everything that lands. Independent review comes as the
project grows. The working rules are in [AGENTS.md](AGENTS.md).

## Early testers

The people running the beta on their own servers and telling us what they
see. Thank you.

<!-- testers:start (one line per tester; see "Join them" below) -->
<!-- testers:end -->

**Join them.** Run Hermian for a week, then open a
[beta report](https://github.com/hermian-security/hermian/issues/new?template=beta-report.yml) with the output of `sudo hermian report` (counts and
versions only, nothing private). After that, [edit this file](https://github.com/hermian-security/hermian/edit/main/README.md): GitHub
forks it for you. Add one line between the two `testers` markers, with your
GitHub username in all three places, and open the pull request with a link to
your report:

```html
<a href="https://github.com/YOU" title="YOU"><img src="https://github.com/YOU.png?size=96" width="48" height="48" alt="YOU"></a>
```

## More

- [Evidence](docs/EVIDENCE.md): what's verified, the burn-in plan, and the
  false-positive log.
- [Project notes](PROJECT.md): architecture, detection rules, and limits.
- [Contributing](CONTRIBUTING.md): builds, tests, PRs, and releases.
- [Changelog](CHANGELOG.md): what changed and when.
- [Security](SECURITY.md): please report vulnerabilities privately.
- [Brand](docs/BRAND.md): naming, logo, and colours.

Found a bug or a false positive? Open an issue with `hermian show <ref> --json`,
after removing secrets and private details.

---

<a href="https://hermian.me#gh-light-mode-only"><img src="docs/brand/company-lockup-light.svg#gh-light-mode-only" alt="Hermian Security" height="24"></a>
<a href="https://hermian.me#gh-dark-mode-only"><img src="docs/brand/company-lockup-dark.svg#gh-dark-mode-only" alt="Hermian Security" height="24"></a>

Hermian is made by Hermian Security and licensed under [Apache-2.0](LICENSE).
