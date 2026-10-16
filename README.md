<p>
  <a href="https://hermian.me">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup-dark.svg">
      <img src="docs/brand/lockup-light.svg" alt="Hermian" height="56">
    </picture>
  </a>
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
> **It's beta.** One host has passed the full attack and false-positive run,
> and a production VPS has run it since September 2026. Wider testing across
> distros is still going. Try it on a test host first. What's been verified is
> in [docs/EVIDENCE.md](docs/EVIDENCE.md), and what it can't do is under
> [Limits](#limits).

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
curl -fsSL https://github.com/hermian-security/hermian/releases/download/v0.1.0-beta.9/install.sh | sudo sh
```

The script comes from the release it installs. On Debian/Ubuntu it installs
the `.deb` (apt starts the daemon); elsewhere it uses the tarball. It always
checks `SHA256SUMS`, and if `cosign` or the GitHub CLI is installed it also
verifies where the release was built. Without either, it tells you and goes on
with the checksum alone.

`--dry-run` downloads and verifies, then shows what would change.
`--version vX.Y.Z` picks another release. The same command installs and
upgrades.

Rather read it first? Grab `install.sh` from the
[release](https://github.com/hermian-security/hermian/releases) assets, look it
over, then run it.

<details>
<summary>Install by hand</summary>

Pin a release tag (the newest is on the
[releases page](https://github.com/hermian-security/hermian/releases)); don't
script against `latest`. These steps work for installing and upgrading.

### Debian / Ubuntu

```bash
VER=v0.1.0-beta.9
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
VER=v0.1.0-beta.9
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
[project notes](PROJECT.md#host-changes).

### Upgrade

Nothing updates itself yet (a signed APT repository is planned). Watch the
releases, read the notes for the new tag (they list any one-time steps), then
rerun the installer with `--version vX.Y.Z`, or set `VER=vX.Y.Z` in the steps
above.

### Uninstall

`sudo hermian uninstall` asks first, then lifts isolation and removes the
daemon, unit, config, stored alerts, logs, PAM hook, and binary. Back up any
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
[the build notes](PROJECT.md#building-ebpf).

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
sudo hermian alerts -s high          # recent HIGH and CRITICAL alerts
sudo hermian show 1                  # today's alert 001
sudo hermian collect HER-2026-0921-001
sudo hermian test                    # synthetic engine checks, not live coverage
```

`status`, `alerts`, `show`, and `test` take `--json` for scripts. `collect`
gathers local context for an alert and never uploads anything.

For the first 24 hours Hermian learns your normal SSH sources and network
activity. After that, a source or destination counts as new the first time it
shows up, not every time it comes back (destinations are grouped by /24, or
/64 for IPv6). Put exceptions in the config's allowlist, each with a `reason`.

Network isolation needs your management CIDRs configured first. Read
[response settings and limits](PROJECT.md#response) before you turn it on.

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
before production is in [the burn-in matrix](docs/ROADMAP-BURN-IN.md).

## How it's built

Parts of the code, tests, and docs are written with AI help, and we'd rather
say so than hide it. AI-assisted work can branch, test, commit, push, and open
a PR; merges and releases are done by hand, never by AI. For now there's one
maintainer, who owns everything that lands. Independent review comes as the
project grows. The working rules are in [AGENTS.md](AGENTS.md).

## More

- [Evidence](docs/EVIDENCE.md): what's been verified, where, and when.
- [Project notes](PROJECT.md): architecture, detection rules, and limits.
- [Burn-in matrix](docs/ROADMAP-BURN-IN.md): the road to production-ready.
- [False-positive log](docs/fp-log.md): every HIGH+ that wasn't real.
- [Contributing](CONTRIBUTING.md): builds, tests, PRs, and releases.
- [Changelog](CHANGELOG.md): what changed and when.
- [Security](SECURITY.md): please report vulnerabilities privately.
- [Brand](docs/BRAND.md): naming, logo, and colours.

Found a bug or a false positive? Open an issue with `hermian show <ref> --json`,
after removing secrets and private details.

---

<a href="https://hermian.me">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/company-lockup-dark.svg">
    <img src="docs/brand/company-lockup-light.svg" alt="Hermian Security" height="24">
  </picture>
</a>

Hermian is made by Hermian Security and licensed under [Apache-2.0](LICENSE).
