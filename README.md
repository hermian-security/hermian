# HERMIAN

[![Hermian](docs/logo-text.svg)](https://hermian.me)

[![CI](https://github.com/hermian-security/hermian/actions/workflows/ci.yml/badge.svg)](https://github.com/hermian-security/hermian/actions/workflows/ci.yml)
[![Release](https://github.com/hermian-security/hermian/actions/workflows/release.yml/badge.svg)](https://github.com/hermian-security/hermian/releases)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A small Linux security daemon. Watches process chains, SSH activity, persistence
changes, privilege escalation signals, and network activity. Alerts go to your
logs, Telegram, email, or a webhook. No dashboard or central server needed.

**Beta, validated on one host so far.** One host has completed the full attack
and false-positive pass; a production VPS has been running it since
September 2026. Broader testing across distros and time is in progress. Start
on a test host. The verified numbers are in [docs/EVIDENCE.md](docs/EVIDENCE.md),
and the known gaps are in [Limits](#limits).

Here's what an alert looks like (Telegram; the CLI has the full record):

```
■■■■ HERMIAN - CRITICAL
Host : web-01

- Web server chain ran downloaded code :

nginx started a shell that downloaded a file and is now running it as
www-data.

Chain  nginx → sh → curl → /tmp/.x
File   /tmp/.x

━━━━━━━━━━━━━━━━

Web servers don't normally spawn shells. The chain then downloaded a
file from the internet, which is the shape of a web shell dropped on a
vulnerable app.

Also
1. Isolate the host unless this is expected.

━━━━━━━━━━━━━━━━
hermian show HER-2026-1006-415
```

## Who it is for

- A VPS, a homelab, or a small set of servers you look after yourself.
- People who want the alert in chat or logs, not another dashboard or account.
- Opt-in response: block a source or disconnect a session from the alert, or
  auto-isolate CRITICAL events, without a central control plane.

## Who it is not for

- Containers and Kubernetes: it watches the host, not what's inside pods.
- Fleets and endpoint management: no central console, policy management, or
  compliance reports.
- Anything you can't test first: the burn-in matrix isn't finished, so don't
  start on a host you can't afford to debug.

## Limits

- **One distro so far.** Only Ubuntu 22.04 hosts have run it in the field.
  RHEL/SELinux, the older-kernel fallback, and arm64 are untested.
- **It sees what it hooks.** Detection runs on kernel and log sources;
  activity outside them is invisible, and separate rules can report one
  incident.
- **Delivery isn't durable.** Pending alerts sit in memory (500 max) and
  don't survive a crash. Good enough for the default channels, not an outbox.
- **No heartbeat.** It flags changes to itself and its config, but if the
  daemon is SIGKILLed, nothing else is watching.
- **Isolation isn't a cutoff.** `hermian isolate` installs an nftables ruleset
  with documented exceptions, and auto-isolation reverts on a timer.
- **Root owns the box.** Local hashes detect changes; they don't stop someone
  who already has root.

Architecture and detection details are in [PROJECT.md](PROJECT.md); plans and
gaps are in [the burn-in matrix](docs/ROADMAP-BURN-IN.md).

## Install

You'll need Linux, systemd, and kernel 5.4+. eBPF needs 5.8+; older kernels use
reduced coverage. Builds target amd64 and arm64.

Pin a release tag (the newest is on the
[releases page](https://github.com/hermian-security/hermian/releases)); don't
script against `latest`. The commands below work the same for installing and
upgrading.

### Debian / Ubuntu

```bash
VER=v0.1.0-beta.5
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
DEB=$(grep -o "hermian_.*_$(dpkg --print-architecture)\.deb" SHA256SUMS)
curl -fsSLO "$BASE/$DEB" && sha256sum -c SHA256SUMS --ignore-missing
sudo apt install "./$DEB"
sudo hermian status
```

The package starts the daemon. `/tmp` is just a directory apt's sandbox user
can read; from your home directory apt still installs, with a warning.

### Other systemd distros

```bash
VER=v0.1.0-beta.5
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
TGZ=$(grep -o "hermian-.*-linux-$ARCH\.tar\.gz" SHA256SUMS)
curl -fsSLO "$BASE/$TGZ" && sha256sum -c SHA256SUMS --ignore-missing
tar xzf "$TGZ" && cd "${TGZ%.tar.gz}"
sudo sh install.sh
```

This installs `/usr/local/bin/hermian`, the optional PAM module, and runs
`hermian enable`.

### Check where it came from (optional)

`sha256sum -c` catches a broken download, but `SHA256SUMS` sits next to the
files it describes. To confirm the release was built by this repository's
release workflow, verify it with either tool you have.

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

Run it before `sha256sum -c`: a verified `SHA256SUMS` then vouches for every
file it lists.

### What setup does

HERMIAN runs as root. Setup creates its config, state, logs, and systemd unit,
and raises inotify limits if needed. Monitoring logs and notifies by default;
automatic isolation is opt-in. Check `status` for reduced coverage or delivery
errors. Details are in [project notes](PROJECT.md#host-changes).

### Upgrade

Nothing updates itself yet (a signed APT repository is planned). Watch the
repository's releases, then rerun the install commands with the new `VER`.
Read that release's notes first; they list any one-time steps.

### Uninstall

`sudo hermian uninstall` lifts isolation and removes the daemon, unit, config,
stored alerts, logs, PAM hook, and binary after confirmation. Back up alerts you
want to keep. With the package, `sudo apt purge hermian` does the same.

### From source

On Debian/Ubuntu, with Rust installed:

```bash
sudo apt install -y build-essential pkg-config libpam0g-dev
cargo build --release --locked
cargo test --locked
sudo make install
```

A prebuilt eBPF object is included. Rebuilding it needs extra tools; see
[the build notes](PROJECT.md#building-ebpf).

## Get notified

By default, alerts stay in journald and `/var/log/hermian/alerts.log`.
Edit `/etc/hermian/config.toml` to add a delivery channel. Valid changes reload
automatically and raise a configuration-change alert. Keep the file root-only (0600).

For Telegram, create a bot with [@BotFather](https://t.me/BotFather), message it,
and get your chat ID from the Bot API's
[`getUpdates`](https://core.telegram.org/bots/api#getupdates) response:

```toml
[notifications]
channels = ["journald", "file", "telegram"]

[notifications.telegram]
bot_token = "123456789:AAH..."
chat_id = "-1001234567890"
```

#### Response buttons (optional)

Telegram alerts can carry buttons: `Block` on the brute-force digest, and
`Ignore` / `Disconnect session` / `Disconnect and block` on suspicious SSH
logins. They act at once, so only list people you trust:

```toml
[notifications.telegram]
actions = true
allowed_user_ids = [123456789]   # your Telegram user id (ask @userinfobot)

[response]
block_duration_hours = 24
```

Then run `sudo hermian enable` once to grant the firewall and kill
capabilities. Presses from anyone else are refused and logged. List or lift
blocks with `sudo hermian blocked` and `sudo hermian unblock <ip>`.

Email (SMTP or sendmail) and webhooks (Slack, Discord, ntfy, generic JSON) are
also supported. Their settings are in the same config file. HIGH and CRITICAL
alerts trigger notifications by default.

Test your setup before relying on it:

```bash
sudo hermian notify-test
```

## Daily use

```bash
sudo hermian status                  # coverage and delivery health
sudo hermian alerts -s high          # recent HIGH/CRITICAL alerts
sudo hermian show 1                  # today's alert 001
sudo hermian collect HER-2026-0921-001
sudo hermian test                    # synthetic engine checks, not live coverage
```

Use `--json` with `status`, `alerts`, `show`, or `test` for scripts.
`collect` gathers local context for an alert; it doesn't upload anything.

The default 24-hour baseline learns SSH sources and network activity for novelty
checks. Exceptions belong in the config's allowlist, with a `reason` for each one.

Optional network isolation needs management CIDRs configured first. See
[response settings and limits](PROJECT.md#response) before using it.

## AI-assisted development

Parts of the code, tests, and docs are written with AI assistance, and the
project says so instead of hiding it. AI-assisted work can branch, test,
commit, push, and open a PR; merging and releasing are done by hand and never
by AI. Right now there's a single maintainer, who owns everything that merges;
independent review is planned as the project grows. The full working rules are
in [AGENTS.md](AGENTS.md).

## More

- [Evidence](docs/EVIDENCE.md): what's been verified, where, and when.
- [Project notes](PROJECT.md): architecture, detection rules, and limits.
- [Burn-in matrix](docs/ROADMAP-BURN-IN.md): how this gets to production ready.
- [False-positive log](docs/fp-log.md): every HIGH+ that wasn't real.
- [Contributing](CONTRIBUTING.md): builds, tests, PRs, and releases.
- [Changelog](CHANGELOG.md): what's changed.
- [Security reports](SECURITY.md): please report vulnerabilities privately.

For bugs or false positives, open an issue with `hermian show <ref> --json`.
Remove secrets and private details before sharing it.

[Apache-2.0](LICENSE).
