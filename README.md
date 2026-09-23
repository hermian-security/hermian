# HERMIAN

[![Hermian](docs/logo-text.svg)](https://hermian.me)

A small Linux security daemon. Watches process chains, SSH activity, persistence
changes, privilege escalation signals, and network activity. Alerts go to your
logs, Telegram, email, or a webhook. No dashboard or central server needed.

**Still in beta.** Start on a test host; coverage and false-positive rates need
more field testing. See [project notes](PROJECT.md) for how it works and its limits.

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

## More

- [Project notes](PROJECT.md): architecture, detection rules, and limits.
- [Contributing](CONTRIBUTING.md): builds, tests, PRs, and releases.
- [Changelog](CHANGELOG.md): what's changed.
- [Security reports](SECURITY.md): please report vulnerabilities privately.

For bugs or false positives, open an issue with `hermian show <ref> --json`.
Remove secrets and private details before sharing it.

[Apache-2.0](LICENSE).
