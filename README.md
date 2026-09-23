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

Needs a writable directory (`/tmp`, not `/opt`). Pin the tag; don't use `latest`.

```bash
VER=v0.1.0-beta.4
ARCH=$(dpkg --print-architecture)
cd /tmp
curl -fsSLO "https://github.com/hermian-security/hermian/releases/download/$VER/SHA256SUMS"
DEB=$(awk -v a="_${ARCH}.deb" '$2 ~ a"$" { print $2; exit }' SHA256SUMS)
FILE=$(printf '%s' "$DEB" | tr '~' '.')
curl -fsSLO "https://github.com/hermian-security/hermian/releases/download/$VER/$FILE"
[ -e "$DEB" ] || cp "$FILE" "$DEB"
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install "./$FILE"
sudo hermian status
```

The package starts the daemon. On other systemd distros, fetch the tarball the
same way, check `SHA256SUMS`, extract, and run `sudo sh install.sh` from that
directory.

HERMIAN runs as root. Setup creates its config, state, logs, and systemd unit,
and raises inotify limits if needed. Monitoring logs and notifies by default;
automatic isolation is opt-in. Check `status` for reduced coverage or delivery errors.

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
`sudo hermian uninstall` removes the daemon, config, stored alerts, and logs
after confirmation.

## More

- [Project notes](PROJECT.md): architecture, detection rules, and limits.
- [Contributing](CONTRIBUTING.md): builds, tests, PRs, and releases.
- [Changelog](CHANGELOG.md): what's changed.
- [Security reports](SECURITY.md): please report vulnerabilities privately.

For bugs or false positives, open an issue with `hermian show <ref> --json`.
Remove secrets and private details before sharing it.

[Apache-2.0](LICENSE).
