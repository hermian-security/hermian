# HERMIAN

Silent by default. Loud when it matters.

HERMIAN is a small security daemon for Linux servers. It watches for a short
list of things that are hard to explain as normal activity, and sends you one
message when one of them happens. No dashboard, no rule language, nothing to
tune.

```
install -> enable -> forget -> one message when something is actually wrong
```

Status: **v0.1.0-beta**. Five detection groups, Telegram/email/webhook
alerting, a `.deb`, signed releases. Tested end to end on one host so far;
the burn-in plan for the rest is in [docs/ROADMAP-BURN-IN.md](docs/ROADMAP-BURN-IN.md).
Full spec: [PROJECT.md](PROJECT.md).

## Install

Requirements on the host: systemd, kernel 5.4 or newer (5.8+ for full eBPF
coverage; older kernels run on /proc polling and audit and say so in
`status`).

Releases are at <https://github.com/hermian-security/hermian/releases>.
Every artifact is signed with Sigstore; the identity is this repository's
release workflow, so there's no key to fetch and nothing to trust but
GitHub's OIDC issuer. Verify first, then install:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp '^https://github.com/hermian-security/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

# Debian / Ubuntu: the package runs `hermian enable` for you
sudo apt install ./hermian_0.1.0-1_amd64.deb

# any other systemd distro
tar xzf hermian-0.1.0-linux-amd64.tar.gz && cd hermian-0.1.0-linux-amd64
sudo sh install.sh

sudo hermian status
```

You should see `PROTECTED`, five coverage rows saying `on`, and `Kernel ...
eBPF`. `.rpm` and AUR come after the Fedora and Arch burn-in.

There is deliberately no `curl | sudo sh`. Piping an unverified script to
root is the kind of thing this tool is meant to catch.

### Building from source

```bash
sudo apt install -y build-essential pkg-config libpam0g-dev   # or your distro's equivalent
cargo build --release
cargo test
sudo make install          # /usr/local/bin, then `hermian enable`
```

That's all you need. The eBPF programs are vendored as a compiled object
(`hermian-ebpf/prebuilt/hermian-ebpf.o`) and picked up automatically; the
object is kernel-independent because struct offsets are read from the running
kernel's BTF at start.

To rebuild the eBPF programs themselves you also need a nightly toolchain
with `rust-src` and `bpf-linker`. Install the linker as a prebuilt static
binary; `cargo install bpf-linker` wants LLVM 21 on the system and no distro
ships that:

```bash
rustup toolchain install nightly -c rust-src
curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
  | sudo tar --zstd -x -C /usr/local/bin bpf-linker
HERMIAN_EBPF_FROM_SOURCE=1 cargo build --release    # refuses the vendored fallback
```

CI builds from source on every push and fails if the vendored object is stale.

## Getting notified

`journald` and `/var/log/hermian/alerts.log` get everything. To be told about
HIGH and CRITICAL alerts, enable a channel in `/etc/hermian/config.toml`. The
daemon picks up the change on save.

**Telegram.** Message [@BotFather](https://t.me/BotFather), `/newbot`, copy
the token. Send your new bot any message (or add it to a group and post
once), then:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
```

```toml
[notifications]
channels = ["journald", "file", "telegram"]

[notifications.telegram]
bot_token = "123456789:AAH..."
chat_id = "-1001234567890"
silent_below_critical = true     # HIGH arrives muted, CRITICAL makes a sound
```

**Email**, via an SMTP account (Gmail and Workspace want an app password;
Fastmail, Postmark, SES, Mailgun all work the same way):

```toml
[notifications]
channels = ["journald", "file", "email"]

[notifications.email]
transport = "smtp"
from = "hermian@example.com"
to = ["ops@example.com"]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_security = "starttls"       # tls for 465, none for a local relay on 25
smtp_username = "hermian@example.com"
smtp_password = "app-password"
```

Or, if the host already has postfix or msmtp set up, `transport = "sendmail"`
with just `from` and `to`.

Then prove it works:

```bash
sudo hermian notify-test                     # probes each channel, sends one test alert
sudo hermian notify-test --probe-only        # connectivity and credentials only
```

Slack, Discord, ntfy and generic JSON webhooks are also supported; see the
`[notifications.webhook]` section in the default config.

Failed deliveries are retried with backoff and never duplicated across
channels. `hermian status` shows the queue, the last error and deliveries per
channel. Fifteen minutes of failure logs a CRITICAL locally. Tokens and
passwords live only in the 0600 config file and are stripped from error
messages.

## What it catches

| | Signals | Source |
|---|---|---|
| **D1** process chains | web server or database spawning a shell; shell -> curl/wget -> something runs; execution from /tmp, /dev/shm, /var/tmp; execution from a deleted file or a memfd | eBPF exec tracepoints, /proc, audit fallback |
| **D2** SSH and auth | root logins, failed-auth bursts, logins from sources never seen before, SSH config edits, new accounts, sudo/wheel membership | PAM module (optional), auth.log or journald, inotify |
| **D3** persistence | cron, shell profiles, systemd units, ld.so.preload, ld.so.conf.d, authorized_keys, changed with nobody at a terminal | inotify plus the process tree |
| **D4** privilege escalation | setuid files and file capabilities outside system directories, ptrace attach by non-debuggers, unattended LD_PRELOAD, sudoers/passwd/shadow edited outside the proper tools | eBPF ptrace tracepoint, inotify, a periodic sweep |
| **D5** network in context | connections from a chain D1 already flagged, web servers reaching new external addresses, first-time connectors, new listeners from suspicious processes | eBPF connect tracepoint, /proc/net |

The same event lands at a different severity depending on context. Editing
`/etc/cron.d/backup` over SSH is INFO. The same file written by a daemon when
nobody is logged in is HIGH. If the new line is `curl ... | sh`, CRITICAL.
`sh /tmp/installer.sh` from your terminal is LOW; the same thing from a
process chain that already tripped D1 is CRITICAL. Severity means "what
should I do right now": INFO and LOW are logged, HIGH is sent to you,
CRITICAL is sent immediately and may isolate the host if you opted in.

The full rule list with the exact severities is in PROJECT.md.

## Day to day

```bash
sudo hermian status                     # coverage, baseline, overhead, delivery health
sudo hermian alerts                     # recent alerts, newest first
sudo hermian alerts -s high -n 50       # HIGH and above
sudo hermian show HER-2025-0914-001     # one alert in full; `hermian show 1` works for today
sudo hermian collect HER-2025-0914-001  # forensic bundle: processes, files, hashes, listeners
sudo hermian test                       # nine synthetic attacks through the real engine
sudo hermian isolate                    # nftables lockdown; management CIDRs stay reachable
sudo hermian unisolate
sudo hermian uninstall --yes
```

`status`, `alerts`, `show` and `test` take `--json`. Colour is only used on a
terminal; `NO_COLOR=1` or `HERMIAN_COLOR=never|always` override.

### Configuration

`/etc/hermian/config.toml`, root-owned, mode 0600. The daemon watches it;
any change is validated and applied, and a CRITICAL alert says what changed,
so nobody can quietly turn a detection off. `systemctl reload hermian` also
reloads.

Suppressions go in the allowlist and every entry needs a `reason`. The
config file is your record of every time you decided something was fine:

```toml
[[allowlist.process_chains]]
parent = "deploy-agent"
child  = "bash"
user   = "deploy"
reason = "CI/CD deployment pipeline"

[[allowlist.persistence]]
path   = "/etc/cron.d/app-*"             # trailing * for prefix match
reason = "written by the app's scheduler"

[[allowlist.ssh_sources]]
source = "10.0.0.0/8"
reason = "office VPN"
```

The first 24 hours after install are a learning window: SSH sources and
network peers seen then are treated as known afterwards. `hermian enable
--no-baseline` skips it on a freshly built host.

## An alert

This is the exact text written to journald and the log file. On a terminal it
gets colour; in email it comes as text plus HTML; on Telegram as a short
message with this attached.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
■■■■ HERMIAN  CRITICAL                                 HER-2025-0914-001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Web server chain downloaded and executed remote content

  Host        web-prod-01
  Time        2025-09-14 03:17:42 UTC
  Detection   D1 Suspicious process chain

WHAT HAPPENED
  nginx spawned a shell, the shell ran curl to fetch content, and that
  content is now executing as sh (pid 3110).

  systemd  root · pid 1
  └─ nginx  www-data · pid 1842
     └─ bash  www-data · pid 3107
        └─ curl  www-data · pid 3109
           └─ sh  www-data · pid 3110
                /tmp/.x.sh

  Executable  /tmp/.x.sh

WHY THIS MATTERS
  Web server, shell, downloader, execution: this exact sequence is the
  signature of remote code execution - an attacker exploiting the
  application, staging a payload, and running it.

RECOMMENDED ACTION
   1. Isolate this host from the network unless the activity is known
      and expected.
   2. Preserve the executed file and the process memory for analysis.
   3. Review web server access logs around the alert time to find the
      entry point.

────────────────────────────────────────────────────────────────────────
hermian show HER-2025-0914-001         hermian collect HER-2025-0914-001
```

Repeats of the same finding within five minutes are folded into the first
alert; one LOW summary closes the window.

## What it does to your system

- Runs as root under a hardened systemd unit: `ProtectSystem=strict`,
  `NoNewPrivileges`, `RestrictNamespaces`, `RestrictSUIDSGID`, and only the
  capabilities eBPF, audit and ptrace need. `CAP_NET_ADMIN` is added only if
  you configure isolation.
- Reads /proc, /etc, and the auth log. Writes only under `/etc/hermian`,
  `/var/lib/hermian`, `/var/log/hermian` and `/run/hermian`, all root-owned.
- Opens no listening socket. Connects out only to the notification endpoints
  you configured.
- Never changes the system configuration it watches, never touches
  credentials. The PAM module is passive and returns `PAM_IGNORE`; it cannot
  affect whether a login succeeds.
- Does nothing on its own beyond logging and notifying. Isolation needs two
  explicit config settings and always leaves your management network
  reachable.
- Raises `fs.inotify.max_user_watches` to 524288 if the host's limit is lower
  (the default is easily exhausted by one file-watching app, which would
  silently blind the persistence rules).
- `hermian uninstall` removes all of it.

## Repository

```
hermian-core/    the engine: events, process tree, D1-D5, severity, dedup, alerts, config.
                 pure Rust, no I/O, 77 tests that run on any OS
hermian/         the daemon and CLI: eBPF loader (aya), BTF reader, inotify, /proc,
                 audit netlink, auth sources, notifier and channels, status, collect
hermian-ebpf/    the eBPF programs (aya-ebpf) and the vendored compiled object
hermian-pam/     pam_hermian.so, optional, passive
packaging/       systemd unit template, sysctl, debian maintainer scripts, tarball installer
tests/           attack simulations, false-positive workloads, soak tooling
docs/            burn-in roadmap
.github/         CI and the signed release workflow
```

```bash
cargo test -p hermian-core     # engine tests, any OS
cargo test                     # everything, Linux
make check                     # fmt, clippy -D warnings, tests
sudo tests/run_suite.sh        # attack sims + false-positive workloads on a real host
```

## Reporting a problem

Security issues: see [SECURITY.md](SECURITY.md), or mail contact@hermian.me.
False positives are bugs too; open an issue with the output of
`hermian show <ref> --json`.

Apache-2.0.
