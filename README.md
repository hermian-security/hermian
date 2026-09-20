# HERMIAN

**Silent by default. Loud when it matters.**

HERMIAN is a lightweight defensive security daemon for Linux. It watches for
high-confidence signs of compromise using deterministic, contextual rules and
only interrupts you when something genuinely requires attention.

```
install -> enable -> forget -> get notified only when it matters
```

No YAML rules. No dashboard. No alert fatigue.

Full product specification: [PROJECT.md](PROJECT.md)

---

## Status

Phase 1 (Linux MVP). Five detection groups, session-aware severity, local and
webhook alerting, a CLI for review and forensics, self-protection, and a signed
package path for Debian/Ubuntu. Windows and macOS are explicitly post-MVP.

## Quickstart (from source)

Build host requirements:

- Rust 1.79+ (`rustup`)
- `libpam0g-dev` (or your distro's PAM development package) for the optional PAM module

That is enough: the eBPF object is vendored at
`hermian-ebpf/prebuilt/hermian-ebpf.o` and used automatically when no BPF
toolchain is present. To rebuild the eBPF programs from source you also need:

- a nightly toolchain with `rust-src` (`rustup toolchain install nightly -c rust-src`)
- `bpf-linker` - install the **prebuilt static binary**, not `cargo install`
  (that needs LLVM 21+ on the system, which no distro ships):
  ```bash
  curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
    | sudo tar --zstd -x -C /usr/local/bin bpf-linker
  ```
  Then `HERMIAN_EBPF_FROM_SOURCE=1 cargo build --release` refuses the vendored
  fallback, and CI checks the vendored object matches the source.

```bash
make build            # builds hermian, hermian-ebpf and the PAM module
sudo make install     # installs to /usr/local/bin, renders the unit, starts the daemon
sudo hermian status   # coverage, overhead, notification health
sudo hermian test     # synthetic attack self-test, prints a sample alert
```

Target host requirements: systemd, kernel 5.4+ (full eBPF coverage on 5.8+;
`/proc` + audit fallback below that). Kernel BTF (`/sys/kernel/btf/vmlinux`,
standard on Ubuntu 20.10+, Debian 11+, RHEL 8.2+) gives exact parent
resolution; without it the daemon falls back to `/proc`.

**Building on a host with an old LLVM** (e.g. Ubuntu 22.04 ships LLVM 14, but
`bpf-linker` needs 21+): build the eBPF object once on any machine that has
the BPF toolchain, then point the daemon build at it:

```bash
# on the build machine
cargo build --release -p hermian   # produces target/.../ebpf-target/bpfel-unknown-none/release/hermian-ebpf
# on the target host, no bpf-linker needed
HERMIAN_EBPF_PREBUILT=/path/to/hermian-ebpf cargo build --release
```

The object is kernel-version independent (struct offsets are read from the
running kernel's BTF at start), so one object serves every host.

## Install from a release

Releases are at <https://github.com/hermian-security/hermian/releases>. Every
artifact is signed with [Sigstore](https://sigstore.dev) (keyless; the
identity is this repository's release workflow), so there is no GPG key to
fetch and nothing to trust but GitHub's OIDC issuer. `curl | sudo sh` is
banned; verify first:

```bash
# 1. verify the checksum file, then the artifacts against it
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp '^https://github.com/hermian-security/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

# 2a. Debian / Ubuntu (postinst runs 'hermian enable')
sudo apt install ./hermian_0.1.0-1_amd64.deb

# 2b. any systemd distro
tar xzf hermian-0.1.0-linux-amd64.tar.gz && cd hermian-0.1.0-linux-amd64
sudo sh install.sh

sudo hermian status
```

`.rpm` and AUR packages follow once the Fedora/Arch burn-in is complete
(see `docs/ROADMAP-BURN-IN.md`).

## What it catches

| Group | What it catches | Source |
|---|---|---|
| **D1** Suspicious process chains | web server or database spawning a shell; shell -> downloader -> exec; unattended exec from `/tmp`, `/dev/shm`, `/var/tmp`; fileless exec (deleted inode, memfd) | eBPF `execve`/`execveat` tracepoints, `/proc`, audit fallback |
| **D2** SSH and authentication abuse | root SSH login, failed-auth bursts, logins from never-seen sources, SSH config edits, new accounts, sudo/wheel membership changes | PAM module (optional), `auth.log` or `journalctl`, inotify |
| **D3** Persistence | cron, shell profiles, systemd units, `ld.so.preload`, `ld.so.conf.d`, `authorized_keys` - written with no operator session | inotify + process-tree correlation |
| **D4** Privilege escalation | setuid/setgid binaries and file capabilities outside system dirs, `ptrace` attach by non-debuggers, unattended `LD_PRELOAD`, sudoers/passwd/shadow tampering | eBPF `ptrace` tracepoint, inotify |
| **D5** Network in context | outbound connections from a flagged chain, web servers reaching new external destinations, first-time connectors, new listeners from suspicious processes | eBPF `connect` tracepoint, `/proc/net` |

### Severity is contextual

The same event gets a different severity depending on who did it:

| Situation | Severity |
|---|---|
| `vim /etc/cron.d/backup` from an SSH session | INFO |
| The same file written by a daemon with no session anywhere on the host | HIGH |
| ...and the cron line is `curl ... \| sh` | CRITICAL |
| `sh /tmp/installer.sh` from your terminal | LOW |
| The same exec from a process chain D1 already flagged | CRITICAL |

Severity answers one question: *what should the operator do right now?*

- **INFO** logged only
- **LOW** logged; notified only if `min_severity = "LOW"`
- **HIGH** notified
- **CRITICAL** notified immediately; may trigger isolation if opted in

## CLI

```bash
sudo hermian enable                 # install config + unit, start daemon (idempotent)
sudo hermian enable --no-baseline   # skip the 24h learning period on a fresh host
sudo hermian enable --with-pam      # hook the passive PAM module into sshd

sudo hermian status                 # coverage, baseline, overhead, delivery health
sudo hermian status --json

sudo hermian alerts                 # recent alerts, newest first
sudo hermian alerts -s high -n 50   # only HIGH and above
sudo hermian alerts -d d3 --json    # persistence alerts as NDJSON
sudo hermian show HER-2025-0914-001 # one alert in full (or: hermian show 1)
sudo hermian collect HER-2025-0914-001   # forensic bundle: processes, files, hashes, listeners

sudo hermian test                   # synthetic attack self-test + sample alert
sudo hermian test --verbose         # print every sample alert
sudo hermian notify-test            # verify Telegram/email/webhook and send a test alert

sudo hermian isolate                # nftables isolation; management CIDRs stay reachable
sudo hermian unisolate
sudo hermian uninstall --yes
```

Colour is used only on a TTY; set `NO_COLOR=1` or `HERMIAN_COLOR=never|always`.

## Getting notified

`journald` and the alert log always receive everything. To be *told* about
HIGH/CRITICAL alerts, enable one or more notifying channels. The daemon
applies the change on save (or `systemctl reload hermian`) and
`hermian notify-test` proves the path works before you rely on it.

### Telegram

1. Message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the token.
2. Open a chat with your new bot and send it any message (or add it to a
   group/channel and post there).
3. Find the chat id:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
   ```
   Personal chats are positive, groups negative, supergroups start with `-100`.
4. Configure and test:
   ```toml
   [notifications]
   channels = ["journald", "file", "telegram"]

   [notifications.telegram]
   bot_token = "123456789:AAH..."
   chat_id = "-1001234567890"
   silent_below_critical = true   # HIGH arrives muted, CRITICAL makes a sound
   ```
   ```bash
   sudo hermian notify-test            # probes token + chat, sends one test alert
   ```

### Email

**Via an SMTP account** (Gmail/Workspace need an *app password*; Fastmail,
Postmark, SES, Mailgun all work the same way):

```toml
[notifications]
channels = ["journald", "file", "email"]

[notifications.email]
transport = "smtp"
from = "hermian@example.com"
to = ["ops@example.com", "you@example.com"]
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_security = "starttls"       # starttls (587) | tls (465) | none (25, local relay)
smtp_username = "hermian@example.com"
smtp_password = "app-password-here"
```

**Via the host's own MTA** (postfix/exim/msmtp already configured):

```toml
[notifications.email]
transport = "sendmail"
from = "hermian@example.com"
to = ["ops@example.com"]
```

```bash
sudo hermian notify-test --channel email --probe-only   # connect + auth only
sudo hermian notify-test                                # send a test alert
```

Emails are multipart: a plain-text body identical to the terminal rendering
and an HTML version with the same layout. Subjects are
`[HERMIAN] CRITICAL D3 | host | title` so mail filters can key on them.

Both channels: failed deliveries are retried with backoff and never
duplicated across channels; `hermian status` shows the last error and
per-channel delivery counts, and 15 minutes of continuous failure raises a
local CRITICAL. Secrets live only in the 0600 config file and are redacted
from error messages.

## Configuration

`/etc/hermian/config.toml` (0600, root-owned). The daemon watches it: any change
is validated, applied, and reported as a CRITICAL self-protection alert so
tampering is never silent. `systemctl reload hermian` (SIGHUP) also reloads.

```toml
[notifications]
channels = ["journald", "file", "telegram", "email"]   # journald + file always get everything
min_severity = "HIGH"                                  # threshold for notifying channels
dedup_window_secs = 300

[notifications.webhook]
url = "https://hooks.slack.com/services/..."
format = "slack"        # generic | slack | discord | ntfy
token = ""              # optional bearer token

[response]
auto_isolate = false    # requires management_cidrs
management_cidrs = ["203.0.113.0/24"]

[allowlist]
[[allowlist.process_chains]]
parent = "deploy-agent"
child  = "bash"
user   = "deploy"
reason = "CI/CD deployment pipeline"

[[allowlist.persistence]]
path   = "/etc/cron.d/app-*"          # trailing * for prefix match
reason = "Managed by the app's scheduler"

[[allowlist.ssh_sources]]
source = "10.0.0.0/8"
reason = "Corporate VPN"
```

Every allowlist entry **requires** a `reason`; the config file is your audit
trail of suppression decisions.

## What an alert looks like

Every alert names the rule that fired, shows the evidence, explains why it
matters, and tells you what to do. This is the exact text written to journald
and `/var/log/hermian/alerts.log`; on a terminal it is colourised.

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

Identical alerts within the dedup window are folded into one; a single LOW
summary closes the window. Notifications that fail are retried with backoff;
after 15 minutes of failure a CRITICAL is logged locally.

## Security properties

- Passive by default. `auto_isolate` requires explicit opt-in **and** configured
  management CIDRs; HERMIAN never performs destructive remediation.
- Hardened systemd unit: `ProtectSystem=strict`, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`, `RestrictNamespaces`, minimal capability set;
  `CAP_NET_ADMIN` only when isolation is configured.
- Self-protection: binary and config hashes are checked at start and the config
  is watched at runtime. Any change produces a CRITICAL alert.
- No network listener. Outbound only, and only to a webhook you configured.
- Never reads, stores, or transmits credentials. The PAM module is passive
  (`PAM_IGNORE`) and cannot affect authentication.
- All state is `0600`/`0700` root-owned under `/var/lib/hermian`,
  `/var/log/hermian`, `/run/hermian`.

## Repository layout

```
hermian-ebpf/    eBPF programs: execve, execveat, connect, ptrace tracepoints (aya-ebpf)
hermian-core/    detection engine: events, D1-D5, severity, alerts, allowlist,
                 baseline, dedup, self-test. Pure Rust, no I/O, tests run anywhere.
hermian/         daemon + CLI: eBPF loader, /proc, inotify, audit netlink,
                 auth log / journald, PAM socket, notifier, status, alerts, collect
hermian-pam/     optional passive PAM module (pam_hermian.so)
packaging/       systemd unit template, debian/, signed-tarball installer, GPG guide
tests/           attack simulations + false-positive workloads (tests/run_suite.sh)
.github/         CI: fmt, clippy -D warnings, tests on Linux/macOS/Windows, eBPF build
```

## Development

```bash
cargo test -p hermian-core     # engine tests, run on any OS
cargo test                     # everything (Linux + bpf-linker)
make check                     # fmt --check + clippy -D warnings + tests
```

## Verification (Phase 2 gate)

```bash
sudo tests/run_suite.sh            # attack sims + 72h false-positive soak
sudo tests/run_suite.sh --quick    # 5-minute smoke version
sudo tests/run_suite.sh --skip-fp  # attack sims only
```

## License

Apache-2.0 (see LICENSE).
