# Project notes

HERMIAN is a Linux host monitor for a VPS, homelab, or small fleet. The aim is a
short set of useful alerts without a separate server to manage. It's still beta,
not a full EDR or a guarantee that a quiet host is clean.

For setup, see the [README](README.md). For development and releases, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Architecture

```text
eBPF / inotify / auth logs / PAM / polling
                  |
                  v
          hermian-core::Engine
   process tree, baseline, rules, allowlist
                  |
                  v
        findings -> dedup -> alerts
                  |
                  v
     JSON store, logs, notifications
```

| Crate | Job |
| --- | --- |
| `hermian-core` | Rules, process tree, baseline, config, and alert rendering; no I/O |
| `hermian` | Linux collectors, daemon, CLI, storage, and delivery |
| `hermian-ebpf` | Kernel tracepoints and the vendored eBPF object |
| `hermian-pam` | Optional passive PAM telemetry module |

The agent targets systemd hosts on kernel 5.4+, amd64 and arm64. The core tests
also run on Windows and macOS; the daemon doesn't. There's no network listener
or remote event stream. Configured channels send alerts, not raw telemetry.
Telegram button presses, when enabled, are fetched by outbound long-polling.

## Detection rules

Rules are deterministic. They use process roles, ancestry, paths, user/session
context, and recent findings rather than a risk score. The source files below
are the detailed rule reference, including exemptions and severity choices.

| Group | Looks for |
| --- | --- |
| [D1: process chains](hermian-core/src/detect/d1.rs) | Web/db shells (direct or through other programs), downloaders and nc/socat started by services, download-and-exec chains, transient or deleted executables |
| [D2: auth](hermian-core/src/detect/d2.rs) | Failed-auth bursts (INFO), a [brute-force digest](hermian-core/src/detect/brute.rs) every 2 h when existing accounts were targeted (HIGH), login after a burst (HIGH), root/new-source logins, SSH config and account changes |
| [D3: persistence](hermian-core/src/detect/d3.rs) | Loader config, cron and at jobs, shell profiles, SSH keys, systemd units (admin, vendor, per-user), PAM, global environment, rc.local, udev rules, and boot-time modules |
| [D4: privileges](hermian-core/src/detect/d4.rs) | Setuid/capability files, ptrace, LD_PRELOAD, sudoers, and shadow writes |
| [D5: network](hermian-core/src/detect/d5.rs) | Connections linked to flagged chains, baseline novelty, and new listeners |

These are engine rules, not a promise of complete live coverage. Collectors can
miss events or lack the context a rule needs.

### Context matters

A web server spawning a shell is HIGH. A normal shell under an SSH session
isn't. File rules also distinguish operator edits from unattended writes.

Roles that exempt a process (package and config managers, user tools,
debuggers, session daemons) need its executable in a root-owned system
directory; a binary merely named `dpkg` doesn't count. Script tools such as
dnf or Debian's adduser run under an interpreter, so the script's own path
(from the command line) has to be in such a directory. Build tools that
excuse LD_PRELOAD (make, cargo, fakeroot...) follow the same rule. A TTY or
`sudo` doesn't count as an operator under a web server, database or cron.
Content checks come before tool exemptions: the real `crontab` installing a
`curl | sh` job, or a package manager writing a unit that runs from `/tmp`,
is still reported.

inotify doesn't identify the writer. The daemon tries to find an open file
descriptor; some rules also look for a recent admin tool, which only counts if
an operator session or a package/config manager started it (so `visudo -c`
from a cron job doesn't excuse a direct sudoers write). If the writer is
unknown, recent operator activity is the fallback: something started from an
interactive session in the last 15 seconds, or an editor running in one. An
idle SSH or tmux session doesn't count. That's a heuristic, not proof of who
changed a file, and it can still downgrade an unrelated write made while an
operator is typing.

The default baseline learns SSH sources, destination IPs, and connector identities
for 24 hours, then freezes those sets. Destination IPs are host-wide, not
per-application. Disabling the baseline also disables novelty judgments.
Root-login source history is tracked separately.

Allowlist entries need a `reason`. Prefer fixing a noisy rule over adding a broad
exception. See the examples in `/etc/hermian/config.toml`.

## Collectors

| Signal | Source and limits |
| --- | --- |
| Execution | eBPF `sched_process_exec`; syscall-entry hooks collect extra exec context |
| Parent PID | Kernel BTF offsets, with a `/proc` fallback |
| Connect / ptrace | eBPF syscall entry: records attempts, not confirmed success. Not seen: 32-bit (compat) syscalls on x86_64, io_uring connects, unconnected UDP `sendto`, TCP Fast Open |
| File changes | inotify on selected paths; 400 ms debounce, max 2.5 s hold |
| Process metadata | `/proc` at startup and while handling events |
| TCP listeners | `/proc/net/tcp*`, polled every 5 s |
| Setuid/setgid files | Sweep every 20 s, depth-limited to four levels |
| SSH auth | journald (root `sshd` entries only) when running, else `auth.log` / `secure`; PAM telemetry is optional |

eBPF needs kernel 5.8+ and the required permissions. If it can't load, execution
falls back to one-second `/proc` polling and audit when available. HERMIAN leaves
an existing auditd alone. Short-lived processes can be missed by polling.

The exec hooks check up to 64 environment entries for `LD_PRELOAD` or
`LD_AUDIT`; more filler variables than that still hide them. A 32-bit
program starting on x86_64 is logged (LOW) since its syscalls bypass the
hooks, and CPUs hot-plugged after startup page HIGH until a restart gives
them a reader.

Container metadata comes from PID namespaces and cgroups. This is host-side
monitoring, not full container or Kubernetes coverage.

Normal-looking commands can fall outside these rules. Exec monitoring won't see
injection that doesn't start a new image, and a ptrace alert doesn't reveal what
was done to the target's memory. There's no cross-host correlation either.

## Alerts and delivery

Alerts include the rule, evidence, process chain when available, and suggested
next steps. JSON records live in `/var/lib/hermian/alerts/`; `show` and `collect`
read them back. Records and collect bundles older than
`general.alert_retention_days` (default 90, 0 keeps them) are deleted hourly,
and `alerts.log` rotates at 50 MB, keeping three old copies.

- **INFO:** context for later.
- **LOW:** worth a look, usually not urgent.
- **HIGH:** investigate; notified by default.
- **CRITICAL:** urgent; notified and eligible for opt-in auto-isolation.

The default dedup window is five minutes. Higher severity gets through immediately;
repeated HIGH/CRITICAL findings can produce a LOW summary. This isn't one alert
per incident: separate rules may report the same activity.

Default local outputs are journald and `/var/log/hermian/alerts.log`. Optional
channels are Telegram, SMTP/sendmail, webhooks, and stdout, gated by `min_severity`.
Use `hermian notify-test` to check them.

Delivery retries use backoff and track which channels still need an alert. The
pending queue holds up to 500 alerts in memory; it isn't a durable outbox.
`status` shows pending deliveries and errors. A prolonged failure is logged locally.

## Host changes

`hermian enable` creates the systemd unit and root-only config/state/log dirs,
records binary/config hashes, initializes the baseline, and starts the daemon.
It also raises low inotify limits. Re-run it after a source or tarball upgrade;
the Debian package handles this itself.

The unit uses `ProtectSystem=strict`, `NoNewPrivileges`, and a capability list
for collection. `PrivateTmp` stays off so monitoring can see the host's `/tmp`.
See [the unit template](packaging/systemd/hermian.service) for the full settings.

A validated config change that actually alters detections, channels, or the
allowlist pages CRITICAL. Reloads compare against the config in effect, not
the hash file on disk. Invalid TOML keeps the last good config and logs LOW.
Startup hash checks still flag binary/config changes made while the daemon was
stopped, and a missing hash record pages HIGH instead of being silently
re-created. Local hashes aren't protection against someone who already
controls root. Nothing auto-updates.

A clean stop (`systemctl stop`, SIGTERM) pages HIGH before exiting, so package
upgrades send one too. The unit restarts the daemon after any other exit and
never gives up. A SIGKILL can't be reported, and there's no independent
tamper monitor or heartbeat. Dropped telemetry (full eBPF rings, inotify
overflows, audit ENOBUFS) pages HIGH and shows in `status`.

PAM integration is opt-in via `hermian enable --with-pam`. The module sends auth
metadata, doesn't read passwords, and returns `PAM_IGNORE`.

## Response

Monitoring logs and notifies by default; it doesn't kill or quarantine processes.
`hermian isolate` adds nftables rules. `hermian unisolate` removes them.

### Telegram buttons

With `notifications.telegram.actions = true` and `allowed_user_ids` set,
alerts that offer responses carry inline buttons:

| Alert | Buttons |
| --- | --- |
| Brute-force digest (failed logins against accounts that exist and have a login shell, or root; sent every `ssh.brute_digest_hours` only when a source reached `ssh.brute_min_attempts`) | `Block <ip>` for the top sources, `Block all`, `Ignore 2h`, and `Remind me in 7 days` when the digest warns that root can log in with a password |
| Login after a burst, from a new source, or root from a new place | `Ignore`, `Disconnect session`, `Disconnect and block` |

Buttons act immediately; there's no confirmation step. They only work for
the listed Telegram user ids in the configured chat, expire after
`action_ttl_mins`, and each works once. Every press is recorded as a local
alert and answered in the chat. Presses are fetched by outbound
long-polling (`getUpdates`), so nothing listens on the host, and it works
during isolation. A webhook set on the same bot stops it; `status` says so.

- **Block** adds the source to an nftables set with a timeout
  (`response.block_duration_hours`, default 24) in its own `hermian_block`
  table, dropping its traffic both ways. IPv6 sources are blocked as their
  /64. Management CIDRs, allowlisted SSH sources and loopback/link-local
  addresses are always refused. `hermian blocked` lists blocks and
  `hermian unblock <ip>` lifts one; blocks survive a daemon restart but not
  a reboot.
- **Disconnect** stops the sshd processes holding that connection (matched
  by source address and port from the log line), so the user's other
  sessions stay up. With block, the block goes in first so the session
  can't come straight back. Programs the user started get SIGHUP; ones that
  ignore it keep running.
- **Ignore** on the digest stops listing those sources for one digest
  period. Successful logins from them still alert.

`hermian enable` grants `CAP_NET_ADMIN` and `CAP_KILL` only when actions are
on; re-run it after turning them on.

Isolation requires `response.management_cidrs`. Automatic isolation also needs
`response.auto_isolate = true` and `CAP_NET_ADMIN`, which `hermian enable`
grants only when isolation is configured; re-run it after turning isolation on.
A CRITICAL whose web server or database doesn't look genuine still pages but
doesn't isolate, so a local user can't trigger it by naming a program
`nginx`. Genuine means the binary in a root-owned location is named like the
service, or a trusted interpreter (gunicorn, puma, tomcat) runs it under a
system account (uid < 1000).
The rules keep loopback, established flows, management CIDRs, DHCP, IPv6
neighbour discovery, DNS to the resolvers in resolv.conf, cloud instance
metadata (169.254.169.254, which some providers need for SSH logins), and TCP
to the notification endpoints resolved at isolation time. Routed traffic
(containers, VMs) is dropped too. It isn't a complete network cutoff.
Catch-all CIDRs (`0.0.0.0/0`, `::/0`) are rejected since they'd make
isolation a no-op.

As a dead-man switch, `hermian isolate --for 30` lifts the isolation after 30
minutes, and `response.auto_isolate_revert_mins` does the same for automatic
isolation. Both use a transient systemd timer, so they work even if the
daemon is gone. Check your CIDRs and recovery access on a test host first;
don't assume remote access is guaranteed.

`hermian uninstall` tries to lift isolation, then removes the unit, config, state,
logs, PAM hook, and binary. Back up any alerts you want to keep.

## Building eBPF

Normal builds can use `hermian-ebpf/prebuilt/hermian-ebpf.o`. To rebuild it,
install nightly Rust with `rust-src` and a suitable
[bpf-linker binary](https://github.com/aya-rs/bpf-linker/releases).
CI currently uses bpf-linker v0.11.1.

```bash
rustup toolchain install nightly-2026-09-17 -c rust-src
HERMIAN_EBPF_NIGHTLY=nightly-2026-09-17 HERMIAN_EBPF_FROM_SOURCE=1 cargo build --release --locked
```

CI pins that nightly and bpf-linker v0.11.1; with both, the build reproduces
the vendored object byte for byte. Bump them together and commit the new
object in the same PR.

`HERMIAN_EBPF_PREBUILT=/path/to/object` selects an explicit object instead.
If a BPF toolchain is installed but the source fails to compile, the build
fails rather than quietly using the vendored object; set
`HERMIAN_EBPF_FROM_SOURCE=0` to use the vendored object on purpose.
Linux CI rebuilds from source and compares against the vendored object.

## Testing and next steps

Portable tests cover the engine. Linux CI builds the daemon/eBPF and runs
synthetic self-tests. Neither proves live collection works on a given host.

The attack harness requires fresh matching HIGH/CRITICAL evidence. Its 30-second
wait accommodates pollers; it isn't a five-second latency test. Run attack and
false-positive workloads only on disposable hosts: they modify real auth and
persistence files.

Field results so far come from Ubuntu 22.04 hosts; [docs/EVIDENCE.md](docs/EVIDENCE.md)
records exactly what's verified and what isn't. CPU under 1%, RSS under 80 MB,
and low false-positive rates are goals, not guarantees. The 20-second privilege
sweep alone rules out a blanket five-second detection promise.

Next: fix collector and attribution gaps, run the wider
[burn-in matrix](docs/ROADMAP-BURN-IN.md), and publish a signed APT repository on GitHub Pages so updates arrive through
`apt upgrade`. RPM and other packaging can wait until that coverage is tested.
