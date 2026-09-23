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

## Detection rules

Rules are deterministic. They use process roles, ancestry, paths, user/session
context, and recent findings rather than a risk score. The source files below
are the detailed rule reference, including exemptions and severity choices.

| Group | Looks for |
| --- | --- |
| [D1: process chains](hermian-core/src/detect/d1.rs) | Web/db shells, download-and-exec chains, transient or deleted executables |
| [D2: auth](hermian-core/src/detect/d2.rs) | Failed-auth bursts (INFO), login after a burst (HIGH), root/new-source logins, SSH config and account changes |
| [D3: persistence](hermian-core/src/detect/d3.rs) | Loader config, cron, shell profiles, SSH keys, and systemd changes |
| [D4: privileges](hermian-core/src/detect/d4.rs) | Setuid/capability files, ptrace, LD_PRELOAD, sudoers, and shadow writes |
| [D5: network](hermian-core/src/detect/d5.rs) | Connections linked to flagged chains, baseline novelty, and new listeners |

These are engine rules, not a promise of complete live coverage. Collectors can
miss events or lack the context a rule needs.

### Context matters

A web server spawning a shell is HIGH. A normal shell under an SSH session
isn't. File rules also distinguish operator edits from unattended writes.

inotify doesn't identify the writer. The daemon tries to find an open file
descriptor; some rules also look for a recent admin tool. If the writer is
unknown, session presence is a fallback. That's a heuristic, not proof of who
changed a file, and it can downgrade an unrelated write.

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
| Connect / ptrace | eBPF syscall entry: records attempts, not confirmed success |
| File changes | inotify on selected paths; 400 ms debounce, max 2.5 s hold |
| Process metadata | `/proc` at startup and while handling events |
| TCP listeners | `/proc/net/tcp*`, polled every 5 s |
| Setuid/setgid files | Sweep every 20 s, depth-limited to four levels |
| SSH auth | `auth.log` / `secure`, or journald; PAM telemetry is optional |

eBPF needs kernel 5.8+ and the required permissions. If it can't load, execution
falls back to one-second `/proc` polling and audit when available. HERMIAN leaves
an existing auditd alone. Short-lived processes can be missed by polling.

Container metadata comes from PID namespaces and cgroups. This is host-side
monitoring, not full container or Kubernetes coverage.

Normal-looking commands can fall outside these rules. Exec monitoring won't see
injection that doesn't start a new image, and a ptrace alert doesn't reveal what
was done to the target's memory. There's no cross-host correlation either.

## Alerts and delivery

Alerts include the rule, evidence, process chain when available, and suggested
next steps. JSON records live in `/var/lib/hermian/alerts/`; `show` and `collect`
read them back.

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
allowlist pages CRITICAL. Invalid TOML keeps the last good config and logs LOW.
Startup hash checks still flag binary/config changes made while the daemon was
stopped. Local hashes aren't protection against someone who already controls
root. Nothing auto-updates. A stopped daemon can't report, and there's no
independent tamper monitor.

PAM integration is opt-in via `hermian enable --with-pam`. The module sends auth
metadata, doesn't read passwords, and returns `PAM_IGNORE`.

## Response

Monitoring logs and notifies by default; it doesn't kill or quarantine processes.
`hermian isolate` adds nftables rules. `hermian unisolate` removes them.

Isolation requires `response.management_cidrs`. Automatic isolation also needs
`response.auto_isolate = true`. The rules keep loopback, established flows, DNS,
and management CIDRs, so this isn't a complete network cutoff. Check your CIDRs
and recovery access on a test host first; don't assume remote access is guaranteed.

`hermian uninstall` tries to lift isolation, then removes the unit, config, state,
logs, PAM hook, and binary. Back up any alerts you want to keep.

## Building eBPF

Normal builds can use `hermian-ebpf/prebuilt/hermian-ebpf.o`. To rebuild it,
install nightly Rust with `rust-src` and a suitable
[bpf-linker binary](https://github.com/aya-rs/bpf-linker/releases).
CI currently uses bpf-linker v0.11.1.

```bash
rustup toolchain install nightly -c rust-src
HERMIAN_EBPF_FROM_SOURCE=1 cargo build --release --locked
```

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

Field results so far come from one Ubuntu host. CPU under 1%, RSS under 80 MB,
and low false-positive rates are goals, not guarantees. The 20-second privilege
sweep alone rules out a blanket five-second detection promise.

Next: fix collector and attribution gaps, run the wider
[burn-in matrix](docs/ROADMAP-BURN-IN.md), and add log rotation/alert pruning.
Broader packaging can wait until that coverage is tested.
