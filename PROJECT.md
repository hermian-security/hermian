Hermian project notes
=====================

How Hermian works inside. To install and use it, see README.md. To build,
test and release, see CONTRIBUTING.md. What has been verified so far is in
docs/EVIDENCE.md.

Hermian watches a single Linux host and sends a short list of useful
alerts, with no separate server to run. It's in beta. It isn't a full EDR,
and a quiet host isn't proof that it's clean.


1. Architecture

    eBPF, inotify, auth logs, PAM, polling
                      |
              hermian-core::Engine
       process tree, baseline, rules, allowlist
                      |
         findings -> deduplication -> alerts
                      |
        JSON store, logs, notifications

- hermian-core: rules, process tree, baseline, config and alert rendering.
  No I/O.
- hermian: the Linux collectors, daemon, CLI, storage and delivery.
- hermian-ebpf: the kernel hooks and the vendored eBPF object.
- hermian-pam: an optional, passive PAM module.

Hermian runs on systemd hosts with kernel 5.4 or newer, amd64 and arm64.
The core tests also run on Windows and macOS; the daemon doesn't. Nothing
listens on the network. Channels send alerts, never raw telemetry, and
Telegram button presses are fetched by outbound polling.


2. Detection rules

Rules are deterministic: they look at process roles, ancestry, paths, who
is logged in and recent findings, not at a risk score. The source files are
the detailed reference.

- D1, process chains (hermian-core/src/detect/d1.rs): shells started by
  web servers or databases, directly or through other programs; downloaders
  and nc or socat started by services; download-and-run chains; programs
  run from /tmp or from deleted files.
- D2, SSH and accounts (d2.rs, brute.rs): failed-login bursts (INFO); a
  digest every 2 hours when real accounts were targeted; a login right after
  a burst; root logins and logins from new sources, naming the key used and
  where it's stored; sshd key sources in hidden places; SSH config and
  account changes.
- D3, persistence (d3.rs): loader config, cron and at jobs, shell profiles,
  SSH keys, systemd units, PAM, global environment, rc.local, udev rules and
  boot-time modules.
- D4, privileges (d4.rs): setuid and capability files, ptrace, LD_PRELOAD,
  sudoers and shadow writes.
- D5, network (d5.rs): connections from flagged chains, new destinations
  and new listeners.

Context decides severity. A web server starting a shell is HIGH; a shell in
an SSH session isn't. Programs that excuse a change (package managers,
config managers, user tools, debuggers) only count when the file and every
directory above it are owned by root and writable by nobody else: a binary
merely named dpkg doesn't count. Content is checked before any excuse: the
real crontab installing a "curl | sh" job is still reported.

inotify doesn't say who wrote a file. Hermian looks for an open file
descriptor first, then for a recent admin tool started from a session or a
package manager. Failing that, it treats a write as an operator's when
something was started from an interactive session in the last 15 seconds,
or an editor is open in one. That's a guess, and it can downgrade an
unrelated write made while someone is typing.

The baseline learns SSH sources, destinations and connecting programs for
24 hours, then judges novelty, and keeps learning: something is new the
first time it's seen, not every time. Destinations are judged by network
(/24, or /64 for IPv6). A key that has logged in before, from a new address
in a network the account already uses (/16, or /32 for IPv6), is INFO.

Allowlist entries need a reason. Fixing a noisy rule is better than a broad
exception. Examples are in /etc/hermian/config.toml.


3. Collectors

- Execution: eBPF sched_process_exec, plus syscall hooks for context.
  Parent PIDs from kernel BTF offsets, with a /proc fallback.
- Connect and ptrace: eBPF syscall entry, so attempts, not confirmed
  success. Not seen: 32-bit syscalls on x86_64, io_uring connects,
  unconnected UDP sends, TCP Fast Open.
- File changes: inotify on selected paths, 400 ms debounce, 2.5 s at most.
- Listeners: /proc/net/tcp, every 5 seconds.
- Setuid files: a sweep every 20 seconds, four levels deep.
- SSH: journald (sshd's own entries only), else auth.log or secure. The
  PAM module is optional.

eBPF needs kernel 5.8 or newer. Without it, execution falls back to
polling /proc every second, and to audit when available (an existing auditd
is left alone). Short-lived processes can be missed then. The exec hooks
check 64 environment entries for LD_PRELOAD and LD_AUDIT; more filler than
that hides them. A 32-bit program on x86_64 is reported LOW, since its
syscalls bypass the hooks.

Hermian watches the host, not what runs inside containers. It doesn't see
injection that doesn't start a new program, and a ptrace alert doesn't
reveal what was done to the target.


4. Alerts and delivery

Alerts carry the rule, the evidence, the process chain when there is one,
the risk and next steps. They're stored as JSON in /var/lib/hermian/alerts/
and kept for general.alert_retention_days (90 by default). alerts.log
rotates at 50 MB.

- INFO: context, never notified, hidden from "hermian alerts" by default.
- LOW: worth a look.
- HIGH: investigate. Notified by default.
- CRITICAL: urgent. Notified, and can trigger automatic isolation.

Repeats within 5 minutes are folded into one alert with a count. Different
rules can still report the same incident.

journald and alerts.log always get every alert. Telegram, email, webhooks
(Slack, Discord, ntfy, JSON) and stdout get those at min_severity and above.
Pending alerts are queued on disk per channel (500 each) and survive a
restart, so delivery is at least once: a crash mid-send can send one twice.


5. What Hermian changes on a host

hermian enable creates the systemd units (the daemon and the watchdog
timer), root-only config, state and log directories, the binary and config
hashes and the baseline, raises low inotify limits, and starts the daemon.
The package runs it on every install and upgrade.

The unit uses ProtectSystem=strict, NoNewPrivileges and a list of
capabilities. PrivateTmp stays off so Hermian sees the host's /tmp.

A config change that alters detections, channels or the allowlist pages
CRITICAL. An invalid config keeps the last good one and logs LOW. A binary
or config changed while the daemon was stopped pages on the next start.
None of this stops someone who already has root.

A stop pages HIGH, except a restart by hermian enable (installs and
upgrades), which is INFO. The unit restarts the daemon after any other exit.
A timer checks the daemon's heartbeat every minute, pages and restarts it if
it's stuck, and the next start reports an unclean shutdown. It runs on the
same host: it isn't an outside monitor. Dropped telemetry pages HIGH.

Updates come through the signed APT repository (apt.hermian.me) when the
installer has added it, or by running the installer again.

The PAM module is opt-in (hermian enable --with-pam). It reports login
results, never reads passwords, and always returns PAM_IGNORE.


6. Response

By default Hermian only logs and notifies.

Telegram buttons, with notifications.telegram.actions on and
allowed_user_ids set:

- The brute-force digest offers Block for its top sources, Block all and
  Ignore 2h, plus a 7-day reminder when root can log in with a password.
- Suspicious logins offer Ignore, Disconnect session and Disconnect and
  block.

Buttons act at once, only for the listed users, expire after action_ttl_mins
and work once. Every press is logged and answered in the chat. Block puts
the source in an nftables set of its own for block_duration_hours (IPv6 as
its /64) and never blocks management CIDRs, allowlisted sources or local
addresses. Disconnect stops the sshd processes holding that one connection.
"hermian blocked" lists blocks and "hermian unblock" lifts one. One bot per
host when buttons are on: see docs/FLEET.md.

Isolation (hermian isolate, or automatic on CRITICAL with
response.auto_isolate) needs response.management_cidrs. It keeps loopback,
the management CIDRs, DHCP, IPv6 neighbour discovery, DNS, cloud metadata
and the alert endpoints, and cuts everything else, open connections and
routed traffic included. Alert endpoints stay reachable, so it isn't a
complete cutoff. A CRITICAL whose service doesn't look genuine (a program
merely named nginx) pages but doesn't isolate. "hermian isolate --for 30"
and auto_isolate_revert_mins lift it with a systemd timer that works even
if the daemon is gone. Test your CIDRs and recovery access first.

hermian enable grants CAP_NET_ADMIN and CAP_KILL only when buttons or
isolation are configured: run it again after turning them on.


7. Building

Builds use the vendored eBPF object (hermian-ebpf/prebuilt/hermian-ebpf.o)
unless told otherwise. To rebuild it, install the pinned nightly with
rust-src and bpf-linker v0.11.1 (the static release binary: building it
needs LLVM 21):

    rustup toolchain install nightly-2026-09-17 -c rust-src
    HERMIAN_EBPF_NIGHTLY=nightly-2026-09-17 HERMIAN_EBPF_FROM_SOURCE=1 \
      cargo build --release --locked

That pair reproduces the vendored object byte for byte; CI checks it. Bump
them together and commit the new object in the same pull request.
HERMIAN_EBPF_PREBUILT picks another object; HERMIAN_EBPF_FROM_SOURCE=0
uses the vendored one on purpose.

Build packages on the oldest glibc you support: a .deb records the build
host's glibc. Releases build on Ubuntu 22.04 (glibc 2.34 and newer).


8. Testing

Portable tests cover the engine; Linux CI builds the daemon and eBPF and
runs the self-test. Neither proves collection works on a real host: the
attack and false-positive suites do, and they modify real auth and
persistence files, so run them only on disposable hosts. Results and the
burn-in plan are in docs/EVIDENCE.md.
