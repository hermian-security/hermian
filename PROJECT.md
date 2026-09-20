# HERMIAN

Silent by default. Loud when it matters.

HERMIAN is a small security daemon for Linux servers. It watches for a short
list of things that are very hard to explain as normal activity, and it tells
you when one of them happens. That's it. No dashboard, no rule language, no
console to keep open.

This document is the spec. It describes what the code does as of v0.1.0-beta,
what it deliberately doesn't do, and how we decide what goes in next. Where
the text and the code disagree, the code is wrong or this file is stale; open
an issue either way.

Contents

- Who it's for and why it exists
- Scope, goals, non-goals
- How detection works
- The five detection groups, as shipped
- Severity
- Alerts
- False positives, and how we fight them
- Architecture
- Data sources
- Containers
- Self-protection
- Notifications
- Response
- Installation and packaging
- Where we are, and what's next
- Targets we measure against
- How we work
- Known hard problems

---

## Who it's for

Most Linux hosts on the internet have no host-based detection at all. Not
because the operator doesn't care, but because every existing option assumes
someone will tend it:

- Falco needs rules written and tuned, and an evening to get quiet.
- Wazuh and OSSEC want a manager server; for one VPS the manager costs more
  than the VPS.
- osquery answers questions but doesn't ask any.
- auditd is on by default on many systems and read by nobody.
- Commercial EDR is sold per seat to companies with a SOC.

HERMIAN is for the machines those tools skip: a developer's VPS, a small
team's handful of servers, a homelab, a personal Linux box with SSH exposed.
The operator is competent but has other work to do. They will install
something once. They will not tune it. If it pages them for nothing twice,
they will uninstall it.

So the bar is:

```
install -> enable -> forget -> get one message when something is actually wrong
```

## Scope

Linux, systemd, kernel 5.4 or newer. x86_64 and aarch64.

Windows and macOS are not in scope and no design work for them has been done.
The Linux agent has to prove itself on real workloads first; porting a tool
that's still finding its false positives would mean finding them twice.

## Goals

**Install in under three minutes with nothing to configure.** `apt install`
the package, or verify and untar the release. Detections are live within ten
seconds of `hermian enable`. Notifications need one config block and a
`notify-test`.

**Catch high-confidence compromise.** Five groups of signals, each chosen
because a legitimate explanation is rare and the malicious one is common.
Breadth is not a goal. See "Detection groups".

**Cost nothing you'd notice.** Under 1% CPU on average, under 80 MB resident,
HIGH or CRITICAL delivered to your phone within five seconds of the event.
Measured on the test host: 0.1% CPU, 19 MB RSS, roughly two seconds.

**Explain every alert.** What happened, the process chain or file that did
it, why we think it matters, what to do first. In plain language. No scores.

## Non-goals

HERMIAN will not become a SIEM, a log shipper, a vulnerability scanner, a
packet capture tool, a compliance product, a sandbox, or a dashboard. It will
not grow to hundreds of rules. It will not ship anything described as "AI".

The test for a new feature: does it improve detection quality, make an alert
clearer, or make response safer? If not, it waits.

---

## How detection works

Every rule is deterministic and reads its context from a process tree the
daemon keeps in memory. A finding is the product of several facts, never one:

```
which process        (comm, resolved exe path, previous images if it re-exec'd)
its ancestry         (full chain to PID 1, with roles: web server, shell, downloader...)
who                  (uid, and whether any ancestor is an interactive session)
where the file lives (transient dir? overlayfs? package-owned?)
what else happened   (was this chain flagged in the last two minutes?)
when                 (during the learning window? off-hours?)
```

The same raw event lands at different severities depending on that context:

| Event | Context | Result |
|---|---|---|
| bash spawned by sshd | interactive session | ignored |
| bash spawned by nginx | web server | HIGH |
| nginx -> bash -> curl -> /tmp/x runs | web server | CRITICAL |
| /etc/cron.d/job written | vim over SSH | INFO |
| /etc/cron.d/job written | no session anywhere on the host | HIGH |
| ...and the line is `curl ... \| sh` | | CRITICAL |
| /etc/shadow renamed into place | useradd ran 2 s ago | ignored |
| /etc/shadow renamed into place | nothing ran, no session | CRITICAL |
| /tmp/installer.sh executed | from your terminal | LOW |
| /tmp/installer.sh executed | by a service, no session | HIGH |

The one piece of statistics we use is a set-membership baseline: for the first
24 hours after install the daemon records SSH sources, outbound peers of each
program, and external destinations of web servers. After that, "never seen
before" is a fact a rule can use. This is a `HashSet`, not a model.

### Session attribution

Half of all false positives in file-based rules come from one question: was a
human at the keyboard when this file changed? inotify doesn't say. We answer
it in layers:

1. If the writing process still has the file open when we look, we know the
   pid; walk its ancestry for a TTY or a session daemon (sshd, login, sudo,
   tmux, ...).
2. Editors write via temp file and rename, so the writer is usually gone. If
   a user-management tool, `visudo`, or a package manager ran in the last
   eight seconds, the change is theirs.
3. Otherwise: is there any interactive session on the host at all? If yes,
   the change is "likely interactive" and lands at INFO. If no, it's
   "likely unattended" and lands at HIGH.

Layer 3 is a heuristic and it cuts both ways: a permanently open tmux session
makes everything look interactive. It is also where a real eBPF file-write
hook would replace guessing with knowing. That's on the list.

---

## Detection groups, as shipped

Each rule below exists in `hermian-core/src/detect/`. Severities are the ones
the code emits.

### D1: process chains

| Rule | Severity | Notes |
|---|---|---|
| web server -> shell | HIGH | nginx, apache, caddy, php-fpm, gunicorn, uwsgi, puma, tomcat, traefik, haproxy, envoy, ... |
| database -> shell | HIGH | mysqld, postgres, mongod, redis, elasticsearch, clickhouse, etcd, vault, ... |
| web server -> shell -> curl/wget | HIGH | |
| web server -> shell -> downloader -> anything executes | CRITICAL | |
| exec from /tmp, /dev/shm, /var/tmp | LOW / HIGH / CRITICAL | interactive or under a package manager / unattended / inside a chain already flagged |
| exec from a deleted inode or a memfd | HIGH | caught via `execveat` too, which is how `fexecve` and memfd loaders work |
| shell -> interpreter, unattended | INFO | context only, never notified |

Container entrypoints (a process whose parent is the container's PID 1) are
exempt from the web/db -> shell rules.

A HIGH or CRITICAL D1 finding "flags" the chain for ten minutes. D1 and D5 use
that to escalate what happens next. Init, sshd and cron are never flagged, so
one alert can't taint every process on the box.

### D2: SSH and authentication

| Rule | Severity | Notes |
|---|---|---|
| root login over SSH, first time from this source | HIGH | INFO on repeats from the same source; disabled by `ssh.permit_root = true` |
| failed-auth burst | HIGH | 5 attempts in 60 s from one source by default; fires once when the threshold is crossed |
| login from a source never seen in the baseline | LOW | HIGH if root or off-hours (22:00 to 06:00 UTC by default) |
| sshd_config / ssh_config / ~/.ssh/config changed | INFO / HIGH | interactive / unattended |
| new account or uid change in /etc/passwd | LOW / HIGH | HIGH if uid 0 or unattended |
| new member of sudo, wheel, admin, root | HIGH | |

Auth events come from the optional PAM module if installed, else
`/var/log/auth.log` or `/var/log/secure`, else `journalctl -f` on sshd. The
timestamp is parsed from the log line so bursts are measured correctly even
if the daemon was briefly behind.

### D3: persistence

| Path | Severity | Notes |
|---|---|---|
| /etc/ld.so.preload | CRITICAL | always; lists the libraries |
| /etc/ld.so.conf.d/* with a non-standard path | HIGH | LOW if a package manager wrote it |
| cron (/etc/crontab, cron.d, cron.*, /var/spool/cron) | INFO / HIGH / CRITICAL | interactive / unattended / the command downloads and pipes to a shell |
| shell profiles (system and per-user, bash and zsh) | INFO / HIGH | |
| systemd units and .wants/.requires links under /etc | INFO / HIGH / CRITICAL | package-owned units are ignored; CRITICAL if ExecStart is in a transient dir |
| authorized_keys | INFO / HIGH | |

Editor artifacts (`.swp`, `~`, `4913`, `tmp.XXXXXX`, `.dpkg-new`, ...) never
trigger a rule. Anything under a container overlay is ignored.

### D4: privilege escalation

| Rule | Severity | Notes |
|---|---|---|
| setuid/setgid file appears under /tmp, /var/tmp, /dev/shm, /home, /root, /var/www, /srv, /opt | CRITICAL | inotify plus a 20 s sweep, because `chmod` leaves no exec event |
| file capabilities set on a binary in those places | HIGH | |
| ptrace ATTACH or SEIZE by a non-debugger on an unrelated process | HIGH | debuggers, container runtimes and a process's own descendants are exempt; LOW when the target is unprivileged |
| LD_PRELOAD in an exec's environment | INFO / HIGH | interactive or under a build tool / unattended |
| sudoers edited outside visudo | LOW / HIGH / CRITICAL | interactive / unattended / adds NOPASSWD unattended |
| shadow or gshadow written outside the user tools | HIGH / CRITICAL | |

### D5: network, in context

| Rule | Severity | Notes |
|---|---|---|
| outbound connection from a chain D1 flagged in the last two minutes | HIGH | |
| web server connects to an external address never seen in the baseline | HIGH | |
| a program makes its first outbound connection since the baseline | LOW external / INFO private | |
| new listening port | INFO | LOW from a shell or interpreter, HIGH from a flagged or /tmp-resident process |

DNS, NTP, DHCP and mDNS ports are ignored. RFC 1918, link-local, loopback,
CGNAT and v4-mapped v6 count as private. Standalone network events never
reach HIGH on their own.

### Self-protection (SELF)

Not a detection group, but it produces alerts through the same pipeline:
binary or config hash mismatch at startup (CRITICAL), config changed while
running (CRITICAL, with a summary of what changed, whether it validated, and
the new hash), and a single INFO on first start to prove the alert path.

---

## Severity

| Level | Meaning | Default |
|---|---|---|
| INFO | context; useful when reading a timeline later | logged |
| LOW | worth a look when you're next at a terminal | logged; notified if `min_severity = "LOW"` |
| HIGH | you should look today | logged and notified |
| CRITICAL | you should look now | logged, notified, may isolate if you opted in |

Severity is the answer to "what should I do right now". It is not a
confidence score and it doesn't combine into anything.

Identical findings (same rule, same key) inside a five-minute window are
folded into the first alert. When the window closes, one LOW summary says how
many times it repeated. INFO repeats are dropped without a summary. A finding
that comes back at a higher severity breaks through the window immediately.

---

## Alerts

Every alert renders from one structure: title, host, time, rule, a plain
paragraph of what happened, the process chain with users and pids, key facts,
why it matters, and numbered next steps. The same structure is written to
journald and the log file as fixed-width text, to a terminal with colour, to
email as text plus HTML, and to Telegram as a short HTML message with the full
text attached in a monospace block.

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

Reference ids are `HER-YYYY-MMDD-NNN`, sequential per day, and survive a
daemon restart. Each alert is also stored as JSON under
`/var/lib/hermian/alerts/` so `hermian show`, `hermian alerts --json` and
`hermian collect` can work on it later.

---

## False positives

This is the product problem. A tool that pages you for nothing teaches you to
ignore it, and then it's worse than no tool.

Target: fewer than one false HIGH or CRITICAL per host per month, on hosts
doing real work.

### What we do about it

- Session attribution (above), so operator activity lands at INFO.
- Role tables for the processes that legitimately touch every persistence
  surface: package managers, config management, user tools, `visudo`,
  `crontab`, `systemctl`, `ldconfig`. Their writes are recognised, not
  allowlisted.
- Editor and packaging temp files are filtered before any rule runs.
- The baseline window, so novelty rules have something to compare against.
- Standalone network and interpreter events cap at LOW.
- A structured allowlist with a mandatory `reason`, so the config file is the
  audit trail of every suppression decision:

```toml
[[allowlist.process_chains]]
parent = "deploy-agent"
child  = "bash"
user   = "deploy"
reason = "CI/CD deployment pipeline"

[[allowlist.persistence]]
path   = "/etc/cron.d/app-*"
reason = "written by the app's scheduler"
```

### How we test it

Two scripts under `tests/`:

- `attacks/run_attack.sh` runs one of thirteen simulated attacks detached
  from any session and asserts a HIGH or CRITICAL with the expected title.
- `false_positives/run_false_positive.sh` runs an operator workload
  (editing cron and sudoers, adding and removing users, enabling units,
  `ssh-copy-id`, installers from /tmp, apt, strace, unshare) or an unattended
  one (apt, unattended-upgrade, logrotate, tmpfiles, ldconfig, pip, snap,
  cron-style jobs) and asserts zero HIGH or CRITICAL.

`tests/soak/` starts a clock on a host and snapshots alert counts hourly;
`report.sh` prints pass or fail against the 72-hour gate.

Results on the first host (Ubuntu 22.04, kernel 5.15, 2 vCPU): 13 of 13
attacks detected at the expected severity; 0 HIGH or CRITICAL across both
workloads. Eight more environments are listed in `docs/ROADMAP-BURN-IN.md`
and haven't been run yet. Until they have, this section describes an
intention with one data point behind it.

---

## Architecture

```
  eBPF tracepoints      inotify          /proc, /proc/net       auth log / journald / PAM
  sched_process_exec    persistence      process tree seed      sshd events
  sys_enter_execve*     account files    listener poller
  sys_enter_connect     config file      setuid sweeper
  sys_enter_ptrace      (debounced,
                         writer captured
                         on first event)
          │                 │                  │                        │
          └─────────────────┴────────┬─────────┴────────────────────────┘
                                     │  Event  (Exec, File, Connect, Ptrace, Auth, Listener)
                                     ▼
                              hermian-core::Engine
                    process tree · roles · baseline · flags · allowlist
                                     │
                              D1  D2  D3  D4  D5  SELF
                                     │  Finding
                                     ▼
                                  dedup
                                     │  Alert (ref id, host, time)
                                     ▼
                                 notifier
              always: JSON store, journald, alerts.log
              at min_severity+: telegram, email, webhook, stdout  (retry, backoff, per-channel)
```

The engine is a separate crate with no I/O. It takes events and returns
alerts, and its 77 tests run on any OS. Everything platform-specific lives in
the daemon crate.

Nothing leaves the host except alerts you've configured a channel for. No
event stream goes anywhere. There is no listener.

## Data sources

| What | How | Notes |
|---|---|---|
| process exec | eBPF `sched/sched_process_exec` | fires after the new image is live, so comm and path are right; `sys_enter_execve` and `execveat` only stash argv0, LD_PRELOAD presence, and the execveat flag |
| parent pid | `task_struct->real_parent->tgid` read in eBPF | offsets come from the kernel's BTF at load; exact even if the parent already exited |
| outbound connect | eBPF `sys_enter_connect` | v4 and v6 |
| ptrace | eBPF `sys_enter_ptrace` | |
| file changes | inotify on a fixed list of files and directories | events per path are debounced 400 ms (max 2.5 s), writer looked up on the first event |
| process metadata | /proc | ancestry seeding, container detection via cgroup and pid namespace |
| listeners | /proc/net/tcp and tcp6 every 5 s | owner pid resolved through /proc/*/fd in one pass |
| setuid files | filesystem sweep every 20 s, depth 4 | |
| auth | PAM module, or auth.log/secure, or `journalctl -f` | picked at startup, shown in `hermian status` |
| exec fallback | NETLINK_AUDIT | only when eBPF is unavailable and no auditd is running; installs an execve/execveat rule, parses the text records, removes the rule on exit |

eBPF is used where nothing else gives the same fact. inotify is cheaper for
files, /proc is fine for metadata. On kernels before 5.8, or when the eBPF
load fails, the daemon runs on /proc polling plus audit and says so in
`status`.

## Containers

A pid is "in a container" if its pid namespace differs from PID 1's or its
cgroup names a runtime. Events carry `container` and, where parseable,
`container_id`. Persistence rules skip paths under docker, containerd and
podman overlays. A container's own PID 1 spawning a shell is not a web-shell.

That's the extent of it. Runtime integration and anything Kubernetes-shaped
is not planned for the standalone agent.

## Self-protection

The daemon is root with eBPF, and an attacker who quiets it wins. So:

- Config and binary are hashed at `enable` time and checked at every start.
  Mismatch is CRITICAL before anything else runs.
- The config file is watched. A change is parsed and validated; if valid it's
  applied and a CRITICAL says what changed; if invalid the old config stays
  and a CRITICAL says so. `systemctl reload` does the same on demand.
- The systemd unit runs with `ProtectSystem=strict`, `NoNewPrivileges`,
  `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`,
  `ProtectKernel*`, and only these capabilities: `CAP_SYS_ADMIN CAP_BPF
  CAP_PERFMON CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
  CAP_AUDIT_CONTROL CAP_AUDIT_READ`, plus `CAP_NET_ADMIN` only when isolation
  is configured. `PrivateTmp` is off on purpose (it hid /tmp from the setuid
  sweeper) and `MemoryDenyWriteExecute` is off because the perf ring buffer
  needs a writable shared mapping.
- State, logs and config are root-owned, mode 0600/0700, written atomically.
- `hermian status` reports inotify watch health. Zero watches with D3 enabled
  shows as DEGRADED, because it happened on the first test host (another
  process had exhausted the kernel's watch limit) and status said everything
  was fine.
- Updates come only through signed releases. Nothing auto-updates.
- `hermian uninstall` removes the unit, state, logs, sysctl file, PAM hook and
  binary, and lifts isolation first if it's on.

Not done: watching the unit file, the state directory and the stored hashes
themselves; a process that kills the daemon is only visible as a systemd
restart.

## Notifications

`journald` and `/var/log/hermian/alerts.log` get every alert. The channels
below get alerts at or above `min_severity` (HIGH by default):

| Channel | Transport | Notes |
|---|---|---|
| telegram | Bot API, HTML | sound only for CRITICAL by default; token redacted from errors |
| email | SMTP with STARTTLS, TLS or none; or the host's sendmail | text plus HTML multipart, filter-friendly subject |
| webhook | HTTPS POST | generic JSON, Slack, Discord or ntfy payloads |
| stdout | | for running in the foreground |

Delivery is queued (500 alerts max), retried with backoff from 5 s to 2 min,
and tracked per channel so a Telegram failure never re-sends the email. After
15 minutes of failure a CRITICAL is logged locally. `status` shows the queue
depth, the last error and deliveries per channel. `hermian notify-test`
probes each configured channel and sends one test alert.

## Response

Passive by default. The daemon logs and notifies; it does not kill, block,
or quarantine anything on its own.

`hermian isolate` installs an nftables table that drops everything except
loopback, established flows, DNS, and the CIDRs in
`response.management_cidrs`. `hermian unisolate` removes it. With
`response.auto_isolate = true` (which the config validator refuses unless
management CIDRs are set) a CRITICAL triggers isolation automatically.

The failure mode is locking an operator out of production. So isolation
requires two deliberate config choices, always leaves the management network
reachable, and is undone by uninstall.

## Installation and packaging

```bash
# verify: every release is signed with Sigstore, keyless, bound to this repo's workflow
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp '^https://github.com/hermian-security/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

sudo apt install ./hermian_0.1.0-1_amd64.deb     # runs `hermian enable` for you
sudo hermian status
```

`curl | sudo sh` is not offered and won't be. Piping an unverified script to
root is the sort of thing HERMIAN exists to catch.

Shipped today: `.deb` for amd64 and arm64, a tarball with `install.sh` for
other systemd distros, checksums, Sigstore bundles. Built on Ubuntu 22.04 so
the glibc requirement is 2.34. `.rpm` and an AUR package come after a
Fedora and Arch burn-in. There's no GPG key; if a distro repository needs
one later it will be generated offline and published alongside.

`hermian enable` writes the unit with the real binary path, creates the state
directories, records the integrity hashes, starts the baseline clock, raises
`fs.inotify.max_user_watches` if it's low, and starts the daemon. It's
idempotent and is how upgrades work too.

---

## Where we are

**Done** (v0.1.0-beta): everything in this document not marked otherwise.
Tested on one host. Details and the bugs it surfaced are in
`docs/ROADMAP-BURN-IN.md`.

**Next**, in order:

1. Make the release workflow produce a verified artifact on a tag.
2. Burn in on Debian 12, Fedora with SELinux, kernel 5.4, arm64, a web host
   under load, a workstation, an Ansible-managed host, a CI runner. 72 hours
   each. Fix what breaks. Publish the false-positive log.
3. `hermian dismiss <ref> [--allow]` and `hermian stats`, so suppression is a
   command and false-positive rates are a number.
4. Baseline learning for `(parent, /tmp path)` pairs, so the one HIGH the
   unattended workload produced becomes a learned fact rather than a rule
   demotion.
5. Log rotation and alert pruning.
6. A file-write eBPF hook, so session attribution stops guessing.

**Later**: `.rpm`, AUR, an optional hosted relay for people who don't want to
run a bot or an SMTP account (alerts only, never events; the agent must keep
working without it), a read-only fleet page on top of that, cross-host
correlation. Windows and macOS after all of it.

## Targets

| | Target | First host |
|---|---|---|
| CPU average | < 1% | 0.1% |
| CPU p99 | < 5% | 0.13% |
| RSS | < 80 MB | 19 MB |
| event to notification, HIGH+ | < 5 s | ~2 s |
| false HIGH+ | < 1 per host per month | 0 in 26 operations plus soak |
| simulated attacks caught | > 95% | 13/13 |
| crashes | 0 | 0 |

Benchmarks run 72 hours on a 2 vCPU idle server, a 2 vCPU web server at 100
req/s, a 4 vCPU CI host and a 4 vCPU workstation, sampled every 30 s. Event
volume is not a target; it's a number we watch so we notice when it changes.

## How we work

Build the smallest thing that's useful. Add a technology only when a
measurement says the simple version fails. Every rule ships with a simulated
attack that trips it and a normal-work suite that doesn't. Ten rules that
stay quiet beat five hundred nobody reads. Normal administration is not an
attack, and the test suite says so in code. Any active response has to be
safe when it fires by mistake, or it stays advisory. The terminal is the
product; the first thing a user should see is `hermian status` saying
PROTECTED and nothing else.

## Known hard problems

Written down so nobody, including us, mistakes the current coverage for
completeness.

**Living off the land.** An attacker using python, curl, openssl or bash
leaves no odd process name. We catch it when the parent is wrong (nginx ->
bash) or the location is (exec from /tmp). We don't catch a cron job that
runs a legitimate-looking python script that does bad things. That needs
argument inspection and per-host behavioural baselines.

**Injection without exec.** `ptrace` writes, `/proc/pid/mem`, shared-library
injection: no new process, no exec event. We see the ptrace attach. We don't
see what it did.

**Attribution.** Layer 3 of session attribution is a guess. A long-lived tmux
session on a server makes unattended writes look attended. The fix is a
kernel-side file-write hook with the writer's pid; it's on the list.

**The daemon itself.** A root process that kills HERMIAN is only visible as a
restart. An attacker who edits the stored hash file and the binary together
defeats the integrity check. Both need the hashes to live somewhere the
daemon's own privileges can't reach, or a second observer.

**Containers.** Ancestry through containerd shims, overlayfs paths that don't
exist on the host, network namespaces where the connect comes from a
different netns than the process. We tag and exempt; we don't yet reason
about it.

**Across hosts.** Lateral movement doesn't produce a suspicious chain on the
source host. Seeing it needs alerts from several hosts in one place, which is
the hosted relay's job, later.
