---
title: How it works
description: Hermian's architecture, its kernel and file collectors, the process tree, operator attribution, deterministic rules, severities and alert delivery.
---

# How it works

Hermian watches one Linux host and turns what happens on it into a short list
of alerts worth reading. Everything runs on that host.

```flow
Collectors | eBPF exec, connect and ptrace hooks · inotify on persistence and account files · sshd's journal · PAM (optional) · /proc polling
Engine | process tree · session attribution · baseline · five rule families · allowlist
Findings | rule, severity, evidence, process chain, risk, next steps
Deduplication | one incident, one page; repeats folded into a summary
Alerts | JSON store · journald · alerts.log · Telegram, email, webhooks
```

The code is split along that line:

| Crate | Role |
|---|---|
| `hermian-core` | The engine: rules, process tree, baseline, config, rendering. No I/O at all, so every rule is unit-tested on synthetic events, on Linux, macOS and Windows. |
| `hermian` | The Linux daemon and CLI: collectors, storage, delivery, response. |
| `hermian-ebpf` | The kernel programs. A prebuilt object ships with the source and CI rebuilds it byte for byte from the pinned toolchain. |
| `hermian-pam` | An optional, passive PAM module. |

Nothing listens on the network. Channels send alerts, never raw telemetry,
and Telegram button presses are fetched by outbound polling.

## Collectors

| Source | What it gives | Notes |
|---|---|---|
| eBPF `sched_process_exec` | Every program start: pid, parent, uid, executable, `argv[0]`, TTY, container flag, `LD_PRELOAD`/`LD_AUDIT` in the environment | Parent pids from kernel BTF offsets, with a `/proc` fallback. The first 64 environment entries are checked. |
| eBPF syscall entry (`connect`, `ptrace`) | Outbound connection attempts and ptrace attaches | Attempts, not confirmed success. Not seen: 32-bit syscalls on x86_64, io_uring connects, unconnected UDP sends, TCP Fast Open. |
| inotify | Changes to persistence, SSH, account and loader files | 400 ms debounce, 2.5 s at most. The writer is found from open file descriptors when possible. |
| sshd's journal (or `auth.log` / `secure`) | Logins, failures, the key used and where it's stored | sshd's own entries only, so a local program can't forge one. |
| `/proc/net/tcp` | New listening ports | Every 5 seconds. |
| setuid sweep | New setuid/setgid files and file capabilities | Every 20 seconds, four levels deep under user-writable trees. |
| PAM module | Login results | Optional (`hermian enable --with-pam`); never sees passwords, always returns `PAM_IGNORE`. |

eBPF needs kernel 5.8 or newer with BTF. Without it, execution falls back to
polling `/proc` every second, and to the audit subsystem when available (an
existing `auditd` is left alone). Short-lived processes can be missed then,
and `hermian status` says so. A 32-bit program on x86_64 is reported LOW,
since its syscalls bypass the hooks.

## The process tree

Every exec lands in a process tree that keeps each process's executable, user,
parent and start time, seeded from `/proc` at start. Rules never judge a
program alone: they judge its chain.

Each process gets a **role** from its executable, not just its name: web
server (nginx, apache2, caddy, gunicorn, php-fpm…), database (mysqld,
postgres, redis-server, mongod…), shell, downloader (curl, wget…), interpreter,
package manager, config manager (ansible, puppet, cloud-init…), debugger,
session daemon (sshd, sudo, tmux…), cron. A role that excuses something
(package manager, user tool, debugger) only counts when the file and every
directory above it are owned by root and writable by nobody else: a binary
merely named `dpkg` in `/tmp` doesn't count.

Wrappers like `env`, `setsid`, `nohup`, `timeout` and `xargs` are seen
through, so `nginx → env → sh` is still a web server starting a shell.

## Who did it: operator or not

The same action means different things depending on who did it. Editing
`authorized_keys` from your SSH session is routine; the same write from a
process nobody started is a backdoor. So every file change and many execs are
**attributed**:

1. **Interactive**: the writer descends from a session (an SSH login, a
   terminal, sudo, tmux).
2. **Unattended**: the writer is known and doesn't.
3. When inotify can't name the writer, Hermian looks for a recent admin tool
   started from a session or by a package manager, then for activity in an
   interactive session in the last 15 seconds or an editor open in one.

Interactive changes are logged as INFO for context; unattended ones page. The
fallback in step 3 is a guess, and it can downgrade an unrelated write made
while someone is typing: that's a documented trade-off, not a secret.

Package managers and config managers excuse clean changes (a unit file a
package installs, a crontab Ansible writes), but **content is checked before
any excuse**: the real `crontab` installing a `curl … | sh` job is still
CRITICAL.

## Rules

Five rule families, each a file of plain Rust you can read:

- [D1 · Process chains](detections/process-chains) (`d1.rs`)
- [D2 · SSH and accounts](detections/ssh-and-accounts) (`d2.rs`, `brute.rs`)
- [D3 · Persistence](detections/persistence) (`d3.rs`)
- [D4 · Privilege escalation](detections/privilege-escalation) (`d4.rs`)
- [D5 · Network](detections/network) (`d5.rs`)

Rules are deterministic. They look at roles, ancestry, paths, file content,
who's logged in and recent findings, not at a score. Given the same events,
Hermian always says the same thing, which is what makes its alerts testable:
each rule has unit tests, and the attack suite replays real techniques on
disposable hosts.

Findings link up: a D1 HIGH or CRITICAL **flags** the chain for ten minutes,
and later events in a flagged chain escalate. A program run from `/tmp` is
HIGH; the same run inside a flagged chain is CRITICAL, and any outbound
connection from it is reported too.

## Severities

| Severity | Meaning | Notified by default |
|---|---|---|
| `INFO` | Context: an operator's own change, a routine repeat | Never. Hidden from `hermian alerts` unless `--all` |
| `LOW` | Worth a look | No (`min_severity` is HIGH) |
| `HIGH` | Investigate | Yes |
| `CRITICAL` | Urgent | Yes, with sound on Telegram; can trigger automatic isolation |

Every rule's severities are listed in its page under Detections.

## An alert

```text
◉◉◉◉  CRITICAL · Process chain
Web server chain downloaded and executed remote content

  nginx spawned a shell, the shell ran curl to fetch content, and that
  content is now executing as payload (pid 4113).

  host   web-01
  chain  nginx › sh › curl › payload
  rule   D1 · Suspicious process chain

hermian show HER-2026-1006-415
```

Each alert carries:

| Field | What it is |
|---|---|
| Reference | `HER-<date>-<sequence>`, unique on the host; `hermian show 415` finds today's |
| Severity and rule | One of the four severities and the rule family (D1 to D5, SELF) |
| What happened | One or two sentences, in plain words |
| Chain | The process ancestry, with users and pids |
| Facts | The evidence: paths, commands, sources, keys, destinations |
| Risk | Why this matters |
| Next steps | What to check or do, in order |

Alerts are stored as JSON under `/var/lib/hermian/alerts/` and kept for
`general.alert_retention_days` (90 by default). Text that comes from the
system (process names, paths, file content) is escaped before it's stored, so
an attacker can't put terminal escape codes or fake log lines in an alert.

## Delivery

journald and `alerts.log` always get every alert. Telegram, email, webhooks
and stdout get alerts at `min_severity` and above. Each channel has its own
queue on disk (500 alerts each) that survives restarts, so delivery is
at least once: a crash mid-send can send one twice, never zero. Failed sends
retry with backoff, and `hermian status` shows pending and dropped counts.

## What it doesn't see

It sees what it hooks. Code injected into a running process without starting
a new program, activity inside containers, and anything an attacker with root
does after blinding the kernel hooks are out of reach. See
[Limits](limits) for the full list.
