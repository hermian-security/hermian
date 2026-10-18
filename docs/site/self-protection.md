---
title: Self-protection and audit
description: How Hermian protects itself - the hardened service, integrity checks, the watchdog, the preload-rootkit shield, the self-check of its own memory, and the start-up audit for intrusions that predate it.
---

# Self-protection and audit

A security tool is a target. Hermian assumes someone may try to blind it,
stop it or lie to it, and reports on itself like on anything else. The
alerts it can send about itself are listed in
[Detections › Self-protection](detections/self).

## The service

The systemd unit runs the daemon with the least it needs:

- `ProtectSystem=strict`: the whole filesystem is read-only to it except its
  own directories (`/etc/hermian`, `/var/lib/hermian`, `/var/log/hermian`,
  `/run/hermian`).
- `NoNewPrivileges`, `ProtectHome=read-only`, `ProtectKernelTunables`,
  `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
  `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictSUIDSGID`,
  `LockPersonality`, `SystemCallArchitectures=native`.
- `RestrictAddressFamilies` to Unix, netlink, IPv4 and IPv6.
- Only the capabilities its collectors need. `CAP_NET_ADMIN` and `CAP_KILL`
  are added only when buttons or isolation are configured.
- `Restart=always` with no start limit: it comes back after any exit you
  didn't ask for.

Two options are deliberately **off**, with the reason written in the unit:
`PrivateTmp` (it would hide the host's `/tmp`, exactly where payloads are
staged) and `MemoryDenyWriteExecute` (it breaks the eBPF ring buffer).

## Integrity

At `hermian enable`, the hashes of the binary and the config are recorded.

| Event | Alert |
|---|---|
| The binary no longer matches its record (checked at every start; `enable` re-records it after an upgrade) | CRITICAL "Hermian binary modified" |
| The config changes while stopped | CRITICAL on the next start |
| A valid config change with an effect (detections, channels, allowlist) | CRITICAL, after reloading it |
| A config change with no functional effect (a comment) | INFO |
| An invalid config | LOW; the last good config stays in force |
| The hash records are missing | HIGH |

Paging on its own config changes is the point: an attacker who silences a rule
or adds an allowlist entry tells you so.

## The dead-man switch

- **Stopping** Hermian pages HIGH ("Hermian is stopping") before it goes
  quiet, except a restart for an install or upgrade, which is INFO.
- A **watchdog** timer checks the daemon's heartbeat every minute. A frozen
  daemon pages HIGH ("not responding") and gets restarted; a dead one pages
  CRITICAL.
- After a crash or a kill, the next start pages HIGH ("restarted after an
  unclean shutdown").
- **Dropped events** (the kernel ring buffer overflowed) page HIGH, and CPUs
  that come online without an event reader are reported.

The watchdog runs on the same host: it isn't an outside monitor. A killed
daemon is reported when it next starts. See [Limits](limits).

## Rootkit shield

A preload rootkit lists a library in `/etc/ld.so.preload`. From then on, the
loader injects it into every dynamically linked program, where it hooks libc
to hide its files and processes. That includes `ps`, `ls`, `cat` and, unless
something stops it, Hermian and the tools Hermian runs.

Hermian keeps it out:

- **The unit bind-mounts `/dev/null` over `/etc/ld.so.preload`** in the
  service's own mount namespace. The loader finds an empty list, so nothing is
  preloaded into the daemon or into the `journalctl`, `nft` and `systemctl`
  it starts, whatever the host's copy says now or later. It's a bind mount,
  not `InaccessiblePaths=-`, because a rootkit already loaded into systemd
  hides its own file from it: verified on a perfctl-infected host.
- Hermian still **judges the host's copy**, read through `/proc/1/root`, so
  writes to it still page CRITICAL.
- The tools it runs are started **by absolute path with a cleared
  environment**, so an `LD_PRELOAD` or a planted `nft` earlier in `PATH` never
  reaches them.
- The daemon is **not dumpable**: no core dumps, and other users can't read
  its memory through `/proc`.

Where the file doesn't exist, systemd creates an empty one to mount over. An
empty preload file loads nothing, raises no alert, and `hermian uninstall`
removes it while it's still empty.

## Self-check

At start and every ten minutes, the daemon reads its own `/proc/self/maps`.
Code loaded from a temporary or hidden location, code no package owns, or a
library listed in `/etc/ld.so.preload` pages **CRITICAL "Hermian itself is
hooked"**: its alerts can't be trusted from that point. The package database is
only asked again when the mappings change, so the check costs next to nothing.

A ptrace attach to the daemon is CRITICAL whoever does it, debuggers
included.

## The start-up audit

Hermian's rules judge what happens after it starts. An implant already
running, persistence already in place, or a rootkit already loaded would stay
unseen until they act, and the baseline would learn them as normal. So every
start begins with an audit. `sudo hermian audit` runs the same checks on
demand.

| Check | Severity of a finding |
|---|---|
| `/etc/ld.so.preload` entries | HIGH; CRITICAL when no package owns the library or it sits in a temporary or hidden directory |
| Programs running from `/tmp`, `/dev/shm`, `/var/tmp` or a hidden directory under `/usr`, `/var`, `/etc`, `/lib`, `/dev`… | HIGH |
| Libraries loaded from a hidden system directory | HIGH |
| Libraries unpacked into `/tmp` (Nx, Netty, JNA, sqlite-jdbc do this) | LOW: listed, never paged |
| Programs and libraries in `/usr/bin`, `/usr/lib` and the like that no package owns | HIGH |
| Crontabs, cron directories and shell profiles that start any of the above | HIGH |

Signs of more than one kind make the alert CRITICAL. One alert lists up to
eight signs ("Signs of an intrusion from before Hermian started"), and
**learning stops at once**: novelty is judged from then on, against nothing
learned on this host.

Package ownership is asked of dpkg in one batched call, aware of merged `/usr`
(`/lib` and `/usr/lib` are the same files), and only for files that still
exist, so a library replaced by an upgrade while a process still maps it isn't
reported. Containers are skipped: their `/usr` isn't the host's.

On a perfctl-infected test host, with the rootkit loaded into the audit
itself, it reported 16 signs in 0.6 seconds: the preload rootkit, a hidden
loader stack under `/var`, a deleted library from `/tmp` loaded into Node.js,
the rootkit loaded into cron, the implant running from `/tmp`, and profiles
starting `perfcc`.

> [!WARNING]
> A rootkit can hide from the audit: on that host it hid the miner's processes
> from the process listing. A clean audit is good news, not a guarantee. A host
> that fails it should be rebuilt, not cleaned in place.

## What none of this stops

Root owns the box. Someone with root can stop the service, unload the eBPF
programs or load a kernel module that blinds them. What Hermian guarantees is
that it **says so** while it can: the stop notice, the watchdog, the integrity
checks and the self-check exist so that blinding Hermian is loud.
