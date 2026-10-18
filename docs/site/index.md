---
title: Introduction
description: What Hermian is, what it watches on a Linux server, how it decides what's worth an alert, and where to start.
---

# Hermian documentation

Hermian is a small intrusion detection daemon for Linux servers. It watches
process chains, SSH logins, persistence, privilege escalation and network
activity in context, and stays quiet until something looks like a real
compromise. Then it tells you, with the evidence, the risk and what to do
next.

It runs on the host it protects. There's no agent manager, no account and no
server to run: the daemon, its rules and its alert store all live on the
machine, and alerts go to the channels you choose.

> [!NOTE]
> Hermian is in beta. Ubuntu 22.04 hosts have passed the full attack suite
> and Ubuntu 24.04 has run live; other distros and longer runs are still
> being verified. See
> [Evidence](evidence) for what's proven and what isn't yet.

## Start here

| If you want to… | Read |
|---|---|
| Install it and get your first alert on your phone | [Install](install), then [First ten minutes](quickstart) |
| Understand how it decides what to report | [How it works](how-it-works) |
| Look up an alert you received | [Detections](detections) |
| Change a setting | [Configuration](configuration) |
| Find a command or a flag | [Command line](cli) |
| Fix something that doesn't work | [Troubleshooting](troubleshooting) |

## What it watches

| Rule | Catches |
|---|---|
| [D1 · Process chains](detections/process-chains) | Web servers and databases starting shells, downloads or relays; download-and-run chains; programs run from /tmp, /dev/shm or deleted files; fileless execution. |
| [D2 · SSH and accounts](detections/ssh-and-accounts) | Logins from new sources, root logins, a login right after failures, brute force, backdoor key files, sshd config and account changes. |
| [D3 · Persistence](detections/persistence) | Cron and at jobs, shell profiles, systemd units, SSH keys, `ld.so.preload`, loader paths, PAM, global environment, rc.local, udev rules, boot modules. |
| [D4 · Privilege escalation](detections/privilege-escalation) | setuid files and file capabilities, sudoers and shadow edits, `LD_PRELOAD` injection, ptrace. |
| [D5 · Network](detections/network) | Connections from chains already flagged, web servers reaching new destinations, first connections, new listeners. |
| [Self-protection](detections/self) | Hermian's own binary or config changed, the daemon stopped or frozen, dropped events, code injected into it, an intrusion that was there before it started. |

## How it's different

- **Context, not counters.** Every rule asks who started a program, from
  where, and whether someone was logged in to do it. The same `bash` is
  nothing in an SSH session and a HIGH under a web server.
- **Deterministic.** Rules are code you can read, with fixed severities. No
  risk score, no model, no cloud lookup.
- **One incident, one page.** Repeats fold into a summary; an incident that
  keeps going pages less and less often.
- **It checks itself.** A start-up audit looks for an intrusion that was there
  before Hermian, and the daemon checks its own memory for injected code.
- **Nothing leaves the host** unless you add a channel, and a minimal mode
  keeps details out of cloud chat services.

## Who it's for

A VPS, a homelab, or a handful of servers you look after yourself, when you
want alerts in chat or your logs rather than another dashboard. It watches the
host, not what runs inside containers, and it isn't a fleet console. The
[limits page](limits) lists what it doesn't do.
