---
title: Limits and threat model
description: What Hermian is built to catch, what it can't see, and the assumptions behind its design - stated plainly.
---

# Limits and threat model

A security tool is only as useful as its limits are clear. This page says
what Hermian is for and where it stops.

## What it's built for

An attacker who gets code running on a Linux server you run yourself, through
a vulnerable web application, a stolen or planted SSH key, or brute force,
and then tries to:

- run tools, download payloads and open a shell back home;
- stay: cron, systemd, profiles, SSH keys, a preload rootkit;
- become root: setuid helpers, sudoers, shadow, injection;
- keep quiet: hidden key files, fileless execution, blinding the monitor.

Hermian should catch those steps, in context, with few false positives, and
tell you on a channel you'll see.

## What it doesn't see

- **Inside containers.** It watches the host, not pods.
- **Injection without a new program.** Code run inside an existing process
  (an interpreter's `eval`, shellcode, writes to `/proc/<pid>/mem`) isn't a
  process chain. `LD_PRELOAD` and ptrace are covered.
- **Some network paths.** 32-bit syscalls on x86_64 (reported separately),
  io_uring connects, unconnected UDP sends, TCP Fast Open.
- **Short-lived processes without eBPF.** On kernels older than 5.8 or without
  BTF, execution is polled from `/proc` every second.
- **What happened before it started**, except what the
  [start-up audit](self-protection#the-start-up-audit) can find, and a rootkit
  can hide from that audit.
- **What a ptrace attach did.** The alert says who attached, not what changed.

## Assumptions

- **The kernel is trustworthy.** A kernel rootkit loaded before or after
  Hermian can hide events from eBPF. Hermian reports module loads into boot
  config and its own blinding where it can, but can't guarantee it.
- **Root owns the box.** Local hashes and the watchdog make tampering loud;
  they don't stop someone who already has root. A killed daemon is reported
  when it next starts.
- **The dead-man switch is local.** The watchdog runs on the same host. It
  isn't an out-of-band monitor.
- **Delivery is at least once.** Alerts queue on disk per channel (500 each);
  a crash mid-send can send one twice.
- **Isolation isn't a full cutoff.** Alert endpoints stay reachable for
  anything on the host, by design, so Hermian can still tell you.
- **Attribution can be wrong.** When inotify can't name a writer, recent
  interactive activity is taken as the operator's. That can downgrade an
  unrelated write made while someone is typing to INFO.
- **A quiet host isn't proof it's clean.** It means nothing matched.

## Maturity

Hermian is in beta. Ubuntu 22.04 hosts have passed the full attack and
false-positive suites; other distributions, the RHEL family with SELinux, the
older-kernel fallback and arm64 hardware haven't been verified in the field
yet. What's proven, where and when, is in [Evidence](evidence), along with
what has to happen before a stable release.
