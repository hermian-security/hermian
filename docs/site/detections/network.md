---
title: D5 · Network
description: Hermian's network rules - outbound connections from flagged chains, web servers reaching new destinations, programs connecting for the first time, and new listening ports.
---

# D5 · Network

D5 never judges a connection alone. It asks who made it and what that
process's chain has done before: a connection is ordinary, a connection from
a web shell is command and control.

Connections come from an eBPF hook on `connect()`, so they're attempts, not
confirmed sessions. Destinations in the
[destination allowlist](configuration#allowlist) are never reported.

### Outbound connection from a flagged process chain

`HIGH`

**Fires when** a process in a chain that [D1](detections/process-chains) flagged
in the last ten minutes connects anywhere, DNS included.

**Why** A suspicious chain reaching out is the command-and-control or
exfiltration step. One flagged program calling many addresses is one
incident: the first connection pages, and the summary lists the other
destinations ([Noise control](noise)).

**Do** Correlate with the D1 alert; block the destination if it's unknown;
investigate the chain end to end.

### Web server connected to a new external destination

`HIGH`

**Fires when** after the [learning period](baseline), a process under a web
server connects to a public address in a network (/24, or /64) never seen
before.

**Why** Web servers talk to a stable set of backends and APIs. A new
destination can be a web shell calling home or a payload fetching its next
stage.

**Tune** A new legitimate dependency:

```toml
[[allowlist.destinations]]
destination = "203.0.113.10/32"
reason      = "Payment provider API"
```

### First outbound connection from a program

`LOW` to a public address · `INFO` to a private one

**Fires when** after learning, a program (by executable and user) makes its
first connection ever.

**Why** A new network-using program is worth a glance, not proof of
anything. DNS, NTP and DHCP to the LAN or known servers don't count.

### New listener opened by a suspicious process

`HIGH`

**Fires when** a new listening port is opened by a process in a flagged chain
or running from a temporary directory.

**Why** That's how bind shells and reverse proxies for attacker access
appear.

### New listener opened by a shell or interpreter

`LOW`

A shell, or an interpreter listening on all addresses on a high port.

### New listening port

`INFO`

Any other new listener, logged so an investigation has the timeline. Listeners
are read from `/proc/net/tcp` every five seconds.

## Limits

The hook sees `connect()` from 64-bit programs. It doesn't see 32-bit
syscalls on x86_64 (Hermian reports 32-bit programs separately), io_uring
connects, unconnected UDP sends or TCP Fast Open.
