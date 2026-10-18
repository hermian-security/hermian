---
title: FAQ
description: Common questions about Hermian - fail2ban and CrowdSec, Wazuh and Falco, Docker, resources, privacy, licence, root, and what happens if an attacker gets root.
---

# FAQ

### Does it replace fail2ban or CrowdSec?

No, it complements them. fail2ban and CrowdSec block brute force at the door.
Hermian watches what happens after a login: the key that was used, what the
session ran, the persistence it left. It does report brute force, but as one
digest of attempts against real accounts, and the alert that matters is the
**login that follows a burst**. Running both is a good setup.

### How is it different from Wazuh, Falco or auditd?

| | Hermian | Wazuh | Falco | auditd |
|---|---|---|---|---|
| Runs | One daemon on the host | Agent + manager + indexer | Daemon, rules in YAML | Kernel audit + log |
| Server to run | None | Yes | No (outputs to a sink) | No |
| Alerts by itself | Telegram, email, webhooks | Through the manager | Through outputs | No, records only |
| Focus | Intrusions on servers you run yourself, in context | Broad HIDS, compliance | Syscall rules, containers first | Recording |

Wazuh covers more ground; Falco is stronger on containers. Hermian is the
small, opinionated one: few alerts, each with the context to act on it.

### Does it work with Docker?

It watches the host: processes, files and network as the host sees them.
Processes running in containers are seen like any process, without container
context (images, pods, namespaces), and files inside container overlays are
ignored. It runs fine on a Docker host, but it's not a container security
tool.

### How much CPU and memory does it use?

Around 0.1% of a CPU and 15 to 25 MB of memory on the hosts measured so far.
On the reference host it processed 925,648 events in 11 h 44 min at 0.06% of
one core and 23 MB. See [Evidence](evidence).

### Does anything leave my server?

Only alerts, only to channels you add, and with `content = "minimal"` only the
severity, rule family, reference and host. No telemetry, no statistics, no
update checks. [Details](files#what-leaves-the-host).

### Why does it need root?

To load eBPF programs, read every process's details, watch system files and,
if you turn them on, change the firewall and end sessions. The systemd unit
restricts it as much as those needs allow
([details](self-protection#the-service)).

### What if an attacker already has root?

Root can stop Hermian, unload its hooks or blind it with a kernel module.
What Hermian guarantees is that this is loud: a stop pages, a frozen daemon
pages through the watchdog, a changed binary or config pages at the next
start, and code injected into it pages CRITICAL. It also checks, at every
start, for signs of an intrusion that was there before it. It doesn't stop
someone who already owns the box.

### Can it block attacks automatically?

It can isolate the host on CRITICAL alerts (`auto_isolate`, off by default),
and Telegram buttons block a source or end a session in two presses. It
doesn't kill processes or delete files on its own: a wrong automatic response
on a production server can do more harm than the alert.

### Why so few alerts?

That's the design. Rules judge context (who started what, from where, with
someone logged in or not) instead of matching single events, operators' own
changes are INFO, and repeats fold. On the reference host: 925,648 events in
almost 12 hours, three notifications.

### Is it free? Can someone sell it?

It's open source under Apache-2.0: free to use, modify and redistribute,
commercially included, with the licence and notices kept.

### Which distros are supported?

Any Linux with systemd and kernel 5.4+, amd64 or arm64. Ubuntu 22.04 has
passed the full suites and Ubuntu 24.04 has run live on a compromised host;
Debian, the RHEL family and arm64 hardware are being verified
([Evidence](evidence)). Reports from other systems are
welcome.

### How do I report a false positive?

Open an issue with `hermian show <ref> --json`, after removing secrets and
private details. Fixing the rule helps everyone; an allowlist entry only helps
you.

### Who makes it?

Hermian Security. Parts of the code, tests and docs are written with AI
assistance; merges and releases are always done by a human. The working rules
are in [AGENTS.md](https://github.com/hermian-security/hermian/blob/main/AGENTS.md).
