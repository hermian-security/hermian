---
title: Learning and novelty
description: How Hermian learns a host's normal SSH sources, destinations and network programs during its first day, how it judges what's new afterwards, and what it refuses to learn.
---

# Learning and novelty

Some things are only suspicious because they're new: a login from an address
nobody has used, a web server calling a server it has never called. Hermian
learns what's normal for the host first, then reports what isn't, once.

## What it learns

| Set | From | Used by |
|---|---|---|
| SSH sources | Every successful SSH login | "SSH login from a new source" |
| Root sources | Successful root logins | "Root login over SSH from a new source" |
| Known keys | `user + key fingerprint` of each key login | Dynamic-IP leniency (below) |
| Destinations | Every outbound connection, grouped by network (/24, or /64 for IPv6) | "Web server connected to a new external destination" |
| Connecting programs | `executable + uid` of each process that connects | "First outbound connection from a program" |

The baseline lives in `/var/lib/hermian/baseline.json`. Each set holds at
most 50,000 entries, so a hostile host can't grow it without limit.

## The learning period

For its first `baseline.duration_hours` (24 by default) Hermian learns and
doesn't judge novelty. After that it judges, **and keeps learning**: a source
is new the first time it's seen, not every time it comes back. Rules that don't
depend on novelty (almost all of them) work from the first second.

Some leniency is built in:

- **Dynamic IPs.** A key that has logged in before, from a new address on a
  network the account already uses (/16, or /32 for IPv6), is INFO, not a
  page. Home and mobile connections change address inside their provider's
  block. A different provider, a password, or an unknown key still pages.
- **Destinations by network.** APIs and CDNs rotate addresses inside a block,
  so destinations are judged by /24 (or /64).
- **Infra ports.** DNS, NTP and DHCP to the LAN or to servers seen while
  learning don't count as new.

## What it refuses to learn

On a host that's already compromised, the malware's routine would become
"normal". So the baseline never learns from:

- connections made by a chain D1 has flagged;
- programs running from `/tmp`, `/dev/shm`, `/var/tmp` or a deleted file;
- logins with a key from a hidden key file (the backdoor key must never become
  a "known key");
- `0.0.0.0`, `::` and loopback.

And the [start-up audit](self-protection#the-start-up-audit) runs before
learning: if it finds signs of an earlier intrusion, learning stops at once
and novelty is judged from then on against nothing learned. You get one
alert saying so.

## Skipping or resetting it

| You want | Do |
|---|---|
| No learning period on a freshly built host | `sudo hermian enable --no-baseline` (judges novelty from the start) |
| Start learning over | Stop Hermian, delete `/var/lib/hermian/baseline.json`, start it: a new period begins |
| No novelty rules at all | `[baseline] enabled = false` |
| A source or destination never reported | An [allowlist](configuration#allowlist) entry, with a reason |
| A longer or shorter period | `[baseline] duration_hours` (1 to 8760) |

`hermian status` shows the time left while learning.
