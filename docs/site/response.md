---
title: Response
description: Act on alerts - Telegram buttons to block a source or end an SSH session, network isolation by hand or automatically on CRITICAL, management networks and their safeguards.
---

# Response

By default Hermian only logs and notifies. Responses are opt-in, each with
its own safeguards, and every response is itself recorded and reported.

## Management networks first

```toml
[response]
management_cidrs = ["203.0.113.0/24", "198.51.100.7/32"]
```

The addresses you manage the host from: home, office, VPN, bastion. They're
**never blocked** by a button and **stay reachable during isolation**. Set
them before turning on buttons or automatic isolation, and test that you can
still get in.

## Telegram buttons

```toml
[notifications.telegram]
actions = true
allowed_user_ids = [123456789]   # numeric Telegram user ids (ask @userinfobot)
action_ttl_mins = 15

[response]
block_duration_hours = 24
```

Then run `sudo hermian enable` once: it grants the daemon the capabilities
these need (`CAP_NET_ADMIN` for the firewall, `CAP_KILL` to end sessions),
which it doesn't have otherwise.

| Alert | Buttons |
|---|---|
| Suspicious SSH login (after a burst, from a new source, root from a new place, hidden key) | Ignore · Disconnect session · Disconnect and block |
| Brute-force digest | Block each top source · Block all · Ignore 2h · a 7-day reminder when root can log in with a password |

### What each one does

| Button | Effect |
|---|---|
| **Block** | Adds the source to an nftables set of Hermian's own (`inet hermian_block`) for `block_duration_hours`. IPv6 sources are blocked as their /64. |
| **Disconnect session** | Stops the sshd processes holding that one connection (source and port), nothing else. |
| **Disconnect and block** | Blocks the source first, then ends the session, so it can't reconnect. |
| **Ignore** | Nothing changes. On a digest, "Ignore 2h" stops reporting those sources for two hours; a successful login from them still alerts. |

### Safeguards

- A press is accepted only from the **configured chat** and from a user in
  `allowed_user_ids`. Anyone else gets "not allowed", and the attempt is
  logged HIGH.
- **Block and Disconnect ask first**: the buttons turn into "Confirm: …" and
  "Cancel". Confirm expires after two minutes; Cancel puts the alert's buttons
  back.
- Every button has a random 96-bit id, **works once**, and expires after
  `action_ttl_mins`. One choice on an alert retires its other buttons.
- Management CIDRs, allowlisted SSH sources and local addresses are **never
  blocked**, whatever is pressed.
- Hermian polls Telegram for presses (outbound only): it still listens on no
  port, and it works during isolation.
- Every press and its result are answered in the chat, logged, and stored.

`sudo hermian blocked` lists current blocks with their time left;
`sudo hermian unblock <ip>` lifts one (for IPv6, any address in the /64).

## Isolation

Isolation cuts the host off the network except what you need to recover it.

```bash
sudo hermian isolate              # until you lift it
sudo hermian isolate --for 30     # lifted after 30 minutes, by a systemd timer
sudo hermian unisolate
```

It installs an nftables ruleset (`inet hermian`) that keeps:

- loopback and your `management_cidrs`;
- DHCP, IPv6 neighbour discovery and DNS;
- the cloud metadata endpoint;
- the alert endpoints (Telegram, the webhook, SMTP), so Hermian can still
  tell you.

Everything else is cut, open connections and routed traffic included.
`--for` uses a systemd timer, so the isolation lifts even if the daemon is gone
or you can't get back in.

### Automatic isolation

```toml
[response]
auto_isolate = true
auto_isolate_revert_mins = 60    # 0 = until you lift it
```

On a CRITICAL alert, Hermian isolates the host. It requires
`management_cidrs`, and it won't fire when the chain rests on a service
identified by name alone: anyone can run a program called `nginx`, and cutting
the host off shouldn't be something an unprivileged user can trigger. That
alert still pages.

> [!WARNING]
> Isolation isn't a full cutoff: alert endpoints stay reachable for anything
> on the host. And automatic isolation can cut your own access if your
> management networks are wrong. Test `hermian isolate --for 5` from your
> management address before turning it on.

## Planned

Response today covers addresses and sessions. Revoking a planted key,
disabling a hidden key file and quarantining a dropped binary, each with an
undo, are on the roadmap.
