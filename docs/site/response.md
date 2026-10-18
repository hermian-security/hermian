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
| **Undo: unblock** | Appears after a block, for as long as the block lasts (up to a day). Lifts it. |

### What you're told

Every press gets an answer in under a second ("Block 203.0.113.24 on web-01:
working on it."), then one result message replying to the alert, naming the
host, with one line per address:

```text
web-01 · Disconnect and block, by @op (id 42)
done: Blocked 203.0.113.24 until 14:02 UTC tomorrow (24h).
done: Disconnected root from 203.0.113.24 (1 connection(s) ended).
note: The block covers 203.0.113.24 only: the key or password they used still works from another address.
```

| Mark | Meaning |
|---|---|
| `done` | The change was made. |
| `already` | It was already that way, and since when and by whom ("was blocked at 14:02 UTC by @op"). Nothing changed; a second Block doesn't extend the first. |
| `refused` | A safety rule stopped it, named ("inside your management network 10.0.0.0/8 (response.management_cidrs)"). |
| `failed` | The cause in a sentence and the next step as a command ("blocking needs nftables, and nft isn't installed. Install it: sudo apt install nftables"). |

The used button then turns into a label with the outcome ("Block
203.0.113.24: done · @op 14:02 UTC"); pressing it shows the full result.
Pressing a button again, or one another admin's choice retired, says who did
what and when instead of acting twice. A button pressed after
`action_ttl_mins` says so and gives the command that does the same thing
(`sudo hermian block 203.0.113.24`), and a message whose buttons all expired
shows "Buttons expired".

Buttons are saved in the state directory, so they still work after a restart.
If a result can't be posted (Telegram down), it's retried, then sent with the
next message that gets through. It's in the journal and `hermian alerts`
either way.

### Safeguards

- A press is accepted only from the **configured chat** and from a user in
  `allowed_user_ids`. Anyone else gets "not allowed", and the attempt is
  logged HIGH.
- **Block and Disconnect ask first**: the buttons turn into "Confirm: …" and
  "Cancel". Confirm expires after two minutes; Cancel puts the alert's buttons
  back.
- Every button has a random 96-bit id, **works once**, and expires after
  `action_ttl_mins`. One choice on an alert retires its other buttons, and
  pressing a retired one says who chose what.
- Management CIDRs, allowlisted SSH sources and local addresses are **never
  blocked**, whatever is pressed.
- Hermian polls Telegram for presses (outbound only): it still listens on no
  port, and it works during isolation.
- Every press and its result are answered in the chat, logged, and stored.

Every button has a twin on the command line, for when the button has
expired or you're already on the host: `sudo hermian block <ip>...`,
`sudo hermian unblock <ip>`, `sudo hermian disconnect <ip>`.
`sudo hermian blocked` lists current blocks with their time left.

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
