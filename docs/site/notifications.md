---
title: Notifications
description: Where Hermian's alerts go - journald, the alert log, Telegram, email, Slack, Discord, ntfy, Matrix and webhooks - with severity filters, minimal content and delivery guarantees.
---

# Notifications

Hermian sends nothing anywhere until you add a channel. Every alert is
always written locally; the channels you add get the ones that matter.

## Channels

| Channel | Gets | Set up |
|---|---|---|
| `journald` | Every alert (`journalctl -t hermian`) | On by default |
| `file` | Every alert, in `/var/log/hermian/alerts.log` (rotated at 50 MB) | On by default |
| `telegram` | Alerts at `min_severity` and up, with optional buttons | [Telegram](notifications/telegram) |
| `email` | Same, over SMTP or the host's sendmail | [Email](notifications/email) |
| `webhook` | Same, as Slack, Discord, ntfy, Matrix or plain JSON | [Webhooks](notifications/webhooks) |
| `stdout` | Same, printed by the daemon (for containers and debugging) | Add `"stdout"` |

```toml
[notifications]
channels = ["journald", "file", "telegram"]
min_severity = "HIGH"      # INFO | LOW | HIGH | CRITICAL
```

`min_severity` applies to every channel except `journald` and `file`. INFO is
never notified, whatever it's set to.

After any change, check with:

```bash
sudo hermian notify-test                 # every configured channel
sudo hermian notify-test -c telegram     # one channel
sudo hermian notify-test --probe-only    # check credentials, send nothing
```

## Keeping alerts in-house

Telegram, Slack and Discord are cloud services: what you send them leaves
your organisation. Two ways to avoid that:

**Use a channel you host.** Your own [ntfy](https://ntfy.sh) server, a
Matrix homeserver, your mail server, or a webhook into your SIEM. Then nothing
leaves your organisation.

**Send minimal content.** With

```toml
[notifications]
content = "minimal"
```

Telegram, email and webhooks receive only:

```text
HIGH alert 025 on web-01. The details stay on the host.
sudo hermian show 025
```

No addresses, users, paths, commands, process names or file content. The
title becomes the rule family ("SSH alert"), and no buttons are sent, since
they'd need that context. journald and the alert log keep everything.

## What a message contains

With `content = "full"` (the default), each message carries the severity
meter, the title, what happened, the host, the process chain, the rule, the
time and the reference to `hermian show`, with the risk and next steps in a
collapsed section on Telegram and in full by email.

## Delivery

- Each channel runs on its own queue, so a broken one doesn't hold up the
  others.
- Pending alerts are stored on disk per channel (up to 500 each) and survive a
  restart.
- Failed sends retry with backoff. Errors that won't fix themselves (an
  invalid address, a rejected token) aren't retried forever.
- Delivery is **at least once**: a crash in the middle of a send can send an
  alert twice, never lose it silently.
- `hermian status` shows each channel's last delivery, pending count and
  errors.

A change to the channels is itself a CRITICAL alert, sent through the new
channels: alerts can't be redirected quietly.
