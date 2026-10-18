---
title: Webhooks
description: Send Hermian alerts to Slack, Discord, ntfy, Matrix or any HTTP endpoint as JSON, with the payload format for SIEMs and scripts.
---

# Webhooks

One webhook channel, five formats. The URL usually carries a secret, so
Hermian never prints it whole: status, logs and errors show only
`scheme://host/…`.

```toml
[notifications]
channels = ["journald", "file", "webhook"]

[notifications.webhook]
url = "https://hooks.slack.com/services/T000/B000/XXXX"
format = "slack"       # generic | slack | discord | ntfy | matrix
token = ""             # sent as "Authorization: Bearer <token>" when set
timeout_secs = 10
```

## Slack

Create an incoming webhook in your Slack app and paste its URL with
`format = "slack"`. Alerts arrive as an attachment coloured by severity, with
the rule, host, chain and facts as fields, and `hermian show <ref>` in the
footer.

## Discord

Channel settings › Integrations › Webhooks › New webhook, copy the URL,
`format = "discord"`. Alerts arrive as an embed with the brand colours, the
detection time as a Discord timestamp, the next steps and the
`hermian show` command.

## ntfy

```toml
[notifications.webhook]
url = "https://ntfy.example.org/servers"    # your server and topic, or ntfy.sh
format = "ntfy"
token = "tk_..."                            # if the topic needs an access token
```

The title is "Hermian HIGH on web-01", the message the compact alert, the
priority follows the severity (CRITICAL 5, HIGH 4, LOW 3, INFO 2), and the
rule and severity become tags. A self-hosted ntfy keeps everything in-house.

## Matrix

```toml
[notifications.webhook]
format = "matrix"
url = "https://matrix.example.org/_matrix/client/v3/rooms/!roomid:example.org/send/m.room.message"
token = "syt_..."      # the bot account's access token
```

1. Create an account for the bot on your homeserver and log in once to get an
   access token.
2. Invite it to the room, and accept the invite as the bot.
3. Take the room's internal id (`!…:example.org`, in the room's advanced
   settings) and build the URL above.

Hermian sends each alert with a `PUT` to that URL plus a transaction id made
from the alert's reference, so a retried delivery posts once. Messages carry a
plain body and an HTML version.

## Generic JSON

`format = "generic"` POSTs the whole alert, for a SIEM, a log pipeline or
your own script:

```json
{
  "source": "hermian",
  "version": "0.1.0",
  "text": "◉◉◉○ HIGH · Process chain\nWeb server spawned a shell\n...",
  "alert": {
    "ref_id": "HER-2026-1017-002",
    "ts": "2026-10-17T19:45:55Z",
    "host": "web-01",
    "severity": "High",
    "detection": "D1",
    "title": "Web server spawned a shell",
    "what": "nginx (pid 2056) spawned the shell sh (pid 2058) running as www-data.",
    "chain": [
      { "pid": 1, "uid": 0, "user": "root", "comm": "systemd", "exe": "/usr/lib/systemd/systemd", "focus": false },
      { "pid": 2056, "uid": 33, "user": "www-data", "comm": "nginx", "exe": "/usr/sbin/nginx", "focus": false },
      { "pid": 2058, "uid": 33, "user": "www-data", "comm": "sh", "exe": "/usr/bin/dash", "focus": true }
    ],
    "chain_pids": [1, 2056, 2058],
    "facts": [{ "label": "Command", "value": "/bin/sh" }],
    "why": "Web servers do not spawn interactive shells in normal operation...",
    "actions": ["Review the web server access logs...", "..."],
    "signature": "d1|web-shell|nginx|2056",
    "repeats": 1
  }
}
```

| Field | Notes |
|---|---|
| `ref_id` | Unique on the host; also the file name under `/var/lib/hermian/alerts/` |
| `severity` | `Info`, `Low`, `High` or `Critical` |
| `detection` | `D1` to `D5`, or `Self_` for self-protection alerts |
| `signature` | The incident key used for [deduplication](noise); stable across repeats |
| `chain` | Root first; `focus` marks the process the alert is about; empty for alerts without a process (logins, file changes without a known writer) |
| `offers` | Present when the alert offers [response buttons](response): `ignore`, `block` or `disconnect`, with their targets |
| `facts` | Evidence as label and value pairs; the labels depend on the rule |
| `text` | The same compact rendering Telegram gets |

The same JSON comes out of `hermian show <ref> --json` and, one alert per
line, `hermian alerts --json`. Text from the system is escaped before it's
stored, so fields never contain raw control characters.

A 2xx answer means delivered. 400, 413, 414, 415 and 422 mean the request
itself is wrong and aren't retried; anything else (timeouts, 5xx, 429) is
retried with backoff.
