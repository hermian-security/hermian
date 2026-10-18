---
title: Email
description: Send Hermian alerts by email over SMTP (STARTTLS, TLS or a local relay) or through the host's sendmail.
---

# Email

Email works through an SMTP server or the host's own mail transfer agent.
Each alert is one message, HTML with a plain-text alternative.

## SMTP

```toml
[notifications]
channels = ["journald", "file", "email"]

[notifications.email]
transport = "smtp"
from = "hermian@example.com"
to = ["ops@example.com", "you@example.com"]
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_security = "starttls"
smtp_username = "hermian@example.com"
smtp_password = "an-app-password"
```

| `smtp_security` | Port | Use |
|---|---|---|
| `starttls` | 587 | The usual choice: submission with STARTTLS (required, not opportunistic) |
| `tls` | 465 | Implicit TLS |
| `none` | 25 | Only for a relay on the host or the local network |

With Gmail or Microsoft 365, use an app password, not your account password.

## sendmail

On a host that already has a working MTA (Postfix, OpenSMTPD, msmtp…):

```toml
[notifications.email]
transport = "sendmail"
from = "hermian@web-01.example.com"
to = ["ops@example.com"]
sendmail_path = "/usr/sbin/sendmail"
```

## Options

| Setting | Default | What it does |
|---|---|---|
| `transport` | `smtp` | `smtp` or `sendmail` |
| `from` | | Sender address |
| `to` | `[]` | One or more recipients |
| `subject_prefix` | `[Hermian]` | Start of the subject |
| `smtp_host`, `smtp_port` | , `587` | Server |
| `smtp_security` | `starttls` | `starttls`, `tls` or `none` |
| `smtp_username`, `smtp_password` | | Credentials, if the server needs them |
| `timeout_secs` | `20` | Connection timeout (1 to 300) |
| `sendmail_path` | `/usr/sbin/sendmail` | For `transport = "sendmail"` |

The subject reads `[Hermian] HIGH: Web server spawned a shell (web-01)`. With
`content = "minimal"` it becomes `[Hermian] HIGH: Process chain alert
(web-01)` and the body only carries the reference.

`sudo hermian notify-test -c email --probe-only` connects and authenticates
without sending.
