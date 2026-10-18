---
title: Configuration
description: Every setting in /etc/hermian/config.toml - general, baseline, SSH thresholds, detections, notifications, Telegram, email, webhooks, response and allowlists - with defaults and valid ranges.
---

# Configuration

Hermian reads one file: `/etc/hermian/config.toml`, root-only (0600).
`hermian enable` creates it with every setting at its default and a note on
each, and on upgrades adds new settings switched off, without touching yours.

**Two kinds of comment.** Lines starting with `##` explain. A line starting
with a single `#`, like `#message_thread_id = 12345`, is a setting that's
switched off: remove that `#` to turn it on. Removing one `#` from an
explanation leaves a comment, so you can't break the file that way. If an
edit does break it, the error names the line, and says so when it looks like
an explanation that lost its `##`.

**Reloading is automatic.** The daemon watches the file:

- a valid change reloads at once, and pages CRITICAL if it changes
  detections, channels or the allowlist (INFO if it changes nothing that
  matters);
- an invalid change is refused with a LOW alert, and the last good config
  stays in force. `hermian status` shows the error.

## `[general]`

| Setting | Default | Range | |
|---|---|---|---|
| `hostname` | `""` | | Name used in alerts; empty uses the system hostname |
| `alert_retention_days` | `90` | 0 to 3650 | Delete stored alerts and collect bundles older than this; `0` keeps them |

## `[baseline]`

| Setting | Default | Range | |
|---|---|---|---|
| `enabled` | `true` | | Learn SSH sources, destinations and network programs, then judge novelty. `false` turns the novelty rules off |
| `duration_hours` | `24` | 1 to 8760 | Length of the learning period |

See [Learning and novelty](baseline).

## `[ssh]`

| Setting | Default | Range | |
|---|---|---|---|
| `permit_root` | `false` | | `true` silences the root-login alerts, for hosts that rely on them |
| `failed_burst_count` | `5` | 1 to 10000 | Failures from one source that make a burst (INFO until a login follows) |
| `failed_burst_window_secs` | `60` | 1 to 86400 | Window for a burst, and for "login after a burst" |
| `brute_digest_hours` | `2` | 1 to 24 | How often the brute-force digest is computed |
| `brute_min_attempts` | `10` | 1 to 10000 | Attempts a source needs in that period to be listed |
| `known_key_new_network` | `"alert"` | `alert`, `log` | A key the account has used before, from a network it hasn't: `log` records it without sending. Passwords and new keys always page |

## `[detections]`

Each rule family can be switched off. All are on by default.

| Setting | Family |
|---|---|
| `d1_process_chains` | [Process chains](detections/process-chains) |
| `d2_auth` | [SSH and accounts](detections/ssh-and-accounts) |
| `d3_persistence` | [Persistence](detections/persistence) |
| `d4_priv_esc` | [Privilege escalation](detections/privilege-escalation) |
| `d5_network` | [Network](detections/network) |

Turning one off pages CRITICAL, like any change to what Hermian watches.

## `[notifications]`

| Setting | Default | |
|---|---|---|
| `channels` | `["journald", "file"]` | Any of `journald`, `file`, `telegram`, `email`, `webhook`, `stdout`; at least one |
| `min_severity` | `"HIGH"` | `INFO`, `LOW`, `HIGH` or `CRITICAL`: the lowest severity sent to channels other than journald and file |
| `dedup_window_secs` | `300` | 1 to 86400. Repeats of an incident within this window fold into one summary ([Noise control](noise)) |
| `content` | `"full"` | `full`, or `minimal` for "HIGH alert 025 on web-01" with no details and no buttons ([why](notifications#keeping-alerts-in-house)) |

## `[notifications.telegram]`

| Setting | Default | |
|---|---|---|
| `bot_token` | `""` | Required with the telegram channel |
| `chat_id` | `""` | Required; in quotes |
| `message_thread_id` | unset | Topic id in a forum-style group |
| `silent_below_critical` | `true` | Only CRITICAL makes a sound |
| `timeout_secs` | `10` | 1 to 300 |
| `actions` | `false` | Response buttons; needs `allowed_user_ids` and a `hermian enable` afterwards |
| `allowed_user_ids` | `[]` | Numeric user ids allowed to press buttons |
| `action_ttl_mins` | `15` | 1 to 1440 |

Details: [Telegram](notifications/telegram).

## `[notifications.email]`

| Setting | Default | |
|---|---|---|
| `transport` | `"smtp"` | `smtp` or `sendmail` |
| `from` | `""` | Required with the email channel |
| `to` | `[]` | At least one address |
| `subject_prefix` | `"[Hermian]"` | |
| `smtp_host` | `""` | Required for smtp |
| `smtp_port` | `587` | |
| `smtp_security` | `"starttls"` | `starttls`, `tls` or `none` |
| `smtp_username`, `smtp_password` | `""` | Both or neither |
| `timeout_secs` | `20` | 1 to 300 |
| `sendmail_path` | `"/usr/sbin/sendmail"` | For `transport = "sendmail"` |

Details: [Email](notifications/email).

## `[notifications.webhook]`

| Setting | Default | |
|---|---|---|
| `url` | `""` | Required with the webhook channel; `https://` or `http://` |
| `format` | `"generic"` | `generic`, `slack`, `discord`, `ntfy` or `matrix` |
| `token` | `""` | Sent as `Authorization: Bearer <token>` when set |
| `timeout_secs` | `10` | 1 to 300 |

Details: [Webhooks](notifications/webhooks).

## `[response]`

| Setting | Default | |
|---|---|---|
| `management_cidrs` | `[]` | Addresses you manage the host from: never blocked, reachable during isolation. A catch-all (`0.0.0.0/0`) is refused |
| `auto_isolate` | `false` | Isolate on CRITICAL; requires `management_cidrs` |
| `auto_isolate_revert_mins` | `0` | Lift an automatic isolation after this long (up to 10080); `0` keeps it until you lift it |
| `block_duration_hours` | `24` | 1 to 8760. How long a Block button blocks a source |

Details: [Response](response).

## `[allowlist]`

Exceptions, each a TOML array entry with a mandatory `reason`. Prefer fixing a
noisy rule (open an issue) over a broad exception. The config file holds a
switched-off example of each: remove the `#` from every line of one block to
use it.

| Entry | Fields | Effect |
|---|---|---|
| `[[allowlist.ssh_sources]]` | `source` (IP or CIDR), `reason` | Logins from it are never reported |
| `[[allowlist.process_chains]]` | `parent`, `child` (process names), optional `user` (name or uid), `reason` | That parent starting that child isn't reported by D1 |
| `[[allowlist.persistence]]` | `path`, `reason` | Changes to that path are ignored by D3 and D4 |
| `[[allowlist.binaries]]` | `path`, `reason` | Executions of it aren't reported as transient-directory or `LD_PRELOAD` findings |
| `[[allowlist.destinations]]` | `destination` (IP or CIDR), `reason` | Connections to it are never reported |
| `[[allowlist.debuggers]]` | `comm`, `reason` | That process name may ptrace without an alert |
| `[[allowlist.ssh_keys]]` | `fingerprint` (`SHA256:…`), optional `user`, `reason` | Logins with that key never count as coming from a new source (CI runners) |

Paths match exactly, as a directory (`/opt/app` covers everything under it),
or as a prefix ending in `*` (`/tmp/app-update-*`).

```toml
[[allowlist.ssh_sources]]
source = "198.51.100.7/32"
reason = "My home connection"

[[allowlist.process_chains]]
parent = "php-fpm8.2"
child  = "sh"
user   = "www-data"
reason = "PHP mail() via sendmail"

[[allowlist.persistence]]
path   = "/var/spool/cron/crontabs/deploy"
reason = "Managed by Ansible"

[[allowlist.destinations]]
destination = "203.0.113.10/32"
reason = "Payment provider API"

[[allowlist.binaries]]
path   = "/opt/app/bin/updater"
reason = "Internal auto-updater runs from /tmp staging"

[[allowlist.debuggers]]
comm   = "my-profiler"
reason = "In-house APM agent uses ptrace"
```

## Environment variables

For tests and unusual layouts; the systemd unit doesn't set them.

| Variable | |
|---|---|
| `HERMIAN_CONFIG` | Another config file |
| `HERMIAN_STATE_DIR`, `HERMIAN_LOG_DIR`, `HERMIAN_RUN_DIR` | Other directories. `uninstall` only deletes a directory whose path contains `hermian` |
| `NO_COLOR`, `HERMIAN_COLOR` | CLI colours |
