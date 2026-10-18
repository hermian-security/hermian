---
title: Files, data and privacy
description: Every file Hermian writes on a host, what it stores, how long it keeps it, and exactly what leaves the server.
---

# Files, data and privacy

Everything Hermian knows stays on the host, in root-only files, unless you add
a channel.

## Files

| Path | What |
|---|---|
| `/usr/bin/hermian` | The binary (`/usr/local/bin/hermian` from the tarball) |
| `/etc/hermian/config.toml` | The [configuration](configuration), mode 0600 |
| `/etc/hermian/config.toml.bak` | The previous config, kept when `enable` adds new settings |
| `/var/lib/hermian/alerts/HER-….json` | One JSON file per alert ([format](notifications/webhooks#generic-json)) |
| `/var/lib/hermian/collections/HER-…/` | Bundles from `hermian collect` |
| `/var/lib/hermian/baseline.json` | What [learning](baseline) has recorded |
| `/var/lib/hermian/engine.json` | Reference counter and daily counts |
| `/var/lib/hermian/state.json` | The snapshot `hermian status` reads |
| `/var/lib/hermian/binary.sha256`, `config.sha256` | Integrity records |
| `/var/lib/hermian/pending/<channel>/` | Alerts waiting for delivery (up to 500 per channel) |
| `/var/log/hermian/alerts.log` | Every alert as text, rotated at 50 MB |
| `/run/hermian/heartbeat` | Touched by the daemon, read by the watchdog |
| `/run/hermian/pam.sock` | Socket for the optional PAM module |
| `/etc/systemd/system/hermian.service` | The daemon's unit |
| `/etc/systemd/system/hermian-watchdog.{service,timer}` | The dead-man switch |
| `/etc/sysctl.d/60-hermian.conf` | Raised inotify limits, only if they were too low |
| `/usr/lib/security/pam_hermian.so` | The PAM module, if installed |
| `/etc/apt/sources.list.d/hermian.sources`, `/usr/share/keyrings/hermian-archive-keyring.gpg` | The APT repository, if the installer added it |

Directories are mode 0700 and owned by root. `hermian uninstall` removes all of
it.

## Retention

Stored alerts and collect bundles older than `general.alert_retention_days`
(90) are deleted once an hour; `0` keeps them forever. `alerts.log` rotates at
50 MB. journald keeps its own retention.

To keep a copy before an uninstall or a rebuild:

```bash
sudo hermian alerts --all -n 100000 --json > hermian-alerts.ndjson
sudo journalctl -t hermian --no-pager > hermian-journal.txt
```

## What leaves the host

| Data | Leaves? |
|---|---|
| Raw telemetry: process events, connections, file contents | **Never** |
| Alerts | Only to the channels you configure, at `min_severity` and up |
| Alert details (addresses, users, paths, commands) | Only with `content = "full"` (the default); `minimal` sends severity, family, reference and host |
| Telegram button presses | Fetched by outbound polling; Hermian listens on no port |
| Usage statistics, crash reports, update checks | **None**. Updates come through apt or the installer, when you run them |
| `hermian report` | Only if you send it: counts by rule and severity, versions and coverage, with no host names, addresses, users, paths or commands |

Hermian makes no outbound connection of its own except to the channels you
configure.
