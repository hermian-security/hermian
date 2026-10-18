---
title: Command line
description: Every hermian command and option - status, alerts, show, collect, report, enable, notify-test, test, audit, isolate, unisolate, block, blocked, unblock, disconnect and uninstall.
---

# Command line

Every command needs root (`sudo`), except `--help` and `--version`.

```bash
sudo hermian <command> [options]
hermian --help              # grouped command list
hermian <command> --help    # options of one command
hermian --version
```

Colours are used on a terminal only. `NO_COLOR=1` turns them off;
`HERMIAN_COLOR=always` or `never` forces them. Most commands take `--json` for
scripts. Exit status is 0 on success and 1 on an error; `audit` uses 2 for "found
something serious".

## Everyday

### `status`

Is the host protected? Coverage per rule family and the source behind it,
baseline progress, today's counts, CPU and memory, delivery per channel,
buttons, and the binary and config hashes.

| Option | |
|---|---|
| `--json` | Machine-readable output |

The verdict is **PROTECTED**, **DEGRADED** (with what's wrong) or
**INTEGRITY FAILURE**. It warns when the `hermian` you ran and the daemon are
different versions (usually an upgrade the daemon hasn't restarted into).

### `alerts`

Recent alerts, newest first, LOW and up.

| Option | |
|---|---|
| `-n`, `--limit <N>` | How many (default 20) |
| `-s`, `--severity <LEVEL>` | At or above `INFO`, `LOW`, `HIGH` or `CRITICAL` (default `LOW`) |
| `-a`, `--all` | Include INFO alerts |
| `-d`, `--detection <ID>` | Only `D1`…`D5` or `SELF` |
| `--json` | One alert per line (NDJSON) |
| `<REF>` | Show that alert in full instead (`hermian alerts 182`) |

```bash
sudo hermian alerts -s high -n 50
sudo hermian alerts -d D2 --json | jq .title
```

### `show <REF>`

One alert in full: what happened, chain, facts, risk, next steps. `REF` is the
full reference (`HER-2026-1017-002`) or today's number (`2`, `002`).

| Option | |
|---|---|
| `--json` | The stored JSON ([format](notifications/webhooks#generic-json)) |

### `collect <REF>`

Gathers local context for an alert into `/var/lib/hermian/collections/<REF>/`:
`context.txt` with the alert, the processes of its chain that are still
running (executable, command line, working directory, notable environment
variables, open files), the files the alert references with their SHA-256
(and a copy of the small ones), and Hermian's own integrity hashes. Run it
soon after the alert, while the processes still exist. Nothing is uploaded.
Bundles follow `alert_retention_days`.

### `report`

A summary to share with the maintainers: alerts by rule and severity, versions,
coverage. It leaves out host names, addresses, users, paths and commands.

| Option | |
|---|---|
| `--days <N>` | Period to count (default 7) |
| `--json` | Machine-readable output |

## Setup

### `enable`

Installs, enables and starts the daemon: units, directories, config (new
settings added switched off, nothing you set changed), hashes, baseline,
inotify limits, capabilities for buttons and isolation. Safe to re-run; the
package runs it on every install and upgrade.

| Option | |
|---|---|
| `--no-baseline` | Skip the learning period and judge novelty from the start (freshly built hosts) |
| `--with-pam` | Also hook the optional PAM module into sshd |
| `-q`, `--quiet` | Don't print the status afterwards |

### `notify-test`

Checks every configured channel and sends a test alert through it.

| Option | |
|---|---|
| `-c`, `--channel <NAME>` | Only `telegram`, `email` or `webhook` |
| `--probe-only` | Check connectivity and credentials, send nothing |
| `--severity <LEVEL>` | Severity of the test alert (default `HIGH`; affects the Telegram sound and the email colour) |

### `test`

Feeds nine synthetic attack scenarios to the detection engine and checks each
fires at the expected severity. Touches nothing on the host.

| Option | |
|---|---|
| `-v`, `--verbose` | Print every sample alert, not just the first |
| `--json` | The sample alerts as NDJSON, to test an integration |

### `audit`

Looks for signs that the host was compromised before Hermian started
([what it checks](self-protection#the-start-up-audit)). The daemon runs the same
checks at every start.

| Option | |
|---|---|
| `--json` | One JSON object per sign: `severity`, `kind`, `path`, `what` |

Exit status 2 when a sign is HIGH or worse.

## Response

### `isolate`

Cuts the host off the network except management CIDRs and recovery essentials
([details](response#isolation)). Needs `response.management_cidrs`.

| Option | |
|---|---|
| `--for <MINUTES>` | Lift automatically after 1 to 10080 minutes, with a systemd timer that works even if the daemon is gone |

### `unisolate`

Removes the isolation ruleset.

### `block <IP>...`

Blocks addresses for `response.block_duration_hours`, like the Telegram Block
button (IPv6: the /64). Management networks, allowlisted SSH sources and local
addresses are refused. An address already blocked is left as it is, expiry
included, and the answer says since when and by whom.

### `blocked`

Lists blocked addresses with the time left.

### `unblock <IP>`

Lifts a block before it expires. For IPv6, any address in the blocked /64.
Says so if it wasn't blocked, and why (lifted, by whom, or expired).

### `disconnect <IP>`

Ends the SSH sessions from that address, like the Disconnect button. It
doesn't block it: add `hermian block` for that.

Each prints one line per address, marked ✓ done, · already, ⊘ refused or
✗ failed, and exits 1 if anything was refused or failed.

## Remove

### `uninstall`

Removes Hermian completely: lifts isolation and blocks, stops and removes the
units, config, state, alerts, logs, PAM hook, APT entry and binary (with
`dpkg --purge` on a package install).

| Option | |
|---|---|
| `--yes` | Don't ask for confirmation |

## Used by systemd

`hermian run` (the daemon) and `hermian watchdog` (the dead-man switch timer)
are hidden from `--help`; you don't call them yourself.
