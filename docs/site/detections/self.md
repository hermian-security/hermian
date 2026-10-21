---
title: Self-protection alerts
description: The alerts Hermian raises about itself - integrity, configuration changes, stops and restarts, the watchdog, dropped events, injected code and coverage gaps.
---

# Self-protection alerts

These alerts are about Hermian itself, under the rule family `SELF`. How the
protections work is explained in [Self-protection and audit](self-protection).

## Integrity

### Hermian itself is hooked

`CRITICAL`

The [self-check](self-protection#self-check) found code in the daemon's memory
that doesn't belong there: a library from a temporary or hidden location, code
no package owns, or a library from `/etc/ld.so.preload`. Restart Hermian, run
`hermian audit`, and treat the host as compromised: alerts from a hooked
daemon can't be trusted.

### Hermian binary modified

`CRITICAL`

The binary doesn't match the hash recorded at `hermian enable`. Checked at
every start; the package re-records it on upgrade.

### Hermian integrity record missing

`HIGH`

The recorded hashes are gone. Run `sudo hermian enable` to record them again
once you've checked the binary and config are yours.

## Configuration

### Hermian configuration changed and reloaded

`CRITICAL` · `LOW` when nothing is loosened

A valid change was loaded. If it loosens anything (a rule off, a wider
exception, a higher `min_severity`, `permit_root` on, more people who can
press buttons, fewer channels), it pages CRITICAL: someone who silences a rule
tells you. Changes that only tune or tighten (a timeout, a retention period, a
new channel, an exception removed) are recorded as LOW, so editing your own
config doesn't page you. Anything Hermian doesn't know to be harmless counts
as loosening.

### Hermian alert destinations changed and reloaded

`CRITICAL`

The channels changed: alerts may now go somewhere else, or nowhere. The alert
is sent through the new channels.

### Hermian configuration reloaded with no functional change

`INFO`

A comment or formatting change.

### Hermian configuration changed but is INVALID

`LOW`

The file doesn't parse or validate. The last good config stays in force;
`hermian status` shows the error.

### Hermian configuration unreadable

`CRITICAL`

The file can't be read at all (permissions, deleted).

### Hermian configuration modified while stopped

`CRITICAL`

The config changed while the daemon wasn't running to see it.

## Liveness

### Hermian is stopping

`HIGH`

Sent before the daemon goes quiet, whatever stops it (it waits up to six
seconds for delivery).

### Hermian is restarting (install or upgrade)

`INFO`

A planned restart by `hermian enable`, so upgrades don't page.

### Hermian is restarting

`INFO`

`systemctl restart hermian`: systemd had a restart queued for the daemon as it
stopped, so it's back in seconds. A plain stop still pages "Hermian is
stopping".

### Alerts aren't reaching one of the channels

`HIGH`

A channel has failed for more than 15 minutes: a revoked bot token, a full
mailbox, a dead webhook, or the host cut off from it. The alert goes to every
channel, so the working ones carry it; the failing channel's alerts stay
queued on the host until it works again. With a single channel, it's in the
journal and `hermian status`.

### Hermian restarted after an unclean shutdown

`HIGH`

The previous run crashed, was killed or was frozen and restarted by the
watchdog. The alert says which.

### Hermian daemon is not responding

`HIGH`

The heartbeat went stale for over a few minutes; the watchdog restarts the
daemon.

### Hermian daemon is down

`CRITICAL`

The watchdog found the daemon not running.

### Hermian is active

`INFO`

The one-time confirmation when Hermian first starts on a host: proof the
alert path works.

## Coverage

### Hermian dropped telemetry

`HIGH`

The kernel ring buffer overflowed and events were lost, so something may have
gone unseen in that window. Usually a burst of activity; frequent drops
deserve an issue.

### Another host is reading this bot's button presses

`HIGH`

Telegram keeps refusing this host its button presses because something else
polls the same bot. Each press then reaches only one of them, so a Block or
Disconnect can quietly not happen. Give each host with buttons its own bot
([Fleet](fleet)), or set `notifications.telegram.actions = false` on the
others. If no other host should have it, revoke the token with @BotFather.

### CPUs came online without eBPF monitoring

`HIGH`

CPUs hot-plugged after start have no event reader. Restart Hermian to cover
them.

### 32-bit program started (partly unmonitored)

`LOW`

A 32-bit program on x86_64 makes compat syscalls the eBPF hooks don't
see, so its connections and ptrace calls are invisible. Rare on a 64-bit
server, and used to get around syscall monitoring.
