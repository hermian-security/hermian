---
title: D2 · SSH and accounts
description: Hermian's SSH and account rules - logins from new sources, root logins, logins after a burst, brute-force digests, backdoor key files, sshd configuration and account changes.
---

# D2 · SSH and accounts

D2 reads sshd's own log entries (from journald, or `auth.log` / `secure`) and
watches the SSH configuration and account files. Every login alert names the
method, the key fingerprint and, for keys, the file and line it came from.

Logins from an [allowlisted](configuration#allowlist) source are never
reported. Suspicious logins (LOW and above) carry Telegram buttons when
[response actions](response) are on: Ignore, Disconnect session, Disconnect
and block.

## Logins

### SSH authentication burst

`INFO`

**Fires when** a source reaches `ssh.failed_burst_count` (5) failed or
attempted logins within `ssh.failed_burst_window_secs` (60).

**Why** Scanners do this to every public SSH port all day. Logged only: what
matters is a login that follows.

### SSH login after a failed-auth burst

`HIGH`

**Fires when** a login succeeds from a source that just had a burst of
failures within the window. The alert lists the usernames it tried.

**Why** One of those attempts probably worked.

**Do** Confirm the session; lock or rotate the account that succeeded and the
others tried; block the source and review what the session did.

### Root login over SSH from a new source

`HIGH`

**Fires when** root logs in from an address that has never logged in as root
(and `ssh.permit_root` is false).

**Why** Direct root logins remove accountability and are the favourite target
of credential attacks.

**Tune** If the host relies on root logins, set `ssh.permit_root = true`, or
allowlist your management address. Better: `PermitRootLogin
prohibit-password` and a named account.

### Root login over SSH

`INFO`

Root again, from an address that has logged in as root before. Context, not a
new incident.

### Root login with a known key from a nearby address

`INFO`

Root, with a key that has logged in before, from a new address on a network
root already uses (/16, or /32 for IPv6). A dynamic IP, not a new incident.

### Root login from a new source / SSH login from a new source

`HIGH` for root · `LOW` for other accounts

**Fires when** after the [learning period](baseline), a login comes from an
address never seen before (and not a known key on a known network).

**Why** A first-time source proves nothing by itself; it's where a surprise
login shows up. A root login matching both rules sends one alert, the sharper
one.

### SSH login with a key from a hidden key file

`HIGH`

**Fires when** a login uses a key stored outside the account's `~/.ssh`: in
`/dev`, `/tmp`, `/var/tmp`, `/run`, `/proc`, `/sys`, or in a dot-directory.
It pages whatever the source, even a familiar one.

**Why** sshd was told to accept keys from an extra file nobody reviews. It's
a common way to keep access that doesn't show in `authorized_keys`. A key used
this way is never learned as a known key.

**Do** `ssh-keygen -lf <file>` to list the keys; if it isn't yours, remove the
`AuthorizedKeysFile` entry and the file, restart sshd, rotate keys.

## Brute force

### SSH brute force against existing accounts

`HIGH`

**Fires when** every `ssh.brute_digest_hours` (2), if failed logins targeted
accounts that can actually log in (a real shell in `/etc/passwd`), listing
the sources with at least `ssh.brute_min_attempts` (10) attempts, busiest
first.

**Why** Attempts against usernames that don't exist are background noise and
never count. Attempts against your real accounts are worth a summary. The
digest also says when root can log in with a password and is being tried.

**Buttons** Block each top source, Block all, Ignore 2h, and a 7-day reminder
for the root-password warning.

## sshd configuration

### sshd reads login keys from a hidden location

`HIGH`

**Fires when** sshd's effective configuration (`sshd -T`, checked at start and
every ten minutes) has `AuthorizedKeysFile`, `AuthorizedKeysCommand`,
`AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand` or
`TrustedUserCAKeys` pointing at a hidden or volatile path. Each one is
reported once, ever.

**Why** This is the backdoor itself, before anyone uses it: a key file that
works for every account it covers and survives password changes.

**Do** `grep -ri authorizedkeys /etc/ssh/sshd_config /etc/ssh/sshd_config.d/`
to find what sets it.

### SSH configuration changed with no session present

`HIGH`

**Fires when** `/etc/ssh/sshd_config`, a file in `sshd_config.d/` or
`ssh_config` changes with nobody logged in, and not by a package manager.

**Do** Diff it against your last version or the package default; revert what
you didn't change; restart sshd.

### SSH configuration edited during a session

`INFO`

The same change, made from an interactive session.

## Accounts

`/etc/passwd` and `/etc/group` are diffed on every change, so the alert says
exactly what changed.

### Privileged account added or changed

`HIGH`

**Fires when** an account gets uid or gid 0, or a service account with a
`nologin` shell gets a real shell.

**Why** A second root, or a service account that can suddenly log in, are
classic ways to keep access.

### Privileged group membership changed

`HIGH`

**Fires when** someone is added to sudo, wheel, admin, root, docker, lxd,
incus-admin, libvirt, disk, shadow or adm. Docker, LXD and libvirt membership
is root by another name; disk and shadow give raw access to block devices and
password hashes.

### System account database changed

`LOW` from a session · `HIGH` otherwise

**Fires when** accounts are added or changed in other ways (uid, gid, shell,
home).

**Do** Verify the change is authorized; if not, remove it and find how it was
made.

Direct writes to `/etc/shadow` and other account files outside the user tools
are covered by [D4](detections/privilege-escalation#shadow-file-modified-outside-user-management-tools).
