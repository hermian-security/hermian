---
title: D3 · Persistence
description: Hermian's persistence rules - ld.so.preload and loader paths, SSH keys, cron and at jobs, shell profiles, systemd units and drop-ins, PAM, global environment, rc.local, udev rules and boot modules.
---

# D3 · Persistence

Persistence is how an attacker survives a reboot or a closed session. D3
watches every place a program can be told to start on its own, with inotify,
and judges each change by its content and by
[who made it](how-it-works#who-did-it-operator-or-not).

The pattern is the same throughout:

| Change | Severity |
|---|---|
| Made from an interactive session, content clean | `INFO` |
| Made by a package or config manager, content clean | nothing |
| Made with nobody logged in | `HIGH` |
| Content that downloads and runs code, or runs from `/tmp`, whoever wrote it | `CRITICAL` |

"Downloads and runs code" means a fetch (`curl`, `wget`, `base64 -d`) piped
into a shell or interpreter, or a program run from `/tmp`, `/dev/shm` or
`/var/tmp`. Paths in the [persistence allowlist](configuration#allowlist) are
skipped. Container overlay paths and editor temp files are ignored.

## Loader

### ld.so.preload modified

`CRITICAL`

**Fires when** `/etc/ld.so.preload` is written with at least one library in
it. An empty file loads nothing and isn't reported (Hermian's own unit has
systemd create one, see [Self-protection](self-protection#rootkit-shield)).

**Why** It injects code into every dynamically linked program: the most
powerful userland rootkit primitive there is, and no routine workflow writes
to it. On a perfctl-infected host it caught the rootkit rewriting its entry.

**Do** Remove any library you didn't install; treat the host as compromised,
since the library can hide processes, files and sockets.

### New dynamic loader search path

`LOW` by a package manager · `HIGH` otherwise

**Fires when** a file in `/etc/ld.so.conf.d/` adds a search path outside the
standard system library directories.

**Why** A planted directory early in the search path wins library lookups for
every program.

**Do** Remove the path, run `ldconfig`, check the directory for unexpected
`.so` files.

### Dynamic loader config added

`INFO`

A loader config with standard paths only, written by a package manager.

## SSH keys

### SSH key added with no session present

`HIGH`

**Fires when** an `authorized_keys` or `authorized_keys2` file changes with
nobody logged in. The alert names the account and the key count.

**Why** A key planted by a process is a backdoor that survives password
changes.

**Do** Review the newest lines; remove keys you don't recognise; audit the
account.

### SSH authorized_keys edited during a session

`INFO`

`ssh-copy-id` or an editor, from a session.

## Cron and at

Covers `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d`,
`/etc/cron.{hourly,daily,weekly,monthly}`, user crontabs under
`/var/spool/cron` and at jobs. Content is read before anything else: the real
`crontab` installing a `curl … | sh` line is still CRITICAL.

### Cron job installed that downloads and runs remote code

`CRITICAL`

**Fires when** a cron or at entry fetches and runs code, or runs a program
from a temporary directory.

### Cron persistence with no session present

`HIGH`

**Fires when** a cron file changes with nobody logged in, not by the `crontab`
tool from a session, nor by a package or config manager. The alert shows the
commands, the suspicious ones first.

### Cron entry edited during a session

`INFO`

`crontab -e` and friends, from a session.

## Shell profiles

System profiles (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`,
`/etc/zsh/zshrc`) and users' `.bashrc`, `.profile`, `.bash_profile`,
`.bash_login`, `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin` under `/home` and
`/root`.

### Shell profile changed with no session present

`HIGH`

**Why** A profile runs at every login. perfctl, for example, adds a line to
`~/.profile` that restarts it whenever root logs in.

**Do** Read the end of the file for appended lines; remove what isn't yours.

### Shell profile edited during a session

`INFO`

## systemd

Unit files (`.service`, `.timer`, `.socket`, `.path`, `.mount`, `.target`,
`.automount`), drop-ins (`x.service.d/*.conf`) and enable links
(`.wants/`, `.requires/`) under `/etc/systemd/system`, `/usr/lib/systemd/system`,
`/lib/systemd/system` and users' `~/.config/systemd/user`. Files a package
owns are skipped.

### systemd unit installed that runs from a transient directory

`CRITICAL`

**Fires when** a unit's `Exec*` line runs from `/tmp`, `/dev/shm`, `/var/tmp`
or is a download-and-run one-liner.

### systemd drop-in makes a service run from a transient directory

`CRITICAL`

**Fires when** a drop-in overrides a service's commands with one of those.

**Why** A drop-in can replace `ExecStart=` of an existing, package-owned
service: the quietest way to persist through systemd.

### systemd unit installed with no session present

`HIGH`

### systemd drop-in added with no session present

`HIGH`

### systemd unit enabled outside of systemctl

`HIGH`

**Fires when** an enable link appears that systemd or `systemctl` didn't
create.

### systemd unit edited during a session

`INFO`

## Other surfaces

| File | Why it matters |
|---|---|
| `/etc/pam.d/*` | PAM runs on every authentication; a changed stack can accept any password, log credentials or run a program at each login |
| `/etc/environment`, `/etc/security/pam_env.conf` | Variables applied to every login session |
| `/etc/rc.local` | Runs as root at every boot |
| `/etc/udev/rules.d/*.rules` | Rules can run programs as root on device events, including at boot |
| `/etc/modules`, `/etc/modules-load.d/*.conf` | Kernel modules loaded at every boot; rootkits persist this way |

Each change is `INFO` from a session and `HIGH` otherwise, under the title
"Change to … with no session present". A red flag in the content raises it
(`HIGH` from a session, `CRITICAL` otherwise) with a sharper title:

### PAM now runs a program or a non-system module

`HIGH` / `CRITICAL`

`pam_exec`, or a module loaded from a path outside `/lib` and `/usr/lib`.

### Global environment sets LD_PRELOAD

`HIGH` / `CRITICAL`

`LD_PRELOAD` or `LD_AUDIT` in the global login environment loads a library
into everything users start.

### udev rule runs a program

`HIGH` / `CRITICAL`

A `RUN+=` or `RUN=` in a udev rule. rc.local lines that download and run code
are red flags too.

## Before Hermian started

### Signs of an intrusion from before Hermian started

`HIGH` / `CRITICAL`

The [start-up audit](self-protection#the-start-up-audit) found persistence,
running implants or a preloaded library that were there before the daemon
started. It's filed under D3 because that's mostly what it finds. The same
findings at the next start (an install restarts more than once) are recorded
as INFO instead of paging again, for a day.
