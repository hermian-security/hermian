---
title: D4 · Privilege escalation
description: Hermian's privilege escalation rules - setuid files and file capabilities, sudoers and shadow edits, LD_PRELOAD injection and ptrace attaches.
---

# D4 · Privilege escalation

D4 looks for the steps between "an attacker runs code" and "an attacker is
root, for good": a setuid helper, a sudoers line, a hash in `/etc/shadow`, a
library injected into a privileged process, a debugger attached to one.

## Files

### setuid binary created outside system directories

`CRITICAL` · `HIGH` under `/opt`

**Fires when** a setuid or setgid executable appears in a user-writable tree:
`/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/root`, `/var/www`, `/srv`, `/opt`.
Seen as the `chmod` happens; a sweep four levels deep catches files created
with the bits already set (see [How it works](how-it-works#collectors)).

**Why** A setuid copy of a shell is the oldest way to keep root. Vendor
software installs setuid helpers under `/opt` (Chrome's `chrome-sandbox`), so
those page HIGH rather than a CRITICAL that could
[auto-isolate](response#isolation) the host.

**Do** Remove the setuid bit or the file; find who created it and audit that
account.

### File capabilities granted outside system directories

`HIGH`

**Fires when** an executable in those same trees gets filesystem capabilities
(`cap_setuid`, `cap_net_raw`…), seen as `setcap` sets them. Needs eBPF: the
sweep doesn't read capabilities.

**Do** `getcap <file>`; `setcap -r <file>` if it isn't yours.

### sudoers changed to grant password-less sudo

`CRITICAL`

**Fires when** `/etc/sudoers` or a file in `/etc/sudoers.d/` gains a
`NOPASSWD` rule, with nobody logged in.

### sudoers modified outside visudo

`LOW` from a session · `HIGH` otherwise

**Fires when** sudoers changes and the writer isn't `visudo` run from a session
or a package manager.

**Do** `visudo -c`; remove entries you didn't create, especially `NOPASSWD`
and `ALL=(ALL)`.

### shadow file modified outside user-management tools

`CRITICAL` unattended · `HIGH` from a session

**Fires when** `/etc/shadow` or `/etc/gshadow` is written by something other
than `passwd`, `useradd`, `usermod`, `chpasswd` and the like (or a package
manager).

**Why** Writing a known hash directly is how a password gets set without a
trace in the tools' logs. The real tool only counts when it was started by an
operator at a session or a package manager: `passwd -S root` followed by a
direct write doesn't pass as the tool's own.

### Account file modified outside user-management tools

`HIGH`

The same, for `/etc/passwd` and `/etc/group`, with nobody logged in. What
changed is described by [D2](detections/ssh-and-accounts#accounts).

## Processes

### LD_PRELOAD injection in an unattended process

`HIGH`

**Fires when** a program starts with `LD_PRELOAD` or `LD_AUDIT` in its
environment, outside an interactive session and outside a build tool (make,
cargo, cmake, ninja, fakeroot, dpkg-buildpackage). Several programs under one
chain are one incident.

**Why** The preloaded library hooks libc in that process: hiding files,
processes and connections, or stealing credentials.

**Do** Read `/proc/<pid>/environ` and `/proc/<pid>/maps` to find the library
and where it came from.

### LD_PRELOAD used in an interactive or build context

`INFO`

jemalloc, ASan, fakeroot, libeatmydata: developers do this all the time.

### Unexpected ptrace attach by a non-debugger

`HIGH` against a root process, or by a non-root user · `LOW` otherwise

**Fires when** a process attaches to an unrelated process with `ptrace`
(attach or seize), and it isn't a debugger (gdb, strace, lldb, ltrace,
valgrind, rr, bpftrace, perf, delve…) known by its installed executable, a
container runtime, or a parent tracing its own child.

**Why** ptrace reads and rewrites another process's memory: credential theft
from sshd, injection into a running service.

**Tune** An APM agent that uses ptrace:

```toml
[[allowlist.debuggers]]
comm   = "my-profiler"
reason = "In-house APM agent uses ptrace"
```

### A process attached to Hermian with ptrace

`CRITICAL`

Any ptrace attach to the Hermian daemon, debuggers included: nobody needs to
debug the live daemon on a production host, and an attacker who does can make
it report nothing.

## Limits

A ptrace alert says who attached, not what was done to the target. Injection
that doesn't go through ptrace or `LD_PRELOAD` (writing `/proc/<pid>/mem`
directly) isn't covered yet.
