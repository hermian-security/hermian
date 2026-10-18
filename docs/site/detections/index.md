---
title: Detections
description: Every alert Hermian can raise, by rule family, with its severity - process chains, SSH and accounts, persistence, privilege escalation, network and self-protection.
---

# Detections

Hermian has five rule families and a set of alerts about itself. Each page
lists every alert of its family: what fires it, why it matters, what to do,
and how to tune it.

| Family | Watches | Page |
|---|---|---|
| D1 | Process chains: what services start, what runs from where | [Process chains](detections/process-chains) |
| D2 | SSH logins, brute force, backdoor key files, sshd config, accounts | [SSH and accounts](detections/ssh-and-accounts) |
| D3 | Cron, profiles, systemd, SSH keys, loader, PAM, environment, udev, modules | [Persistence](detections/persistence) |
| D4 | setuid, capabilities, sudoers, shadow, `LD_PRELOAD`, ptrace | [Privilege escalation](detections/privilege-escalation) |
| D5 | Outbound connections and listeners in context | [Network](detections/network) |
| SELF | Hermian's own integrity, liveness, and intrusions that predate it | [Self-protection](detections/self) |

Each family can be switched off in `[detections]`
([Configuration](configuration#detections)); they're all on by default.

## Every alert

| Alert | Family | Severity |
|---|---|---|
| Web server spawned a shell | D1 | `HIGH` |
| Database server spawned a shell | D1 | `HIGH` |
| Web server / Database server spawned a network relay tool | D1 | `HIGH` |
| Web server / Database server spawned a download tool | D1 | `HIGH` |
| Web server / Database server spawned an interpreter | D1 | `LOW` |
| Web server shell chain started a download | D1 | `HIGH` |
| Web server chain downloaded and executed remote content | D1 | `CRITICAL` |
| Execution from a transient directory inside a flagged chain | D1 | `CRITICAL` |
| Unattended execution from a transient directory | D1 | `HIGH` |
| Binary executed from a transient directory | D1 | `LOW` |
| Execution from a deleted file | D1 | `HIGH` |
| Fileless execution from memory (memfd) | D1 | `HIGH` |
| SSH authentication burst | D2 | `INFO` |
| SSH login after a failed-auth burst | D2 | `HIGH` |
| SSH brute force against existing accounts | D2 | `HIGH` |
| Root login over SSH from a new source | D2 | `HIGH` |
| Root login over SSH | D2 | `INFO` |
| Root login with a known key from a nearby address | D2 | `INFO` |
| Root login from a new source | D2 | `HIGH` |
| SSH login from a new source | D2 | `LOW` |
| SSH login with a key from a hidden key file | D2 | `HIGH` |
| sshd reads login keys from a hidden location | D2 | `HIGH` |
| SSH configuration changed with no session present | D2 | `HIGH` |
| SSH configuration edited during a session | D2 | `INFO` |
| Privileged account added or changed | D2 | `HIGH` |
| Privileged group membership changed | D2 | `HIGH` |
| System account database changed | D2 | `LOW` / `HIGH` |
| ld.so.preload modified | D3 | `CRITICAL` |
| New dynamic loader search path | D3 | `LOW` / `HIGH` |
| Dynamic loader config added | D3 | `INFO` |
| SSH key added with no session present | D3 | `HIGH` |
| SSH authorized_keys edited during a session | D3 | `INFO` |
| Cron job installed that downloads and runs remote code | D3 | `CRITICAL` |
| Cron persistence with no session present | D3 | `HIGH` |
| Cron entry edited during a session | D3 | `INFO` |
| Shell profile changed with no session present | D3 | `HIGH` |
| Shell profile edited during a session | D3 | `INFO` |
| systemd unit installed that runs from a transient directory | D3 | `CRITICAL` |
| systemd drop-in makes a service run from a transient directory | D3 | `CRITICAL` |
| systemd unit installed with no session present | D3 | `HIGH` |
| systemd drop-in added with no session present | D3 | `HIGH` |
| systemd unit enabled outside of systemctl | D3 | `HIGH` |
| systemd unit edited during a session | D3 | `INFO` |
| PAM now runs a program or a non-system module | D3 | `HIGH` / `CRITICAL` |
| Global environment sets LD_PRELOAD | D3 | `HIGH` / `CRITICAL` |
| udev rule runs a program | D3 | `HIGH` / `CRITICAL` |
| Change to … with no session present (PAM, environment, rc.local, udev, boot modules) | D3 | `HIGH` |
| Change to … during a session | D3 | `INFO` |
| Signs of an intrusion from before Hermian started | D3 | `HIGH` / `CRITICAL` |
| setuid binary created outside system directories | D4 | `HIGH` / `CRITICAL` |
| File capabilities granted outside system directories | D4 | `HIGH` |
| sudoers changed to grant password-less sudo | D4 | `CRITICAL` |
| sudoers modified outside visudo | D4 | `LOW` / `HIGH` |
| shadow file modified outside user-management tools | D4 | `HIGH` / `CRITICAL` |
| Account file modified outside user-management tools | D4 | `HIGH` |
| LD_PRELOAD injection in an unattended process | D4 | `HIGH` |
| LD_PRELOAD used in an interactive or build context | D4 | `INFO` |
| Unexpected ptrace attach by a non-debugger | D4 | `LOW` / `HIGH` |
| A process attached to Hermian with ptrace | D4 | `CRITICAL` |
| Outbound connection from a flagged process chain | D5 | `HIGH` |
| Web server connected to a new external destination | D5 | `HIGH` |
| First outbound connection from a program | D5 | `INFO` / `LOW` |
| New listener opened by a suspicious process | D5 | `HIGH` |
| New listener opened by a shell or interpreter | D5 | `LOW` |
| New listening port | D5 | `INFO` |
| Hermian itself is hooked | SELF | `CRITICAL` |
| Hermian binary modified | SELF | `CRITICAL` |
| Hermian configuration changed and reloaded | SELF | `CRITICAL` |
| Hermian alert destinations changed and reloaded | SELF | `CRITICAL` |
| Hermian configuration modified while stopped | SELF | `CRITICAL` |
| Hermian configuration unreadable | SELF | `CRITICAL` |
| Hermian configuration changed but is INVALID | SELF | `LOW` |
| Hermian configuration reloaded with no functional change | SELF | `INFO` |
| Hermian integrity record missing | SELF | `HIGH` |
| Hermian is stopping | SELF | `HIGH` |
| Hermian is restarting (install or upgrade) | SELF | `INFO` |
| Hermian restarted after an unclean shutdown | SELF | `HIGH` |
| Hermian daemon is not responding | SELF | `HIGH` |
| Hermian daemon is down | SELF | `CRITICAL` |
| Hermian dropped telemetry | SELF | `HIGH` |
| Another host is reading this bot's button presses | SELF | `HIGH` |
| CPUs came online without eBPF monitoring | SELF | `HIGH` |
| 32-bit program started (partly unmonitored) | SELF | `LOW` |
| Hermian is active | SELF | `INFO` |

Repeats of any alert fold into a LOW "Repeated: …" summary when the dedup
window closes ([Noise control](noise)).
