---
title: First ten minutes
description: Check that Hermian is protecting the host, run the self-test and the start-up audit, get alerts on your phone, and read your first alert.
---

# First ten minutes

You've installed Hermian. Here's how to confirm it works and get its alerts
where you'll see them.

## 1. Is it protecting the host?

```bash
sudo hermian status
```

```text
  ╱╱╱●  hermian  v0.1.0                              web-01 · up 2m
  ──────────────────────────────────────────────────────────────────────
  PROTECTED

  COVERAGE
  Process chains ............................................... on eBPF
  SSH and authentication ......................... on journald + inotify
  Persistence ............................................... on inotify
  Privilege escalation ............................... on eBPF + inotify
  Network correlation .................................. on eBPF + /proc
  Baseline ................................. learning, 23h 58m remaining
```

**PROTECTED** means every collector runs and nothing is failing. **DEGRADED**
lists what's wrong (a channel failing, events dropped, file watches that
couldn't be added). **INTEGRITY FAILURE** means the binary or the config no
longer matches its recorded hash. If a family says `on /proc` instead of
`on eBPF`, the kernel is too old or lacks BTF: see
[Troubleshooting](troubleshooting#coverage-says-proc-instead-of-ebpf).

## 2. Self-test and audit

```bash
sudo hermian test     # 9 simulated attacks, run inside the engine
sudo hermian audit    # signs of an intrusion from before Hermian started
```

`test` feeds synthetic events to the detection engine and checks each
scenario fires at the expected severity. It touches nothing on the system, so
it proves the rules, not live collection.

`audit` looks for what an implant or a rootkit leaves behind:
`/etc/ld.so.preload`, programs running from temporary or hidden directories,
code in system directories that no package installed, crontabs and profiles
that start any of it. "Clean" is the expected answer. Anything else: read
[Self-protection and audit](self-protection#the-start-up-audit).

## 3. Get alerts on your phone

Alerts always go to journald and `/var/log/hermian/alerts.log`. To get them
on your phone, the quickest is Telegram:

1. Message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the
   token.
2. Send any message to your new bot.
3. Find your chat id:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":[0-9-]*'
   ```
4. Edit `/etc/hermian/config.toml`:
   ```toml
   [notifications]
   channels = ["journald", "file", "telegram"]

   [notifications.telegram]
   bot_token = "123456789:AAH..."
   chat_id = "123456789"
   ```
5. Send a test:
   ```bash
   sudo hermian notify-test
   ```

The daemon reloads a valid config on its own, and the change itself raises an
alert (that's on purpose: see [Self-protection](detections/self)). Email, Slack,
Discord, ntfy, Matrix and plain webhooks work the same way:
[Notifications](notifications).

## 4. Read an alert

Once something fires (your own first SSH login from a new address will do, once
learning is over):

```bash
sudo hermian alerts          # the list, LOW and up
sudo hermian show 1          # today's alert 001, in full
```

```text
◉◉◉○ Hermian  HIGH                                     HER-2026-1017-002
Web server spawned a shell

WHAT HAPPENED
  nginx (pid 2056) spawned the shell sh (pid 2058) running as www-data.

  systemd  root · pid 1
  └─ nginx  www-data · pid 2056
     └─ sh  www-data · pid 2058

RISK
  Web servers do not spawn interactive shells in normal operation...

NEXT STEPS
   1. Review the web server access logs for the request that coincides...
```

Every alert has the same parts: severity, rule, what happened, the process
chain, facts, the risk and next steps. `hermian collect <ref>` gathers the
local context (process details, hashes, connections) into a bundle for an
investigation. It never uploads anything.

## 5. Let it learn

For its first 24 hours Hermian learns your normal SSH sources, outbound
destinations and network programs, then reports what's new once. Use the
server as usual. Your own login from a new place after that will page once,
then be known. [Learning and novelty](baseline) explains the details.

## Next

- [How it works](how-it-works): how it decides what's an alert.
- [Response](response): Block and Disconnect buttons, network isolation.
- [Several servers](fleet): one Telegram group for all of them.
