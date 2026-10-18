---
title: Troubleshooting
description: Fix common Hermian problems - no Telegram messages, HTTP 409, DEGRADED status, /proc fallback without eBPF, invalid config, false positives, version mismatch, high CPU and more.
---

# Troubleshooting

Start with these two; they answer most questions:

```bash
sudo hermian status                       # what's on, what's failing
sudo journalctl -u hermian -n 100 --no-pager   # the daemon's own log
```

## Notifications

### No Telegram message arrives

Run `sudo hermian notify-test -c telegram`. It names the problem:

| It says | Fix |
|---|---|
| `bot_token rejected by Telegram (401)` | Copy the token again from @BotFather (`/mybots` › API token) |
| `chat_id … not reachable: send a message to the bot first` | Send any message to the bot (in a group: mention it), then read the id from `getUpdates` again |
| Nothing wrong, test arrives, real alerts don't | Check `min_severity`: by default only HIGH and CRITICAL are sent. LOW alerts are in `hermian alerts` |
| `telegram` isn't in the list | Add it to `[notifications] channels` |

A group's id is negative and must be quoted: `chat_id = "-1001234567890"`.

### `HTTP 409` in status, buttons don't respond

Something else is reading the bot's updates: another host with buttons on the
same bot (each press reaches only one of them), or a webhook set on the bot.
Give each host with buttons its own bot ([Several servers](fleet)), or remove
the webhook:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/deleteWebhook"
```

### Buttons say "You're not allowed to do this"

Your Telegram user id isn't in `allowed_user_ids`. Ask @userinfobot for it and
add it as a number, without quotes. Presses from the wrong chat are refused
too.

### Buttons do nothing / "Response buttons are turned off"

`actions = true` needs `allowed_user_ids`, and then `sudo hermian enable` once
to grant the firewall and kill capabilities. Buttons expire after
`action_ttl_mins` (15) and work once; pending buttons don't survive a restart.

### Email doesn't send

`sudo hermian notify-test -c email --probe-only` checks the connection and the
login. Common causes: port and `smtp_security` mismatched (587 with
`starttls`, 465 with `tls`), a provider that needs an app password, or a
`from` address the server won't relay for.

### Webhook errors

`hermian status` shows the last error with the URL cut to `scheme://host/…`.
A `400`, `413` or `422` means the format is wrong for that service (check
`format`); a timeout or `5xx` is retried.

## Status

### DEGRADED

It lists the cause:

| Cause | What it means |
|---|---|
| Channel failures, pending notifications | A channel can't deliver; see above |
| Events dropped | The kernel buffer overflowed during a burst; occasional is fine, constant deserves an issue |
| File watches failed | inotify limits too low: run `sudo hermian enable` (it raises them) |
| `DEGRADED: FILE WATCHERS DOWN` | No persistence watches at all; check the journal for inotify errors |

### INTEGRITY FAILURE

The binary or the config no longer matches its recorded hash. If you just
changed the config by hand while the daemon was stopped, or upgraded outside
the package, check the file is what you expect, then `sudo hermian enable`
records the current hashes.

### Coverage says `/proc` instead of `eBPF`

The kernel is older than 5.8 or has no BTF (`/sys/kernel/btf/vmlinux`
missing), or the eBPF programs couldn't load (the journal says why: a
lockdown kernel, SELinux, missing capabilities). Hermian falls back to polling
`/proc` every second and to audit when available. Detection still works, but
very short-lived processes can be missed. On SELinux hosts (RHEL family),
coverage hasn't been verified yet: please [report](https://github.com/hermian-security/hermian/issues)
what `status` shows.

### "This command is vX, the daemon runs vY"

An upgrade the daemon hasn't restarted into (`sudo systemctl restart hermian`),
or an older copy earlier in `PATH` (`type -a hermian`), often a build from
source in `/usr/local/bin`.

### "The daemon is not running"

```bash
sudo systemctl status hermian
sudo journalctl -u hermian -n 50 --no-pager
sudo systemctl start hermian
```

The unit restarts the daemon after any exit you didn't ask for, so a daemon
that keeps stopping is crashing: the journal has the reason, and the next
start pages "restarted after an unclean shutdown".

## Configuration

### My change isn't applied

An invalid config is refused (LOW alert, "configuration changed but is
INVALID") and the last good one stays. `hermian status` and the journal show
the error, such as `notifications.telegram.chat_id is required` or a TOML syntax
error with its line.

### Every config change pages CRITICAL

On purpose: a change to what Hermian watches or where it sends alerts must be
visible. Comment-only changes are INFO.

## Alerts

### A legitimate action keeps alerting

1. `sudo hermian show <ref>` to see exactly what matched.
2. If the rule is wrong for everyone, open an issue with
   `hermian show <ref> --json` (remove secrets first).
3. If it's specific to your host, add an
   [allowlist entry](configuration#allowlist) with a reason.

Typical cases: PHP `mail()` (allowlist `php-fpm` → `sh`), a CI/CD agent that
runs shells (allowlist its chain), an updater staging in `/tmp` (allowlist the
binary), your own admin address (allowlist the SSH source).

### My own SSH login paged

Once learning is over, a login from an address never seen before pages once
(LOW, or HIGH for root); then the address is known. A known key from a new
address on the same /16 is INFO. Allowlist your fixed addresses, or set
`ssh.permit_root = true` if the host relies on root logins.

### Nothing ever alerts

Good, usually. To check the pipeline end to end: `sudo hermian test` (the
engine) and `sudo hermian notify-test` (delivery). `hermian alerts --all`
shows INFO alerts too, which prove events are being seen.

### The same incident pages repeatedly

Repeats within `dedup_window_secs` (5 minutes) are folded; an incident still
going gets longer windows (15, 45 minutes, then hourly). If it's legitimate,
allowlist it; if it's an attack, it should page.

## Performance

Hermian typically uses well under 1% of a CPU and 15 to 25 MB of memory
(`hermian status` shows both). A busy host with thousands of short processes a
second costs more. If CPU stays high, the journal and `hermian status` (dropped
events, watch counts) help; please open an issue with them.

## Still stuck

Open an issue with the output of `hermian status --json` and
`hermian report`, or ask in
[Discussions](https://github.com/hermian-security/hermian/discussions).
Security problems go to [SECURITY.md](https://github.com/hermian-security/hermian/blob/main/SECURITY.md),
privately.
