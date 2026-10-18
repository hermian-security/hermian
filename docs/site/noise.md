---
title: Noise control
description: How Hermian keeps alerts rare and worth reading - one incident one page, summaries that list what varied, longer windows for incidents that keep going, operator attribution and allowlists.
---

# Noise control

An alert nobody reads is worse than none. Hermian's rules are built to stay
quiet on a normal host, and the alert pipeline folds what's left.

## One incident, one page

Every finding has a signature describing the incident, not the event. Within
the dedup window (`notifications.dedup_window_secs`, 300 s by default):

- the first occurrence is sent at once;
- repeats are counted, not sent;
- when the window closes, one **LOW summary** ("Repeated: …") says how many
  times it recurred and **lists what varied**: the first destinations, the
  first executables, and how many distinct ones there were.

```text
LOW  Repeated: Outbound connection from a flagged process chain
     The pattern recurred 49 more times within 5 minutes of the original alert.
     Destinations   77.239.112.0:1080, 77.239.112.1:1080, 77.239.112.2:1080,
                    77.239.112.3:1080, 77.239.112.4:1080, ... (50 distinct)
```

Signatures are chosen per rule. A flagged program calling 50 addresses is one
incident (keyed on the program); one implant preloading into `node`,
`timeout` and `ls` is one incident (keyed on the chain's root). Rules that
judge file content are keyed on the content, so a harmless edit can't hide a
malicious one made a minute later.

**Escalation always breaks through**: if the same incident gets worse (HIGH to
CRITICAL), the new severity is sent at once.

## Incidents that keep going

An incident still recurring when its window closes gets a longer window next
time: 5, then 15, then 45 minutes, then hourly. A cryptominer that keeps
calling out pages a few times an hour instead of every five minutes. A quiet
window resets it.

## Operators and installers

Most changes on a server are made by its admins and its package manager. The
[attribution](how-it-works#who-did-it-operator-or-not) step tells them apart
from unattended writes:

| Change made… | Typical result |
|---|---|
| From an interactive session (SSH, sudo, tmux) | INFO, for context |
| By a package or config manager, content clean | Nothing |
| By the real tool (`crontab`, `visudo`, `usermod`) from a session | Nothing or INFO |
| By no session, no known tool | HIGH |
| With content that downloads and runs code, whoever wrote it | CRITICAL |

## Internet noise

- Failed SSH logins from scanners are everywhere. A burst is INFO; what pages
  is a **login right after a burst** from the same source.
- Failed logins for usernames that don't exist (`admin`, `test`, `oracle`…)
  never count. Attempts against real accounts are summed up in one
  **brute-force digest** every `ssh.brute_digest_hours` (2 by default), only
  listing sources with at least `ssh.brute_min_attempts` (10) attempts.

## Allowlists

When something legitimate keeps firing, prefer fixing the rule (open an issue
with `hermian show <ref> --json`). When it's specific to your host, add an
allowlist entry to `/etc/hermian/config.toml`. Every entry needs a `reason`:

```toml
[[allowlist.process_chains]]
parent = "php-fpm8.2"
child  = "sh"
user   = "www-data"
reason = "PHP mail() via sendmail"
```

There are allowlists for SSH sources, process chains, persistence paths,
destinations, binaries and debuggers. The full list is in
[Configuration](configuration#allowlist). An allowlist change pages CRITICAL
like any functional config change, so a quiet exception can't be slipped in.
