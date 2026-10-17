# Changelog

Noteworthy changes are recorded here before release. Versions follow Semantic
Versioning; release preparation moves entries from Unreleased into a dated section.
Earlier release information remains in the repository's GitHub Releases and Git history.

## Unreleased

### Added

- A start-up audit, also available as `hermian audit` (`--json`; exits 2
  when it finds something serious). It looks for signs that the host was
  compromised before Hermian started: a library in `/etc/ld.so.preload`,
  programs running and libraries loaded from /tmp, /dev/shm or hidden system
  directories, programs and libraries in system directories that no package
  owns, and crontabs and shell profiles that start any of these. If it finds
  any, you get one alert (CRITICAL when the signs are of more than one
  kind), and a baseline still learning stops, so the intrusion isn't learned
  as normal. On a perfctl-infected test host it reported the preload
  rootkit, the implant and a hidden loader under /var in under a second, with
  the rootkit loaded into it. Libraries unpacked into /tmp by runtimes such
  as Nx or Netty are listed as LOW and don't page.

### Changed

- The installer has the CLI's look: the same header, brand colours on a
  terminal (`NO_COLOR` and `HERMIAN_COLOR` respected), one line per step,
  and next steps at the end. It now says whether the service is actually
  running, and apt's own output is quieter.

### Fixed

- The baseline no longer learns an intrusion as normal. Connections from a
  chain D1 flagged, or from a program running out of /tmp, /dev/shm or a
  deleted file, aren't learned, and neither is a login through a hidden key
  file. On an infected host the implant's programs and its C2 addresses
  used to become "known", which silenced the novelty rules for them.
- `hermian enable --no-baseline` skips the learning period as its help
  says. It used to switch the novelty rules off for good. A missing
  baseline.json now starts a new learning period instead of doing the same.
- 0.0.0.0, `::` and loopback are no longer recorded as destinations.

## 0.1.0-beta.12 - 2026-10-17

The CLI gets the identity: one header on every screen, grouped help, brand
colours. Retired config settings are commented out on upgrade, and `status`
warns when the command and the daemon are different versions.

### Changed

- The CLI wears the identity. Every screen (status, alerts, report, test,
  notify-test) opens with the same header: the mark, `hermian`, the version
  or screen name, and context on the right. `--help` groups the commands
  (everyday, setup, response, remove) and ends with examples and links.
  Severities use the brand colours. `--version` output is unchanged.
- `hermian status` says so when the shell's `hermian` and the daemon run
  different versions, which usually means a stale copy earlier in `PATH`.

### Deprecated

- `general.log_level`, `ssh.off_hours_start` and `ssh.off_hours_end` do
  nothing (off-hours scoring was removed earlier; `log_level` was never
  used). Configs that set them still load. `hermian enable`, which runs on
  every upgrade, now comments them out, with a note, keeping a backup. They
  stop being accepted at v0.1.0.

### Fixed

- When the Telegram button poller gets HTTP 409, `hermian status` now
  names the usual cause on a fleet: another host with `actions = true`
  sharing the same bot (each press reaches only one of them). It used to
  blame a webhook only. `docs/FLEET.md` explains the setup: one bot for
  every host's alerts, a bot of its own only where you want buttons.

## 0.1.0-beta.11 - 2026-10-16

Quieter by default, a report for beta testers, and the first release on the
signed APT repository `apt.hermian.me`. Hosts on an earlier version: rerun the
one-line installer once, and `apt upgrade` takes over from there.

### Added

- `hermian report`: a summary to send the maintainers during the beta.
  Version, OS, kernel, coverage, how long it's been installed, alert counts
  by severity and by rule over the last 7 days (`--days`), delivery health
  and overhead, under the identity banner. Nothing private: no host name,
  addresses, users, paths or commands (titles that would name one are
  withheld). `--json` for the same data as JSON.
- A signed APT repository, `apt.hermian.me`, published by the release
  workflow: `beta` for every prerelease, `stable` from v0.1.0. On
  Debian/Ubuntu the installer adds it (key from the release, checked like the
  `.deb`), so `apt upgrade` keeps Hermian current; `--no-apt-repo` skips it.
  `hermian uninstall` and `apt purge` remove the entry and the key. Until the
  repository's signing key is configured, releases and installs behave as
  before.

### Changed

- Less noise. "Script executed from a shell" (cron or a service running a
  script through sh) is gone: no other rule used it, and it was 82% of the
  test VPS's alert store. `hermian alerts` lists LOW and above by default
  and says how many INFO alerts from the last day it left out; `--all`
  includes them, `-s` still picks a level.
- A restart by `hermian enable` (every install and upgrade) is logged as
  INFO, "Hermian is restarting", instead of paging "Hermian is stopping".
  Any other stop still pages HIGH.
- `hermian alerts 182` and `hermian alerts show 182` work like
  `hermian show 182`.
- The hidden key source alert says the path is *included* in the setting
  (`AuthorizedKeysFile` usually lists several).

## 0.1.0-beta.10 - 2026-10-16

Redesigned alerts, SSH logins that say which key got in, and a new check
for hidden SSH key files.

### Added

- Hidden SSH key sources are caught. Hermian audits sshd's effective
  configuration (`sshd -T`) at start and every ten minutes, and pages once
  when `AuthorizedKeysFile`, `AuthorizedKeysCommand`, the principals
  settings or `TrustedUserCAKeys` point into `/dev`, `/tmp`, `/run` or a
  hidden directory, including a setting that was there before Hermian was
  installed. A login with a key from such a file pages too, whatever the
  source address. (Found by planting a key in `/dev/.cache/rdpii` on the
  test VPS: nothing noticed it before.)

### Changed

- Alerts are redesigned in Telegram, email and Discord:
  - **Telegram:** `◉◉◉○  HIGH · Persistence` header (the host moves to the
    fact sheet), the title on its own line, the sentence as a quote, a
    tap-to-copy fact sheet (host, facts, process chain, rule, time), then
    the risk and next steps in a collapsed quote so the push stays short.
    Detail is shed automatically to stay under Telegram's 4096 characters.
  - **Email:** an ink header band with the lockup, the severity as a pill
    with a drawn four-dot meter, a spec grid (host, detected, facts), numbered
    steps, both commands in one terminal block, and the Hermian Security
    lockup in the footer. The subject is now
    `[Hermian] HIGH: <title> (<host>)`, so the useful part survives inbox
    truncation. Both logos are inline images (about 1.1 KB each); nothing is
    loaded from a server.
  - **Discord:** brand colours, the mark as avatar, meter and detection in
    the author line, host and a live relative time, risk and steps as fields.
    Alert text can no longer ping anyone (`allowed_mentions` is empty), even
    if it carries `@everyone` from an attacker-chosen username.
- "Why this matters" is now **Risk** and "Recommended action" is **Next
  steps**, in the CLI and every channel.
- SSH login alerts say how the login authenticated: the key's type and
  fingerprint, and the authorized_keys file and line it sits on (with its
  comment, often `user@machine`), or "password". The daemon fingerprints
  the keys in the files sshd actually reads (`AuthorizedKeysFile` from
  `sshd -T`) itself; nothing is spawned per login.
- Fewer root-login pages for dynamic IPs: a key that has logged in before,
  from a new address on a network (/16, or /32 for IPv6) the account already
  logs in from, is now INFO. Password logins, keys never seen before and
  genuinely new networks still page.

## 0.1.0-beta.9 - 2026-10-16

An installer fix for hosts moving from the tarball to the `.deb`.

### Fixed

- Moving from the tarball to the `.deb` with `install.sh` left the old
  `/usr/local/bin/hermian` in place, ahead of the package's `/usr/bin/hermian`
  in PATH, so `hermian status` and every other command kept running the old
  version (the daemon itself was upgraded). The installer now removes it,
  after checking it really is a hermian binary, and says so.

## 0.1.0-beta.8 - 2026-10-16

The new identity reaches the product: the CLI banner, Telegram alerts and
alert emails now match the site, with a dot severity meter and the real logo
in emails.

### Changed

- `hermian enable` opens with the new identity: the mark (three strokes and
  the signal dot, the only coloured part) beside the wordmark and tagline.
  `--quiet` (used by the package) still prints nothing.
- Telegram alerts are laid out for scanning: `◉◉◉◉ CRITICAL · web-01`, the
  headline, the sentence as a quote card, a quiet `hermian · D1 · time` line
  and the `hermian show` command. Same content as before; the evidence still
  stays in the CLI.
- Alert emails use the identity: brand row, severity stripe and meter, the
  process chain drawn like a terminal with the flagged process in red, facts,
  why it matters, numbered next steps and the command to run. Severity
  colours follow the site (CRITICAL red, HIGH purple), there's an inbox
  preview line, and a dark palette for clients that support it. The logo
  travels inside the message as a small inline image (about 0.6 KB), so
  nothing is loaded from a server and there's no read tracking.
- The severity meter is now dots (`◉◉◉◉` CRITICAL to `◉○○○` INFO), echoing
  the logo, in the CLI, Telegram and email alike.
- The product is written "Hermian" everywhere people read it: CLI headers,
  alert titles, webhooks, the email sender, systemd unit descriptions and the
  docs. The default email subject prefix is now `[Hermian]`; configs written by
  earlier installs spell out `[HERMIAN]`, so their mail filters keep working.
  The PAM marker in `/etc/pam.d/sshd` is unchanged.
- The README is rewritten and shows the new logo, with a dark-mode variant.

## 0.1.0-beta.7 - 2026-10-15

The first release with the one-command installer: a dead-man switch, durable
alert queues, Telegram response buttons, a brute-force digest, and hardening
across the engine, collectors, isolation and packaging.

v0.1.0-beta.6 was tagged but never published: its arm64 build failed on a
lint that only fires on that architecture (#53). Everything below ships here.

### Added

- Telegram response buttons (off by default; `notifications.telegram.actions`
  plus `allowed_user_ids`):
  - A brute-force digest every 2 hours, only when failed logins targeted
    accounts that exist and can log in (or root), with `Block <ip>`,
    `Block all` and `Ignore 2h`. It warns when root can log in with a
    password (checked with `sshd -T`), with a `Remind me in 7 days` button.
  - Suspicious logins (after a burst, from a new source, root from a new
    place) get `Ignore`, `Disconnect session` and `Disconnect and block`.
  - Buttons act immediately, work only for the listed user ids in the
    configured chat, expire, and each works once. Presses are fetched by
    outbound polling, so nothing listens on the host. Each one is answered
    in the chat and recorded as a local alert.
  - Blocks live in their own nftables table with a timeout
    (`response.block_duration_hours`, default 24); IPv6 is blocked per /64;
    management CIDRs and allowlisted sources are never blocked.
    `hermian blocked` and `hermian unblock <ip>` manage them.
- `hermian enable` (which upgrades run) adds settings and sections new in
  this version to an existing `config.toml`, commented out next to where
  they belong, with their explanations. Values are never changed: the file
  must read back as exactly the same settings or it's left alone. A backup
  is kept as `config.toml.bak`. Configs from early betas, which had no
  Telegram or email section, now show them.
- The default config documents every option: what each detection group
  covers, `message_thread_id`, what `management_cidrs` is for, and an
  allowlist example for your own SSH sources.
- Telegram alerts open with a `■■■□ HERMIAN - HIGH` header (filled cells
  count up with severity), `Host : web-01`, the bold title, and a sentence
  or two: what happened and where, then a `hermian show` line. Evidence,
  process chains, the why and the steps stay in the CLI; they were the same
  story three times in a chat window. No emoji, and the whole alert is
  no longer repeated underneath. The brute-force digest lists its sources
  on one line instead of emitting a raw newline escape in the value, and
  the disconnect button reads `Disconnect session`.
- Alert retention: stored alerts and collect bundles older than
  `general.alert_retention_days` (default 90; 0 keeps them) are deleted
  hourly, and `alerts.log` rotates at 50 MB with three old copies kept.
- The dead-man switch: the daemon writes a heartbeat to its run directory
  every 30 s, and a new `hermian-watchdog` systemd timer (installed by
  `hermian enable`, checked every minute) pages HIGH and restarts the
  daemon when the heartbeat goes stale. A crash or SIGKILL is reported on
  the next start. `status` shows the heartbeat age.
- Durable alert queues: alerts waiting for a notifying channel are written
  to `state/pending/<channel>/` and reloaded after a restart, so delivery
  is at-least-once (a crash mid-send can duplicate an alert, never lose
  one). Retention prunes them with the rest of the store.
- Releases ship an `install.sh` next to the binaries, and the README leads
  with one command: `curl -fsSL .../releases/download/vX.Y.Z/install.sh |
  sudo sh`. It's served from the same tag it installs, picks the `.deb` on
  Debian/Ubuntu or the tarball elsewhere, always checks `SHA256SUMS`, and
  verifies it with `cosign` or `gh` when installed (checksum-only, with a
  warning, otherwise). It takes `--version` and `--dry-run`, and the whole
  script runs from one function so a truncated download can't half-run.
  Manual steps and the strict verification flow moved into the README's
  "Verify manually" details.

### Security

- rustls is updated to 0.23.46 for RUSTSEC-2026-0346, -0347, -0348 and
  -0349. It reaches the binary through every Telegram and webhook delivery.
- A web or database shell started through another program (`nginx -> perl
  -> sh`, `awk 'BEGIN{system("sh")}'`) is HIGH like a direct one; only the
  nearest parent used to count. Downloaders behind an interpreter and relay
  tools (nc, socat) anywhere under a service are HIGH too.
- A web shell flag no longer marks the web server itself, so its other
  requests aren't escalated for the next ten minutes.
- Auto-isolation ignores CRITICALs whose web server or database doesn't look
  genuine: the binary must be named like the service in a root-owned
  location, or be a trusted interpreter running as a system account. Any
  local user could otherwise run a program called `nginx` (or rename python
  to it) and cut the host off. The alert still pages.
- Tool exemptions are harder to borrow:
  - A script named like a tool (`/tmp/dnf`, python renamed to `dnf`) isn't
    the package manager; the script's own path has to be trusted.
  - LD_PRELOAD under `make`, `cargo` and friends is INFO only when that build
    tool is really installed, not just named so.
  - Running `visudo -c` or `passwd -S` from a cron job or service no longer
    excuses a direct sudoers/shadow write a moment later. The tool has to
    come from an operator session or a package/config manager.
  - A ptrace from a process we never saw exec (a forked child calling itself
    `gdb`) isn't treated as a debugger; the daemon now reads it from /proc.
  - A TTY or `sudo` under a web server, database or cron isn't an operator
    session (`pty.spawn` from a web shell no longer downgrades alerts).
- The real `crontab` installing a download-and-run job is CRITICAL, and every
  cron line is checked (only the first four were). A package manager writing
  a unit that runs from `/tmp` is reported too.

- A second, different change to the same sudoers, cron, unit,
  authorized_keys, ld.so.preload or account file within the dedup window is
  its own alert; only identical content is folded.
- Account diffs catch more: uid/gid 0 however written (`00`), a service
  account getting a login shell, gid and home changes, and new members of
  docker, lxd, incus-admin, libvirt, disk, shadow and adm.
- ld.so.conf.d checks no longer accept `/libevil`, `/usr/../tmp` or an
  `include` outside ld.so.conf.d.
- DNS/NTP-port connections to a new public address are judged like any
  other once the baseline is done; only the LAN and learned servers are
  skipped.
- A known port bound again on another address (`127.0.0.1:8080` then
  `0.0.0.0:8080`) is a new listener.
- `ExecStart = x` (spaces around `=`) is parsed.
- Listener alerts name the owning process again: the `/proc/net/tcp`
  parser was one field off and read the refcount as the socket inode, so
  the owner was never found.
- Exited ancestors of a live process are all kept in the tree, not just its
  parent, so a double-forked implant keeps the web server in its chain.
- D1 flags escalate related connects, listeners and `/tmp` execs for ten
  minutes (was two, beaten by a `sleep 130`).
- A setuid file under `/opt` (vendor helpers like chrome-sandbox) is HIGH,
  not CRITICAL. The default config shows how to allowlist PHP `mail()`.
- Isolation cuts connections that were already open. A blanket
  `ct state established` rule kept every flow from before the alert alive,
  a reverse shell included. Now only management CIDRs keep their sessions,
  and DNS, metadata and notification endpoints get their replies.
- Trusted install paths are checked for ownership, not just their prefix.
  A tool under `/opt/<app>` owned by a deploy user (or any file or parent
  directory someone other than root can rewrite) no longer earns a package
  manager's or admin tool's exemption.

### Fixed

- Ref ids follow the wall clock and never go backwards, so a late event or a
  clock step around midnight can't reissue an id and overwrite an alert file.
- The staging heuristic works on words: `ssh` and `flush` aren't shells (an
  rsync cron job touching `/tmp` was CRITICAL), and a unit is only flagged
  when the program, not an option like `--socket /tmp/x`, sits in `/tmp`.
  `base64 -d | sh` and a cron job running a `/tmp` binary are flagged.
- Known SSH sources, destinations, and connector programs are recorded for
  the lifetime of the install. They used to freeze when the baseline window
  closed, so a source first seen after it (a new ISP address, a jump host)
  paged `new source` on every login, and programs re-alerted as `first
  outbound` on every connect. Novelty now means first sighting, so each is
  reported once.
- Dedup signatures, auth sources and learned baseline sets are capped, so
  attacker-chosen paths or rotating IPv6 sources can't grow memory without
  bound. Far-past event timestamps are clamped like future ones.

- Self-protection gaps:
  - A missing `binary.sha256` or `config.sha256` pages HIGH at startup
    instead of being quietly re-created (delete it, swap the binary, and
    nothing used to fire).
  - Config reloads compare against the config in effect, so writing the
    hash file before the config no longer skips both the reload and its
    alert.
  - A clean stop pages HIGH and waits a few seconds for delivery.
  - Dropped telemetry (eBPF ring loss, inotify overflow, audit ENOBUFS) pages
    HIGH; `status` shows those totals and alerts a channel gave up on.
- The unit restarts after any exit not requested through systemctl and no
  longer gives up after five quick failures. It also sets `UMask=0077`,
  `ProtectKernelLogs` and a private keyring.

- More persistence surfaces are watched: `/etc/pam.d`, `/etc/environment`
  and `pam_env.conf`, `rc.local`, udev rules, boot-time kernel modules, at
  jobs, vendor units in `/usr/lib/systemd/system`, per-user systemd units,
  and `.ssh` in service-account homes outside `/home` (`/var/www/.ssh`).
  `pam_exec`, a non-system PAM module, `LD_PRELOAD` in the global
  environment and udev `RUN+=` are CRITICAL when unattended.
- The audit fallback only accepts netlink messages from the kernel; other
  local sockets could inject fake exec records. Its exec rule is removed on
  shutdown again (the daemon used to exit before the reader noticed).
- Root reads of user-controlled files use `openat2(RESOLVE_NO_SYMLINKS)` on
  5.6+ kernels, closing the swap-the-parent-for-a-symlink race. Symlinked
  homes and `.ssh` dirs aren't watched.
- `/etc/pam.d/sshd` edits (enable, uninstall) are atomic and keep the file's
  mode and owner; a crash mid-write could leave a broken PAM stack.
- `hermian uninstall` stops the daemon before lifting isolation, and only
  deletes absolute paths with a `hermian` component, so an odd
  `HERMIAN_STATE_DIR` can't point `remove_dir_all` at `/`.
- auth.log rotation is detected by inode within ~2 s and the new file is read
  from the start; lines logged right after a rotation used to be skipped.
- eBPF event conversion (several /proc reads per event) and alert
  persistence (fsync) run off the async workers; the alert queue is bounded
  and overflow is logged and counted.
- Alert records are never overwritten if a ref id repeats, and a failed
  write is logged instead of dropped silently.
- Webhook and Telegram errors have every URL cut to scheme and host, so a
  normalised URL can't leak the secret path or bot token into status or
  syslog.
- SMTP credentials aren't sent over a cleartext connection to a remote host.
- Isolation also drops forwarded traffic (Docker, VMs), keeps cloud metadata
  reachable, loads management CIDRs normalised from the parsed value, and
  refuses `0.0.0.0/0` / `::/0`. New dead-man switch: `hermian isolate --for
  <minutes>` and `response.auto_isolate_revert_mins` lift it via a systemd
  timer.
- eBPF probes:
  - The connect probe reads the address family first, then only that
    family's bytes. A fixed 28-byte read failed (and dropped the event)
    when a `sockaddr_in` sat at the end of a page.
  - `LD_AUDIT` is flagged like `LD_PRELOAD`, and 64 env entries are
    checked (was 32).
  - Exec intents are built on the BPF stack instead of a per-CPU scratch
    slot that a preempted syscall tracepoint could share.
  - 32-bit programs on x86_64 (whose syscalls the hooks don't see) are
    logged, and CPUs hot-plugged after startup page until a restart.
- The PAM module has no JSON dependency and no panic paths left. It runs
  inside sshd under `panic = "abort"`, so a panic there would kill the login.
  Its docs show the absolute module path (a bare name never loads).
- A corrupt BTF blob can't panic the daemon, and `dpkg-query` isn't asked
  about file names that would act as globs.
- One SSH login, one alert: root logging in from a never-seen source fired
  both the root-policy finding and the new-source finding, which meant two
  Telegram messages for one event. The sharper finding is kept; ties keep
  the root-policy alert.
- `apt remove` stops and deletes the watchdog timer too. It used to keep
  firing every minute against the removed binary. Remove and purge now
  match `hermian uninstall`, including the Telegram block table and, on
  purge, the inotify sysctl file.
- `install.sh` piped into `sh` always downloads and verifies. A file named
  `hermian` in the current directory used to switch it to local mode and
  get installed as root unchecked. Local mode now means the script sits in
  an extracted tarball, and `--version` there is an error.
- After a crash, the "unclean shutdown" alert quotes the panic (thread and
  message) instead of guessing between a crash, a kill and power loss.
- Two Telegram `Block` presses at the same moment can't create the block
  table twice.

### Changed

- CI runs clippy on arm64 too, so architecture-specific problems fail the
  pull request instead of the release (#53).
- Destination novelty is judged by network, /24 for IPv4 and /64 for
  IPv6. An app server calling an API or CDN that rotates addresses inside
  a block paged HIGH "Web server connected to a new external destination"
  for each new address. `baseline.json` is unchanged.
- Login alerts name the SSH auth method when the log has it: `(key)` or
  `(password)` after "authenticated" (keyboard-interactive counts as
  password). Nothing is claimed when the method is unknown.
- Alert copy says what was seen instead of what it might mean: an SSH login
  from a new source is no longer called "unusual timing", and "assume the
  host is compromised" reads "potentially" where the evidence is a change,
  not an intrusion.
- Releases need green CI: the release workflow checks the five required
  checks on the tagged commit before building. Release builds also run
  clippy and the full test suite on both amd64 and arm64.
- The eBPF build is pinned to `nightly-2026-09-17` (with bpf-linker
  v0.11.1, it reproduces the vendored object exactly), so a new nightly can't
  break the byte-for-byte check.
- New CI jobs: `cargo deny` (advisories, yanked crates, licenses, sources)
  and an MSRV check. `rust-version = "1.91"` is declared; the docs' old 1.79
  claim didn't build. A yanked `yoke-derive` was updated.
- Checkouts don't keep credentials; `make deb` uses cargo-deb like the
  release (it called `dpkg-buildpackage` with no `debian/` dir), and the
  Makefile picks the host arch.
- Expect a HIGH "HERMIAN is stopping" notice on every stop, including
  package upgrades.
- User management run from cron or a plain service (not a session, package
  or config manager) is now reported when it rewrites `/etc/shadow`.
- Email with `smtp_security = "none"` and a username now fails (with a clear
  error in `status`) unless the SMTP host is loopback.

### Removed

- Off-hours weighting for SSH logins. Administrators log in whenever they
  need to; timing alone isn't evidence. Old `ssh.off_hours_start/end` keys
  still parse but do nothing.

### Upgrade

- If you send email through a remote SMTP server with `smtp_security =
  "none"` and credentials, switch to `"starttls"` or `"tls"`.
- To use the Telegram buttons, set `actions = true` and `allowed_user_ids`,
  then run `sudo hermian enable` once (it grants the capabilities).
- Stored alerts older than 90 days are deleted within an hour of upgrading.
  To keep them, set `general.alert_retention_days = 0` (or back up
  `/var/lib/hermian/alerts/`) first.
- Isolation now drops SSH sessions that don't come from
  `response.management_cidrs`. If you rely on auto-isolation, make sure the
  address you manage the host from is in that list.

## 0.1.0-beta.5 - 2026-09-23

Fixes from the first full run on a real host (Ubuntu 22.04, kernel 6.8): the
attack suite now passes 7/7 there.

### Fixed

- An idle SSH, tmux or desktop session no longer turns unattended changes to
  `authorized_keys`, cron or shell profiles into INFO. Only an operator active
  in the last 15 seconds, or a running editor, downgrades a change whose
  writer is gone (#39).
- The PAM hook runs before `common-auth`, so failed logins reach it. PAM
  attempts are ignored while journald or auth.log already reports failures,
  so nothing is counted twice (#40).
- Every distinct config change pages; a second change within the dedup
  window used to be silent (#41).
- `hermian status`, `alerts` and `show` without sudo say they need root
  instead of "not installed" or "no alerts" (#42).
- Status lists the SSH auth sources actually in use and only claims PAM when
  sshd loads the module (#43).
- A systemd drop-in written into a brand-new `x.service.d` dir is caught right
  away (#44).

### Changed

- README install steps are shorter, cover the tarball path properly, and add
  optional origin checks with `gh attestation verify` or `cosign verify-blob`,
  plus upgrade and uninstall sections.
- Releases carry GitHub build attestations, and their notes are this
  changelog's section for the version with a link to the install steps.
- The attack suite runs itself outside the login session, so launching it
  doesn't count as operator activity.

### Upgrade

- Nothing to do by hand. The package re-runs `hermian enable`, which moves an
  existing PAM hook to its new place. The manual `--with-pam` step from
  beta.4's notes is no longer needed.

## 0.1.0-beta.4 - 2026-09-23

### Security

- Watched files are read with `O_NOFOLLOW|O_NONBLOCK` and must be regular
  files: a FIFO no longer hangs the watcher and a symlink no longer gets read
  as root (#11).
- Forged `sshd` log lines (via `logger` or a crafted SSH username) no longer
  count as logins; journald is preferred and only trusted fields are used (#12).
- Webhook URLs and tokens are redacted from errors, status and logs (#29).
- Control characters and bidi overrides in alert text are escaped (#32).
- Isolation keeps DHCP and IPv6 ND, limits DNS to the configured resolvers, and
  still lets alerts out (#20).
- The attack harness cleans up after every scenario and refuses to run on a
  host that isn't marked disposable (#16).

### Fixed

- The eBPF LD_PRELOAD check never matched; it does now, and scans 32 env
  entries (#17). Failed execs no longer exhaust the exec-intent map (#18).
  Dropped perf events are counted and reported (#23).
- Trusted-tool exemptions need a real system binary (#14) and a non-web
  origin (#15), so `/tmp/dpkg` or a web shell running `crontab` isn't excused.
- D5 judges the connecting process instead of PID 1 (#10), and flagged chains
  alert even on DNS/NTP ports (#9).
- D1 sees shells behind `env`/`setsid`, service → downloader/nc, and
  `curl | sh` download-and-exec chains (#25).
- D3 covers systemd drop-ins, every `Exec*` line, and enable links (#26).
- Exited processes stop counting as live sessions (#24).
- New `.ssh`/home dirs are watched right away (#21); inotify overflows are
  rescanned instead of dropped (#22).
- Each notification channel has its own queue; one broken channel no longer
  blocks the rest, and a message an endpoint always rejects is dropped (#13).
  Dropped alerts are counted (#29).
- Reloads that repoint alert destinations page CRITICAL and notify the old
  destination too (#19).
- Out-of-range config values are rejected instead of crashing the daemon (#27).
- Future-dated events no longer suppress alerts; flags are pruned properly (#28).
- Long PAM usernames no longer drop auth events (#30).
- Audit fallback: quoted names aren't hex-decoded, gid is real (#31).
- `--with-pam` loads the module by absolute path; `apt remove` lifts isolation
  and removes the PAM hook (#33). Re-run `hermian enable --with-pam` once.
- A failing eBPF source build no longer falls back to the vendored object (#35).

## 0.1.0-beta.3 - 2026-09-21

### Changed

- Install docs use curl + `sha256sum` on a pinned tag. `cosign` is optional.
- Release checksums use GitHub asset names (`.` not `~`) so the download URL matches.

## 0.1.0-beta.2 - 2026-09-21

### Changed

- Failed SSH bursts stay INFO. HIGH is a login from that source while the burst
  window is still open.
- Invalid config edits and no-op reloads no longer page CRITICAL. A real
  validated change still does. Self-protection alerts share the dedup window.
- User-facing feat/fix landings now get a new prerelease tag so GitHub Releases
  match `main`, not the previous package.

### Fixed

- Attack validation requires fresh HIGH/CRITICAL JSON evidence instead of accepting
  historical log matches. Failed queries and malformed evidence fail verification.
