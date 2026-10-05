# Changelog

Noteworthy changes are recorded here before release. Versions follow Semantic
Versioning; release preparation moves entries from Unreleased into a dated section.
Earlier release information remains in the repository's GitHub Releases and Git history.

## Unreleased

### Added

- Alert retention: stored alerts and collect bundles older than
  `general.alert_retention_days` (default 90; 0 keeps them) are deleted
  hourly, and `alerts.log` rotates at 50 MB with three old copies kept.

### Security

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
- Exited ancestors of a live process are all kept in the tree, not just its
  parent, so a double-forked implant keeps the web server in its chain.
- D1 flags escalate related connects, listeners and `/tmp` execs for ten
  minutes (was two, beaten by a `sleep 130`).
- A setuid file under `/opt` (vendor helpers like chrome-sandbox) is HIGH,
  not CRITICAL. The default config shows how to allowlist PHP `mail()`.

### Fixed

- Ref ids follow the wall clock and never go backwards, so a late event or a
  clock step around midnight can't reissue an id and overwrite an alert file.
- The staging heuristic works on words: `ssh` and `flush` aren't shells (an
  rsync cron job touching `/tmp` was CRITICAL), and a unit is only flagged
  when the program, not an option like `--socket /tmp/x`, sits in `/tmp`.
  `base64 -d | sh` and a cron job running a `/tmp` binary are flagged.
- Off-hours windows are in the host's local time, not UTC.
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

### Changed

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

### Upgrade

- If you send email through a remote SMTP server with `smtp_security =
  "none"` and credentials, switch to `"starttls"` or `"tls"`.

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
