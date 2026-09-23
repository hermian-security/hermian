# Changelog

Noteworthy changes are recorded here before release. Versions follow Semantic
Versioning; release preparation moves entries from Unreleased into a dated section.
Earlier release information remains in the repository's GitHub Releases and Git history.

## Unreleased

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
