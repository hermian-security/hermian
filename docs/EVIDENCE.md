# Evidence

What Hermian has actually been verified to do, where, and when. This is the
source of truth for numbers in the README, release notes, and PROJECT.md. If a
number isn't here, treat it as unproven.

The project is in beta; the [burn-in matrix](ROADMAP-BURN-IN.md#3-burn-in-matrix-phase-2-gate)
is in progress. "Validated on one host" means exactly that: one host has
completed a full field pass, not a fleet.

## Build and tests

| Suite | What it covers | Last result |
|---|---|---|
| `cargo test -p hermian-core --locked` | Detection engine, synthetic events | 158 passing, 2026-10-15 |
| `cargo test -p hermian --locked` | Daemon logic (Linux only) | 103 passing, 7 ignored, 2026-10-15 |
| PAM module tests | The PAM hook shim | 2 passing, 2026-10-15 |
| `tests/helpers` | Suite plumbing (alert waits, disposable-host guard) | 20 passing, 3 skipped, 2026-10-15 |

CI runs all of these on every change. Synthetic tests don't prove live
collection works on a host; the field runs below are what covers that.

## Field runs

### Burn-in host (September 2026)

Ubuntu 22.04, kernel 6.8, 2 vCPU. Sources: CHANGELOG 0.1.0-beta.5 and
[ROADMAP-BURN-IN.md](ROADMAP-BURN-IN.md).

- Attack suite: 7 of 7 scenarios fired at the expected severity. The seven:
  web-shell chain, SSH key injection, cron persistence, systemd unit,
  `ld.so.preload`, fileless exec, setuid drop.
- False positives: 0 HIGH+ across 26 admin and unattended operations (idle,
  admin edits, web, dev, ansible, CI workloads).
- Overhead: around 0.1% CPU, 19 MB RSS, ~80k events over 3 hours.
- Detection to Telegram: ~2 s in one measured run (400 ms inotify debounce
  plus delivery). One measurement, not a percentile; the setuid sweep can
  take ~20 s by design.

### Production VPS (soaking since 2026-09-20)

Ubuntu 22.04.5, kernel 5.15.0-170, 2 vCPU. Sources: deployment notes and
`hermian status`.

- Installed as beta.2, upgraded in place twice since, once with a config
  merge that added new settings as comments (backup kept, reload reported no
  functional change).
- Running since 2026-09-20 apart from upgrade restarts; real HIGH alerts
  delivered and reviewed (root SSH login from a new source, brute-force
  digests).
- No attack or false-positive workloads were run here; it's a production
  host, not a disposable one.
- Dead-man switch exercised on 2026-10-15 (deployed build, sha `180f15d6…`):
  SIGKILLing the daemon paged HIGH on the next start (unclean shutdown,
  HER-2026-1015-188); freezing it with SIGSTOP paged HIGH after 3m42s of
  stale heartbeat and the watchdog restarted it (HER-WD-20261015-170218),
  heartbeat back to 0s. The durable alert queue is covered by tests but
  hasn't faced a real channel outage yet.
- Once-per-sighting novelty verified on 2026-10-15 (deployed build, sha
  `49dc976e…`): a root login from an operator IP that appeared after the
  baseline window paged HIGH `Root login from a new source`
  (HER-2026-1015-210), the IP was written to `baseline.json`, and the next
  login from the same IP was INFO only (HER-2026-1015-211). Both summaries
  named the auth method (`(key)`). Before this build the same login re-paged
  HIGH every time.

## Numbers that looked inconsistent

Older drafts disagree; this is the current reading:

| Seen in older drafts | What it means |
|---|---|
| 13/13 | The full `run_suite.sh`: 7 attacks + 6 false-positive workloads. 13/13 per host is the matrix gate; a complete 13-check run hasn't been recorded on a matrix host yet. |
| 7/7 | The attack half of that, on the burn-in host. |
| kernel 5.15 vs 6.8 | Two hosts: the burn-in host ran 6.8, the production VPS runs 5.15. |
| ~5 hours of field time | The burn-in host's first afternoon. Superseded: the production VPS soak since 2026-09-20. |

## Not proven yet

- Any distro but Ubuntu 22.04: RHEL family with SELinux, the kernel 5.4
  fallback path, and arm64 are untested.
- Automatic isolation under a real incident (unit tests only). Telegram
  buttons have been pressed live on the production VPS, but not during an
  actual attack.
- Durable alert queues under a real channel outage (unit tests only so far;
  the watchdog and unclean-shutdown paths have run live on the VPS).
- A heartbeat or independent tamper monitor beyond the local watchdog.
- Release verification reproduced on a clean machine: `sha256sum -c`,
  `gh attestation verify`, `cosign verify-blob`.
- An install from a release-served `install.sh`: its remote path has only run
  with `--dry-run` (in WSL, against the beta.5 assets; `gh` attestation and
  checksums pass, and the checksum-only branch was exercised). No install from
  a release asset yet.
