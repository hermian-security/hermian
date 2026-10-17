Hermian evidence
================

What Hermian has been verified to do, where and when, what isn't proven
yet, and what has to happen before v0.1.0. Numbers in the README, the
website and release notes come from here. If a number isn't here, treat it
as unproven.


1. Tests

Last run 2026-10-16, on every change in CI:

- hermian-core (detection engine, synthetic events): 165 passing.
- hermian (daemon, Linux only): 127 passing, 7 ignored.
- hermian-pam (the PAM hook): 2 passing.
- tests/helpers (installer, packaging, suite plumbing): 41 passing.

These don't prove live collection works on a host. The field runs below do.


2. Field runs

Host A, the burn-in host (September 2026). Ubuntu 22.04, kernel 6.8,
2 vCPU.

- Attack suite: 7 of 7 scenarios fired at the expected severity (web shell
  chain, SSH key injection, cron, systemd unit, ld.so.preload, fileless
  exec, setuid drop).
- False positives: 0 HIGH or CRITICAL across 26 admin and unattended
  operations.
- Overhead: about 0.1% CPU and 19 MB of memory, 80,000 events in 3 hours.
- Detection to Telegram: about 2 seconds, in one measured run (400 ms of
  inotify debounce plus delivery). The setuid sweep can take up to 20 s by
  design.

The maintainer's VPS (since 2026-09-20). Ubuntu 22.04.5, kernel 5.15.0-170,
2 vCPU. Day-to-day host until 2026-10-16, a disposable test host since.

- Upgraded in place release after release, from beta.2 to beta.11, once
  with a config merge that added new settings as comments.
- Dead-man switch (2026-10-15): killing the daemon paged HIGH on the next
  start; freezing it paged HIGH after 3m42s of stale heartbeat and the
  watchdog restarted it.
- Novelty once per source (2026-10-15): a root login from a new address
  paged HIGH, the next one from it was INFO.
- Full suite (2026-10-16, --quick): self-test 9 of 9, attacks 7 of 7.
  False-positive workloads 5 of 6 at first: the web run's cleanup rewrote
  /root/.bashrc with nobody logged in, which Hermian rightly reported. The
  cleanup was fixed (#60) and admin-edit and web passed again, run with no
  session open.
- Hidden SSH key source (2026-10-16, beta.10): a drop-in pointing sshd at
  /dev/.cache/rdpii paged on the first start, and a login with the key in
  it paged with the file and line.
- Install and updates (2026-10-16, beta.11): the one-line installer from
  the release installed the .deb and added apt.hermian.me; apt verified the
  repository's signature and lists Hermian from it. An earlier tarball
  install's binary was removed so the package's took over (#58).
- Signal to noise (2026-10-17, beta.12): from daemon start to snapshot,
  11 h 44 min, 925,648 events and 3 notifications, plus one LOW repeat
  that was logged, not sent. All four were logins with the planted hidden
  key above, so none was a false alarm. Same window: 23 MB of memory,
  about 0.06% of one core on average. Counted from the alert files since
  started_at; the status screen's "today" alert count resets at midnight
  UTC, so don't pair it with events processed.


3. Not proven yet

- Any distro but Ubuntu 22.04: Debian, the RHEL family with SELinux, the
  kernel 5.4 fallback path, and arm64 on real hardware.
- 72 hours with zero unexplained HIGH alerts on several hosts. The runs
  above were 5-minute workloads.
- Automatic isolation during a real incident (unit tests only).
- The disk-backed alert queue during a real channel outage (unit tests
  only).
- Release verification on a clean machine with cosign and gh attestation.


4. Burn-in plan

Each host is a disposable machine of one kind:

    A  idle VPS, sshd, nginx       Ubuntu 22.04        done (see 2)
    B  busy web server             Debian 12           to do
    C  developer workstation       Ubuntu 24.04        to do
    D  SSH users and Ansible       Debian 12           to do
    E  CI runner                   Ubuntu 22.04        to do
    F  RHEL family, SELinux on     Rocky 9 or Fedora   to do
    G  old kernel                  Ubuntu 20.04, 5.4   to do
    H  arm64                       Debian 12           to do

F, G and H are the most likely to find bugs.

On each host, about 20 minutes plus 72 hours:

    sudo touch /etc/hermian-disposable-host
    sudo tests/run_suite.sh --skip-fp
    sudo tests/false_positives/run_false_positive.sh admin-edit 300
    sudo cp tests/soak/hermian-soak-snapshot /usr/local/bin/
    sudo tests/soak/start.sh
    # use the host normally for 72 hours, then:
    sudo tests/soak/report.sh

A host passes with 0 HIGH not caused by a real event, average CPU under 1%
and memory under 80 MB. Never run the suites on a machine you care about:
they modify real auth and persistence files.


5. Before v0.1.0

- Hosts A to H have each run 72 hours with 0 unexplained HIGH alerts.
- Every attack scenario passes on every host.
- CPU under 1% on average (5% at worst) and memory under 80 MB everywhere.
- The false-positive log below is complete and every entry is closed.
- A release has been verified on a clean machine (sha256sum, gh attestation,
  cosign).
- apt upgrade has delivered a release to a test host. (Repository live since
  beta.11.)
- hermian uninstall leaves nothing behind on every distro.
- Two hosts the maintainer relies on have run the release for 30 days.


6. False positives

Every HIGH or CRITICAL alert that wasn't a real event gets an entry here.
Find the cause: the rule was wrong, the attribution failed, or it's specific
to that host. Only the last kind ends with an allowlist entry; the others
end with a fix and a regression test.

Format: date, host, alert, rule, cause, fix, closed.

None recorded yet. (The web workload alert of 2026-10-16 was a real event
caused by the test harness, not a false positive; see 2.)


7. Things that bit us, now fixed

- The eBPF verifier rejected the exec program: a 400-byte struct on the
  512-byte stack. Fixed with a per-CPU scratch map.
- perf mmap failed with EPERM: MemoryDenyWriteExecute and a 64 KB memlock
  limit in the unit. Both removed.
- No inotify watches while status said PROTECTED: another process had used
  up max_user_watches. The package raises the limit; status shows watch
  health.
- Setuid files in /tmp were invisible with PrivateTmp. It's off, and a
  sweep finds them.
- The web-to-shell chain never fired: sys_enter_execve sees the old name.
  Hooked sched_process_exec instead.
- Root logins paged every time. Now HIGH the first time per source.
- useradd paged on /etc/shadow: the writer exited before inotify fired.
  Recent user-management tools now count.
- The .deb refused to install on 22.04: built on a newer glibc. Releases
  build on Ubuntu 22.04.
- A tarball install's /usr/local/bin/hermian shadowed the package's binary
  after an upgrade. The installer removes it.
- An upgrade's own restart paged "Hermian is stopping". Planned restarts
  are now INFO.
