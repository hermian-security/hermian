# HERMIAN v0.1.0-beta - Production burn-in roadmap

This is the plan for taking the beta from "one host, one afternoon" to
"defensible production readiness". It follows PROJECT.md sections 11, 20
(Phase 2) and 21 exactly, and is written so that someone who is not the
author can execute it.

Everything below has been exercised at least once on a real host
(Ubuntu 22.04.5, kernel 5.15, 2 vCPU) except where marked **untested**.

---

## 0. Where we are

| Area | State | Evidence |
|---|---|---|
| Detection engine | 5 groups, 77 unit tests, clippy clean | `cargo test` |
| Live attack matrix | 13/13 scenarios fire at expected severity | `tests/attacks/run_attack.sh` on host |
| False positives | 0 HIGH+ across 26 admin/unattended operations | `tests/false_positives/*.sh` on host |
| Overhead | 0.1 % CPU, 19 MB RSS, 80 k events/3 h | `hermian status` |
| Packaging | `.deb` builds, installs, upgrades in place | `cargo deb` on host |
| Notifications | Telegram + email verified through the daemon | `hermian notify-test` |
| Field time | ~5 h on one host | `soak.jsonl` |

The gap to production is **breadth and time**, not features.

---

## 1. Build and release

### 1.1 Toolchain reality

`cargo install bpf-linker` needs LLVM 21+ on the system; most distros ship
14-18 and GitHub runners have none. Requiring it on every build host is how
we lost two hours on the test box and the first CI run. **Always install the
static prebuilt binary** from aya-rs releases (LLVM bundled, ~100 MB):

```bash
curl -fsSL https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
  | sudo tar --zstd -x -C /usr/local/bin bpf-linker
```

The build has three tiers, tried in order:

1. **From source** - nightly with `rust-src` plus the prebuilt `bpf-linker`.
   Used by developers and CI.
2. **Vendored object** - `hermian-ebpf/prebuilt/hermian-ebpf.o` is
   committed. Any host with plain Rust can build the daemon. The object is
   kernel-version independent (struct offsets come from the running kernel's
   BTF at start).
3. **Explicit path** - `HERMIAN_EBPF_PREBUILT=/path/to/hermian-ebpf.o`.

CI builds from source with `HERMIAN_EBPF_FROM_SOURCE=1` and fails if the
vendored object is stale, so tier 2 can never drift.

### 1.2 Local release build (any Linux, Rust >= 1.79)

```bash
sudo apt install -y build-essential pkg-config libpam0g-dev   # Debian/Ubuntu
cargo install cargo-deb --locked

cargo build --release            # daemon + PAM module; uses vendored eBPF if needed
cargo test --release             # 77 core + 12 daemon tests
./target/release/hermian test    # 9 synthetic scenarios against the built binary

cargo deb -p hermian --no-build -o dist/          # dist/hermian_0.1.0-1_amd64.deb
make release                                       # dist/hermian-0.1.0-linux-amd64.tar.gz
```

**Build on the oldest glibc you intend to support.** The `.deb` records the
build host's glibc as a dependency; a package built on Ubuntu 24.04 needed
glibc 2.39 and refused to install on 22.04. Built on 22.04 the requirement
is `libc6 >= 2.34`, which covers Debian 12, Ubuntu 22.04+, RHEL 9+. Release
builds run on `ubuntu-22.04` for this reason.

### 1.3 Signed releases (GitHub Actions)

`.github/workflows/release.yml` runs on every `v*` tag:

1. Builds the eBPF object from source; fails if it differs from the vendored one.
2. Builds `amd64` and `arm64` on Ubuntu 22.04 runners.
3. Runs core tests and `hermian test` on the built binary.
4. Produces `.deb` + `.tar.gz` per arch, `SHA256SUMS`, and **Sigstore
   keyless signatures** (`*.sigstore` bundles) bound to the repository's
   workflow identity - no long-lived GPG key to protect.
5. Publishes a GitHub pre-release (tags containing `-`) or release.

To cut a release:

```bash
git tag -a v0.1.0-beta.2 -m "..." && git push origin v0.1.0-beta.2
```

**Untested:** the `arm64` runner and the Sigstore step have not been run
yet; expect one iteration on the first tag.

### 1.4 What PROJECT.md asked for and what we ship

PROJECT.md §19 lists `.deb`, `.rpm`, AUR, and a signed tarball, with GPG.
For the beta:

| Artifact | Beta | Why |
|---|---|---|
| `.deb` (amd64, arm64) | **yes** | Target users are overwhelmingly Debian/Ubuntu VPS |
| Signed tarball + `install.sh` | **yes** | Distro-agnostic fallback |
| Sigstore instead of GPG | **yes** | Same guarantee, no key custody problem for a solo maintainer; GPG can be added later |
| `.rpm` | Phase 3 | Needs a Fedora/RHEL burn-in first (§3 below) |
| AUR | Phase 3 | After `.rpm` |
| apt repository | later | A bare `.deb` download + verification is fine for a beta |

---

## 2. Install on a production host

### 2.1 Pre-flight (2 minutes)

```bash
uname -r                                  # >= 5.8 for eBPF; 5.4-5.7 runs in reduced mode
ls /sys/kernel/btf/vmlinux                # present = exact parent resolution
systemctl is-active auditd                # if active, the audit fallback is skipped (fine)
sysctl fs.inotify.max_user_watches        # hermian enable raises this to 524288 if lower
```

### 2.2 Install (`.deb`)

```bash
# verify
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp 'https://github.com/<org>/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

# install; postinst runs `hermian enable`
sudo apt install ./hermian_0.1.0-1_amd64.deb
sudo hermian status
```

Expected within 10 seconds: `PROTECTED`, all five rows `on`, `Kernel ... eBPF`.
If you see `reduced: no eBPF`, read `journalctl -u hermian -n 20`; the two
causes met so far were both fixed in the unit (`LimitMEMLOCK`,
`MemoryDenyWriteExecute`) - anything new is a bug to report.

### 2.3 Wire a notification channel (do this before walking away)

See README "Getting notified". Minimum for a beta host:

```toml
[notifications]
channels = ["journald", "file", "telegram"]
[notifications.telegram]
bot_token = "..."
chat_id = "..."
```

```bash
sudo hermian notify-test      # must print SENT
```

### 2.4 Baseline

The first 24 h are the learning window (SSH sources, network peers). Novelty
rules stay quiet until it completes. On a freshly provisioned host with no
history worth learning, `sudo hermian enable --no-baseline`.

### 2.5 Upgrade

```bash
sudo apt install ./hermian_<new>_amd64.deb   # postinst re-runs enable, restarts the daemon
```

Verified: reinstall over a running daemon keeps state, alerts, baseline and
the soak clock; the binary hash is refreshed so no false integrity alert.

### 2.6 Remove

```bash
sudo hermian uninstall --yes     # unit, state, logs, sysctl, PAM hook, binary
# or
sudo apt purge hermian
```

---

## 3. Burn-in matrix (Phase 2 gate)

PROJECT.md §11 requires **72 h with zero HIGH/CRITICAL** per environment and
**every simulated attack detected within 5 s**. Run the matrix below; each
cell is one disposable host.

| # | Environment | Distro / kernel | Purpose | Status |
|---|---|---|---|---|
| A | idle VPS + sshd + nginx | Ubuntu 22.04 / 5.15 | reference | **running** since 2026-09-20 |
| B | active web | Debian 12 / 6.1, nginx + php-fpm under `wrk` 100 r/s | D1/D5 noise under real traffic | untested |
| C | developer workstation | Ubuntu 24.04 / 6.8, cargo, npm, docker, VS Code | `/tmp` exec, LD_PRELOAD, docker parent chains | untested |
| D | SSH-active + Ansible | Debian 12, 3 users, `ansible-pull` every 10 min | D2/D3 attribution under CM tooling | untested |
| E | CI runner | Ubuntu 22.04, GitHub Actions self-hosted runner | build chains, container spawns | untested |
| F | RHEL family | Fedora 40 or Rocky 9 / 6.x, SELinux enforcing | `rpm`, `dnf`, `journalctl`-only auth, SELinux vs eBPF/audit | untested |
| G | old kernel | Ubuntu 20.04 / 5.4 | the `/proc` + audit fallback path | untested |
| H | arm64 | Debian 12 on Ampere/Graviton | eBPF object + syscall numbers on aarch64 | untested |

F, G and H are the ones most likely to find bugs of the kind found today.

### 3.1 Per-host procedure (about 20 minutes plus 72 h)

```bash
# 1. install and wire notifications (§2)
# 2. attack matrix - all must PASS
sudo tests/run_suite.sh --skip-fp
# 3. operator workload - must produce 0 HIGH+
sudo tests/false_positives/run_false_positive.sh admin-edit 300
# 4. start the soak clock and the hourly snapshot
sudo cp tests/soak/hermian-soak-snapshot /usr/local/bin/
sudo tests/soak/start.sh
# 5. use the host normally for 72 h
# 6. read the result
sudo tests/soak/report.sh
```

The report prints HIGH+ count since the soak started, grouped by rule, and
the p50/p99 CPU and RSS. **Pass** = 0 HIGH+ not attributable to a real
event, CPU avg < 1 %, RSS < 80 MB.

### 3.2 What to do with a false positive

Every FP is a rule defect until proven otherwise:

1. `hermian show <ref>` - read the chain/facts.
2. Decide: (a) rule is wrong, (b) attribution failed, (c) genuinely
   host-specific. Only (c) gets an allowlist entry.
3. For (a)/(b): reproduce in a unit test in `hermian-core`, fix, rerun the
   suite, redeploy.

Keep a `docs/fp-log.md` with one line per FP: host, rule, cause, fix. That
log is the evidence behind any public claim about FP rate.

### 3.3 Latency check

Detection-to-notification < 5 s is a gate. Measure once per host:

```bash
T0=$(date +%s.%N)
sudo systemd-run --quiet --collect sh -c 'echo /tmp/x.so >> /etc/ld.so.preload'
# watch the Telegram message arrive; note wall time; then
sudo sed -i '/x\.so/d' /etc/ld.so.preload
```

On host A: ~2 s (400 ms inotify debounce + delivery).

---

## 4. Exit criteria for "production ready"

All of the following, with evidence linked from the release notes:

- [ ] Hosts A-H each completed 72 h with 0 unexplained HIGH+.
- [ ] Attack matrix 13/13 on every host, < 5 s each.
- [ ] CPU avg < 1 %, p99 < 5 %, RSS < 80 MB on every host.
- [ ] `docs/fp-log.md` published; every entry closed.
- [ ] Release workflow ran green on a tag; artifacts verified with `cosign` on a clean machine.
- [ ] `hermian uninstall` leaves nothing on every distro.
- [ ] Two hosts the maintainer depends on have run the release build for 30 days.

When the boxes are ticked, retag as `v0.1.0`.

---

## 5. Sequencing

| Week | Work |
|---|---|
| 1 | Push tag, fix the release workflow until green. Provision B, F, G. Run §3.1 on each. Fix what breaks. |
| 2 | C, D, E, H. Start `fp-log.md`. Implement `hermian dismiss/ack` (see next section). |
| 3-4 | Let soaks run. Address FP log. Add log rotation for `alerts.log` and pruning of `alerts/*.json`. |
| 5 | Review evidence against §4. Retag or extend. |

---

## 6. Appendix - things that bit us on host A and are now fixed

Kept here so nobody re-learns them.

| Symptom | Cause | Fix |
|---|---|---|
| eBPF verifier rejected exec program | 400-byte struct on the 512-byte BPF stack | per-CPU scratch map |
| perf mmap EPERM | `MemoryDenyWriteExecute`, `LimitMEMLOCK=64K` | dropped MDWE, `LimitMEMLOCK=infinity` |
| 0 inotify watches, status still PROTECTED | another process exhausted `max_user_watches` | sysctl in package; status shows watch health |
| setuid in `/tmp` invisible | `PrivateTmp=true` | removed; added setuid sweeper |
| web->shell chain never fired | `sys_enter_execve` sees the *old* comm; `exec` keeps the PID | `sched_process_exec` hook; per-PID re-exec history |
| root login HIGH every time | rule had no memory | HIGH first time per source, INFO after |
| `useradd` -> shadow HIGH | writer exited before inotify fired | "user-mgmt tool ran in last 8 s" attribution |
| `.deb` refused to install | built on newer glibc | build on oldest supported distro |
