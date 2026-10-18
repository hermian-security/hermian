---
title: Install
description: Install Hermian on a Linux server with one command, from the signed APT repository, from a release by hand, or from source, and verify where it came from.
---

# Install

## Requirements

| | |
|---|---|
| System | Linux with systemd |
| Kernel | 5.4 or newer. eBPF needs **5.8+**; older kernels run with reduced coverage (see [How it works](how-it-works#collectors)) |
| Architecture | amd64 or arm64 |
| Access | root (Hermian runs as root) |
| Tested | Ubuntu 22.04 (full suites) and 24.04 (live run) in the field; Debian, the RHEL family and arm64 hardware are being verified |

It watches the host. On a container host it sees the host's processes and
files, not what runs inside containers.

## One command

```bash
curl -fsSL https://hermian.me/install.sh | sudo sh
```

`hermian.me/install.sh` redirects to the `install.sh` attached to the newest
release, so what runs is always the release's own script. It:

1. downloads the release for your architecture and its `SHA256SUMS`, and
   checks the checksum;
2. verifies where the release was built, with `cosign` or the GitHub CLI if
   either is installed (it says so and goes on with the checksum alone if
   neither is);
3. on Debian and Ubuntu, installs the `.deb` (apt starts the daemon) and adds
   the signed APT repository `apt.hermian.me`, so `apt upgrade` keeps Hermian
   current; elsewhere, installs the tarball;
4. runs `hermian enable` and shows whether the service is running.

| Option | Effect |
|---|---|
| `--version vX.Y.Z` | Install that release instead of the one the script comes from |
| `--dry-run` | Download and verify, print what would change, change nothing |
| `--no-apt-repo` | Don't add `apt.hermian.me` (updates stay manual) |

```bash
curl -fsSL https://hermian.me/install.sh | sudo sh -s -- --dry-run
```

Rather read it first? Download `install.sh` from the
[release assets](https://github.com/hermian-security/hermian/releases), read
it, then run it with `sudo sh install.sh`.

## From the APT repository

```bash
curl -fsSL https://apt.hermian.me/hermian-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/hermian-archive-keyring.gpg >/dev/null
printf 'Types: deb\nURIs: https://apt.hermian.me\nSuites: beta\nComponents: main\nSigned-By: /usr/share/keyrings/hermian-archive-keyring.gpg\n' \
  | sudo tee /etc/apt/sources.list.d/hermian.sources
sudo apt update && sudo apt install hermian
```

The `beta` suite gets every prerelease; `stable` starts with v0.1.0. apt
checks every download against that key. To compare it with the key a release
ships, download `hermian-archive-keyring.gpg` from the release and diff the
two.

## One release by hand

Pin a release tag (the newest is on the
[releases page](https://github.com/hermian-security/hermian/releases)); don't
script against `latest`. The same steps install and upgrade.

**Debian and Ubuntu:**

```bash
VER=v0.1.0-beta.12
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
DEB=$(grep -o "hermian_.*_$(dpkg --print-architecture)\.deb" SHA256SUMS)
curl -fsSLO "$BASE/$DEB" && sha256sum -c SHA256SUMS --ignore-missing
sudo apt install "./$DEB"
sudo hermian status
```

The package starts the daemon. `/tmp` is only there because apt's sandbox user
can read it.

**Other systemd distros:**

```bash
VER=v0.1.0-beta.12
BASE=https://github.com/hermian-security/hermian/releases/download/$VER
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cd /tmp
curl -fsSLO "$BASE/SHA256SUMS"
TGZ=$(grep -o "hermian-.*-linux-$ARCH\.tar\.gz" SHA256SUMS)
curl -fsSLO "$BASE/$TGZ" && sha256sum -c SHA256SUMS --ignore-missing
tar xzf "$TGZ" && cd "${TGZ%.tar.gz}"
sudo sh install.sh
```

This installs `/usr/local/bin/hermian` and the optional PAM module, then runs
`hermian enable`.

## Verify where it came from

`sha256sum -c` catches a broken download, but `SHA256SUMS` sits next to the
files it describes. To confirm the project's release workflow built them:

```bash
# GitHub CLI (needs gh auth login)
gh attestation verify "$DEB" --repo hermian-security/hermian

# or cosign: verify SHA256SUMS, which then vouches for every file it lists
curl -fsSLO "$BASE/SHA256SUMS.sigstore"
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity "https://github.com/hermian-security/hermian/.github/workflows/release.yml@refs/tags/$VER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Every release is built by GitHub Actions from a tag, signed keylessly with
Sigstore and attested with build provenance. Tags are protected; a human cuts
every release.

## What setup changes

`hermian enable` (run by the installer and by the package on every install
and upgrade) creates:

| What | Where |
|---|---|
| Config, root-only | `/etc/hermian/config.toml` |
| State: alerts, baseline, hashes | `/var/lib/hermian/` |
| Logs | `/var/log/hermian/alerts.log` |
| The daemon's unit and the watchdog timer | `/etc/systemd/system/hermian.service`, `hermian-watchdog.{service,timer}` |
| inotify limits, only if they're too low | `/etc/sysctl.d/60-hermian.conf` |

It records the hashes of the binary and the config, starts the baseline, and
starts the daemon. Out of the box Hermian only logs and notifies: buttons and
isolation are off until you turn them on. The unit runs with
`ProtectSystem=strict`, `NoNewPrivileges` and only the capabilities it needs
([details](self-protection#the-service)).

`hermian enable --with-pam` also hooks the optional PAM module into sshd. It
reports login results, never reads passwords and always returns
`PAM_IGNORE`.

## Upgrade

With the APT repository: `sudo apt update && sudo apt upgrade`. Otherwise
rerun the installer, or the by-hand steps with a newer `VER`. Read the
[release notes](https://github.com/hermian-security/hermian/releases) first:
they list any one-time steps. A restart for an upgrade pages INFO, not HIGH.
New settings are added to your config file, switched off (a single `#` in
front), without touching what you've set.

## Uninstall

```bash
sudo hermian uninstall
```

It asks first, then lifts isolation and removes the units, config, stored
alerts, logs, PAM hook, APT entry and binary. On a package install it ends with
`dpkg --purge hermian`. Save the alerts you want to keep before
(`hermian alerts --json > alerts.ndjson`). `sudo apt purge hermian` does the
same.

## From source

```bash
sudo apt install -y build-essential pkg-config libpam0g-dev
cargo build --release --locked
cargo test --locked
sudo make install
```

A prebuilt eBPF object is included and checked byte for byte in CI.
Rebuilding it needs a pinned nightly and `bpf-linker`; see
[CONTRIBUTING.md](https://github.com/hermian-security/hermian/blob/main/CONTRIBUTING.md).
Packages should be built on the oldest glibc you support: releases build on
Ubuntu 22.04.
