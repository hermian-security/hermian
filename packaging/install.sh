#!/bin/sh
# HERMIAN installer, served from the release it installs and shipped inside
# its tarball. Everything runs from main(), so a truncated download can't
# half-run.
#
# What it changes (the README's "What setup does"):
#   - the binary: /usr/local/bin/hermian, or /usr/bin via the .deb
#   - the optional PAM module; it stays unwired until `hermian enable --with-pam`
#   - `hermian enable`: config, state, logs, systemd unit, inotify limits
# It never edits sshd_config, pam.d or nftables; isolation is opt-in.
#
# Remote (piped, or no hermian binary next to this script): downloads the pinned release,
# verifies it (cosign, else gh, else checksum-only with a warning), picks the
# .deb on Debian/Ubuntu or the tarball elsewhere.
# Local (run from an extracted tarball): installs the files next to the script.
#
#   curl -fsSL https://github.com/hermian-security/hermian/releases/download/vX.Y.Z/install.sh | sudo sh
#   sudo sh install.sh [--version vX.Y.Z] [--dry-run]
set -eu

REPO=hermian-security/hermian
DEFAULT_VERSION=v0.1.0-beta.5   # release packaging rewrites this to the tag

say() { echo "==> $*"; }
die() { echo "hermian: $*" >&2; exit 1; }

run() {
    if [ "$dry_run" -eq 1 ]; then
        echo "    (dry-run) $*"
    else
        "$@"
    fi
}

usage() {
    cat <<'EOF'
Usage: install.sh [--version vX.Y.Z] [--dry-run]

  --version VER   install that release tag (default: the tag this script is from)
  --dry-run       download and verify, print what would change, change nothing
  -h, --help      this text
EOF
}

fetch() { # url dest
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

verify_sums() { # dir version base
    say "verifying SHA256SUMS with cosign"
    fetch "$3/SHA256SUMS.sigstore" "$1/SHA256SUMS.sigstore"
    cosign verify-blob "$1/SHA256SUMS" --bundle "$1/SHA256SUMS.sigstore" \
        --certificate-identity \
        "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$2" \
        --certificate-oidc-issuer \
        "https://token.actions.githubusercontent.com" >/dev/null ||
        die "cosign could not verify SHA256SUMS for $2"
}

install_tree() { # extracted tarball dir
    [ -f "$1/hermian" ] || die "no hermian binary in $1"
    say "installing /usr/local/bin/hermian"
    run install -m 0755 "$1/hermian" /usr/local/bin/hermian
    if [ -f "$1/libpam_hermian.so" ]; then
        say "installing the PAM module (opt in later: hermian enable --with-pam)"
        run install -D -m 0644 "$1/libpam_hermian.so" /usr/lib/security/pam_hermian.so
    fi
    say "running hermian enable"
    run /usr/local/bin/hermian enable
}

install_local() { # dir holding this script and the binary
    cd "$1" || die "cannot enter $1"
    say "installing the tarball at $(pwd)"
    install_tree .
    say "done - check with: hermian status"
}

# Where this script lives, when it runs from a file. Piped into `sh`, $0 is
# the shell, so there's no file and the remote path is taken. The current
# directory never decides it: a stray ./hermian there used to be installed
# as root, unverified.
script_dir() {
    case "$0" in
        install.sh|*/install.sh) [ -f "$0" ] && dirname "$0" ;;
    esac
}

install_remote() {
    _base="https://github.com/$REPO/releases/download/$1"
    TD=$(mktemp -d) || die "mktemp failed"
    trap 'rm -rf "$TD"' EXIT

    say "fetching SHA256SUMS for $1"
    fetch "$_base/SHA256SUMS" "$TD/SHA256SUMS"

    _verifier=none
    if command -v cosign >/dev/null 2>&1; then
        _verifier=cosign
        verify_sums "$TD" "$1" "$_base"
    elif command -v gh >/dev/null 2>&1; then
        _verifier=gh
    else
        echo "hermian: no cosign or gh here; checking the download against SHA256SUMS"
        echo "hermian: only. That catches corruption, not tampering. Verify later:"
        echo "hermian: see 'Verify manually' in the README."
    fi

    if command -v apt-get >/dev/null 2>&1; then
        _arch=$(dpkg --print-architecture)
        _name=$(grep -o "hermian_.*_${_arch}\.deb" "$TD/SHA256SUMS" | head -n 1 || true)
    else
        _arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
        _name=$(grep -o "hermian-.*-linux-${_arch}\.tar\.gz" "$TD/SHA256SUMS" | head -n 1 || true)
    fi
    [ -n "$_name" ] || die "no $_arch build in $1 (see the release page)"

    say "fetching $_name"
    fetch "$_base/$_name" "$TD/$_name"

    if [ "$_verifier" = gh ]; then
        say "verifying $_name with gh attestation"
        gh attestation verify "$TD/$_name" --repo "$REPO" >/dev/null ||
            die "gh could not verify $_name (gh auth login? or install cosign)"
    fi

    (cd "$TD" && sha256sum -c SHA256SUMS --ignore-missing) || die "checksum mismatch"

    case "$_name" in
        *.deb)
            chmod 755 "$TD"   # so apt's sandbox user can read the .deb
            say "installing $_name with apt"
            run apt-get install -y "$TD/$_name"
            ;;
        *)
            say "extracting $_name"
            (cd "$TD" && tar xzf "$_name") || die "could not unpack $_name"
            install_tree "$TD/${_name%.tar.gz}"
            ;;
    esac
    say "done - check with: hermian status"
}

main() {
    version=$DEFAULT_VERSION
    version_set=0
    dry_run=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) [ $# -ge 2 ] || die "--version needs a value"; version=$2; version_set=1; shift 2 ;;
            --version=*) version=${1#--version=}; version_set=1; shift ;;
            --dry-run) dry_run=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown argument: $1 (try --help)" ;;
        esac
    done
    case "$version" in v*) ;; *) version="v$version" ;; esac

    if [ "$dry_run" -eq 0 ]; then
        [ "$(id -u)" -eq 0 ] || die "run as root: pipe to 'sudo sh', or use --dry-run"
        command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    fi

    here=$(script_dir || true)
    if [ -n "$here" ] && [ -f "$here/hermian" ]; then
        [ "$version_set" -eq 0 ] ||
            die "--version picks a download; this script is inside an extracted tarball ($here)"
        install_local "$here"
    else
        install_remote "$version"
    fi
}

main "$@"
