#!/bin/sh
# HERMIAN tarball installer - run from inside an extracted, verified release
# directory.
#
# NO 'curl | sudo sh'. Ever. Fetch SHA256SUMS + the tarball, then:
#   sha256sum -c SHA256SUMS --ignore-missing
#   tar xzf hermian-<ver>-linux-<arch>.tar.gz
#   cd hermian-<ver>-linux-<arch>
#   sudo sh install.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "hermian: run as root: sudo sh install.sh" >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "hermian: systemd is required" >&2
    exit 1
fi

BIN=/usr/local/bin/hermian
PAM_SRC=./libpam_hermian.so
PAM_DST=/usr/lib/security/pam_hermian.so

if [ ! -f ./hermian ]; then
    echo "hermian: ./hermian binary not found - run from the extracted release directory" >&2
    exit 1
fi

install -m 0755 ./hermian "$BIN"

if [ -f "$PAM_SRC" ]; then
    install -D -m 0644 "$PAM_SRC" "$PAM_DST"
    echo "hermian: installed optional PAM module ($PAM_DST)"
    echo "         enable it with: sudo hermian enable --with-pam"
fi

"$BIN" enable
