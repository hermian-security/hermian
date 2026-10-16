#!/bin/sh
# Add a release's .deb files to the signed APT repository served at
# https://apt.hermian.me (the hermian-security/apt repo, deployed by
# Cloudflare Pages from its public/ directory). Run by the release workflow.
#
#   sh packaging/apt/publish.sh <dist-dir> <apt-repo-checkout> <tag>
#
# Needs reprepro and a gpg keyring holding exactly one secret key: the
# repository signing key. Prereleases (tags with a "-") go to the beta suite
# only; releases go to stable and beta, so beta users get them too.
set -eu

DIST=$1
REPO=$2
TAG=$3

case "$TAG" in
    v*-*) SUITES="beta" ;;
    v*) SUITES="stable beta" ;;
    *) echo "publish.sh: not a release tag: $TAG" >&2; exit 2 ;;
esac

mkdir -p "$REPO/conf" "$REPO/public"
# reprepro's own state (conf/, db/) stays outside public/, which is all the
# web server sees.
cat > "$REPO/conf/distributions" <<'EOF'
Origin: Hermian Security
Label: Hermian
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: Hermian releases
SignWith: yes

Origin: Hermian Security
Label: Hermian
Suite: beta
Codename: beta
Architectures: amd64 arm64
Components: main
Description: Hermian prereleases and releases
SignWith: yes
EOF

found=0
for deb in "$DIST"/*.deb; do
    [ -f "$deb" ] || continue
    found=1
    for suite in $SUITES; do
        # Replaces the previous version of the package in that suite;
        # files nothing references any more are deleted from the pool.
        reprepro --basedir "$REPO" --outdir "$REPO/public" includedeb "$suite" "$deb"
    done
done
[ "$found" -eq 1 ] || { echo "publish.sh: no .deb in $DIST" >&2; exit 1; }

# The public key, for the manual setup in the README (the installer takes
# the copy shipped and checksummed with each release).
gpg --batch --export > "$REPO/public/hermian-archive-keyring.gpg"
gpg --batch --armor --export > "$REPO/public/hermian-archive-keyring.asc"

# Index lists change on every release; the pool never does.
cat > "$REPO/public/_headers" <<'EOF'
/dists/*
  Cache-Control: public, max-age=300
/pool/*
  Cache-Control: public, max-age=31536000, immutable
EOF

# The landing page, from the template next to this script: the current
# versions and the key fingerprint filled in, with the brand logos.
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
current() { # suite -> the version in it, or "none yet"
    v=$(reprepro --basedir "$REPO" --outdir "$REPO/public" list "$1" hermian 2>/dev/null | awk 'NR==1{print $3}')
    echo "${v:-none yet}"
}
FPR=$(gpg --batch --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}' | sed 's/.\{4\}/& /g; s/ $//')
sed -e "s|@VERSION@|$TAG|g" \
    -e "s|@BETA@|$(current beta)|g" \
    -e "s|@STABLE@|$(current stable)|g" \
    -e "s|@FINGERPRINT@|$FPR|g" \
    "$HERE/index.html" > "$REPO/public/index.html"
cp "$ROOT/docs/brand/lockup-light.svg" "$ROOT/docs/brand/lockup-dark.svg" "$REPO/public/"
cp "$ROOT/hermian/assets/company-email.png" "$REPO/public/company-lockup.png"
# Without a 404.html, Cloudflare Pages answers every missing path with
# index.html and a 200, so apt would get a web page where it expects a
# signed file (a suite that doesn't exist yet, a typo in sources).
cp "$HERE/404.html" "$REPO/public/404.html"
# The brand fonts, served from here (no third-party requests), with their
# SIL Open Font License texts.
mkdir -p "$REPO/public/fonts"
cp "$HERE"/fonts/*.woff2 "$HERE"/fonts/OFL-*.txt "$REPO/public/fonts/"

echo "published $TAG to: $SUITES"
