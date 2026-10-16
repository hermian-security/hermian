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

cat > "$REPO/public/index.html" <<'EOF'
<!doctype html><meta charset="utf-8"><title>Hermian APT repository</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:720px;margin:48px auto;padding:0 20px;color:#17142E}
pre{background:#0F0E17;color:#ECEBF7;padding:14px 16px;border-radius:10px;overflow-x:auto}a{color:#5B4FD0}</style>
<h1>Hermian APT repository</h1>
<p>Signed packages for <a href="https://hermian.me">Hermian</a>. Suites: <code>beta</code> (prereleases and releases) and <code>stable</code>.</p>
<pre>curl -fsSL https://apt.hermian.me/hermian-archive-keyring.gpg | sudo tee /usr/share/keyrings/hermian-archive-keyring.gpg &gt;/dev/null
printf 'Types: deb\nURIs: https://apt.hermian.me\nSuites: beta\nComponents: main\nSigned-By: /usr/share/keyrings/hermian-archive-keyring.gpg\n' | sudo tee /etc/apt/sources.list.d/hermian.sources
sudo apt update &amp;&amp; sudo apt install hermian</pre>
<p>Or use the one-line installer from the <a href="https://github.com/hermian-security/hermian#install">README</a>: it sets this up for you.</p>
EOF

echo "published $TAG to: $SUITES"
