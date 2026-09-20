# Signing and verifying HERMIAN releases

`curl | sudo sh` is banned for HERMIAN. Every release artifact is signed with a
published GPG key. The key fingerprint is published on the project website, on
GitHub, and in a Sigstore transparency log.

## Release key

```bash
gpg --quick-generate-key "HERMIAN Release Signing <security@hermian.security>" ed25519 sign 1y
gpg --armor --export security@hermian.security > gpg.pub
```

Publish `gpg.pub` and the fingerprint:

```bash
gpg --fingerprint security@hermian.security
```

## Signing a release

```bash
# Build the release artifacts (see Makefile: make release)
gpg --detach-sign --armor hermian-1.0.0-linux-amd64.tar.gz   # -> .sig
gpg --detach-sign --armor hermian_1.0.0_amd64.deb

# Publish checksums too
sha256sum hermian-1.0.0-linux-amd64.tar.gz > SHA256SUMS
gpg --detach-sign --armor SHA256SUMS
```

## Verifying (user side)

```bash
curl -fsSL https://packages.hermian.security/gpg.pub | gpg --import
gpg --fingerprint security@hermian.security   # compare with published fingerprint
gpg --verify hermian-1.0.0-linux-amd64.sig hermian-1.0.0-linux-amd64.tar.gz
```

Package managers (apt/dnf/pacman) verify repository signatures automatically.
