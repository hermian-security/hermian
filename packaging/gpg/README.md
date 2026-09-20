# Release signing

HERMIAN releases are signed with **Sigstore** (`cosign`), keyless. The
signing identity is the GitHub Actions workflow
`https://github.com/hermian-security/hermian/.github/workflows/release.yml`
and the certificate is issued by `https://token.actions.githubusercontent.com`.
Every signature is recorded in the public Rekor transparency log.

This means:

- there is no long-lived private key that could be stolen or lost;
- a signature proves the artifact was produced by *that workflow on that
  repository*, not merely by someone holding a key;
- verification needs only `cosign`, no key distribution step.

## Verify a release

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore \
  --certificate-identity-regexp '^https://github.com/hermian-security/hermian/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Individual `.deb` and `.tar.gz` files also carry their own `.sigstore`
bundle and can be verified the same way.

## GPG

A GPG key is **not** used for the beta. If a distribution repository later
requires one (apt/dnf repos do), it will be generated on an offline machine,
its fingerprint published at <https://hermian.me> and in this file, and the
`SHA256SUMS` file will be signed with both methods. Until then, treat any
"HERMIAN GPG key" you encounter as untrusted.

Security contact: <contact@hermian.me>
