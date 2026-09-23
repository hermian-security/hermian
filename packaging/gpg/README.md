# Release signing

Every release is checked three ways; the commands are in the README's
Install section.

- `SHA256SUMS`: catches a broken download. It sits next to the files, so it
  doesn't prove origin on its own.
- GitHub build attestations (`gh attestation verify`), from v0.1.0-beta.5 on:
  provenance for every file in `SHA256SUMS`, tied to `release.yml`.
- Sigstore bundles (`*.sigstore`, `cosign verify-blob`): keyless signatures
  bound to `https://github.com/hermian-security/hermian/.github/workflows/release.yml@refs/tags/<tag>`
  and issuer `https://token.actions.githubusercontent.com`.

Neither needs a key we have to guard. The planned APT repository will need a
GPG key, because apt only understands signed `InRelease` files; see
`docs/ROADMAP-BURN-IN.md` §1.5. There's no GPG key yet.

Security contact: contact@hermian.me
