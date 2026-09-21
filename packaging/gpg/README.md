# Release signing

Install path is checksums, not `cosign`. See the README.

CI still signs artifacts with Sigstore (keyless, identity bound to
`.github/workflows/release.yml`). That's extra, not required to install.

A GPG key is not used for the beta. Security contact: contact@hermian.me
