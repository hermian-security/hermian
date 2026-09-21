# Security

HERMIAN runs as root. If you find a security issue, please report it privately
before opening a public issue.

## Report a vulnerability

Email **contact@hermian.me** with `SECURITY` in the subject, or use
[GitHub's private reporting form](https://github.com/hermian-security/hermian/security/advisories/new).
Need encryption? Ask for a key first.

Include the version (`hermian --version`), distro, kernel, impact, and steps to
reproduce. We'll acknowledge within three days and send updates at least every
two weeks until it's resolved.

## Scope

Anything in this repo is in scope, including the daemon, eBPF, PAM, packaging,
systemd unit, and release pipeline. That includes code execution as the daemon,
detection bypasses, missed attacks within the stated coverage, silent loss of
monitoring, and tampered release artifacts.

False positives belong in normal issues, with a redacted `hermian show <ref> --json`.
Third-party service bugs and denial of service that already requires root on
the host aren't covered here.

## Fixes and disclosure

Only the latest release gets fixes. We'll coordinate disclosure, publish a fix
and changelog entry, and seek a CVE where applicable. You'll get credit unless
you'd rather stay anonymous. There's no bounty at this stage.
