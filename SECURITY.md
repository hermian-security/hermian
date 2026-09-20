# Security policy

HERMIAN runs as root with eBPF and audit privileges on the hosts it protects.
A vulnerability in it is a vulnerability in every host that runs it. Please
report privately.

## Reporting

- Email **contact@hermian.me**. Put `SECURITY` in the subject.
- Or use GitHub's private vulnerability reporting on this repository
  ("Report a vulnerability" under the Security tab).

Please include: affected version (`hermian --version`), kernel and distro,
and steps or a proof of concept. Encrypted mail is welcome; ask for a key in
your first message if you need one.

You will get an acknowledgement within **3 days** and a status update at
least every **14 days** until resolution.

## Scope

In scope: anything in this repository - the daemon, the eBPF programs, the
PAM module, packaging scripts, the systemd unit, and the release workflow.

Particularly interesting:

- ways to run code as the daemon or influence its detection decisions;
- ways to disable or blind the daemon without triggering a self-protection
  alert;
- false negatives in the five detection groups that a defender would
  reasonably expect to be caught (please include a reproducible scenario);
- supply-chain issues in the release pipeline.

Out of scope: false *positives* (open a normal issue), the third-party
services you configure as notification channels, and denial of service that
requires root on the host already.

## Disclosure

Coordinated disclosure. Fixes ship as a new release with a changelog entry
and, where applicable, a CVE. Reporters are credited unless they ask not to
be. There is no bounty programme at this stage.

## Supported versions

Only the latest release receives fixes. During the beta this may change
quickly; `hermian status` shows the running version.
