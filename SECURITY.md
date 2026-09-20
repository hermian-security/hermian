# Security

HERMIAN runs as root with eBPF and audit privileges on every host it's
installed on. A bug in it is a bug on all of those hosts at once. If you find
one, please tell us privately first.

## How to report

Mail contact@hermian.me with `SECURITY` somewhere in the subject, or use the
"Report a vulnerability" button under this repository's Security tab.

Useful to include: the version (`hermian --version`), the distro and kernel,
and enough to reproduce. If you'd rather encrypt, ask for a key in your first
mail and you'll get one.

We'll acknowledge within three days and keep you updated at least every two
weeks until it's fixed.

## What counts

Anything in this repository: the daemon, the eBPF programs, the PAM module,
the packaging scripts, the systemd unit, the release workflow.

We're especially interested in:

- running code as the daemon, or making it decide wrongly;
- disabling or blinding it without a self-protection alert firing;
- a false negative, meaning an attack in one of the five detection groups
  that a defender would reasonably expect to be caught and isn't (please
  include a reproducible scenario, ideally as a script under `tests/attacks`);
- anything in the release pipeline that could let a modified artifact carry a
  valid signature.

Not security reports: false positives (open a normal issue with `hermian show
<ref> --json` attached), problems in Telegram, your mail provider or other
third parties you've configured as a channel, and denial of service that
already requires root on the host.

## Disclosure

Coordinated. A fix ships as a new release with a changelog entry and a CVE
where one applies. You'll be credited unless you ask not to be. There's no
bounty at this stage; we're a beta with one maintainer.

## Supported versions

Only the latest release gets fixes. During the beta that moves fast;
`hermian status` shows what you're running.
