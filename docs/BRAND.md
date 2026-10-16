# Brand

Short rules for naming and the logo, so the docs, the CLI, alerts, and the site
stay consistent.

## Company and products

**Hermian Security** is the company. It owns the GitHub org
(`hermian-security`), the domain (hermian.me), the copyright, and the security
contact.

**Hermian** is the first product: the Linux daemon in this repo.

Future tools get **Hermian + one plain word** for what they do, for example
"Hermian Scan". No unrelated codenames. Each one gets its own binary
(`hermian-scan`), or a subcommand if it's close enough to the daemon.

The daemon keeps the bare name. Its binary, `/etc/hermian`, the package, and
existing installs all depend on `hermian`, so that never changes. Once a second
tool exists, the site can describe it as "Hermian for hosts" without renaming
anything.

## Writing the name

| Where | Write | Not |
| --- | --- | --- |
| Prose, UI text, alert titles | Hermian | HERMIAN, hermian |
| Commands, paths, packages | `hermian` | |
| The company | Hermian Security | Hermian security, HermianSec |
| Logo | the lockup files below | typed text |

Capitals stay only where something machine-readable depends on them: the
`HERMIAN_*` environment variables and the `# HERMIAN:` marker in
`/etc/pam.d/sshd`.

Tagline: **Silent by default. Loud when it matters.**

## Logo

The mark is three 45° strokes and a dot. Only the dot carries colour; it's the
signal, and it's shared by every product. Don't give products their own
colours.

| File | Use |
| --- | --- |
| [`brand/lockup-light.svg`](brand/lockup-light.svg), [`-dark`](brand/lockup-dark.svg) | the product: README, site header, docs |
| [`brand/company-lockup-light.svg`](brand/company-lockup-light.svg), [`-dark`](brand/company-lockup-dark.svg) | the company: footers, legal pages, decks |

`light` is for light backgrounds, `dark` for dark ones. Every file is outlined,
so it renders the same without the font. Keep clear space of at least half the
mark's height around a lockup, and don't recolour, stretch, or retype it.

## Colours

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| Ink | `#17142E` | `#ECEBF7` | text, the strokes |
| Accent | `#5B4FD0` | `#9A8CF7` | the dot, links, HIGH |
| Dim | `#6B6888` | `#8D8AA8` | secondary text, "security" |
| Critical | `#D9344C` | `#FF6B81` | CRITICAL only |

Severity uses a four-dot meter: `◉◉◉◉` CRITICAL, `◉◉◉○` HIGH, `◉◉○○` LOW,
`◉○○○` INFO.
