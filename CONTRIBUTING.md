# Contributing

HERMIAN uses short-lived branches and pull requests into a protected main branch.
There is no permanent develop branch. Main should remain buildable, but merging
code does not automatically publish a release.

## Branches And Commits

Use one task per branch:

| Prefix | Purpose |
| --- | --- |
| feat/ | New behavior |
| fix/ | Bug or security fix |
| docs/ | Documentation |
| refactor/ | Internal restructuring |
| test/ | Test-only work |
| ci/ | CI and build automation |
| chore/ | Repository maintenance |
| release/ | Version and release preparation |

Examples: fix/validation-harness, feat/file-write-attribution, release/0.1.0-beta.2.
Keep names lowercase with hyphens. Start from the latest origin/main and never
mix someone else's local changes into a task.

Use Conventional Commits for new commits and PR titles:

```text
fix(harness): reject historical attack evidence
feat(auth): support an additional authentication source
ci: require reproducible release inputs
docs: clarify reduced kernel coverage
```

Use feat for a feature, fix for a bug, and docs, refactor, test, ci, build, chore,
perf, or revert for the corresponding maintenance work. Use ! and a BREAKING
CHANGE footer for an incompatible change. Explain why a change is needed in the
body when the title is not enough. Existing commits are not rewritten to adopt
this convention.

## Daily Workflow

The following commands are separate commands and work in PowerShell as well as
a POSIX shell. Inspect the working tree before switching branches; use a separate
worktree if you have unrelated work in progress.

```sh
git status --short --branch
git fetch origin
git switch -c fix/short-description origin/main
```

Implement and test the change, then inspect both staged and unstaged changes:

```sh
git diff
git diff --check
git add -- path/to/changed-file path/to/regression-test
git diff --cached
git commit -m "fix: explain the problem being corrected"
git push -u origin fix/short-description
gh pr create --base main --head fix/short-description --fill
gh pr checks --watch
```

The example paths are placeholders: stage only files belonging to the task.
After the upstream is set, git push publishes subsequent commits from that branch.
Do not use git push --all or git push --tags for normal work.

AI-assisted implementation follows the owner's standing authorization in AGENTS.md:
branch, verify, commit, push, and open a PR without repetitive approval prompts.
Merging and releasing remain explicit maintainer decisions.

## Required Checks

Main requires these GitHub Actions checks:

- validation harness (non-root)
- core (ubuntu-latest)
- core (macos-latest)
- core (windows-latest)
- daemon + eBPF (linux)

Keep these job names stable. A rename must be coordinated with the required-check
settings or PRs will remain blocked waiting for the old name.

Run relevant checks locally before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy -p hermian-core --all-targets --locked -- -D warnings
cargo test -p hermian-core --locked
python3 -B -m unittest discover -s tests/helpers -p 'test_*.py' -v
```

On Linux with the required toolchains, also run the daemon tests and the
source-built eBPF checks used by .github/workflows/ci.yml. On Windows, python may
be the Python command, and Linux-specific verification must be delegated to CI.

The scripts under tests/attacks and tests/false_positives modify real system files.
Run them only on an explicitly designated disposable Linux host, never as a
generic pre-commit hook. Synthetic self-tests do not validate live telemetry.

## Review And Merge

PRs must describe the problem, scope, verification, and operational impact.
Resolve review conversations and wait for all required checks. Branches must be
up to date with main; merge origin/main into a published task branch when needed
rather than rewriting its history.

Only squash merges are enabled. The PR title becomes the single main-branch
commit title, so review it as carefully as the code. Delete the remote task
branch after merge; GitHub does this automatically. Delete a local branch only
after confirming its work was merged and it contains no unique changes.

The current single-maintainer setup requires a PR and green CI but zero mandatory
review approvals: authors cannot approve their own PRs. This is not independent
review. Set the required approval count to one when another maintainer is
available. Branch protections apply to administrators too.

For an exceptional dependent PR, target the prerequisite branch and mark the PR
as draft. Do not merge it into that branch. Once the prerequisite is merged,
retarget to main, reconcile the branch, inspect the remaining diff, and rerun CI.

Do not bypass checks to fix a broken build. Add a corrective commit. Reverting
merged work is a new PR with a revert commit, not a force push or reset of main.

## Versioning And Releases

The workspace package version in Cargo.toml is the version source of truth; all
four crates inherit it. Cargo.lock must reflect the same workspace versions.
Release tags must be v followed by that exact version, including any prerelease
suffix. For example, version 0.1.0-beta.2 requires tag v0.1.0-beta.2.

Follow Semantic Versioning:

- Patch: backward-compatible fixes, such as 0.1.0 to 0.1.1.
- Minor: new functionality; during 0.x, also clearly documented breaking changes.
- Major: incompatible changes after 1.0.
- Prerelease: increment the beta number for each beta build; never move an old tag.

People install GitHub Release artifacts, not `main`. After a user-facing feat
or fix lands (installed binary, pager policy, install path), ship a new
prerelease. Docs, CI, and chore-only changes don't get a tag.

Record notes under Unreleased while the PR is open. The release prep PR bumps
`workspace.package.version` (next `0.1.0-beta.N` during beta), updates
Cargo.lock to match, and moves those notes into a dated section. Don't mix the
bump into the feat/fix PR. Don't run a blanket `cargo update` just to change
the workspace version.

Release procedure:

1. User-facing change is on `main` with green CI.
2. Open `release/x.y.z` with the version bump and changelog move.
3. Merge it through the normal PR checks.
4. Wait for CI on that `main` commit. A green PR build isn't enough.
5. Tag `v` + that exact version on that commit and push only that tag.
6. Watch `release.yml`, then verify Sigstore + SHA256SUMS. Don't move a failed tag.

Example commands, only after the version has been prepared and approved:

```sh
git tag -a v0.1.0-beta.2 -m "HERMIAN 0.1.0-beta.2"
git push origin v0.1.0-beta.2
gh run list --workflow release.yml
```

A tag push automatically invokes the existing build/sign/publish workflow. Tags
containing a hyphen publish a GitHub prerelease. The workflow rejects a tag whose
version differs from Cargo.toml or whose commit is not on origin/main.

Existing historical tags are not rewritten to match this new policy. Historical
runs use the workflow stored at their tagged commit; new validation is not
retroactive. Prepare new releases from tested main commits containing the guard,
with the prerelease suffix included in Cargo.toml as well as the tag.

## GitHub Settings

The initial setup enables these server-side controls:

- Main: pull requests, the five required checks, up-to-date branches, resolved
  conversations, linear history, and enforcement for administrators.
- Main: no force pushes or deletion.
- Merges: squash only, PR title as the squash commit title, automatic branch deletion.
- Release tags matching v*: updates and deletion blocked, with no bypass actors.

These are GitHub settings, not protections conferred by this Markdown file.
Verify them in Settings > Branches and Settings > Rules > Rulesets after a
repository transfer or settings migration. Changing them requires explicit
maintainer approval. Adding collaborators, teams, or required reviewers is not
part of the routine automated workflow.
