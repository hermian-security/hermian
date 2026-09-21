# Working together

Read [CONTRIBUTING.md](CONTRIBUTING.md) before editing. Keep changes small and
leave unrelated work alone.

## Tone

Write like a teammate, not a brochure. Keep docs, PRs, commit messages, and updates
short and relaxed. Contractions and familiar abbreviations are fine; skip hype,
repetition, and forced slang. Keep Conventional Commit prefixes. This is a prose
preference, not a change to code style. Don't cut warnings just to save words.

## Permission

For requested implementation work, go ahead and branch, edit, test, commit, push
the task branch, and open/update its PR. Don't ask for each routine Git step.
Analysis-only requests stay read-only.

Get an explicit request before merging, pushing to main, tagging or publishing a
release, changing access/protection rules, rewriting history, or doing anything
destructive. Don't amend or force-push by default. Never change Git identity or
global Git config.

## Workflow

1. Check status, staged changes, branch, and upstream. Fetch origin; branch from
   origin/main for a new task, or continue the same task's branch.
2. Preserve existing work. Don't commit, revert, stash, or delete unrelated files.
   Use a separate worktree if switching would disturb them.
3. Make the smallest useful fix and add regression coverage. Run relevant safe checks.
4. Review the full diff and run `git diff --check`. Stage explicit paths and use
   a Conventional Commit. No version bump or release tag for an ordinary task.
5. Push the named branch (`-u` on first push). Open a PR to main, or update its
   existing PR. Keep incomplete work draft.
6. Check CI and fix failures caused by the change. Report pending or blocked checks
   honestly; don't bypass them. Include branch, commit, PR link, checks, blockers,
   and any preserved local changes in the handoff. Stop before merge or release.

For dependent work, name the prerequisite, branch from it, and open a draft PR against it.
Once it's merged, retarget to main, reconcile without rewriting published history,
review the remaining diff, and rerun CI before marking ready. Never merge into
the temporary task-branch base.

Ask when requirements are unclear, work conflicts, secrets could leak, or an
operation falls outside this permission. Otherwise, keep going.

## Checks

- Core: `cargo test -p hermian-core --locked`
- Lint: `cargo clippy -p hermian-core --all-targets --locked -- -D warnings`
- Format: `cargo fmt --all -- --check`
- Harness: `python3 -B -m unittest discover -s tests/helpers -p 'test_*.py' -v`
- Shell edits: `sh -n` on changed scripts. Use `python` on Windows if needed.

Linux daemon/eBPF changes need Linux CI and relevant disposable-host tests.
Synthetic engine tests don't prove live coverage. Never run the root attack or
false-positive suites on a dev machine: they modify auth and persistence files.
Don't commit secrets, generated build output, or local experiments.
