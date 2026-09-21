# Repository Working Agreement

Read CONTRIBUTING.md before making changes. These are the owner's standing
preferences for implementation tasks, not authorization to change unrelated work.

## Standing Authorization

For a requested implementation task, proceed without repeatedly asking permission
to create a task branch, make focused edits, run safe checks, commit the verified
changes, push the task branch to origin, and open or update its pull request.
Analysis-only requests do not authorize edits or publication.

Always require an explicit request before merging a PR, pushing to main, creating
or pushing release tags, publishing a release, changing repository access or
protection rules, rewriting history, or running destructive operations. The
initial protection setup was approved separately; it is not standing permission
to weaken those protections. Do not amend commits or force-push by default.

## Task Workflow

1. Inspect git status, staged changes, the current branch, and remote tracking.
2. Preserve all pre-existing changes. Never commit, revert, stash, or delete
   unrelated files. Stage explicit paths, not the entire working tree.
3. Fetch origin. Start a short-lived task branch from origin/main. Continue the
   existing branch when the request extends the same task. Use a separate
   worktree if unrelated work would otherwise need to be moved or overwritten.
4. Use the smallest correct change and add regression coverage for bug fixes.
5. Run relevant safe checks. Do not run the root attack or false-positive suites
   on a developer's machine: they modify authentication and persistence files.
6. Review the full diff, run git diff --check, and commit with a Conventional
   Commit message. Do not update versions or tags for an ordinary task.
7. Push the named task branch, setting its upstream on the first push. Open a PR
   against main; reuse an existing PR for the same branch instead of duplicating it.
8. Inspect GitHub checks. Fix failures caused by the change. If checks are pending,
   unavailable, or blocked, report that accurately; never bypass them or claim
   they passed. Keep incomplete or dependent work in a draft PR.
9. Report the branch, commit, PR URL, checks, remaining blockers, and any preserved
   unrelated changes. Stop before merge or release unless explicitly requested.

If a task genuinely depends on an unmerged PR, branch from that task branch and
open a draft PR against it. State the dependency prominently. After the dependency
is merged, retarget the draft to main, reconcile with main without rewriting
published history, review its remaining diff, and rerun CI before marking it ready.
Never merge a dependent PR into its temporary task-branch base.

Ask questions only when requirements are ambiguous, work conflicts, a secret could
be exposed, or an operation needs authorization outside the boundaries above.

## Verification

- Portable Rust: cargo test -p hermian-core --locked.
- Core lint: cargo clippy -p hermian-core --all-targets --locked -- -D warnings.
- Formatting: cargo fmt --all -- --check.
- Harness: python3 -B -m unittest discover -s tests/helpers -p 'test_*.py' -v.
- Shell changes: syntax-check changed scripts with sh -n.
- Linux daemon/eBPF changes: use the Linux CI job and relevant disposable-host
  tests. A passing synthetic engine test does not prove live collector coverage.

Use Python instead of python3 on Windows if necessary. Do not commit secrets,
generated build artifacts, or local experiment files. Never modify Git identity or
global Git configuration as part of a task.
