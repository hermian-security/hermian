# Changelog

Noteworthy changes are recorded here before release. Versions follow Semantic
Versioning; release preparation moves entries from Unreleased into a dated section.
Earlier release information remains in the repository's GitHub Releases and Git history.

## Unreleased

### Fixed

- Attack validation requires fresh HIGH/CRITICAL JSON evidence instead of accepting
  historical log matches. Failed queries and malformed evidence fail verification.

### Changed

- Failed SSH bursts stay INFO. HIGH is a login from that source while the burst
  window is still open.
- Invalid config edits and no-op reloads no longer page CRITICAL. A real
  validated change still does. Self-protection alerts share the dedup window.

- Shorten the main docs and keep the writing plain, with setup steps and safety
  notes still easy to find.
- Adopt a protected-main, squash-merge PR workflow with documented standing
  authorization for routine AI-assisted branch, commit, push, and PR operations.
- Reject future release tags that do not match the workspace package version or
  point to commits outside main. Existing tags remain unchanged.
