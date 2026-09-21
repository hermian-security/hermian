# Changelog

Noteworthy changes are recorded here before release. Versions follow Semantic
Versioning; release preparation moves entries from Unreleased into a dated section.
Earlier release information remains in the repository's GitHub Releases and Git history.

## Unreleased

### Changed

- Install docs use curl + `sha256sum` on a pinned tag. `cosign` is optional.

## 0.1.0-beta.2 - 2026-09-21

### Changed

- Failed SSH bursts stay INFO. HIGH is a login from that source while the burst
  window is still open.
- Invalid config edits and no-op reloads no longer page CRITICAL. A real
  validated change still does. Self-protection alerts share the dedup window.
- User-facing feat/fix landings now get a new prerelease tag so GitHub Releases
  match `main`, not the previous package.

### Fixed

- Attack validation requires fresh HIGH/CRITICAL JSON evidence instead of accepting
  historical log matches. Failed queries and malformed evidence fail verification.
