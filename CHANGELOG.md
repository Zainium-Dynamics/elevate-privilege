# Changelog

All notable changes to `elevate-pam` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versioning:
[SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- This repository now contains only `elevate-pam`. `elevate` (sudo/su),
  `elevate-umbra` (shadow-utils) and `elevate-crypto` moved to their own
  repositories under `Zainium-Dynamics`. The previous monorepo is preserved
  in git history (tag `v1.0.1`).
- Dropped the `elevate-paths` dependency. Paths are now read from the
  `[paths]` table of `elevate-pam.toml` (see `elevate_pam::paths`), defaulting
  to the conventional Linux layout instead of `/overlayer/syshub`.
- `elevate-crypto` is consumed as a git dependency.
- Makefile and `scripts/install.sh` rewritten: `PREFIX` / `DESTDIR` support, no
  dependency on the monorepo config.

### Fixed
- `cargo check -p elevate-pam --no-default-features --features alloc` (no_std)
  failed on an unqualified `format!`.

## [1.0.1] - 2026-08-25

Last release as part of the `elevate-privilege` monorepo.
