---
id: 20260720-test-fixture-portability-cleanup
title: Test Fixture Portability Cleanup
status: completed
created: 2026-07-20
updated: 2026-07-20
branch: codex/test-fixture-portability-cleanup
pr: https://github.com/Joey-Project/Webex-generic-account-bot/pull/30
supersedes: []
superseded_by:
---

# Test Fixture Portability Cleanup

## Summary
- Remove a historical credential-shaped PEM fixture and make host-policy tests
  portable across supported Linux distributions before reviewing the systemd
  empty-listing compatibility fix.

## Current State
- The redaction test generates an Ed25519 private key at runtime and uses the
  catalogued synthetic API-key fixture instead of storing credential-shaped
  test data in the repository.
- Host-policy tests use trusted temporary executables and exercise the real
  launcher shebang with the active Node.js interpreter, covering Ubuntu 26.04
  without weakening production path validation.
- This cleanup is intentionally independent of the systemd compatibility fix.
  Its one-time review exception skips local Codex and Claude review because the
  historical base blob blocks their secret preflight; CI and remote GitHub
  Codex review remain required.

## Next Steps
- None for this completed cleanup workstream.

## Evidence
- Node.js suite: 470 tests, 469 passed, 1 expected skip, 0 failed.
- Rust gates: `cargo fmt --check`, Clippy with warnings denied, and all-feature
  tests passed.
- MSRV gate: Rust 1.85.1 locked all-targets and all-features check passed.
