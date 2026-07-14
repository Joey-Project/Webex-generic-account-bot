---
id: 20260714-structural-config-check
title: Structural Config Check
status: completed
created: 2026-07-14
updated: 2026-07-14
branch: codex/structural-config-check
pr:
supersedes: []
superseded_by:
---

# Structural Config Check

## Summary
- Add an explicit unprivileged config-validation mode for CI without weakening
  deployment-host preflight.

## Contract
- `--check-config-structure` loads and validates the complete `BotConfig`, then
  exits before activation receipt or launcher socket inspection.
- `--check-config` retains activation receipt and fixed launcher socket
  verification for ephemeral profiles.
- The two check modes are mutually exclusive and emit distinct success output.
- Normal service startup retains activation, launcher installation, and live
  launcher preflight.

## Validation
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --all-targets --all-features`
- `cargo fmt --all -- --check`
- `node --test test/*.node-test.mjs` (398 passed, one passwordless-sudo test
  skipped)
- Project journal validator

## Next Steps
- Update both config-repository CI lanes to invoke
  `--check-config-structure`.
- Keep trusted deployment and runner activation on full `--check-config`.
