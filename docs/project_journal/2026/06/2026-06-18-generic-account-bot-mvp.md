---
id: 20260618-generic-account-bot-mvp
title: Generic Account Bot MVP
status: active
created: 2026-06-18
updated: 2026-06-19
branch:
pr:
supersedes: []
superseded_by:
---

# Generic Account Bot MVP

## Summary
- Build the first Rust bot layer on top of `webex-headless-messenger` v0.1.0.

## Current State
- Rust CI scaffolding has been generated with `scripts/setup-ci.mjs --tool rust`.
- The first bot slice receives sidecar message events, matches room policies, runs `codex exec`, and replies through Webex REST.
- Codex execution defaults to current-user, read-only, no-approval, ephemeral sessions with a scrubbed environment.
- Live E2E setup now targets `miku bot test` with `miku.gen@cisco.com` as the generic account and a separate sender bot from local `.env`.
- `scripts/e2e-webex-bot.mjs` starts the Rust bot plus JS sidecar, sends a prefix-triggered Webex message from `E2E_BOT_ACCESS_TOKEN`, and waits for the thread reply.
- Live E2E passed after updating the Codex runner to pass approval policy as a top-level Codex CLI option before the `exec` subcommand.
- The E2E harness now fails if the generic-account reply does not contain the run marker, preventing false positives from Codex error replies.
- The E2E harness also checks the reply identity when Webex returns `personEmail`, verifies fixed localhost ports are free, and fails if the bot or sidecar exits before the Webex reply is observed.
- Review hardening added retry-safe Webex reply failure handling with marker reconciliation, loopback-only unauthenticated sidecar mode, authenticated health metadata, runner timeout coverage for blocked stdin writes, and `codex.codex_home` support for bot-owned Codex auth/config.

## Next Steps
- Decide whether the next slice should prioritize durable job recovery or privileged ephemeral Linux user runner support.

## Evidence
- Local source files: `Cargo.toml`, `src/`, `config/example.toml`, `README.md`.
- E2E harness: `scripts/e2e-webex-bot.mjs`.
- Live E2E: `node scripts/e2e-webex-bot.mjs` returned `e2e_ok=true` and `marker_found=true` against `miku bot test` on 2026-06-19 after the marker, reply-identity, and child-process assertions were added.
- Local validation: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo run -- --config config/example.toml --check-config`, `node --test test/setup-ci.node-test.mjs test/e2e-webex-bot.node-test.mjs`, `actionlint .github/workflows/ci.yml`, and `git diff --check`.
