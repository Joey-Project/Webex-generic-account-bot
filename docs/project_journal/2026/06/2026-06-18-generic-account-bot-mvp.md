---
id: 20260618-generic-account-bot-mvp
title: Generic Account Bot MVP
status: active
created: 2026-06-18
updated: 2026-06-18
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

## Next Steps
- Run formatting, clippy, tests, and journal validation.
- Decide whether the next slice should prioritize durable job recovery or privileged ephemeral Linux user runner support.

## Evidence
- Local source files: `Cargo.toml`, `src/`, `config/example.toml`, `README.md`.
