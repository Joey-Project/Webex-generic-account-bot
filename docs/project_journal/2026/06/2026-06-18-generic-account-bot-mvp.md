---
id: 20260618-generic-account-bot-mvp
title: Generic Account Bot MVP
status: active
created: 2026-06-18
updated: 2026-06-26
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
- Review hardening added retry-safe Webex reply failure handling with stable marker reconciliation, loopback-only unauthenticated sidecar mode, authenticated health metadata, runner timeout coverage for blocked stdin writes, and `codex.codex_home` support for bot-owned Codex auth/config.
- WME Jenkins staging now supports recursive read-only diagnostics bundles under the Codex cwd, mirrored production-source messages into the staging output room, and an opt-in `jenkins-diagnosis-json` reply format so Codex returns structured diagnosis fields while the bot renders deterministic Webex Markdown.
- Follow-up MVP is implemented behind opt-in room config: allowed users can mention the generic account in an existing bot thread, the bot resolves the prior source message through hidden markers, includes recent thread context in the Codex prompt, and replies in the same thread while preserving staging output/read-only source boundaries. Quoted-reply follow-up is supported when the incoming Webex payload preserves the bot marker, but still needs live client payload validation.
- Deployment automation and runner isolation are planned in `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`.

## Next Steps
- Let the WME Jenkins staging deployment run for a few days before moving replies from staging output to the production space.
- Enable follow-up config in the staging deployment and validate live `@miku.gen` follow-ups; separately test whether Webex quoted replies preserve hidden marker content in webhook or hydrated message payloads.
- Execute the deployment automation and runner isolation roadmap, starting with deployment-host pull/validate/reload automation.

## Evidence
- Local source files: `Cargo.toml`, `src/`, `config/example.toml`, `README.md`.
- E2E harness: `scripts/e2e-webex-bot.mjs`.
- Live E2E: `node scripts/e2e-webex-bot.mjs` returned `e2e_ok=true` and `marker_found=true` against `miku bot test` on 2026-06-19 after the marker, reply-identity, and child-process assertions were added.
- Local validation: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo run -- --config config/example.toml --check-config`, `node --test test/setup-ci.node-test.mjs test/e2e-webex-bot.node-test.mjs`, `actionlint .github/workflows/ci.yml`, and `git diff --check`.
- WME Jenkins staging validation on 2026-06-23: recursive helper bundle identified failed downstream leaves for `Pipeline-AV1-Test` replays, and `env REPLAY_LIMIT=3 node .codex-tmp/local-deploy/replay-production-source.mjs` produced three staging replies classified as Jenkins infra false alarms with GUI `/console` log links.
- Follow-up local validation on 2026-06-24: `cargo fmt --check`, `cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo run --all-features -- --config config/example.toml --check-config`, and `git diff --check`.
