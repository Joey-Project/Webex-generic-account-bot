---
id: 20260627-configuration-space-commands
title: Configuration Space Commands
status: active
created: 2026-06-27
updated: 2026-06-27
branch: codex/config-prepare-backend
pr:
supersedes: []
superseded_by:
---

# Configuration Space Commands

## Summary
- Add a deny-by-default administrative Webex Space without trusting sidecar
  payload fields or running deployment mutation inside the request handler.

## PR 2a
- Hydrate every event message through Webex and replace the sidecar hint before
  room, sender, body, thread, Codex, or write-routing decisions.
- Add an optional `[config_commands]` schema with one non-overlapping admin
  room, explicit person ID/email allowlists, and exact command enums.
- Implement read-only `/config status` from fixed host metadata paths. Status
  input is no-follow, regular-file, bounded, parsed, and field-allowlisted
  before deterministic Markdown rendering.
- Keep `pull`, `reload`, and `sync` undeployable in this slice. Production host
  policy also rejects all config-command configuration until an exact admin
  room and sender policy are reviewed in the companion config PR.
- Merged as bot PR #9 at
  `8448c5e6f4cb98fd448d461d18799d46cdb2fba5`.

## PR 2b1
- Add explicit immutable staged preparation. It may fetch, render, validate,
  and persist a revision, but must not replace the live rendered config or
  restart the service.
- Keep all mutating Webex commands disabled.

## PR 2b2
- Add a separate-identity worker with a host-owned Unix socket and durable queue
  keyed by Webex message ID.
- Enable `/config pull` only after enqueue durability, crash recovery,
  duplicate-event, worker-restart, ownership, symlink, and fixed-argv tests pass.

## PR 2b3
- Add recoverable activation and persist the exact staged target revision before
  changing live config or service state.
- Enable `/config reload` and `/config sync` only after activation rollback,
  health, and in-flight work semantics are tested.

## Evidence
- Deployment foundation: bot PR #8, merge commit
  `09e86d36a51b832e564fab2b861f8aff16e30e19`.
- Config layout migration: config PRs #13-#15, final merge commit
  `9821e00f0680e480267e5060607bdad2c055feb1`.
