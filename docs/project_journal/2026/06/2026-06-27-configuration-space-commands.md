---
id: 20260627-configuration-space-commands
title: Configuration Space Commands
status: active
created: 2026-06-27
updated: 2026-06-27
branch: codex/config-space-commands
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

## PR 2b
- Add a durable file-backed action queue keyed by Webex message ID, an external
  systemd worker, staged config preparation/activation, and fixed argv mapping.
- Enable `pull`, `reload`, and `sync` only after enqueue durability, crash
  recovery, duplicate-event, and worker-restart tests pass.

## Evidence
- Deployment foundation: bot PR #8, merge commit
  `09e86d36a51b832e564fab2b861f8aff16e30e19`.
- Config layout migration: config PRs #13-#15, final merge commit
  `9821e00f0680e480267e5060607bdad2c055feb1`.
