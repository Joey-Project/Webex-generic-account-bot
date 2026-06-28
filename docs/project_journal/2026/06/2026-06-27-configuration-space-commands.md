---
id: 20260627-configuration-space-commands
title: Configuration Space Commands
status: active
created: 2026-06-27
updated: 2026-06-28
branch: codex/config-pull-worker
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
- Merged as bot PR #10 at
  `45d87b7d6fb59f7d751285a253b3cf7e21826563`.

## PR 2b2a
- Add a separate-identity worker with a host-owned Unix socket and durable queue
  keyed by Webex message ID.
- Use a stable `webex-config-deploy` identity and a host-owned Unix socket. The
  bot request process receives no Git, deploy-key, checkout, or prepare-command
  access.
- Bind the worker action ID into staged metadata so a crash after prepare commit
  recovers without resolving a different config revision.
- Publish only a strict, non-secret worker action status projection for
  `/config status`; keep it separate from the private worker queue and staging
  state.
- Publish the credential-free production root-apply recovery journal as
  root-owned (UID 0) mode `0644` so the non-root bot can strictly expose only
  allowlisted phase, config revision, and service fields. Do not trust or
  require its GID because mode `0644` grants no group write. Deployment recovery
  trusts the same-owner UID for both current mode `0644` and legacy mode `0600`
  journals. `/config status` still parses only the root-owned (UID 0), mode
  `0644` journal at the fixed path, mapping private legacy files, malformed
  journals, and files with an untrusted UID or mode to generic
  `recovery_required` without exposing contents.
- Keep the deployment recovery journal distinct from both the worker's private
  queue/staging artifacts and its public status projection; the deployment
  journal is not private worker transaction state.
- Preserve queue order across deployment-lock contention by durably requeueing
  and retrying the oldest action instead of recording a terminal failure.
- Treat an uncontained deployment process tree as a worker integrity failure;
  persist a terminal taint and exit so systemd kills the complete worker cgroup
  before restart. Never reconcile that action's staged pair as success; a new
  Webex message is required after operator review.
- Require cgroup v2 and verify PID/start-time membership around every fixed
  deployment child without granting cgroup delegation or write access.
- Serialise the worker's single-use startup and shutdown path, including a
  bounded, abortable stale-socket probe.
- Hold the root-provisioned `config-pull-worker.lock` flock from before any
  durable recovery through the complete worker lifetime. Keep it separate from
  `deploy-config.lock` so a same-UID second instance cannot mutate action state
  before discovering the first worker's active socket.
- Keep `/config pull` configuration-invalid and do not grant the bot the socket
  group because current-user Codex children inherit its supplementary groups.

## PR 2b2b
- After the runner abstraction and `ephemeral-linux-user` launcher merge, prove
  prompt-controlled children cannot access `/run/webex-config-pull`.
- Then grant only the bot process the socket group, enable `/config pull`, and
  add the reviewed admin Space/sender config in one bounded enablement sequence.

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
