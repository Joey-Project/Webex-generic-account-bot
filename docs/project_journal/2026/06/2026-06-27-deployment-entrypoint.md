---
id: 20260627-deployment-entrypoint
title: Trusted deployment host entrypoint
status: active
created: 2026-06-27
updated: 2026-06-27
branch: codex/deploy-entrypoint-pr1b
pr:
supersedes: []
superseded_by:
---

# Trusted Deployment Host Entrypoint

## Summary
- Add a host-owned deployment entrypoint in the bot repo so config-space commands
  can later delegate to fixed deployment behaviour instead of running shell
  snippets or config-repo code directly.

## Scope
- `scripts/deploy-config.mjs` builds fixed argv calls for config fetch, trusted
  bot-repo validation, candidate install, and service restart.
- The config checkout is recreated under a fresh `work` directory for each
  apply and is passed to the trusted policy helper only as `--source-root`.
- GitHub fetch uses fixed host SSH policy rather than ambient agent, home, or
  proxy state.
- Host policy overrides for executable paths, repo paths, timeouts, and output
  caps require `WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES=1`.
- The entrypoint defaults to dry-run/status and requires `--apply` for mutation.
- Child processes run with a scrubbed environment that removes ambient Git,
  SSH-agent, proxy, home, and token-shaped variables.
- Child processes run from a fixed host cwd (`/`) while all trusted inputs are
  passed as absolute argv values, so a config checkout cannot affect local tool
  config discovery through the deploy script's inherited cwd.
- The entrypoint writes bounded deployment metadata after a successful apply,
  distinguishes skipped restarts, records generic apply and restart failure
  states, uses `failed_after_commit` for metadata failures after a successful
  restart, and rolls back the rendered config if restart fails.
- Child commands have per-command deadlines and bounded stdout/stderr capture;
  the lock parent and checkout directory must be deployment-user-owned `0700`
  directories.
- The trusted Jenkins helper is vendored into the bot repo with service-bounded
  graph fetch limits, redacted diagnostics snippets, explicit partial collection
  markers, and downstream traversal limited to structured Jenkins API metadata.
- Jenkins helper stdout exposes every prefetched GUI console URL for reply
  rendering allowlists while keeping the recommended reading preview short.
- Jenkins API graph discovery is kept separate from console log fetches so a
  missing or oversized root log does not prevent traversal to downstream jobs.

## Follow-Ups
- Wire fixed Webex admin commands to this entrypoint in the next PR.
- Add stronger protected-check verification before accepting a config revision
  when deployment host credentials and GitHub status access are finalised.
- Update config repo Jenkins helper paths to the trusted bot repo helper path
  before deploying with this entrypoint.
- Replace `systemctl restart` with a stronger handoff primitive if the service
  needs more availability guarantees than restore-on-restart-failure.
