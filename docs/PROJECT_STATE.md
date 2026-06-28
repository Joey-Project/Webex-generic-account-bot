# Project State

## Current State
- Repo is being converted from the Codex review-gate template into a Rust Webex generic-account bot.
- First slice targets a synchronous sidecar receiver that maps Webex rooms to Codex prompt policies.
- PR1b deployment automation adds `scripts/deploy-config.mjs`, a host-owned
  fixed-argv entrypoint for fresh config fetch, trusted bot-repo
  validation/install policy, restart rollback, and dry-run/status support.
- Configuration Space PR 2a treats sidecar message fields as hints, hydrates
  every message through Webex before security decisions, and adds an optional
  explicit-sender admin Space with read-only `/config status`.
- Configuration Space PR 2b1 adds immutable staged config preparation without
  changing live config or service state.
- Configuration Space PR 2b2a adds the separate-identity durable pull-worker
  foundation. Bot socket-group access and deployable `/config pull` remain
  disabled until Codex runs use the isolated runner.
- Runner PR 3 routes each current-user Codex invocation through a replaceable
  backend with existing behaviour unchanged. `ephemeral-linux-user` remains
  rejected by config validation and `--check-config`, with no fallback.
- Runner PR 4a adds only the root-owned launcher
  protocol, caller-authorisation, and systemd socket foundation at
  `/run/webex-codex-launcher/launcher.sock`, backed by
  `/opt/webex-generic-account-bot/bin/webex-codex-launcher`. It remains
  fail-closed and is not a deployable isolation backend.

## Recovery Pointers
- Active workstream: `docs/project_journal/2026/06/2026-06-18-generic-account-bot-mvp.md`
- Deployment automation and isolation roadmap: `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`
- Configuration Space workstream: `docs/project_journal/2026/06/2026-06-27-configuration-space-commands.md`
- Local index: optional generated `docs/project_journal/INDEX.md`; regenerate with the bundled `project_journal.py generate` helper.

## Global Blockers
- PR 4b must still provide the immutable root image, transient `DynamicUser`
  execution, credential/model-channel separation, and crash cleanup; PR 4c
  must activate the runner and pass permission-capable production-image smoke
  tests. `DynamicUser` alone does not separate Codex main-process credentials
  or network access from same-UID tool descendants, and UID/group-only launcher
  authorisation does not distinguish those descendants.
- PR 4a does not grant bot group access, execute `systemd-run`, enable
  `ephemeral-linux-user`, or enable `/config pull`, `/config reload`, or
  `/config sync`.

## Notes
- Ordinary implementation state belongs in the active workstream journal.
