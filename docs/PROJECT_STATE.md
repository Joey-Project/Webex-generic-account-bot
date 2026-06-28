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

## Recovery Pointers
- Active workstream: `docs/project_journal/2026/06/2026-06-18-generic-account-bot-mvp.md`
- Deployment automation and isolation roadmap: `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`
- Configuration Space workstream: `docs/project_journal/2026/06/2026-06-27-configuration-space-commands.md`
- Local index: optional generated `docs/project_journal/INDEX.md`; regenerate with the bundled `project_journal.py generate` helper.

## Global Blockers
- `/config pull` enablement depends on the ephemeral Linux-user runner so
  prompt-controlled Codex children cannot inherit the bot's worker-socket group.

## Notes
- Ordinary implementation state belongs in the active workstream journal.
