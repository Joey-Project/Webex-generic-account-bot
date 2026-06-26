---
id: 20260626-deployment-automation-isolation-roadmap
title: Deployment Automation and Isolation Roadmap
status: active
created: 2026-06-26
updated: 2026-06-26
branch: codex/roadmap-deploy-isolation
pr:
supersedes: []
superseded_by:
---

# Deployment Automation and Isolation Roadmap

## Summary
- Split deployment automation and Codex runner isolation into small PRs with independent worktrees and merge gates.

## Delivery Rules
- Each implementation PR uses its own worktree and branch.
- After each PR merges, refresh the target branch locally before creating the next worktree.
- Each PR must pass local validation, CI, an independent Codex PR review, an offline frozen-diff review, and any required GitHub review gate.
- Before merge, all actionable PR conversations must be fixed or explicitly resolved.
- Do not use admin bypass or forced checks unless Joey explicitly authorises that exact exception.

## Planned PRs

### PR 1: Deployment Host Pull/Validate/Reload
- Repository: `WebexServices-staging/webex-generic-account-bot-config`.
- Add a deployment-host sync entrypoint that fetches the config repo, renders production config, validates it, runs bot `--check-config`, and only then installs the rendered config and reloads the bot.
- The privileged entrypoint must come from a host-installed or otherwise trusted fixed path, not from the newly pulled config repo checkout.
- Treat the pulled config repo as data until validation succeeds; any repo-provided render helper must run as a low-privilege deployment user or inside a constrained workspace that cannot read production secrets or reload the bot.
- Failure must leave the currently deployed config and running service untouched.
- Include unit/smoke tests for argument parsing, failed validation, atomic install behaviour, and dry-run/status output.

### PR 2: Configuration Space Fixed Commands
- Repository: `Joey-Project/Webex-generic-account-bot`, with matching config updates if needed.
- Add allowlisted fixed commands for an admin configuration Space, initially `/config status`, `/config pull`, `/config reload`, and `/config sync`.
- Commands must call fixed argv only; user message text must never be interpolated into a shell command.
- Use the PR 1 deployment script as the backend.

### PR 3: Runner Backend Abstraction for Existing Isolation Config
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Connect the existing `codex.isolation` configuration and `IsolationMode` model to an internal runner backend abstraction while keeping current-user execution as the default.
- Do not add a second isolation schema; preserve the existing `current-user` and `ephemeral-linux-user` mode names.
- Keep existing Codex execution behaviour unchanged for current configs, but route execution through a replaceable backend that PR 4 can implement.

### PR 4: Ephemeral Linux User Launcher
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Implement the privileged isolation backend with a narrow root-owned launcher or `systemd-run DynamicUser`.
- Each Codex run should get an isolated temporary user/workspace, receive only allowlisted inputs, and clean up after success, failure, or timeout.
- Launcher integration must be covered by unit tests and, where host permissions allow, an opt-in integration smoke test.

## Current Open Decisions
- Whether the deployment host should use a system service reload, tmux-local restart, or a configurable reload command in the first production script.
- Whether the fixed Webex config commands should live in a dedicated room policy type or a fixed-command section attached to an existing room policy.
- Whether the privileged launcher should standardise on `systemd-run DynamicUser` first or ship a minimal root-owned helper first.

## Evidence
- Main bot PR #6 merged as `b44e509`.
- Config repo PR #11 merged as `d464a8a` and restored `Render` / `Bot Check Config` checks.
- Local staging deployment after PR #11 used bot `b44e509` and config `d464a8a`.
