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

### PR 1a: Low-Privilege Config Render and Validation
- Repository: `WebexServices-staging/webex-generic-account-bot-config`.
- Keep this repo limited to config data, render helpers, static validation, bot `--check-config`, and documentation.
- Add any helper tests needed for deployment-host use, but do not add a privileged install/reload entrypoint here.
- Repo-provided helpers must be safe to run as a low-privilege deployment user or inside a constrained workspace that cannot read production secrets or reload the bot.
- Production config must not be able to choose arbitrary executable paths that later run with bot or deployment privileges; executable fields such as `codex.bin`, Jenkins `node_bin`, Jenkins helper `script`, and future launcher paths must be fixed by host policy or validated against a deployment allowlist.

### PR 1b: Trusted Deployment Host Entry Point
- Repository: `Joey-Project/Webex-generic-account-bot` or a host-installed package delivered from the bot release process.
- Add the trusted fixed-path deployment entrypoint that fetches the config repo as data, invokes the low-privilege render/validation path, runs bot `--check-config`, and only then installs the rendered config and reloads the bot.
- The privileged entrypoint must never be executed from the newly pulled config repo checkout.
- Resolve the config source to an immutable commit SHA and verify expected repo/ref reachability plus required protected-branch checks before executing any config-repo-provided helper code or installing any rendered output.
- If that pre-helper verification cannot be made strong enough, render/validation code must be host-owned and config-repo checkouts must remain data-only.
- Record the deployed bot/config revisions in status output and install metadata.
- Before install, enforce the host executable, read-root, write-root, secret, and authentication allowlists for rendered config fields that can run programs, grant access to secrets, select environment variables, disable authentication, or widen filesystem scope.
- Boundary checks must cover Codex binaries, global and per-room `codex.cwd`, `codex.codex_home`, `state_file`, Jenkins artifact roots, Webex token file/env selectors, sidecar token env selectors, Jenkins helper binaries/scripts, Jenkins env files, future launcher helpers, and any equivalent override fields.
- Codex execution policy fields must be fixed or explicitly allowlisted, including global and per-room `sandbox`, `approval_policy`, `skip_git_repo_check`, `ephemeral`, model/reasoning controls, and future runtime-mode fields.
- Webex routing and write-policy fields must be fixed or explicitly allowlisted, including source rooms, staging/output rooms, admin command rooms, `read_only_source`, `forward_source_message`, trigger/follow-up policy, and any production-space write permission downgrade.
- Production deployment must require sidecar authentication and reject `server.allow_unauthenticated = true`.
- Path checks must canonicalise symlinks and verify ownership/permissions so approved roots cannot be bypassed through writable directories or symlink swaps.
- Failure before the commit point must leave the currently deployed config and running service untouched.
- The reload mechanism must either be a true in-process reload or a supervised handoff that keeps the old service healthy until the new config is validated and accepted; stop/start restarts are not sufficient for this safety target.
- Enforce single-flight deployment with a host-wide/interprocess lock; a process-local mutex may only be an additional guard. Define explicit duplicate-request semantics and machine-readable in-progress/status output.
- Include unit/smoke tests for argument parsing, failed validation, protected-revision checks, boundary allowlist rejection, authentication downgrade rejection, symlink/ownership rejection, atomic install behaviour, dry-run/status output, rollback/old-service health checks, and concurrent invocation handling.

### PR 2: Configuration Space Fixed Commands
- Repository: `Joey-Project/Webex-generic-account-bot`, with matching config updates if needed.
- Add allowlisted fixed commands for an admin configuration Space, initially `/config status`, `/config pull`, `/config reload`, and `/config sync`.
- Commands must call fixed argv only; user message text must never be interpolated into a shell command.
- Mutating commands must delegate to PR 1b's trusted entrypoint and deploy only an immutable revision that passed required checks; status replies must show the currently deployed bot/config revisions and any in-progress target revision.
- Commands must not accept user-provided source/output/admin Space IDs or execution-policy overrides; those must come from the host allowlist and reviewed config revision only.
- Require both a configured admin room and an explicit sender allowlist by person ID or email; `allow_all_senders` must not be available for the config command surface.
- Include wrong-room and wrong-sender tests for every fixed config command, including status and dry-run commands.
- Use the PR 1b deployment entrypoint as the backend, but do not synchronously reload the current bot from inside a Webex request handler.
- Until durable background job recovery exists, mutating commands must acknowledge first and then hand off to an out-of-process status-tracked action, or be limited to status/dry-run commands.

### PR 3: Runner Backend Abstraction for Existing Isolation Config
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Connect the existing `codex.isolation` configuration and `IsolationMode` model to an internal runner backend abstraction while keeping current-user execution as the default.
- Do not add a second isolation schema; preserve the existing `current-user` and `ephemeral-linux-user` mode names.
- Until PR 4 lands, deployable configs that set `ephemeral-linux-user` must continue to fail validation and `--check-config`; it must never become a runtime-only failure or silently fall back to current-user execution.
- Keep existing Codex execution behaviour unchanged for current configs, but route execution through a replaceable backend that PR 4 can implement.

### PR 4: Ephemeral Linux User Launcher
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Implement the privileged isolation backend with a narrow root-owned launcher or `systemd-run DynamicUser`.
- Each Codex run should get an isolated temporary user/workspace, receive only allowlisted inputs, and clean up after success, failure, or timeout.
- Codex auth must be provided as minimal read-only or copied per-run material, while writable home/cache/state directories must be per-run temporary paths that cannot persist data across Webex prompts.
- Add tests showing one ephemeral run cannot read files, cache state, or credentials left by another run.
- Add negative tests showing an ephemeral run cannot read bot/deployment secrets such as Webex token files, Jenkins env files, persistent Codex home, or host-owned config and deployment metadata.
- Enabling `ephemeral-linux-user` must require `--check-config` and deployment preflight to verify the launcher is present, fixed-path, root-owned, not writable by the bot/deployment user, uses fixed argv semantics, and has its required `DynamicUser` or helper capability available.
- If the launcher preflight is unavailable or fails, `ephemeral-linux-user` configs must stay undeployable and must not fall back to current-user execution.
- Launcher integration must be covered by unit tests plus at least one permission-capable opt-in integration smoke test before the mode is considered deployable.

## Current Open Decisions
- Which deployment reload primitive can preserve old-service availability: in-process reload, supervised blue/green handoff, or another rollback-capable mechanism.
- Whether the fixed Webex config commands should live in a dedicated room policy type or a fixed-command section attached to an existing room policy.
- Whether the privileged launcher should standardise on `systemd-run DynamicUser` first or ship a minimal root-owned helper first.

## Evidence
- Main bot PR #6 merged as `b44e509`.
- Config repo PR #11 merged as `d464a8a` and restored `Render` / `Bot Check Config` checks.
- Local staging deployment after PR #11 used bot `b44e509` and config `d464a8a`.
