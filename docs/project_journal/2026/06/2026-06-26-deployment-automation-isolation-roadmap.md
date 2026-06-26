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
- Verify that the active bot binary, host-installed deployment entrypoint, and any release artifact to be reloaded match a protected, reviewed bot revision before accepting a reload.
- Record the deployed bot/config revisions and verified artifact identities in status output and install metadata.
- Run any allowed config-repo helper with a scrubbed, credential-free environment and constrained filesystem/network access; it must not receive GitHub/SSH fetch credentials, deployment tokens, production token files, or host reload privileges.
- Host-owned deployment policy must resolve and validate runtime secret paths and env selectors itself, including production token-file values that are intentionally absent from the helper environment; `--check-config` is an additional bot-schema check, not the sole secret-boundary check.
- Before install, enforce a deny-by-default host deployment policy for every security-relevant rendered config field. Fields that can run programs, grant access to secrets, select environment variables, disable authentication, widen filesystem scope, alter Webex routing/authorization, change Codex runtime policy, expose listeners, or consume host resources must be fixed by host policy or explicitly allowlisted.
- Boundary checks must cover Codex binaries, global and per-room `codex.cwd`, `codex.codex_home`, `state_file`, Jenkins artifact roots, Webex token file/env selectors, sidecar token env selectors, configured `self_person_id`, Jenkins helper binaries/scripts, Jenkins env files, future launcher helpers, and any equivalent override fields.
- The configured bot identity must be fixed or verified against the active Webex token identity so config cannot spoof another account for mention triggers, marker ownership, or reply reconciliation.
- Codex execution policy fields must be fixed or explicitly allowlisted, including global and per-room `profile`, `sandbox`, `approval_policy`, `skip_git_repo_check`, `ephemeral`, `codex.isolation.mode`, `codex.isolation.trusted_prompt_authors`, model/reasoning controls, and future runtime-mode fields.
- Webex routing, sender authorization, and write-policy fields must be fixed or explicitly allowlisted, including source rooms, staging/output rooms, admin command rooms, `allowed_person_ids`, `allowed_person_emails`, `allow_all_senders`, follow-up sender overrides, `read_only_source`, `forward_source_message`, trigger/follow-up policy, and any production-space write permission downgrade.
- Production room and follow-up policies must reject `allow_all_senders = true` unless a host-owned policy explicitly permits that exact room and mode.
- Listener and resource-control fields must be host-owned or explicitly bounded, including `server.bind`, concurrency limits, Webex attempt leases, Codex timeouts/output limits, Jenkins URL/time/output limits, and any retry or budget fields that can expose the service or exhaust host resources.
- Production deployment must require sidecar authentication and reject `server.allow_unauthenticated = true`.
- Path checks must canonicalise symlinks and verify ownership/permissions so approved roots cannot be bypassed through writable directories or symlink swaps.
- Failure before the commit point must leave the currently deployed config and running service untouched.
- The reload mechanism must either be a true in-process reload or a supervised handoff that keeps the old service healthy until the new config is validated and accepted; stop/start restarts are not sufficient for this safety target.
- Enforce single-flight deployment with a host-wide/interprocess lock; a process-local mutex may only be an additional guard. Define explicit duplicate-request semantics and machine-readable in-progress/status output.
- Include unit/smoke tests for argument parsing, failed validation, protected bot/config revision checks, runtime secret-path validation, helper credential/filesystem/network isolation, boundary allowlist rejection, identity mismatch rejection, isolation downgrade rejection, sender-authorization rejection, authentication downgrade rejection, resource-limit rejection, symlink/ownership rejection, atomic install behaviour, dry-run/status output, rollback/old-service health checks, and concurrent invocation handling.

### PR 2: Configuration Space Fixed Commands
- Repository: `Joey-Project/Webex-generic-account-bot`, with matching config updates if needed.
- Add allowlisted fixed commands for an admin configuration Space, initially `/config status`, `/config pull`, `/config reload`, and `/config sync`.
- Commands must call fixed argv only; user message text must never be interpolated into a shell command.
- Mutating commands must delegate to PR 1b's trusted entrypoint and deploy only an immutable revision that passed required checks; status replies must show the currently deployed bot/config revisions and any in-progress target revision.
- Commands must not accept user-provided source/output/admin Space IDs or execution-policy overrides; those must come from the host allowlist and reviewed config revision only.
- Require both a configured admin room and an explicit sender allowlist by person ID or email; `allow_all_senders` must not be available for the config command surface.
- Include wrong-room and wrong-sender tests for every fixed config command, including status and dry-run commands.
- Use the PR 1b deployment entrypoint as the backend, but do not synchronously reload the current bot from inside a Webex request handler.
- Mutating commands must durably create or successfully hand off a status-tracked deployment action before acknowledging acceptance; if that cannot be guaranteed, they must remain status/dry-run only.
- Include handoff failure, process-crash recovery, duplicate Webex event, and in-progress status tests so an accepted config command cannot be lost.

### PR 3: Runner Backend Abstraction for Existing Isolation Config
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Connect the existing `codex.isolation` configuration and `IsolationMode` model to an internal runner backend abstraction while keeping current-user execution as the default.
- Do not add a second isolation schema; preserve the existing `current-user` and `ephemeral-linux-user` mode names.
- Until PR 4 lands, deployable configs that set `ephemeral-linux-user` must continue to fail validation and `--check-config`; it must never become a runtime-only failure or silently fall back to current-user execution.
- Keep existing Codex execution behaviour unchanged for current configs, but route execution through a replaceable backend that PR 4 can implement.

### PR 4: Ephemeral Linux User Launcher
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Implement the privileged isolation backend with a narrow root-owned launcher or `systemd-run DynamicUser`.
- Each Codex run must get an isolated temporary user/workspace, receive only allowlisted inputs, and clean up after success, failure, or timeout.
- Codex auth must use brokered, tool-inaccessible credentials or one-time revocable per-run material that prompt-controlled code cannot read; writable home/cache/state directories must be per-run temporary paths that cannot persist data across Webex prompts.
- Network access must default to no egress or an explicit allowlist; any Codex API or auth-broker egress must be unavailable to prompt-controlled tool subprocesses.
- Launcher preflight and smoke tests must cover blocked localhost, host admin endpoints, metadata services, non-allowlisted internal networks, non-allowlisted public Internet, and DNS egress.
- Add tests showing one ephemeral run cannot read files, cache state, or credentials left by another run after success, failure, or timeout cleanup paths.
- Add negative tests showing an ephemeral run cannot read its own Codex auth material, bot/deployment secrets such as Webex token files, Jenkins env files, persistent Codex home, or host-owned config and deployment metadata.
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
