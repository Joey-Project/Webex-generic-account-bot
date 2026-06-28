---
id: 20260626-deployment-automation-isolation-roadmap
title: Deployment Automation and Isolation Roadmap
status: active
created: 2026-06-26
updated: 2026-06-27
branch: codex/roadmap-deploy-isolation
pr:
supersedes: []
superseded_by:
---

# Deployment Automation and Isolation Roadmap

## Summary
- Split deployment automation and Codex runner isolation into small PRs with independent worktrees and merge gates.

## Current Progress
- Trusted deployment entrypoint merged in bot PR #8.
- Host-owned config layout migration merged in config PRs #13, #14, and #15.
- Configuration Space delivery is split into PR 2a (authoritative hydration,
  admin schema, read-only status), PR 2b1 (immutable staged preparation), PR
  2b2a (separate-worker durable queue foundation), PRs 3 and 4 (runner
  abstraction and ephemeral-user isolation), PR 2b2b (`/config pull`
  enablement), and PR 2b3 (recoverable activation plus `/config reload` and
  `/config sync`). Mutating commands remain undeployable until their security
  dependencies land.
- Bot PR #9 merged the PR 2a slice as `8448c5e6f4cb98fd448d461d18799d46cdb2fba5`.
- Bot PR #10 merged immutable staged preparation as
  `45d87b7d6fb59f7d751285a253b3cf7e21826563`.

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
- Treat the Git checkout itself as untrusted data: run Git with blank or controlled system/global/local config, credential scope, and environment allowlist; disable hooks, smudge filters, LFS smudge, submodule recursion, unsafe includes, credential helpers, `url.*.insteadOf`, `core.sshCommand`, `GIT_CONFIG_*`, `GIT_SSH*`, `SSH_AUTH_SOCK`, proxy env vars, inherited `HOME`/curl home, `.netrc`, and unexpected protocol redirects before verification; allow only the expected remote/protocol/ref; bound fetch/checkout runtime, CPU, disk/object size, file count, and worktree size with shallow/sparse/filter strategies; and test malicious system/global/repo Git config, Git environment, `.gitattributes`, `.gitmodules`, LFS config, large packfiles, and oversized worktrees cannot execute, egress, rewrite remotes, leak credentials, or exhaust the host.
- Resolve the config source to an immutable commit SHA and verify expected repo/ref reachability plus required protected-branch checks before executing any config-repo-provided helper code or installing any rendered output.
- If that pre-helper verification cannot be made strong enough, render/validation code must be host-owned and config-repo checkouts must remain data-only.
- Verify that the active bot binary, host-installed deployment entrypoint, and any release artifact to be reloaded match a protected, reviewed bot revision before accepting a reload.
- All PR 1b deployment operations, including Git, helper, install, and reload actions, must use fixed executables and argv arrays only; shell interpolation of repo/ref/path/render output/reload arguments must be forbidden and covered by injection tests.
- Record the deployed bot/config revisions and verified artifact identities in status output and install metadata.
- Status output, dry-run output, validation errors, helper stdout/stderr, and Codex runner stdout/stderr/final output surfaced to Webex, service logs, or persisted metadata must be length-limited and secret-redacted, including token values, secret paths, env names where sensitive, and credential-like material.
- Run any allowed config-repo helper with a scrubbed, credential-free environment, closed inherited file descriptors, constrained filesystem/network access, no SSH agent or proxy socket access, no Unix/abstract socket escape path, and no host reload privileges; it must not receive GitHub/SSH fetch credentials, deployment tokens, production token files, or equivalent secret material.
- Apply resource limits to config-repo helpers for runtime, CPU, memory, process/PID count, open files, and temporary disk/file size so render/validation cannot exhaust the deployment host or affect the running bot service.
- Apply the same isolation class to runtime context helpers that can read secrets or write Codex-visible artifacts, including Jenkins helpers: closed file descriptors, scrubbed environment, constrained filesystem/network/proxy/socket access, bounded runtime and resources, private artifact roots, and redacted/bounded stdout, stderr, summary files, and logs before they enter Codex prompts, workspaces, service logs, or Webex rendering.
- Host-owned deployment policy must resolve and validate runtime secret paths and env selectors itself, including production token-file values that are intentionally absent from the helper environment; `--check-config` is an additional bot-schema check, not the sole secret-boundary check.
- Before install, enforce a deny-by-default host deployment policy for every security-relevant rendered config field. Fields that can run programs, grant access to secrets, select environment variables, disable authentication, widen filesystem scope, alter Webex routing/authorization, change prompt or reply-rendering behaviour, change Codex runtime policy, expose listeners, or consume host resources must be fixed by host policy or explicitly allowlisted.
- The host deployment policy must prove full rendered-config schema coverage: any current or newly added bot config field must be classified as fixed, explicitly allowlisted, explicitly bounded, or rejected before deployment can pass.
- Boundary checks must cover Codex binaries, global and per-room `codex.cwd`, `codex.codex_home`, `state_file`, Jenkins artifact roots, Webex token file/env selectors, sidecar token env selectors, configured `self_person_id`, Jenkins helper binaries/scripts, Jenkins env files, future launcher helpers, and any equivalent override fields.
- Runtime context helpers that can feed Codex prompts or Webex replies, including Jenkins helper stdout/stderr and generated summary files, must have bounded capture and secret redaction before prompt insertion, logging, or rendering.
- The configured bot identity must be fixed or verified against the active Webex token identity so config cannot spoof another account for mention triggers, marker ownership, or reply reconciliation.
- Codex execution policy fields must be fixed or explicitly allowlisted, including global and per-room `profile`, `sandbox`, `approval_policy`, `skip_git_repo_check`, `ephemeral`, `codex.isolation.mode`, `codex.isolation.trusted_prompt_authors`, model/reasoning controls, and future runtime-mode fields.
- Webex routing, sender authorization, and write-policy fields must be fixed or explicitly allowlisted, including source rooms, staging/output rooms, admin command rooms, `allowed_person_ids`, `allowed_person_emails`, `allow_all_senders`, follow-up sender overrides, `read_only_source`, `forward_source_message`, trigger/follow-up policy, and any production-space write permission downgrade.
- Prompt and rendering fields must be fixed or explicitly allowlisted, including room `prompt_template`, follow-up `prompt_template`, `reply_format`, and future renderer selection fields.
- Production room and follow-up policies must reject `allow_all_senders = true` unless a host-owned policy explicitly permits that exact room and mode.
- Listener and resource-control fields must be host-owned or explicitly bounded, including `server.bind`, `server.event_path`, `server.health_path`, concurrency limits, Webex attempt leases, Codex timeouts/output limits, Jenkins URL/time/output limits, and any retry or budget fields that can expose the service, break sidecar/probe routing, or exhaust host resources.
- Production deployment must require sidecar authentication and reject `server.allow_unauthenticated = true`.
- Path checks must canonicalise symlinks and verify ownership/permissions so approved roots cannot be bypassed through writable directories or symlink swaps; validated artifacts must be read and installed with race-resistant handles such as trusted output roots, held directory file descriptors, `openat`/`O_NOFOLLOW`, and atomic rename/commit semantics so validation and installation operate on the same object.
- Failure before the commit point must leave the currently deployed config and running service untouched.
- The reload mechanism must either be a true in-process reload or a supervised handoff that keeps the old service healthy until the new config is validated and accepted; stop/start restarts are not sufficient for this safety target.
- Reload and handoff must define in-flight Webex attempt and Codex-run semantics: active work must drain, transfer its lease, or be retried without lost or duplicate replies before any old process is stopped.
- Enforce single-flight deployment with a host-wide/interprocess lock; a process-local mutex may only be an additional guard. Define explicit duplicate-request semantics and machine-readable in-progress/status output.
- Include unit/smoke tests for argument parsing, fixed-argv/no-shell execution, failed validation, protected bot/config revision checks, safe Git checkout settings, schema-policy completeness, runtime secret-path validation, helper credential/filesystem/network/fd/socket isolation, helper resource-exhaustion rejection, status/error/context-helper/Codex-output redaction and truncation, boundary allowlist rejection, identity mismatch rejection, isolation downgrade rejection, sender-authorization rejection, prompt/rendering policy rejection, authentication downgrade rejection, resource/listener rejection, symlink/ownership/TOCTOU rejection, atomic install behaviour, dry-run/status output, in-flight attempt handoff/drain, rollback/old-service health checks, and concurrent invocation handling.

### PR 2: Configuration Space Fixed Commands
- Repository: `Joey-Project/Webex-generic-account-bot`, with matching config updates if needed.
- Add allowlisted fixed commands for an admin configuration Space, initially `/config status`, `/config pull`, `/config reload`, and `/config sync`.
- Commands must call fixed argv only; user message text must never be interpolated into a shell command.
- All bot decisions that can trigger Codex execution or Webex writes must use authoritative Webex-hydrated room, sender, body, mentions, and parent/thread fields; sidecar event payload fields may only be hints.
- Include forged payload and sidecar-versus-hydrated mismatch tests for ordinary prompt execution, follow-up execution, routing, and reply/write decisions.
- Mutating commands must delegate to PR 1b's trusted entrypoint and deploy only an immutable revision that passed required checks; status replies must show the currently deployed bot/config revisions and any in-progress target revision.
- Commands must not accept user-provided source/output/admin Space IDs or execution-policy overrides; those must come from the host allowlist and reviewed config revision only.
- Require both a configured admin room and an explicit sender allowlist by person ID or email; `allow_all_senders` must not be available for the config command surface.
- Authorise and select config commands only after hydrating the message from Webex and parsing the authoritative room, sender, and command body from that hydrated message; sidecar event payload fields must not be trusted for command authorisation or action selection.
- Include wrong-room, wrong-sender, forged sidecar-payload, and sidecar-body-versus-hydrated-body mismatch tests for every fixed config command, including status and dry-run commands.
- Use the PR 1b deployment entrypoint as the backend, but do not synchronously reload the current bot from inside a Webex request handler.
- Mutating commands must durably create or successfully hand off a status-tracked deployment action before acknowledging acceptance; if that cannot be guaranteed, they must remain status/dry-run only.
- Include handoff failure, process-crash recovery, duplicate Webex event, and in-progress status tests so an accepted config command cannot be lost.

#### PR 2b1: Immutable Staged Preparation
- Add an explicit trusted prepare mode that fetches, renders, validates, and
  durably records one immutable config revision without replacing the live
  rendered config or touching the bot service.
- Keep all mutating Webex commands undeployable in this slice.
- Do not treat the existing install-without-restart mode as pull: it replaces
  the live config and discards the cross-action rollback boundary.

#### PR 2b2a: Durable Pull Worker Foundation
- Run a stable, separate deployment identity behind a host-owned Unix socket.
  The bot may submit only an exact message ID and fixed action enum.
- The worker must durably deduplicate and enqueue before acknowledging the bot,
  recover queued/running work after restart, and invoke the trusted prepare
  backend with fixed argv.
- Keep bot socket-group access and deployable `/config pull` disabled because
  current-user Codex children inherit the bot's supplementary groups.

#### PR 2b2b: Pull Enablement After Runner Isolation
- Merge PRs 3 and 4 first and prove prompt-controlled Codex subprocesses cannot
  access the worker socket, bot/deployment secrets, or host `/run` paths.
- Then grant the bot socket access and enable `/config pull` only after socket
  authorization, queue durability, duplicate-event, crash-recovery, fixed-argv,
  ownership, symlink, and isolated-child denial tests pass.

#### PR 2b3: Recoverable Activation
- Add activation of an already staged immutable revision without network fetch,
  including deployment transaction recovery, health verification, rollback,
  and explicit in-flight attempt/Codex-run drain or handoff semantics.
- Enable `/config reload` and `/config sync` only after those guarantees and the
  worker's target-revision persistence are tested.

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
- Filesystem access must be deny-by-default with a mount/filesystem namespace, bind-mounted workspace and allowlisted inputs, private temporary storage, protected home paths, restricted `/proc`, `/run`, and device access, and negative tests for host canary files, symlink escapes, procfs/run leaks, and device paths.
- The launcher must drop capabilities, set `no_new_privs`, clear ambient/bounding capability sets, and prevent setuid or capability-bearing binaries from escalating prompt-controlled subprocesses; include setuid and file-capability canary tests.
- Prompt-controlled subprocesses must not be able to invoke the privileged launcher, `systemd-run`, sudoers/polkit paths, or systemd DBus/socket controls directly; launcher access must be caller-bound to the trusted bot path and covered by rejection tests from inside an ephemeral run.
- Codex auth must use brokered, tool-inaccessible credentials or one-time revocable per-run material that prompt-controlled code cannot read; writable home/cache/state directories must be per-run temporary paths that cannot persist data across Webex prompts.
- Network access must default to no egress or an explicit allowlist; any Codex API or auth-broker egress must be unavailable to prompt-controlled tool subprocesses while the Codex runner itself remains able to reach the required model/auth channel.
- Egress controls must block proxy env variables, SSH agents, inherited file descriptors, Unix/abstract sockets, local proxy sockets, and equivalent non-TCP/DNS bypasses unless each is explicitly needed and isolated from prompt-controlled subprocesses.
- Launcher preflight and smoke tests must prove Codex model/auth access still works, prove prompt-controlled subprocesses cannot reuse that channel, and cover blocked localhost, host admin endpoints, metadata services, non-allowlisted internal networks, non-allowlisted public Internet, DNS egress, proxy/agent/socket bypasses, and inherited descriptor leaks.
- The launcher must apply OS or cgroup resource limits for CPU, memory, process/PID count, open files, and temporary disk/file size, with negative tests for fork, memory, and disk exhaustion attempts.
- Add tests showing one ephemeral run cannot read files, cache state, workspace data, or credentials from another simultaneous run, or left by another run after success, failure, timeout, bot crash, launcher crash, or host reboot cleanup paths.
- Use crash/orphan cleanup or a UID/workspace non-reuse policy so stale prompt data, cache files, and credentials cannot be observed by later runs even when normal cleanup did not complete.
- Add negative tests showing an ephemeral run cannot read its own Codex auth material, bot/deployment secrets such as Webex token files, Jenkins env files, persistent Codex home, or host-owned config and deployment metadata.
- Enabling `ephemeral-linux-user` must require `--check-config` and deployment preflight to verify the launcher is present, fixed-path, root-owned, not writable by the bot/deployment user, uses fixed argv semantics, and has its required `DynamicUser` or helper capability available.
- If the launcher preflight is unavailable or fails, `ephemeral-linux-user` configs must stay undeployable and must not fall back to current-user execution.
- Launcher integration must be covered by unit tests plus at least one permission-capable opt-in integration smoke test before the mode is considered deployable.

## Current Open Decisions
- Which deployment reload primitive can preserve old-service availability: in-process reload, supervised blue/green handoff, or another rollback-capable mechanism.
- Whether the privileged launcher should standardise on `systemd-run DynamicUser` first or ship a minimal root-owned helper first.

## Resolved Decisions
- Fixed Webex config commands use a dedicated top-level `[config_commands]`
  section, separate from ordinary room policies and with an explicit admin
  Space and sender allowlist.

## Evidence
- Main bot PR #6 merged as `b44e509`.
- Config repo PR #11 merged as `d464a8a` and restored `Render` / `Bot Check Config` checks.
- Local staging deployment after PR #11 used bot `b44e509` and config `d464a8a`.
