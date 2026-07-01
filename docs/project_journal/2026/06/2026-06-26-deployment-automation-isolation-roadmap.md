---
id: 20260626-deployment-automation-isolation-roadmap
title: Deployment Automation and Isolation Roadmap
status: active
created: 2026-06-26
updated: 2026-07-01
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
  2b2a (separate-worker durable queue foundation), completed PR 3 (runner
  backend abstraction), PR 4a (root-owned launcher foundation), PR 4b
  (isolated execution), PR 4c1a (boot-scoped activation receipt foundation),
  PR 4c1b (root fresh-inode input sealer), PR 4c1c (gated runner wiring), PR
  4c2a1 (canary contract/probe), 4c2a2 (production-image and lifecycle
  canaries plus receipt helper), 4c2b (transactional final activation), PR
  2b2b1 (config-pull permission and schema boundary), PR 4d1 (base bot host
  contract), PR 4d2 (guarded host provisioner), PR 2b2b2 (reviewed Space and
  config enablement), and PR 2b3 (recoverable
  activation plus `/config reload` and `/config sync`). Mutating commands
  remain undeployable until their security dependencies land.
- Bot PR #9 merged the PR 2a slice as `8448c5e6f4cb98fd448d461d18799d46cdb2fba5`.
- Bot PR #10 merged immutable staged preparation as
  `45d87b7d6fb59f7d751285a253b3cf7e21826563`.
- Runner PR 3 routes each current-user invocation through a replaceable backend
  while preserving existing execution behaviour. Config validation and
  `--check-config` still reject `ephemeral-linux-user`, with no fallback.
- PR 4a establishes the root-owned launcher protocol,
  caller-authorisation, and systemd socket foundation, but remains fail-closed
  and is not deployable. It does not grant bot group access, execute
  `systemd-run`, enable `ephemeral-linux-user`, or enable any config command.
- PR 4b adds the pinned content-addressed SquashFS image, static ELF checks,
  FD-bound root-sealed input handoff through a dedicated read-only group, transient
  `DynamicUser` unit, inner Codex permission profile, and bounded unit cleanup.
  It remains inactive: the bot is not a member of either input or launcher
  group, a compile-time launcher gate rejects preflight/execute, and config
  validation still rejects `ephemeral-linux-user`.
- PR 4c is split further so each privilege boundary receives an independent
  frozen review. PR 4c1a defines and verifies the root-owned boot-scoped
  activation receipt but does not call it or provide a minting command. PR
  4c1b owns the root fresh-inode input sealer, PR 4c1c owns client/runner
  wiring, and PR 4c2 owns live canaries plus final activation. Bot socket
  groups and `/config pull`, `/config reload`, and `/config sync` remain
  disabled in PR 4c1a.
- PR 4c1c wires the fixed launcher client, explicit Jenkins evidence staging,
  root fresh-inode sealer, boot-ID systemd credential, and exact
  `ephemeral-linux-user` dispatcher path. It grants no bot launcher group or
  pending-root path while current-user children could inherit them; PR 4c2
  owns that access as part of atomic ephemeral activation. The bot never
  receives the sealed-input group. Config validation rejects mixed
  current-user and ephemeral effective runner configurations, then rejects all
  ephemeral activation in this slice. PR 4c2 must remove that final gate only
  while adding bot access and minting the boot-scoped receipt after production
  canaries pass; 4c1c `--check-config` therefore stops at the activation gate,
  and production config remains current-user until then.
  Preflight, evidence staging, and launcher preparation use explicit bounded
  budgets that are included in ephemeral attempt-lease validation. Blocking
  file workers check cooperative deadlines and launcher-socket cancellation;
  the launcher waits for their scoped cleanup instead of detaching them.
  Independent process watchdogs terminate stuck staging or launcher
  preparation before the surrounding 10-minute lease budget, while client
  disconnect gives cooperative launcher cleanup a final 105-second grace.
  Source-quarantine deletion fsyncs its parent before success, and consumed
  cleanup runs in a blocking worker with a 50-second hard bound inside the
  protocol's 110-second cleanup allowance after at most 50 seconds of
  transient-unit cleanup. Socket trigger capacity includes
  startup preflight and both per-run launcher connections.
  Pending workspace publication and bot-side removal use `syncfs` through the
  held workspace fd before returning, preserving a non-enumerable `2730`
  pending root. Normal post-staging cleanup runs in a bounded blocking worker;
  async task drop defers the private tree to the existing tmpfiles crash
  fallback instead of performing recursive I/O on a runtime thread.
  Configured request concurrency cannot exceed the socket's four accepted
  connections, and the service runtime maximum stays above the protocol's
  largest request plus preparation, cleanup, and response budget.
  Normal success, rejection, timeout, client disconnect, and cancellation
  remove ready, source-quarantine, and consumed sealed trees by verified inode;
  ready trees remain group-inaccessible until consumed, and tmpfiles remains
  the crash fallback.
- PR 4c2a2 implements the pinned Codex JSONL event validator, trusted runtime
  interior evidence, nonce-scoped host fixtures/listeners, timeout and launcher
  owner-crash lifecycle checks, a pidfd-backed bot peer-exit supervisor check,
  a real-reboot challenge, and root-only atomic receipt renewal. It remains
  inactive and grants no bot launcher permission; PR 4c2b still owns the
  deployment transaction and production switch.
- PR 4c2b implements explicit transactional runner activation with a strict
  ephemeral-only staging policy, version 2 config/drop-in/receipt recovery,
  bounded receipt renewal, bot host preflight, minimum launcher/pending access,
  restart/readiness rollback, boot-time renewal ordering, and downgrade
  prevention after permission activation. The explicit command refuses a
  repeated activation once the permission drop-in is installed; boot renewal
  and later ordinary ephemeral-only config applies own subsequent lifecycle.
  Renewal stop verification cannot suppress three-state or old-service
  recovery, and an unresolved stop leaves the recovery journal in place.
  Permission rollback precedes any config downgrade; a failed drop-in removal
  leaves the ephemeral config and journal intact. The renewal unit is part of
  the bot restart lifecycle and uses a fixed ensure command so a valid receipt
  is a fast no-op while a missing or stale receipt runs the full canaries.
  Ordinary active-runner apply reloads an active renewal unit to ensure the
  receipt without propagating a bot stop or restart. If the bot and renewal
  unit are already inactive, it starts the renewal unit instead. A permission
  drop-in installed outside the transaction fails closed unless the live
  rendered config is already fully ephemeral. Every apply reloads the systemd
  manager before permission detection so stale loaded drop-in state cannot
  select the wrong isolation policy. Permission-relevant reloads reject any
  other loadable unit, prefix, or service-wide drop-in across systemd's control,
  runtime, generator, local, and vendor paths, and verify the fixed managed
  drop-in state both before and after reload. Version 2 journals may record the
  exact reviewed launcher-only policy that predates migration, and rollback
  restores only that byte-matched legacy policy. Rollback reloads the manager
  after permission removal and before config downgrade; reload failure preserves
  the ephemeral config and recovery journal. When a crash journal records that a
  service transition started or completed pending metadata, any startup
  permission preflight failure stops the bot and verifies it inactive before
  leaving the journal for recovery.
  Recovery mode rejection, including ordinary apply over a version 2 journal
  or skip-restart over a service transition, applies the same containment.
  Recovery records `activation_files_installing` before writing the new config
  and drop-in. Both that phase and `activation_files_installed` contain startup
  preflight failures and stop the bot before rollback, covering a reboot that
  loaded the new group policy before the service-transition phase was recorded.
  After restoring an existing old config, recovery restarts and verifies the
  old service before continuing.
  A failed new-service transition, from activation or an ordinary active-runner
  update, stops and verifies the bot before restoring permission or config, so
  a crash cannot leave inherited groups in a process after the on-disk policy
  has rolled back. Recovery from `committed_pending_metadata` renews any active
  runner receipt and re-verifies service readiness before clearing the journal.
  Receipt-only rollback failures retain the journal and fail the action after
  restoring the prior config and service.
  Ordinary apply enforces current-user policy while permission is absent and
  ephemeral-only policy while it is present, leaving explicit activation as
  the only mode transition.
  Committed legacy apply recovery continues into an explicitly requested
  activation instead of returning ordinary deployment metadata as success.
  The production host still requires
  a matching reviewed config and a successful real-reboot canary run.
- PR 2b2b1 adds the config-worker socket group to the same fixed drop-in owned
  by the runner activation transaction, so it cannot be independently granted
  while current-user Codex execution is active. The Rust schema allows `pull`
  only for a fully ephemeral effective runner configuration, while `reload`
  and `sync` remain invalid. Transient Codex receives only the input group and
  continues to hide and deny `/run/webex-config-pull`; the activation canary
  probes the real worker socket. Host policy recognises the command schema but
  keeps the admin Space pin disabled. PR 2b2b2 owns the exact room pin,
  companion config change, deployment, and Webex E2E.
- Host discovery after PR 2b2b1 found no installed bot, activation, or worker
  units and no repository-owned base bot service. PR 4d1 therefore adds the
  stable unprivileged bot identity, fixed service, and root-managed versus
  bot-writable filesystem contract. It grants no launcher, input, or
  config-worker group and does not install secrets, assets, units, or the
  activation drop-in. PR 4d2 adds the guarded dry-run/apply provisioner with a
  fixed non-secret allowlist, stable no-follow reads of complete files identity
  and gshadow databases, a DynamicUser-only systemd userdb boundary,
  identity-drift, locked-group-credential, and cross-group shadow-grant checks,
  dormant-unit
  preflight, transactional policy-file installation, device-bound kernel lock
  verification shared with config deployment, exact loaded-fragment and
  no-drop-in, no-stale-manager, and no-external-reverse-activator checks,
  enabled-unit next-boot dependency graph inspection, fixed-path scanning for
  unloaded policy and dependency directories across all managed units plus
  template, instance, type-level, and dash-prefix overrides, with exact
  usr-merge compatibility, merged boot sysusers/tmpfiles policy auditing,
  trusted re-exec paths, bounded streamed stale candidate cleanup and unit
  discovery, recovery-before-write dormancy checks, immediate recovery-time
  manager reload, explicit complete-target stale-cache convergence recovery,
  fail-closed recovery with full target-directory durability,
  non-rollback journal-unlink failure handling, interrupted first-run lock
  migration recovery, and post-reload verification. Real host apply remains an
  explicit operational gate.

## Delivery Rules
- Each implementation PR uses its own worktree and branch.
- After each PR merges, refresh the target branch locally before creating the next worktree.
- Each PR must pass the complete local test/build gate, one local Codex review,
  one Claude review, CI, and the remote PR Codex review/required gate.
- Before merge, all actionable PR conversations must be fixed or explicitly resolved.
- Do not use admin bypass or forced checks unless Joey explicitly authorises that exact exception.

## Planned PRs

### PR 4d1: Base Bot Host Contract
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Define a stable non-login bot identity, fixed base service, and explicit
  tmpfiles ownership boundary for root-managed config/token inputs and
  bot-writable state, Codex home, and workspace.
- Keep privileged supplementary groups and pending-input access absent from the
  base service; the reviewed activation drop-in remains their only source.
- Ship policy assets and tests only. Do not install files, create secrets,
  enable units, stop the tmux staging deployment, or mutate the host.

### PR 4d2: Guarded Host Provisioner
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Add a default-dry-run, explicit-apply provisioner with a fixed artifact
  allowlist, atomic root-owned installation, sysusers/tmpfiles application,
  manager reload, and post-install verification.
- Before installation, reject pre-existing static bot membership in every
  launcher, input, config-pull, or config-deploy group because systemd extends
  user-database groups even after an empty `SupplementaryGroups=` assignment.
  Also reject worker membership in the bot group or any bot-secret group.
- Install the complete root-owned policy file set transactionally with atomic
  per-file replacement. If a later
  commit is interrupted, recover the old set from a fixed root-only journal
  before reapplying, but reject any target that matches neither the recorded
  old nor desired digest. Apply the same all-target digest gate before rollback.
  Require an exact `files systemd` NSS policy, enumerate static identities from
  `files`, reject static systemd userdb records and managed IDs in the
  DynamicUser range, require locked files-backed gshadow credentials for every
  managed privilege group, and permit only the trusted DynamicUser provider.
  Fsync every target directory and re-verify the complete old target set before
  clearing a recovery journal. Keep that journal while immediately reloading
  systemd after startup recovery, and prove every managed unit and discovered
  instance dormant before and after recovery mutates policy. Do not begin a
  second rollback after a fully installed desired set reaches journal unlink but
  its directory fsync fails. Serialise the full apply with
  a PID/device/inode-bound kernel lock shared with config deployment, validate
  every re-exec path ancestor, stream a bounded scan that removes only trusted
  stale candidates, and bound and reject active launcher template instances as
  well as active template units. Allow only the exact root-owned half-migrated
  first-run lock state, then require tmpfiles to converge and revalidate the held
  inode before success. Require each loaded unit and instance to use the fixed
  managed fragment without any
  drop-ins, and reject unloaded unit overrides, drop-ins, wants, and requires
  for every managed unit and launcher instance from every fixed systemd
  system-unit load path while
  accepting only the exact root-owned `/lib -> usr/lib` compatibility link. If
  a later sysusers, tmpfiles, manager-reload, or
  post-verification step fails, retain that complete set and fail with an
  explicit convergent-rerun requirement; do not claim rollback of users or
  directories already created by systemd.
- Never copy secrets, install the activation-owned bot drop-in, enable the bot,
  or run the real reboot challenge as an implicit side effect.

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

#### PR 2b2b1: Pull Permission and Schema Boundary
- Merge PRs 3, 4a, 4b, and 4c first and prove prompt-controlled Codex
  subprocesses cannot access the worker socket, bot/deployment secrets, or host
  `/run` paths.
- Add the config-worker group to the transactional runner permission drop-in,
  allow the `pull` schema only under fully ephemeral isolation, and keep the
  production admin-room pin disabled.

#### PR 2b2b2: Reviewed Pull Enablement
- Pin the exact admin Space and sender, update the reviewed config repository,
  and enable `/config pull` only after socket authorization, queue durability,
  duplicate-event, crash-recovery, fixed-argv, ownership, symlink, and
  isolated-child denial tests pass.

#### PR 2b3: Recoverable Activation
- Add activation of an already staged immutable revision without network fetch,
  including deployment transaction recovery, health verification, rollback,
  and explicit in-flight attempt/Codex-run drain or handoff semantics.
- Enable `/config reload` and `/config sync` only after those guarantees and the
  worker's target-revision persistence are tested.

### PR 3: Runner Backend Abstraction for Existing Isolation Config
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Status: completed on 2026-06-28.
- The existing `codex.isolation` schema and `IsolationMode` names are unchanged.
- Each current-user invocation now dispatches through a replaceable backend
  while preserving existing execution behaviour.
- Config validation and `--check-config` continue to reject
  `ephemeral-linux-user`; it never becomes a runtime-only failure or silently
  falls back to current-user execution.

### PR 4a: Root-Owned Launcher Protocol and Socket Foundation
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Status: completed on 2026-06-28; foundation only, fail-closed, and not
  deployable.
- Reserve the fixed socket path
  `/run/webex-codex-launcher/launcher.sock` and fixed executable path
  `/opt/webex-generic-account-bot/bin/webex-codex-launcher`.
- Define a versioned, bounded, length-prefixed request/response protocol with
  one frame per credentialled `SOCK_SEQPACKET` packet, without accepting
  arbitrary executables, argv, environment variables, unit properties, or
  paths outside validated fields.
- Add root-owned systemd socket activation with one launcher service instance
  per accepted connection and host-owned sysusers/tmpfiles definitions.
- Authorise each connection from kernel `SO_PEERCRED` plus atomic
  `SO_PEERPIDFD`, and require the request packet's `SCM_CREDENTIALS` to match,
  but never authorise by UID or group alone. Require the peer PID to be the
  exact live `MainPID` of
  `webex-generic-account-bot.service`, running the fixed root-owned bot binary
  in the exact service cgroup; bind authorisation to a pidfd and stable process
  snapshot so child callers, PID reuse, executable replacement, and caller
  exit fail closed.
- Require Linux cgroup v2 explicitly through
  `/sys/fs/cgroup/cgroup.controllers` and require kernel `SO_PEERPIDFD`
  support; unsupported hosts fail closed before request parsing.
- Start the root launcher service with only `CAP_SYS_PTRACE` for different-UID
  bot inspection and `CAP_SETPCAP` for the irreversible drop; expose no ambient
  capability, remove both capabilities from the bounding and thread sets after
  caller authorisation and before reading the untrusted request packet, and
  never pass them into a launcher-created Codex unit.
- UID/group-only authorisation is insufficient because prompt-controlled Codex
  descendants inherit the bot identity and supplementary groups.
- PR 4a does not grant the bot membership in `webex-codex-launch` or any config
  worker group, execute `systemd-run`, enable
  `codex.isolation.mode = "ephemeral-linux-user"`, or enable `/config pull`,
  `/config reload`, or `/config sync`.

### PR 4b: Isolated DynamicUser Execution
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Build an immutable root-owned runtime image and execute each Codex run in a
  transient `DynamicUser` unit through the narrow root-owned launcher.
- `DynamicUser` alone is not the isolation boundary: the Codex main process and
  prompt-controlled tool descendants share the same UID. Provide a
  credential/model-access channel available to the Codex main process but not
  reusable, readable, or reachable by same-UID tool descendants, and apply the
  corresponding network boundary at process rather than UID granularity.
- Own cross-UID output and read-only input handling; cgroup and process
  containment; credential brokerage; inherited file descriptor and
  supplementary-group clearing; filesystem, network, and resource isolation;
  and launcher preflight.
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

### PR 4c1a: Boot-Scoped Activation Receipt Foundation
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Define a deny-unknown-fields receipt that binds the current boot ID, active
  runtime manifest and image identity, fixed executable digests, pinned Codex
  version/model, and the exact required production-canary result set.
- Verify fixed root-owned paths with bounded no-follow reads, stable file
  identities, strict owner/mode/link/type checks, and atomic root-only writes.
- Provision only the root-owned `/run/webex-codex-activation` directory. Do not
  pre-create a receipt, call the verifier from runtime paths, add bot groups,
  or provide a command that can mint a receipt in this slice.

### PR 4c1b: Root Fresh-Inode Input Sealer
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Add the narrow root-owned input sealer required to convert bot output into
  the recursively immutable PR 4b workspace contract without relabelling
  bot-owned inodes in place.
- Quarantine the pending source before inspection, copy through no-follow
  descriptor-relative operations, enforce the existing depth/entry/byte
  limits, and publish with no-replace semantics only after recursive metadata
  validation and durability checks.
- Resolve the fixed launch/input groups through one trusted host policy and
  reject access or default POSIX ACLs on roots, source entries, sealed entries,
  and runtime re-verification so mode-bit checks cannot be bypassed.
- Reject static primary-GID users for both privileged groups, then consume a
  verified workspace with descriptor-relative same-mount no-replace rename and
  fsync both parent directories before launch. Hash each source while copying
  and compare a second full read before publication to reject same-size races.
- Provision the pending/source-consumed/staging roots and give only the root
  launcher the supplementary groups and writable paths needed after its
  capability drop. Do not add a bot drop-in, launcher client, runtime call
  site, or activation-receipt access in this slice.

### PR 4c1c: Gated Runner Wiring
- Repository: `Joey-Project/Webex-generic-account-bot`.
- Connect the `ephemeral-linux-user` runner backend to the fixed PR 4a launcher
  only after the PR 4b boundary is present. Do not add a bot group/drop-in
  while current-user Codex children could inherit launcher access.
- Enabling `ephemeral-linux-user` must require `--check-config` and deployment preflight to verify the launcher is present, fixed-path, root-owned, not writable by the bot/deployment user, uses fixed argv semantics, and has its required `DynamicUser` or helper capability available.
- If the launcher preflight is unavailable or fails, `ephemeral-linux-user` configs must stay undeployable and must not fall back to current-user execution.
- Preserve `ProcSubset=pid`: copy the current kernel boot ID into the launcher
  with a root-owned systemd credential and verify activation through
  the launcher-specific activation path instead of exposing `/proc/sys`.
- Bind bot startup and every launcher verification to the currently executing
  `/proc/self/exe` path, inode metadata, and digest as well as the fixed path
  and receipt, so an old process cannot accept a receipt minted for an
  atomically replaced executable.
- Bind each verified activation snapshot to the exact active-manifest bytes and
  selected image digest used by the run, and send launcher diagnostics only to
  journal-backed `stderr` so protocol `stdout` remains unmodified. Bound and
  sanitise internal failure causes before logging them.

### PR 4c2: Production-Image Smoke Tests and Final Activation
- Repository: `Joey-Project/Webex-generic-account-bot`, with a matching config
  change only after the host canaries pass.
- Run permission-capable opt-in integration smoke tests against the production
  image, fixed executable/socket paths, systemd units, ownership, group, and
  socket permissions before the mode is considered deployable.
- Smoke tests must prove Codex model/auth access works for the main process;
  prompt-controlled descendants cannot reuse the credential/model channel,
  launcher socket, bot/config-worker sockets, or forbidden network paths; and
  timeout, launcher crash, bot crash, and host-reboot cleanup converge safely.
- Install the minimum bot launcher-group and pending-path access only in the
  same activation that switches production away from current-user execution.
- Run the real production image to prove the main process can write the bounded
  final message, tool subprocesses cannot read auth/main-home/final-output
  paths, and launcher stdout contains only the final message before minting the
  receipt.
- PR 4c2 activates only the runner. `/config pull`, `/config reload`, and
  `/config sync` remain owned by PRs 2b2b and 2b3 and stay disabled here.

#### PR 4c2 delivery split
- PR 4c2a1 adds the exact `runtime-boundary-v1` report schema, static syscall
  probe, immutable image allowlist entry, and activation-time host probe
  digest/size binding. Inconclusive socket timeouts and a merely absent but
  creatable final-output path fail closed. It does not run Codex, mint a
  receipt, install a bot drop-in, or remove the config gate.
- PR 4c2a2 validates the probe through the pinned Codex `exec --json`
  command-execution event. Its host harness must create nonce-scoped protected
  regular file, nested read-only workspace file, and live Unix/TCP listener
  fixtures before launch, use the nonce as the transient run ID, create exact
  nonce-scoped files in both private main-process homes and beside the real
  final-output path, use a controlled non-loopback unicast forbidden-network
  listener, verify the derived credential and all fixtures before and after
  Codex, require every regular-file fixture to retain its identity and
  contents, prove the tool cannot create siblings or unlink disposable
  fixtures in protected roots, and require zero accepted denied connections;
  an inner `true` is never sufficient when a fixture is missing, replaced,
  modified, or unhealthy. The report and final line bind the nonce, process,
  descriptor secret, endpoints, and fixture paths; the success validator also
  requires matching host evidence with before/after liveness, regular-file
  identity, and zero accepts. It also runs host
  timeout/crash/reboot canaries and owns the root-only boot receipt helper and
  renewal unit. It still grants no bot launcher access and does not enable
  production configuration.
- PR 4c2b extends the existing deploy-config recovery transaction to install
  only the launch-group/pending-path bot permission, switch every effective
  Codex config away from current-user execution, mint or renew the receipt,
  restart and health-check the service, and roll all three states back
  together. Bot launcher permission must never land in an earlier slice.
  This slice is implemented; host activation remains a separate deployment
  operation because the first reboot-cleanup challenge intentionally fails
  until a real reboot occurs.

## Current Open Decisions
- Which deployment reload primitive can preserve old-service availability: in-process reload, supervised blue/green handoff, or another rollback-capable mechanism.
- Which process-scoped credential/model and network mechanism PR 4b will use so
  the Codex main process retains required model access while same-UID tool
  descendants cannot reuse that channel.

## Resolved Decisions
- Fixed Webex config commands use a dedicated top-level `[config_commands]`
  section, separate from ordinary room policies and with an explicit admin
  Space and sender allowlist.
- PR 4 is split into 4a launcher protocol/caller-authorisation/socket
  foundation, 4b isolated transient execution, 4c1a activation-receipt
  foundation, 4c1b fresh-inode sealer, 4c1c gated runner wiring, and 4c2
  permission-capable production-image smoke tests plus final activation.
- `DynamicUser` alone cannot separate Codex main-process credentials or network
  access from same-UID tool descendants, and UID/group-only launcher
  authorisation cannot distinguish the trusted bot process from inherited
  prompt-controlled descendants.
- PR 4b uses two enforced layers: a root-owned systemd `RootImage`/
  `DynamicUser` boundary for the entire run, plus Codex `0.142.3`'s named Linux
  permission profile for same-UID tool filesystem and network separation.
  Activation remains conditional on PR 4c2 proving the profile with live
  credential, `/proc`, descriptor, socket, and egress canaries on the target
  host.

## Evidence
- Main bot PR #6 merged as `b44e509`.
- Config repo PR #11 merged as `d464a8a` and restored `Render` / `Bot Check Config` checks.
- Local staging deployment after PR #11 used bot `b44e509` and config `d464a8a`.
