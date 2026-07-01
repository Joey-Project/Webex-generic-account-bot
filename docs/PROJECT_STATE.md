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
- Runner PR 3 routed each current-user Codex invocation through a replaceable
  backend with existing behaviour unchanged. At that stage,
  `ephemeral-linux-user` remained rejected by config validation and
  `--check-config`, with no fallback. PR 4c1c validates the fixed
  receipt-gated contract but still rejects activation.
- Runner PR 4a adds only the root-owned launcher
  protocol, caller-authorisation, and systemd socket foundation at
  `/run/webex-codex-launcher/launcher.sock`, backed by
  `/opt/webex-generic-account-bot/bin/webex-codex-launcher`. It remains
  fail-closed and is not a deployable isolation backend.
- Runner PR 4b adds the pinned immutable runtime image, FD-bound read-only
  root-sealed input handoff with root-only consumed-input quarantine, transient
  `DynamicUser` execution, two-layer Codex permission profile, bounded cleanup,
  and static runtime dependency checks. The bot is
  still not a member of the launcher or input groups, and a compile-time gate
  rejects launcher preflight/execute until PR 4c adds a root input sealer and
  passes production-image capability canaries.
- Runner PR 4c1a adds the boot-scoped activation receipt format and strict
  root-owned verifier as an unused, fail-closed foundation. No runtime/config
  path calls it and no receipt-minting command or bot group access is added.
- Runner PR 4c1b adds the root fresh-inode input sealer, root-only source
  quarantine, trusted named-group resolution, POSIX-ACL rejection, and
  double-read content verification, same-mount no-replace durable runtime
  consumption plus the launcher-side staging group/path contract. It adds no
  bot drop-in, client, runtime call site, or activation-receipt read, so it
  remains unused and fail closed.
- Runner PR 4c1c wires the fixed launcher client, explicit evidence staging,
  and receipt-gated runner dispatch, but grants no bot socket/pending-root
  access while production still uses current-user execution.
  Configuration validation rejects mixed current-user and ephemeral backends
  and then rejects all ephemeral activation until PR 4c2 installs the required
  permissions in the same change that removes that final gate.
  Consequently, 4c1c `--check-config` stops at the gate; receipt, socket, and
  live image canary validation become reachable only in PR 4c2.
  Cooperative work deadlines and launcher-socket disconnect cancellation
  clean inode-verified ready and consumed trees before returning. Ready trees
  remain group-inaccessible until moved below the root-only consumed root.
  Bot and launcher activation verification bind the currently executing
  `/proc/self/exe` path, inode metadata, and digest to the fixed executable and
  receipt, rejecting receipts minted after an atomic binary replacement.
  Independent
  process watchdogs hard-stop stuck staging and preparation syscalls before
  their lease budgets expire. Production configuration remains on
  `current-user` until PR 4c2 mints a receipt after live capability canaries
  pass and atomically installs the minimum launcher/pending-path access.
- Runner PR 4c2a1 adds the exact runtime-boundary canary report schema and a
  static syscall probe to the immutable image allowlist.
- Runner PR 4c2a2 adds strict pinned-Codex JSONL command-event validation,
  trusted runtime-interior evidence, nonce-scoped host file and listener
  evidence, timeout and launcher owner-crash lifecycle checks, a pidfd-backed
  bot peer-exit supervisor check, a real-reboot challenge, and root-only atomic
  receipt renewal. That slice grants no bot group access and does not remove
  the ephemeral activation gate.
- Runner PR 4c2b adds explicit `--apply --activate-runner` deployment,
  backwards-compatible version 2 recovery journals, three-state
  config/drop-in/receipt rollback, boot-gated receipt renewal, and permanent
  post-activation downgrade prevention. The explicit activation command is a
  one-time transition; committed recovery is idempotent and later reviewed
  config updates use ordinary apply. Bot restarts and ordinary active-runner
  applies ensure a valid receipt, reusing a fresh receipt without rerunning
  canaries. Ordinary apply reloads an active renewal unit without disrupting
  the bot, or starts the renewal unit when the bot and renewal unit are already
  inactive. Any out-of-band permission drop-in requires an already-ephemeral
  live config before deploy proceeds, and apply reloads the systemd manager
  before permission detection. Rollback revokes launcher permission and reloads
  the manager before any config downgrade; a reload failure preserves the
  ephemeral config and journal. Receipt-only cleanup failures retain the journal
  but do not block old-service recovery. Version 2 journals accept a predating
  launcher permission only when the saved drop-in matches the exact reviewed
  legacy policy required by the migration.
  Ordinary apply requires current-user policy before permission activation and
  ephemeral-only policy afterwards; only explicit activation may cross modes.
  The fixed bot drop-in grants the launch and config-worker socket groups plus
  pending-input access. Production config commands remain disabled until the
  reviewed admin Space is pinned, and `reload` and `sync` remain invalid.
  Production stays on `current-user` until the deployment host completes the
  real-reboot challenge and activates a matching reviewed config.
- Host deployment discovery found that the repository had privileged launcher,
  activation, and worker units but no base bot unit or reproducible host
  provisioner. The base contract now defines the unprivileged bot identity,
  fixed service, and root-managed versus bot-writable filesystem layout. The
  guarded provisioner now has a fixed non-secret allowlist, files-only static
  identity enumeration, a DynamicUser-only systemd userdb boundary,
  identity-drift checks, bounded dormant-unit preflight, device-bound kernel
  lock verification shared with config deployment, exact loaded-fragment and
  no-drop-in checks, trusted re-exec paths, fail-closed crash recovery with full
  target-directory durability, streamed stale-candidate cleanup, transactional
  root-owned policy installation, explicit sysusers/tmpfiles application, and
  post-reload verification. Real host apply remains explicit before
  Configuration Space pinning and activation.

## Recovery Pointers
- Active workstream: `docs/project_journal/2026/06/2026-06-18-generic-account-bot-mvp.md`
- Deployment automation and isolation roadmap: `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`
- Configuration Space workstream: `docs/project_journal/2026/06/2026-06-27-configuration-space-commands.md`
- Local index: optional generated `docs/project_journal/INDEX.md`; regenerate with the bundled `project_journal.py generate` helper.

## Global Blockers
- The deployment host must run PR 4c2b's explicit activation against the
  installed production image and host kernel, satisfy the real-reboot
  challenge, and activate a matching ephemeral-only config. Code and unit-test
  evidence are not substitutes for that deployment-host gate.
- Production config does not enable `ephemeral-linux-user`, `/config pull`,
  `/config reload`, or `/config sync` before PR 4c2 activation.

## Notes
- Ordinary implementation state belongs in the active workstream journal.
