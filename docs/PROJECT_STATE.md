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
  Cooperative work deadlines and launcher-socket disconnect cancellation
  clean inode-verified ready and consumed trees before returning. Ready trees
  remain group-inaccessible until moved below the root-only consumed root.
  Independent
  process watchdogs hard-stop stuck staging and preparation syscalls before
  their lease budgets expire. Production configuration remains on
  `current-user` until PR 4c2 mints a receipt after live capability canaries
  pass and atomically installs the minimum launcher/pending-path access.

## Recovery Pointers
- Active workstream: `docs/project_journal/2026/06/2026-06-18-generic-account-bot-mvp.md`
- Deployment automation and isolation roadmap: `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`
- Configuration Space workstream: `docs/project_journal/2026/06/2026-06-27-configuration-space-commands.md`
- Local index: optional generated `docs/project_journal/INDEX.md`; regenerate with the bundled `project_journal.py generate` helper.

## Global Blockers
- PR 4c2 must still deliver live production canaries and activation. It must
  prove the inner
  Codex/bwrap credential, post-exec process
  memory and `/proc`, inherited descriptor, and network boundaries against the
  production image and host kernel policy before activating the runner. Static
  PR 4b preflight and the unused 4c1b sealer are not substitutes for those
  canaries.
- Production config does not enable `ephemeral-linux-user`, `/config pull`,
  `/config reload`, or `/config sync` before PR 4c2 activation.

## Notes
- Ordinary implementation state belongs in the active workstream journal.
