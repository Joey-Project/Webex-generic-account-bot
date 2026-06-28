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
  quarantine, and launcher-side staging group/path contract. It adds no bot
  drop-in, client, runtime call site, or activation-receipt read, so it remains
  unused and fail closed.

## Recovery Pointers
- Active workstream: `docs/project_journal/2026/06/2026-06-18-generic-account-bot-mvp.md`
- Deployment automation and isolation roadmap: `docs/project_journal/2026/06/2026-06-26-deployment-automation-isolation-roadmap.md`
- Configuration Space workstream: `docs/project_journal/2026/06/2026-06-27-configuration-space-commands.md`
- Local index: optional generated `docs/project_journal/INDEX.md`; regenerate with the bundled `project_journal.py generate` helper.

## Global Blockers
- PRs 4c1c and 4c2 must still deliver gated runner wiring and live production
  canaries. PR 4c2 must prove the inner
  Codex/bwrap credential, post-exec process
  memory and `/proc`, inherited descriptor, and network boundaries against the
  production image and host kernel policy before activating the runner. Static
  PR 4b preflight and the unused 4c1b sealer are not substitutes for those
  canaries.
- PRs through 4c1b do not grant the bot launcher/staging group access, enable
  `ephemeral-linux-user`, or enable `/config pull`, `/config reload`, or
  `/config sync`.

## Notes
- Ordinary implementation state belongs in the active workstream journal.
