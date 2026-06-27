---
id: 20260627-deployment-entrypoint
title: Trusted deployment host entrypoint
status: active
created: 2026-06-27
updated: 2026-06-27
branch: codex/deploy-entrypoint-pr1b
pr: https://github.com/Joey-Project/Webex-generic-account-bot/pull/8
supersedes: []
superseded_by:
---

# Trusted Deployment Host Entrypoint

## Summary
- Add a host-owned deployment entrypoint in the bot repo so config-space commands
  can later delegate to fixed deployment behaviour instead of running shell
  snippets or config-repo code directly.

## Scope
- `scripts/deploy-config.mjs` builds fixed argv calls for config fetch, trusted
  bot-repo validation, candidate install, and service restart.
- The config checkout is recreated under a fresh `work` directory for each
  apply and is passed to the trusted policy helper only as `--source-root`.
- GitHub fetch uses fixed host SSH policy rather than ambient agent, home, or
  proxy state.
- Git commands run through fixed `/usr/bin/prlimit` resource limits. Path shape
  and file count are checked before sparse checkout; file type, per-blob size,
  and total declared config bytes are checked before trusted rendering.
- The initial fetch uses `blob:none`, path validation runs before checkout, and
  sparse checkout materialises only `production/` under Git resource limits.
  The post-checkout manifest uses `GIT_NO_LAZY_FETCH=1` so missing blobs fail
  closed before trusted rendering, including on Git 2.43 hosts.
- Rendered-config and metadata parent directories are checked for symlink-free
  canonical paths, trusted ownership, and non-writable group/world modes before
  candidate cleanup or failure-status writes.
- Mutable checkout, lock, output, metadata, bot-code, and credential paths must
  be topologically disjoint when host overrides are enabled. Existing ancestors
  are canonicalised and symlink ancestors are rejected before lock creation or
  recursive cleanup.
- Host policy overrides for executable paths, repo paths, timeouts, and output
  caps require `WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES=1`.
- The entrypoint defaults to dry-run/status and requires `--apply` for mutation.
- Status mode is mutually exclusive with apply, dry-run, and restart options.
- Child processes run with a scrubbed environment that removes ambient Git,
  SSH-agent, proxy, home, and token-shaped variables.
- Child processes run from a fixed host cwd (`/`) while all trusted inputs are
  passed as absolute argv values, so a config checkout cannot affect local tool
  config discovery through the deploy script's inherited cwd.
- The entrypoint writes bounded deployment metadata after a successful apply,
  distinguishes skipped restarts, records generic apply and restart failure
  states, uses `failed_after_commit` for metadata failures after a successful
  restart, and rolls back the rendered config if restart fails.
- Restart success requires both `systemctl is-active` and a retrying loopback
  `/healthz` probe. HTTP `200` and authenticated-endpoint `401` are ready;
  failed readiness rolls back through the same path.
- Deployment metadata uses a same-directory fsynced temporary file plus atomic
  rename. Cleanup failures are merged into the reported error and residual lock
  state is recorded when possible without replacing an earlier specific failure
  status. Status mode validates the full metadata schema before returning it.
- Candidate contents and the rendered-config directory are fsynced before
  success metadata, preserving config-before-status durability ordering. A
  post-rename directory-fsync failure restores the previous config internally.
- Child commands have per-command deadlines, process-group termination, a hard
  post-SIGKILL pipe-close deadline, and bounded stdout/stderr capture. The lock
  records PID, process start time, and a random owner token so dead-process locks
  can be reclaimed without stealing a live deployment. Lock, checkout, and
  output directories must be deployment-user-owned and non-writable by others.
- The trusted Jenkins helper is vendored into the bot repo with service-bounded
  graph fetch limits, redacted diagnostics snippets, explicit partial collection
  markers, and downstream traversal limited to structured Jenkins API metadata.
- The helper process retains the configured overall timeout while each HTTP
  attempt uses a derived timeout capped at 60 seconds, leaving room for three
  retries and output cleanup before the parent deadline.
- Jenkins API child and upstream build numbers must be decimal before they can
  affect graph traversal; malformed metadata is ignored without discarding
  already collected root evidence. Markdown-only Jenkins rooms do not require
  a structured evidence index, while deterministic JSON reply formats do.
- Jenkins JSON API responses have a separate 1 MiB streaming cap and omit
  unused build parameter values.
- Jenkins inputs must identify `/job/.../<build-number>/`; authenticated fetches
  use manual redirect handling so credentials are never forwarded to a redirect
  target.
- Oversized per-node log attempts debit their reserved bytes from the aggregate
  log budget, preventing repeated failed reads from bypassing the total cap.
- Every streamed console byte, including bytes from failed retry attempts, is
  charged to the aggregate budget. Derived diagnostics cap both line length and
  retained line count, and redact PEM private keys and common API-key fields.
- Console lines retained in graph and summary artifacts are capped at 4 KiB
  after redaction, preventing one log line from amplifying derived artifacts.
- Jenkins helper stdout exposes every prefetched GUI console URL for reply
  rendering allowlists while keeping the recommended reading preview short;
  control characters are collapsed and Rust consumes only the explicit URL
  block.
- Reply rendering receives the full structured URL allowlist before prompt
  truncation, so long 32-node graphs cannot silently lose valid log links.
- Host policy rejects every room outside the pinned production, staging, and
  `miku bot test` room set.
- Jenkins diagnosis and follow-up prompts must match full host-owned normalized
  template hashes; fragment-preserving instruction injection is rejected.
- Host policy pins `/usr/bin/node`, the helper `PATH`, the global Codex model,
  and Jenkins timeout/fan-out/output values. Jenkins-format replies fail closed
  unless at least one non-empty local log was written; only those nodes enter
  the URL allowlist. Excerpts require the model's own log URL to match that
  allowlist and the sanitized excerpt text to occur verbatim in the mapped local
  log; they are dropped when the renderer uses a single-log fallback link.
- Failure metadata write errors are surfaced together with the primary apply
  error, so operators know an existing status file is stale.
- Jenkins API graph discovery is kept separate from console log fetches so a
  missing or oversized root log does not prevent traversal to downstream jobs.

## Follow-Ups
- Wire fixed Webex admin commands to this entrypoint in the next PR.
- Add stronger protected-check verification before accepting a config revision
  when deployment host credentials and GitHub status access are finalised.
- Update config repo Jenkins helper paths to the trusted bot repo helper path
  plus the pinned Codex workspace and `skip_git_repo_check` values before
  deploying with this entrypoint.
- Replace `systemctl restart` with a stronger handoff primitive if the service
  needs more availability guarantees than restore-on-restart-failure.
