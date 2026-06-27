# Webex Generic Account Bot

Long-running Webex generic-account bot that dispatches space-specific messages
to Codex and replies in the original Webex thread.

This repo is the bot layer. It depends on
[`webex-headless-messenger`](https://crates.io/crates/webex-headless-messenger)
for Webex OAuth/REST, sidecar event envelopes, and durable message attempt state.

## Current Slice

- Receives `SidecarEvent` JSON from the Webex JS SDK sidecar over loopback HTTP.
- Authenticates local forwarding with `WEBEX_SIDECAR_TOKEN`.
- Uses `JsonlStateStore` leases to avoid concurrent duplicate Codex runs for the
  same Webex message.
- Matches behavior by Webex `roomId`.
- Supports `mention`, `prefix`, `always`, and `never` room triggers.
- Supports sender allowlists by Webex person ID and email.
- Renders a per-room prompt template and runs `codex exec`.
- Replies to the Webex message thread with the Codex result.
- Reconciles ambiguous Webex reply creation failures with a stable reply marker
  before retrying, using the same bounded marker-page budget as the initial
  reconciliation.
- Bounds concurrent request processing with `server.max_concurrent_requests`.
- Scrubs Webex token variables from the Codex subprocess environment.
- Hydrates every sidecar message ID through Webex before making room, sender,
  body, thread, Codex, or reply-routing decisions. Sidecar message fields are
  hints only.
- Supports an optional dedicated Configuration Space with explicit sender and
  command allowlists. The current slice implements read-only `/config status`.

The first implementation is synchronous per sidecar request: the HTTP request
returns after Codex finishes and the Webex reply is accepted. For this slice,
set the JS sidecar forwarding timeout higher than the configured Codex timeout.
Durable background job recovery is the next reliability layer.

## Configuration

Start from [`config/example.toml`](config/example.toml). Keep secrets in
environment variables or token files.

Codex model settings can be configured globally under `[codex]` or overridden
per room under `[rooms.codex]`, including `model` and
`model_reasoning_effort`.

The binary supports an optional `[config_commands]` table separate from
ordinary room policy:

```toml
[config_commands]
room_id = "ADMIN_WEBEX_ROOM_ID"
allowed_person_ids = []
allowed_person_emails = ["operator@example.com"]
allowed_commands = ["status"]
```

The admin Space cannot overlap an input or output room, has no
`allow_all_senders` mode, and accepts only exact `/config ...` commands after
authoritative Webex hydration. `/config status` reads fixed host deployment
metadata with no-follow and size checks, returns only allowlisted fields, and
uses the normal idempotent Webex reply marker. `pull`, `reload`, and `sync` are
reserved command names but remain undeployable until the durable external
action worker is implemented; configuration validation rejects them.
When a valid deployment transaction exists, status reports its allowlisted
phase and in-progress revision; malformed journals fail closed to
`recovery_required` without exposing their contents.
The current production host policy also rejects the entire table until a
companion config PR pins the exact admin Space and sender allowlist. The example
above is therefore for local validation and the upcoming reviewed deployment,
not yet for `scripts/deploy-config.mjs --apply`.

For staging production Space behaviour, a room policy can set
`output_room_id`, `forward_source_message = true`, and
`read_only_source = true`. The bot then treats `room_id` as a read-only source:
it mirrors the original message into `output_room_id` as a top-level staging
message and replies under that mirror. Runtime write guards reject any attempt
to create a Webex message in a configured read-only source room.

For Jenkins triage rooms, `[rooms.jenkins_context]` can prefetch read-only
diagnostics with a trusted helper script and append the result to the Codex
prompt. Configure `script` as an absolute path outside any Codex workspace, for
example `/opt/webex-generic-account-bot/code/scripts/jenkins-readonly.mjs`. The bot
runs the helper from the helper script's directory, kills timed-out helpers, and
requires `server.attempt_lease_secs` to cover the Codex timeout, Jenkins
prefetch timeout budget, and Webex request margin. Codex then summarises the
prefetched evidence without needing network access to Jenkins from inside its
sandbox.
Production host policy pins this lease to 3600 seconds and validates the
rendered policy with the bot's `--check-config` contract before installation.
Trusted deployment policy rejects Jenkins helper paths under the config checkout;
the helper must be installed with the bot code.

Jenkins triage rooms can set `reply_format = "jenkins-diagnosis-json"` so the
bot renders deterministic Webex Markdown from compact Codex JSON:

```json
{
  "verdict": "infra_false_alarm|likely_product_test_failure|not_enough_evidence",
  "reason": "one concise clause without Markdown",
  "log_url": "https://.../console",
  "excerpt": "optional short exact log excerpt",
  "excerpt_format": "inline_code|block_quote"
}
```

The renderer accepts fenced JSON, escapes model-controlled Markdown in
`reason`, downgrades blank reasons to `not_enough_evidence`, and only renders
`log_url` values that match prefetched Jenkins `/console` links. A single
prefetched log can be used as a fallback; multi-log diagnoses omit an invalid or
missing link rather than guessing. Optional excerpts are rendered as either
backtick inline code or a `>` quote block, capped to a short length, and escaped
as plain text.

Minimum environment:

```bash
export WEBEX_SIDECAR_TOKEN='<local-forwarding-token>'
export WEBEX_ACCESS_TOKEN_FILE=/var/lib/webex-headless-access/access-token
```

Check config without calling Webex:

```bash
cargo run -- --config config/example.toml --check-config
```

Run the bot:

```bash
cargo run -- --config config/example.toml
```

Trusted config deployment entrypoint:

```bash
node scripts/deploy-config.mjs --dry-run
node scripts/deploy-config.mjs --prepare
node scripts/deploy-config.mjs --apply
```

The deployment entrypoint lives in this bot repository, not in the config
repository checkout. It treats the config checkout as data, builds fixed argv
calls for `git`, the bot repo's trusted `scripts/config-policy/validate-config.sh`,
and `systemctl restart`, and runs children with a scrubbed environment that does
not forward `SSH_AUTH_SOCK`, proxy variables, ambient `GIT_*` settings, `HOME`,
or token-shaped secrets. GitHub fetch uses fixed host policy:
`GIT_SSH_COMMAND` points at `/usr/bin/ssh`,
`/var/lib/webex-generic-account-bot/deploy/id_ed25519`, and
`/etc/ssh/ssh_known_hosts`. The config checkout is recreated under a fresh
`work` directory for each apply, and the trusted policy helper reads it only
through `--source-root`. Final config validation invokes the fixed host-installed
bot binary directly; deployment never runs Cargo, downloads crates, or executes
dependency build scripts. The default paths match the staging deployment layout:

- config checkout: `/var/lib/webex-generic-account-bot/config-checkout`
- bot code: `/opt/webex-generic-account-bot/code`
- bot binary: `/opt/webex-generic-account-bot/bin/webex-generic-account-bot`
- Codex workspace: `/var/lib/webex-generic-account-bot/codex-workspace`
- rendered config: `/var/lib/webex-generic-account-bot/rendered/production.toml`
- staged config: `/var/lib/webex-generic-account-bot/rendered/production.toml.staged`
- staged metadata: `/var/lib/webex-generic-account-bot/rendered/production.toml.staged.json`
- service: `webex-generic-account-bot`

Use `--prepare` to fetch the fixed config ref, render and validate it, and
durably publish an immutable staged artifact without replacing the live
rendered config or invoking `systemctl`. The staged metadata binds the config
revision, SHA-256 digest, fixed repo/ref, bot code path, live target path, and
service. Its mode is `0600`; it is published only after the staged config is
durable. Before replacing an older staged artifact, prepare removes and fsyncs
the older metadata, so a crash or metadata commit failure cannot leave old
metadata pointing at new config bytes. A pending or malformed install
transaction makes prepare fail closed without attempting recovery or starting
Git/render work. Preparation uses the same host-wide deployment lock and
scrubbed fixed-argv execution as apply.

Use `--skip-restart` when validating an install without restarting the service.
That mode writes `status=installed_without_restart` instead of `status=deployed`.
It still replaces the live rendered config and therefore is not equivalent to
`--prepare` or `/config pull`.
`--status` is a separate read-only operation and cannot be combined with apply,
prepare, dry-run, or restart flags.
Normal apply renders and validates a candidate config first, installs it
atomically, restarts the service, and restores the previous rendered config if
`systemctl restart` fails, the unit is not active, or the loopback `/healthz`
endpoint does not become ready. A `200` response is ready; `401` also proves
readiness when the endpoint requires the sidecar bearer token. Failed fetch,
validation, install, restart, health, or cleanup paths
write machine-readable failure metadata. A completed service rollback makes its
failure metadata durable before removing the recovery journal, so a crash or
metadata error cannot expose stale success status. Metadata is fsynced to a
same-directory temporary file and atomically renamed, so existing links are
replaced rather than followed and a failed write preserves the last complete
status. If failure metadata cannot be written, the apply reports both the
primary error and the metadata error; an existing status file must then be
treated as stale. The candidate file and rendered-config directory are fsynced
before success metadata is committed, so `status=deployed` cannot become more
durable than the installed config. A post-rename durability failure restores
the previous config before returning. If rollback changes the live path but its
final directory fsync fails, service restart/stop compensation still runs and
the recovery journal is preserved. Before replacing the live config, the
entrypoint writes and fsyncs a
mode `0600` transaction journal beside it. The journal advances through
`prepared`, `service_transition_started`, and `committed_pending_metadata`, and
remains until success metadata is durable. After an unclean exit, the next apply
either restores the preserved backup without consuming it or finalises metadata
for an already committed service. Required rollback restarts and verifies an old
service; a failed first deployment is restored by stopping the service after its
config is removed. Journal removal is fsynced before deleting the backup or
starting a new checkout. A malformed journal fails closed and preserves the live
config, backup, and journal for inspection; `--skip-restart` cannot bypass a
pending service recovery. If metadata writing or cleanup fails after the new
config has been installed and the service restart has succeeded, the entrypoint
records a post-commit failure state when possible instead of implying the apply
was rolled back. While any journal remains, `--status` returns
`recovery_required` instead of stale deployment metadata. Cleanup details are
added without replacing an earlier, more specific failure status. Status output,
including `--status --json`, validates the status schema and rejects malformed or
incomplete metadata.
Child command stdout/stderr capture is bounded and each child has a deadline,
process-group termination, and a final pipe-close deadline so a stuck fetch,
validation, or restart cannot hold the deployment lock forever. The lock stores
the owner's PID, process start time, and random token in a persistent mode
`0600` file. `/usr/bin/flock` acquires the kernel lock on an inherited file
description that the Node process retains for the whole transaction, so process
exit releases the lock automatically and no pathname-based stale deletion is
needed. Cleanup-failure metadata is persisted before that description is
closed, and no deployment status is written after lock release. `SIGINT` and
`SIGTERM` are converted into controlled transaction
aborts; active child process groups are terminated and an installed but
uncommitted candidate follows the normal rollback and failure-metadata path.
Existing checkout and lock-parent directories must be owned by the
deployment user and mode `0700`.
Missing rendered-config and metadata directories are created one component at
a time, and each new directory entry is made durable by fsyncing its parent.
Path, repo, binary, timeout, and output-cap overrides are rejected
unless the host environment sets `WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES=1`. The
entrypoint creates the lock parent directory when host permissions allow it and
writes deployment metadata to
`/var/lib/webex-generic-account-bot/rendered/deploy-status.json` after a
successful apply. Fetch credentials must be provided by host policy without
ambient agent, proxy, or token environment leakage.

The config checkout is sparse and data-only: only `production/bot.toml` and
`production/spaces/*.toml` are accepted. Tree paths are allowlisted before
checkout. The initial fetch uses Git's server-side `blob:limit=1048576` filter
and `--no-tags`, preventing auto-followed tag refs from expanding the bounded
checkout.
A manifest check with `GIT_NO_LAZY_FETCH=1` rejects missing blobs, executable or
symlink entries, more than 128 files, blobs over 1 MiB, or more than 8 MiB of
declared config data before worktree materialisation. Small blobs outside
`production/` may enter the bounded object store, but sparse checkout
materialises only the allowlisted tree; checkout also disables lazy fetch. Git
runs through fixed `/usr/bin/prlimit`
CPU, address-space, file-size, process, and file-descriptor limits, in addition
to the command deadline and output cap. Rendered-config and metadata parent
directories are also rejected before cleanup or status writes if they contain
symlinks, have unexpected ownership, or are group/world writable.
Host path overrides are also rejected when checkout, lock, rendered config,
metadata, bot code, or credential paths overlap a mutable deployment tree or
one another. Existing path ancestors are canonicalised before any lock or
recursive cleanup, and symlink or untrusted writable ancestors are rejected.
Root-owned sticky directories such as `/tmp` remain valid ancestors.

The host-owned static policy allowlists every deployable Webex room and pins its
sender, routing, trigger, Codex, follow-up, and Jenkins policy. Jenkins prompts
must match host-owned full-template SHA-256 values; retaining a few guardrail
phrases while appending conflicting instructions is rejected. The Jenkins
helper uses fixed `/usr/bin/node` and `PATH=/usr/bin:/bin`, accepts only
`/job/.../<build-number>/` URLs, rejects HTTP redirects rather than forwarding
credentials, caps JSON API responses at 1 MiB, and charges every streamed log
byte, including failed retries, against the aggregate budget. Derived evidence
also caps retained line length and count, and redacts private-key blocks and
common API-key assignments. The configured Jenkins helper timeout remains the
overall process deadline; each HTTP attempt uses a derived timeout capped at 60
seconds, leaving budget for three retries and helper output cleanup. Helper
termination and pipe readers also have hard deadlines, including when an
escaped descendant retains stdout or stderr. Only nodes with a non-empty local
log enter the renderer URL allowlist, so Jenkins replies
fail closed when prefetch produces no local evidence. Exact excerpts are
rendered only when the model's own log URL matches that allowlist; a single-log
fallback link never authenticates an excerpt. Before rendering, the bot also
requires the sanitized excerpt text to occur verbatim in the local log mapped
to that URL. Post-run evidence reopens reject symlinks and non-regular files,
use non-blocking reads, and enforce a short deadline so a replaced path cannot
stall reply rendering. The helper emits a
control-character-safe console URL
block and keeps the complete structured URL allowlist separate from the prompt
text truncation used for Codex context. Host policy pins the global Codex model
and Jenkins prefetch fan-out/resource settings.

Config fragment rendering uses fixed code-unit filename ordering rather than
host locale. Jenkins log responses with an oversized declared `Content-Length`
charge that declared size to the aggregate log budget before the body is
cancelled.

Point the `webex-headless-messenger` JS sidecar at the bot:

```bash
WEBEX_ACCESS_TOKEN_FILE=/var/lib/webex-headless-access/access-token \
WEBEX_SIDECAR_TOKEN="$WEBEX_SIDECAR_TOKEN" \
WEBEX_SIDECAR_TARGET_URL=http://127.0.0.1:8787/webex/events \
WEBEX_SIDECAR_MESSAGE_EVENTS=created \
WEBEX_SIDECAR_FORWARD_TIMEOUT_MS=700000 \
node ../Webex-headless-messenger/examples/sidecar-js/index.mjs
```

## Safety Model

The default Codex runner uses:

- `codex --ask-for-approval never exec`
- `--sandbox read-only`
- `--ephemeral`
- `--ignore-user-config` and `--ignore-rules`
- a scrubbed subprocess environment that does not forward Webex token variables
  or an inherited `CODEX_HOME`

The event and health endpoints both require the sidecar bearer token unless
`server.allow_unauthenticated = true`; unauthenticated mode is restricted to a
loopback bind address.

The runner always sets `CODEX_HOME` from `codex.codex_home`; it never falls back
to the parent process value. Keep Webex token files, `codex.codex_home`, and
config files that contain secrets outside every configured Codex `cwd`. The bot
rejects explicit token files, token files provided through
`WEBEX_ACCESS_TOKEN_FILE`, and `codex.codex_home` when they sit under a
configured Codex working directory.

Each room must configure `allowed_person_ids`, `allowed_person_emails`, or the
explicit `allow_all_senders = true` escape hatch. Use `allow_all_senders` only
for trusted Spaces; current-user isolation is not a strong secret boundary
against allowed prompt authors.

Temporary Linux user isolation is the right long-term boundary for untrusted
chat-driven prompts. `codex.isolation.mode = "current-user"` is only a
trusted-prompt-author mode and requires
`codex.isolation.trusted_prompt_authors = true`; it is not a secret-read
boundary against allowed prompt authors. Creating and deleting OS users requires
root or a privileged helper, so this MVP rejects
`codex.isolation.mode = "ephemeral-linux-user"` until that helper is explicitly
designed. Good follow-up shapes are `systemd-run --property=DynamicUser=yes`, a
small root-owned worker launcher, or a pre-provisioned pool of locked-down worker
users.

## Development

Generated CI runs:

```bash
node test/run-node-tests.mjs
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Local tests:

```bash
node test/run-node-tests.mjs
cargo test --all-features
```

## Live E2E

The live E2E harness starts the Rust bot, starts the JavaScript Webex sidecar,
sends a message with a separate Webex bot token, and waits for the generic
account to reply in the original thread.

Required local `.env` keys:

```bash
E2E_BOT_ACCESS_TOKEN='<sender-bot-token>'
E2E_BOT_EMAIL='<sender-bot-email>'
```

Default target:

- generic account: `miku.gen@cisco.com`
- room: `miku bot test`
- trigger prefix: `/codex-e2e`
- generic-account access token file:
  `../Webex-headless-messenger/.codex-tmp/webex-test/access-token`

Run:

```bash
node scripts/e2e-webex-bot.mjs
```

The script writes its generated bot config under `.codex-tmp/miku-bot-test/`,
uses `.env` only for the sender bot token/email, and stops the bot and sidecar
when the test completes. Set `E2E_KEEP_PROCESSES=1` to leave both processes
running for manual inspection. If `cargo` or `codex` is not on `PATH`, set
`E2E_CARGO_BIN` or `E2E_CODEX_BIN` to the executable path before running it.
