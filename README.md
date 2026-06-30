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
- Dispatches each current-user Codex invocation through a replaceable runner
  backend without changing the existing execution behaviour.
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
  command allowlists. The current slice implements read-only `/config status`
  and the dormant durable pull-worker foundation.

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
uses the normal idempotent Webex reply marker. The dormant `/config pull` path
can durably submit a fixed action to a separate worker over a host-owned Unix
socket before acknowledgement, but configuration validation rejects it until
Codex runs use the isolated runner. The worker runs immutable staged preparation
only; it cannot reload the bot. `reload` and `sync` also remain undeployable.
When a trusted, valid deployment recovery journal exists, status reports only
its allowlisted phase, config revision, and service. Production root apply
writes that credential-free journal as root-owned (UID 0) with mode `0644` so
the non-root bot can read it. Its GID is not trusted or required because mode
`0644` grants no group write. Deployment recovery trusts the same-owner UID for
both current mode `0644` and legacy mode `0600` journals. `/config status`
still parses only the root-owned (UID 0), mode `0644` journal at the fixed path;
private legacy files and files with an untrusted UID or mode map to generic
`recovery_required` without exposing their contents. Malformed journals also
fail closed. This deployment journal is separate
from the worker's private queue and staging state. A strict, bounded mode
`0644` public worker status file projects only the latest pull action state and
prepared revision, without exposing private queue records or failure output.
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
requires `server.attempt_lease_secs` to cover the Codex timeout, ephemeral
launcher/staging overhead when selected, Jenkins prefetch timeout budget, and
Webex request margin. Codex then summarises the
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
`/etc/ssh/ssh_known_hosts`. Each mode recreates its own config checkout under a
fresh `work` directory, and the trusted policy helper reads it only through
`--source-root`. Final config validation invokes the fixed host-installed
bot binary directly; deployment never runs Cargo, downloads crates, or executes
dependency build scripts. The default paths match the staging deployment layout:

- apply checkout: `/var/lib/webex-generic-account-bot/config-checkout`
- prepare checkout:
  `/var/lib/webex-generic-account-bot/config-prepare-checkout`
- config staging: `/var/lib/webex-generic-account-bot/config-staging`
- bot code: `/opt/webex-generic-account-bot/code`
- bot binary: `/opt/webex-generic-account-bot/bin/webex-generic-account-bot`
- Codex workspace: `/var/lib/webex-generic-account-bot/codex-workspace`
- rendered config: `/var/lib/webex-generic-account-bot/rendered/production.toml`
- staged config:
  `/var/lib/webex-generic-account-bot/config-staging/production.toml.staged`
- staged metadata:
  `/var/lib/webex-generic-account-bot/config-staging/production.toml.staged.json`
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
scrubbed fixed-argv execution as apply. Apply does not inspect, create, clean,
or validate ownership of the prepare checkout or config staging directory.
An optional `--request-id` accepts only a 64-character lowercase hexadecimal
worker action ID and records it in staged metadata. This lets the worker recover
a prepare that committed before its private action state was updated, without
fetching a newer revision for the same Webex request.

The reviewed pull worker assets are:

- `scripts/config-pull-worker.mjs`
- `deploy/systemd/webex-config-pull-worker.service`
- `deploy/systemd/webex-config-pull-worker.sysusers.conf`
- `deploy/systemd/webex-config-pull-worker.tmpfiles.conf`

The service runs as the stable `webex-config-deploy` user with the dedicated
`webex-config-pull` primary group; it is not lifecycle-coupled to the bot unit.
The mode `0660` socket is at `/run/webex-config-pull/config-pull.sock`; the
common state parent `/var/lib/webex-generic-account-bot` is root-owned with mode
`0755`. The worker state root
`/var/lib/webex-generic-account-bot/config-actions` is owned by
`webex-config-deploy:webex-config-pull` with mode `0755`, while its worker-owned
`queue` and `state` subdirectories remain mode `0700`. The only public worker
artifact is the mode `0644`
`/var/lib/webex-generic-account-bot/config-actions/public-status.json`, whose
schema excludes message text, stderr, paths, and failure details.
Before creating its state directories, the worker verifies every state-root
ancestor through `/` is a real root-owned directory that non-root identities
cannot write. The root-owned sticky `/tmp` directory is accepted only for the
isolated test layout, relying on sticky-directory replacement protection.
Before connecting, the bot resolves the fixed system account and group names and
requires both the socket and its mode `0750` parent to be owned by
`webex-config-deploy:webex-config-pull`. The worker is never added to the bot's
own group, so it cannot read bot tokens, Codex state, or Jenkins credentials.
The bot is deliberately not added to `webex-config-pull` in this slice: a Codex
child currently inherits the bot's supplementary groups, so granting socket
access before isolated runner execution would let ordinary-room code bypass the
configuration Space allowlist. The service keeps `UMask=0077`; worker code
explicitly applies and verifies mode `0660` on the socket and mode `0644` on the
public status file after creation.

The socket parent and lock parent are deliberately separate. The shared socket
parent is mode `0750` at `/run/webex-config-pull`. The root-owned
`/run/webex-config-deploy` parent contains two distinct mode `0660`,
`root:webex-config-pull` files: `config-pull-worker.lock` is the worker lifetime
singleton, while `deploy-config.lock` serialises non-root prepare with a future
root activation. The unit grants write access to those exact files without
giving the worker write access to their parent. The lifetime lock does not
replace the deployment transaction lock.
Lock contention is reported by the fixed deployment entrypoint as a structured
retryable status. The worker durably moves that oldest action back to `queued`,
waits one second, and retries without allowing newer actions to pass it. A
deployment child tree that cannot be fully reaped is instead an integrity
failure: the worker persists a terminal taint for that action, exits non-zero,
and relies on the unit's explicit `KillMode=control-group` to remove every
process in the worker cgroup before systemd restarts it. The tainted staged pair
is never reconciled as success; after operator review, a new Webex message is
required to request another preparation.
The unit requires Linux cgroup v2. Each fixed deployment command records the
unit cgroup's PID and process-start-time identities before spawn and verifies
the same membership after the direct child closes. A new live identity, or an
inability to prove membership, is the same integrity failure. The worker never
receives cgroup write or delegation access.
The prepare checkout and prepared candidate, staged config, and staged metadata
files are confined to worker-owned mode `0700` directories. The worker unit
mounts the live `rendered` directory read-only and does not provision or own it,
so preparation cannot overwrite the live config or deployment metadata. The
read-only path is optional at unit startup so a fresh host can prepare before
the first live install; `ProtectSystem=strict` still keeps an absent or
later-created live path outside the worker's writable allowlist. Prepare also
rejects a live directory or checked existing parent owned by its own UID even
when mode `0555`, because that owner could restore write permission.

Before enabling the unit, provision the sysusers and tmpfiles definitions and
make the fixed deploy key readable only by `webex-config-deploy`. Tmpfiles
enforces the common state parent as `root:root` mode `0755`, creates the
worker-owned `config-actions` root and its private `queue` and `state` leaves,
and creates worker-owned `config-prepare-checkout` and `config-staging`; it does
not create or change the existing root/apply
`/var/lib/webex-generic-account-bot/config-checkout`. On hosts deployed from an
older worker definition, stop the worker before migration, remove the old
nested `StateDirectory=` management by installing the current unit, then apply
the current tmpfiles definition. Verify the common parent is `root:root` mode
`0755`, the `config-actions` root is
`webex-config-deploy:webex-config-pull` mode `0755`, and its `queue` and `state`
leaves are mode `0700` before restarting the worker. Do not recursively change
the common parent's children: restore `config-checkout` to the root/apply
identity if the old definition assigned it to `webex-config-deploy`. Do not
grant the worker write access to that apply checkout. Keep the live `rendered`
directory and
`/opt/webex-generic-account-bot` outside the worker's write boundary. The worker
has no bot token, Codex home, Jenkins credential,
`systemctl`, or live-config activation permission. It invokes only
`/usr/bin/node /opt/webex-generic-account-bot/code/scripts/deploy-config.mjs
--prepare --json --request-id <action-id>` with a scrubbed environment and no
shell. A response is sent only after the immutable request, private queued
state, and public status are durable. A lost response converges through the
same message-derived action ID; running actions recover after restart, and
terminal actions are not executed again.
Worker startup and shutdown are single-use and serialised. Before any durable
queue or action-state recovery, the worker acquires a non-blocking kernel flock
on `config-pull-worker.lock` and retains it for the entire worker lifetime,
including shutdown cleanup. A second process under the same UID therefore
fails on the singleton lock before it can change durable state, rather than
changing state and only then discovering the first worker's active socket. A
stop signal aborts the bounded stale-socket probe, waits for partial startup to
unwind, and removes any socket already created before the process exits.

The bot-side client and fixed command routing are present for integration tests,
but configuration validation still rejects `pull`, `reload`, and `sync` and no
config-pull worker socket-group drop-in is shipped. PR 4c1c separately adds
only the receipt-gated Codex launcher client path; PR 4c2 owns the bot launcher
group drop-in when it removes the current-user path. A later enablement PR may allow `pull`
only after `ephemeral-linux-user` runner isolation is deployable and verified;
`reload` and `sync` require the later activation work as well.

Use `--skip-restart` when validating an install without restarting the service.
That mode writes `status=installed_without_restart` instead of `status=deployed`.
It still replaces the live rendered config and therefore is not equivalent to
`--prepare`.
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
entrypoint writes and fsyncs a credential-free recovery journal beside it.
Production root apply publishes the journal as root-owned (UID 0) with mode
`0644`, allowing the non-root bot to strictly parse and expose only its
allowlisted phase, config revision, and service. Its GID is not trusted or
required because mode `0644` grants no group write. Deployment recovery trusts
the same-owner UID for both current mode `0644` and legacy mode `0600` journals,
while `/config status` parses only the root-owned (UID 0), mode `0644` journal
at the fixed path and reports private legacy files only as generic
`recovery_required`. The journal
advances through
`prepared`, `service_transition_started`, and `committed_pending_metadata`, and
remains until success metadata is durable. After an unclean exit, the next apply
either restores the preserved backup without consuming it or finalises metadata
for an already committed service. Required rollback restarts and verifies an old
service; a failed first deployment is restored by stopping the service after its
config is removed. Journal removal is fsynced before deleting the backup or
starting a new checkout. A malformed or untrusted journal fails closed to a
generic `recovery_required` status and preserves the live config, backup, and
journal for inspection; `--skip-restart` cannot bypass a pending service
recovery. If metadata writing or cleanup fails after the new
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
Each mode's existing checkout must be owned by that mode's deployment identity
and group with mode `0700`. A custom private lock uses a current-deployment-user
owned parent with mode `0700` and a mode `0600` lock file. The default shared
lock is different: `/run/webex-config-deploy` is preprovisioned as
`root:webex-config-pull` mode `0750`, and `deploy-config.lock` is root-owned with
group `webex-config-pull` and mode `0660` so root apply and non-root prepare use
the same kernel flock.
Missing rendered-config and metadata directories are created one component at
a time, and each new directory entry is made durable by fsyncing its parent.
Path, repo, binary, timeout, and output-cap overrides are rejected
unless the host environment sets `WEBEX_BOT_DEPLOY_ALLOW_HOST_OVERRIDES=1`. The
entrypoint creates a custom private lock parent when host permissions allow it;
the default shared lock parent and file must already be provisioned. It writes
deployment metadata to
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

The current-user Codex runner uses:

- `codex --ask-for-approval never exec`
- `--sandbox read-only`
- `--ephemeral`
- `--ignore-user-config` and `--ignore-rules`
- a scrubbed subprocess environment that does not forward Webex token variables
  or an inherited `CODEX_HOME`

Each invocation dispatches through a replaceable runner backend. The
current-user backend preserves the existing command, environment, output,
timeout, and process-cleanup behaviour; the boundary only makes it possible for
a later backend to replace execution for that invocation.

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

Temporary Linux user isolation is the intended boundary for untrusted
chat-driven prompts. `codex.isolation.mode = "current-user"` remains only a
trusted-prompt-author mode and requires
`codex.isolation.trusted_prompt_authors = true`; it is not a secret-read
boundary against allowed prompt authors. Static configuration validation
validates the fixed `ephemeral-linux-user` contract but PR 4c1c then rejects
activation before `--check-config` can reach host receipt or socket checks. PR
4c2 must remove that final gate only while adding bot access; after that,
`--check-config` requires a current boot-scoped activation receipt and verifies
the fixed launcher socket installation. The live service then also performs an
authorised launcher preflight before reading Webex credentials or opening its
listener. No failure falls back to current-user execution.

PR 4 is split into three fail-closed slices: PR 4a establishes the root-owned
launcher protocol, caller authorisation, and systemd socket foundation; PR 4b
adds the immutable root image, transient `DynamicUser` execution,
credential/model-channel separation, containment, and crash cleanup; PR 4c
activates the runner and adds permission-capable production-image smoke tests.
`DynamicUser` alone is insufficient because the Codex main process and its
tool descendants otherwise share a UID and can share the same credentials and
network access. UID/group-only launcher authorisation is also insufficient
because prompt-controlled descendants inherit those identities.

### PR 4a Launcher Foundation (Not Deployable)

The fixed launcher paths are:

- socket: `/run/webex-codex-launcher/launcher.sock`
- executable: `/opt/webex-generic-account-bot/bin/webex-codex-launcher`

The socket unit owns the runtime directory and credentialled
`SOCK_SEQPACKET` socket and uses `Accept=yes` to start one root-owned
`webex-codex-launcher@.service` instance per connection. The launcher protocol
is versioned, length-prefixed JSON with one bounded request or response per
packet. Caller authorisation uses `SO_PEERCRED` and an atomic `SO_PEERPIDFD`;
the request packet's `SCM_CREDENTIALS` must identify that same peer. The peer
must also be the exact live `MainPID` of
`webex-generic-account-bot.service`, running the fixed root-owned bot
executable in the exact service cgroup; a pidfd and repeated process snapshot
close PID-reuse and caller-exit races. The launcher units explicitly require
Linux cgroup v2, detected through `/sys/fs/cgroup/cgroup.controllers`, and a
kernel that supports `SO_PEERPIDFD`; an unsupported kernel fails closed before
reading a request packet.
The root launcher service starts with only `CAP_SYS_PTRACE` for different-UID
bot inspection and `CAP_SETPCAP` for the subsequent irreversible drop; it has
no ambient capabilities. Immediately after caller authorisation and before
reading the untrusted request packet, the launcher removes both capabilities
from its bounding, effective, permitted, and inheritable sets. Neither
capability is exposed to Codex runs, whose capability sets remain part of PR
4b's deny-by-default transient-unit boundary.

PR 4a is only a foundation and must remain fail closed. It does not add the bot
to `webex-codex-launch`, execute `systemd-run`, enable
`codex.isolation.mode = "ephemeral-linux-user"`, or enable `/config pull`,
`/config reload`, or `/config sync`. Operators must not treat the PR 4a units
as a deployable isolation backend. The launcher executable must remain at the
fixed path, root-owned, and not writable by the bot or launcher socket group;
the socket path must be created by the reviewed systemd/tmpfiles assets rather
than by the bot.

### PR 4b Isolated Execution (Not Activated)

PR 4b adds the root-owned execution boundary without making it selectable by
bot configuration. Each accepted launcher request uses a content-addressed,
read-only SquashFS image and a transient `DynamicUser` service. The transient
unit has fixed resource limits, no host capabilities, a private temporary
filesystem, a read-only input bind, and no bot, config-worker, systemd, or host
filesystem paths inside its root image.

The reviewed runtime is pinned to Codex `0.142.3`, package layout version `1`,
and target `x86_64-unknown-linux-musl`. The image builder rejects extra source
entries, unexpected package metadata, writable published images, and any
runtime executable with an ELF interpreter. Build the runtime wrapper as a
static PIE before installing it at the fixed source path:

```bash
cargo rustc --release --bin webex-codex-runtime -- -C target-feature=+crt-static
cargo rustc --release --bin webex-codex-canary-probe -- -C target-feature=+crt-static
file target/release/webex-codex-runtime
file target/release/webex-codex-canary-probe
ldd target/release/webex-codex-runtime
ldd target/release/webex-codex-canary-probe
```

The fixed root-owned source layout is:

```text
/opt/webex-generic-account-bot/bin/webex-codex-runtime
/opt/webex-generic-account-bot/bin/webex-codex-canary-probe
/opt/webex-generic-account-bot/runtime-sources/busybox
/opt/webex-generic-account-bot/runtime-sources/codex/bin/codex
/opt/webex-generic-account-bot/runtime-sources/codex/codex-path/rg
/opt/webex-generic-account-bot/runtime-sources/codex/codex-resources/bwrap
/opt/webex-generic-account-bot/runtime-sources/codex/codex-package.json
```

Copy the files from the matching Codex vendor package without following
symlinks. Every source and parent directory must be root-owned and not writable
by group or other. The runtime wrapper, BusyBox, Codex, `rg`, and `bwrap` must
be static x86-64 ELF executables. With `/usr/bin/mksquashfs` installed, generate
and consume the fixed source manifest as root:

```bash
node scripts/build-codex-runtime-image.mjs --write-source-manifest
node scripts/build-codex-runtime-image.mjs
```

The builder atomically selects
`/opt/webex-generic-account-bot/runtime/active.json` only after fsyncing and
publishing `images/<sha256>.squashfs`. Codex auth remains outside the image at
`/etc/webex-generic-account-bot/codex-auth.json`, owned by root with mode `0600`
or stricter. systemd copies it into the transient unit with `LoadCredential`;
the wrapper then creates a private main-process `CODEX_HOME`. Codex tool
commands use the OS-enforced `webex-isolated` permission profile, which denies
that home and credential directory, supplies separate temporary home paths,
disables tool network access, and always uses `--skip-git-repo-check` because a
sealed evidence workspace cannot contain a `.git` control directory. The
launcher validates the complete request policy before consuming the sealed
workspace pathname and rejects requests that do not opt into that fixed
repository-check bypass. The wrapper keeps Codex progress off stdout, asks
`codex exec` to write its final response into the tool-denied main home, then
validates and emits only that bounded UTF-8 file.

Input workspaces live below `/var/lib/webex-codex-runtime-inputs/ready`. The host provisions
that root as sticky `root:webex-codex-input` mode `1730`; each run must be
sealed by a root-owned broker before launch. Ready run directories are
`root:webex-codex-input` mode `0500` and files are mode `0400`, so a launcher
hard stop cannot leave group-readable evidence there. After the verified inode
is moved below the root-only consumed quarantine, the launcher recursively
grants directory mode `0550` and file mode `0440` before creating the transient
unit. Regular files retain the same owner/group and a single hard link.
Symlinks, special files, more than
8192 entries, nesting beyond 32 levels, and aggregate regular-file bytes above
2 GiB plus 64 MiB are rejected. The host group database entry must have no
static members, no numeric-GID alias, and no static user with that primary GID.
The root launcher retains the supplementary input group after systemd starts
it. PR 4c1b also adds `webex-codex-launch` solely so the capability-dropped
launcher can read the pending source tree. In the PR 4c1b-only state, the bot
still belongs to neither group; PR 4c2 later grants it only the launch group
while activating ephemeral execution.
The launcher has no config-worker group membership. Its template
instances are pinned directly to `system.slice`, matching the launcher's strict
cgroup identity check. It opens the run
directory with `O_PATH|O_NOFOLLOW` and binds the held
inode through `/proc/<launcher-pid>/fd/<fd>`, preventing a path replacement
between validation and transient-unit creation. Before starting the transient
unit it atomically moves the pathname into the root-only
`/var/lib/webex-codex-runtime-inputs/consumed` quarantine. Both directories
share one non-writable parent and one systemd writable mount so the no-replace
rename cannot cross mount points. The open inode remains the
unit input, the bot cannot reuse the run path, and `systemd-tmpfiles` removes
abandoned quarantined inputs after one day. PR 4b creates the input group but
does not add the bot to it or provide the privileged sealing broker.

The minimum host contract is systemd 255, Linux 5.9 or newer, cgroup v2,
SquashFS/loop support, mount and PID namespaces, `close_range(2)`, and a host
policy that permits the bundled `bwrap` to create its inner sandbox. These are
not inferred from version strings alone. PR 4c2 must run the real image and
permission canaries on the deployment host and mint the boot-scoped activation
receipt before the wired runner can be selected by a deployable configuration.
Those executable canaries must prove that the Codex main process can write the
bounded final message, tool subprocesses cannot read the auth credential, main
home, or final output, and launcher stdout contains only the final message.
In PR 4c1c, config validation rejects activation before receipt or socket
preflight. After PR 4c2 atomically removes that gate, a missing receipt makes
`--check-config`, launcher preflight, and execute requests fail closed. If any
canary fails, `ephemeral-linux-user` remains
undeployable with no current-user fallback. In particular, ordinary `exec`
resets process dumpability: the transient unit denies the `@debug` syscall group, process-VM
access calls, and core dumps, while PR 4c2 must still prove that the inner tool
PID/filesystem sandbox cannot inspect the Codex main process after `exec`.

PR 4c1c does not grant the bot a launcher group or pending-staging write path,
because current-user Codex children would inherit either permission. PR 4c2
must grant only the launcher group and pending path in the same activation that
removes current-user execution; the bot never receives the sealed-input group
or worker-socket access. `/config pull`, `/config reload`, and `/config sync`
remain disabled until their separate command-enablement changes land.

### PR 4c1a Activation Receipt Foundation (Not Activated)

PR 4c1a adds only the fail-closed boot-scoped activation receipt format and
verifier. The root-owned receipt path is
`/run/webex-codex-activation/receipt.json`; tmpfiles creates only its root-owned
parent directory and deliberately does not pre-create a receipt. A valid
receipt binds the current boot ID, active runtime manifest, runtime image
digest, fixed bot/launcher/runtime executable digests, Codex version, model,
and the exact required production-canary result set. The active image's source
manifest digest and `/usr/libexec/webex-codex-runtime` entry must match the
fixed host runtime wrapper digest, size, source path, and mode. Unknown, missing, false,
stale, oversized, linked, misowned, or modified-runtime receipts are rejected.
The launcher unit treats the read-only activation bind mount as optional so a
missing tmpfiles directory reaches the verifier and produces the same
fail-closed activation error instead of failing during systemd namespace setup.

This foundation does not call the verifier from config or execution paths and
provides no command that can mint a receipt. Runner activation remains blocked
until the later sealer/client wiring and production-image canary PRs land.
Because the launcher keeps `ProcSubset=pid`, PR 4c1c must copy the current boot
ID with a root-owned systemd credential and pass that fixed credential path to
the launcher-specific activation verifier; it must not loosen the launcher
procfs boundary. Executable verification also rejects Linux file capabilities
so a canary-approved binary cannot gain ambient privilege without invalidating
activation.

### PR 4c1b Fresh-Inode Input Sealer (Not Wired)

PR 4c1b adds the root-only input sealer and its host staging layout. PR 4c1c
sets the pending root to non-enumerable `root:webex-codex-launch` mode `2730`.
The bot uses `O_PATH` descriptor-relative operations and `syncfs` on the held
workspace fd to persist publication/removal without gaining directory-list
permission. Each per-run tree
inside it is owned by the future bot caller with group `webex-codex-launch`,
using mode `2770` for directories and `0640` for files. The launch group write
bit permits the capability-dropped sealer to remove the source after quarantine.
The launcher receives the launch group now; the fixed bot receives it only
when PR 4c2 atomically activates ephemeral execution. The unpredictable run ID
prevents callers outside that boundary from selecting a run. The sealer first moves
that pathname into a root-only consumed-source
quarantine, recursively validates it through no-follow descriptor-relative
operations, and copies only regular files and directories into fresh
`root:webex-codex-input` inodes. It rejects links, special files, control
directories, POSIX ACLs, owner/mode changes, duplicate publication, and the PR
4b depth, entry, and byte limits before publishing a read-only tree. The public
sealer entrypoint accepts only the authorised source UID; it resolves the fixed
`webex-codex-launch` and `webex-codex-input` groups through the same trusted
host group policy used by runtime verification. Both privileged groups reject
static primary-GID users. Runtime consumption preserves the verified inode
through its `O_PATH` guard, moves it with no-replace semantics, and fsyncs the
consumed and public parent directories before launch.
Each source file is copied and SHA-256 hashed, then rewound and hashed again;
same-size writes through retained source descriptors are rejected before the
fresh target inode can be published.

The staging parent is traversable only by `webex-codex-launch`; the sticky
sealed-input root prevents non-root input-group members from replacing
root-owned entries; and tmpfiles
expires abandoned pending, consumed-source, hidden sealed-staging, and
unconsumed final entries after one day. The launcher receives only the
supplementary groups and two writable staging roots needed after its capability
drop. The namespace exposes their common parent as writable so quarantine
rename stays on one mount, while parent mode `0550` prevents the launcher from
creating or replacing sibling entries.
This slice adds no bot service drop-in, no launcher client or runtime
call site, no activation-receipt read, and no config enablement. The bot still
cannot reach the launcher socket or pending root, so the isolation backend
remains undeployable until PR 4c1c wires the gated path.

### PR 4c1c Gated Runner Wiring (Receipt-Gated)

PR 4c1c adds the fixed `SOCK_SEQPACKET` launcher client and explicit evidence
staging, but deliberately ships no bot service drop-in. Granting the launch
group while production still uses current-user execution would also grant it
to prompt-controlled Codex children. PR 4c2 must add the launcher group and
pending-path write access only while activating ephemeral execution; the bot
is never a member of `webex-codex-input`. Configuration validation rejects any
mix of current-user and ephemeral execution whenever ephemeral execution is
present, then rejects ephemeral activation entirely in this slice. PR 4c2 must
remove that final gate in the same change that installs the bot permission, so
no current-user child can inherit launcher access. The runner
copies only the evidence root supplied by the Jenkins prefetch path, rejects
links, special files, control directories, metadata/content races, and the
existing depth, entry, and byte limits, then identifies the run with an
unpredictable ID. A request is sent only after launcher preflight succeeds.
Preflight responses and bot-side evidence staging each have a 10-minute bound;
their blocking file work and launcher preparation use cooperative 9-minute
deadlines plus response margins. Each blocking worker also owns an independent
570-second process watchdog, so a syscall that cannot reach a cooperative
checkpoint terminates the systemd-managed bot or per-connection launcher
before the 10-minute lease budget expires. Deadline and client-disconnect
cancellation are checked between directory, copy, and hash operations, so
normal paths finish scoped cleanup before their futures return. These fixed
costs are included in ephemeral attempt-lease validation. Ephemeral
configuration also caps
`server.max_concurrent_requests` at the launcher's fixed four accepted
connections. Socket trigger and poll bursts include startup preflight plus two
connections per concurrent run. The launcher service runtime maximum is
protocol-bound above the largest request, preparation, cleanup, and response
budget.

Pending workspace publication and removal use `syncfs` through the held
workspace descriptor so the non-enumerable pending root need not be opened for
listing; the launcher likewise fsyncs source-quarantine removal before it can
consume a sealed run. After staging, every normal success or failure path runs
pending cleanup in the same bounded blocking-worker/process-watchdog envelope
as staging. A forcibly dropped async task never performs recursive I/O in
`Drop`; it leaves the private tree for the existing one-day tmpfiles fallback.

The launcher re-verifies the activation receipt on every preflight and execute
request. Its boot ID comes from the root-owned systemd
`activation-boot-id` credential, preserving `ProcSubset=pid`; isolated child
units do not receive that credential and cannot read the activation directory.
Bot startup and every launcher verification also open `/proc/self/exe` and
require its path, inode metadata, and SHA-256 digest to match both the fixed
root-owned executable and the receipt. An already-running process therefore
cannot accept a receipt minted after an atomic executable replacement.
The verified activation snapshot is carried into runtime selection: the exact
active-manifest bytes and selected image digest must still match the receipt,
so an overlapping runtime rollout cannot substitute an untested image. Launcher
diagnostics are emitted only to `stderr`, which systemd sends to the journal;
protocol `stdout` remains the accepted socket. Preflight and execution failures
log only bounded, control-character-sanitised internal causes while clients
continue to receive stable generic rejection messages.
Their own Codex credential remains available to the runtime wrapper and is
denied to tool subprocesses by the fixed permission profile. Static config
requires model `gpt-5.5`, no profile, `--ephemeral`, the fixed repository-check
bypass, bounded timeout/output values, and
`trusted_prompt_authors = false`. This slice then rejects activation, so its
`--check-config` path does not claim host receipt/socket coverage. PR 4c2 must
remove that gate only after deployment preflight verifies the activation
receipt and fixed root-owned socket metadata; the live bot must additionally
perform the caller-authorised launcher preflight before Webex startup.
Source quarantine trees are removed immediately after sealing, and the
inode-guarded consumed tree is removed when the transient run finishes, fails,
times out, or is cancelled. Closing the bot's launcher socket cancels
preflight, preparation, and a running transient unit even while the authorised
bot process remains alive. Cancellation receives a 105-second cleanup grace;
the per-connection launcher then exits if blocked work cannot drain. A normal
launcher response is emitted only after source and consumed parent-directory
cleanup is durable. Consumed cleanup runs off the current-thread runtime and
has its own 50-second process watchdog after at most 50 seconds of transient
unit cleanup, all inside the 110-second response budget;
one-day tmpfiles expiry remains only a crash, hard-watchdog, or host-reboot
fallback.

PR 4c1c does not mint the receipt or activate production configuration. PR
4c2 owns permission-capable production-image canaries and receipt creation.

### PR 4c2a1 Runtime Canary Contract (Not Activated)

PR 4c2a1 adds the versioned `runtime-boundary-v1` canary report contract and a
static `/bin/webex-codex-canary-probe` inside the content-addressed production
image. The report uses an exact allowlist of checks, a 32-byte lowercase hex
nonce, a fixed final-line binding, one-line JSON framing, and a 16 KiB byte
limit. Missing, unknown, false, duplicated, oversized, or malformed results are
not successful canary evidence. The activation verifier independently hashes
the root-owned host probe and requires its exact digest and size in the source
manifest before a receipt can be minted or accepted.

The probe performs direct filesystem, process, descriptor, capability,
privilege, Unix-socket, and loopback TCP checks rather than delegating those
checks to shell text. PR 4c2a2 will run it through Codex `exec --json` and trust
only the pinned command-execution event, not the model's final prose. Host
lifecycle canaries and receipt minting also remain in 4c2a2. PR 4c2b alone owns
the deployment transaction that installs bot launcher access and removes the
current-user configuration. This slice therefore keeps the activation receipt
unminted, the bot drop-in absent, and `ephemeral-linux-user` rejected.

A successful probe report is not standalone activation evidence. Before the
4c2a2 harness starts Codex, it must use the nonce as the run ID, create a
nonce-scoped protected regular file and nested read-only workspace fixture,
verify the derived systemd credential file, create nonce-scoped regular files
inside both private main-process homes, create a real final-output sibling
fixture, verify live Unix/TCP listener fixtures, and pass the exact nonce and
endpoints in the pinned command. The forbidden TCP listener must use a
controlled non-loopback unicast address; the bot listener remains loopback.
The inner probe must read the nested workspace fixture without opening it for
write or creating files beside it, and must be denied read and write access to
the exact derived credential, private-home, and final-output fixture files. It
must also be unable to create sibling entries or unlink disposable fixtures in
credential, private-home, protected, or workspace directories. After Codex
exits, the harness must prove the files retained the same regular-file identity
and contents, the listeners remained live, and denied listeners accepted zero
connections. A missing, replaced, modified, unhealthy, or accepted fixture
invalidates the run even if the inner probe reported `true`; the receipt writer
must never consume the inner report without these host-side preconditions.

The report binds the nonce, main PID, descriptor-secret digest, both TCP
endpoints, and both nonce-derived host paths into `fixture_binding`. The final
line carries that binding as well as the nonce. The library success validator
requires matching host evidence with before/after liveness and zero accept
counts for the instrumented host Unix and TCP fixtures. It also requires the
credential, protected-path, and workspace fixtures to retain the same
regular-file identity, requires private-home and workspace fixture contents to
remain unchanged, requires the real final-output sibling fixture to retain its
identity and contents, and requires the fixed launcher and config-worker
sockets to remain live before and after the probe. The process boundary
directly checks `ptrace`, `kcmp`, `process_vm_readv`, and `process_vm_writev`;
parsing a boolean-only inner report can never establish success. The privilege check
covers every prompt-executable image path: BusyBox, the canary probe, and
`rg`. The absent final-output path must also reject an actual `create_new`
attempt, so `NotFound` alone cannot prove output isolation. Socket connection
timeouts are inconclusive and fail closed rather than being treated as access
denial.

### PR 4c2a2 Runtime and Host Canaries (Not Activated)

PR 4c2a2 adds the root-only
`/opt/webex-generic-account-bot/bin/webex-codex-activation renew` helper and an
inactive `webex-codex-activation-renew.service` oneshot. The helper invalidates
any old receipt before testing, locks renewal to one process, snapshots the
candidate image and executable identities, and writes a new receipt only when
the same artifact binding remains current after every canary succeeds.

The production runtime has a separate fixed `--runtime-canary` mode. It runs
the pinned Codex `0.142.3` `exec --json` path, accepts exactly one matching
command-execution event for the static probe, validates the one-line report and
bound final message, and independently checks the systemd credential, both
private homes, the real final-output sibling, the sealed workspace fixture,
and a CLOEXEC descriptor secret before and after Codex. The host helper keeps
the protected file and live Unix/TCP listeners open, requires unchanged file
identity and contents, requires the launcher and config-worker sockets to stay
live, and rejects any accepted denied connection.

Timeout and launcher owner-crash canaries use fixed `systemd-run`/`systemctl`
argv and must converge to inactive units. The bot crash canary terminates a
controlled pidfd-backed peer while the production transient supervisor is
running and requires that supervisor to detect the peer exit and stop its
unit. Reboot cleanup uses a persistent root-owned challenge plus a `/run`
marker: the first renewal prepares the challenge and fails closed until one
real reboot has removed the marker. A service restart is not accepted as
reboot evidence.

This slice remains non-deploying. It does not add the bot to launcher or input
groups, install a bot drop-in, switch production away from `current-user`, or
enable `/config pull`, `/config reload`, or `/config sync`. Those permission
and configuration changes remain transactional work for PR 4c2b and the later
configuration-command PRs.

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
