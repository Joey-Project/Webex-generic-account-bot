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
  before retrying.
- Bounds concurrent request processing with `server.max_concurrent_requests`.
- Scrubs Webex token variables from the Codex subprocess environment.

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

Generated Rust CI runs:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Local tests:

```bash
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
