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
- Bounds concurrent request processing with `server.max_concurrent_requests`.
- Scrubs Webex token variables from the Codex subprocess environment.

The first implementation is synchronous per sidecar request: the HTTP request
returns after Codex finishes and the Webex reply is accepted. For this slice,
set the JS sidecar forwarding timeout higher than the configured Codex timeout.
Durable background job recovery is the next reliability layer.

## Configuration

Start from [`config/example.toml`](config/example.toml). Keep secrets in
environment variables or token files.

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

- `codex exec`
- `--sandbox read-only`
- `--ask-for-approval never`
- `--ephemeral`
- a scrubbed subprocess environment that does not forward Webex token variables

Temporary Linux user isolation is the right long-term boundary for untrusted
chat-driven prompts, but it should live behind the runner abstraction. Creating
and deleting OS users requires root or a privileged helper, so this MVP rejects
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
