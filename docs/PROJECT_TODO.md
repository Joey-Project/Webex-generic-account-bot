# Project TODO

- [pending] Add durable background job recovery so long Codex runs can survive bot restarts after sidecar acceptance.
- [pending] Wire Webex admin configuration commands to the trusted `scripts/deploy-config.mjs` entrypoint without running deployment work inside the request handler.
- [pending] Add an explicit privileged runner for `ephemeral-linux-user` isolation, likely via `systemd-run DynamicUser` or a root-owned launcher.
