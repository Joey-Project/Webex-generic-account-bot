# Project TODO

- [pending] Add durable background job recovery so long Codex runs can survive bot restarts after sidecar acceptance.
- [completed] Add immutable staged config preparation that does not replace
  live config or touch the bot service.
- [completed] Add the separate-identity Unix-socket config-action worker and
  durable queue foundation.
- [pending] Add the runner abstraction and ephemeral Linux-user launcher, then
  grant the bot socket access and enable `/config pull` in a separate reviewed
  bot/config change with the dedicated admin Space and sender allowlist.
- [pending] Add recoverable activation and in-flight drain/handoff semantics
  before enabling `/config reload` and `/config sync`; never run deployment or
  service work inside the Webex request handler.
- [pending] Add an explicit privileged runner for `ephemeral-linux-user` isolation, likely via `systemd-run DynamicUser` or a root-owned launcher.
