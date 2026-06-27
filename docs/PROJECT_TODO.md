# Project TODO

- [pending] Add durable background job recovery so long Codex runs can survive bot restarts after sidecar acceptance.
- [pending] Add the durable external config-action queue/worker and staged
  deployment modes required to enable `/config pull`, `/config reload`, and
  `/config sync`; never run restart work inside the Webex request handler.
- [pending] Add an explicit privileged runner for `ephemeral-linux-user` isolation, likely via `systemd-run DynamicUser` or a root-owned launcher.
