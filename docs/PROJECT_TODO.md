# Project TODO

- [pending] Add durable background job recovery so long Codex runs can survive bot restarts after sidecar acceptance.
- [completed] Add immutable staged config preparation that does not replace
  live config or touch the bot service.
- [completed] Add the separate-identity Unix-socket config-action worker and
  durable queue foundation.
- [completed] Route current-user Codex execution through a replaceable
  per-invocation backend without changing existing behaviour.
- [pending] Implement PR 4's ephemeral Linux-user launcher and isolation, then
  separately grant bot socket access and enable `/config pull` under reviewed
  bot/config policy.
- [pending] Add recoverable activation and in-flight drain/handoff semantics
  before enabling `/config reload` and `/config sync`; never run deployment or
  service work inside the Webex request handler.
