# Project TODO

- [pending] Add durable background job recovery so long Codex runs can survive bot restarts after sidecar acceptance.
- [completed] Add immutable staged config preparation that does not replace
  live config or touch the bot service.
- [completed] Add the separate-identity Unix-socket config-action worker and
  durable queue foundation.
- [completed] Route current-user Codex execution through a replaceable
  per-invocation backend without changing existing behaviour.
- [completed] Complete PR 4a's root-owned launcher protocol,
  caller-authorisation, and systemd socket foundation while keeping it
  fail-closed and undeployable.
- [pending] Implement PR 4b's immutable root image, transient `DynamicUser`
  execution, credential/model-channel separation, containment, and crash
  cleanup.
- [pending] Implement PR 4c runner activation and permission-capable
  production-image smoke tests, then separately grant config-worker socket
  access and enable `/config pull` under reviewed bot/config policy.
- [pending] Add recoverable activation and in-flight drain/handoff semantics
  before enabling `/config reload` and `/config sync`; never run deployment or
  service work inside the Webex request handler.
