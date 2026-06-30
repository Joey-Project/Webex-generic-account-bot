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
- [completed] Implement PR 4b's immutable root image, transient `DynamicUser`
  execution, credential/model-channel separation, containment, and crash
  cleanup.
- [completed] Add PR 4c1a's boot-scoped activation receipt foundation without
  wiring it into config or execution paths.
- [completed] Implement PR 4c1b's root fresh-inode input sealer and inactive
  launcher-side staging contract.
- [completed] Implement PR 4c1c's gated runner wiring.
- [completed] Implement PR 4c2a1's exact canary contract, static syscall probe,
  and immutable image allowlist entry.
- [completed] Implement PR 4c2a2's deterministic production-image and host
  lifecycle canaries plus root-only receipt renewal without granting bot
  launcher access or enabling production configuration.
- [pending] Implement PR 4c2b's transactional permission/config activation;
  then separately grant config-worker socket access and enable `/config pull`.
- [pending] Add recoverable activation and in-flight drain/handoff semantics
  before enabling `/config reload` and `/config sync`; never run deployment or
  service work inside the Webex request handler.
