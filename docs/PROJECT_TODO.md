# Project TODO

- [completed] Add durable background job recovery so long Codex runs can
  survive bot restarts after sidecar acceptance.
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
- [completed] Implement PR 4c2b's transactional permission/config activation.
- [completed] Include config-worker socket access in transactional runner
  activation and permit the `pull` schema only under fully ephemeral isolation.
- [completed] Add the base bot systemd identity, service, and filesystem layout.
- [completed] Add a guarded host provisioner before production activation;
  real host apply remains an explicit operational step.
- [completed] Add a content-manifested, fixed-path, first-install host release
  bootstrap with a commit-exported Rust build, content-pinned Rust toolchain,
  digest-pinned third-party sources,
  a separate environment-clearing root-owned trust anchor, and recoverable
  no-clobber publish without installing secrets, policy, or service state.
- [completed] Add a structural config-check CLI mode for unprivileged CI while
  preserving full activation and launcher preflight in `--check-config`.
- [completed] Update both config-repository CI lanes to use
  `--check-config-structure` and pin the all-ephemeral `status`/`pull` profile.
- [pending] Stage and apply the reviewed host release, complete activation, and
  run deployment and Webex E2E before relying on production `/config pull`.
- [pending] Add recoverable activation and in-flight drain/handoff semantics
  before enabling `/config reload` and `/config sync`; never run deployment or
  service work inside the Webex request handler.
