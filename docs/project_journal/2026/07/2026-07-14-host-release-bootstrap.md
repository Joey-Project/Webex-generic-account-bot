---
id: 20260714-host-release-bootstrap
title: Initial Host Release Bootstrap
status: completed
created: 2026-07-14
updated: 2026-07-14
branch: codex/host-release-bootstrap
pr: https://github.com/Joey-Project/Webex-generic-account-bot/pull/26
supersedes: []
superseded_by:
---

# Initial Host Release Bootstrap

## Summary
- The first-install host release has a fixed root-owned bootstrap entrypoint, an unprivileged reproducible builder, a content-manifested bundle, and a no-clobber root installer.

## Current State
- The builder exports an approved Git commit, uses digest-pinned Rust toolchain, Cargo vendor, Codex, and BusyBox inputs, and runs Cargo with fixed offline source replacement.
- Static BusyBox wrappers clear inherited loader state and verify root-owned metadata plus all JavaScript module digests before Node imports them.
- Build and install recovery accept only byte-identical completed outputs; secrets, activation policy, service state, and live deployment remain outside this slice.

## Next Steps
- Stage and apply an approved release through the deployment automation workstream.
- Complete activation, persistence, reboot recovery, and Webex E2E before enabling production configuration actions.

## Evidence
- PR: https://github.com/Joey-Project/Webex-generic-account-bot/pull/26
- Release contract: `scripts/host-release-contract.mjs`
- Node tests: `test/host-release.node-test.mjs`
