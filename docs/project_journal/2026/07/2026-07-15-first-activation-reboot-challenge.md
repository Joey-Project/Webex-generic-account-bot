---
id: 20260715-first-activation-reboot-challenge
title: First Activation Reboot Challenge
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: codex/first-activation-challenge
pr:
supersedes: []
superseded_by:
---

# First Activation Reboot Challenge

## Summary
- Add a fixed, default-dry-run operational gate that establishes only the
  pre-reboot challenge required before first runner activation.

## Current State
- The root-owned activation helper exposes `prepare-reboot-challenge`, whose
  default mode is read-only. Explicit apply holds the activation renewal lock,
  requires an absent receipt, validates the complete installed activation
  binding, and atomically writes the persistent challenge and boot-scoped
  marker without entering the runtime canary path.
- Challenge schema version 2 binds the active manifest, runtime image, bot,
  launcher, and runtime executable digests plus the Codex version and model.
  Same-boot retries are idempotent. Binding drift, invalid state, an already
  validated challenge, or a crossed boot boundary fails closed.
- The host entrypoint reuses reviewed release, policy, runtime, and secret
  readiness checks. Apply serialises with config deployment, requires the
  receipt, runner permission, and deployment transaction to remain absent,
  and proves the bot, activation renewal, launcher socket, and config worker
  units are inactive before and after.
- This step never fetches or installs config, starts or enables a unit, runs
  Codex canaries, reboots the host, activates the runner, or contacts Webex.

## Next Steps
- Install this reviewed release and complete the preactivation-ready host gate.
- Run the challenge dry-run and explicit apply on the deployment host.
- Perform one real reboot, then complete post-reboot canaries and transactional
  runner activation in the next reviewed slice.

## Evidence
- Entrypoint: `scripts/prepare-activation-reboot-challenge`
- Implementation: `scripts/prepare-activation-reboot-challenge.mjs`
- Activation helper: `src/bin/webex-codex-activation.rs`
- State machine: `src/activation_canary.rs`
- Tests: `test/prepare-activation-reboot-challenge.node-test.mjs`
