---
id: 20260715-host-deployment-preflight
title: Host Deployment Preparation
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: codex/host-deployment-preflight
pr:
supersedes: []
superseded_by:
---

# Host Deployment Preparation

## Summary
- Add one fixed, default-dry-run entrypoint for the reviewed release, host
  policy, runtime image, and secret-readiness preparation sequence.

## Current State
- Every run revalidates the installed release through the root-owned installer
  with the operator-supplied reviewed commit and manifest digest.
- Dry-run invokes only the guarded provisioner inspection. Apply invokes the
  guarded provisioner. The explicit `provisioned` target stops there; the
  explicit `preactivation-ready` target then acquires the shared deployment
  lock, revalidates policy under that lock, and invokes the fixed runtime
  source-manifest and image builders.
- Runtime dry-run inspects fixed sources without writing. It compares the
  source, builder, `mksquashfs`, and fixed argv contract and reports a different
  upgrade runtime as a conflict. Apply rejects an existing active runtime unless
  that contract exactly matches an idempotent retry; corrupt runtime state
  remains intact for a separate recovery workflow.
- The provisioner uses the shared deployment lock for policy convergence. The
  preactivation phase reacquires it for policy revalidation and runtime
  preparation, then rechecks activation and secret metadata after the build. A
  later readiness failure leaves the host safely provisioned and rerunnable.
- Secret readiness checks fixed parent and file metadata with `lstat`; secret
  files are never opened or read. Missing secrets are reported as incomplete
  readiness unless the operator selects `--require-secrets`.
- Child processes receive a fixed scrubbed environment. Failure output excludes
  child stdout and stderr. Shared-lock contention retains retryable exit status
  `75` through the top-level launcher.
- The entrypoint never enables or starts units, installs activation permission,
  mints a receipt, or contacts Webex. A preactivation apply also requires the
  receipt, permission drop-in, and reboot challenge to remain absent.

## Next Steps
- Build, review, stage, and install the approved release on the deployment host.
- Deliver the five fixed secret files through the separate operator channel and
  pass the explicit secret readiness gate.
- Run the real reboot activation challenge in its own reviewed and observable
  operational step.

## Evidence
- Entrypoint: `scripts/prepare-host-deployment`
- Implementation: `scripts/prepare-host-deployment.mjs`
- Tests: `test/prepare-host-deployment.node-test.mjs`
