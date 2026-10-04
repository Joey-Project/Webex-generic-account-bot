---
id: 20261004-v2gate
title: Codex Review Gate v2 Consumer Installation
status: active
created: 2026-10-04
updated: 2026-10-04
branch:
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Consumer Installation

## Summary
- The target-branch installation replaces the dedicated v1 review producer with the canonical v2 verifier and controller, and protects the workflow control plane through CODEOWNERS.

## Current State
- `.github/workflows/codex-review-gate.yml` uses the floating `@v2` action, read-only verifier permissions including `actions: read`, `request_author_permission: any`, and `request_review: false`.
- `.github/workflows/codex-review-gate-controller.yml` is installed; `.github/CODEOWNERS` assigns workflow and CODEOWNERS ownership to `@JoeyTeng`.
- The README defines the supported review-gate scope as ordinary same-repository pull requests to the default branch. Fork-head `workflow_run` association and automatic request are explicitly unsupported and are not implied by this installation.
- The production ruleset is unchanged by this consumer installation. This note does not claim that a v2 production requirement or the wider repository migration is complete.

## Next Steps
- Complete the separately authorized production-ruleset transition while preserving existing rules and without adding a new `@codex` requirement; continue the remaining consumer rollout before recording the shared cutover as complete.

## Evidence
- Consumer implementation commit: `cf5c410d85a954f206ad77dbafafef31ae00eb98`.
- Canonical bootstrap preview/apply and exact verifier/controller template comparisons passed; `actionlint` 1.7.12 and `git diff --check` passed.
