---
id: 20260715-durable-message-job-recovery
title: Durable Message Job Recovery
status: completed
created: 2026-07-15
updated: 2026-07-15
branch: codex/durable-message-job-recovery
pr:
supersedes: []
superseded_by:
---

# Durable Message Job Recovery

## Summary
- Persist supported Webex message-created events before sidecar acknowledgement
  and process accepted work outside the HTTP request lifetime.

## Completed
- Added a mode-`0700` job spool derived from `state_file`, with mode-`0600`
  records, strict topology and metadata validation, a fixed 4096-job bound, and
  atomic no-clobber publication backed by file and directory syncs.
- Preserved the first sidecar hint for duplicate message IDs while retaining
  authoritative Webex hydration for all room, sender, body, thread, execution,
  and write decisions.
- Added bounded background execution, automatic retry, startup rescheduling,
  duplicate in-process scheduling suppression, and health counts for pending
  and active jobs.
- Kept the existing `JsonlStateStore` attempt lease as the crash boundary: an
  unclean restart waits for a surviving lease to expire, then resumes the
  durable job. Existing hidden Webex markers reconcile ambiguous writes.
- Added tests for durable reopen/removal, duplicate enqueue, backlog limits,
  interrupted candidates, corrupt or unsafe spool entries, acknowledgement
  before Codex completion, duplicate sidecar delivery, transient retry, and
  restart recovery after an old lease expires.

## Boundaries
- This slice does not provide cross-process lease transfer, immediate takeover,
  supervised drain, config activation, `/config reload`, or `/config sync`.
- The later activation/handoff slice must keep the old service healthy until a
  replacement owns ingress and must define immediate transfer or drain for
  active jobs.
