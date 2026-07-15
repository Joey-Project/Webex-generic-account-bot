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
- Persisted only a canonical message-ID envelope, never sidecar body, person,
  or room hints that a same-UID current-user runner could read. Authoritative
  Webex hydration supplies all room, sender, body, thread, execution, and write
  decisions.
- Required raw job and recovery-candidate bytes to match the canonical record
  serialization, rejecting duplicate JSON keys and other noncanonical disk
  records before they enter the in-memory index.
- Added background execution bounded by `server.max_concurrent_requests`,
  permit-before-load event handling, a lightweight startup index, bounded
  non-active and non-deferred backlog selection, automatic retry that releases
  worker capacity, startup rescheduling, duplicate in-process scheduling
  suppression, and lightweight health counts for pending and active jobs.
- Capped deferred retry scheduling at 24 hours, used checked deadline
  arithmetic before taking the scheduler lock, and latched scheduler-state
  failures into health.
- Bounded job and recovery-candidate enumeration at the fixed spool limit and
  serialized blocking health scans behind a dedicated single-slot gate;
  concurrent health scans return `503` without consuming another blocking
  worker.
- Latched runtime spool failures into authenticated health while allowing
  unrelated indexed jobs to continue; a corrupt event no longer blocks later
  records or leaves `/healthz` falsely healthy.
- Classified fixed backlog-capacity responses separately from spool I/O and
  integrity failures, so ordinary backpressure remains retryable without
  poisoning health while persistence failures latch `503` until restart.
- Kept the existing `JsonlStateStore` attempt lease as the crash boundary: an
  unclean restart waits for a surviving lease to expire, then resumes the
  durable job. Existing hidden Webex markers reconcile ambiguous writes.
- Added tests for durable reopen/removal, duplicate enqueue, backlog and active
  task limits, both interrupted publication states, corrupt or unsafe spool
  entries including non-blocking FIFO rejection, terminal invalid-ID handling,
  canonical ID-only persistence, same-UID payload non-disclosure,
  duplicate-key rejection,
  acknowledgement before Codex completion, duplicate sidecar delivery,
  non-starving deferred retry, runtime-corruption health latching, transient
  retry, retry-delay bounding, scheduler-state health latching, health-scan
  admission, bounded filesystem enumeration, and restart recovery after an old
  lease expires.

## Boundaries
- This slice does not provide cross-process lease transfer, immediate takeover,
  supervised drain, config activation, `/config reload`, or `/config sync`.
- The later activation/handoff slice must keep the old service healthy until a
  replacement owns ingress and must define immediate transfer or drain for
  active jobs.
