# ADR-0050: Decouple and delta-batch checkpoint flushes

**Status:** Accepted  
**Date:** 2026-09-08

## Context

ADR-0049 isolated the convergence stall to the synchronous, per-entity checkpoint flush in the
origin's commit path. With `--wal-checkpoint-interval=1000`, the `PutLocals` call that crossed the
interval ran `drainCheckpoints` inline. The flush wrote the full live state as one fsync'd Arrow
file per entity. For 10K keys this meant about 110,000 fsyncs on the acknowledgement path, a
260–300s quiescence stall, and a seed whose `commit_in_flight` never reached zero.

The `ckpt=0` arm of the ADR-0049 experiment converged in 8.323 s, but disabling periodic
checkpoints leaves replay unbounded. The production configuration needed the checkpoint work
removed from the commit path without disabling it.

## Decision

### Run periodic checkpoints in the background

`designateCheckpoint` starts `go b.drainCheckpoints()` instead of running the drain inline. The
committing `PutLocals` returns after its own WAL fsync. A packed atomic word, `ckptState`, stores
the runner flag in `bit0`, the pending count in `bits 1-62`, and the closing flag in `bit63`.
`Close` sets the closing bit, rejects new designations, and calls `waitCheckpointsIdle` before
closing the WAL and engine. A background checkpoint therefore cannot outlive `Close`.

### Flush only changed query-tier entities

A per-entity `lastFlushedDot` watermark selects entities whose maximum dot changed since the last
durable flush. The full `(NodeID, Counter)` comparison also handles foreign dots, and entity keys
are cloned onto the Go heap. Query-tier work is O(Δ) per checkpoint rather than O(N) over all
entities; the recovery image remains full.

`AppendCheckpoint` captures the image and delta rows under an EBR pin, then releases the pin before
`stageAndFlushQueryTierDelta`. The slow per-entity Arrow flushes no longer hold back arena
reclamation. The watermark advances only after a successful flush. The `l0/{hash8}/` layout remains
one entity per file, preserving the read path's per-entity discovery.

## Consequences

For the 10K-key workload, query-tier checkpointing changes from 110,000 fsyncs on the commit and
acknowledgement path to 20,000 fsyncs in the background runner. Commit-path checkpoint fsyncs drop
to zero. The full recovery image and per-entity query files retain their existing formats and
recovery semantics. The merge-law and wire-schema files and the recovery image's state binding were
unchanged.

Seven consecutive multi-region runs produced four consecutive passes under the 10 s convergence
objective, but one run reached t100 in 10.150 s. These results resolved the commit-path stall; they
did not establish a bound on the WAN convergence tail. Later mesh admission, timeout, relay, and
topology changes are recorded in their own ADRs.

## Evidence

### Regression guards

The checkpoint and delta tests ran under the race detector with negative controls:

- `TestDecoupleCommitNotBlockedByFlush` blocks an inline checkpoint for 3 s and checks that the
  decoupled commit is not held behind it.
- `TestDecoupleFlushCompletesAndIsDurable` checks completion and durability of background work.
- `TestCloseDrainsCheckpointRunner` checks that a pending anchor survives shutdown; a closed-WAL
  control loses the anchor without the drain.
- `TestAsyncCheckpointRequiresDrain` checks that the WAL anchor count includes all pending work.
- `TestDeltaFlushFsyncCount` distinguishes O(Δ) flush work from the full-flush control.
- `TestDeltaFlushDurableReadCorrect` checks changed and unchanged entities; dropping a delta makes
  the read stale.
- `TestDeltaCheckpointRecovery` checks recovery to the same root, with a torn image falling back to
  exact-WAL replay.

### Asynchronous witness regression

The first full `pkg/mesh` run exposed a regression in
`TestQuery_InsertEndpointToQueryEndpoint_RoundTrip`. That test drives an interval-triggered
checkpoint over the production HTTP path with `checkpointInterval=1`, but checked the `l0/` witness
synchronously. Once checkpointing became asynchronous, its assertion raced the background flush.
Sibling query tests called the synchronous public `AppendCheckpoint` directly at `interval=0` and
were unaffected.

The test now polls the eventually consistent witness with a bounded deadline, so a checkpoint that
never flushes still fails. The full package run then passed in 714 s. The narrower convergence and
topology test filter did not cover this case.

### Multi-region convergence runs

Seven consecutive runs used 100 node processes on three c7gd.8xlarge machines, one per AWS region,
with integrity verification enabled and `--wal-checkpoint-interval=1000`.

| Run | t50 | t90 | t100 | Result |
|---|---|---|---|---|
| 1 | 0.865 s | 3.774 s | 6.682 s | Passed |
| 2 | 1.233 s | 4.129 s | 8.365 s | Passed |
| 3 | 1.201 s | 5.193 s | 10.150 s | Missed the 10 s objective by 150 ms |
| 4 | 0.259 s | 3.838 s | 8.738 s | Passed |
| 5 | 0.230 s | 3.562 s | 7.260 s | Passed |
| 6 | 0.859 s | 3.750 s | 6.659 s | Passed |
| 7 | 0.237 s | 3.912 s | 6.586 s | Passed |

Runs 4 through 7 were four consecutive passes. Across the runs, quiescence took 3.11–3.14s rather
than the earlier 260–300s. Injection batches had zero hard timeouts and no slow-commit log lines.
All 100 Merkle roots matched. Crash recovery restored the pre-crash root and replayed zero
post-checkpoint records, and all three regions completed teardown with no running nodes.

Seed profiles showed the checkpoint flush on a background `drainCheckpoints` goroutine through
`stageAndFlushQueryTierDelta`, `LocalFS.Upload`, and `os.File.Sync`. No commit-path goroutine was
parked in checkpoint fsync.

Run 3's miss was a mesh-tail straggler rather than a return of the checkpoint stall: t50 and t90
stayed in their approximately 0.2–1.2s and 3.5–5.2s bands while t100 varied, and the `ckpt=0`
diagnostic had already measured 8.323 s. The result left the WAN tail as a separate problem.
