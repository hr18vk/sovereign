# ADR-0021: L0 Reaping and Recovery Timestamp Fixes

**Status:** Accepted  
**Date:** 2026-08-03

## Context

[ADR-0019](0019_l0_l1_per_entity_compaction.md) leaves source L0 files in place
after writing L1 and its manifest. This preserves a recovery backstop but makes
the L0 footprint grow after every merge. Deleting those files requires proof
that the replacement L1 remains readable; otherwise the manifest's L0 inputs
can be the only durable copy.

Two independent recovery hazards also remained. `MaxValidTime.UnixNano()`
converted a year-9999 endpoint outside the int64 nanosecond range, producing a
negative endpoint and an empty valid-time interval. Separately, `newEngineAt`
assigned the package-global `sync.DataDir` before constructing an engine. The
constructor needed that value to locate its Lamport file, but concurrent
constructors could race on the global.

[ADR-0020](0020_level2_superseded_row_pruning.md) deferred L0 reclamation and
carried these two hazards forward. This decision addresses all three without
changing the CRDT merge or wire schema.

## Decision

### Reclaim superseded L0 objects

Add `S3Deleter` and an opt-in `L0Reaper`. The reaper depends on lister,
downloader, and deleter interfaces, never an uploader. `LocalFS.Delete` uses
`os.Remove` and treats `os.IsNotExist` as success, allowing an interrupted sweep
to resume. A compile-time assertion in `localfs.go` uses an anonymous interface
with the same `Delete` signature rather than importing `database.S3Deleter`.

Each `Reap` sweep proceeds as follows:

1. List all objects under `compaction/` without a cap and ignore non-manifest
   keys.
2. Download and parse each manifest with `ParseManifest`, the same parser used
   by the resolver. A manifest that cannot be read is skipped.
3. Download the referenced L1 before deleting any input. An empty L1 key or any
   download error increments `SkippedOrphan` and preserves both the L0 inputs
   and manifest. Storage outages therefore degrade to a skipped reap rather
   than deletion.
4. Delete each listed L0. On the first error, retain the manifest, increment
   `SkippedError`, and leave later keys untouched. Successful earlier deletions
   remain; the next sweep retries them idempotently.
5. Delete the manifest only after all listed L0 deletes succeed. A manifest
   delete error is retried on a later sweep.
6. Increment `ReapedManifests`. `ReapedL0` counts successful L0 `Delete` calls,
   including calls for objects already absent.

The node constructs the reaper only with durable LocalFS storage and
`--compaction-reap-enable`, which defaults to false.
`--compaction-reap-interval` defaults to 5m; nonpositive durations also use 5m.
The separate compaction scheduler runs every 30 seconds. Context cancellation
stops the reaper, and disabling it leaves the L0 backstop in place.

Four Prometheus counters report sweeps, successful L0 delete calls, reaped
manifests, and orphan skips. `SkippedError` is part of `ReapResult` and is
logged; it is not a separate Prometheus counter.

### Use an int64-safe open-ended timestamp

Replace `MaxValidTime` with:

```go
const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000
```

This matches `pkg/mesh.OpenEndedValidEndNs` and stays below `MaxInt64`, whose
approximate value is 9.22e18. The old year-9999 `time.Time` was outside the
int64 nanosecond range and became negative when converted. The write path now
uses the integer sentinel directly. Eight test call sites
were updated: two in `l0_flusher_test.go` and six in `memtable_test.go`. There
were no production callers of `MaxValidTime.UnixNano()`.

### Keep recovery's pre-constructor directory, then synchronize the instance

`newEngineAt` still assigns `eng.DataDir = scratchDir` before calling
`NewDeltaCRDTEngine`. The constructor copies that global into `e.dataDir` and
calls `recoverLamport`, which looks for `lamport_<nodeID>.dat` there. A fresh
scratch directory prevents a stale persisted Lamport value from overriding the
WAL-derived initial counter.

After construction, `newEngineAt` calls `engine.SetDataDir(scratchDir)`. The
setter changes the instance field under `persistMu`, giving later apply and
persistence work the same synchronization boundary. The accompanying `crdt.go`
change is a comment warning at `DataDir`; executable engine behavior is
unchanged.

This does not remove the package-global race between concurrent `newEngineAt`
calls. Recovery currently constructs one engine sequentially during process
boot. Removing the limitation requires a constructor that accepts the data
directory explicitly instead of reading `sync.DataDir`.

## Consequences

With the reaper disabled, compaction and recovery retain their previous
behavior. With it enabled, each manifest's L1 must be downloadable before any
of its L0 inputs can be removed. The probe establishes readability at that
instant, not L1 content integrity or continued availability afterward.

A missing manifest means no reclamation: L0 files for an entity that was never
compacted remain untouched. A failed manifest or delete operation does not stop
work on other manifests. `ReapedL0` and `L0ReapL0Deleted` count successful calls
rather than physical removals, so recreating a manifest for absent L0 objects
can inflate that count. `ReapedManifests` is the clearer completed-work signal.

The timestamp sentinel removes the year-9999 overflow without changing the
Arrow schema. The recovery change protects instance-level data-directory access
but leaves concurrent construction unsupported. Neither change enables L0
reaping, row pruning, receive-path transport work, or io_uring.

## Evidence

The reaper tests use real `LocalFS` storage in `pkg/durability/l0_reaper_test.go`:

- `TestReapDeletesSupersededL0AndManifestRedThenGreen` compacts 8 checkpoints,
  reaps their L0 files and manifest, and verifies that the L1 and one unrelated
  entity's unmerged L0 survive. `AsOf` still resolves the oldest row through
  the L1.
- `TestOrphanL1SafetyGuardPreservesL0AndManifest` deletes the L1 first. The
  sweep reports `SkippedOrphan=1` and preserves every L0 and the manifest.
- `TestIdempotentSecondSweepIsCleanNoOp` gets zero counts of every kind on the
  sweep after a complete reap. Recreating the manifest then exercises successful
  deletes of already-absent objects.
- `TestPartialReapDeleteFailureRetainsManifest` fails the second L0 delete. The
  first L0 stays deleted, the manifest remains, and `SkippedError=1`; a later
  unfaulted sweep completes the work. `faultyDeleter` has a compile-time
  `database.S3Deleter` assertion.
- `TestReaperDeadCompactorScopeHygiene` checks that this path introduces no
  production caller of `EpochCompactor`, `SetCompactor`, `InsertTombstone`, or
  `PruneTombstones`.

The current source carries `MaxValidTimeEndNs` in
`internal/database/l0_flusher.go` and the equal `OpenEndedValidEndNs` in
`pkg/mesh/control.go`. `newEngineAt` in `pkg/durability/recovery.go` contains
both the required pre-constructor assignment and the post-constructor
`SetDataDir` call, and documents the remaining global race.

