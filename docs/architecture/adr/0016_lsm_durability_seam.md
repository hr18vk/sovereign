# ADR-0016: The LSM–Durability Seam — Bounded Recovery

**Status:** Accepted; recovery mechanics superseded by [ADR-0045](0045_mesh_transport_invariants.md), [ADR-0050](0050_checkpoint_decouple_delta.md), and [ADR-0053](0053_wal_snapshot_crc32c.md)
**Date:** 2026-08-02
**Builds on:** [ADR-0013](0013_durability_wal_recovery.md) (WAL recovery and the seed-by-trace proof in §4)

## 1. Context

Before this change, `pkg/durability/recovery.go` rebuilt state by replaying the
entire WAL into a seed engine. Recovery cost grew with every write since the log
was created, rather than with the writes since the last checkpoint. The
checkpoint's `{MerkleRoot, LamportHigh}` record supported an equality assertion
but contained no state from which to rebuild the HAMT.

The seed-by-trace proof in ADR-0013 made replay reproduce the recorded origin
dots; it did not bound replay cost. The `internal/database` LSM tier already
provided a MemTable, an L0 flusher, and Arrow IPC output, but no package outside
`internal/database` imported it. This decision connects that tier to checkpoint
and recovery without rewriting its data structures.

## 2. Decision

Persist two artifacts when a durable node takes a checkpoint under `--lsm-root`:

1. A dot-bearing recovery image at `ckpt/<LamportHigh>`. This plain binary
   contains one `SnapshotRecord` per `CRDTEntry`, across every entry of every
   entity. `(*HAMT).MerkleRoot` obtains those entries through `ForEach`, collects
   every `(DotNodeID, DotCounter)` pair, sorts the pairs, and hashes the sorted
   set with SHA-256. The result therefore does not depend on `maphash.Seed`, and
   the image preserves foreign dots absent from the local WAL. A
   latest-entry-per-entity recovery image would drop historical dots and could
   change the recovered root; only the query index uses that representation.
2. An Arrow IPC query index under `l0/<...>`, written through the existing
   MemTable and L0 flusher. It contains the latest entry per entity. At the time
   of this decision, `CRDTEntry` was 120 bytes: a `PayloadDigest [32]byte`,
   `OriginNodeID`, `DotNodeID`, `DotCounter`, five time fields, and `H3Index`. It
   had no payload body, so each query row carries the recorded digest and an
   empty body. `(*MemTable).Write` packs that digest as supplied; it does not
   recompute it from the empty payload.

The integration touched five sites:

| File | Change | Role |
|---|---|---|
| `pkg/durability/localfs.go` | Added `LocalFS` | Local implementation of the uploader, lister, and downloader interfaces used by the LSM tier |
| `pkg/durability/snapshot.go` | Added `SnapshotToLSM` and the `SnapshotImage` codec | Checkpoint image and query-index persistence |
| `pkg/durability/recovery.go` | Added `RecoverEngineWithSnapshot` and `RecoveryWitness` | Snapshot recovery, full-replay fallback, and recovery diagnostics |
| `pkg/durability/bridge.go` | Added snapshot wiring to `AppendCheckpoint` | Persist the WAL anchor before the derived artifacts |
| `cmd/sovereign-node/main.go` | Added `--lsm-root` | Enable snapshots alongside `--wal-path` |

The first implementation loaded the image into an engine seeded at the
checkpoint watermark, joined the recorded dots, and replayed mutations and clock
advances whose counters exceeded that watermark. This was the algorithm covered
by the original measurements below. The superseding changes are described under
Consequences.

### Original recovery proof

The original algorithm relied on the seed-by-trace proof in ADR-0013.
`InsertLocal` re-minted `DotNodeID` and `DotCounter` from `NextDot`, regardless
of the recorded entry fields. Full replay reproduced origin dots by seeding the
engine at `firstMutation.Counter-1`. The snapshot path could not use that seed
alone: the image was merged state with scattered dots, so it restored those dots
through `Join`, which preserves each recorded dot. The determinism question was
whether the two paths reached the same dot set:

```text
at the checkpoint      : A.State().MerkleRoot() == checkpoint.MerkleRoot
after post-ckpt replay : A.MerkleRoot() == B.MerkleRoot()
```

Here A used bounded recovery and B used full replay from the same WAL and
snapshot. The original bounded seed was
`max(firstMutation.Counter-1, ckpt.LamportHigh)`. Under its original
append-order assumptions, the checkpoint followed the mutations, making the
maximum `ckpt.LamportHigh`. Post-checkpoint `InsertLocal` calls then minted
`ckpt.LamportHigh+1, +2, …`, matching the recorded mutation counters above the
watermark, while the pre-checkpoint dots were already present from the image
join. Thus A and B reached the same dot set and watermark in the origin-only
case exercised by the test.

This proof belongs to the original re-minting algorithm. It does not establish
correctness under concurrent mint and append reordering; the later exact-WAL
recovery decision replaced that assumption rather than extending this proof.

Two other implementation facts constrained the original recovery path:

- `ReplayWAL` set `FinalCheckpt` and `HasCheckpoint` but did not append the
  checkpoint to `rep.Ordered`, which contained only mutations and clock
  advances. The original bounded replay therefore could not cut the tail at the
  checkpoint's position in `Ordered`; it used the counter-based filter instead.
- `State` did not pin EBR. A bare `State` call concurrent with `InsertLocal`
  could dereference a shard root that a racing compare-and-swap had retired and
  freed. `Acquire` obtained a participant from the pool but did not enter the
  epoch. The original `SnapshotToLSM` therefore called `ebr.Acquire`, then
  `participant.Enter(ebr)`, and deferred `ebr.Release(participant)` around
  `State` and `ForEach`. The checkpoint stress test exercised this pin with
  concurrent writers.

## 3. Consequences

### Recovery and checkpoint cost

The recovery image restores state through `(*DeltaCRDTEngine).Join`, which keeps
each recorded dot instead of minting a replacement. A latest-entry-per-entity
image would not be sufficient: historical dots contribute to the Merkle root, so
dropping them can change the recovered root. The separate query index is the
latest-per-entity representation.

Bounding the WAL tail does not make recovery independent of total state. Image
loading is O(total state), and the original decoder materialized a
`[]SnapshotRecord` before joining it. Checkpoint capture also walks the full
live HAMT. The trade is an O(total-state) checkpoint and image load for an
O(post-checkpoint) replay tail.

A snapshot can contain foreign state that full replay of the local WAL cannot
reconstruct. Origin-only recovery comparisons can therefore assert equal roots,
but a foreign-state comparison has no equivalent full-replay state.

### Failure handling and compatibility

The WAL checkpoint is synced before the image is written. The important crash
cases are:

| Crash window | WAL anchor | Image | Recovery |
|---|---|---|---|
| Before the WAL sync | Absent | Absent | Cold boot or replay from an earlier checkpoint |
| After the WAL sync, before the image write | Present | Absent | Full-replay fallback |
| During the original image write | Present | Incomplete or malformed | Decode rejection and full-replay fallback |

An unavailable, unreadable, or undecodable derived image does not discard the
authoritative WAL. Recovery uses full replay and records the cause in
`RecoveryWitness.FallbackReason`. The original decoder rejected mismatched magic
or version numbers and truncated input, so recovery never interpreted a malformed
image as valid state.

`RecoverEngine` remains the full-replay wrapper around
`RecoverEngineWithSnapshot` with a nil store. A nil snapshotter writes only the
WAL anchor. An empty `--lsm-root` leaves full replay in effect when `--wal-path`
is set; an empty `--wal-path` selects the in-memory engine without `LocalFS`.

At the time of this decision, the Arrow rows were written and flushed, but
`Resolver.AsOf` did not read them. Their recorded digest and empty body were a
storage contract for a later resolver, not evidence that temporal resolution had
been exercised. Incremental snapshots were also outside this decision: the
original checkpoint walked the full live HAMT under an EBR pin every time.

### Changes after this decision

- [ADR-0045](0045_mesh_transport_invariants.md) §4 replaced re-minting and
  counter-based cuts with exact-dot replay through synthetic-delta joins. The
  current recovery constructor seeds from the durable WAL and checkpoint clock
  high-water. It selects the tail by WAL record sequence: `CutSeq` for V2 `0x05`
  checkpoints and the record after the checkpoint for legacy `0x02` logs, with
  repair for legacy checkpoint holes.
- The same ADR moved capture to one EBR-pinned `CaptureShardsPinned` walk, bound
  images to checkpoint roots and sequence cuts, added state-fingerprint checks,
  and rejected duplicate or local-phantom image records. A root or fingerprint
  mismatch on an otherwise usable bound image is fatal rather than a fallback.
  `LocalFS.Upload` now syncs a temporary file, atomically renames it, and syncs
  the parent directory; interrupted temporary uploads are reaped.
- [ADR-0050](0050_checkpoint_decouple_delta.md) moved checkpoint work off the
  commit path and changed query-index flushing to changed entities after the
  initial full flush. Unchanged entities no longer require another Arrow file
  and sync on every checkpoint.
- [ADR-0053](0053_wal_snapshot_crc32c.md) added a whole-image Castagnoli CRC32C
  trailer in snapshot v3 and checksummed WAL records. A checksum failure in the
  authoritative WAL refuses boot; a checksum failure in a snapshot selects
  logged full-WAL fallback. Version 2 images remain readable but have no CRC.
- The original scope left `Resolver.AsOf` unexercised. [ADR-0017](0017_query_resolver_read_half.md),
  [ADR-0024](0024_resolver_range.md), and [ADR-0032](0032_live_source_read_your_writes.md)
  subsequently wired `AsOf`, `Range`, and live read-your-writes behavior into the
  node.

## 4. Evidence

These results belong to the original decision. They are not new measurements of
the current implementation described above.

### Original verification

`TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual` compared bounded and
full recovery from the same WAL and snapshot with pre=256 and post=24 under
`-race`. It asserted equality with the live Merkle root. The checkpoint stress
test intersected extraction with 6 concurrent writers under `-race` to exercise
the epoch pin.

The original decision recorded these verification results for that
implementation:

| Check | Command or scope | Result |
|---|---|---|
| Build | `go build ./...` | Passed |
| Vet | `go vet ./...` | Passed |
| Format | `gofmt -l` on `pkg/durability` and `cmd/sovereign-node` | Clean |
| Durability race tests | `go test -race ./pkg/durability/` | Passed in 9.1s |
| Database race tests | `go test -race ./internal/database/` | Passed in 2.2s |
| Sync and mesh race tests | `go test -race ./pkg/sync/ ./pkg/mesh/` | Passed |
| Hot-path allocation check | `TestHotPathZeroAllocations` | Passed |
| Field layout | Analysis of the new durability structs | Clean |
| Recovery benchmark | `BenchmarkRecovery_BoundedVsFull` | Results below |
| Backward compatibility | `TestWALRecoveryDeterminism` and `TestRecoveryDeterminism_KillRebuildMerkleEqual` | Passed |

The two package timings are quoted from the original gate table, which did not
record separate host metadata for those runs.

### Recovery benchmark

`BenchmarkRecovery_BoundedVsFull` ran on arm64 with four cores, pre=8192 and
post=64:

```text
BenchmarkRecovery_BoundedVsFull/Full-4        80409917 ns/op   13760184 B/op   34004 allocs/op   ReplayedRecords=8256
BenchmarkRecovery_BoundedVsFull/Bounded-4     77439932 ns/op   22285733 B/op   35270 allocs/op   ReplayedRecords=64
```

The `ReplayedRecords` witness directly counted the records passed to replay, so
the replay-tail reduction did not depend on an asymptotic formula. Bounded
recovery replayed 64 records instead of 8256 records, a 129× reduction, and
reached the same Merkle root. Wall-clock time was approximately 4% lower at this
workload, while allocation volume rose from 13.7 MB to 22.3 MB (+63%) and
allocation count rose from 34,004 to 35,270 (+3.7%). The original decoder's
`io.ReadAll` and materialized `[]SnapshotRecord` account for the added
recovery-time allocation. Decoding rows directly into the join sequence could
avoid that full materialization, but such a decoder was not part of the measured
implementation.

The benchmark establishes a shorter replay tail, not a general latency
improvement. Its 8192-record image is small enough that snapshot loading and
full replay have similar wall-clock cost. As an arithmetic illustration rather
than a measurement, pre=8,192,000 with post=64 would leave a replay tail 128,000×
shorter; the O(total-state) image load would still remain.
