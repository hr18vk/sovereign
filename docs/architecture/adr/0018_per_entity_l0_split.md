# ADR-0018: Per-entity L0 split-merge

**Status:** Accepted

**Date:** 2026-08-02

**Builds on:** [ADR-0017](0017_query_resolver_read_half.md) (the resolver read path), [ADR-0016](0016_lsm_durability_seam.md) (the LSM–durability connection), and [ADR-0013](0013_durability_wal_recovery.md) (WAL recovery)

## 1. Context

ADR-0017 verified the durable write/read round trip with one entity per
checkpoint. Its tests and the accompanying live drive did not cover a checkpoint
containing several entities, although a mesh-participating node writes many
entities into one MemTable.

The L0 flusher serialized the whole frozen `SkipListArena` into one Arrow IPC
file. `UploadBuffer` named that file with `firstKey[:8]`, the first 8 bytes of
the lexicographically smallest entity hash in the arena. `Resolver.AsOf` instead
listed objects under the prefix derived from the queried entity:

```text
l0/{hex(sha256(queriedEntityID)[:8])}/
```

For a checkpoint containing N entities, the single file was visible only under
the smallest entity's prefix. Queries for the other N-1 entities returned
`ErrEntityNotFound` even though their rows were durable and indexed inside the
file. For example, a single-entity checkpoint for `wonder` produced the valid
key `l0/36296059cca8b7c7/0.arrow`, where `36296059cca8b7c7` is
`hex(sha256("wonder")[:8])`. That example did not exercise the multi-entity
case.

The original path through the code was:

1. `SnapshotToLSM` wrote every latest entity entry into one MemTable and called
   `Flush`.
2. The old `FlushArenaToIPC` implementation iterated the entire SkipList without
   partitioning it.
3. `UploadBuffer` used the first key's 8-byte hash prefix for the sole upload.
4. `AsOf` listed only the queried entity's prefix, so it could not discover a
   file stored under another entity's prefix.

The SkipList orders keys by `key[:16]`, the big-endian 128-bit SHA-256 prefix of
the entity ID. The first key therefore selected the smallest entity hash, not a
hash shared by the file's contents.

The tests also bypassed the defective route. The `l0Key` helper in
`internal/database/query_test.go` placed each test object directly under the
queried entity's prefix, and `bridge.PutLocal` with `queryTestEntry` supplied
already indexed state. No test drove a multi-entity checkpoint through the
production flusher and then read every entity back. A round-trip test must
exercise that route, including the multi-entity case, rather than construct the
object layout that the route is supposed to produce.

## 2. Decision

Emit one Arrow IPC file per entity per checkpoint:

```text
l0/{hex(entityHash[:8])}/{firstSysTimeNs}.arrow
```

`entityHash` is the 16-byte entity hash stored in the SkipList key, and
`firstSysTimeNs` is the first system timestamp in that entity's partition. All
rows for an entity in the checkpoint share one file. `AsOf` can then find every
checkpoint file for an entity by listing that entity's own prefix.

### Split during serialization

The frozen SkipList is already sorted by `key[:16]`, so rows belonging to an
entity are contiguous. `(*L0Flusher).FlushArenaToIPC(sl, emit)` makes one pass
over the arena. When the hash changes, it finalizes the current Arrow record and
invokes `emit(L0Partition)` before starting the next builder. There is no second
arena traversal or re-sort.

The callback owns the partition buffer. It uploads the buffer, retaining it
across any upload retries, and frees it before returning. Consequently the
flusher holds O(1) live partition buffers regardless of entity count; this is a
bound on partition-buffer count, not on the MemTable or the serialized row data.

The first implementation instead returned a `[]L0Partition` containing every
serialized entity before uploading any of them. With 50K unique entities in the
`TestMemTable_InsertAndFlush` workload, this retained 50K `JemallocBuffer`
objects simultaneously and the process was killed for exceeding memory.
Streaming emission retains one partition buffer at a time. The asynchronous
path retries the same serialized bytes rather than serializing the arena again.
Both synchronous and asynchronous flush paths can write a failed partition to
an entity-keyed local fallback file without preventing later partitions from
being processed.

`FlushFromArena` remains the synchronous wrapper around streaming serialization
and `UploadPartition`. The old `UploadBuffer` and the multi-entity one-blob
implementation were removed because they were incorrect whenever N>1. A global
L0 lookup manifest was also rejected: it would add a second durable object to
keep consistent with the files and another fetch on each query. The per-entity
object key is itself the lookup index.

The single-entity case retains the object key produced by the old path.

### Make query truncation observable

The default `ResolverConfig.MaxL0Files` was 1000. At acceptance, a query over
more than 1000 uncompacted checkpoint files for one entity could omit older
files. `AsOf` increments `telemetry.QueryL0ListCapped` with `Add(1)` when it
truncates this list. The metric discloses the cap; it does not make a truncated
result complete.

## 3. Consequences

Every entity in a multi-entity checkpoint is retrievable through the production
flush/read path, while N=1 still produces one upload under the same key as
before. The number of files in a checkpoint now follows its entity count rather
than its row count. Per-entity partitioning also makes later per-entity
compaction possible without a global index.

Streaming changes the memory tradeoff: serialization and upload finish for one
partition before the next partition buffer is allocated. Higher upload fan-out
exposed a race in the test `mockS3Uploader`, whose map is now protected by a
mutex and accessed through `Uploads` and `Len`. Production object-store clients
already provide the corresponding synchronization.

At acceptance, L0 files grew without compaction and the 1000-file cap could
hide older history. [ADR-0019](0019_l0_l1_per_entity_compaction.md) later added
per-entity L0-to-L1 compaction. The current resolver scans compacted L1 history
and applies `MaxL0Files` only to the uncompacted L0 tail;
`QueryL0ListCapped` now signals that this tail is growing faster than
compaction drains it. [ADR-0021](0021_l0_reaper.md) added an opt-in reaper for
superseded L0 files after verifying that their L1 file exists.

This decision did not add a delete operator or wire `EpochCompactor` into
production. Tombstone pruning remains separate from the per-entity compaction
introduced later.

It also left two existing hazards unchanged. `MaxValidTime.UnixNano()` for year-9999
overflowed to `−4.85e18`; the write path avoided it with
`OpenEndedValidEndNs = 9e18`. ADR-0021 later introduced the matching
`MaxValidTimeEndNs` constant. The `eng.DataDir` global-mutation hazard described
in ADR-0013 was also outside this decision. ADR-0021 subsequently routed
instance updates through `SetDataDir`, but engine construction still requires
serialization around the package global.

## 4. Evidence

The regression tests are in `internal/database/l0_split_test.go`. They compute
the entity hashes at run time rather than relying on a presumed ordering. The
prefix order is `wonder 3629..` < `victor 99bd..` < `toast a60e..` <
`zulu f71a..`.

| Test | Condition checked |
|:--|:--|
| `TestMultiEntityFlushRoundTripAllRetrievable` | Three entities pass through `FlushFromArena` and `AsOf`; each query returns the correct `EntityID`. Against the old one-blob implementation, the negative control produced 1 upload instead of 3, and `toast` and `victor` returned `ErrEntityNotFound`. |
| `TestLawVDigestVerbatim` | Each returned `PayloadDigest` equals the SHA-256 digest stamped for that entity's payload. |
| `TestOneBlobPerEntityNoEmptyOrDuplicate` | Four entities, one with 3 rows, produce 4 non-empty files under 4 distinct entity prefixes. |
| `TestSingleEntityBackwardCompat` | N=1 produces one upload and remains readable through `AsOf`. |
| `TestMaxL0FilesCapDisclosed` | With 25 files and `MaxL0Files=20`, the resolver returns a valid row within the cap and increments `QueryL0ListCapped`. |

`TestMemTable_InsertAndFlush` supplies the 50K-unique-entity workload that
exposed the initial implementation's memory failure. Its `signal: killed`
result motivated streaming emission; the streaming design avoids materializing
all partition buffers at once.

The original acceptance checks ran on 2026-08-02:

| Check | Recorded result |
|:--|:--|
| `go build ./...` | Passed |
| `go vet ./internal/database/ ./pkg/durability/ ./pkg/mesh/ ./internal/telemetry/` | Passed |
| `gofmt -l` on the changed Go files | Empty output |
| `go test -race -count=1 ./internal/database/` | Passed in 33.356s |
| `go test -race -count=1 ./pkg/durability/` | Passed in 10.273s |
| `go test -race -count=1 ./pkg/mesh/` | Passed in 29.099s |
| `go test -race -count=1 ./internal/telemetry/` | Passed in 1.542s |

These are historical package-test timings, not current performance claims. The
original gate table did not record host metadata for them.

The acceptance record also disclosed a pre-existing hang in
`TestChaosDigestReleaseRoundTrip`. It reproduced without the L0 changes, whose
symbols are not referenced by the chaos test, and was not fixed by this
decision.
