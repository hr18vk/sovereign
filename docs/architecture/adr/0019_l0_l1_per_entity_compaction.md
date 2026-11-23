# ADR-0019: L0 to L1 Per-Entity Compaction

**Status:** Accepted  
**Date:** 2026-08-03

## Context

[ADR-0018](0018_per_entity_l0_split.md) gave each entity its own L0 key prefix,
and [ADR-0017](0017_query_resolver_read_half.md) exposed a limit in the resolver:
`AsOf` scanned only the newest `MaxL0Files` files for an entity. The default was
and remains 1000. Older files were still durable, but a query outside that window
could return `ErrEntityNotFound`. At one checkpoint per second, the oldest
checkpoint became invisible after approximately 16.7 minutes.
`QueryL0ListCapped` reported the truncation but did not make the row visible.

The per-entity layout from ADR-0018 made a bounded merge possible. The storage
boundary established by [ADR-0016](0016_lsm_durability_seam.md) also meant the
merge could run against durable Arrow files without entering the CRDT write path.

## Decision

Add `L1Compactor` in `internal/database/l1_compactor.go`. For one entity it lists
all L0 objects, downloads them, retains rows matching both the 16-byte hash prefix
and the full entity ID, and sorts the survivors by the 40-byte composite key
`hash | sysTime | validStart | assertTime`. It writes one Arrow IPC file at
`l1/{hex(hash8)}/{firstSysTimeNs}.arrow` and a manifest at
`compaction/{hex(hash8)}/{firstSysTimeNs}.manifest` listing the merged L0 keys.
Sorting the input keys makes repeated merges over an unchanged set deterministic.

The initial merge preserves every row. Pruning is not implied by compaction:
[ADR-0020](0020_level2_superseded_row_pruning.md) later adds it as an opt-in
operation with a transaction-time retention floor. The unused tombstone
`EpochCompactor` is not part of this path.

`compactionSchedulerLoop` runs independently of the MemTable flush and mesh
loops. Every 30 seconds it groups the uncapped `l0/` listing by entity and
compacts entities with at least `L0FilesPerEntityTrigger` files, whose default is
64. `CompactionByHash8` recovers the entity ID from column 7 of the earliest L0
file's first row and then calls `Compaction`, so every row still passes both the
hash-prefix and exact-entity checks. Compaction reads L0 and writes L1 and
manifest objects; it does not mutate the SkipList, HAMT, or WAL.

`AsOf` lists both the entity's L1 objects and all of its L0 objects. It removes
L0 keys named by readable manifests, then applies `MaxL0Files` to the newest
uncompacted tail. L1 files are not subject to that cap. An unreadable manifest
leaves its L0 inputs available for scanning. If manifests supersede every L0 but
no L1 is listed, the resolver falls back to the complete L0 listing.

Listing before applying the cap is necessary because `LocalFS.ListObjects`
truncates an ascending list to its oldest keys. Capping at the lister would both
discard newer files and let superseded files consume the tail allowance.

`MaxL1FilesPerEntity`, default 4, remains reserved for possible future L1
tiering; the current compactor writes one L1 per merge. The scheduler discovers
entities through an uncapped prefix listing, and a later sweep can download L0
files again even when an earlier manifest already covers them.

## Consequences

Compacted history no longer disappears merely because it lies outside the L0
listing window. Queries combine that history with newer, uncompacted rows, and
`QueryL0ListCapped` now reports truncation of the tail rather than truncation of
the entire stored history.

The tail cap is still a correctness boundary when compaction falls far behind:
if more than 1000 uncompacted L0 files remain for an entity, older files in that
tail are not scanned. The counter makes this condition visible, but operators
must still keep compaction progressing. The 30-second scheduler and trigger of
64 files normally compact the tail well before that limit.

Source L0 objects initially remain in place as a recovery backstop, so storage
use grows after compaction. [ADR-0021](0021_l0_reaper.md) adds an opt-in reaper
that verifies each L1 before deleting its inputs. ADR-0020 adds optional row
pruning; without it, L1 size grows with the entity's complete write history.
`MaxValidTime` overflow and the package-global recovery data directory were
separate residuals addressed by ADR-0021.

The change does not add a tombstone or live delete operation and does not alter
the CRDT merge law, wire schema, `SnapshotToLSM`, or write-path locking.

## Evidence

The regression tests run against the real `LocalFS` implementation as well as
the in-package merge code:

- `TestOldestQuerySurvivesMaxL0CapRedThenGreen` writes 20 checkpoints with
  `MaxL0Files=10`. The oldest query returns `ErrEntityNotFound` before
  compaction and returns the original row, payload, and digest after the 20 L0
  files become one L1.
- `TestL1ByteIdentityUnionOfMergedL0Rows` compares the L1 row set with the union
  of its inputs using the 40-byte composite keys.
- `TestIdempotentMergeTwiceSameL1Bytes` requires identical L1 bytes from two
  merges over the same input set.
- `TestAsOfScansL1PlusUncompactedTail` compacts 20 checkpoints, adds 5 newer
  checkpoints with `MaxL0Files=10`, and requires the tail's newer dominant row
  to win.
- `TestDeadTombstoneCompactorUnchanged` records that the L1 path does not use
  `EpochCompactor`, `SetCompactor`, or `InsertTombstone`.

The acceptance run on 2026-08-03 used Go 1.24.x and `GOMAXPROCS=4`. Its recorded
results were:

```text
go build ./...                          clean
go vet ./internal/database/ ./pkg/durability/ ./pkg/mesh/ ./internal/telemetry/ ./cmd/sovereign-node/
                                        clean
gofmt -l on every touched Go file       empty
go test -race -count=1 ./internal/database/ ./pkg/durability/ ./pkg/mesh/
  internal/database                     34.869s
  pkg/durability                        11.887s
  pkg/mesh                              30.546s
```

Those timings describe that acceptance environment; they are not current
performance claims. The implementation under test added
`internal/database/l1_compactor.go`, changed `internal/database/query.go`,
added the resolver telemetry and `cmd/sovereign-node` scheduler, and added the
compaction tests in `internal/database` and `pkg/durability`.

