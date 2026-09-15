# ADR-0019: L0→L1 Per-Entity Compaction — Eliminating the MaxL0Files Silent-Data-Loss Cap (Level Overwrite)

**Status:** Accepted
**Date:** 2026-08-03
**Author:** Harsh Rawat
**Builds on:** ADR-0018 (the per-entity L0 split-merge — the keying prerequisite whose payoff this change collects), ADR-0017 (the resolver read-half — disclosed the MaxL0Files cap), ADR-0016 (the LSM↔durability seam), and the tooth principle established earlier in this series ("a test that proves X→Y must DRIVE X the route, not shortcut to Y's seam with a hand-tuned input").

---

## §1. Context (the MaxL0Files silent-data-loss cap)

ADR-0018 aligned the WRITE/READ keying so every co-located non-smallest entity is retrievable
(the silent multi-entity read-miss, the keying form of the silent-miss class). Its §6
explicitly disclosed a second form of the same class via a test plus the
`telemetry.QueryL0ListCapped` counter, and named level-overwrite compaction as the follow-up:
`AsOf` lists ONLY the newest `MaxL0Files` per-entity L0 files per query, so every older
per-entity file is invisible to the read path → a query for an old valid-time returns
`ErrEntityNotFound` for data that IS durable on disk. ADR-0018 was the prerequisite
(per-entity keying makes per-entity merge a single-key operation); this ADR is that merge.

The production node writes one per-entity file per checkpoint. After >1000 checkpoints for an
entity, `AsOf` silently drops that entity's earliest history. A 1-checkpoint/sec node loses
the oldest checkpoint after ~16.7 minutes. The `QueryL0ListCapped` counter increments (the
ADR-0018 disclosure) but the query returns `ErrEntityNotFound` for genuinely durable,
merge-law-correct, indexed data. The same silent-miss class as the keying form, in its cap
form.

## §2. The root cause + the byte chain

**Root cause (one sentence):** `AsOf` lists ONLY the newest `MaxL0Files=1000` per-entity L0
files per query (query.go ListObjects capped at `config.MaxL0Files`; reverse-sort takes the
newest 1000), so every older per-entity file is invisible to the read path → a query for an
old valid-time returns `ErrEntityNotFound` for data that is durable on disk.

**The byte-verified chain (read from the committed tree at the time):**

```
query.go:30-32   ResolverConfig{MaxL0Files int}; DefaultResolverConfig → 1000
query.go:77-79   if config.MaxL0Files <= 0 { config.MaxL0Files = 1000 }
query.go:139     l0Keys := r.lister.ListObjects(ctx, bucket, l0Prefix, MaxL0Files)  // capped
query.go:153     reverse-sort → newest 1000 scanned
query.go:166-176 for each surviving key: scanFile → scanRecordBatch  // the dropped older files are NEVER scanned
query.go:160     if len(keys) >= MaxL0Files: QueryL0ListCapped.Add(1)  // disclosure
```

So a node with >1000 checkpoints for an entity loses the oldest durable data silently on the
read path.

## §3. The fix — the L0→L1 per-entity merge

### §3.1 The L1 tier
Introduce an L1 tier per entity: a background compaction (`internal/database/l1_compactor.go`)
merges the N per-entity L0 files for an entity into ONE sorted L1 file at
`l1/{hex(hash8)}/{firstSysTimeNs}.arrow`. I picked the `{firstSysTimeNs}`-keyed shape so the
name is deterministic with respect to the merged set and the list prefix `l1/{hex(hash8)}/`
stays the per-entity scoping the read path needs. A compaction manifest at
`compaction/{hex(hash8)}/{firstSysTimeNs}.manifest` lists the L0 keys merged into each L1 so
`AsOf` can skip them.

### §3.2 Why preserve ALL rows (the bitemporal truth-maintenance trap)
`AsOf` returns the row with `max(SystemTime)` subject to `sysTime<=txTime` AND
`validStart<=validTime<validEnd` (query.go `scanRecordBatch` filters 2–3 + dominance). A row R
is SAFE TO DROP on merge IFF there exists a row R' in the merged set with
`sysTime(R') > sysTime(R)` AND `[validStart(R'), validEnd(R')) ⊇ [validStart(R), validEnd(R))`
— i.e. R' dominates R for every future query. Determining ⊇ over arbitrary intervals for an
unbounded future is truth maintenance — O(rows²) at worst, and wrong under partial
observability (a query with txTime in the past sees an older dominant, not the newer one). The
honest minimal compaction therefore PRESERVES ALL ROWS: merge = concatenate + sort by the
composite key (`hash|sysTime|validTime|assertTime`), write one L1 file. The L1 is the full
per-entity history, bounded by entity write volume. Row-pruning (superseded-row elimination)
is future work requiring truth maintenance + a real DELETE operator — the dead tombstone
`EpochCompactor` stays dead (zero production importers, grep-verified: `NewEpochCompactor`/
`SetCompactor`/`InsertTombstone` have zero production callers).

### §3.3 Why a background scheduler (no write-path lock)
The compaction is a READ-L0 → WRITE-L1 background job only. It never touches the live
SkipList / HAMT / WAL. The scheduler goroutine (`compactionSchedulerLoop` in
`cmd/sovereign-node/main.go`) has its own goroutine (not the MemTable flush goroutine, not the
sweep loop) so a slow merge stalls compaction but not writes and not the anti-entropy mesh. It
periodically lists the `l0/` entity prefixes; for each entity with `≥ L0FilesPerEntityTrigger`
(default 64) L0 files, it runs a compaction job. The entity set is derived from the L0 key
prefixes (`l0/{hex8}/`); the scheduler recovers the entityID from the first L0 file's first
row (column 7) so the full `Compaction(entityID, hash8)` re-verifies both Filter1 and Filter4
for every merged row (defense in depth).

### §3.4 Why a manifest (skip superseded L0 in reads, keep them durable)
A compaction tombstones the compacted L0 files via the manifest (the L0 keys merged into each
L1). `AsOf` loads the manifests for the entity and skips any L0 key listed in any manifest
(those rows are superseded by the L1). The L0 files are NOT deleted (delete-after-read-safety
— a future reaper; for now they stay durable as the crash-recovery backstop). A manifest that
fails to load is skipped (honest fallback: the L0 remains scannable → worst case a superseded
L0 is re-scanned, returning the same dominant the L1 already produced — no correctness loss,
only redundant work).

### §3.5 The read path — AsOf scans L1 + the uncompacted L0 tail
`query.go AsOf`: list BOTH `l1/{hex(hash8)}/` (uncapped — the compacted merged history, always
scanned) + `l0/{hex(hash8)}/` (uncapped at the lister; apply supersession; cap the surviving
tail to the newest `MaxL0Files`). The cap now bounds the tail (the recent uncompacted
checkpoints), which is small in steady state (write rate × compaction interval) — a
performance cap, not a correctness cap; if the tail exceeds the cap, the `QueryL0ListCapped`
disclosure counter fires (the rare-stall signal: compaction is behind; the tail is growing
faster than compaction drains), and the L1 is always scanned, so no durable data is silently
lost. The cap class is eliminated.

**An honest subtlety the first implementation hit (and the tests caught):** listing L0 capped
at the lister level would (a) drop the newest L0 keys under some listers (LocalFS keeps the
oldest, asc-truncated) — the opposite of the tail semantics this section mandates — and (b)
mis-cap when most L0s are superseded by an L1 (the manifest's superseded L0s would consume the
cap, hiding the few real tail files). The fix: list L0 unbound, apply supersession, cap the
surviving tail to the newest-N. Two of the tests below caught this: the first cut had the
lister cap; T1 RED failed to even reproduce, and T4's post-compaction tail was pruned away.

## §4. The tests — T1 RED→GREEN through T6 (each with the run output)

Run on 2026-08-03, Go 1.24.x, GOMAXPROCS=4. Every number is a run output.

### T1 — `TestOldestQuerySurvivesMaxL0CapRedThenGreen` (the headline, real *LocalFS)
Write > `MaxL0Files` (N=20, `MaxL0Files=10`) per-entity checkpoints for one entity over a real
`*LocalFS`. Without compaction: query the oldest valid-time → `ErrEntityNotFound` (silent
loss, RED). With compaction (the 20 L0 files merge → one L1): the same oldest query → 200, the
right dominant. Byte-captured:

```
T1 RED: oldest query (sysTime=1785759886156255455) with MaxL0Files=10 → ErrEntityNotFound (silent loss of the OLDEST 10 durable files)
T1 GREEN: compaction merged 20 L0 files → L1 l1/8ed3f6ad685b959e/1785759886156255455.arrow (20 rows preserved); oldest query now 200 (dominant sysTime=1785759886156255455, digest=8255a8e760234bb3e3f6096260e272bf288cdbfd483c2b031def83a8055729c0)
```

### T2 — `TestL1ByteIdentityUnionOfMergedL0Rows` (byte identity across the merge)
The L1 file's row set == the union of the merged L0 files' rows for that entity (same count,
same composite-key fragments). Asserted as set equality on the 40-byte composite key. PASS
(L1 row count == union of merged L0 rows).

### T3 — `TestIdempotentMergeTwiceSameL1Bytes` (deterministic merge)
Run the same compaction job twice on the same L0 set → the L1 byte-content is byte-identical
(sorted + schema-identical + deterministic input ordering; the L0 keys are sorted before
merging so map-iteration nondeterminism cannot bleed). PASS (byte-identical
`l1Bytes1 == l1Bytes2`).

### T4 — `TestAsOfScansL1PlusUncompactedTail` (L1 + tail, not L1 alone)
Write 30 checkpoints (bulk=20, `MaxL0Files=10`); compaction merges the 20 → L1. Then write 5
more checkpoints (the uncompacted tail) with sysTime newer than the L1's newest. `AsOf`
returns the dominant for a query the L1 alone would get wrong (the tail's latest sysTime is
newer than the L1's newest → it is in the tail, not the L1) — proving `AsOf` scans both L1
and the tail. PASS (the tail dominant's sysTime + digest returned).

### T5 — `TestDeadTombstoneCompactorUnchanged` (scope hygiene)
`EpochCompactor`/`SetCompactor`/`InsertTombstone` still have zero production importers
(grep-verified: `NewEpochCompactor` + `.InsertTombstone(` + production `.SetCompactor(`
call-sites are all empty outside `compactor.go`/`compactor_test.go`/the `l0_flusher.go`
seam). The L1 compaction is a new trigger+merger, not a subclass of `EpochCompactor`. The dead
tombstone compactor stays dead. PASS.

### T6 — the core files are untouched (no core bleed)
The core merge-law/wire-schema files are unchanged: the compaction touches only
`internal/database/l1_compactor.go` + `internal/database/query.go` + the cmd wiring +
`internal/telemetry/registry.go` — `crdt.go`/`crdt_apply.go`/`schema.capnp`/
`schema.capnp.go`/`envelope.go` are untouched. PASS.

## §5. The honest scope (what this change is NOT — disclose, do not fake-fix)

- **NOT** superseded-row pruning (truth maintenance). The L1 keeps every row; its size grows
  with the entity's write history; a future level-2 change prunes with a real DELETE operator
  + the tri-temporal dominance lattice.
- **NOT** a DELETE operator. The dead tombstone `EpochCompactor` stays dead (zero production
  importers, grep-verified; `L1Compactor` is not a subclass of `EpochCompactor`).
- **NOT** a `crdt.go` unfreeze. `Join` is untouched; the core merge-law/wire-schema
  files are unchanged (T6).
- **NOT** the io_uring / gRPC work (those remain open).
- **NOT** the `SnapshotToLSM` write path. The compaction reads L0 files and writes L1 files
  only — it never touches the live SkipList / HAMT / WAL.
- **NOT** a write-path lock. The compaction is a background READ-L0 → WRITE-L1 job only.
- **NOT** a deletion. The L0 files are not deleted (a manifest makes `AsOf` skip superseded
  L0 keys; a future reaper deletes them — delete-after-read-safety).

## §6. Residuals (honestly disclosed, not fake-fixed)

- The L1 grows with the entity's full write history (the level-2 superseded-row pruning work
  needs truth maintenance + a real DELETE op — future). The `MaxL1FilesPerEntity=4` config is
  reserved for a tiered-L1 change (if one file outgrows memory).
- The L0 reaper (delete-after-read-safety, future) — for now L0 files stay durable on disk as
  the crash-recovery backstop; the manifest makes `AsOf` skip them.
- The `MaxValidTime.UnixNano()` int64-overflow latent landmine (ADR-0017 §6.4, disclosed, out
  of read-only scope; no production caller hits it).
- The `eng.DataDir` global (ADR-0013 §7g, a residual from the frozen engine surface).
- The entity-set discovery for the scheduler is a prefix-list of `l0/` (a future change caches
  the live entity set off the CRDT engine to avoid the periodic prefix list).
- The `Compaction` job re-downloads the L0 files on every sweep after the trigger even if a
  manifest already points them into an L1 (the scheduler's per-entity bucket is bounded by the
  trigger count + compaction drains it; a future change caches the manifest state).

## §7. The test-drives-the-route principle, enforced

T1 drives the oldest-query route (write N>cap, compaction, `AsOf`) over a real `*LocalFS`, not
the seam with hand-tuned counts. The first implementation cut had the lister-level cap (§3.5);
T1 RED failed to even reproduce the silent-loss symptom (LocalFS asc-truncated to the oldest,
so the oldest query kept succeeding). The corrected read path (list unbound + supersede + cap
the surviving tail newest-N) reproduces the RED symptom and proves the GREEN fix. The tests
drove the route, not the seam.

## §8. Headline

The L0→L1 per-entity merge eliminates the `MaxL0Files` silent-data-loss cap; the durability
read tier returns the full per-entity history, bounded only by write volume, never silently
dropped. The cap form of the silent-miss class (the keying form was closed in ADR-0018) is now
closed in cap form — the `QueryL0ListCapped` counter is now a rare-stall signal (the tail
exceeds the cap), no longer a silent-loss sentinel.

## §9. Gate output (run 2026-08-03)

```
go build ./...                          → clean (exit 0)
go vet ./internal/database/ ./pkg/durability/ ./pkg/mesh/ ./internal/telemetry/ ./cmd/sovereign-node/ → clean (exit 0)
gofmt -l on every touched .go           → clean (empty output)
go test -race -count=1 ./internal/database/ ./pkg/durability/ ./pkg/mesh/
        → ok internal/database 34.869s; ok pkg/durability 11.887s; ok pkg/mesh 30.546s
T1 RED→GREEN (byte-captured, §4 T1 above)
The core merge-law/wire-schema files are unchanged (no core bleed; Join untouched). T6 PASS.
Dead compactor: NewEpochCompactor + .InsertTombstone( + production .SetCompactor( call-sites
        all empty outside compactor.go/compactor_test.go (the l0_flusher.go SetCompactor seam has zero
        production callers that wire a compactor in).
```

## §10. Files touched

```
new     internal/database/l1_compactor.go                  // L1Compactor + CompactionConfig + CompactionByHash8, the merge, the manifest
edit    internal/database/query.go                         // AsOf scans L1 (always) + L0 tail (capped post-supersession, newest-N) + manifest skip
edit    internal/telemetry/registry.go                     // QueryL1FilesScanned + CompactionMerged + CompactionL1Written counters
edit    cmd/sovereign-node/main.go                         // compactionSchedulerLoop (gated --lsm-root like the resolver)
new     internal/database/l1_compaction_test.go            // T2/T5/T6 (the database-package tests; LocalFS lives in pkg/durability → import cycle)
new     pkg/durability/l1_compaction_test.go               // T1/T3/T4 (the real *LocalFS tests)
new     docs/architecture/adr/0019_l0_l1_per_entity_compaction.md  // this ADR
```
