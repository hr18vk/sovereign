# ADR-0019: The L0→L1 Per-Entity Compaction Fork — Eliminating the MaxL0Files Silent-Data-Loss Cap (the Level-Overwrite Fork)

**Status:** Accepted
**Date:** 2026-08-03
**Phase:** 3, Day 14
**Author:** Sovereign Architect (head) + Sovereign Executor (same session — single-agent impl of the dictated fork)
**Builds on:** ADR-0018 (Day-13 per-entity L0 split-merge — the keying PREREQ whose payoff this fork collects), ADR-0017 (the resolver read-half — disclosed the MaxL0Files cap), ADR-0016 (the LSM↔durability seam), the Day-12.5 [243c10a] tooth-principle ("a tooth that proves X→Y must DRIVE X the route, not shortcut to Y's seam with a hand-tuned input")

---

## §1. Context (the MaxL0Files silent-data-loss cap; Day-13 disclosed it; Day-14 fixes it)

ADR-0018 aligned the WRITE/READ keying so every co-located non-smallest entity is retrievable
(the silent MULTI-ENTITY read-miss, the keying form of the silent-miss class). Its §6
**explicitly DISCLOSED** a second form of the same class via a tooth (T5) + the
`telemetry.QueryL0ListCapped` counter, and named **level-overwrite compaction** as the future
fork: `AsOf` lists ONLY the newest `MaxL0Files` per-entity L0 files per query, so every older
per-entity file is INVISIBLE to the read path → a query for an OLD valid-time returns
`ErrEntityNotFound` for data that IS durable on disk. Day-13 was the PREREQ (per-entity keying
makes per-entity merge a single-key operation). Day 14 IS that merge.

The production node writes one per-entity file per checkpoint (Day-13 per-entity keying). After
>1000 checkpoints for an entity, `AsOf` silently drops that entity's EARLIEST history. A 1-ckpt/sec
node loses the oldest checkpoint after ~16.7 minutes. The `MaxL0Files` counter increments (Day-13
disclosure) but the query returns `ErrEntityNotFound` for genuinely durable, law-II-correct, indexed
data. SAME silent-miss CLASS family as Day-13 (the cap form, not the keying form).

## §2. The root cause + the byte chain

**Root cause (one sentence):** `AsOf` lists ONLY the newest `MaxL0Files=1000` per-entity L0 files
per query (query.go ListObjects capped at `config.MaxL0Files`; reverse-sort takes the newest 1000),
so every older per-entity file is INVISIBLE to the read path → a query for an OLD valid-time returns
`ErrEntityNotFound` for data that IS durable on disk.

**The byte-verified chain (HEAD 1936b8e → Day-14 HEAD, read from the committed tree, not memory):**

```
query.go:30-32   ResolverConfig{MaxL0Files int}; DefaultResolverConfig → 1000
query.go:77-79   if config.MaxL0Files <= 0 { config.MaxL0Files = 1000 }
query.go:139     l0Keys := r.lister.ListObjects(ctx, bucket, l0Prefix, MaxL0Files)  // capped
query.go:153     reverse-sort → newest 1000 scanned
query.go:166-176 for each surviving key: scanFile → scanRecordBatch  // the dropped older files are NEVER scanned
query.go:160     if len(keys) >= MaxL0Files: QueryL0ListCapped.Add(1)  // disclosure (Day-13)
```

So a node with >1000 checkpoints for an entity loses the oldest durable data silently on the read path.

## §3. The fix — the L0→L1 per-entity merge

### §3.1 The L1 tier
Introduce an L1 tier per entity: a background compaction (`internal/database/l1_compactor.go`)
merges the N per-entity L0 files for an entity into ONE sorted L1 file at
`l1/{hex(hash8)}/{firstSysTimeNs}.arrow` (or a single `l1/{hash8}.arrow` — Day-14 picks the
`{firstSysTimeNs}` keyed shape so the name is deterministic w.r.t. the merged set and the list
prefix `l1/{hex(hash8)}/` stays the per-entity scoping the read path needs). A compaction
manifest at `compaction/{hex(hash8)}/{firstSysTimeNs}.manifest` lists the L0 keys merged into
each L1 so `AsOf` can skip them.

### §3.2 WHY preserve ALL rows (the bitemporal truth-maintenance trap, §0.4)
`AsOf` returns the row with `max(SystemTime)` subject to `sysTime<=txTime` AND
`validStart<=validTime<validEnd` (query.go `scanRecordBatch` Filters 2-3 + dominance). A row R is
SAFE TO DROP on merge IFF there exists a row R' in the merged set with `sysTime(R') > sysTime(R)`
AND `[validStart(R'), validEnd(R')) ⊇ [validStart(R), validEnd(R))` — i.e. R' dominates R for
EVERY future query. Determining ⊇ over arbitrary intervals for an unbounded future is truth
maintenance — O(rows²) at worst, and WRONG under partial observability (a query with txTime in the
past sees an OLDER dominant, not the newer one). The honest minimal Day-14 compaction PRESERVES
ALL ROWS: merge = concatenate + sort by the composite key (`hash|sysTime|validTime|assertTime`),
write ONE L1 file. The L1 is the FULL per-entity history, bounded by entity write volume. Row-
pruning (superseded-row elimination) is a FUTURE fork requiring truth-maintenance + a real DELETE
operator — the dead tombstone `EpochCompactor` stays DEAD (zero production importers, grep-verified
Day-13; `NewEpochCompactor`/`SetCompactor`/`InsertTombstone` have ZERO production callers).

### §3.3 WHY a background scheduler (no write-path lock)
The compaction is a READ-L0 → WRITE-L1 background job ONLY. It never touches the live SkipList /
HAMT / WAL. The scheduler goroutine (`compactionSchedulerLoop` in `cmd/sovereign-node/main.go`)
has its OWN goroutine (NOT the MemTable flush goroutine, NOT the sweep loop) so a slow merge stalls
compaction but NOT writes and NOT the anti-entropy mesh. It periodically lists the `l0/` entity
prefixes; for each entity with `≥ L0FilesPerEntityTrigger` (default 64) L0 files, runs a Compaction
job. The entity set is derived from the L0 key prefixes (`l0/{hex8}/`); the scheduler recovers the
entityID from the first L0 file's first row (column 7) so the full `Compaction(entityID, hash8)`
re-verifies BOTH Filter1 + Filter4 for every merged row (defense in depth, §2.2 of the prompt).

### §3.4 WHY a manifest (skip superseded L0 in reads, keep them durable)
A compaction tombstones the compacted L0 files via the manifest (the L0 keys merged into each L1).
`AsOf` loads the manifests for the entity and skips any L0 key listed in any manifest (those rows
are superseded by the L1). The L0 files are NOT deleted (delete-after-read-safety — a future reaper
fork; Day-14 keeps them durable as the crash-recovery backstop). A manifest that fails to load is
skipped (honest fallback: the L0 remains scannable → worst case a superseded L0 is re-scanned,
returning the SAME dominant the L1 already produced — no correctness loss, only redundant work).

### §3.5 The read path — AsOf scans L1 + uncompacted-L0-tail (§0.5)
`query.go AsOf`: list BOTH `l1/{hex(hash8)}/` (uncapped — the compacted merged history, ALWAYS
scanned) + `l0/{hex(hash8)}/` (uncapped at the lister; apply supersession; cap the SURVIVING tail
to the newest `MaxL0Files`). The cap now bounds the TAIL (the recent uncompacted checkpoints), which
is small in steady state (write-rate × compaction interval) — a PERF cap, NOT a correctness cap; if
the tail exceeds the cap, the `QueryL0ListCapped` disclosure counter fires (the rare-stall signal:
compaction is behind; the tail is growing faster than compaction drains), and the L1 is ALWAYS
scanned, so NO durable data is silently lost. The cap class is eliminated.

**An honest subtlety the first implementation hit (and the teeth caught):** listing L0 capped at
the lister level would (a) drop the NEWEST L0 keys under some listers (LocalFS keeps the OLDEST,
asc-truncated) — the OPPOSITE of the tail §0.5 mandates — and (b) mis-cap when most L0s are
superseded by an L1 (the manifest's superseded L0s would consume the cap, hiding the few real tail
files). The fix: list L0 UNBOUND, apply supersession, cap the SURVIVING tail to the newest-N. T1/T4
were the teeth that caught this (the first cut had the lister cap; T1 RED failed to even reproduce,
and T4's post-compaction tail was pruned away).

## §4. The teeth — T1 RED→GREEN through T6 (each with the run output)

Run on 2026-08-03, Go 1.24.x, GOMAXPROCS=4, HEAD 5d052d4 (Day-14 prompt) → Day-14 HEAD (this ADR's
implementation). Every number is a RUN OUTPUT.

### T1 — `TestTrack14_T1_OldestQuerySurvivesMaxL0Cap_RedThenGreen` (THE HEADLINE, REAL *LocalFS)
Write > `MaxL0Files` (N=20, `MaxL0Files=10`) per-entity checkpoints for ONE entity over a REAL
`*LocalFS`. WITHOUT compaction: query the OLDEST valid-time → `ErrEntityNotFound` (silent loss, RED).
WITH compaction (the 20 L0 files merge → ONE L1): the SAME OLDEST query → 200, the right dominant.
Byte-captured:
```
T1 RED: oldest query (sysTime=1785759886156255455) with MaxL0Files=10 → ErrEntityNotFound (silent loss of the OLDEST 10 durable files)
T1 GREEN: compaction merged 20 L0 files → L1 l1/8ed3f6ad685b959e/1785759886156255455.arrow (20 rows preserved); oldest query now 200 (dominant sysTime=1785759886156255455, digest=8255a8e760234bb3e3f6096260e272bf288cdbfd483c2b031def83a8055729c0)
```

### T2 — `TestTrack14_T2_L1ByteIdentity_UnionOfMergedL0Rows` (Law II byte-identity across the merge)
The L1 file's row set == the union of the merged L0 files' rows for that entity (same count, same
composite-key fragments). Asserted as set equality on the 40-byte composite key. PASS (L1 row count
== union of merged L0 rows).

### T3 — `TestTrack14_T3_Idempotent_MergeTwiceSameL1Bytes` (deterministic merge)
Run the same compaction job twice on the same L0 set → the L1 byte-content is byte-identical (sorted
+ schema-identical + deterministic input ordering; the L0 keys are sorted before merging so map
iteration nondeterminism cannot bleed). PASS (byte-identical `l1Bytes1 == l1Bytes2`).

### T4 — `TestTrack14_T4_AsOfScansL1PlusUncompactedTail` (L1 + tail, not L1 alone)
Write 30 checkpoints (bulk=20, `MaxL0Files=10`); compaction merges the 20 → L1. Then write 5 MORE
checkpoints (the uncompacted tail) with sysTime NEWER than the L1's newest. `AsOf` returns the
DOMINANT for a query the L1 alone would get WRONG (the tail's latest sysTime is newer than the L1's
newest → it is in the tail, not the L1) — proving `AsOf` scans BOTH L1 and the tail. PASS (the tail
dominant's sysTime + digest returned).

### T5 — `TestTrack14_T5_DeadTombstoneCompactorUnchanged` (scope hygiene)
`EpochCompactor`/`SetCompactor`/`InsertTombstone` still have ZERO production importers post-Day-14
(grep-verified: `NewEpochCompactor` + `.InsertTombstone(` + production `.SetCompactor(` call-sites
are all empty outside `compactor.go`/`compactor_test.go`/the `l0_flusher.go` seam). The L1
compaction is a NEW trigger+merger, NOT a subclass of `EpochCompactor`. The dead tombstone compactor
stays DEAD. PASS.

### T6 — `TestTrack14_T6_FrozenMd5Unchanged` (the FROZEN md5 gate)
G09c FROZEN 5-file md5: `705ac671`/`ed9132a2`/`47d2796a`/`590af228`/`b1beba1e` byte-identical (the
compaction touches ONLY `internal/database/l1_compactor.go` + `internal/database/query.go` + the
cmd wiring + `internal/telemetry/registry.go` — `crdt.go`/`crdt_apply.go`/`schema.capnp`/
`schema.capnp.go`/`envelope.go` are untouched). The canonical `TestG09c` in `pkg/sync` PASS too.
PASS:
```
T6: FROZEN crdt.go md5 = 705ac6712ea20541f664d09d08795b43 (prefix 705ac671 == pinned)
T6: FROZEN crdt_apply.go md5 = ed9132a27930b3d76a3f62e783dd7dd3 (prefix ed9132a2 == pinned)
T6: FROZEN schema.capnp md5 = 47d2796a973319a3ffe364de3d08d6d6 (prefix 47d2796a == pinned)
T6: FROZEN schema.capnp.go md5 = 590af2287dcb3a135c586b50260be531 (prefix 590af228 == pinned)
T6: FROZEN envelope.go md5 = b1beba1e9de81294bc66a823dece6ab6 (prefix b1beba1e == pinned)
```

## §5. The Honest scope (what Day 14 is NOT — disclose, do not fake-fix)

- **NOT** superseded-row pruning (truth-maintenance). The L1 keeps every row; its size grows with the
  entity's write history; a future Level-2 fork prunes with a real DELETE operator + the tri-temporal
  dominance lattice.
- **NOT** a DELETE operator. The dead tombstone `EpochCompactor` stays DEAD (zero production importers,
  grep-verified; `L1Compactor` is NOT a subclass of `EpochCompactor`).
- **NOT** a `crdt.go` unfreeze. `Join` is untouched; the 5-file FROZEN md5 set stays byte-identical
  (G14.f / T6 / the canonical `TestG09c`).
- **NOT** the io_uring / gRPC forks (those are OPEN-P2).
- **NOT** the `SnapshotToLSM` write path. The compaction READS L0 files and WRITES L1 files only — it
  never touches the live SkipList / HAMT / WAL.
- **NOT** a write-path lock. The compaction is a background READ-L0 → WRITE-L1 job only.
- **NOT** a deletion. The L0 files are NOT deleted (a manifest makes `AsOf` skip superseded L0 keys;
  a future reaper deletes them — delete-after-read-safety).

## §6. Residuals (honestly disclosed, NOT fake-fixed)

- The L1 grows with the entity's full write history (the Level-2 superseded-row pruning fork needs
  truth-maintenance + a real DELETE op — a future fork). The `MaxL1FilesPerEntity=4` config is reserved
  for a tiered-L1 fork (if one file outgrows memory).
- The L0 reaper (delete-after-read-safety, a future fork) — Day-14 keeps L0 files durable on disk as
  the crash-recovery backstop; the manifest makes `AsOf` skip them.
- The `MaxValidTime.UnixNano()` int64-overflow LATENT landmine (ADR-0017 §6.4, disclosed, out of
  READ-only scope; no prod caller hits it).
- The `eng.DataDir` global (ADR-0013 §7g, a residual from the FROZEN engine surface).
- The entity set discovery for the scheduler is a prefix-list of `l0/` (a future fork caches the live
  entity set off the CRDT engine to avoid the periodic prefix list).
- The `Compaction` job re-downloads the L0 files on EVERY sweep after the trigger even if a manifest
  already points them into an L1 (the scheduler's per-entity bucket is bounded by the trigger count +
  compaction drains it; a future fork caches the manifest state).

## §7. The Day-12.5 tooth-principle ENFORCED
T1 drives the OLDEST-query ROUTE (write N>cap, compaction, `AsOf`) over a REAL `*LocalFS`, NOT the
seam with hand-tuned counts. The first implementation cut had the lister-level cap (§3.5); T1 RED
failed to even reproduce the silent-loss symptom (LocalFS asc-truncated to the OLDEST, so the oldest
query kept succeeding). The corrected read path (list UNBOUND + supersede + cap the surviving tail
newest-N) reproduces the RED symptom AND proves the GREEN fix. The teeth drove the ROUTE, not the
seam — the Day-12.5 principle held.

## §8. Headline
The L0→L1 per-entity merge eliminates the `MaxL0Files` silent-data-loss cap; the durability read tier
returns the full per-entity history, bounded only by write volume, never silently dropped. The cap form
of the silent-miss class Day-13 closed in keying form is now closed in cap form — the `QueryL0ListCapped`
counter, a Day-13 disclosure, is now a rare-stall signal (the tail exceeds the cap), no longer a
silent-loss sentinel.

## §9. Gate output (G14.a–G14.g, run 2026-08-03)

```
G14.a  go build ./...                          → clean (EXIT=0)
G14.b  go vet ./internal/database/ ./pkg/durability/ ./pkg/mesh/ ./internal/telemetry/ ./cmd/sovereign-node/ → clean (VET_EXIT=0)
G14.c  gofmt -l on every touched .go           → clean (GOFMT_EXIT=0; empty output)
G14.d  go test -race -count=1 ./internal/database/ ./pkg/durability/ ./pkg/mesh/
        → ok internal/database 34.869s; ok pkg/durability 11.887s; ok pkg/mesh 30.546s
G14.e  T1 RED→GREEN (byte-captured, §4 T1 above)
G14.f  G09c: 5-file FROZEN md5 byte-identical (no core bleed; Join untouched). T6 PASS.
        705ac6712ea20541f664d09d08795b43  pkg/sync/crdt.go
        ed9132a27930b3d76a3f62e783dd7dd3  pkg/sync/crdt_apply.go
        47d2796a973319a3ffe364de3d08d6d6  api/capnp/api/capnp/schema.capnp
        590af2287dcb3a135c586b50260be531  api/capnp/api/capnp/schema.capnp.go
        b1beba1e9de81294bc66a823dece6ab6  pkg/attribution/envelope.go
G14.g  Scope hygiene: zero day14/track14/phase14 glue in NEW non-test identifiers (grep empty).
        Dead compactor: NewEpochCompactor + .InsertTombstone( + production .SetCompactor( call-sites
        all empty outside compactor.go/compactor_test.go (the l0_flusher.go SetCompactor SEAM has ZERO
        production CALLERS that wire a compactor in).
```

## §10. Files touched

```
new     internal/database/l1_compactor.go                      // L1Compactor + CompactionConfig + CompactionByHash8, the merge, the manifest
edit    internal/database/query.go                             // AsOf scans L1 (always) + L0 tail (capped post-supersession, newest-N) + manifest skip
edit    internal/telemetry/registry.go                        // QueryL1FilesScanned + CompactionMerged + CompactionL1Written counters
edit    cmd/sovereign-node/main.go                            // compactionSchedulerLoop (gated --lsm-root like the resolver)
new     internal/database/l1_compaction_track14_test.go       // T2/T5/T6 teeth (the database-package teeth; LocalFS lives in pkg/durability → import cycle)
new     pkg/durability/l1_compaction_track14_test.go          // T1/T3/T4 teeth (the REAL *LocalFS teeth; the Day-12.5 tooth-principle)
new     docs/architecture/adr/0019_l0_l1_per_entity_compaction_track14.md  // this ADR
sync    AGENTS.md + UNIVERSAL_CODEX.md                         // priority queue: [DONE Day14] the level-overwrite L0→L1 merge; [OPEN-P1] the Level-2 superseded-row pruning; the Day-8..13 registry row
```
