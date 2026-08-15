# ADR-0018: The Per-Entity L0 Split-Merge — Closing the Silent Multi-Entity Read-Miss (the Durability Read-Tier's Mesh-Participation Defect)

**Status:** Accepted
**Date:** 2026-08-02
**Phase:** 3, Day 13
**Author:** Sovereign Architect (head) + Sovereign Executor (same session — single-agent impl of the dictated fork)
**Builds on:** ADR-0017 (the resolver read-half — the single-entity round-trip that HID this class), ADR-0016 (the LSM↔durability seam), ADR-0013 (the WAL recovery seed), the Day-12.5 [243c10a] tooth-principle ("a tooth that proves X→Y must DRIVE X the route, not shortcut to Y's seam with a hand-tuned input")

---

## §1. Context (the root cause, byte-verified against the committed Day-12.5 tree `243c10a`)

ADR-0017 closed the durability round-trip for **one** entity. ADR-0017 §8's headline
("the round-trip closes") shipped under a tooth (T-I2) that wrote **exactly one** entity
through the HTTP surface. The Day-12.5 audit's own live drive wrote **one** entity
("wonder"). Every Day-12 tooth used **one** entity. The PERSISTENT index landed on disk
at the byte-correct prefix `l0/36296059cca8b7c7/0.arrow` (= `hex(sha256("wonder")[:8])`),
Law II held, T-I2 went green, and the durability tier was declared "round-trip-closed."

It is round-trip-closed **for one entity per checkpoint**. It is **not** closed for the
production node, which writes many entities per checkpoint — every mesh-participating
node. The class this closes is the SAME class the Day-8 audit named on the write path
("every mesh-participating production node"); it now sat on the read path, undetected
because every tooth shortcut to the seam with N=1.

**The one-sentence root cause:** the L0 flush co-locates a checkpoint's entire
multi-entity slice into ONE Arrow file keyed under a SINGLE (smallest-hash) entity's
hash, while `AsOf` lists by the QUERIED entity's hash — so every co-located non-smallest
entity is a silent read-miss (`ErrEntityNotFound` for data that IS on disk, law-II-correct,
and indexed inside the file).

**The byte-verified chain (read from the committed tree, not memory):**

```
snapshot.go:445    for entityID, entry := range latest { mt.Write(ctx, event) }  // ALL entities → ONE MemTable
snapshot.go:451    mt.Flush(ctx)                                                  // ONE flush
l0_flusher.go:104  for it.Valid() { ... it.Next() }                             // iterates the WHOLE SkipList (no split)
l0_flusher.go:224  hex.Encode(hexPrefix[:], firstKey[:8])                       // names file under the SMALLEST hash
                   key := "l0/" + hex(firstKey[:8]) + "/" + txTime + ".arrow"
query.go:137       prefix := "l0/" + hex(sha256(queriedEntityID)[:8]) + "/"      // lists ONLY the queried entity
query.go:139       keys := r.lister.ListObjects(ctx, bucket, prefix, MaxL0Files)
                   → a blob keyed under a DIFFERENT entity = invisible to ListObjects ⇒ ErrEntityNotFound
```

`firstKey[:8]` is the smallest entity hash because the SkipList is sorted by
`key[:16]` (16-byte entity hash, BigEndian → lexicographic = numeric). A multi-entity
flush emits exactly ONE upload under the smallest-hash entity; `AsOf` lists under the
queried entity; the other N-1 entities per checkpoint are read-misses.

**Why every Day-12/12.5 tooth missed it:** the tooth-principle Day-12.5 [243c10a]
codified at SESSION-NOTE time — *"a tooth that proves X→Y must DRIVE X the route, not
shortcut to Y's seam with a hand-tuned input"* — was VIOLATED by every one of those
teeth. `pkg/mesh/query_test.go`'s `l0Key()` helper (line ~140) keys a test file by the
QUERIED entity's own hash — the OPPOSITE of what `UploadBuffer` does — so the harness
can only reproduce the well-keyed case. The T-I2 tooth inserted ONE entity. The Day-12.5
live drive wrote ONE entity. grep-verified this session: **NO multi-entity L0 test
existed anywhere in the repo** (`internal/database/*_test.go`, `pkg/durability/*_test.go`,
`pkg/mesh/*_test.go`).

---

## §2. The fix (class-elimination — structural, NOT a manifest, NOT a band-aid)

Align the WRITE keying and the READ keying to the SAME key by emitting ONE Arrow IPC
file PER ENTITY PER CHECKPOINT:

```
l0/{hex(entity-hash8)}/{firstSysTimeNs}.arrow        (one file per entity per checkpoint)
```

`AsOf`'s prefix list (`l0/{hex(queried-hash8)}/`) then CANNOT miss: every blob for that
entity lives under exactly that prefix.

### §2.1 Split-merge inside the flush (ZERO re-sort, ZERO re-read)

The frozen SkipList is already sorted by `key[:16]` (the 128-bit `sha256(entityID)`);
contiguous same-hash entries ARE one entity-partition. The split is a single pass:

- `FlushArenaToIPC(sl, emit)` iterates the frozen SkipList; on each `key[:16]` transition
  it finalizes the current entity's record, invokes `emit(L0Partition)`, **and frees the
  current builder before the next partition starts**.
- `emit(part)` uploads the per-entity `part.Buf` (and runs the upload retry loop for the
  async path) then `part.Buf.Free()`s it — **O(1) live memory regardless of entity count**.
  This is the load-bearing subtlety: the natural "materialize all partitions then upload"
  shape holds N `JemallocBuffer`s simultaneously — at 50K unique entities that OOMs (a real
  regression that the first implementation hit; verified by `TestMemTable_InsertAndFlush`'s
  50K-entity stress). Streaming, with the buffer freed inside `emit` before the next
  partition begins, holds only ONE buffer at a time.

### §2.2 Why NOT a global manifest

- A manifest is a SECOND durable object that must stay in-sync with the blobs → a new
  WAL-style consistency problem (manifest ←→ blob skew). The per-entity keying makes the
  keySELF-describing: the filename IS the query index; no coordination object required.
- A manifest adds a list+download for the manifest on EVERY query (O(files) under the cap
  PLUS the manifest fetch) — strictly worse.

### §2.3 Why the OLD one-blob path is DELETED, not kept for "back-compat"

The one-blob `FlushArenaToIPC` (one `*JemallocBuffer` for the whole list, keyed under
`firstKey[:8]`) had NO honest back-compat reason to stay: it was ALWAYS wrong for N>1
(multi-entity co-location → silent miss). The Degenerate N=1 case yields exactly one
partition with the IDENTICAL key the old path produced, so the existing single-entity
teeth stay green via T4. There is no honest reason to keep a path that was always wrong.

---

## §3. Teeth (RED→GREEN, byte-driven — drive the ROUTE, not the seam)

All teeth live in `internal/database/l0_split_track13_test.go`. The hash8 ordering is
computed IN the test (not assumed from memory), logged per-run: `wonder 3629..` <
`toast a60e..` < `victor 99bd..` < `zulu f71a..`.

**T1 — `TestTrack13_T1_MultiEntityFlushRoundTrip_AllRetrievable` (THE HEADLINE, RED at HEAD-pre-fix)**
Drives the production flush+read with THREE entities. Asserts every entity's `AsOf`
returns 200 with the right `EntityID`.
- **RED** (one-blob path keyed under `wonder`'s smallest hash8): captured `—
  expected: 3 / actual: 1` ("one upload per entity") AND `entity "toast": AsOf returned
  an error (silent read-miss class)`. Toast + victor miss with `ErrEntityNotFound`.
- **GREEN** (per-entity split-merge): three 200s, three distinct EntityIDs.

**T2 — `TestTrack13_T2_LawV_DigestVerbatim`**
For each entity, returned `PayloadDigest == sha256(payload)` the write stamped. No
fabricated payload (the G06.e guard Day-12.5 codified).

**T3 — `TestTrack13_T3_OneBlobPerEntity_NoEmptyOrDuplicate`**
4 entities (one with 3 rows). Asserts uploaded count == entity count (not row count);
distinct-entity-prefix map size == entity count; no empty Arrow IPC blobs.

**T4 — `TestTrack13_T4_SingleEntity_BackwardCompat`**
The split path is the N=1 degenerate case: one entity → exactly ONE upload, `AsOf`
returns it. The existing Day-12 single-entity teeth stay green.

**T5 — `TestTrack13_T5_MaxL0Files_CapDisclosed`**
Writes > `MaxL0Files` (20) per-entity files (25). Asserts the resolver with that cap
returns a valid row AND the new `telemetry.QueryL0ListCapped` counter increments — the
silent-truncation cap is DISCLOSED (counted), not fake-fixed. Honest: the result returned
is best-within-cap; the metric surfaces the cap; the structural fix is level-overwrite
compaction (future fork).

---

## §4. Per-entity streaming — the O(1)-memory subtlety (the FIRST-impl regression this fork closed)

The first cut of the split path materialized every `L0Partition.Buf` at once
(`FlushArenaToIPC → []L0Partition`), uploaded them, then freed. At 50K unique entities
per checkpoint (the `TestMemTable_InsertAndFlush` stress shape), that held 50K
`JemallocBuffer`s simultaneously → process OOM (`signal: killed`). The streaming
emission (`FlushArenaToIPC(sl, emit func(L0Partition) error)`) — finalize one partition,
`emit` (upload + retry), free its buffer, **then** start the next — holds ONE buffer at a
time, O(1) regardless of N. The async upload retry concern (Override 9.2: serialize once,
retry only the upload) is preserved by holding the per-partition `Buf` inside the emit
callback's OWN retry loop, then `Free()`'d before the next partition begins.

A concurrent-map-write race in the test's `mockS3Uploader` (previously never observed
because the old one-blob path produced one upload per flush) also surfaced under the
split path's higher upload rate; that mock is now Mutex-serialized mirroring the
thread-safety a real S3 client / `LocalFS` provide.

---

## §5. Gate (byte-verified, run-output shown — never asserted)

```
G13.a  go build ./...                                          → clean
G13.b  go vet ./internal/database/ ./pkg/durability/ ./pkg/mesh/ ./internal/telemetry/  → clean
G13.c  gofmt -l (all touched .go)                              → clean
G13.d  go test -race -count=1 ./internal/database/             → ok 33.356s
G13.d  go test -race -count=1 ./pkg/durability/                → ok 10.273s
G13.d  go test -race -count=1 ./pkg/mesh/                      → ok 29.099s
G13.d  go test -race -count=1 ./internal/telemetry/            → ok 1.542s
G13.e  T1 RED at HEAD-one-blob (temp revert of the flusher):   → "expected 3 actual 1" + "toast: ErrEntityNotFound"
       T1 GREEN post-split:                                    → 3 distinct 200s
G13.f  G09c 5-file FROZEN md5 table                           → 705ac671 / ed9132a2 / 47d2796a / 590af228 / b1beba1e
       (all 5 byte-identical; the 4 untouched FROZEN files prove no core-bleed; crdt.go's 705ac671 is the Day-10 re-pin)
G13.g  Scope hygiene: zero day13/track13/phase13 glue in NEW identifiers
```

**Pre-existing `TestPhase25B1_ChaosDigestReleaseRoundTrip` hang:** reproduced at the
PRISTINE dictation HEAD `f8f86bc` with all Day-13 code stashed AND via the Day-12
ruthless report ("reproduced at HEAD — NOT a Day-12 regression"). Chaos has no
dependency on the L0 flush path (`grep`-confirmed zero references to
`L0Flusher`/`FlushFromArena`/`UploadPartition`/`L0Partition`). It is a pre-existing
test-infra hang, NOT introduced by Day-13. Honest disclosure: not fixed here.

---

## §6. Honest scope — what Day 13 is NOT

1. **NOT the compaction fork.** L0 stays unbounded-merge; `MaxL0Files=1000` (query.go:32) is
   a SILENT TRUNCATION cap → a query over >1000 per-entity checkpoints silently drops the
   oldest. Day 13 DISCLOSES it (T5 + `telemetry.QueryL0ListCapped`), not fake-fixes it. The
   structural fix is the level-overwrite compaction fork (a component that DOES NOT EXIST —
   NOT the existing dead tombstone compactor).
2. **NOT a Delete operator.** `internal/database/compactor.go`'s `EpochCompactor` /
   `SetCompactor` still has ZERO production importers (grep-verified this session: only
   `l0_flusher.go` references the type; `InsertTombstone` has ZERO production callers; the
   engine has no production DELETE op). The compactor stays dead.
3. **NOT a manifest.** Per-entity keying eliminates the manifest need; no second durable
   coordination object was added.
4. **NOT a crdt.go unfreeze.** `Join` is untouched; the 5-file FROZEN md5 set is
   byte-identical (the no-bleed gate, §5 G13.f). The 0-alloc PreSorted Seq ("the other Day
   11") stays open.
5. **NOT the `MaxValidTime.UnixNano()` overflow reset** (year-9999 → int64 overflow →
   −4.85e18, ADR-0017 §6.4 latent WRITE-path landmine). Day-13 sidesteps it with the
   `OpenEndedValidEndNs = 9e18` sentinel (the Day-12.5 fix); the var is unchanged.

---

## §7. The Day-12.5 tooth-principle this commit ENFORCES

Day-12.5 [243c10a] set: *"a tooth that proves X→Y must DRIVE X the route, not shortcut to
Y's seam with a hand-tuned input."* Day 13 ENFORCES it: T1 drives the FLUSH route
(SkipList → `FlushFromArena` → per-entity upload → `AsOf`) with N=3 entities, NOT the
seam with N=1. The teeth that hid this defect for 2 days — every Day-12 tooth —
short-cut to `l0Key(queriedEntity)` and `bridge.PutLocal(.., queryTestEntry(..))`. The
burden now codified for future forks: every "the surface is closed" claim ships with a
tooth that drives the surface, and the surface must include the multi-entity /
multi-participant case the production node actually runs.

---

## §8. Headline

**Per-entity L0 keying closes the silent multi-entity read-miss class — every
mesh-participating node, every checkpoint, every co-located non-smallest entity. The
WRITE keying and the READ keying now use the SAME key; the filename is the query index.**
The Day-12.5 single-entity claim ("round-trip-closed") is now honest WITHOUT the
single-entity asterisk — every entity per checkpoint is retrievable through the production
flush→read path.

---

## §9. Residuals (disclosed, not fixed — honest)

- **L0 unbounded growth** — one fresh per-entity file per checkpoint, no merge → the
  `MaxL0Files` silent-truncation cap (T5-disclosed). Future fork: level-overwrite
  compaction (a component that does not exist yet; NOT the dead tombstone compactor).
- **`MaxValidTime.UnixNano()` overflow** — ADR-0017 §6.4 WRITE-path landmine; not touched.
- **`eng.DataDir` global-mutation hazard** — ADR-0013 §7(g); not touched this fork.
- **Pre-existing `TestPhase25B1` chaos hang** — reproduced at the pristine dictation HEAD;
  not a Day-13 regression; chaos does not reference the L0 path.

---

### File-level diff (atomic commit)

```
 internal/database/l0_flusher.go          | the split-merge (FlushArenaToIPC streaming emit + UploadPartition) — DELETES the buggy one-blob FlushFromArena+UploadBuffer
 internal/database/memtable.go            | swapAndFlushAsync + Flush wired to the per-entity streaming emit (per-partition retry + per-entity disk fallback)
 internal/database/query.go               | AsOf MaxL0Files cap-disclosure (telemetry.QueryL0ListCapped.Inc) — the silent-truncation truth
 internal/telemetry/registry.go           | QueryL0ListCapped Counter (the cap-disclosure metric, T5 asserts it)
 internal/database/l0_split_track13_test  | T1-T5 (the per-entity RED→GREEN teeth)
 internal/database/l0_flusher_test.go     | migrated to the streaming L0Partition API (single-entity = N=1 degenerate)
 internal/database/memtable_test.go       | mockS3Uploader made thread-safe (the split path amplifies the upload race) + Uploads()/Len()
```

