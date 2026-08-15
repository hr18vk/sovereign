# ADR-0029: The Filename-Bounded Download Skip — the Transitively-Safe Elimination on the FILE Channel (Day 24, Track 24)

**Status:** ACCEPTED (Day 24, 2026-08-09) — §5 CONDITIONAL-GO (Day 24 is NOT an E1/E2/E3/E5 verdict-blocker; it adds a READ-path elimination + a disclosure counter, does NOT touch the single-writer root-equality qualifier / the FROZEN `crdt.go` blocks).

**Closes:** the FILE channel of the durable AsOf/Range unbounded-download residual ADR-0017 §6 named (the FIRST claw). The `AGENTS.md:61` OPEN-P1 ("wire Seek into scanWindowRecordBatch") is REFUTED (M1: `scanWindowRecordBatch` takes `arrow.Record`, NOT a SkipList; the wiring is a NO-OP; the genuine target is the DOWNLOAD count, NOT the row scan).

**Enforced by:** `internal/database/day24_track24_test.go` (8 teeth), `pkg/durability/day24_track24_test.go` (4 REAL-`*LocalFS` route teeth), `internal/telemetry/day24_track24_test.go` (2 SSoT teeth), `pkg/metrics/day24_track24_test.go` (1 bridge-sister tooth). 15 teeth total across 4 packages + 3 re-pinned count-assertion teeth (Day-18/21/22).

---

## §1. Context (the named residual; ADR-0017 §6 named the unbounded download)

ADR-0017 §6.1 named the durable read path's unbounded-download residual: `AsOf` + `Range` are O(L0-files) per query because they DOWNLOAD + DECODE every L0/L1 Arrow file under the entity's prefix. Day-24 closes the FILE channel: a file whose filename-encoded `FirstSysTimeNs` (the file's MIN sysTime, written by the flush since Day-13) exceeds the query's txTime is transitively-safe to skip — every row in it fails Filter2 (`sysTime <= txTime`) → zero qualifying rows → skipping preserves the answer byte-identically (Law II) AND cuts the download. Day-25 (ADR-0030) closes the MANIFEST channel — the second download the read path pays.

## §2. The root cause (one sentence) + the byte-verified constraints

**Root cause (one sentence):** the read path paid an unbounded per-query download for files the filename ALREADY proved carry ZERO rows visible at the query's txTime — the transitively-safe elimination was never applied to the download.

The byte-verified constraints (the §0 premise-audit, BEFORE code):

- **§0.a — the filename ALREADY carries the bound.** `l0KeyFor`/`l1KeyFor` (l1_compactor.go:943/957) write `{firstSys}.arrow`; `FirstSysTimeNs` is the file's MIN sysTime (l0_flusher.go, written since Day-13). The bound is on the filename, NOT the row scan — the honest acceleration target is the filename, NOT the SkipList.
- **§0.b — the transitively-safe tautology.** `file.min > T ⟹ every row's sysTime >= file.min > T ⟹ every row fails Filter2 (sysTime <= T) ⟹ ZERO qualifying rows ⟹ skip preserves the answer byte-identically (Law II) AND cuts the download`. The bound is STRICT `>` (a row AT `sysTime == T` passes Filter2 with `<=` → `firstSys == T` → DO NOT skip).
- **§0.c — the FAILSAFE.** `parseFirstSysFromKey` returns `(int64, bool)`; a parse anomaly (`ok=false`) → NO skip → full download. A corrupt filename is NEVER silently dropped (the honest fallback is the full download, NOT a silent data loss).

## §3. The mechanism design + the load-bearing premise-audit (decided BEFORE code)

The skip is a guarded `continue` in the `l0Keys`/`l1Keys` scan loops (query.go): `parseFirstSysFromKey(fileKey)`; if `ok && firstSys > txTimeNs` → increment `QueryDownloadSkippedFirstSys` (the disclosure) + `continue` (skip the download). The `txTimeNs` is threaded in from the `AsOf`/`Range` entry. The skip is OPT-OUT (gated on `EnableFirstSysSkip`, default true — Day-24 INVERTS Day-19's opt-IN).

**The premise-audit (SEVENTH dictated-correction, the load-bearing M1):** the queue's "wire Seek into scanWindowRecordBatch" was FALSE on the bytes. `scanWindowRecordBatch` takes `arrow.Record` (query.go:1013), NOT a SkipList; the Resolver struct (query.go:104) holds NO live MemTable/SkipList field; the durable read path reads Arrow files ONLY. Wiring Seek into the durable Arrow read is a NO-OP. The genuine residual is the DOWNLOAD count, NOT the row scan. The honest acceleration target is the filename (which ALREADY carries the bound), NOT the SkipList. M2: SkipList key order `hash|sysTime|validStart|assertTime` (validStart co-sorted NOT independent — a Seek can bound AT MOST the sysTime ceiling, NOT the `[vLo,vHi)` validTime window). M3: Seek stays DORMANT (NOT ROI to wire; the genuine first consumer is the live cross-entity tail mega-fork, NOT the durable Arrow wiring). M4: count-growth 15→16 re-pinned Day-18/21/22 SSoT teeth (the SAME class Day-22 M4 hit).

## §4. The byte chain

- **`internal/database/query.go` — the `txTimeNs` param + the guarded `continue`** in the `l0Keys`/`l1Keys` scan loops (parseFirstSysFromKey + `firstSys > txTimeNs` + `QueryDownloadSkippedFirstSys.Add(1)` + `continue`).
- **`internal/telemetry/registry.go` — the 16th counter (4 sites).** `QueryDownloadSkippedFirstSys` (a `modeCounter`) in `init()` + `rebuildCounters()` (the Day-21 fill discipline) + `allCounters()` (the SSoT slice) + the var-block. Name: `supremum.l0.query_download_skipped_first_sys`. The bridge auto-surfaces the 16th series WITHOUT an edit (§6.e).
- **`internal/database/l1_compactor.go:943/957` — `l1KeyFor`/`manifestKeyFor` (READ-ONLY verify).** The filename grammar `{firstSys}.arrow` / `{firstSys}.manifest` — UNCHANGED. Day-24 READ-ONLY-verifies it parses; the producer is byte-UNCHANGED.

## §5. The teeth (the gate) — all GREEN

15 teeth across 4 packages + 3 re-pinned count-assertion teeth. The EQUIV fuzz (`N=64×2000` seed=24) PROVED load-bearing via BUG-INJECT (`>=`→divergences at every `firstSys==txNs` → RED). The DOWNLOAD-COUNT tooth PROVED load-bearing via RED-NEUTER (downloads 4→2, skips 0→2).

- **In-package (8 teeth):** the parser, the parser-alloc, the failsafe, the off-by-skip boundary, the EQUIV fuzz, the download-count, the FROZEN scope, the default-gate.
- **REAL-`*LocalFS` route (4 teeth):** preserves-answer, download-count, range-window-orthogonal, the boundary over the production on-disk path.
- **SSoT (2 teeth):** the in-package count assertion (15→16) + the subprocess-Init non-nil.
- **Bridge-sister (1 tooth):** the bridge auto-surfaces the 16th series WITHOUT a bridge edit (bridge byte-UNCHANGED — the 7th clean-chain fork, NO bridge re-pin since Day-13).

## §6. Future forks (the honest carry-forward, NOT this fork)

- **§6.a — the MANIFEST channel (Day 25, ADR-0030).** The SECOND download the read path pays (`loadSupersededL0Keys` downloads+`ParseManifest`-decodes every compaction manifest per query). The SAME tautology applies on the manifest channel (the manifest's filename-encoded `firstSys` is the L1's MIN sysTime — the SAME field). CLOSED Day 25.
- **§6.b — the upper-bound `maxSys` sidecar (a SEPARATE opt-in fork).** Bounds the OPPOSITE end (`file.max < txTime`, a file whose NEWEST row is older than the query's txTime). NOT transitively-safe in the same tautological sense (a file with `max < txTime` CAN still carry a row a FORENSIC query at a txTime BELOW `max` wants — a HEURISTIC, not a tautology). Disclosed as opt-in, NOT this fork.
- **§6.c — the `Seek` wiring stays DORMANT (the REFUTED #61 premise).** `scanWindowRecordBatch` takes `arrow.Record`, NOT a SkipList. The genuine first `Seek` consumer is the live cross-entity tail mega-fork (the Resolver↔MemTable seam), NOT the durable Arrow wiring.

## §7. The premise-audit (the SEVENTH dictated-correction since Day-17)

M1 (load-bearing): `scanWindowRecordBatch` takes `arrow.Record`, NOT a SkipList — the wiring is a NO-OP; the genuine residual is the DOWNLOAD count. M2: SkipList key order (validStart co-sorted NOT independent). M3: Seek stays DORMANT. M4: count-growth 15→16 re-pinned the SSoT teeth.

## §8. The §III gate (byte-verified)

`go build ./...` exit 0; `gofmt -l` clean; `go vet` 35 `unsafe.Pointer` warnings ALL in `pkg/sync` (PRE-EXISTING — vet 35==35); `fieldalignment` ZERO new debt (the `loadSupersededL0Keys` signature change adds an `int64` PARAM, NOT a struct field; `ResolverConfig` UNCHANGED); 5-FILE FROZEN md5 byte-identical (`835350a8`/`ed9132a2`/`47d2796a`/`590af228`/`b1beba1e`); verifier-side byte-UNCHANGED (`3c1b4a8f`/`2ed28034`/`22c36f61`/`8fcc149b`); `TestGate_FrozenMD5`+`TestGate_UntouchedFrozenAndOutOfScope` GREEN pre-AND-post; `TestHotPathZeroAllocations` GREEN (READ path, NOT write); `-race` clean per-package (the 4-core box constraint).

**§5 STAYS CONDITIONAL-GO.** ZERO FROZEN touched. The SEVENTH clean-chain fork after Day-18/19/20/21/22/23.1. Day-24 is NOT an E1/E2/E3/E5 verdict-blocker; it does NOT touch the single-writer root-equality qualifier — the MANDATE-2 the FROZEN `crdt.go` blocks.

## §9. The decision (two-commit, per the Day-22/23 protocol)

1. `feat(database)` Day 24: the filename-bounded download-skip + the counter (`query.go` + `registry.go` + the re-pinned SSoT teeth + the 15 NEW teeth). The test files travel with the feat commit.
2. `docs(codex,agents)` Day 24 ADR-0029 session note (`UNIVERSAL_CODEX.md` + `AGENTS.md` priority-queue sync). The queue's `[OPEN-P1]` `#61` line gets the first REFUTED stamp (M1).

NO dictated-flip this fork (Day-24 ADDS a guarded `continue` + a counter + re-pins the count-assertion teeth; the `DominancePrune` is UNCHANGED). The bridge is byte-UNCHANGED (the §0.f SSoT-grows-auto property). NOTE: Day-24's feat+docs shipped in the SAME two-commits as Day-25 at ship time (Day-25 builds directly on Day-24's primitives — `parseFirstSysFromKey` + `EnableFirstSysSkip` + the file-skip counter — so the two forks combined).
