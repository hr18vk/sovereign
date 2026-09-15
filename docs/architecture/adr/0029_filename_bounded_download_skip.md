# ADR-0029: The Filename-Bounded Download Skip — the Transitively-Safe Elimination on the FILE Channel

**Status:** ACCEPTED (2026-08-09). The change adds a READ-path elimination plus a disclosure counter; it does NOT touch the single-writer root-equality qualifier or the core `crdt.go`.

**Closes:** the FILE channel of the durable AsOf/Range unbounded-download residual ADR-0017 §6 named. The standing hypothesis "wire `Seek` into `scanWindowRecordBatch`" is REFUTED: `scanWindowRecordBatch` takes an `arrow.Record`, NOT a SkipList, so that wiring would be a NO-OP; the genuine target is the DOWNLOAD count, NOT the row scan.

**Enforced by:** `internal/database/download_skip_counter_test.go` (8 guards), `pkg/durability/download_skip_counter_test.go` (4 REAL-`*LocalFS` route guards), `internal/telemetry/download_skip_counter_test.go` (2 counter-registry guards), `pkg/metrics/download_skip_counter_test.go` (1 bridge-sister guard). 15 guards total across 4 packages + 3 updated count-assertion guards.

---

## §1. Context (the named residual; ADR-0017 §6 named the unbounded download)

ADR-0017 §6.1 named the durable read path's unbounded-download residual: `AsOf` + `Range` are O(L0-files) per query because they DOWNLOAD + DECODE every L0/L1 Arrow file under the entity's prefix. This ADR closes the FILE channel: a file whose filename-encoded `FirstSysTimeNs` (the file's MIN sysTime, written by the flush since the L0 format landed) exceeds the query's txTime is transitively-safe to skip — every row in it fails Filter2 (`sysTime <= txTime`) → zero qualifying rows → skipping preserves the answer byte-identically AND cuts the download. ADR-0030 closes the MANIFEST channel — the second download the read path pays.

## §2. The root cause (one sentence) + the byte-verified constraints

**Root cause (one sentence):** the read path paid an unbounded per-query download for files the filename ALREADY proved carry ZERO rows visible at the query's txTime — the transitively-safe elimination was never applied to the download.

The byte-verified constraints (the premise-audit, established BEFORE code):

- **§0.a — the filename ALREADY carries the bound.** `l0KeyFor`/`l1KeyFor` (l1_compactor.go:943/957) write `{firstSys}.arrow`; `FirstSysTimeNs` is the file's MIN sysTime (l0_flusher.go, written since the flush format landed). The bound is on the filename, NOT the row scan — the honest acceleration target is the filename, NOT the SkipList.
- **§0.b — the transitively-safe tautology.** `file.min > T ⟹ every row's sysTime >= file.min > T ⟹ every row fails Filter2 (sysTime <= T) ⟹ ZERO qualifying rows ⟹ skip preserves the answer byte-identically AND cuts the download`. The bound is STRICT `>` (a row AT `sysTime == T` passes Filter2 with `<=` → `firstSys == T` → DO NOT skip).
- **§0.c — the FAILSAFE.** `parseFirstSysFromKey` returns `(int64, bool)`; a parse anomaly (`ok=false`) → NO skip → full download. A corrupt filename is NEVER silently dropped (the honest fallback is the full download, NOT a silent data loss).

## §3. The mechanism design + the load-bearing premise-audit (decided BEFORE code)

The skip is a guarded `continue` in the `l0Keys`/`l1Keys` scan loops (query.go): `parseFirstSysFromKey(fileKey)`; if `ok && firstSys > txTimeNs` → increment `QueryDownloadSkippedFirstSys` (the disclosure) + `continue` (skip the download). The `txTimeNs` is threaded in from the `AsOf`/`Range` entry. I made the skip OPT-OUT (gated on `EnableFirstSysSkip`, default true — inverting the earlier opt-in precedent for read-path accelerations).

**The premise-audit (the load-bearing finding):** the hypothesis "wire Seek into scanWindowRecordBatch" was FALSE on the bytes. `scanWindowRecordBatch` takes `arrow.Record` (query.go:1013), NOT a SkipList; the Resolver struct (query.go:104) holds NO live MemTable/SkipList field; the durable read path reads Arrow files ONLY. Wiring Seek into the durable Arrow read is a NO-OP. The genuine residual is the DOWNLOAD count, NOT the row scan. The honest acceleration target is the filename (which ALREADY carries the bound), NOT the SkipList. Supporting findings: the SkipList key order is `hash|sysTime|validStart|assertTime` (validStart co-sorted, NOT independent — a Seek can bound AT MOST the sysTime ceiling, NOT the `[vLo,vHi)` validTime window); Seek stays DORMANT (not worth wiring here; its genuine first consumer is the live cross-entity tail work, NOT the durable Arrow wiring); the counter-count growth 15→16 required updating the earlier count-assertion guards.

## §4. The byte chain

- **`internal/database/query.go` — the `txTimeNs` param + the guarded `continue`** in the `l0Keys`/`l1Keys` scan loops (`parseFirstSysFromKey` + `firstSys > txTimeNs` + `QueryDownloadSkippedFirstSys.Add(1)` + `continue`).
- **`internal/telemetry/registry.go` — the new counter (4 sites).** `QueryDownloadSkippedFirstSys` (a `modeCounter`) in `init()` + `rebuildCounters()` (the rebuild-fill discipline) + `allCounters()` (the full counter slice) + the var-block. Name: `supremum.l0.query_download_skipped_first_sys`. The bridge auto-surfaces the new series WITHOUT an edit.
- **`internal/database/l1_compactor.go:943/957` — `l1KeyFor`/`manifestKeyFor` (READ-ONLY verify).** The filename grammar `{firstSys}.arrow` / `{firstSys}.manifest` — UNCHANGED. I only verified the grammar parses; the producer is byte-UNCHANGED.

## §5. The guards (the gate) — all GREEN

15 guards across 4 packages + 3 updated count-assertion guards. The EQUIV fuzz (`N=64×2000` seed=24) PROVED load-bearing via BUG-INJECT (`>=` instead of `>` → divergences at every `firstSys==txNs` → RED). The DOWNLOAD-COUNT guard PROVED load-bearing via RED-NEUTER (downloads 4→2, skips 0→2).

- **In-package (8 guards):** the parser, the parser-alloc, the failsafe, the off-by-skip boundary, the EQUIV fuzz, the download-count, the core-file-untouched guard, the default-gate.
- **REAL-`*LocalFS` route (4 guards):** preserves-answer, download-count, range-window-orthogonal, the boundary over the production on-disk path.
- **Counter-registry (2 guards):** the in-package count assertion (15→16) + the subprocess-Init non-nil.
- **Bridge-sister (1 guard):** the bridge auto-surfaces the new series WITHOUT a bridge edit (the bridge file is unchanged).

## §6. Future work (the honest deferred work, NOT this change)

- **§6.a — the MANIFEST channel (ADR-0030).** The SECOND download the read path pays (`loadSupersededL0Keys` downloads+`ParseManifest`-decodes every compaction manifest per query). The SAME tautology applies on the manifest channel (the manifest's filename-encoded `firstSys` is the L1's MIN sysTime — the SAME field). CLOSED by ADR-0030.
- **§6.b — the upper-bound `maxSys` sidecar (a SEPARATE opt-in change).** Bounds the OPPOSITE end (`file.max < txTime`, a file whose NEWEST row is older than the query's txTime). NOT transitively-safe in the same tautological sense (a file with `max < txTime` CAN still carry a row a FORENSIC query at a txTime BELOW `max` wants — a HEURISTIC, not a tautology). Disclosed as opt-in, NOT part of this change.
- **§6.c — the `Seek` wiring stays DORMANT (the REFUTED hypothesis).** `scanWindowRecordBatch` takes `arrow.Record`, NOT a SkipList. The genuine first `Seek` consumer is the live cross-entity tail work (the Resolver↔MemTable seam), NOT the durable Arrow wiring.

## §7. The premise-audit

The premise-audit surfaced four findings before any code was written:

1. (load-bearing) `scanWindowRecordBatch` takes `arrow.Record`, NOT a SkipList — the proposed wiring is a NO-OP; the genuine residual is the DOWNLOAD count.
2. The SkipList key order co-sorts validStart (NOT independent), so a Seek can bound AT MOST the sysTime ceiling, NOT the `[vLo,vHi)` validTime window.
3. Seek stays DORMANT.
4. The counter-count growth 15→16 required updating the count-assertion guards.

## §8. The verification gate (byte-verified)

`go build ./...` exit 0; `gofmt -l` clean; `go vet` 35 `unsafe.Pointer` warnings ALL in `pkg/sync` (PRE-EXISTING — vet 35==35); `fieldalignment` ZERO new debt (the `loadSupersededL0Keys` signature change adds an `int64` PARAM, NOT a struct field; `ResolverConfig` UNCHANGED); the five core files unchanged; the durable-read producer files (`l0_flusher.go`/`l1_compactor.go`/`skiplist_arena.go`/`telemetry_bridge.go`) byte-unchanged; the change confined to its target files; `TestHotPathZeroAllocations` GREEN (READ path, NOT write); `-race` clean per-package (the 4-core box constraint).

No core file touched. The change does not touch the single-writer root-equality qualifier in the core `crdt.go`.

## §9. The decision (two-commit split)

1. `feat(database)`: the filename-bounded download-skip + the counter (`query.go` + `registry.go` + the updated count-assertion guards + the 15 NEW guards). The test files travel with the feat commit.
2. `docs`: this ADR + the session note.

No behavioural flip was required: the change ADDS a guarded `continue` + a counter + updates the count-assertion guards; `DominancePrune` is UNCHANGED. The bridge is byte-UNCHANGED (the counter registry auto-surfaces a newly registered series). NOTE: this change shipped in the same two commits as the follow-up manifest-channel work (ADR-0030), which builds directly on these primitives — `parseFirstSysFromKey` + `EnableFirstSysSkip` + the file-skip counter — so the two combined at ship time.
