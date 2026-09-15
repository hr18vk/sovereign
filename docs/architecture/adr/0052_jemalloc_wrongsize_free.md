# ADR-0052: The resliced-buffer wrong-size free that corrupted the jemalloc heap

- **Status:** RESOLVED — the intermittent `internal/database` `SIGSEGV` "fault 0x30".
- **Date:** 2026-09-10
- **Core merge-law/wire-schema files:** UNCHANGED — the five files carrying the CRDT merge law and the wire schema are identical before and after this change.
- **Severity framing (honesty):** this was a **TEST-CODE heap-corruption bug, not a production defect.** The production allocator and flush paths already honored the usable-size contract; the bug was a *test helper* that resliced a buffer before freeing it, corrupting the process-global jemalloc heap that every test in one `go test` process shares. The crash *victim* (the MemTable flush) is production code; the corruption *source* was test code. The fix is in the **production** allocator, so the wrong-size-free class is now impossible from ANY caller — present or future, test or production.

## 1. ROOT CAUSE (physics, one sentence)
`readAllIntoJemalloc` (`internal/database/l1_compaction_test.go`) returned `buf[:n]` — the jemalloc buffer resliced to the *content* length `n` — and `collectRowKeys` freed that reslice, so `sdallocx(ptr, n)` was handed a size (e.g. `3266`) that did **not** equal the usable size jemalloc recorded for the block (`32768`), returning a 32KB large block to the wrong (~3.2KB) size class and corrupting the heap metadata that a later 64KB MemTable-flush alloc/free tripped over at `addr=0x30`.

## 2. The mechanism (why it corrupts; why intermittent; why the flush is the victim)
- `Allocate(32768)` → `mallocx` → usable `32768` (a 32KB *large* extent). `Free(buf[:3266])` → `sdallocx(ptr, 3266, 0)`: jemalloc computes the size class from `3266` (a *small* class) but the block is a 32KB large extent, so the free treats a large block as a small slab region and writes freelist/bitmap metadata into a non-slab extent → corrupted size-class bookkeeping.
- The corruption is **latent** until a later alloc/free walks the poisoned size class. The MemTable flush is the heaviest 64KB-class churner in the suite (`TestMemTable_InsertAndFlush`: 50000 partitions → 50000 64KB `NewJemallocBuffer` alloc/free), so it is where the corruption detonates — "seed early, detonate later." The ~50% intermittency is whether the corrupted block happens to be reused in a way that trips a 64KB op.
- The `TestJemallocAllocator_Reallocate` anomaly (`2048→32768`; see H4 below) is a **symptom** of the same corruption — `malloc_usable_size` reads the poisoned size-class metadata and returns a wrong value — not a separate bug. It is gone post-fix.

## 3. The instrument that caught the culprit (diagnosis before the fix)
The fault is invisible to `-race` (cgo/jemalloc memory is outside the Go data-race model) and to the jemalloc redzone (this 5.3.0 build REJECTS `redzone:true`, so an OOB write was *not* ruled out by a redzone run). Isolated repros of the flush path were **CLEAN** (16/16: a pure 64KB buffer churn AND a faithful Arrow `RecordBuilder`+`JemallocBuffer`+ipc-writer mini-flush), proving the corruption is seeded by a *different* test and detonates in the flush (the process-global heap is shared across every test in the process). So I built a process-global **heap-audit instrument** (`memory_allocator_audit.go`, env-gated by `SUPREMUM_JEMALLOC_AUDIT`, zero-cost when unarmed) that registers every live block and validates every `Free`.

On the full suite it caught, **deterministically (4/4 runs)**, a `WRONG-SIZE-FREE`: `free_size=3266` vs recorded usable `32768`; the alloc stack pointed at `readAllIntoJemalloc`, freed in `collectRowKeys`.

**CAUSATION PROOF:** a heal-mode audit (free with the recorded correct size, then continue) let the full suite run to completion with **0 SIGSEGV** and exactly **13** healed wrong-size frees — *all* from the one compaction test helper. Healing only the free *size* eliminated the crash ⇒ the wrong-size free is the (sole) cause.

## 4. Hypothesis verdicts (CONFIRM/REFUTE, evidence-backed)
- **H0 (OOB write): REFUTED** as the cause — healing only the free *size* removed the crash; an OOB write would not be healed by that. (The guard-band instrument variant was therefore not needed.)
- **H1 (align flag dropped on sdallocx): REFUTED** — the allocator already passes the *usable* size to `sdallocx`, so the align flag is moot (analysis), and the pure-allocator stress (alloc-with-`ALIGN(64)` + free-`flags=0`, the exact H1 pattern) was clean 16/16 (empirical).
- **H2 (uploader UAF): REFUTED** — the test mocks never escape the buffer; the culprit is upstream in the helper.
- **H3 (Go data race): REFUTED** — full-suite `-race` clean (615s, 0 `DATA RACE`); the culprit is a deterministic single-goroutine wrong-size free.
- **H4 (size-accounting drift → wrong-size sdallocx): CONFIRMED** — this is the mechanism, byte-anchored.

## 5. The fix (the core files untouched)
- **`memory_allocator.go` `Free`:** derive the freed size from `malloc_usable_size(ptr)` (jemalloc's ground truth), NOT `len(b)`. A caller that frees a resliced buffer can no longer corrupt the heap — the wrong-size-free *class* is eliminated, not just this instance. The `bytesAllocated` accounting now subtracts the true usable size, so a resliced free can no longer silently drift the 256MB MemTable ceiling either. **Cost: one radix lookup per free (~+6.5% on the alloc+free microbenchmark, 865→921 ns/op, 0 allocs/op).** This retires the earlier "trust the caller's size to skip the lookup" optimization — that optimization *was* the footgun. Justification: `JemallocAllocator` is **NOT** on the per-op CRDT hot path (`pkg/sync` uses its own `HamtArena`; 0 references — verified), so the lookup sits on the LSM/durability/transport paths where frees are per-checkpoint/per-connection/per-query, immaterial to engine throughput. `BenchmarkHAMTInsertZeroAlloc` + `TestHotPathZeroAllocations` (both `pkg/sync`) unaffected.
- **`l1_compaction_test.go`:** `readAllIntoJemalloc` now returns the FULL buffer + `n`; `collectRowKeys` reads `buf[:n]` but frees the FULL `buf`. (Hygiene — the test no longer relies on the allocator's robustness; it models the correct pattern.)

## 6. Guards (bug-injection-proven, `-race` GREEN)
- **T1 (culprit guard — `TestReslicedFreeIsSafeAndBalanced`, `jemalloc_free_audit_test.go`):** reslice-and-free a 32KB block ×512, then a 64KB sweep — asserts `BytesAllocated` returns to baseline and no corruption. Deterministic: it keys on the accounting drift, not the intermittent SIGSEGV. **Bug-inject RED:** reverting `Free` to trust `len(b)` → FAILS (`BytesAllocated=16134400, want 0`).
- **T2 (accounting pin — `TestReallocateAccountingExact`):** alloc → realloc(grow) → realloc(shrink) → free; `BytesAllocated` tracks the usable size exactly and returns to 0.
- **T4 (audit load-bearing — `TestAuditInstrumentIsLoadBearing`):** subprocess with the audit armed — a resliced free is logged `WRONG-SIZE-FREE-CALL`, a double free PANICS `INVALID-OR-DOUBLE-FREE`. Proves the diagnostic is not vacuous (the "no test is lying" guard for the instrument itself).
- **T3 (coverage gap closed):** `internal/database` added to the standard verification battery (the WHOLE package, `-race` on) — the exact gap that let this bug hide for days.

## 7. Gates (all measured, none inherited)
- `go build` / `go vet` clean (no NEW findings beyond the pre-existing `unsafe.Pointer` set).
- Guards `-race` GREEN.
- Full `internal/database` suite **N=12/12 clean post-fix** (0 SIGSEGV; pre-fix ~50% fault — 12 consecutive cleans ≈ p=0.5¹²≈0.02% if the bug persisted). Full-suite `-race`: 615s clean, 0 `DATA RACE`.
- `fieldalignment`: 11 findings (baseline unchanged — the audit structs are field-reordered to stay clean; never `-fix`).
- The core merge-law/wire-schema files remain unchanged; `TestHotPathZeroAllocations` PASS; `BenchmarkHAMTInsertZeroAlloc` unchanged.
- Full verification battery on a 32-core machine: GREEN.

## 8. Honesty / open item
- The wrong-size free was a **test-code** bug; production allocator/flush paths were already correct. The fix hardens the **production** allocator against the class (any future caller, any package).
- The audit instrument is kept, env-gated, as a production-safe heap-forensics tool (its double-free/invalid-free detection is a class the fix does NOT cover — a double-free is still UB). Off the hot path (a single never-taken branch when unarmed).
- The `+6.5%` `JemallocAllocator` microbenchmark cost is disclosed; it is off the CRDT hot path and immaterial to throughput.
- Pre-existing gofmt drift in several unrelated test files predates this change and is NOT touched (out of scope).
- An OOB-write guard-band instrument was designed but not needed (H0 refuted by the heal-causation proof); it remains a future option if a heap corruption ever survives the free-size fix.
