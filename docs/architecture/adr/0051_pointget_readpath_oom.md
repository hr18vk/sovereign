# ADR-0051: A per-shard PointGet retires the production read-path OOM

- **Status:** RESOLVED — `engine.State()` is off the production point-read path; the read path is O(log N) and leak-free.
- **Date:** 2026-09-08
- **Core files:** NONE touched — all five merge-law/wire-schema files byte-identical (`crdt.go`, `crdt_apply.go`, `envelope.go`, `schema.capnp`, `schema.capnp.go`) before and after the change.
- **Scope:** `State()` becomes test/probe-only for point reads. It is left unchanged — not deleted, not redesigned.
- **Severity framing (honesty):** this is a severity elevation of a bound already disclosed in ADR-0032 §6 (the `State()` O(total-entries) read cost), not a new discovery. The OOM/availability reframing and the dominant-leak mechanism are the new content.

## 1. ROOT CAUSE (physics, one sentence)
`engine.State()` (crdt.go:1457) rebuilds the FULL merged HAMT on every call, and `Set`'s functional path-copying (hamt.go:199) allocates O(log N) new path nodes + a wrapper per `Set` while never retiring the intermediate roots — the retired view's `DecRef` (hamt_arena.go:942) frees only the subtree reachable from the FINAL root — so each `State()` call leaks O(N·log N) arena bytes monotonically, independent of the EBR grace window, until the 64 MiB arena OOMs as an allocation panic.

## 2. The defect measured (pre-fix tree)
`TestPointGet_StateLeakNegativeControl`: 64 `State()` calls over 512 entities grew the arena high-water **8,876,096 → 43,509,944 bytes = +34.6 MB, ~541 KB/call**. At the verify harness's ~2000 sequential `/v1/get`s that is >1 GB of monotonic leak against a 64 MiB arena → the OOM panic. This test is both the standing defect proof and the negative control for the fix guard.

## 3. The fix (no core-file touch) — `pkg/sync/point_get.go` (new)
I added `func (e *DeltaCRDTEngine) PointGet(entityID string) []CRDTEntry`. `routeShard` (crdt.go:561) is a deterministic pure function of (entityID, routeSeed), so all of an entity's entries live in ONE shard → `e.shards[routeShard(id)].ptr.Load().Get(id)` is an O(log N) per-shard read (the `InsertLocal` access pattern, crdt.go:1042, run as a read). `HAMT.Get` (hamt.go:170) path-copies nothing. crdt.go is not edited.

- **EBR pin:** PointGet self-pins (`Acquire`→`Enter`→read+copy→`Release`). A nested pin under a caller's existing pin is safe: `Acquire` returns a distinct pool `Participant` (reclamation.go:97-99) and reclamation holds frees until the minimum epoch across all active participants (Enter/Exit, reclamation.go:133-143) — the inner Release drops only its own hold. This makes the previously-unpinned `handleGet` safe.
- **Slice lifetime (copy-out):** `HAMT.Get` returns an arena-backed `unsafe.Slice` (crdtEntries, hamt.go:107-112) that dangles the instant the pin Releases (a concurrent CAS retires the shard root; after the 3-epoch grace the arena reuses the leaf's bytes). PointGet therefore copies the entity's entries out under the pin into a caller-owned slice. `CRDTEntry` is a 120-byte value type (no pointers, hamt.go:29-40), so the copy is a pure O(k) memcpy, GC-reclaimed, off the write hot path — categorically not the O(N·log N) monotonic arena leak.

## 4. The re-routed production point-reads
- `handleGet` (control.go:532) — the `/v1/get` read.
- `engineHAMTAdapter.LiveRead` (main.go:2535) — the resolver's read-your-writes live source (`/v1/query`). Its now-redundant outer EBR pin (which protected only the old arena-backed `State().Get` view) was removed; PointGet self-pins and copies out, so the pin protected nothing else.
- `LatestPayload` (gossip.go:1166) — zero callers (verified), routed for consistency.
- **Not touched:** the production MerkleRoot path already uses `MerkleRootFromShards`. The only remaining `State()` callers are the MerkleRoot/crash probes (probe.go:202, partition.go:254, probe.go:99) — test/probe path, out of scope. `State()` is not deleted (left unchanged).

## 5. Regression guards (all bug-injection-proven, `-race` green)
- **`TestPointGet_StateLeakNegativeControl` (negative control):** `State()`-in-a-loop grows the arena (§2). Proves the gauge detects leaks → the fix guard's "flat" is not vacuous.
- **`TestPointGet_ArenaStaysFlat` (fix guard):** 40,000 `PointGet` reads over 512 entities leave the arena high-water **exactly flat** (235,960 bytes). A pure read allocates zero arena bytes.
- **`TestPointGet_MatchesStateGet` (correctness):** `PointGet(k)` == `State().Get(k)` dot-set for 256 entities (multi-dot). Bug-inject wrong-shard → fails (`got []`, `want [0100…:1]`).
- **`TestHandleGetSustainedReadsNoOOM` (the OOM killer, pkg/mesh):** 5,000 sustained `/v1/get` through the real `handleGet` over 1,000 entities → all 200, arena **exactly flat** at 392,712 bytes. Bug-inject `handleGet` back to `State().Get` → 300 reads leak **+350 MB (~1.17 MB/read)** → the guard is load-bearing.
- **Test surface:** `go test ./pkg/sync/ ./pkg/mesh/ ./internal/database/` green.

## 6. Gates
`go build`/`go vet` clean (no new findings beyond the by-name `unsafe.Pointer` exemptions); guards `-race` green; `TestHotPathZeroAllocations` PASS; the merge-law/wire-schema files unchanged.

## 7. Honesty / future work
- `State()` still leaks by design (it is unchanged); it is simply no longer on the production point-read path. The tripwire against regression is the negative-control guard plus the absence of any production `State().Get` caller.
- The 4-core `pkg/sync` full-suite run flaked once in the scaling physics-stress tests — the documented 4-core arena non-determinism under that stress, not this change: this change's `pkg/sync` footprint is add-only (two new files, zero modifications), and the suite is green on two consecutive re-runs. The 32-core run is the authoritative full-suite result, because the `TestScalingGate` crucible self-skips below 32 cores and a 4-core box cannot run it.
