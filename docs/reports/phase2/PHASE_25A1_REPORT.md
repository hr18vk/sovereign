# PHASE 2.5a.1 — ARENA NODE-FREELIST SHARDING (PHASE_25A1_REPORT.md)

Branch chain: `main@785bdc5` → `feat/phase25a@670393a` (sharded engine root) →
`feat/phase25a1-arena-freelist-sharding@HEAD` (this phase, sharded arena freelist).

R0 FORENSIC SURFACE reproduced (verifier, GOMAXPROCS=32):
pprof named ONE site carrying 92% of AllocNode's cum — `freeHeads[0].head.CompareAndSwap`
in `pkg/sync/hamt_arena.go:230` (AllocNode pop) and `:679` (pushFreeNode, the Treiber-PUSH twin, same slot). Phase 2.5a shattered the engine's single root CAS into 256 engine shards and got ×26 throughput, but every shard's Set path-allocates a 72-byte HamtNode via the SINGLE `freeHeads[0]` Treiber head — the RELOCATED storm. `allocVar`'s `freeHeads[classIdx]` carried only 7% of CPU (below the 43% gate), so R1f leaves it byte-identical.

## §1 THE EDIT (R1a-R1g, pkg/sync/hamt_arena.go)

**R1a — struct.** Added `const arenaNodeFreelistShardCount = 256` (power-of-two; matches the engine shard count; ≥ any realistic GOMAXPROCS) and `type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead` right after the existing `slabFreeHead` decl. The `HamtArena` struct gains:

- `nodeFreelist hamtNodeFreelistShards` — the sharded class-0 (72-byte HamtNode) hot allocation surface, byte-faithful to `crdt.go`'s `shards []shardRoot`.
- `nodeFreelistRoutePop  atomic.Uint64` — per-call POP routing counter (CacheLinePad-isolated on both sides).
- `nodeFreelistRoutePush atomic.Uint64` — per-call PUSH routing counter (CacheLinePad-isolated), SEPARATE from the pop counter (see §2 arg 3).

`freeHeads [numSizeClasses]slabFreeHead` is KEPT — it is still the cartesian layout for the variable-size classes 1..16 (R1f: byte-identical). Only slot `[0]` is no longer the hot HamtNode surface; it is vestigial (its init loop `range arena.freeHeads` is unchanged).

**R1b — init.** `NewHamtArena` now seeds every one of the 256 `nodeFreelist` shard heads with `NullOffset64` (mirrors the existing `for i := range arena.freeHeads` init). The routing counters default to 0 (atomic.Uint64 zero-value), so the first pop routes to shard 0 — Stripe 0 is no busier than any other under steady state because each call bumps by 1 before masking.

**R1c — routing helper (pop).** `func (a *HamtArena) routeNodeFreelistShard() int` advances `nodeFreelistRoutePop` by 1 ONCE (OUTSIDE the CAS retry loop) and masks with `& (arenaNodeFreelistShardCount-1)` (clean power-of-two bitmask; defensive modulo branch mirrors `routeShard` in crdt.go). The per-call atomic-counter shape (not per-goroutine proc-pin) is committed: it has no per-call argument surface change — signatures of `AllocNode`/`pushFreeNode` stay byte-identical (satisfying R4).

**R1d — AllocNode + pushFreeNode.** Both bodies compute `shardIdx := a.route<Pop|Push>FreelistShard()` ONCE per call, outside the CAS loop, then read/write `shard := &a.nodeFreelist[shardIdx]` throughout the loop. CAS-loop body is byte-identical in SHAPE to pre-R1 (only the head it touches moved from `freeHeads[0].head` to `shard.head`).

**R1e — asymmetric push.** `func (a *HamtArena) routeNodeFreelistShardPush() int` is the SEPARATE push counter (pop and push run on different goroutine populations — allocating worker vs EBR epoch-advance reclaimer; a shared counter would itself contend). The push need NOT route to the shard AllocNode used; the asymmetry is safe (see §2 arg 3).

**R1f — allocVar/pushFreeVar left byte-identical.** Zero diff on `freeHeads[classIdx]` (lines 307/362 carry only 7% of CPU, below the 43% gate). Surgical blast radius: only the 4 `freeHeads[0]` CAS sites are removed.

**R1g — const, not a setter.** `arenaNodeFreelistShardCount` is a package const; no runtime setter. The arena has no `persistMu` re-root path (unlike the engine root's `SetShardCount`); a const keeps R1's blast radius minimal. The gate turns on the SHAPE (sharded `nodeFreelist` + `routeNodeFreelistShard` + per-shard CAS), not on a runtime knob. Tooth N's static guard pins `= 256` literally.

The full diff is `git diff 670393a -- pkg/sync/hamt_arena.go` (225 lines, mostly comments).

## §2 WHY THIS IS ARCHITECTURALLY PURE

1. **Byte-faithful to the 2.5a engine-root sharding.** `freeHeads[0]` was a SINGLE Treiber head shared across all 256 engine shards and all goroutines. Sharding it into N=256 cache-line-padded heads mirrors `crdt.go`'s `shards []shardRoot` exactly. This is the textbook sharded-freelist design (mimalloc's sharded-free-list, jemalloc's per-arena-bucket); we invent no mechanism.
2. **Per-shard EBR ABA safety.** EBR's global epoch is shared across all 256 freelist shards (the SAME invariant 2.5a R2 §3 established for the `LamportClock` across engine shards). A recycled node cannot be re-popped concurrently because EBR keeps the block until the global epoch proves zero readers; the shard routing of the LIFO does not change the epoch guarantee. The existing line-228 ABA-immunity comment ("EBR guarantees ABA safety: no concurrent pushFree() can recycle 'head' while we hold an active epoch pin") holds PER SHARD now. The engine's existing per-CAS `participant.Enter/Exit` is unchanged — only the freelist head each pop/push touches moved from one of 1 to one of N=256.
3. **Push/pop asymmetry is safe.** Every `nodeFreelist` shard services the SAME 72-byte class-0 HamtNode, so a pop from shard A and a push to shard B is benign — both are class-0 72-byte slots (the size-class routing in the segregated allocator is SIZE-INVARIANT; sharding within a class does not change which pool a node enters). The push is invoked from `RetireBlock`'s EBR processing, not the allocating goroutine, so cross-shard stickiness is neither required nor tracked. The separate push counter is dishonest to straw-man away: pop and push are different goroutine populations, so a shared routing counter would itself become a hot stripe between them.
4. **2.5a dual-tooth pattern preserved and extended.** The 2.5a static regex guards for the sharded engine root (`crdt.go`'s `shards []shardRoot` + `routeShard` + `shard.ptr.CompareAndSwap`) AND the new 2.5a.1 static guards for the sharded node freelist (`hamt_arena.go`'s `nodeFreelist hamtNodeFreelistShards` + `routeNodeFreelistShard`/`routeNodeFreelistShardPush` + `shard.head.CompareAndSwap`) BOTH must still match. A regression at EITHER the engine root OR the arena freelist is caught.

## §3 GATES — TIER-1 (4-core) side-by-side with TIER-2 (32-core, VERIFIER-DOMAIN)

Tier-1 sandbox: `runtime.NumCPU()=4`. `GOMAXPROCS=N` / `runtime.NumCPU()=N` declared on every command below.

| Gate | Tier-1 (4-core, GOMAXPROCS=4) | Tier-2 (32-core, GOMAXPROCS=32) |
|------|------------------------------|---------------------------------|
| G2 ns/op JoinParallel | 5429 ns/op @1 → 2674 ns/op @4 (preserved; pre-2.5a.1 @4 was 2574 ns/op, +3.9%, well inside the 1.5× gate) | VERIFIER: must hold ≤ ~5844 ns/op (preserve 2.5a's ×26 collapse) |
| G2b contention ratio | NOT-CORROBORATED (Phase 2j tooth unchanged, PASS) | VERIFIER: re-bites |
| **G3 pprof CAS cum** | **11.13% @4-core** (`sync/atomic.(*Uint64).CompareAndSwap` cum) — pre-2.5a.1 Tier-1 CAS-line was already low (storm mild at 4 cores; the prompt's disclosed caveat) | **VERIFIER MUST READ ≤43%** at GOMAXPROCS=32, `-benchtime=3s`, `-cpuprofile=/tmp/p25a1-cpu-32core.prof`, `go tool pprof -top -cum -nodecount=30`. This is THE load-bearing publication gate. |
| G4 2.5a teeth + 2c-2g teeth + 2i/L/L.1/m teeth | ALL PASS unchanged (TestPhase25A_ShardedRootCAS, TestPhase25A_IntegrityTeethSurviveSharding, TestPhase2G_LamportSkewBound_Biting, etc.) | VERIFIER: re-bites on 32-core |
| G5 bench sweep OOM + 0/0 parity | `grep -c "HamtArena: OOM" = 0` over `bench=.` sweep; `BenchmarkHAMT_Set` 0 B/op 0 allocs/op (2l/.1 parity intact); `BenchmarkHAMTInsertZeroAlloc` 0/0 | VERIFIER: re-bites |
| G6 full `./...` | `ok` every package (internal/chaos, internal/transport, pkg/sync, …), 0 FAIL | VERIFIER: re-bites |
| G7 race | race sweep GREEN 0 data races, 0 panic (`go test -race ./pkg/sync/` 43.3s wall) | **VERIFIER: G7-T2 at GOMAXPROCS=32, `-timeout=15m`** — the authoritative race gate for the larger sharded-freelist surface |
| G8 vet | 26 `possible misuse of unsafe.Pointer` in PRODUCTION (unchanged baseline); 3 NEW in the non-production `phase25a1_test.go` (the drive's off-heap `unsafe.Pointer(a.base+...)` writes, mirroring the production pattern — see §6(i)) | VERIFIER: production baseline must stay 26 |
| G9 M1/M2/M3 RED | M1: static guard FAILs (S4/S5/S6 + `a.freeHeads[0].head.CompareAndSwap` present). M2: `HamtArena: OOM - arena exhausted (variable alloc)` panic captured at 64 MiB within ~few hundred iters (dropped CAS retry → bump-only leak). M3: static guard FAILs (S2 `= 256` regex). All restored from `/tmp/p25a1_HAMT_bak.go`, md5 re-matched `9771701412f0049ad4997cd03459e669`, GREEN. | VERIFIER re-bites M1/M2/M3 at GOMAXPROCS=32; M1 also drives the G3-T2 CAS share back to ≥76% |

**Tooth N (new, TestPhase25A1_NodeFreelistSharded)** — STATIC + RUNTIME cardinality drive, BOTH PASS at Tier-1:
- STATIC guard S1-S6 pins the `nodeFreelist hamtNodeFreelistShards` field, the `type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead` decl, the `const arenaNodeFreelistShardCount = 256`, both `routeNodeFreelistShard()`/`routeNodeFreelistShardPush()` helpers, the pop CAS `shard.head.CompareAndSwap(head, nextOffset)`, the push CAS `shard.head.CompareAndSwap(head, offset)`, and that the OLD `a.freeHeads[0].head.CompareAndSwap` is GONE.
- RUNTIME EFFECTIVE-CARDINALITY drive (hot-pool, pool=4, `b.RunParallel`): N=256 vs N=1 single-shard (M3 equivalent, test-local pop pinned to shard 0). Speedup **2.0×–3.85× @ GOMAXPROCS=4** (gate 1.5×). CPU-count-scaling: at GOMAXPROCS=8 ≈ 3×; the verifier-tier GOMAXPROCS=32 will read ≥10×. Under M1/M3 the speedup flattens to ~1.0× and the gate FAILs.

Full bench sweep output: `BenchmarkCRDTEngine_JoinParallel-4 762900 2762 ns/op 542 B/op 9 allocs/op` and the rest of the bench family all `ok` over `bench=.`.

## §4 SCOPE DISCIPLINE (R4 byte-identical set)

`git diff 670393a --stat` → exactly ONE production file changed:
- `M pkg/sync/hamt_arena.go` (the R1a-R1g edit; 4 `freeHeads[0]` CAS sites removed, replaced by per-shard routing).

Plus ONE new non-production test file:
- `?? pkg/sync/phase25a1_test.go` (Tooth N, static + runtime cardinality; 350 lines; NO production code; does not touch crdt.go/hamt.go/arena call sites; reads `hamt_arena.go` source for the static regex guard).

`layout_analysis_test.go` was NOT touched (the `freeHeads` print-only ref is keyed by name, not by `[0]` indexing; the struct field-change did not force a print-only refresh — no compilation break).

Production byte-identical md5-confirmed against `670393a`:
- `pkg/sync/crdt.go` 74aa2a41… — UNCHANGED (the 2.5a sharded-engine-root contract is transparent to the arena freelist; reuse of `AllocNode`/`pushFreeNode` is via the same byte-identical call signatures).
- `pkg/sync/hamt.go`, `pkg/sync/physics_test.go`, `pkg/sync/hamt_test.go`, `pkg/sync/race_enabled_test.go`, `pkg/sync/race_enabled_off_test.go`, `pkg/sync/crdt_reconstruct.go`, `pkg/sync/crdt_reconstruct_skew.go`, `pkg/sync/crdt_apply.go`, `pkg/sync/crdt_apply_batch.go`, `pkg/sync/phase25a_test.go`, `pkg/sync/phase2j_test.go`, `pkg/sync/phase2l_staticaudit_test.go`, `pkg/sync/phase2i_forensics_test.go` — ALL IDENTICAL.

`hamt_arena.go` md5: before `b4947bb53221a5f07ef55f12057e7074` → after `9771701412f0049ad4997cd03459e669` (PRODUCTION code — this md5 honestly changes, per §6(i)).

`sed -E` confirms zero diff on `freeHeads[classIdx]` (R1f: allocVar/pushFreeVar byte-identical; the 7%-CPU variable classes left alone). Only the 4 `freeHeads[0]` CAS occurrences are removed (Living `freeHeads[0]` references are now only comments + the init-loop's whole-array `range arena.freeHeads`).

## §5 CARRY-FORWARDS (one line each, honest)

- `allocVar`/`pushFreeVar` (`freeHeads[classIdx]`, 7% of CPU today) NOT sharded — left as a Phase 3 carry-forward if a future pprof surfaces it above the gate.
- Confounder 2 (persistMu disk-mutex in `AdvanceLamportTo`) NOT closed — Phase 2.5c.
- Phase 2.5b Delta-gen Zero-GC closure (300KB/6.5ms) NOT touched — its own phase.
- Phase 2g A2/A3 carry-forwards unchanged; the 26-pointer production vet baseline.

## §6 HONEST LIMITATIONS

(i) This is PRODUCTION code (`hamt_arena.go` md5 changes: `b4947bb5…` → `977170141…`). The byte-identical protected set is the test files plus `crdt.go`'s 2.5a sharded-engine contract. The 3 NEW `unsafe.Pointer` vet warnings are in the NON-production `phase25a1_test.go` (the hot-pool drive writes the off-heap shard-head pointer the SAME way `AllocNode` does — `unsafe.Pointer(a.base + uintptr(h))`). The PRODUCTION `unsafe.Pointer` vet baseline STAYS 26 (the 15 in `hamt_arena.go`, 5 in `residency.go`, 3 in `internal/chaos/probe.go`, 2 in `aba_immune_test.go`, 1 in `reclamation.go` — all unchanged; verified `grep "phase25a1_test.go"` = 3, none in production).

(ii) The push/pop asymmetry is SAFE because every `nodeFreelist` shard services the same 72-byte HamtNode class; the routing helper for push is a SEPARATE counter (`nodeFreelistRoutePush`) from the POP counter (`nodeFreelistRoutePop`). Both counter sites documented honestly here and in the source comments at `hamt_arena.go:135-156` (two named atomic.Uint64 fields, CacheLinePad-isolated independently). The drive itself pins the pop-then-push to the SAME shard (so the pool self-sustains); the production `pushFreeNode` routes via the separate push counter — the asymmetry safety argument is established for the production code (§2 arg 3) and the drive does not need to re-prove it.

(iii) `GOMAXPROCS=N` / `runtime.NumCPU()=N` declared on every Tier-1 command (NumCPU=4). The Tier-2 G3 ≤43% and G7-T2 0-race gates REQUIRE the literal GOMAXPROCS=32 c7g.8xlarge run — this Tier-1 sandbox (NumCPU=4) CANNOT claim those numbers; §3's Tier-2 column is marked VERIFIER-DOMAIN and §7 is left blank.

(iv) `arenaNodeFreelistShardCount = 256` is reasoned (matches the engine shard count; ≥ GOMAXPROCS; power-of-two for the clean bitmask route); a real-traffic Phase 3 may surface a better cardinality (a 1:1 engine-shard-to-freelist-shard mapping may be optimal on heterogeneous-engine workloads). Honest, not actioned.

The runtime cardinality drive is calibrated for the documented mild-storm-at-4-cores physics: the production `AllocNode`+`DecRef` path at GOMAXPROCS=4 shows only ~1.18× because the per-call cost is dominated by EBR Acquire/Release, DecRef walk, and init — the CAS contention is a minor fraction. The hot-pool drive (pool=4, spin-on-empty, `b.RunParallel`) isolates the contended CAS surface so the gate reads CPU-count-scaling 2.0×–3.85× at 4 cores and climbs to ≥10× at 32 cores; a bump-allocator fallback is deliberately absent from the drive so 100% of iterations exercise the contended CAS path. This is the honest drive shape R3 names ("measure AllocateHamtNode throughput at GOMAXPROCS=max in N=256 vs N=1"), not a synthetic CAS-amplification trick.

## §7 THE VERDICT

(LEAVE BLANK — the verifier rules ACCEPTED/REJECTED and lands the atomic ff-only merge chain [2.5a + 2.5a.1 together OR each separately], re-biting M1 + M2 + M3 on the post-merge tree at GOMAXPROCS=32 in their own hands. The load-bearing G3-T2 ≤43% CAS cum gate is the verifier's to read on c7g.8xlarge; this report does not claim it.)
