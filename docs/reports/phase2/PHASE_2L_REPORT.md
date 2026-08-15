# PHASE 2L — ARENA-EXHAUSTION FORENSIC RESOLUTION: `BenchmarkHAMT_Set`

Sandbox: committed `main @ 8f399c5`, `GOMAXPROCS=32`, `goos=linux goarch=arm64`, `GOCACHE=/tmp/p2l-gocache`. All gate output in §3 is literal, captured in this same sandbox, run exactly once except where noted.

## §1 The fix — what changed in `hamt_test.go`, and why

`BenchmarkHAMT_Set` was structurally identical to its sibling `BenchmarkHAMTInsertZeroAlloc` (`pkg/sync/physics_test.go:156-178`) in every line **except** the reclamation pair. The bench orphaned the previous `*HAMT` wrapper each iteration (`h = h.Set(...)`), leaking ~1300 B/op of path-copied arena nodes unbounded into the 512 MiB arena. At the framework's default 1s scaling the bench OOM'd at `b.N≈500K` (`runN=0x79e13=499,219` in this sandbox's pristine reproduction — see §3 "pre-fix panic") with `panic: HamtArena: OOM - arena exhausted` at `hamt_arena.go:261`. This is a **Stage-1 leftover** that never received the reclamation fix its sibling got; the Phase 2i report documented it honestly as out-of-scope, and Phase 2l closes the last open wire.

The fix (Candidate 2 per the ruling) mirrors the sibling and the production `InsertLocal` reclamation contract (`crdt.go:399-404`): retire the previous `*HAMT` wrapper via EBR and advance the epoch each iteration so the three-epoch ring buffer physically recycles slab offsets and the arena reaches steady state. `Retire`/`AdvanceEpoch` operate on the `sync.Pool`-backed `RetiredNode` list, never on the Go heap, so they add zero allocations.

The exact 4 lines added inside the loop (at `pkg/sync/hamt_test.go:283-286`):

```
		prev := h
		h = h.Set(key, entries)
		arena.ebr.Retire(unsafe.Pointer(prev))
		arena.ebr.AdvanceEpoch()
```

plus `b.ReportAllocs()` and the surrounding reclamation-contract comment block.

The deleted arena-sizing preamble (old `hamt_test.go:248-258`):

```
	size := uintptr(b.N) * 1024 * 64
	if size < 64*1024*1024 {
		size = 64 * 1024 * 1024
	} else if size > 512*1024*1024 {
		size = 512 * 1024 * 1024
	}
	arena, err := NewHamtArena(size, NewEBRManager())
	if err != nil {
		b.Fatal(err)
	}
	defer arena.Free()
```

replaced by `arena := allocTestArenaSized(b, 2*1024*1024*1024)` (which registers `arena.Free` via `b.Cleanup` at `physics_test.go:103-108`) plus `warmEBRPool(arena)`. No second `NewHamtArena` call, no double-`Free`. Imports unchanged (`"unsafe"` already present at line 10; `allocTestArenaSized`/`warmEBRPool` are same-package helpers in `physics_test.go`).

Refused: Candidate 1 (delete the bench) — see §5 for the axis-distinction justification. Refused: Candidate 3 (cap `b.N` / bump the arena) — see §5 for the Phase 2i §5 precedent.

## §2 The tooth — `TestPhase2L_HAMTSetReclamationTooth`

The tooth lives in `pkg/sync/phase2l_staticaudit_test.go` (new, non-production `_test.go`). It has two parts:

1. **Static source-level guard.** Reads `hamt_test.go`, locates `BenchmarkHAMT_Set`, and asserts the hot loop contains BOTH `arena.ebr.Retire(unsafe.Pointer(prev))` and `arena.ebr.AdvanceEpoch()` as stand-alone lines (anchored regexes). A bench-side regression that deletes either line turns the tooth RED before any runtime panic is needed — the tooth bites the bench directly, not a parallel copy.
2. **Runtime forced-N drive.** Drives the bench's exact steady-state contract (2 GiB arena, `NewHAMT`, `warmEBRPool`, `Set` + `Retire` + `AdvanceEpoch`) at forced `N=1_000_000` — double the Phase 2i no-reclamation OOM threshold of ~500K. `testing.Benchmark` honors only a 1s wall-clock budget and on this arm64 box stops at `N≈396K`, which is **below** the 500K death threshold and therefore cannot itself prove the contract; the forced-N drive removes the wall-clock dependency. With the pair present the 2 GiB arena reaches steady state and survives 1M ops; without it the arena panics at the same `hamt_arena.go` OOM site at ~500K.

**Mutation contract (R2, verified in §3).** Commenting out / removing the `Retire`+`AdvanceEpoch` pair from `BenchmarkHAMT_Set`'s loop triggers the static guard (two `t.Errorf` lines + `t.Fatalf`) → tooth RED, FAIL. Restoring the pair → tooth GREEN, PASS.

The tooth pins the ~500K death threshold documented in `PHASE_2I_REPORT.md` Gate 5 (this sandbox measured the pristine pre-fix panic at `runN=0x79e13=499,219`).

## §3 Verification — literal output of G1–G8

No paraphrase. No truncation of the mutation-red output.

### G1 — Production byte-identity (EXPECT: empty)

```
$ git diff 8f399c5..HEAD -- \
    pkg/sync/hamt.go pkg/sync/hamt_arena.go pkg/sync/crdt.go \
    pkg/sync/crdt_apply.go pkg/sync/crdt_apply_batch.go \
    pkg/sync/crdt_reconstruct.go pkg/sync/crdt_reconstruct_skew.go
(empty)
```

Working-tree-vs-HEAD diff of the same set is also empty (verified separately). The protected production set is byte-identical to `main @ 8f399c5`.

### G2 — Bench-green on the formerly-panicking bench (EXPECT: real ns/op, no panic, no `hamt_arena.go` frame)

```
$ GOCACHE=/tmp/p2l-gocache GOMAXPROCS=32 \
    go test ./pkg/sync/ -run='^$' -bench='^BenchmarkHAMT_Set$' \
      -benchmem -benchtime=1s -count=1
goos: linux
goarch: arm64
pkg: github.com/hr18vk/supremum/pkg/sync
BenchmarkHAMT_Set-32    	  395604	      4582 ns/op	      24 B/op	       1 allocs/op
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	1.866s
```

No panic. No `hamt_arena.go` frame. The `1 allocs/op` is the `fmt.Sprintf("entity-%d", i)` string-key allocation — this bench deliberately measures string-key wire-shaped throughput (ASCII entity-IDs), distinct from the binary-key zero-alloc microscope `BenchmarkHAMTInsertZeroAlloc` (0 allocs/op, see §5). The `24 B/op` is the string buffer + path-copy header overhead on the wire-shaped path.

### G3 — Full master sweep clean (EXPECT: every `Benchmark*` completes, no OOM, sweep runs to completion)

```
$ GOCACHE=/tmp/p2l-gocache GOMAXPROCS=32 \
    go test ./pkg/sync/ -run='^$' -bench=. -benchmem -benchtime=1s -count=1
goos: linux
goarch: arm64
pkg: github.com/hr18vk/supremum/pkg/sync
BenchmarkCRDTEngine_GenerateDelta-32    	     181	   6565473 ns/op	  298355 B/op	      14 allocs/op
BenchmarkCRDTEngine_Join-32             	  327038	      5701 ns/op	     474 B/op	       6 allocs/op
BenchmarkStrataEstimator_Insert-32      	19711582	        60.80 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMT_Set-32                    	  394725	      4561 ns/op	      24 B/op	       1 allocs/op
BenchmarkHAMT_Get-32                    	 4891974	       243.7 ns/op	      23 B/op	       1 allocs/op
BenchmarkPhase2I_JoinRecover64M-32      	       0	               NaN ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_JoinParallel-32     	   17883	     74825 ns/op	    4932 B/op	      40 allocs/op
BenchmarkHAMTInsertZeroAlloc-32         	  414862	      4334 ns/op	       0 B/op	       0 allocs/op
BenchmarkFalseSharingUnpadded-32        	      31	  39520577 ns/op	     184 B/op	       2 allocs/op
BenchmarkFalseSharingPadded-32          	     217	   5495786 ns/op	      75 B/op	       2 allocs/op
BenchmarkEngineProxyUnpadded-32         	      21	  52591766 ns/op	      48 B/op	       2 allocs/op
BenchmarkEngineProxyPadded-32           	      52	  25542743 ns/op	      260 B/op	       2 allocs/op
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	19.282s
```

`grep -c "HamtArena: OOM" /tmp/p2l-g3.txt` = **0**. The sweep runs to completion; the formerly-aborting `BenchmarkHAMT_Set` now completes; the suite no longer halts at the Phase 2i death site.

### G4 — Phase 2+ integrity battery (EXPECT: every Phase 2b–2g tooth PASS + TestPhase2L PASS + TestPhase2I_CRDTEntryWidthStaticAudit PASS)

Every test in the regex PASSes. Relevant summary tail:

```
--- PASS: TestPhase2e_ApplyCRDTDeltaBatch_Biting (0.00s)
--- PASS: TestPhase2d_ApplyCRDTDeltaEvent_Biting (0.00s)
--- PASS: TestPhase2_CapnpWireFormatRoundtrip (0.00s)
--- PASS: TestPhase2_TriTemporalEventSchemaSurfaceIsFiveFields (0.00s)
--- PASS: TestPhase2_CRDTDeltaEventSchemaSurface (0.00s)
--- PASS: TestPhase2b_VersionMismatchRefusal (0.34s)
--- PASS: TestPhase2b_WireIntegrityCrossValidation (0.00s)
--- PASS: TestPhase2f_CausalDotAttribution_Biting (0.00s)
--- PASS: TestPhase2g_LamportSkewBound_Biting (0.00s)
--- PASS: TestPhase2g_LamportSnapshotCoherence (0.00s)
--- PASS: TestPhase2c_ReconstructEntry_Biting (0.00s)
--- PASS: TestPhase2I_CRDTEntryWidthStaticAudit (0.00s)
--- PASS: TestPhase2J_BenchArenaGreen (1.90s)
--- PASS: TestPhase2J_JoinParallelContentionCurve (3.70s)
--- PASS: TestPhase2L_HAMTSetReclamationTooth (6.93s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	12.881s
```

Phase 2 `TestPhase2I_CRDTEntryWidthStaticAudit` reports `unsafe.Sizeof(CRDTEntry{}) = 120 bytes` (Phase 1 form intact). All carry-forward teeth green.

### G5 — Full repo green (EXPECT: every package ok, no FAIL)

```
$ GOCACHE=/tmp/p2l-gocache go test ./... -count=1
?  	github.com/hr18vk/supremum/api/capnp/api/capnp	[no test files]
?  	github.com/hr18vk/supremum/examples/embed	[no test files]
ok  	github.com/hr18vk/supremum/internal/chaos	3.809s
ok  	github.com/hr18vk/supremum/internal/crypto	0.006s
ok  	github.com/hr18vk/supremum/internal/database	0.302s
ok  	github.com/hr18vk/supremum/internal/network	0.005s
ok  	github.com/hr18vk/supremum/internal/spatial	0.113s
ok  	github.com/hr18vk/supremum/internal/telemetry	0.020s
ok  	github.com/hr18vk/supremum/internal/temporal_store	0.257s
ok  	github.com/hr18vk/supremum/internal/transport	0.380s
ok  	github.com/hr18vk/supremum/pkg/sync	23.198s
```

Every package `ok`; zero `FAIL`. The two `?` lines are `[no test files]` packages, not failures.

### G6 — Race-clean (EXPECT: ok, zero data races)

The heavy `TestPhase2L` forced-N drive (1M ops × `fmt.Sprintf`/Set/Retire/Advance per op under `-race` instrumentation) runs >10m and exceeds the `-test.timeout=10m` ceiling before producing output. The forced-N drive is single-goroutine sequential throughput, NOT a data-race surface by construction. G6's stated intent (race the EBR retire path under concurrency) is honored by the fast concurrency/EBR/Treiber teeth plus the Phase2j parallel contention bench. Run in two scopes:

**G6a** — `TestPhase2g|Concurrent|EBR|Treiber|AtomicCounter|TestHotPath`:

```
$ GOCACHE=/tmp/p2l-gocache go test ./pkg/sync/ \
    -run='TestPhase2g|Concurrent|EBR|Treiber|AtomicCounter|TestHotPath' \
    -count=1 -race -timeout=8m
ok  	github.com/hr18vk/supremum/pkg/sync	6.093s
```

`grep -c "DATA RACE"` = 0.

**G6b** — `InsertLocal|Join|TestHotPath|TestPhase2J|TestPhase2g` (verbose, the EBR retire path + Phase2j parallel contention curve under `-race`):

```
=== RUN   TestConcurrentInsertLocalRace
--- PASS: TestConcurrentInsertLocalRace (0.51s)
=== RUN   TestConcurrentJoinRace
--- PASS: TestConcurrentJoinRace (0.08s)
=== RUN   TestPhase2g_LamportSkewBound_Biting
--- PASS: TestPhase2g_LamportSkewBound_Biting (0.00s)
=== RUN   TestPhase2g_LamportSnapshotCoherence
--- PASS: TestPhase2g_LamportSnapshotCoherence (0.00s)
=== RUN   TestCRDTJoinCommutativity
--- PASS: TestCRDTJoinCommutativity (0.33s)
=== RUN   TestCRDTJoinAssociativity
--- PASS: TestCRDTJoinAssociativity (0.44s)
=== RUN   TestCRDTJoinIdempotence
--- PASS: TestCRDTJoinIdempotence (0.17s)
=== RUN   TestCRDTJoinMonotonicGrowth
--- PASS: TestCRDTJoinMonotonicGrowth (0.21s)
=== RUN   TestCRDTEngine_InsertLocal
--- PASS: TestCRDTEngine_InsertLocal (0.00s)
=== RUN   TestCRDTEngine_Join_Idempotent
--- PASS: TestCRDTEngine_Join_Idempotent (0.00s)
=== RUN   TestCRDTEngine_Join_BackPropagationPrevention
--- PASS: TestCRDTEngine_Join_BackPropagationPrevention (0.00s)
=== RUN   TestCRDTEngine_ConcurrentInsertAndJoin
--- PASS: TestCRDTEngine_ConcurrentInsertAndJoin (0.06s)
=== RUN   TestCRDTEngine_EmptyDeltaJoin
--- PASS: TestCRDTEngine_EmptyDeltaJoin (0.00s)
=== RUN   TestPhase2J_BenchArenaGreen
--- PASS: TestPhase2J_BenchArenaGreen (3.46s)
=== RUN   TestPhase2J_JoinParallelContentionCurve
--- PASS: TestPhase2J_JoinParallelContentionCurve (5.47s)
=== RUN   TestHotPathZeroAllocations
--- SKIP: TestHotPathZeroAllocations (0.00s)
ok  	github.com/hr18vk/supremum/pkg/sync	11.826s
```

`grep -c "DATA RACE"` = 0. `TestHotPathZeroAllocations` SKIP is documented behavior (`physics_test.go:198`: `-race` instrumentation perturbs `testing.AllocsPerRun`; the `8f399c5` commit is exactly the guard that makes the zero-alloc gate skip cleanly under `-race`). No data races on the EBR retire path.

### G7 — Vet (EXPECT: empty after the documented unsafe.Pointer filter)

```
$ GOCACHE=/tmp/p2l-gocache go vet ./... 2>&1 | \
    grep -v "possible misuse of unsafe.Pointer" | grep -v "^#" | grep -v "go: warning"
(empty)
```

Honesty count: `grep -c "possible misuse of unsafe.Pointer"` = **26** (the documented 23–26 baseline; all in `pkg/sync/hamt_arena.go`, `pkg/sync/reclamation.go`, `pkg/sync/residency.go`, `pkg/sync/aba_immune_test.go`, `internal/chaos/probe.go`). Phase 2l touched none of these files; the count is unchanged by this phase.

### G8 — Tooth mutation-verified (R2)

**Pre-fix panic** (pristine `hamt_test.go @ 8f399c5`, captured before restoring the fix — literal, this sandbox):

```
$ GOCACHE=/tmp/p2l-gocache GOMAXPROCS=32 \
    go test ./pkg/sync/ -run='^$' -bench='^BenchmarkHAMT_Set$' \
      -benchmem -benchtime=1s -count=1
goos: linux
goarch: arm64
pkg: github.com/hr18vk/supremum/pkg/sync
BenchmarkHAMT_Set-32    	       0	               NaN ns/op	       0 B/op	       0 allocs/op
panic: HamtArena: OOM - arena exhausted

goroutine 66 [running]:
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).bumpAllocateNode(...)
	/workspace/sovereign-engine/pkg/sync/hamt_arena.go:261
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).AllocNode(0x568b889c8008)
	/workspace/sovereign-engine/pkg/sync/hamt_arena.go:252 +0x1bc
github.com/hr18vk/supremum/pkg/sync.NodePtr.set(0xe02bb7ffa738, 0x568b889c8008, {0x568b88c63580?, 0x20?}, 0x9f0cf92a0efa0546?, {0x568b8888ddd0?, 0x568b88d5f9f8?, 0x4adac?}, 0x85fc58?)
	/workspace/sovereign-engine/pkg/sync/hamt.go:528 +0x4b8
github.com/hr18vk/supremum/pkg/sync.NodePtr.set(0xe02bb7fff958, 0x568b889c8008, {0x568b88c63580?, 0x32c390?}, 0x568b88c16000?, {0x568b8888ddd0?, 0xd?, 0x568b8888de70?}, 0x1?)
	/workspace/sovereign-engine/pkg/sync/hamt.go:495 +0x380
github.com/hr18vk/supremum/pkg/sync.(*HAMT).Set(0xe02bb7fffba8, {0x568b88c63580, 0xd}, {0x568b8888ddd0, 0x1, 0x1})
	/workspace/sovereign-engine/pkg/sync/hamt.go:206 +0x88
github.com/hr18vk/supremum/pkg/sync.BenchmarkHAMT_Set(0x568b88a68308)
	/workspace/sovereign-engine/pkg/sync/hamt_test.go:266 +0x1dc
testing.(*B).runN(0x568b88a68308, 0x79e13)
	/home/ubuntu/go/src/testing/benchmark.go:219 +0x180
testing.(*B).launch(0x568b88a68308)
	/home/ubuntu/go/src/testing/benchmark.go:357 +0x16c
created by testing.(*B).doBench in goroutine 1
	/home/ubuntu/go/src/testing/benchmark.go:296 +0x6c
```

`runN=0x79e13=499,219` ≈ the documented ~500K threshold. Death site family: `hamt_arena.go:252/261` (`bumpAllocateNode`/`AllocNode`, the fixed-size node bump path at this N); the prompt's `allocVar@329` is the variable-size cousin that fires at a different N — same `HamtArena: OOM` panic, same root cause (unbounded orphaning).

**Mutation RED** (reclamation pair removed from `BenchmarkHAMT_Set`'s loop; `prev := h` and the two reclamation lines deleted, leaving the orphan-every-iteration shape; restored from `/tmp/p2l-hamt_test.green3.bak` after):

```
$ GOCACHE=/tmp/p2l-gocache GOMAXPROCS=32 go test ./pkg/sync/ \
    -run='^TestPhase2L_HAMTSetReclamationTooth$' -count=1 -v
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:67: PHASE2l TOOTH: BenchmarkHAMT_Set is missing 'arena.ebr.Retire(unsafe.Pointer(prev))' — the EBR reclamation contract has regressed; the bench will OOM at ~500K ops
    phase2l_staticaudit_test.go:73: PHASE2l TOOTH: BenchmarkHAMT_Set is missing 'arena.ebr.AdvanceEpoch()' — the epoch-advance contract has regressed; the three-epoch ring cannot recycle slab offsets
    phase2l_staticaudit_test.go:81: PHASE2l TOOTH: static guard FAILED — see errors above
--- FAIL: TestPhase2L_HAMTSetReclamationTooth (0.00s)
FAIL
FAIL	github.com/hr18vk/supremum/pkg/sync	0.004s
FAIL
```

Tooth bites RED: the static guard catches the bench-side regression immediately and aborts before the runtime drive can print a misleading green line.

**Restore + GREEN** (`cp /tmp/p2l-hamt_test.green3.bak pkg/sync/hamt_test.go`; `md5sum` verified `531f66d6c10f13c189139c6eea1dde75` matches the pre-mutation green file):

```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:83: PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set
    phase2l_staticaudit_test.go:93: PHASE2l TOOTH (framework 1s): N=396786, 4515 ns/op, 2 B/op, 24 allocs/op
    phase2l_staticaudit_test.go:121: PHASE2l TOOTH (forced N=1000000): arena reached steady state, no OOM
--- PASS: TestPhase2L_HAMTSetReclamationTooth (6.88s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	6.884s
```

Tooth restored GREEN: static guard finds both reclamation lines, framework smoke runs, forced-N=1M drive reaches steady state with no OOM.

## §4 Scope discipline — files changed, byte-identical protected set, out-of-scope NOT touched

**Files changed by Phase 2l:**

- `pkg/sync/hamt_test.go` — modified (the surgical fix inside `BenchmarkHAMT_Set`; `git diff --stat HEAD` = 1 file, 31 insertions, 11 deletions).
- `pkg/sync/phase2l_staticaudit_test.go` — new (non-production `_test.go`, the audit tooth).
- `PHASE_2L_REPORT.md` — new (this file).

**Byte-identical protected set (`git diff 8f399c5..HEAD` empty, working-tree-vs-HEAD empty):**

- `pkg/sync/hamt.go`
- `pkg/sync/hamt_arena.go`
- `pkg/sync/crdt.go`
- `pkg/sync/crdt_apply.go`
- `pkg/sync/crdt_apply_batch.go`
- `pkg/sync/crdt_reconstruct.go`
- `pkg/sync/crdt_reconstruct_skew.go`

No production code touched. No `physics_test.go`, `crdt_test.go`, or other bench-file edits. The two stray same-package `_test.go` files present in the working tree (`v_gate2_verify_test.go`, `v_verify_dummy_test.go`, both empty `package sync` stubs) are not mine and were moved aside (not deleted, not modified) for the gate runs; they carry no tests and do not affect any gate.

**Out-of-scope carry-forwards, named one line each (NOT touched):**

- A2/A3 closure (per-peer EWMAs + authenticated clocks) — Phase 3+.
- Origin authentication (Ed25519) — Phase 3.
- TCP/IP transport + real AWS Terraform — Phase 3 (pending Gemini Deep Research return).
- Chaos 120-byte deltagram path still bypasses the wrapper (Phase 2f Ruling 3); defense-in-depth routing is a future phase.
- The 23–26 `unsafe.Pointer` vet warnings — known baseline, not touched (G7 measured 26, unchanged).
- `internal/transport` unix-socket environment-dependent noise — did not fire in the Phase 2i/2j/2k/2l runs; not actioned.

## §5 Observations (not actioned)

- **String-key vs binary-key axis.** `BenchmarkHAMT_Set` measures ASCII entity-ID `Set` throughput (`fmt.Sprintf("entity-%d", i)`) — the shape every `Join`/`InsertLocal` actually uses on the real wire. Its `1 allocs/op` is the `fmt.Sprintf` string allocation, which is intrinsic to the wire shape. `BenchmarkHAMTInsertZeroAlloc` proves `0 allocs/op` on stack-backed binary 8-byte keys — the microscope that proves the HAMT.Set hot path itself allocates nothing on the heap. The two benches measure distinct axes; deleting `BenchmarkHAMT_Set` would leave the suite with only the binary-key microscope and no throughput number for the actual wire-shaped `Set` path. **Delete refused** on the axis-distinction justification.
- **Cap-`b.N` / arena-bump refused** with Phase 2i §5 precedent. The legacy bench already capped the arena at 512 MiB AND still panicked at `b.N≈500K` because `500K × ~1300 B ≈ 650 MiB > 512 MiB`. Raising the cap to 2 GiB without reclaiming would only push the death to ~1.5M ops — the leak is unbounded; the cap just moves the cliff. Capping `b.N` is the same shape: it silences the panic by refusing to look at the regime where the bench dies. Refused.
- **`testing.Benchmark` wall-clock scaling.** On this arm64 box `testing.Benchmark(BenchmarkHAMT_Set)` under the default 1s budget stops at `N≈396K`, below the ~500K death threshold. A naive `assert N >= 500_000` tooth would be flaky (RED on a slow box despite the fix). The tooth's static guard removes the wall-clock dependency and bites the bench-side regression deterministically; the forced-N drive proves the steady-state contract at `N=1M` regardless of box speed.
- **Phase 2j parallel contention corroborated, not actioned.** `TestPhase2J_JoinParallelContentionCurve` reports `ratio = ns/op@32 / ns/op@1 = 10.33` (threshold 1.50x), corroborating the Candidate-3 hypothesis (persistMu/persistLamport serialization under the disk-write mutex + shared-root CAS loop). Phase 2j did NOT land it; Phase 2l inherits that carry-forward and does NOT action it.

## §6 Honest limitations

Phase 2l does NOT close A2/A3. It does NOT authenticate origin. It does NOT touch transport. It does NOT add an integrity axis. It does NOT prove the 2 GiB calibration is optimal for planetary scale (Phase 3 surfaces that). The fix is behavior-preserving for the bench's **steady-state** measurement: it changes what the bench measures from "unbounded orphan leak" to "steady-state reclaimed throughput," which is what production `InsertLocal` actually does. The 1 `allocs/op` on the string-key bench is the `fmt.Sprintf` allocation intrinsic to the wire shape, NOT a zero-alloc regression on the binary-key microscope (which still reports `0 allocs/op`). The tooth's static guard is a source-string regex — it bites deletion of the reclamation pair, which is the only regression shape this phase cares about; it does not catch arbitrary behavioral drift in the bench harness (the forced-N runtime drive provides that coverage for the arena-steady-state invariant).

## §7 The verdict

(LEAVE BLANK. The verifier rules ACCEPTED / REJECTED. On ACCEPT the verifier lands the atomic `--ff-only` merge of `feat/phase2l-hamt-set-arena-steadystate` to `main` and re-bites `TestPhase2L_HAMTSetReclamationTooth` mutation in their own hands.)

------------------------------------------------------------

CARRY-FORWARDS (named, one line each, do NOT action)

- A2/A3 closure (per-peer EWMAs + authenticated clocks) — Phase 3+.
- Origin authentication (Ed25519) — Phase 3.
- TCP/IP transport + real AWS Terraform — Phase 3 (pending Gemini Deep Research return).
- Chaos 120-byte deltagram path still bypasses the wrapper (Phase 2f Ruling 3); defense-in-depth routing is a future phase.
- The 23–26 unsafe.Pointer vet warnings — known baseline, not touched.
- internal/transport unix-socket environment-dependent noise — did not fire in the Phase 2i/2j/2k/2l runs; not actioned.

------------------------------------------------------------

DONE. The Phase 2l working-tree state is at HEAD on `main` (no new commit per S5: no `git commit` to `main`, no push). Parent `8f399c5` (== `main`, untouched). The only untracked files are the cosmetic `.txt` (the original prompt paste) and the new `PHASE_2L_REPORT.md` / `pkg/sync/phase2l_staticaudit_test.go`. No `sync.test` binary was left in the tree.

The atomic merge to `main` is left to the verifier per the mandate's process (S5: no `git commit` to `main`, no push). The verifier re-bites the `TestPhase2L_HAMTSetReclamationTooth` mutation on the post-merge tree in their own hands.
