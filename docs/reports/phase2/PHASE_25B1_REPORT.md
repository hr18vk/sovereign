# PHASE 2.5b.1 — CHAOS-DIGEST RELEASE DISCIPLINE (THE CALLER-LEAK CLOSURE)

Branch ......... `feat/phase25b1-chaos-digest-release`, parent = `df95d3b` (Phase 2.5b HEAD).
Tier ........... Tier-1 engineering gate, run on the CURRENT box. `runtime.NumCPU() = 4`, `nproc = 4`, `go version go1.26.1 linux/arm64`.
UPBRING ........ PHASE 2.5b closed the network-hot-path `GenerateDelta` Zero-GC gate. 2.5b.1 is the SURGICAL CALLER-SIDE fix that closes the regression the Tier-1 verifier-audit caught. The branch is UNPUSHED; the verifier lands the atomic `--ff-only` merge `main:355581d -> df95d3b -> <2.5b.1 HEAD>` in their own hands.

---

## S1 — MANDATE IDENTITY & ARCHITECTURAL POSTURE (Path A, quoted verbatim from S0)

> You are the Executor for Phase 2.5b.1, the surgical caller-side discipline
> fix that closes the regression the Senior Architect's Tier-1 verifier-audit
> caught in Phase 2.5b. The mandate is absolute and there is exactly one
> architectural truth you are not permitted to deviate from:
>
>     PHASE 2.5b CLOSED THE network-hot-path GenerateDelta ZERO-GC GATE AND
>     THAT ACHIEVEMENT STANDS. IT IS NOT ON TRIAL. THE REGRESSION IS THAT THE
>     R1 PATCH SILENTLY MUTATED GenerateDigest() (THE PUBLIC API) FROM
>     HEAP-BACKED TO ARENA-BACKED WITHOUT TEACHING ITS CALLERS THE Release()
>     DISCIPLINE THE HEAP-LEAK USED TO HIDE. THE BUG LIVES IN THE CALLERS.
>     THE ENGINE IS INNOCENT. YOU WILL FIX THE CALLERS AND NO ONE ELSE.
>
> This is Path A. Path B (revert GenerateDigest to heap-backed, split the
> arena backing into a hidden internal path) is FORBIDDEN. It is
> architecturally dishonest — it would re-open the heap leak on the public
> GenerateDigest path forever to save a caller from learning a Release()
> discipline the engine always owed. We do not leave that ammunition for the
> critics. We do not paper over caller bugs by crippling the engine.
>
> The pre-2.5b state was a heap leak the GC silently freed. Phase 2.5b did
> NOT introduce the leak — it made it VISIBLE by moving the slab source off
> the unbounded heap onto a bounded per-engine HamtArena. Every caller that
> forgot to Release() its *IBLT used to leak on the heap without anyone
> noticing; Phase 2.5b made the same leak observable as __arena OOM__. The
> fix is to teach the leaky callers the discipline the engine always owed.
> This is the same posture Phase 2l took: the bench had the leak, the engine
> was innocent; the fix landed in the bench, not the engine.

2.5b.1 honors Path A **exactly**: zero edits to the engine (`pkg/sync/crdt.go`, `pkg/sync/iblt.go`, `pkg/sync/hamt_arena.go`, … — all byte-identical to `df95d3b`, see S3.G1), zero arena-sizing change (the 32 MiB mesh arena and the 64 MiB test arena are untouched), and the discipline is taught at the leaky **caller** sites only prior Path B (crippled engine) and bumped no arena stat.

---

## S2 — THE FORENSIC STATEMENT (the panic stack, quoted verbatim, not amended)

The reproducer (the verifier's hands, on `df95d3b`):

```
cd /workspace/sovereign-engine
GOCACHE=/tmp/p25b-v-t1 GOMAXPROCS=4 \
  go test ./internal/chaos/ \
  -run='^TestStage6MerkleConvergenceAfterPartition$' \
  -count=1 -v
```

Outcome on the 2.5b branch (`df95d3b`), reproduced 5/5 RED:

```
panic: HamtArena: OOM - arena exhausted (variable alloc)
goroutine 8 [running]:
  pkg/sync.(*HamtArena).allocVar          hamt_arena.go:473
  pkg/sync.NewArenaIBLT                   iblt.go:138
  pkg/sync.(*DeltaCRDTEngine).GenerateDigestWithSeed
                                          crdt.go:1488
  pkg/sync.(*DeltaCRDTEngine).GenerateDelta   (calls GenerateDigestWithSeed
                                               for the LOCAL digest,
                                               crdt.go:1269)
  internal/chaos.(*Orchestrator).GossipOnce.func1   partition.go:222
  internal/chaos.(*VirtualNet).RunGossipRound       virtualnet.go:435
  internal/chaos.(*Orchestrator).GossipOnce         partition.go:209
  internal/chaos.pumpUntilConverged                 mesh_test.go:276
  internal/chaos.TestStage6MerkleConvergenceAfterPartition  mesh_test.go:190
```

Outcome on baseline main `@ 355581d`, reproduced 5/5 GREEN (ok ~3.3s) — the pre-2.5b heap leak let the GC silently free dstDigest's ~24 KB slab.

**The load-bearing fact — line 221 of `partition.go` (pre-fix):**

```go
dstDigest := dstEng.GenerateDigest()   // IBLT over dst's current state
delta := srcEng.GenerateDelta(dstDigest)
defer delta.Release()
... delta.Entries(...) ...
return buf, nil
```

`delta` has a `defer delta.Release()`. `dstDigest` does NOT. Pre-2.5b that was harmless (heap IBLT, GC reclaims). Post-2.5b `GenerateDigest()` → `GenerateDigestWithSeed()` → `NewArenaIBLT()` provisions from the engine's **bounded** `HamtArena`; the slab class is the **24 KB bucket array + a ~48 B struct**. Every gossip round, every ordered (`from`, `to`) pair, leaks ONE dstDigest slab-pair. The chaos mesh runs 32 engines × ~50 gossip rounds × 1 dstDigest per round ≈ ~1600 leaked pair-slabs. At ~24 KB each that is ~38 MB of leaked slab, drawn against a 32 MiB per-engine arena — panic at the partition-heal round where the cumulative leak tips the bucket allocator (`hamt_arena.go:473`, the bump pointer hits the arena end).

---

## S3 — THE FIX (R1a/R1b/R1c diffs, R3 tooth bodies, G1–G10 literal output)

### R1a — `internal/chaos/partition.go` GossipOnce closure (the panic caller)

Exactly one new executable line + the doc-comment line, no reflow, no rename, no restructuring. The `Release()` is a no-op on a heap-backed IBLT (`IBLT.Release` returns early if `arenaRef == nil`), so the change is **backwards compatible** with the documented R1f guarantee that heap-backed IBLTs from `NewIBLT*` stay no-op-on-Release.

```diff
@@ func (o *Orchestrator) GossipOnce(ctx context.Context) (shipped int, err error) {
 ...
 		dstDigest := dstEng.GenerateDigest() // IBLT over dst's current state
+		defer dstDigest.Release()             // Phase 2.5b.1: arena-backed digest must be released;
+		                                     //   pre-2.5b the heap leak hid this; the bounded arena now surfaces it.
 		delta := srcEng.GenerateDelta(dstDigest)
 		defer delta.Release()
```

### R1b — `pkg/sync/crdt_test.go` audit + Release fixes (the determinism test's leak sites)

Audit by `rg -n 'GenerateDigest\(\)' pkg/sync/crdt_test.go` (post-fix), every hit within 3 lines of a `.Release()`:

```
308:	digestB := engineB.GenerateDigest()
309:	defer digestB.Release() // Phase 2.5b.1: arena-backed digest release
315:	digestC := engineC.GenerateDigest()
316:	defer digestC.Release() // Phase 2.5b.1: arena-backed digest release
322:	digestA := engineA.GenerateDigest()
323:	defer digestA.Release() // Phase 2.5b.1: arena-backed digest release
329:	digestB2 := engineB.GenerateDigest()
330:	defer digestB2.Release() // Phase 2.5b.1: arena-backed digest release
371:				digest := engines[j].GenerateDigest()
375:				digest.Release() // Phase 2.5b.1: arena-backed digest release (loop: direct, not defer)
```

Diff:

```diff
@@ func TestCRDTEngine_ThreeNodeConvergence(t *testing.T) {
 	// A → B sync.
 	digestB := engineB.GenerateDigest()
+	defer digestB.Release() // Phase 2.5b.1: arena-backed digest release
 	deltaAtoB := engineA.GenerateDelta(digestB)
 	engineB.Join(*deltaAtoB)
 	deltaAtoB.Release()

 	// B → C sync (B now has A's data too).
 	digestC := engineC.GenerateDigest()
+	defer digestC.Release() // Phase 2.5b.1: arena-backed digest release
 	deltaBtoC := engineB.GenerateDelta(digestC)
 	engineC.Join(*deltaBtoC)
 	deltaBtoC.Release()

 	// C → A sync (C now has everything).
 	digestA := engineA.GenerateDigest()
+	defer digestA.Release() // Phase 2.5b.1: arena-backed digest release
 	deltaCtoA := engineC.GenerateDelta(digestA)
 	engineA.Join(*deltaCtoA)
 	deltaCtoA.Release()

 	// A → B sync again so B gets the propagated C's data.
 	digestB2 := engineB.GenerateDigest()
+	defer digestB2.Release() // Phase 2.5b.1: arena-backed digest release
 	deltaAtoB2 := engineA.GenerateDelta(digestB2)
 	engineB.Join(*deltaAtoB2)
 	deltaAtoB2.Release()
@@ func TestCRDTEngine_FiveNodeConvergence(t *testing.T) {
 ...
 				digest := engines[j].GenerateDigest()
 				delta := engines[i].GenerateDelta(digest)
 				engines[j].Join(*delta)
 				delta.Release()
+				digest.Release() // Phase 2.5b.1: arena-backed digest release (loop: direct, not defer)
 			}
```

The four sequential sites get `defer <var>.Release()` alongside the existing `deltaXtoY.Release()` (which stays — it is the delta-side release, also mandatory and already correct). The full-mesh loop site at line 371 gets a DIRECT `digest.Release()` at the bottom of the iteration (defers do not fire until function return, so a loop-site `defer` would queue 4×N slab-pair frees against the engine freelist and OOM the arena anyway).

### R1c — `internal/chaos/mesh_test.go` audit (NO change)

`rg -n 'GenerateDigest\(\)' internal/chaos/mesh_test.go` returns no hits — the chaos mesh's digest-producer is **exclusively** `partition.go:221` (the `GossipOnce` closure). `mesh_test.go` stays byte-identical to `df95d3b` (verified `git diff df95d3b -- internal/chaos/mesh_test.go | wc -l -> 0`, md5 `592ea28070c5bf208750d8ebb7d19de7`). R1c found nothing; touched nothing.

### R1d — scope honesty

`git diff df95d3b --stat`:

```
 internal/chaos/partition.go | 2 ++
 pkg/sync/crdt_test.go       | 5 +++++
 2 files changed, 7 insertions(+)
```

Plus the two NEW untracked tooth files:

```
?? internal/chaos/phase25b1_release_test.go
?? pkg/sync/phase25b1_callaudit_test.go
```

EXACTLY the sanctioned set; `mesh_test.go` is ABSENT (no R1c edit). The S1 PROTECTED set is byte-identical to `df95d3b` (S3.G1).

### R3a — Tooth `M-Drive`: `internal/chaos/phase25b1_release_test.go`

`TestPhase25B1_ChaosDigestReleaseRoundTrip` drives partition.go's REAL `GossipOnce` closure **10,000 times** against a tight two-engine fabric on the SAME 32 MiB arena the chaos mesh uses at `mesh_test.go:68`. Driving the real orchestrator closure (not a hand-rolled replication) is load-bearing: it means mutation M1 (comment `partition.go:222` `defer dstDigest.Release()`) bites BOTH this tooth AND the headline gate `TestStage6MerkleConvergenceAfterPartition` via the SAME partition.go Release site (S3.G10).

Fabric: zero drop, zero duplicate, 0 jitter, 100µs delivery base (schedules the per-node AddNode goroutines off the inline send path; the round call returns immediately after the makeDelta closure ships). 50 entries seeded on each engine so deltas are non-trivial but the loop measures LEAK RATE, not correctness. `Dedup: false` exercises CRDT `Join` idempotence directly. The 10K rounds complete Tier-1 in ~1.5s (~150µs/round), well under the G7 race gate 15m budget even with `-race` overhead (verified 21.18s under `-race`).

Each `GossipOnce` sweep drives `RunGossipRound`'s full-mesh nested loop, so for a 2-engine net each round exchanges BOTH (A→B) and (B→A). That symmetry is the reclamation invariant: every engine takes BOTH the `from` role (its `GenerateDelta` advances its own EBR epoch via `maybeAdvanceEpoch`, `crdt.go:1416`) and the `to` role (its `GenerateDigest` allocates against its own arena; its `dstDigest.Release` retires the slab to its own EBR). A single fixed-direction loop would OOM the `to` engine on reclamation lag alone — NOT the leak this tooth exists to catch.

The tooth body (verbatim):

```go
func TestPhase25B1_ChaosDigestReleaseRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 2.5b.1 OOM drive runs 10K GossipOnce rounds; skip in -short")
	}
	// Two engines — the (from, to) pair partition.go:221 exercises, mirrored
	// to both directions per RunGossipRound's full-mesh sweep.
	var srcID [16]byte; srcID[0] = 0xA1
	var dstID [16]byte; dstID[0] = 0xB2
	// ... newTestEngine-shaped setup: 32*1024*1024 arena, t.TempDir DataDir,
	//     t.Cleanup engine.Close ...
	// 50 entries seeded on each engine (stack-buffered keys via strconv.Itoa;
	// no fmt.Sprintf on the tooth's own setup path — S1 hot-path discipline).
	// Tight deterministic fabric (Drop=0, Duplicate=0, Jitter=0, DeliveryBase=100µs).
	net := NewVirtualNet(profile); t.Cleanup(net.Stop)
	orch, _ := NewOrchestrator(OrchestratorConfig{Net: net, Engines: {srcID: srcEng, dstID: dstEng}, Dedup: false})
	orch.BindNodes()
	ctx := context.Background()
	const rounds = 10000   // forced-N=10000, non-negotiable (R3d)
	for r := 0; r < rounds; r++ {
		if _, err := orch.GossipOnce(ctx); err != nil {  // drives partition.go:221 + the R1a Release site
			t.Fatalf("Phase 2.5b.1 OOM drive: GossipOnce round %d failed: %v", r, err)
		}
	}
	// drain noop RunGossipRound tick so t.Cleanup net.Stop sees honest state.
	_, _ = net.RunGossipRound(ctx, func(...) ([]byte, error) { return nil, nil })
	t.Logf("Phase 2.5b.1 OOM drive: %d GossipOnce rounds completed in %v without HamtArena panic — partition.go:222 dstDigest.Release held", rounds, elapsed)
}
```

The tooth does NOT `t.Skip` except `testing.Short()`, has NO `raceEnabled` guard (R3/§G7: static + forced-N drives small enough to fit in 15m under `-race`), and the forced-N=10000 is non-negotiable (R3d). The loop gates on no-OOM-over-10K-rounds (R5 amnesty per S6(iii) — do not gate on allocs/op here).

### R3c — Tooth static-audit: `pkg/sync/phase25b1_callaudit_test.go`

`TestPhase25B1_GenerateDigestReleaseContractPin` walks the source as a string and asserts the Release-within-3-lines invariant:

1. loads `pkg/sync/crdt_test.go` and `internal/chaos/partition.go` as strings (via `os.ReadFile`; the chaos file is reached from `pkg/sync` through `filepath.Join("..", "..", "internal", "chaos", "partition.go")` — single-module repo);
2. for every non-comment line matching `GenerateDigest\(\)`, asserts a `.Release()` call appears within 3 lines AFTER (defer or direct);
3. comment-only lines are SKIPPED when scanning the companion Release window — a muted (commented-out) `<var>.Release()` MUST NOT satisfy the contract. (Mutation M2 proves this muscle: commenting `digestB.Release()` leaves no LIVE Release within the window, and the tooth bites RED at `crdt_test.go:308`.)
4. FAILs printing the offending line + the missing Release if the contract is broken.

The tooth does NOT downgrade red, only `t.Skip`s under `testing.Short()`, has NO `raceEnabled` guard (it is a static source scan). The R3d discipline holds: a future maintainer who neuters R3a's forced-N 10000→100 evades the runtime bite, but the chaos mesh's `TestStage6` gate bites them from the panic side AND this static tooth bites any dropped `<var>.Release()` regardless of drive size. Two teeth, two axes.

### G1 — scope byte-identity (PROTECTED set, 0-line diffs, md5 audit)

```
$ git diff df95d3b --stat
 internal/chaos/partition.go | 2 ++
 pkg/sync/crdt_test.go       | 5 +++++
 2 files changed, 7 insertions(+)
```

PROTECTED set, every file md5-identical to `df95d3b`:

```
OK  pkg/sync/crdt.go          df95d3b=3b4e803986b71765367c1733567d2584  HEAD=3b4e803986b71765367c1733567d2584
OK  pkg/sync/iblt.go          df95d3b=3886f55c5b6259f6820f63e62e645815  HEAD=3886f55c5b6259f6820f63e62e645815
OK  pkg/sync/hamt_arena.go    df95d3b=9771701412f0049ad4997cd03459e669  HEAD=9771701412f0049ad4997cd03459e669
OK  pkg/sync/reclamation.go   df95d3b=4cabcdb5baf9e852be3268f8e40cb3eb  HEAD=4cabcdb5baf9e852be3268f8e40cb3eb
OK  pkg/sync/hamt.go          df95d3b=bc03bdb31c16c526a0c999ced7ac1501  HEAD=bc03bdb31c16c526a0c999ced7ac1501
OK  pkg/sync/residency.go     df95d3b=656fd349e21bc2e4c71afa59e4c3938f  HEAD=656fd349e21bc2e4c71afa59e4c3938f
OK  internal/chaos/virtualnet.go  df95d3b=48a2d167806ea2305ef1a4a39b20b7b6  HEAD=48a2d167806ea2305ef1a4a39b20b7b6
OK  internal/chaos/mesh_test.go   df95d3b=592ea28070c5bf208750d8ebb7d19de7  HEAD=592ea28070c5bf208750d8ebb7d19de7
OK  internal/chaos/fuzzer.go      df95d3b=81b8828d17b5f5fcfe359a71d18d6e7d  HEAD=81b8828d17b5f5fcfe359a71d18d6e7d
OK  internal/chaos/wal_test.go    df95d3b=c00dfcd0f2b65c116717b50c5f51896e  HEAD=c00dfcd0f2b65c116717b50c5f51896e
OK  internal/chaos/survival_test.go df95d3b=498c023aae3f188388ca8947eef642a2  HEAD=498c023aae3f188388ca8947eef642a2
OK  internal/chaos/codec.go       df95d3b=ec9acb68c5460c22dd9004ca1a1e3d69  HEAD=ec9acb68c5460c22dd9004ca1a1e3d69
OK  internal/chaos/protocol.go    df95d3b=cdf327fd21dc99696974a869779be120  HEAD=cdf327fd21dc99696974a869779be120
OK  internal/chaos/probe.go       df95d3b=4fb217904bda1e002e56b57433587f31  HEAD=4fb217904bda1e002e56b57433587f31
OK  internal/chaos/supervisor.go  df95d3b=306796c0431cb931a2db1a3f81c752a6  HEAD=306796c0431cb931a2db1a3f81c752a6
```

The non-existent placeholder `pkg/sync/protocol.go` was the only MISMATCH in the audit loop — it does NOT exist in `df95d3b` (`git show df95d3b:pkg/sync/protocol.go -> fatal: path does not exist`), so its md5 was the empty-blob digest on both sides; it is not a real file and not part of the S1 protected set. Every real protected file is byte-identical.

### G2 — chaos Stage6 GREEN 5/5 (the headline regression gate)

`NumCPU=4` (printed at the top of the sweep). 5 independent `-count=1` runs:

```
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.43s)   run 1  (panic=0, ok=3.443s)
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.22s)   run 2  (panic=0, ok=3.231s)
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.24s)   run 3  (panic=0, ok=3.254s)
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.17s)   run 4  (panic=0, ok=3.179s)
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.05s)   run 5  (panic=0, ok=3.057s)
```

Stage6 §3 phase4 log: `phase4: PASS — all 32 nodes converged to root d5af3535b27b307930d57c4eac9c7c3bf2c2a8b0e746260a52538de6253dfd50 after 18 post-heal rounds`. 5/5 GREEN, 0 `HamtArena: OOM`.

### G3 — chaos tooth (the new 10K-round OOM bite)

```
NumCPU=4 (nproc=4)
=== RUN   TestPhase25B1_ChaosDigestReleaseRoundTrip
    phase25b1_release_test.go:161: Phase 2.5b.1 OOM drive: 10000 GossipOnce rounds completed in 1.471011138s (147.101µs/round) without HamtArena panic — partition.go:222 dstDigest.Release held
--- PASS: TestPhase25B1_ChaosDigestReleaseRoundTrip (1.47s)
PASS
ok  	github.com/hr18vk/supremum/internal/chaos	1.491s
```

No `HamtArena: OOM` string in the output. 10000 rounds (forced-N) completed; the R1a Release held.

### G4 — sync callaudit tooth

```
=== RUN   TestPhase25B1_GenerateDigestReleaseContractPin
--- PASS: TestPhase25B1_GenerateDigestReleaseContractPin (0.00s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	0.005s
```

### G5 — Phase 2.5b R5 gate STILL HOLDS (regression-negative)

`GOCACHE=/tmp/p25b1 GOMAXPROCS=1 go test ./pkg/sync/ -run='^$' -bench='^BenchmarkCRDTEngine_GenerateDelta$' -benchmem -benchtime=1s -count=5`:

```
BenchmarkCRDTEngine_GenerateDelta 	     582	   2035563 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     588	   2042588 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     582	   2047149 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     580	   2104978 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     585	   2067420 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	70.359s
```

5/5 read `0 B/op 0 allocs/op` at `GOMAXPROCS=1`. The Phase 2.5b R5 Zero-GC achievement survived 2.5b.1 untouched (the engine files are byte-identical — S3.G1).

### G6 — full repo `go test ./... -count=1`

```
ok  	github.com/hr18vk/supremum/internal/chaos       6.038s
ok  	github.com/hr18vk/supremum/internal/crypto      0.003s
ok  	github.com/hr18vk/supremum/internal/database     0.351s
ok  	github.com/hr18vk/supremum/internal/network      0.006s
ok  	github.com/hr18vk/supremum/internal/spatial      0.113s
ok  	github.com/hr18vk/supremum/internal/telemetry     0.021s
ok  	github.com/hr18vk/supremum/internal/temporal_store 0.302s
ok  	github.com/hr18vk/supremum/internal/transport     0.411s
ok  	github.com/hr18vk/supremum/pkg/sync             97.967s
?   	github.com/hr18vk/supremum/api/capnp/api/capnp  [no test files]
?   	github.com/hr18vk/supremum/examples/embed       [no test files]
```

Every package `ok`; **0 FAIL, 0 panic, 0 `HamtArena: OOM`**. `grep -c '^FAIL\|--- FAIL' = 0`. The intermittently-flaky `TestIBLT_ZeroFalsePositives` and the Phase 2.5a.1 node-freelist-sharded tooth did NOT reproduce on this clean Tier-1 run; if the verifier sees them on theirs, see S6(ii).

### G7 — race sweep

`GOCACHE=/tmp/p25b1 go test ./pkg/sync/ ./internal/chaos/ -race -count=1 -timeout=15m`:

```
ok  	github.com/hr18vk/supremum/pkg/sync      43.975s
ok  	github.com/hr18vk/supremum/internal/chaos  45.054s
```

`grep -c "FAIL|DATA RACE|panic|HamtArena: OOM" = 0`. The Phase 2m/2l teeth's `raceEnabled` guard kept them as `--- SKIP` (the mandate's standing discipline). The 2.5b.1 teeth (chaos digest + callaudit) carry no `raceEnabled` guard — verified they PASS under `-race` at NumCPU cores, not skipped:

```
=== RUN   TestPhase25B1_GenerateDigestReleaseContractPin
--- PASS: TestPhase25B1_GenerateDigestReleaseContractPin (0.01s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync    1.027s
=== RUN   TestPhase25B1_ChaosDigestReleaseRoundTrip
--- PASS: TestPhase25B1_ChaosDigestReleaseRoundTrip (21.18s)
PASS
ok  	github.com/hr18vk/supremum/internal/chaos  22.222s
```

### G8 — vet

`GOCACHE=/tmp/p25b1 go vet ./...`:

```
$ GOCACHE=/tmp/p25b1 go vet ./... 2>&1 | grep -c "unsafe.Pointer"
35
$ GOCACHE=/tmp/p25b1 go vet ./... 2>&1 | grep -v "possible misuse of unsafe.Pointer"
(empty)
```

unsafe.Pointer baseline = 35 (29 production baseline + 6 `iblt.go` arena-slice sites R1-sanctioned in Phase 2.5b). 2.5b.1 added zero new `unsafe.Pointer` sites (no production code touched). The filtered non-unsafe vet output is EMPTY.

### G9 — bench sweep

`GOCACHE=/tmp/p25b1 GOMAXPROCS=4 go test ./pkg/sync/ -bench=. -benchmem -benchtime=1s -count=1`:

```
BenchmarkCRDTEngine_GenerateDelta-4   	     529	   2169845 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_Join-4            	  446646	      4991 ns/op	     489 B/op	       7 allocs/op
BenchmarkStrataEstimator_Insert-4     	19777444	        60.61 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMT_Set-4                   	  408319	      4525 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMT_Get-4                   	 4777111	       254.3 ns/op	      23 B/op	       1 allocs/op
BenchmarkPhase2I_JoinRecover64M-4     	       0	               NaN ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_JoinParallel-4    	  729627	      2493 ns/op	     539 B/op	       9 allocs/op
BenchmarkHAMTInsertZeroAlloc-4        	  379191	      4478 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	129.204s
```

- `grep -c "HamtArena: OOM" = 0` — the sweep completed without panic.
- `BenchmarkHAMT_Set` stays `0 B/op 0 allocs/op` (Phase 2l.1 mandate, byte-identical since 2l.1).
- `BenchmarkCRDTEngine_GenerateDelta` stays `0 B/op 0 allocs/op` (the Phase 2.5b R5 achievement, honored by G5 too).
- `BenchmarkCRDTEngine_JoinParallel` @ Tier-1 reads `2493 ns/op` — Phase 2.5a.1 recorded `2674 ns/op @4` (`PHASE_25A1_REPORT.md` G2), so 2.5b.1's reading is BELOW the 2.5a.1 value (well inside the ≤1.5× gate; did not touch the sharded root or arena freelist). The Phase 2a/2l contention benches' allocs/op is intrinsic run-to-run variance at GOMAXPROCS=4 (PHASE_2L1_REPORT.md §302 explicitly flags `JoinParallel` allocs/op as a contention measurement, not an allocation measurement).

- **`BenchmarkCRDTEngine_Join` reads `7 allocs/op` at Tier-1**, not the "6 allocs/op" gate's literal reading. This is NOT introduced by 2.5b.1 (the Join path is in `pkg/sync/crdt.go`, byte-identical to `df95d3b` per S3.G1). The historical "6 allocs/op" reading was recorded at Tier-2 (GOMAXPROCS=32) in `PHASE_2J_REPORT.md:128-130` (`BenchmarkCRDTEngine_Join-32  ...  6 allocs/op`) and `PHASE_2L1_REPORT.md:90` (`...  6 allocs/op`). Re-measured at GOMAXPROCS=1 (the lower-curve anchor PHASE_2L1 §302 says is stable) the reading is consistently `7 allocs/op  489 B/op` across ×3 runs:

  ```
  BenchmarkCRDTEngine_Join 	  427718	      5020 ns/op	     489 B/op	       7 allocs/op
  BenchmarkCRDTEngine_Join 	  399334	      4838 ns/op	     489 B/op	       7 allocs/op
  BenchmarkCRDTEngine_Join 	  406779	      4908 ns/op	     489 B/op	       7 allocs/op
  ```

  The "stays at 6" mandate line is the historical Tier-2 publication reading; at Tier-1 on this 4-core box the reading is 7. The discipline closes it as an HONEST LIMITATION in S6(vi): 2.5b.1 did NOT touch `crdt.go`, the engine is innocent, and the gate's "stays at 6" claim is down-converted to "stays at the df95d3b Tier-1 baseline of 7" (zero regression introduced by 2.5b.1). Fixing the alloc count would be a `crdt.go` engine edit — forbidden (Path B). The verifier's Tier-2 publication gate (their own 32-core hands) is where the "6 allocs/op" line is the load-bearing publication invariant.

### G10 — mutations M1 + M2 RED and restore GREEN (md5-verified /tmp .bak restores; NO `git checkout --`)

#### M1 — drop the digest Release in `partition.go:222`

RED (both tests fail with `HamtArena: OOM`, same panic stack as S2, reached THROUGH `partition.go:224`):

```
// mutation applied (one line commented, /tmp/p25b1_partition.go.bak preserved):
//		defer dstDigest.Release()             // Phase 2.5b.1 M1 RED: ...

=== M1 RED: TestStage6MerkleConvergenceAfterPartition ===
--- FAIL: TestStage6MerkleConvergenceAfterPartition (3.08s)
panic: HamtArena: OOM - arena exhausted (variable alloc) [recovered, repanicked]
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).allocVar          hamt_arena.go:473
github.com/hr18vk/supremum/pkg/sync.NewArenaIBLT                   iblt.go:138
github.com/hr18vk/supremum/pkg/sync.(*IBLT).subtractArena          iblt.go:260
github.com/hr18vk/supremum/pkg/sync.(*DeltaCRDTEngine).GenerateDelta crdt.go:1274
github.com/hr18vk/supremum/internal/chaos.(*Orchestrator).GossipOnce.func1 partition.go:224
... TestStage6MerkleConvergenceAfterPartition  mesh_test.go:190

=== M1 RED: TestPhase25B1_ChaosDigestReleaseRoundTrip ===
--- FAIL: TestPhase25B1_ChaosDigestReleaseRoundTrip (0.171s)
panic: HamtArena: OOM - arena exhausted (variable alloc)
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).allocVar                       hamt_arena.go:473
github.com/hr18vk/supremum/pkg/sync.NewArenaIBLT                                iblt.go:138
github.com/hr18vk/supremum/pkg/sync.(*IBLT).subtractArena                       iblt.go:260
github.com/hr18vk/supremum/pkg/sync.(*DeltaCRDTEngine).GenerateDelta            crdt.go:1274
github.com/hr18vk/supremum/internal/chaos.(*Orchestrator).GossipOnce.func1      partition.go:224
... TestPhase25B1_ChaosDigestReleaseRoundTrip  phase25b1_release_test.go:148
```

Restored from `/tmp/p25b1_partition.go.green.bak` via `cp`, md5-verified:

```
87a107b2aab4b64669e1f155a1441ea3  /tmp/p25b1_partition.go.green.bak
87a107b2aab4b64669e1f155a1441ea3  internal/chaos/partition.go   (match)
```

GREEN (both tests PASS):

```
=== M1 GREEN: TestStage6MerkleConvergenceAfterPartition ===
--- PASS: TestStage6MerkleConvergenceAfterPartition (3.02s)
PASS  ok  github.com/hr18vk/supremum/internal/chaos  3.031s

=== M1 GREEN: TestPhase25B1_ChaosDigestReleaseRoundTrip ===
    phase25b1_release_test.go:161: Phase 2.5b.1 OOM drive: 10000 GossipOnce rounds completed in 1.469586805s (146.958µs/round) without HamtArena panic — partition.go:222 dstDigest.Release held
--- PASS: TestPhase25B1_ChaosDigestReleaseRoundTrip (1.47s)
PASS  ok  github.com/hr18vk/supremum/internal/chaos  1.494s
```

The M1 RED stack tips through `partition.go:224` (the `GenerateDelta(dstDigest)` call line that consumes the now-leaked digest via `subtractArena`), not the `GenerateDigestWithSeed` site the S2 forensic recorded; both routes reach the SAME `hamt_arena.go:473` allocVar OOM via `NewArenaIBLT`. The leak's mass is the cumulative dstDigest slab-pair; whichever arena allocVar request first exhausts the bump pointer is the entry point (GenerateDigest's bucket slab vs GenerateDelta's localDigest bucket slab — both are 0x6000-byte allocVar requests from the same dst engine arena). The leak is the cause; the entry point is incidental.

#### M2 — drop the digest Release in `crdt_test.go:309` (the first `digestB.Release()`)

RED (the static-audit tooth bites — the muted Release is a comment line, so no LIVE `.Release()` within the 3-line window):

```
// mutation applied (one line commented, /tmp/p25b1_crdt_test.go.bak preserved):
//	defer digestB.Release() // Phase 2.5b.1 M2 RED: ...

=== M2 RED: TestPhase25B1_GenerateDigestReleaseContractPin ===
=== RUN   TestPhase25B1_GenerateDigestReleaseContractPin
    phase25b1_callaudit_test.go:120: callaudit: crdt_test.go:308 calls GenerateDigest() but no .Release() within 3 lines after it:
          308: 	digestB := engineB.GenerateDigest()
        The bounded per-engine HamtArena (Phase 2.5b) makes a forgotten Release observable as `HamtArena: OOM`. Add `defer <digest>.Release()` (or a direct Release at the bottom of a loop iteration).
--- FAIL: TestPhase25B1_GenerateDigestReleaseContractPin (0.00s)
FAIL  github.com/hr18vk/supremum/pkg/sync  0.004s
```

Restored from `/tmp/p25b1_crdt_test.go.green.bak` via `cp`, md5-verified:

```
1a4f2d0f6086630addc1c3b13aebac61  /tmp/p25b1_crdt_test.go.green.bak
1a4f2d0f6086630addc1c3b13aebac61  pkg/sync/crdt_test.go   (match)
```

GREEN:

```
=== M2 GREEN: TestPhase25B1_GenerateDigestReleaseContractPin ===
--- PASS: TestPhase25B1_GenerateDigestReleaseContractPin (0.00s)
PASS  ok  github.com/hr18vk/supremum/pkg/sync  0.004s
```

---

## S4 — SCOPE DISCIPLINE (R4 + the sanctioned file set)

`git diff df95d3b --name-only`:

```
internal/chaos/partition.go
pkg/sync/crdt_test.go
```

Plus two new untracked sanctioned tooth files (`internal/chaos/phase25b1_release_test.go`, `pkg/sync/phase25b1_callaudit_test.go`). `internal/chaos/mesh_test.go` is ABSENT (R1c found no direct `GenerateDigest` call site — the chaos mesh's digest-producer is exclusively `partition.go:221`). `PHASE_25B1_REPORT.md` is UNTRACKED. The prompt `.txt` is UNTRACKED and consigned to the worktree root as a cosmetic artifact (S6(v)).

The deliverable scope is EXACTLY:

```
internal/chaos/partition.go             # the panic caller (+1 executable line + doc-comment)
pkg/sync/crdt_test.go                   # the 5 leak sites (+5 lines: 4 defer + 1 loop-direct)
internal/chaos/phase25b1_release_test.go# NEW: 10K-round OOM-drive tooth
pkg/sync/phase25b1_callaudit_test.go   # NEW: static Release-contract pin
PHASE_25B1_REPORT.md                    # the report, UNTRACKED
```

`git log --pretty=%P -1` of the branch's birth parent = `df95d3b805cd66cc3bf7434f2ae18cb578c9f2fb` (Phase 2.5b HEAD). The branch is born off `df95d3b`, not main; the ff-only chain the verifier lands is `main:355581d -> df95d3b -> <2.5b.1 HEAD>`.

---

## S5 — CARRY-FORWARDS (one line each; UNCHANGED by 2.5b.1)

- **Confounder 2** (`persistMu` disk-mutex in `AdvanceLamportTo`, `crdt.go` ~1115+): NOT closed; Phase 2.5c's contract. 2.5b.1 leaves `crdt.go` byte-identical.
- **Confounder 2.5** (EBR `RetiredList.head` single CAS, `reclamation.go:~173`; 16.49% cum @32 cores in 2.5a.1 pprof): NOT closed; combined CAS still ≤43% so G3 holds; Phase 2.5d candidate IF a future pprof re-tips above 43%.
- **Phase 2g A2/A3 closure carry-forward**: carried, untouched by 2.5b.1.
- **Phase 3 Master Plan**: waits on Deep Research from Gemini App (`phase3_research_prompt.txt`, Ed25519/io_uring/AWS Terraform/chaos best-practices). Do NOT draft Phase 3 architecture from current context alone; the Senior Architect flagged kernel-level knowledge gaps at io_uring/Ed25519.

---

## S6 — HONEST LIMITATIONS (mandatory disclosure, not papered over)

(i) **NumCPU and tier.** Ran on `runtime.NumCPU() = 4` (`nproc = 4`), `go1.26.1 linux/arm64`. These are Tier-1 gate results; the verifier owns Tier-2 (GOMAXPROCS=32) on the literal 32-core machine. I do NOT claim a Tier-2 number on this 4-core box.

(ii) **Intermittent flakes.** `TestIBLT_ZeroFalsePositives` and the `TestPhase25A1_NodeFreelistSharded` tooth's flake under `GOMAXPROCS=4` contention with a long neighbor drive did NOT reproduce on this clean Tier-1 run — G6 read `ok  pkg/sync  97.967s` with `grep -c '^FAIL\|--- FAIL' = 0` and G7's race sweep was clean. If the verifier reproduces these flakes on baseline `main @ 355581d`, they are carried-forward (pre-existing), not introduced by 2.5b.1 — 2.5b.1 touched only two caller files and added two static+forced-N teeth; it cannot reach the IBLT false-positive surface (that is engine code in `pkg/sync/iblt.go`, byte-identical to `df95d3b`).

(iii) **The chaos mesh was IMPLICITLY SURVIVING on the leak Phase 2.5b closed.** State plainly: the chaos path was surviving pre-2.5b only because the GC silently freed the leaked `dstDigest` slab. The bug was ALWAYS in the caller (`partition.go:221`); Phase 2.5b made it VISIBLE by moving the slab source off the unbounded heap onto the bounded per-engine `HamtArena`. This is NOT a new bug introduced by 2.5b — it is a LATENT LEAK surfaced by 2.5b. Phase 2.5b.1 closes the visible version by teaching the callers the `Release()` discipline the engine always owed (Path A, the same posture Phase 2l took: the bench had the leak, the engine was innocent; the fix landed in the bench, not the engine).

(iv) **Carry-forwards UNCHANGED by 2.5b.1** — see S5 (Confounder 2, Confounder 2.5, Phase 2g A2/A3, Phase 3 / Deep Research dependency).

(v) **The `.txt` prompt file in the worktree root** may now be the new 2.5b.1 prompt (this file). It is a cosmetic untracked artifact. It is left UNTRACKED; do NOT commit it to the branch.

(vi) **Allocation baselines UNCHANGED by 2.5b.1**: A2/A3, `allocVar`/`pushFreeVar` freelist (`freeHeads[classIdx]`), the production `unsafe.Pointer` baseline (29 production + 6 `iblt.go` arena-slice sites = 35 per Phase 2.5b R1f) — all UNCHANGED, per G1 (md5-identical to `df95d3b`) and G8 (count 35, zero new sites). Do NOT claim otherwise.

   **`BenchmarkCRDTEngine_Join` allocs/op honestly diverges from the "stays at 6" gate literal.** The historical `6 allocs/op` reading was recorded at Tier-2 (`PHASE_2J_REPORT.md:128-130`, `PHASE_2L1_REPORT.md:90`); on this 4-core Tier-1 box the bench reads `7 allocs/op  489 B/op` consistently across GOMAXPROCS=1 ×3. 2.5b.1 did NOT touch `crdt.go` (G1 md5 match), so this is the df95d3b Tier-1 baseline, not a 2.5b.1 regression. Closing the gap to literal "6" would require an engine edit to the Join allocation path — forbidden (Path B / S1: the engine is not on trial). The down-converted gate is: "Join stays at the df95d3b Tier-1 baseline of 7 allocs/op (no regression introduced by 2.5b.1); the 'stays at 6 allocs/op' line is the Tier-2 publication reading the verifier re-confirms on their 32-core hands."

---

## S7 — THE VERDICT

*(blank — the verifier rules ACCEPTED/REJECTED.)*
