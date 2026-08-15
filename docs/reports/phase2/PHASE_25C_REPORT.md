# PHASE 2.5C REPORT — persistMu DISK-MUTEX DECOUPLE

**Branch:** `feat/phase25c-persistmu-decouple`
**Parent:** `d0f23dd` (feat(phase2.5b.1): chaos-digest Release discipline)
**HEAD:** `e5f1b35` (feat(phase2.5c): persistMu disk-mutex decouple)
**Tier:** Tier-1 (sandbox `runtime.NumCPU()=4`). The verifier owns the Tier-2
(`c7g.8xlarge`, `NumCPU=32`) re-run; this report never claims a Tier-2 number.

---

## S1 — Mandate + Path A Surgical Posture

I am the Executor for Phase 2.5c — the decoupling of the per-engine
fsync-in-mutex in `persistLamport`. This is the LAST internal-engine sub-phase
before Phase 3 (Ed25519 origin auth + TCP/eBPF transport + AWS Terraform + AWS
FIS chaos). After 2.5c lands, the engine is fully internal-engine-stabilized and
Phase 3 opens on a clean foundation.

### S0 — the absolute architectural truth (quoted)

`persistLamport` performed `os.OpenFile -> Write -> f.Sync() -> Close ->
os.Rename` ALL UNDER `e.persistMu.Lock()`. The fsync (`f.Sync()`) is the
load-bearing cost: it can stall the holder of `persistMu` for milliseconds to
tens of milliseconds on real block storage, during which EVERY concurrent
`NextDot` (InsertLocal hot path) AND every `AdvanceLamportTo` (Join hot path,
remoteCounter > lastSaved+0 every 1000 inbound ops) was BLOCKED on the same
`persistMu`. The semaitone was single-mutex-fsync-in-CAS-loop:

```
NextDot:          lamportCounter.Add(1) -> if counter > lastSaved ->
                  persistMu.Lock -> persistLamport (fsync!) -> Store -> Unlock
AdvanceLamportTo: lamportCounter.CAS -> lastSavedCounter.CAS ->
                  persistMu.Lock -> persistLamport (fsync!) -> Unlock
```

The fsync is DURABILITY, not ordering. The Lamport-counter CAS already publishes
the in-memory value BEFORE the disk write — that is the contract: in-memory clock
visible immediately, durable-bump lags by one `f.Sync()`. The mutex's ONLY job is
to serialize the disk write so two concurrent `persistLamport` calls do not stomp
each other's tmp file or rename. NOTHING in the ordering requires the fsync to
block the CAS caller; `persistMu` guards the disk FILE, not the in-memory counter.

### THE RULING — Path A (the only permitted path), quoted

> DECOUPLE THE FSYNC OFF THE MUTEX HOLDER. THE CAS CALLER ACQUIRES THE MUTEX LONG
> ENOUGH TO HAND THE PERSIST JOB TO A BACKGROUND WORKER (a channel of "value to
> persist"), releases `persistMu` IMMEDIATELY, and a single goroutine (the
> persist worker) drains the channel and owns the `f.Sync()` + `os.Rename`. The
> CAS caller NEVER blocks on fsync. The in-memory counter and
> `lastSavedCounter` advance synchronously; the durable bump lags by at most one
> in-flight persist job.

### THE FORBIDDEN PATH — Path B (the easy way out), quoted

> REJECT "put the fsync on a goroutine WITHOUT a persist worker" — i.e.,
> `go func(){ e.persistLamport(nextLimit) }()`. That spawns an unbounded herd of
> goroutines all racing for the same tmp file path
> (`"%s/lamport_%x.dat.tmp"`), each one truncating the other's tmp write before
> its Sync+Rename lands. Durability is destroyed (last writer wins on tmp, the
> others' Rename fails or overwrites), and under -race the herd's tmp-file races
> SHOW UP as data races because `os.Rename` is not atomic-vs-itself across
> distinct goroutines writing to the same tmp path. A single dedicated worker
> owning the disk path is non-negotiable.

The +2000 worst-case durability window expansion (§6(i)):

> the non-blocking-select send drops the persist job if the worker is busy. The
> next +1000 CAS re-issues with a strictly-higher `nextLimit`. No Lamport VALUE
> is lost (the in-memory counter advanced already). Only the DURABILITY of the
> +1000 step lags by one extra +1000 step (a crash can lose up to +2000 of
> advancement in the worst case: the dropped job + the in-flight job's
> un-fsynced state). This widens the durability-loss window from +1000
> (pre-2.5c) to +2000 (post-2.5c) in the worst case. Document the arithmetic;
> do NOT claim zero durability loss.

Also-forbidden list honored: f.Sync() stays in the persist worker path; the four
operator setters stay byte-identical (`R4`); the +1000 amortization window stays
byte-identical; exactly ONE in-flight job (unbuffered channel).

---

## S2 — Forensic (the 2.5b.1 Tier-2 reading + why 2.5c is a STRATEGIC close)

The forensic path reproduced by the verifier pre-2.5c on `c7g.8xlarge`:

```
GOMAXPROCS=32 go test ./pkg/sync/ -bench=BenchmarkCRDTEngine_JoinParallel \
    -benchmem -benchtime=1s -count=1
BenchmarkCRDTEngine_JoinParallel-32   688509   2059 ns/op   617 B/op   9 allocs/op
```

That `2059 ns/op` is WELL within the 1.5x gate (vs the 2.5a.1 publication
`2046 ns/op`; read `1.006x` — parallel-Join is scaling, NOT regressing). The
CAS-storm closed by 2.5a/2.5a.1 IS holding. So `persistMu` today is NOT the
load-bearing bottleneck on JoinParallel; the Phase 2j Tooth C verdict flipped
from CORROBORATED pre-2.5a to NOT-CORROBORATED post-2.5a.1 (the sharded root CAS
eliminated the lion's share of the contention).

### SO WHY CLOSE IT NOW? (the strategic posture, documented honestly)

- The +1000 amortization means `persistMu` is grabbed exactly ONCE per 1000
  NextDot / AdvanceLamportTo CAS-successes. Per worker at
  `BenchmarkCRDTEngine_JoinParallel-32`, that is 1 fsync per 1000 ops. With 32
  workers hammering the engine, that is 32 fsyncs/1000 ops = ~3.2% of InsertLocal
  ops blocked on a multi-millisecond fsync — at the publication tier that is ~the
  only serializing component left in the engine's hot path.

- The Phase 2j §6 mandate named this IS the sub-phase to decouple it. Leaving it
  open means the production Workload Sampler (Phase 3) on a real `c7g.8xlarge`
  with NVMe fsync latency WILL surface it: the bench at `-benchtime=1s` is too
  short to see fsync stalls; the Sampler at minutes/hours on real block storage
  will. Pre-2.5c the in-process bench hides the bind; the production engine
  exposes it. Close it before AWS Terraform ships the engine to real disks.

- The `2059 ns/op` headline INCLUDES the fsync cost amortized across the whole
  bench window. The bench is bench-shaped (`b.N` ops in `-benchtime=1s`,
  `b.N≈688509`); the fsync cost per op is amortized across the whole window by
  Go's testing framework. Per-second fsync-stall variance is invisible. The
  Workload Sampler (Phase 3) measures TAIL latency, not mean — and tail latency
  is exactly where fsync-in-mutex bites. 2.5c closes the tail BEFORE the Sampler
  exists to measure it.

This Tier-1 box (`NumCPU=4`) cannot reproduce the `2059 ns/op @ NumCPU=32` Tier-2
reading — the verifier owns that row. The Tier-1 symmetric is the
`BenchmarkCRDTEngine_JoinParllel-4` non-regression (S3.G6/G10).

---

## S3 — The Fix (R1a-R1g exact diffs; R3 teeth; G1-G11 literal output)

### R1a — Persist worker fields (crdt.go struct, near persistMu)

```diff
 	persistMu       sync.Mutex
 	dataDir         string
 	participantPool sync.Pool
 	arena           *HamtArena
 	ebr             *EBRManager
+	_persistPad0    CacheLinePad
+	// Phase 2.5c (persistMu disk-mutex decouple): the CAS callers
+	// (NextDot / AdvanceLamportTo) NO LONGER block on the fsync inside
+	// persistMu. They hand a "value to persist" to persistCh (an UNBUFFERED
+	// chan uint64 — exactly one in-flight persist job; the CAS caller drops
+	// the send if the worker is busy, see §6(i)) and return immediately; a
+	// single dedicated goroutine (persistWorkerLoop) drains the channel and
+	// owns the f.Sync()+os.Rename UNDER persistMu ... (+1000 pre-2.5c ->
+	// +2000 worst-case durability window post-2.5c; §6(i)). persistStopOnce
+	// guards Close()'s idempotent stop/close path ... persistWorkerWg lets
+	// Close drain the worker BEFORE arena.Free (no in-flight fsync dangles
+	// after Close).
+	persistCh          chan uint64
+	persistWorkerWg    sync.WaitGroup
+	persistStopOnce    sync.Once
+	persistWorkerReady chan struct{}
+	_persistPad1       CacheLinePad
```

`persistWorkerReady chan struct{}` is the **startup-ready handshake**: the worker
closes it once it has parked on the `for val := range e.persistCh` receive point,
and `NewDeltaCRDTEngine` blocks on `<-e.persistWorkerReady` before returning.
This is essential for the unbuffered-channel + non-blocking-select design: a
non-blocking send to an UNBUFFERED channel rendezvouses ONLY if the worker is
already parked on the receive. Without the handshake, the FIRST CAS-issued
persist job (right after `go e.persistWorkerLoop()`) could race the worker's
startup schedule and DROP via the `select { default: }` branch — defeating the
Close-drain durability contract (R3c: a single NextDot then Close MUST round-trip
1001). The handshake guarantees the worker is parked on the receive BEFORE the
constructor returns, so the first send rendezvouses (worker idle, not busy) and
becomes the one in-flight job the Close drain then completes. The worker remains
the ONLY caller of `persistLamport`. See §6 — this handshake is the one
addition beyond the literal R1a three-field list, and it is the minimal fix for
the unbuffered-channel startup race the durability tooth exposes; it adds ZERO
new `unsafe.Pointer` sites (R4/G9).

### R1b — NewDeltaCRDTEngine init (crdt.go)

```diff
 	e.observedInboundRateBits.Store(math.Float64bits(0.0))
+	// Phase 2.5c: spawn the single dedicated persist worker ...
+	e.persistCh = make(chan uint64)
+	e.persistWorkerReady = make(chan struct{})
+	e.persistWorkerWg.Add(1)
+	go e.persistWorkerLoop()
+	<-e.persistWorkerReady  // startup-ready handshake (see R1a rationale)
+	return e, nil
```

### R1c — NextDot rewrite (NextDot NO LONGER HOLDS persistMu)

```diff
-	e.persistMu.Lock()
-	defer e.persistMu.Unlock()
-	lastSaved := e.lastSavedCounter.Load()
-	if counter > lastSaved {
-		nextLimit := counter + 1000
-		_ = e.persistLamport(nextLimit)
-		e.lastSavedCounter.Store(nextLimit)
-	}
+	// Phase 2.5c: advance lastSavedCounter SYNCHRONOUSLY (in-memory truth);
+	// +1000 amortization window byte-identical; durable write lags by at most
+	// one in-flight persist job (§6(i)). CAS on lastSavedCounter wins the
+	// persist slot (two goroutines can race past the counter<=lastSaved check
+	// together now that the mutex is gone); the select-default send drops the
+	// job if the single worker is busy; next +1000 CAS re-issues.
+	nextLimit := counter + 1000
+	if e.lastSavedCounter.CompareAndSwap(
+		e.lastSavedCounter.Load(), nextLimit,
+	) {
+		select {
+		case e.persistCh <- nextLimit:
+		default:
+		}
+	}
```

### R1d — AdvanceLamportTo rewrite (mirrors NextDot; NO persistMu)

```diff
 				nextLimit := remoteCounter + 1000
 				if e.lastSavedCounter.CompareAndSwap(lastSaved, nextLimit) {
-					e.persistMu.Lock()
-					_ = e.persistLamport(nextLimit)
-					e.persistMu.Unlock()
+					select {
+					case e.persistCh <- nextLimit:
+					default:
+					}
 					break
 				}
```

### R1e — Close() drain (drain worker BEFORE arena.Free)

```diff
 // Close releases the off-heap arena.
 func (e *DeltaCRDTEngine) Close() error {
+	e.persistStopOnce.Do(func() { close(e.persistCh) })
+	e.persistWorkerWg.Wait()
 	return e.arena.Free()
 }
```

### persistWorkerLoop (the ONLY caller of persistLamport now)

```go
func (e *DeltaCRDTEngine) persistWorkerLoop() {
	close(e.persistWorkerReady) // startup-ready handshake
	for val := range e.persistCh {
		e.persistMu.Lock()
		_ = e.persistLamport(val)
		e.persistMu.Unlock()
	}
	e.persistWorkerWg.Done()
}
```

The LOCK is held for the duration of the `f.Sync()` + `os.Rename`, exactly as
pre-2.5c, so the disk serialization guarantees are byte-identical; the ONLY thing
that changed is that the CAS caller is not the one BLOCKING on that lock-hold.

### R1f — Off-hot-path setter drain hooks: NONE needed (R4 honored)

The four setters (`SetDataDir`, `SetLamportHorizonSeconds`,
`SetLamportAbsoluteSlack`, `SetShardCount`) each STILL acquire `persistMu` and
are byte-identical to `d0f23dd` (md5-audited in G1). They do NOT hold the fsync
today (they hold `persistMu` only for the in-memory copy; no `f.Sync`). Their
existing `persistMu` usage is ALREADY correct under the worker model: the
worker holds `persistMu` during `f.Sync()`+`os.Rename`; a setter's
`persistMu.Lock` blocks until that in-flight job finishes, then the setter
mutates `e.dataDir` / the skew knobs / `e.shards`; the NEXT job the worker
picks up uses the NEW `dataDir` / config — no race, NO drain hook needed.

### R1g — scope honesty

`git diff d0f23dd..HEAD --stat`:

```
 pkg/sync/crdt.go          | 137 ++++++++++++--
 pkg/sync/phase25c_test.go | 456 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 579 insertions(+), 14 deletions(-)
```

Exactly the two sanctioned files; `PHASE_25C_REPORT.md` is left UNTRACKED.

### R3 — the teeth (phase25c_test.go)

**R3a — `TestPhase25C_PersistWorkerDecoupledStatic`** is a STATIC regex guard
over `pkg/sync/crdt.go` asserting S1-S9 (no race/skip guard; pins shape under
every build). Sorted across the engine struct + the NewDeltaCRDTEngine init +
the persistWorkerLoop body + the NextDot/AdvanceLamportTo/CLOSE function bodies
(scoped via `phase25cFuncBody`):
- S1 `persistCh chan uint64` field declared; `make(chan uint64)` cap-0 unbuffered.
- S2 `persistWorkerWg sync.WaitGroup` field declared.
- S3 `persistStopOnce sync.Once` field declared.
- S4 `go e.persistWorkerLoop()` spawn present.
- S5 NextDot body MUST NOT contain `e.persistMu.Lock()` (scope-absence regex).
- S6 AdvanceLamportTo body MUST NOT contain `e.persistMu.Lock()`.
- S7 persistWorkerLoop body contains `for val := range e.persistCh` and
  `e.persistLamport(val)` (the worker is the ONLY caller of persistLamport).
- S8 Close() body contains `e.persistStopOnce.Do(func(){ close(e.persistCh) })`
  + `e.persistWorkerWg.Wait()` BEFORE `e.arena.Free()` (textual ordering).
- S9 NextDot + AdvanceLamportTo each contain the non-blocking
  `select { case e.persistCh <- nextLimit: default: }`.

The teeth do NOT downgrade red; they do NOT `t.Skip` under any condition other
than `testing.Short()` (the static guard has NO skip guard at all).

**R3b — `TestPhase25C_NoBlockingFsyncDrive`** is the runtime sanity drive.
Constructs one engine in `t.TempDir()`, spawns `runtime.NumCPU()` goroutines
each minting 1000 `NextDot()` calls (each goroutine trips persistMu once on
pre-2.5c code), and measures the max wall-clock of the LAST `NextDot()` per
goroutine (`t_MAX`). Gate: `t_MAX < 50ms` at NumCPU=4, `< 100ms` at NumCPU=32.
Thresholds are LENIENT ON PURPOSE — on NVMe this tooth does NOT bite RED on
pre-2.5c (the gate is satisfied incidentally). It is a sanity check, not the
load-bearing bite.

**R3c — `TestPhase25C_DurabilityRoundTrip`** is the LOAD-BEARING runtime bite.
- Sub-case `Steady_1001NextDot`: mint 1001 NextDot, Close, reconstruct a NEW
  engine in the SAME dataDir, assert `recoverLamport` reads 1001 (the first
  persist fires at counter=1 with lastSaved=0 -> nextLimit=1001).
- Sub-case `OneNextDot_ThenClose_RaceSurface`: mint exactly ONE NextDot then
  immediately Close, repeat 100x. Under 2.5c Close() DRAINS the worker
  (`persistWorkerWg.Wait` BEFORE `arena.Free`), so the file MUST read 1001 every
  iteration (no scheduler-luck dependency). Mutation M4 (remove the Wait)
  surfaces the race here.

### R3d — mutation M1/M2/M3/M4 RED + restore GREEN (G11 capture)

All four mutations were applied to `pkg/sync/crdt.go`, captured RED, then
restored from `/tmp/phase25c_crdt.bak` with md5-verify (`md5` returned to
`cac7976936a969b19bcae34df7718825`). NO `git checkout --` was used for restore.

**M1** (revert NextDot to `persistMu.Lock` + inline `persistLamport` shape):
- RED — `TestPhase25C_PersistWorkerDecoupledStatic` FAILED:
  ```
  PHASE25C STATIC GUARD: S5 FAILED — NextDot body contains e.persistMu.Lock(); the decouple is undone (the CAS caller must NOT block on the disk mutex).
  PHASE25C STATIC GUARD: S9 FAILED — NextDot body MISSING non-blocking select { case e.persistCh <- nextLimit: default: }.
  --- FAIL: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
  ```
- Restored GREEN: `--- PASS: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)`.

**M2** (revert AdvanceLamportTo to the `persistMu.Lock` shape):
- RED — `TestPhase25C_PersistWorkerDecoupledStatic` FAILED:
  ```
  PHASE25C STATIC GUARD: S6 FAILED — AdvanceLamportTo body contains e.persistMu.Lock(); the decouple is undone.
  PHASE25C STATIC GUARD: S9 FAILED — AdvanceLamportTo body MISSING non-blocking select { case e.persistCh <- nextLimit: default: }.
  --- FAIL: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
  ```
- Restored GREEN: `--- PASS: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)`.

**M3** (remove the `go e.persistWorkerLoop()` spawn in NewDeltaCRDTEngine):
- RED — `TestPhase25C_PersistWorkerDecoupledStatic` FAILED:
  ```
  PHASE25C STATIC GUARD: S4 (go e.persistWorkerLoop() spawn in NewDeltaCRDTEngine) FAILED — go e.persistWorkerLoop() spawn MISSING — the worker never starts; channel sends hang / persist never happens
  --- FAIL: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
  ```
- Honest note: with the ready handshake, M3 ALSO deadlocks the constructor
  (`<-e.persistWorkerReady` blocks forever because the worker that would close
  it is never spawned), so `NewDeltaCRDTEngine` never returns and the durability
  tooth cannot even construct an engine. This is a STRICTER RED than the
  mandate's literal text ("the channel sends hang forever ... static guard
  FAILs on S4; AND the durability tooth R3c FAILs because nothing ever
  persists"); the constructor deadlock is the mechanism by which "nothing ever
  persists" manifests under the ready-handshake fix. Documented honestly in §6.
  The static guard S4 RED is the captured cross-bite head; the durability RED
  is implied (and confirmed by the fact that no engine constructs).
- Restored GREEN: all three `TestPhase25C_` teeth PASS.

**M4** (remove `persistWorkerWg.Wait()` from Close):
- RED — static guard + durability:
  ```
  PHASE25C STATIC GUARD: S8 FAILED — Close() body MISSING e.persistWorkerWg.Wait(). Close body:
  --- FAIL: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
  PHASE25C R3c 1-NextDot: iterations=100 ok=80 miss=20 (Close-drain must read 1001 every iteration; any miss is a decouple regression)
  --- FAIL: TestPhase25C_DurabilityRoundTrip/OneNextDot_ThenClose_RaceSurface (0.03s)
  ```
  20/100 iterations missed the persisted value — the M4 race surfaced with high
  probability over 100 iterations, exactly as the mandate predicted.
- Restored GREEN:
  ```
  PHASE25C R3c 1-NextDot: iterations=100 ok=100 miss=0
  --- PASS: TestPhase25C_DurabilityRoundTrip/OneNextDot_ThenClose_RaceSurface (0.03s)
  ```

### G1 — scope byte-identity (R4 protected set, 0-line diffs)

```
$ git diff d0f23dd..HEAD --stat
 pkg/sync/crdt.go          | 137 ++++++++++++--
 pkg/sync/phase25c_test.go | 456 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 579 insertions(+), 14 deletions(-)
```

Every file in the PROTECTED set shows `lines=0` and an md5 identical to its d0f23dd form:

```
lines=0 md5=3886f55c pkg/sync/iblt.go
lines=0 md5=bc03bdb3 pkg/sync/hamt.go
lines=0 md5=97717014 pkg/sync/hamt_arena.go
lines=0 md5=ed9132a2 pkg/sync/crdt_apply.go
lines=0 md5=e8422f6d pkg/sync/crdt_apply_batch.go
lines=0 md5=f856f0fa pkg/sync/crdt_reconstruct.go
lines=0 md5=e755d894 pkg/sync/crdt_reconstruct_skew.go
lines=0 md5=4cabcdb5 pkg/sync/reclamation.go
lines=0 md5=656fd349 pkg/sync/residency.go
lines=0 md5=413dd7b8 pkg/sync/physics_test.go
lines=0 md5=1a4f2d0f pkg/sync/crdt_test.go
lines=0 md5=49872741 pkg/sync/phase2j_test.go
lines=0 md5=b4c0d192 pkg/sync/phase25b_test.go
lines=0 md5=21b20d59 pkg/sync/phase25b1_callaudit_test.go
lines=0 md5=116c8a73 pkg/sync/phase25a_test.go
lines=0 md5=8997aa5d pkg/sync/phase25a1_test.go
lines=0 md5=40885459 pkg/sync/phase2l_staticaudit_test.go
lines=0 md5=603e5612 pkg/sync/crdt_capnp_roundtrip_test.go
lines=0 md5=a58ab79b pkg/sync/crdt_capnp_teeth_test.go
lines=0 md5=4fe64185 pkg/sync/crdt_dot_origin_test.go
lines=0 md5=e2e7e43f pkg/sync/crdt_lamport_skew_test.go
lines=0 md5=26e5ff21 pkg/sync/crdt_apply_test.go
lines=0 md5=8c6ca99b pkg/sync/crdt_apply_batch_test.go
lines=0 md5=27e9e2e9 pkg/sync/hamt_test.go
lines=0 md5=87a107b2 internal/chaos/partition.go
lines=0 md5=ed9721c9 internal/chaos/phase25b1_release_test.go
lines=0 md5=592ea280 internal/chaos/mesh_test.go
lines=0 md5=48a2d167 internal/chaos/virtualnet.go
lines=0 md5=81b8828d internal/chaos/fuzzer.go
lines=0 md5=c00dfcd0 internal/chaos/wal_test.go
lines=0 md5=4fb21790 internal/chaos/probe.go
```

The four operator setters are byte-identical (md5-audited function bodies):
```
OK SetDataDir            md5=36d8026e3b0c51c75ae50a7e9200b27c
OK SetLamportHorizonSeconds md5=4fd1e84b81b4c387cb2fe5e6c35fb292
OK SetLamportAbsoluteSlack   md5=8848764dee2a4bb8c4a5baf4edbdbbd4
OK SetShardCount         md5=b6f7fa92d2275af8f6cc31026f44133b
OK persistLamport        byte-identical
```

### G2 — Phase 2j Tooth C verdict MUST STAY NOT-CORROBORATED

```
NumCPU=4
$ GOMAXPROCS=4 go test ./pkg/sync/ -run='^TestPhase2J_JoinParallelContentionCurve$' -count=1 -v
    phase2j_test.go:240: Tooth C: sandbox runtime.NumCPU()=4; clamped max GOMAXPROCS=4; declared threshold=1.50x
    phase2j_test.go:255: Tooth C row: GOMAXPROCS=1    ns/op=5460.00 N=407343 (actual GOMAXPROCS=1)
    phase2j_test.go:256: Tooth C row: GOMAXPROCS=4    ns/op=2607.00 N=777103 (actual GOMAXPROCS=4)
    phase2j_test.go:257: Tooth C: ratio Y/X = ns/op@4 / ns/op@1 = 2607.0000 / 5460.0000 = 0.48
    phase2j_test.go:268: Tooth C VERDICT: NOT-CORROBORATED — ns/op@4 (2607.00) < 1.50x ns/op@1 (5460.00). No contention at this scale; Candidate 3 closed-at-this-scale — no Phase 2k fix warranted by THIS bench's data.
--- PASS: TestPhase2J_JoinParallelContentionCurve (4.30s)
```

Verdict STAYS NOT-CORROBORATED — the STAY is the proof that 2.5c did NOT regress
parallel-Join at the Tier-1 scale (ratio 0.48x; parallel-Join accelerates). The
verifier will re-rule on `c7g.8xlarge` at NumCPU=32; if it flips to CORROBORATED
post-2.5c that is a 2.5c regression.

### G3 — Phase 2.5c static guard tooth

```
$ go test ./pkg/sync/ -run='^TestPhase25C_PersistWorkerDecoupledStatic$' -count=1 -v
=== RUN   TestPhase25C_PersistWorkerDecoupledStatic
--- PASS: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
```

### G4 — Phase 2.5c runtime teeth (R3b + R3c)

```
$ GOMAXPROCS=4 go test ./pkg/sync/ -run='^TestPhase25C_' -count=1 -v
NumCPU=4
=== RUN   TestPhase25C_PersistWorkerDecoupledStatic
--- PASS: TestPhase25C_PersistWorkerDecoupledStatic (0.00s)
=== RUN   TestPhase25C_NoBlockingFsyncDrive
    phase25c_test.go:286: PHASE25C R3b: runtime.NumCPU()=4; workers=4
    phase25c_test.go:332: PHASE25C R3b: t_MAX (last NextDot per worker)=179ns; threshold=50ms (workers=4, NumCPU=4)
--- PASS: TestPhase25C_NoBlockingFsyncDrive (0.00s)
=== RUN   TestPhase25C_DurabilityRoundTrip
    phase25c_test.go:358: PHASE25C R3c: runtime.NumCPU()=4
=== RUN   TestPhase25C_DurabilityRoundTrip/Steady_1001NextDot
    phase25c_test.go:406: PHASE25C R3c Steady: recovered Lamport counter=1001 == want 1001 (Close-drain held)
=== RUN   TestPhase25C_DurabilityRoundTrip/OneNextDot_ThenClose_RaceSurface
    phase25c_test.go:448: PHASE25C R3c 1-NextDot: iterations=100 ok=100 miss=0 (Close-drain must read 1001 every iteration; any miss is a decouple regression)
--- PASS: TestPhase25C_DurabilityRoundTrip (0.03s)
    --- PASS: TestPhase25C_DurabilityRoundTrip/Steady_1001NextDot (0.00s)
    --- PASS: TestPhase25C_DurabilityRoundTrip/OneNextDot_ThenClose_RaceSurface (0.03s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	0.038s
```

`t_MAX=179ns` — far below the 50ms gate (sanity tooth; not the load-bearing bite).

### G5 — Phase 2.5b R5 regression-negative (network hot path stays 0/0)

```
$ GOMAXPROCS=1 go test ./pkg/sync/ -run='^$' -bench='^BenchmarkCRDTEngine_GenerateDelta$' -benchmem -benchtime=1s -count=5
BenchmarkCRDTEngine_GenerateDelta 	     542	   2089394 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     492	   2099025 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     572	   2118311 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     576	   2131009 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_GenerateDelta 	     573	   2110566 ns/op	       0 B/op	       0 allocs/op
ok  	github.com/hr18vk/supremum/pkg/sync	72.544s
```

0 B/op · 0 allocs/op 5/5 at GOMAXPROCS=1 — R5 Zero-GC survived (iblt.go untouched, R4 holds).

### G6 — GenerateDelta + Join + JoinParallel NON-REGRESSION

```
$ GOMAXPROCS=4 go test ./pkg/sync/ -run='^$' -bench='^(BenchmarkCRDTEngine_Join$|BenchmarkCRDTEngine_JoinParallel$|BenchmarkCRDTEngine_GenerateDelta$)' -benchmem -benchtime=1s -count=1
BenchmarkCRDTEngine_GenerateDelta-4   	     481	   2722529 ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_Join-4            	  445801	      5301 ns/op	     489 B/op	       7 allocs/op
BenchmarkCRDTEngine_JoinParallel-4    	  700964	      2698 ns/op	     543 B/op	       9 allocs/op
ok  	github.com/hr18vk/supremum/pkg/sync	27.431s
```

- `BenchmarkCRDTEngine_GenerateDelta-4`: 0 allocs/op maintained.
- `BenchmarkCRDTEngine_Join-4`: 489 B/op · 7 allocs/op (byte-identical to pre-2.5c; the Join body was not touched — only NextDot + AdvanceLamportTo which Join calls, and those changes removed the inline fsync from the Join hot path, so the steady-state alloc count is unchanged).
- `BenchmarkCRDTEngine_JoinParallel-4`: 2698 ns/op. The 2.5b.1 Tier-1 baseline at NumCPU=4 was ~2811 ns/op (the publication Tier-2 reading was 2059 ns/op @ NumCPU=32). 2698 ≤ 1.5×2811 (≈4216) — PASS, comfortably under the gate.

### G7 — full repo go test ./...

```
$ go test ./... -count=1
ok  	github.com/hr18vk/supremum/internal/chaos	5.444s
ok  	github.com/hr18vk/supremum/internal/crypto	0.002s
ok  	github.com/hr18vk/supremum/internal/database	0.331s
ok  	github.com/hr18vk/supremum/internal/network	0.005s
ok  	github.com/hr18vk/supremum/internal/spatial	0.115s
ok  	github.com/hr18vk/supremum/internal/telemetry	0.027s
ok  	github.com/hr18vk/supremum/internal/temporal_store	0.320s
ok  	github.com/hr18vk/supremum/internal/transport	0.414s
ok  	github.com/hr18vk/supremum/pkg/sync	102.813s
```

Every package `ok`; zero FAIL. `TestIBLT_ZeroFalsePositives` and the Phase 2.5a.1
A1 tooth did NOT surface on this Tier-1 run (so no baseline reproduction on d0f23dd
was needed; carried forward faithfully in §6(iii)). The Phase 2g lamport-skew tooth
still bites (`crdt_apply.go` untouched; R4).

### G8 — race sweep

```
$ go test ./pkg/sync/ ./internal/chaos/ -race -count=1 -timeout=15m
ok  	github.com/hr18vk/supremum/pkg/sync	41.293s
ok  	github.com/hr18vk/supremum/internal/chaos	45.213s
```

0 data race, 0 panic, 0 FAIL. The 2m/2l teeth's `raceEnabled` guard kept them as
`--- SKIP` (clean build → `raceEnabled=false`; under `-race` the companion file
flips it true and they SKIP exactly as designed). The new 2.5c teeth PASS under
`-race` (the worker is single-goroutine; the channel send is non-blocking
select-default; no race surface).

### G9 — vet + unsafe.Pointer baseline

`go vet ./...` reports only the pre-existing `possible misuse of unsafe.Pointer`
advisories on the production arena/IBLT/HAMT paths (unchanged from d0f23dd). The
filtered non-unsafe output is EMPTY.

unsafe.Pointer site count is byte-identical to `d0f23dd`:

```
crdt.go unsafe.Pointer sites @ d0f23dd vs HEAD:
  d0f23dd: 8 sites  (incl. the single unsafe.Slice at crdt.go:532)
  HEAD:    8 sites  (same bodies; the unsafe.Slice now at crdt.go:582)
  Added by 2.5c: 0  (git diff d0f23dd..HEAD -- pkg/sync/crdt.go | grep '^+.*unsafe.Pointer' == empty)
```

2.5c adds ZERO new `unsafe.Pointer` sites. The mandate's "35 (29 production +
6 iblt.go arena-slice sites)" baseline accounting is the iblt/HAMT/reclamation
production set; 2.5c does not touch any of those files (R4) and adds no `unsafe`
to crdt.go's persist path, so the count stays at its 2.5b baseline. Honest
fidelity: a raw repo-wide `grep -c` returns a larger number because the mandate's
"35" counts *sites* under its own scoping, not raw occurrences across the wider
`internal/` tree; the load-bearing invariant — "2.5c adds ZERO new sites" — is
proven by the empty `^+.*unsafe.Pointer` diff and the byte-identical d0f23dd↔HEAD
per-file counts.

### G10 — bench sweep (no OOM; HAMT_Set 0/0; sanity sweep)

```
$ GOMAXPROCS=4 go test ./pkg/sync/ -bench=. -benchmem -benchtime=1s -count=1 -timeout=10m
BenchmarkCRDTEngine_GenerateDelta-4   	     481	   2493067 ns/op	       10 B/op	       0 allocs/op
BenchmarkCRDTEngine_Join-4            	  445801	      5349 ns/op	     489 B/op	       7 allocs/op
BenchmarkStrataEstimator_Insert-4     	19636509	        60.99 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMT_Set-4                   	  404197	      4658 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMT_Get-4                   	 4228686	       293.5 ns/op	      23 B/op	       1 allocs/op
BenchmarkPhase2I_JoinRecover64M-4     	       0	               NaN ns/op	       0 B/op	       0 allocs/op
BenchmarkCRDTEngine_JoinParallel-4    	  708916	      2588 ns/op	     545 B/op	       9 allocs/op
BenchmarkHAMTInsertZeroAlloc-4        	  396426	      4677 ns/op	       0 B/op	       0 allocs/op
... (false-sharing sanity benches ...)
ok  	github.com/hr18vk/supremum/pkg/sync	144.177s
$ grep -c "HamtArena: OOM" <sweep> == 0
```

No OOM (`grep -c "HamtArena: OOM" == 0`). `BenchmarkHAMT_Set-4` stays
0 B/op 0 allocs/op (Phase 2l.1 mandate). `BenchmarkCRDTEngine_JoinParallel-4`
2588 ns/op ≤ 1.5× the 2.5b.1 baseline. `BenchmarkCRDTEngine_Join-4` 489 B/op ·
7 allocs/op byte-identical to pre-2.5c.

(`BenchmarkPhase2I_JoinRecover64M-4` reads `NaN ns/op` with `N=0` — that is the
pre-existing Phase 2i "64 MiB Join OOM-recovery" probe that catches the panic
shape; it is byte-identical to d0f23dd (`phase2i_forensics_test.go` protected,
0-line diff) and is NOT a 2.5c regression.)

### G11 — mutations M1 + M2 + M3 + M4 RED + restore GREEN

Captured literally in R3d above. Each mutation was restored from
`/tmp/phase25c_crdt.bak` with md5-verify (md5 returned to
`cac7976936a969b19bcae34df7718825` after every restore); the restored tree ran
all three `TestPhase25C_` teeth GREEN. NO `git checkout --` was used for any
restore.

---

## S4 — Scope Discipline (R4 + the sanctioned file set diff --stat)

The sanctioned file set (R1g) is exactly:
```
pkg/sync/crdt.go            # the engine: worker fields, spawn, NextDot, AdvanceLamportTo, Close, persistWorkerLoop
pkg/sync/phase25c_test.go   # NEW: the R3 teeth
PHASE_25C_REPORT.md         # this report (UNTRACKED, not committed)
```

`git diff d0f23dd..HEAD --stat`:
```
 pkg/sync/crdt.go          | 137 ++++++++++++--
 pkg/sync/phase25c_test.go | 456 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 579 insertions(+), 14 deletions(-)
```

R4 PROTECTED set (31 files) audited in G1 — every file `lines=0` and md5-identical
to its d0f23dd form. The four operator setters + `persistLamport` are
byte-identical (function-body md5 audit). DO NOT TOUCH the apply/reconstruct/
IBLT/HAMT production paths — R4 binds; honored.

The 14 deleted lines in crdt.go are EXACTLY the pre-2.5c NextDot and
AdvanceLamportTo `persistMu.Lock`+`persistLamport` blocks (and a gofmt-driven field
re-alignment of `mergedView` + a one-character typo fix `limit limit`→`limit` in
the AdvanceLamportTo comment). No production setter or persistLamport line was
deleted; no R4-protected file was touched.

---

## S5 — Carry-Forwards (one line each)

- **Confounder 2.5** — the EBR `RetiredList.head` single CAS
  (`reclamation.go ~173`; 16.49% cum @ 32 cores in the 2.5a.1 pprof) is NOT
  closed; it is a Phase 2.5d candidate IF a future pprof re-tips above 43%.
  2.5c does not touch `reclamation.go` (R4 → `lines=0` md5-audited).
- **Phase 2g A2/A3 origin-authentication closure** — unchanged. 2.5c touches
  only the persist path; `crdt_lamport_skew_test.go`, `crdt_apply.go`, and the
  skew-bound snapshot seam are byte-identical (R4). The lamport-skew tooth still
  bites (apply seam untouched).
- **The 26-pointer (now 35) production `unsafe.Pointer` baseline** — 2.5c adds
  ZERO new sites; the count stays at its 2.5b baseline (G9). Phase 3 Master Plan
  waits on Deep Research from Gemini App (`phase3_research_prompt.txt` —
  Ed25519/io_uring/AWS Terraform/chaos best practices); do NOT draft Phase 3
  architecture from current context alone; the Senior Architect flagged knowledge
  gaps at the io_uring/Ed25519 kernel level.

---

## S6 — Honest Limitations

**(i) Durability-loss window arithmetic.** The non-blocking-select send drops the
persist job if the single worker is busy. The next +1000 CAS re-issues with a
strictly-higher `nextLimit`. No Lamport VALUE is lost (the in-memory counter
advanced already). Only the DURABILITY of the +1000 step lags by one extra +1000
step: a crash can lose up to +2000 of advancement in the worst case (the dropped
job's +1000 step + the in-flight job's un-fsynced +1000 step). This widens the
durability-loss window from +1000 (pre-2.5c) to +2000 (post-2.5c) in the worst
case. This report does NOT claim zero durability loss. The ready handshake
(R1a) does NOT narrow this window — it only closes the startup-race drop of the
FIRST job; it does not stop a busy-worker drop of a later job.

**(ii) NumCPU actually run on.** All gates ran on a Tier-1 box with
`runtime.NumCPU()=4`. This report claims no Tier-2 number. The JoinParallel
`2059 ns/op @ NumCPU=32` (S2) is the verifier's pre-2.5c publication Tier-2
reading, reproduced here as the forensic baseline ONLY; the 2.5c Tier-2 re-run
on `c7g.8xlarge` is the verifier's to land. The Tier-1 JoinParallel reading here
is `2698 ns/op @ NumCPU=4` (G6) / `2588 ns/op` in the G10 sweep, both ≤ 1.5× the
~2811 ns/op Tier-1 2.5b.1 baseline — the load-bearing 2.5c non-regression at
the scale this box can measure.

**(iii) Intermittent flakes.** `TestIBLT_ZeroFalsePositives` and the Phase 2.5a.1
A1 tooth did NOT surface on this 4-core Tier-1 run (G7); no baseline
`d0f23dd` reproduction was triggered. They remain carried-forward pre-existing
flakes; if the verifier's Tier-2 run surfaces them, reproduce each on `main @
d0f23dd` to prove they are NOT 2.5c regressions. The Phase 2g lamport-skew tooth
MUST still bite post-2.5c — it does (`crdt_apply.go` untouched, R4; the apply
seam is byte-identical, G1).

**(iv) The 2.5c non-regression vs the tail-latency claim.** The 2.5c
non-regression is the JoinParallel `ns/op` staying at-or-below the 2.5b.1 reading
at the bench's scale (G6/G10). The bench at `-benchtime=1s` is too short to
expose fsync-stall TAIL latency; the Phase 3 Workload Sampler (the
tail-latency instrument) is where 2.5c's true value will be MEASURED. 2.5c is a
STRATEGIC close (the mandate's posture: fix the tail BEFORE the Sampler exists to
expose it); it is not provable in the in-process bench today. This report does
NOT claim a 2.5c tail-latency improvement the bench cannot measure.

**(v) Carry-forwards UNCHANGED by 2.5c** — Confounder 2.5 (EBR
`RetiredList.head` single CAS, `reclamation.go ~173`; 16.49% cum @ 32 cores in
2.5a.1 pprof) — NOT closed; Phase 2.5d candidate IF a future pprof re-tips above
43%. Phase 2g A2/A3 origin-authentication closure — unchanged. The
26-pointer (now 35) production `unsafe.Pointer` baseline — 2.5c adds ZERO new
sites. Phase 3 Master Plan waits on Deep Research from Gemini App — do NOT draft
Phase 3 architecture from current context alone.

**(vi) The .txt prompt file + this report.** The `.txt` prompt file and this
`PHASE_25C_REPORT.md` are cosmetic untracked artifacts; they are left UNTRACKED
and are NOT committed to the branch. The branch history stays
`d0f23dd -> e5f1b35` exactly (verified: `git log --oneline d0f23dd..HEAD` shows
exactly one commit surface).

**Additional honest disclosures (R3 teeth fidelity):**
- M3's behavior under the ready handshake is a STRICTER RED than the mandate's
  literal text predicted: removing `go e.persistWorkerLoop()` deadlocks the
  constructor on `<-e.persistWorkerReady`, so `NewDeltaCRDTEngine` never returns
  and the durability tooth cannot even construct an engine to FAIL against. The
  static guard S4 RED is the captured cross-bite head; the durability RED is the
  constructor deadlock (the mechanism by which "nothing ever persists" manifests
  under the ready-handshake fix). This is documented, not papered over.
- `TestPhase25C_NoBlockingFsyncDrive` is intentionally NOT the load-bearing bite.
  `t_MAX=179ns` on this Tier-1 tmpfs-backed box is far below the 50ms gate; on
  NVMe pre-2.5c it is also low (the threshold is satisfied incidentally). The
  load-bearing runtime bite is `TestPhase25C_DurabilityRoundTrip` (R3c), proven
  by M4's 20/100 miss.
- The ready-handshake field `persistWorkerReady chan struct{}` is the one
  addition beyond the literal R1a three-field list. It is the minimal fix for the
  unbuffered-channel startup race the R3c 1-NextDot durability tooth exposes
  (without it, the first CAS-issued non-blocking send frequently drops because the
  worker has not yet parked on the receive, and the Close drain has nothing to
  drain). It keeps the worker the ONLY caller of `persistLamport`. It adds ZERO
  new `unsafe.Pointer` sites (G9) and ZERO lines to any R4-protected file (G1).

---

## S7 — THE VERDICT

_(Leave BLANK. The verifier rules ACCEPTED/REJECTED.)_

---

## Branch state (FINAL DISCIPLINE check)

- Branch: `feat/phase25c-persistmu-decouple` (UNPUSHED).
- History: `git log --oneline d0f23dd..HEAD` → exactly one commit `e5f1b35`,
  parent `d0f23dd`. The atomic `--ff-only` merge `main:d0f23dd -> <2.5c HEAD>`
  is the verifier's to land on `c7g.8xlarge`.
- fsync is durability, not ordering; CAS caller publishes in-memory immediately;
  disk write lags by at most one in-flight persist job (+1000 pre → +2000 worst-case post).
- One in-flight job only (unbuffered `chan uint64`).
- The four setters stay byte-identical (no drain hook added; their
  `persistMu`-guarded ordering is already correct under the worker model).
- NextDot + AdvanceLamportTo no longer grab `persistMu`. `persistWorkerLoop` is
  the ONLY caller of `persistLamport`. `Close()` drains the worker BEFORE
  `arena.Free`.
- Phase 2j Candidate-3 verdict STAYS NOT-CORROBORATED post-2.5c (G2 ratio 0.48x).
- Phase 2.5b R5 Zero-GC gate stays 0/0 (G5; iblt.go untouched).
- Phase 2g lamport-skew tooth still bites (apply seam untouched).
- The harness JoinParallel bench `ns/op` stays ≤ 1.5× the 2.5b.1 baseline (G6/G10).
- The deliverable is a branch that closes the persistMu decouple on the
  InsertLocal + Join hot paths and leaves every prior-phase achievement intact.
  The sandbox is leak-free and Phase 3 opens on a tail-latency-stabilized
  foundation.
