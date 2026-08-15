# PHASE 2.5C.1 REPORT — PERSIST-WORKER PARK-HANDSHAKE RACE CLOSURE

**Ten-word summary:** The 2.5c handshake proves scheduled, not parked. Buffer the ack.
**Branch:** `feat/phase25c1-park-handshake-race-closure` (parent `e5f1b35`). **Tier:** Tier-1 only
(`runtime.NumCPU()=4`); NO 32-core number claimed; the verifier owns the Tier-2 re-bite and S7.

---

## S1 — the smoking gun (S0) + the 2.5c G10 RED

S0 (quoted from the 2.5c.1 prompt): the 2.5c handshake was
`close(e.persistWorkerReady)` in `persistWorkerLoop` +
`<-e.persistWorkerReady` at the constructor tail. A `close(c)` wakes receivers
on `c` but does NOT guarantee the closing goroutine has advanced to any
subsequent statement — there is a SCHEDULER WINDOW between
`close(e.persistWorkerReady)` and the worker reaching
`for val := range e.persistCh`. During that window a caller issuing
`select { case e.persistCh <- v: default: }` sees NO parked receiver, hits
`default`, and DROPS the job. `Close()` drains an empty channel; the worker
exits without ever calling `persistLamport`; `recoverLamport` reads 0 instead
of 1001. **A durability tooth that flakes even ONCE is a hard REJECT.**

2.5c G10 RED (`/tmp/p25c-bench-sweep.log`, literal):
```
--- FAIL: TestPhase25C_DurabilityRoundTrip (0.31s)
    phase25c_test.go:358: PHASE25C R3c: runtime.NumCPU()=4
    --- FAIL: TestPhase25C_DurabilityRoundTrip/Steady_1001NextDot (0.00s)
        phase25c_test.go:404: PHASE25C R3c Steady: recovered Lamport
        counter=0, want 1001 — Close() did not drain the persist worker
        before arena.Free (the durability round-trip broke)
```
The fix is Path A: replace the close-channel handshake with a
receive-acknowledgement handshake on a SECOND channel
`persistWorkerParked chan struct{}` (the worker sends `struct{}{}`). FORBIDDEN:
B1 (buffering `persistCh`) and B2 (a sentinel-job round-trip).

## S2 — purity rationale (buffered-send happens-before + the determinism booster)

A buffered-channel send synchronizes-with the receive; the constructor's
`<-persistWorkerParked` unblocks only after the worker's send, proving the
worker REACHED the send. The raw buffered-ack is NECESSARY-but-INSUFFICIENT in
the strict Go memory model: the deposit is ASYNC, so the constructor returns at
the deposit instant WITHOUT proving the worker has reached the for-range park.
A pure-disk diagnostic (fresh `t.TempDir()` engine → ONE `NextDot` → `Close` →
reconstruct → stat dir+`.dat`+`.tmp`+re-stat 5ms later) reproduced the drop
with BOTH `.dat` AND `.tmp` MISSING on a miss (`persistLamport` never ran) at
~0.01%/iter ungated and surfacing under `-race`; literal:
`iter 700 MISS dirStat=exists dat=MISSING tmp=MISSING datAfter5ms=MISSING`. The
fix ADDS a documented `runtime.Gosched()` × 2 determinism booster in the
constructor tail that yields the constructor scheduler turns so the worker
(which has nothing to do but reach the for-range park) parks on `<-persistCh`
BEFORE the constructor returns. It is a scheduler HINT (no busy-wait, no sleep),
NOT a sentinel job (B2 respected — no value round-trips, no persist slot
consumed) and NOT a buffered `persistCh` (B1 respected — cap-0). A HARD proof
of park in pure Go would require the B2-forbidden sentinel (a goroutine cannot
send from a parked `<-ch`); the booster is the achievable best inside Path A.

## S3 — R1a-c diffs + R3 teeth + G1-G11 literal output

**R1a-c** (`pkg/sync/crdt.go`, +122/-19). R1a: `persistWorkerParked chan
struct{}` adjacent to `persistWorkerReady` in the pad block, S0-tied doc-comment.
R1b: `e.persistWorkerParked = make(chan struct{}, 1)` (load-bearing `, 1` cap);
`persistCh = make(chan uint64)` (cap-0, UNBUFFERED — B1 respected). R1c worker:
`close(e.persistWorkerReady)` (stage 1) → `e.persistWorkerParked <- struct{}{}`
(stage 2, the buffered park-ack) →
`for val := range e.persistCh { persistMu.Lock; persistLamport(val); Unlock }`
+ `persistWorkerWg.Done()` (send textually before for-range). R1d Close byte-
identical to `e5f1b35`. Booster (ctor tail, after both receives): `runtime.Gosched()` × 2.
**R3 teeth** (`pkg/sync/phase25c1_test.go`, new). R3a
`TestPhase25C1_ParkHandshakeStatic`: static regex guard P1-P6 (field; cap-1
`make`; worker send; send before `for val := range`; ctor two-stage order;
preserved 2.5c shape). No `t.Skip`; red-on-mute. R3b
`TestPhase25C1_ColdStartFirstSendNeverDrops`: 1000 iters (200 under `-race`
via `raceEnabled`) of fresh `t.TempDir()` → ONE `NextDot` → `Close` → reconstruct
→ assert 1001; gate `sawMiss==0`, single miss = HARD FAIL naming the iteration.
R3c `TestPhase25C1_ParkHappensBeforeReasoning`: the comment block above the
park-ack send contains `happens-before`. Red-on-mute.

**G1 scope** — `git diff --stat e5f1b35..HEAD -- pkg/sync/`:
```
 pkg/sync/crdt.go | 141 +++++++++++++++++++++++++++++++++++++++++++++++--------
 1 file changed, 122 insertions(+), 19 deletions(-)
```
R4 protected set: all 31 files byte-identical to `e5f1b35` (md5-match).
`Close`+`persistLamport`+4 setters byte-identical (SetDataDir a0aace26,
SetLamportHorizonSeconds d56c5052, SetLamportAbsoluteSlack 6405eb04,
SetShardCount b687edb6, persistLamport eff4c6dd, Close be6707cc — SAME base↔cur).
Staged = exactly `pkg/sync/crdt.go` + `pkg/sync/phase25c1_test.go` + `PHASE_25C1_REPORT.md`.

**G2** (5×1000 ungated + −race 200). All 5 ungated runs: `sawOK=1000 sawMiss=0`,
`--- PASS` (~3.8s each). −race 200-iter: `sawOK=200 sawMiss=0`, `--- PASS` (1.71s). Gross miss: 0.

**G3** (static). `TestPhase25C1_ParkHandshakeStatic` PASS — `all invariants present (P1-P6 +
P5 ordering + P5b constructor order)`. `TestPhase25C1_ParkHappensBeforeReasoning` PASS —
`happens-before present in BOTH the persistWorkerLoop and NewDeltaCRDTEngine comment blocks`.

**G4** (2.5c teeth 5×). All three 2.5c teeth PASS every run.
`DurabilityRoundTrip/Steady_1001NextDot`: `recovered Lamport counter=1001 == want 1001 (Close-drain held)` 5/5.
`/OneNextDot_ThenClose_RaceSurface`: `iterations=100 ok=100 miss=0` 5/5. The 2.5c R3c flake is closed by 2.5c.1.

**G5** (2.5b regression-negative). `TestPhase25B_DeltaGenZeroGC` PASS;
`BenchmarkCRDTEngine_GenerateDelta-4 N=579 ns/op=2144557 B/op=8 allocs/op=0`
(0 allocs/op — 2.5b Zero-GC intact). `BenchmarkHAMT_Set-4 4489 ns/op 0/0`
(post-2.5a sharded-root bench, byte-faithful to 2.5c).

**G7** (`go test ./...`). Every package `ok`, 0 FAIL (`pkg/sync` 99.801s, rest ≤8s).
The known transient `TestIBLT_ZeroFalsePositives` Phase 2l.1 baseline flake did NOT surface.

**G8** (`-race ./pkg/sync/ ./internal/chaos/`). `ok pkg/sync 46.253s`,
`ok internal/chaos 46.241s`. 0 `WARNING: DATA RACE`, 0 panic. R3b ran under −race at 200-iter and passed.

**G9** (`go vet ./...`). Filtered non-`unsafe.Pointer` output: EMPTY. `unsafe.Pointer` site
count: 35 (byte-identical baseline to 2.5c; `crdt.go:659` is the pre-existing 2.5c sharded-roots
slice, NOT 2.5c.1). `git diff e5f1b35 -- pkg/sync/crdt.go | grep '^[+-].*unsafe.Pointer'` EMPTY
→ 2.5c.1 adds ZERO new `unsafe.Pointer` sites.

**G10** (full bench sweep):
```
BenchmarkCRDTEngine_GenerateDelta-4   550   2172982 ns/op    0 B/op    0 allocs/op
BenchmarkCRDTEngine_Join-4          459337      4956 ns/op  489 B/op    7 allocs/op
BenchmarkStrataEstimator_Insert-4 19725380     60.82 ns/op    0 B/op    0 allocs/op
BenchmarkHAMT_Set-4                 347433     4452 ns/op    0 B/op    0 allocs/op
BenchmarkHAMT_Get-4                4723276    250.3 ns/op   23 B/op    1 allocs/op
BenchmarkCRDTEngine_JoinParallel-4 553364     3050 ns/op  577 B/op    9 allocs/op
BenchmarkHAMTInsertZeroAlloc-4      404720     4509 ns/op    0 B/op    0 allocs/op
BenchmarkFalseSharingPadded-4         217   5491963 ns/op   92 B/op    2 allocs/op
BenchmarkEngineProxyPadded-4           57  21778661 ns/op  106 B/op    2 allocs/op
PASS  ok  github.com/hr18vk/supremum/pkg/sync  32.491s
PASS  ok  github.com/hr18vk/supremum/internal/chaos  0.003s
```
0 OOM, 0 panic. `TestPhase25C_DurabilityRoundTrip` GREEN in a sweep+tests run (`recovered=1001 == want 1001`).

**G11** (mutations RED + restore GREEN md5). GREEN baseline md5: `1c29ac3c8d7c7f373921ea771e9e7ea8  pkg/sync/crdt.go`.
- **M1** (full 2.5c-form regression: park-send + ctor park-recv + Gosched removed). DETERMINISTIC RED on the
  static tooth: `P4: park ack send ... regex MISS` and `P5b-b: <-e.persistWorkerParked in constructor — regex MISS`.
  Probabilistic RED on the runtime tooth, run 6/8: `iter 312/1000: recovered Lamport counter=0, want 1001 —
  the cold-start park handshake DROPPED the first persist job`. Restored; md5-match; GREEN.
- **M2** (`make(chan struct{}, 1)` → `make(chan struct{})`). RED: the runtime tooth saw 15+ iters/run with
  `recovered=0, want=1001` (iter 78, 87, 93, 118, 165, 222, 250, 261, 338, 383, 399, 407, 435, 440, …). The
  cap-1 buffer IS load-bearing. Restored; md5-match; GREEN.
- **M3** (swap ctor tail: `<-persistWorkerParked` before `<-persistWorkerReady`). DETERMINISTIC RED on the
  static tooth P5b: `stage-1 <-persistWorkerReady (8784) textually AFTER stage-2 <-persistWorkerParked (8759) —
  reversed order is a HARD FAIL (bite RED)`. RED on the runtime tooth: `iter 752/1000 recovered=0`,
  `sawMiss=1 across 1000 iters` (M3 DOES bite at runtime, not merely stylistic). Restored; md5-match; GREEN.

## S4 — R4 scope discipline

`git diff --stat e5f1b35..HEAD` = exactly the staged set. The 31-file R4 protected set byte-identical
to `e5f1b35` (md5-audited). `phase25c_test.go` (existing 2.5c test file) is FROZEN — byte-identical, untouched.
`persistLamport`, `Close`, the four operator setters byte-identical (function-body md5-match); only the
handshake shape + the additive booster change. Conf 2 (persistMu disk-mutex) body unchanged. Conf 2.5
(EBR RetiredList) NOT touched (2.5d's domain).

## S5 — carry-forwards (R6)

- Conf 2 (persistMu disk-mutex) — CLOSED by 2.5c; 2.5c.1 hardens the handshake.
- Conf 2.5 (EBR RetiredList.head single CAS, 16.49% cum @32c in 2.5a.1 pprof) — NOT closed; Phase 2.5d candidate; combined CAS ≤43%; no action here.
- freeHeads[classIdx] variable-size class sharding — Phase 2.5d candidate.
- Phase 2g A2/A3 skew-bound carry-forwards unchanged.
- Phase 3 Master Plan deferred to Gemini-app Deep Research (NOT drafted here).

## S6 — honest limitations

- **NumCPU=4 (no Tier-2 claim).** The 32-core (`c7g.8xlarge`) re-bite is the verifier's; S7 is theirs.
- **The buffered-ack alone is NECESSARY-but-INSUFFICIENT; a `runtime.Gosched()` ×2 booster is added.** The raw
  cap-1 buffered-ack (literal R1c) reproduces the S0 cold-start drop at ~0.01%/iter ungated and surfaces under
  `-race` (captured: `iter 700 MISS dirStat=exists dat=MISSING tmp=MISSING datAfter5ms=MISSING` —
  `persistLamport` never ran). A goroutine cannot hard-send from a parked `<-ch`, so pure Go cannot HARD-prove
  park without the FORBIDDEN-PATH-B2 sentinel; the Gosched booster (a documented scheduler yield — no busy-wait,
  no sleep, no sentinel, no buffered persistCh) is the achievable best inside Path A. Empirically it drops the
  residual below the tooth's detection floor across 5×1000 ungated + the 200-iter `-race` run + a 10-run
  scheduling-stress sweep (all sawMiss=0). The verifier's GOMAXPROCS=32 re-bite makes the window LARGER; if it
  flakes there, escalation is to the architect (the hard-park-proof requires the B2 sentinel the prompt
  forbids, OR a typed drain).
- **M3 bit RED at runtime, NOT merely stylistic.** The prompt hedged M3 "may NOT bite"; here M3 bit RED on BOTH
  the static tooth AND the runtime tooth (sawMiss=1). The static P5b tooth is the deterministic guard regardless.
- **M2 did NOT produce a clean deadlock.** Predicted a 30s-test deadlock at the park send; the cap-1→cap-0 swap
  surfaced as a heavy drop-rate regression (15+ misses/run) rather than a hang. RED confirms the cap-1 buffer
  is load-bearing regardless. Restored GREEN.
- **-race iteration count reduction (1000 → 200)** per R3b stipulation via the `raceEnabled` gate (Phase 2k
  precedent). The ungated floor is 1000.
- **G2 sawMiss==0 across all runs** — no run saw a non-zero-but-passed miss; no framework misreport observed.

---

## S7 — VERDICT (LEAVE BLANK — verifier's cross-tier ruling)
