# PHASE 2m — TOOTH -RACE POLISH (EXECUTOR REPORT)

Branch: `feat/phase2m-tooth-race-polish` off `b854a8a`, not pushed. One file, one
function, one R1a block replacement + one R1d doc-comment line. `forcedN` stays
`1_000_000` (2x the ~500K no-reclamation OOM threshold). Verifier rules from §3.

## §1 — THE EDIT (R1a verbatim + R1d line)

**R1a** — Part 2 block replacement (deletes the
`testing.Benchmark(BenchmarkHAMT_Set)` call + its t.Logf/result-fatal; adds the
`raceEnabled` `t.Skip` guard before `const forcedN`):

```go
// --- Part 2: RUNTIME forced-N drive ---------------------------------
// Drive the bench's exact steady-state contract at forced N=1_000_000,
// double the documented ~500K no-reclamation OOM threshold. A green
// drive means the 2 GiB arena reached steady state under the Retire +
// AdvanceEpoch pair; a regressed bench (or a regressed drive loop)
// panics at hamt_arena.go:329.
//
// Phase 2m: under -race the framework-scaled testing.Benchmark call
// that previously lived here timed out (the race detector's
// shadow-memory instrumentation slows the exponentially-scaled b.N
// loop 5-10x until the 1s wall-clock budget can never converge —
// panic: test timed out). That call was ALSO architecturally
// confused: a tooth must AUDIT the bench, not INVOKE the bench
// framework. It has been deleted; the forced-N drive below is the
// no-OOM proof and uses an inlined copy of the bench's exact loop.
//
// The forced-N drive is single-goroutine sequential throughput
// (NOT a data-race surface); the race detector perturbs its timing
// but adds no race coverage. Per the Phase 2k precedent
// (TestHotPathZeroAllocations at physics_test.go:198), the drive
// SKIPS under -race. The static guard above runs unconditionally
// (it is an os.ReadFile + regexp.MatchString, no -race surface).
// Concurrent race coverage is carried by TestConcurrentInsertLocalRace,
// TestConcurrentJoinRace, and TestPhase2J_JoinParallelContentionCurve.
if raceEnabled {
    t.Skip("PHASE2l TOOTH (forced-N drive): -race instrumentation perturbs " +
        "the single-goroutine steady-state drive (5-10x slowdown; the " +
        "drive would exceed the test timeout). The static source guard " +
        "above already PASSED; the no-OOM drive runs un-raced. The race " +
        "coverage is carried by TestConcurrentInsertLocalRace / " +
        "TestConcurrentJoinRace / TestPhase2J_JoinParallelContentionCurve. " +
        "Mirrors the Phase 2k TestHotPathZeroAllocations precedent at " +
        "physics_test.go:198.")
}
const forcedN = 1_000_000
```

The forced-N drive loop body (NewHamtArena 2 GiB, warmEBRPool, the for-loop with
`fmt.Sprintf` key + Set + `arena.ebr.Retire(unsafe.Pointer(prev))` +
`arena.ebr.AdvanceEpoch()`, closing t.Logf) stayed BYTE-IDENTICAL.

**R1d** — additive doc-comment note after line 30's mutation-contract paragraph:

```go
//
// Phase 2m: the runtime drive is now guarded by raceEnabled (Phase 2k
// precedent) and the redundant testing.Benchmark call has been removed;
// see the Part 2 inline comment for the structural rationale.
```

No other function/file/import/helper/bench/tooth touched. No new tooth (R4 honored).

## §2 — WHY ARCHITECTURALLY PURE

1. Tooth stays TWO-part: (a) STATIC regex guard (os.ReadFile + strings.Index +
   regexp.MatchString on hamt_test.go) bites a bench-side regression in <1s at zero
   runtime cost; (b) RUNTIME forced-N drive proves the 2 GiB arena reaches steady
   state at 1M ops (2x the ~500K no-reclamation OOM threshold, PHASE_2I Gate 5). Both preserved.
2. The deleted `testing.Benchmark(BenchmarkHAMT_Set)` call was REDUNDANT with the drive
   (same loop contract) AND architecturally confused (a tooth INVOKING the framework
   bench runner the tooth AUDITS). Removal is pure purification, not a coverage loss.
3. The forced-N drive is single-goroutine sequential throughput — by construction NOT a
   data-race surface. The race detector perturbs its timing (5-10x; cannot converge in
   any sane per-test timeout) but adds NO race coverage. Skipping under -race mirrors
   the Phase 2k precedent: `TestHotPathZeroAllocations` at physics_test.go:198 skips
   its `testing.AllocsPerRun` closure under -race because the race detector perturbs the
   MEASUREMENT, not because there is a race to find. Concurrent race coverage is carried
   by `TestConcurrentInsertLocalRace` / `TestConcurrentJoinRace` /
   `TestPhase2J_JoinParallelContentionCurve` (all -race PASS, re-confirmed in G4).
4. The STATIC regex guard runs UNCONDITIONALLY under -race (os.ReadFile + strings.Index
   + regexp.MatchString — no -race surface). The tooth STILL BITES a bench-side regression
   under -race in <1s (M4a RED). Surgical trade: skip the slow drive, keep the fast guard.

The verifier's forensic stack — reproduced in MY own hands in G9 — proved the -race
panic fired at `phase2l_staticaudit_test.go:96` (the `testing.Benchmark` call), reached
via `testing.Benchmark` at `testing/benchmark.go:1019` → `doBench` at
`testing/benchmark.go:297`, NOT at the forcedN loop at lines 138-144. The static guard
at line 87 had ALREADY logged its PASS before the timeout. This is the Phase 2k
-race-instrumentation shape; the clean fix is to skip the perturbed measurement path,
NOT to downgrade its denomination (the Orchestrator's `forcedN=100K` would edit the
WRONG line AND neuter the tooth — refused).

## §3 — GATES (literal output; `GOCACHE=/tmp/p2m-gc` + `GOMAXPROCS=32` on each)

Box note: the executor's farm box exposes `runtime.NumCPU()==4` (docker-limited), NOT
the verifier's 32-core c7g.8xlarge. `GOMAXPROCS=32` is declared on every command as
mandated; race-detector slowdown, expanding-b.N convergence, and the OOM threshold
contract are core-count invariant. The verifier's re-bite on c7g.8xlarge is the
authoritative timing re-ratification.

**G2 — -race isolated tooth — GREEN+SKIP fast (HEADLINE)**
```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:87: PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set
    phase2l_staticaudit_test.go:114: PHASE2l TOOTH (forced-N drive): -race instrumentation perturbs the single-goroutine steady-state drive ... Mirrors the Phase 2k TestHotPathZeroAllocations precedent at physics_test.go:198.
--- SKIP: TestPhase2L_HAMTSetReclamationTooth (0.00s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	1.020s
```
Static guard PASS @ line 87 unconditional; `t.Skip` @ line 114; GREEN in 1.02s.

**G3 — Un-raced isolated tooth — GREEN, drive completes**
```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:87: PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set
    phase2l_staticaudit_test.go:147: PHASE2l TOOTH (forced N=1000000): arena reached steady state, no OOM
--- PASS: TestPhase2L_HAMTSetReclamationTooth (5.35s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	5.360s
```

**G4 — -race FULL pkg/sync suite — GREEN, 0 FAIL / 0 RACE / no timeout**
```
ok  	github.com/hr18vk/supremum/pkg/sync	37.988s  EXIT_G4=0
```
Verbose recount (separate -v run): `FAIL: `=0, `DATA RACE`=0, `panic: test timed out`=0,
`SKIP: TestPhase2L_HAMTSetReclamationTooth`=1. The gate the whole phase exists to deliver.

**G5 — Un-raced bench sweep — 0 OOM, `0 B/op · 0 allocs/op` preserved**
```
OOM=0
BenchmarkHAMT_Set-32               413077    4497 ns/op    0 B/op    0 allocs/op
BenchmarkHAMTInsertZeroAlloc-32    393210    4529 ns/op    0 B/op    0 allocs/op
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	18.814s  EXIT_G5=0
```

**G6 — Un-raced Phase 2 battery — all PASS**
```
--- PASS: TestPhase2L_HAMTSetReclamationTooth (5.41s)
PASS
ok  	github.com/hr18vk/supremum/pkg/sync	11.178s  EXIT_G6=0
```
`--- PASS: TestPhase2{|L|I|J}` count = 15; `FAIL: TestPhase2…` = 0.

**G7 — Un-raced `go test ./...` — 9 packages ok, 0 FAIL**
```
ok  	github.com/hr18vk/supremum/pkg/sync	20.743s
ok count: 9   EXIT_G7=0
```

**G8 — `go vet ./...`**
- non-unsafe.Pointer warnings: 0
- `unsafe.Pointer` warnings across the whole tree: **26** (UNCHANGED from b854a8a; R1
  does not touch unsafe.Pointer usage; the drive's `unsafe.Pointer(prev) Retire` line
  is byte-identical).

**G9 — R3 M3 RED + restore GREEN (mutation-verify M3)**
M3 = undo R1 (restore the `testing.Benchmark(BenchmarkHAMT_Set)` call + t.Logf/result-fatal,
remove the `raceEnabled` `t.Skip` guard). R1 saved to `/tmp/p2m_r1.bak` first.
Command: `... -count=1 -race -v -timeout=30s`. RED literal (core):
```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:87: PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set
panic: test timed out after 30s
	running tests: TestPhase2L_HAMTSetReclamationTooth (30s)
goroutine 21 [chan receive]:
testing.(*B).doBench(...) /home/ubuntu/go/src/testing/benchmark.go:297
testing.(*B).run(...)     /home/ubuntu/go/src/testing/benchmark.go:291
testing.Benchmark(...)     /home/ubuntu/go/src/testing/benchmark.go:1019
github.com/hr18vk/supremum/pkg/sync.TestPhase2L_HAMTSetReclamationTooth(...)
	/workspace/sovereign-engine/pkg/sync/phase2l_staticaudit_test.go:96
FAIL	github.com/hr18vk/supremum/pkg/sync	30.045s FAIL
```
Stack proves panic at the `testing.Benchmark` call (line 96 → benchmark.go:1019 →
doBench benchmark.go:297), NOT at the forcedN loop. Static guard @ line 87 PASSED in
<1s before the timeout. M3 RED confirmed in MY own hands. Restored R1 from
`/tmp/p2m_r1.bak`; md5 `408854597ce028aa065d391a881126cc` == `408854597ce028aa065d391a881126cc` MATCH.
Re-ran -race isolated tooth post-restore: GREEN+SKIP in 1.02s (matches G2).

**G10 — R3 M4 RED (M4a -race + M4b un-raced) + restore GREEN**
M4 = disable the reclamation contract. The static regex guard scans hamt_test.go;
the forced-N drive is an inline copy of the same loop in the test file. To prove BOTH
bites from one contract regression, `arena.ebr.Retire(unsafe.Pointer(prev))` was
commented out at BOTH sites (hamt_test.go:286 bench side + the test drive loop at
phase2l_staticaudit_test.go:144). Each comment paired with a single
`_ = unsafe.Pointer(prev)` ref so the mutant compiles (`prev` otherwise unused); that
placeholder is NOT a Retire call and cannot regress the contract forward. Backups:
`/tmp/p2m_hamt_test.bak`, `/tmp/p2m_r1.bak`.

M4a — under -race, the static regex guard must FAIL immediately (<1s):
```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:71: PHASE2l TOOTH: BenchmarkHAMT_Set is missing 'arena.ebr.Retire(unsafe.Pointer(prev))' — the EBR reclamation contract has regressed; the bench will OOM at ~500K ops
    phase2l_staticaudit_test.go:85: PHASE2l TOOTH: static guard FAILED — see errors above
--- FAIL: TestPhase2L_HAMTSetReclamationTooth (0.00s)
FAIL	FAIL	github.com/hr18vk/supremum/pkg/sync	0.022s
```
RED in 0.022s under -race — the runtime drive never runs (guard `t.Fatalf` aborts
first). M4a proves the tooth STILL BITES under -race purely from the unconditional regex.

M4b — UN-RACED, the forced-N drive must PANIC. For THIS forensic mutant only, the
guard's `t.Fatalf` was relaxed to `t.Logf` so the drive is allowed to run (harness
scaffold only; never shipped — restored from `/tmp/p2m_r1.bak` afterward):
```
=== RUN   TestPhase2L_HAMTSetReclamationTooth
    phase2l_staticaudit_test.go:71: PHASE2l TOOTH: BenchmarkHAMT_Set is missing 'arena.ebr.Retire(unsafe.Pointer(prev))' — ...
    phase2l_staticaudit_test.go:88: PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set
--- FAIL: TestPhase2L_HAMTSetReclamationTooth (4.05s)
panic: HamtArena: OOM - arena exhausted [recovered, repanicked]
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).bumpAllocateNode(...)
	/workspace/sovereign-engine/pkg/sync/hamt_arena.go:261
github.com/hr18vk/supremum/pkg/sync.(*HamtArena).AllocNode(...)
	/workspace/sovereign-engine/pkg/sync/hamt_arena.go:252
...
github.com/hr18vk/supremum/pkg/sync.(*HAMT).Set(...)
	/workspace/sovereign-engine/pkg/sync/hamt.go:206
github.com/hr18vk/supremum/pkg/sync.TestPhase2L_HAMTSetReclamationTooth(...)
	/workspace/sovereign-engine/pkg/sync/phase2l_staticaudit_test.go:144
FAIL	github.com/hr18vk/supremum/pkg/sync	4.060s FAIL
```
The forced-N=1M drive panics with `HamtArena: OOM - arena exhausted` via
`Set → AllocNode → bumpAllocateNode` (hamt_arena.go:261, fixed-size bump allocator short
form). Set only allocates fixed-size HAMT nodes, so the fixed-size bump allocator
exhausts first; the variable-alloc form `HamtArena: OOM - arena exhausted (variable
alloc)` at hamt_arena.go:329 sits on a path Set never reaches. Both are the
"HamtArena: OOM - arena exhausted" death-family Phase 2i Gate 5's ~500K no-reclamation
OOM threshold refers to; with Retire commented out the three-epoch EBR ring never
recycles slab offsets and the 2 GiB arena exhausts before 1M iterations complete.

Restored R1 + hamt_test.go from /tmp .bak; md5 phase2l_staticaudit_test.go MATCH
(`408854597ce028aa065d391a881126cc`), md5 hamt_test.go MATCH
(`27e9e2e9850a004b714a1a6b1951a4e1`). Re-ran G3 post-restore: GREEN PASS in 5.30s.
Re-ran G2 post-restore: GREEN+SKIP in 1.022s. R1 GREEN restored both ways.

## §4 — SCOPE DISCIPLINE

```
$ git diff b854a8a --stat
 pkg/sync/phase2l_staticaudit_test.go | 38 ++++++++++++++++++++++++++++++------
 1 file changed, 32 insertions(+), 6 deletions(-)
```
Exactly 1 file changed. Every R4-protected path individually diffed against b854a8a is
empty: `pkg/sync/{crdt.go,crdt_apply.go,crdt_apply_batch.go,crdt_reconstruct.go,crdt_reconstruct_skew.go,hamt.go,hamt_arena.go,hamt_test.go,physics_test.go,race_enabled_test.go,race_enabled_off_test.go,crdt_test.go}`.

Production set md5 (UNCHANGED before == after):
```
64dad041890b1566038622de70cf0022  pkg/sync/crdt.go
bc03bdb31c16c526a0c999ced7ac1501  pkg/sync/hamt.go
b4947bb53221a5f07ef55f12057e7074  pkg/sync/hamt_arena.go
ed9132a27930b3d76a3f62e783dd7dd3  pkg/sync/crdt_apply.go
e8422f6d785fbd7738659e81b61ddf28  pkg/sync/crdt_apply_batch.go
f856f0fa2a05dbb2c20f2dc0087a995e  pkg/sync/crdt_reconstruct.go
e755d8945052a081011335801e0bdc27  pkg/sync/crdt_reconstruct_skew.go
27e9e2e9850a004b714a1a6b1951a4e1  pkg/sync/hamt_test.go
413dd7b8537d88bb91ccf8060b5863e0  pkg/sync/physics_test.go
c0451559ad41dc8e1e2f1d07ccae7bb3  pkg/sync/race_enabled_test.go
79c83f5bf5bded23a936636ed2436df0  pkg/sync/race_enabled_off_test.go
```
Sanctioned file md5: `e68d368410379462ac3a2b976ac2aac7` (b854a8a) → `408854597ce028aa065d391a881126cc` (R1).

## §5 — CARRY-FORWARDS (one line each)

- Production code (crdt.go, hamt.go, hamt_arena.go, crdt_apply*, crdt_reconstruct*) UNTOUCHED (md5-identical to b854a8a).
- Phase 2l reclamation contract still pinned by the static regex guard under -race (M4a RED bites in <1s unconditionally).
- Phase 2l.1 zero-alloc key shape in hamt_test.go UNTOUCHED (md5 unchanged, G5: 0 B/op · 0 allocs/op).
- InsertLocal + BenchmarkHAMTInsertZeroAlloc remain the Zero-GC contract bearers (G5).
- parallel-Join CAS-storm regression from Phase 2j (14.4x under GOMAXPROCS=1→32) UNSUBSIDIZED — Phase 3 carry-forward, NOT a Phase 2m deliverable; do NOT touch.
- 26 unsafe.Pointer vet baseline UNCHANGED (G8).

## §6 — HONEST LIMITATIONS

(i) The race-gated skip is a coverage trade: the forced-N=1M no-OOM drive no longer
runs under -race. Coverage carried by (a) the un-raced gate G3 (5.30s PASS at 1M ops,
no OOM) + (b) the static regex guard which DOES run under -race and bites a bench-side
regression in <1s (M4a RED). The drive is single-goroutine sequential throughput — NOT
a data-race surface — so no race coverage is lost.
(ii) The t.Skip reason is a long string because it documents the exact carry-out
(static guard status, where the no-OOM drive runs, who carries race coverage, and the
Phase 2k precedent reference). Intentional, NOT a style slip.
(iii) `GOMAXPROCS=32` declared on every command as mandated. Executor's farm box
exposes `runtime.NumCPU()==4` (docker-limited), NOT the verifier's 32-core c7g.8xlarge.
Race-detector slowdown, expanding-b.N convergence, and the OOM threshold contract are
core-count invariant; only absolute wall-clocks scale, and none of the gates hinge on
absolute core count. The verifier's re-bite on c7g.8xlarge is the authoritative timing
re-ratification.
(iv) The Phase 2i Gate 5 ~500K OOM threshold is preserved EXACTLY: `forcedN` stays
`1_000_000` — the Orchestrator's `forcedN=100K` neuter was refused. The
2x-above-threshold ratio IS the tooth's bite; preserved verbatim.
- M4b's panic fires at `hamt_arena.go:261` (the fixed-size bumpAllocateNode short
  form `panic("HamtArena: OOM - arena exhausted")`). Set only allocates fixed-size HAMT
  nodes, so the fixed-size bump allocator exhausts first; the doc-comment's cited
  variable-alloc form at hamt_arena.go:329 sits on a path Set never reaches. Both are
  the "HamtArena: OOM - arena exhausted" death-family Phase 2i Gate 5 refers to; the
  test's forced-N drive pins the same ~500K threshold via the fixed-size path.

## §7 — THE VERDICT

(LEAVE BLANK — the verifier rules ACCEPTED/REJECTED. On ACCEPT the verifier lands the
atomic --ff-only merge to main and re-bites M3 + M4a + M4b on the post-merge tree in
their own hands.)
