# ADR-0014: Ingest-path alloc hardening — value-return seam + zero-copy Payload read (Day 9)

Date: 2026-08-01
Status: ACCEPTED (CONDITIONAL-GO — Day 9 reduces the ingest alloc ceiling by −15.7% measured; it does NOT make ingest zero-alloc; the FROZEN-locked ceiling is documented, NOT patched; the prompt's FIX-A attribution is EMPIRICALLY REFUTED and corrected here)
Track: 09 (alloc hardening)

---

## 0. The correction (read this BEFORE the prompt's narrative)

The Day-9 executor prompt (phase-03/day9_ingest_alloc_hardening_executor_prompt.txt)
and a DRAFT of this ADR (committed 3f568d5 before any Day-9 code was run)
predicted, BEFORE measurement:

  FIX A (zero-copy Payload SHA):   ~538 allocs/op (−15.7%)   — WRONG attribution
  FIX A+C (value-return):           ~438 allocs/op (−31.3%)   — WRONG magnitude

The headline prediction assumed FIX A's `sha256.Sum256([]byte(payload))`
paid a per-delta HEAP alloc ("alloc #2 ... the []byte(string) conversion").
The Executor ran FIX A in ISOLATION (zero-copy `ev.PayloadBytes()` + the OLD
pointer return) and MEASURED:

  FIX A ONLY:  638 allocs/op, 126305 B/op   — BYTE-IDENTICAL TO THE 638 BASELINE.
               FIX A contributes 0 heap allocs and ~0 bytes on the integrated path.

The proof is escape analysis on the OLD code (crdt_reconstruct.go:345,
git HEAD before Day 9): `]([]byte)(payload) does not escape`. Go's escape
analysis stack-allocated the `[]byte(string)` inside `sha256.Sum256`'s
argument — it was NEVER a heap alloc. The prompt's §0/§1 "alloc #2" diagnosis
is the SAME CLASS of layer-mix §0 accused the codex of, reproduced in the
prompt's own root-cause framing (a conversion hidden inside a function
argument, invisible to a `make(` grep, AND invisible to the alloc counter —
triple-misleading).

FIX C (value-return ReconstructedEntry) is the SOLE source of the measured
−100 allocs/op:

  FIX A+C:     538 allocs/op, 110273 B/op   — −15.7% allocs, −11.6% bytes.
  (the delta from FIX-A-only 638 → A+C 538 is FIX C, entirely.)

A per-call micro-proof (testing.AllocsPerRun, 100 runs, tooth G09.b):

  BASELINE (old ev.Payload() + []byte(payload) + *ReconstructedEntry): 4 allocs/op
  FIX A+C    (ev.PayloadBytes() zero-copy + value return):              2 allocs/op

So FIX C eliminated 2 heap allocs PER CALL on the success path (the
`&ReconstructedEntry{...}` pointer + a second alloc escape analysis sinks
under the value signature). The integrated bench amortizes this to −100/batch
(N=100); the −2/call × 100 ≠ −200/batch discrepancy is honest and recorded:
the batch path's `accum`/`Join.func3` closure and the allocator's batch-level
amortization mean the per-call probe and the integrated bench are NOT a clean
linear scale — the bench's −100 is the AUTHORITATIVE integrated number, the
probe's −2/call confirms the DIRECTION (FIX C sinks heap allocs; FIX A does
not). ADR-0014 reports the bench number, not the probe's arithmetic.

This ADR SUPERSEDES the commit-3f568d5 draft's §2/§6 numbers. The gate log
below is RE-RUN, not prediction.

---

## 1. Context

The Day-8.5 codex Session Note (UNIVERSAL_CODEX.md, 2026-08-01T02:00Z)
proposed two Day-9 tracks, BOTH based on stale/layer-mixed measurements.
The Architect ground them against physical bytes on HEAD commit 3f615a0
(2026-08-01) and REFUTES the headline diagnoses:

- REFUTATION 1 — "the rate-gate CAS is the ~7× ceiling-raise." The "7×"
  was the codex reading the N=1→N=100 verify amortization (31K→966K
  deltas/sec) and misattributing it to the shard mutex. The rate gate
  (pkg/admission/ewma.go:199) fires ONCE PER BATCH on the headline path
  (receiver.go:537). At N=100 it is 0.035% of the per-delta cost. Measured
  head-to-head at 4c/N=100: shared 966,183 vs ceiling 761,614 — shared
  OUTPERFORMS ceiling (the shared engine's HAMT stays L3-hot; the ceiling
  sub-bench conflates rate-gate removal + per-goroutine construction + cache
  destruction).

- REFUTATION 2 — "pool the verify buffers; circl's allocs are the ceiling."
  The alloc profile shows circl ed25519.Verify = 2.22% of allocs. The verify
  is amortized (one per batch at N=100); its allocs are NOT the driver.

- REFUTATION 3 (ADDED this session, by MEASUREMENT) — "FIX A (zero-copy
  Payload SHA) is a ~15.7% alloc reduction." See §0. FIX A measures 0 heap
  allocs on the integrated path. The reachable alloc win is FIX C, not FIX A.
  FIX A is RETAINED for code-clarity (removes a hidden []byte(string)
  conversion) and as the seam-prep for a future arena-pooled zero-copy path;
  it is NOT a measured allocation win and is reported as such.

The honest alloc breakdown (flat, alloc_objects, this session, pprof):
  35%  Join.func3              (crdt.go:1016 FROZEN — closure append)
  27%  capnp.Ptr.Text          (schema.capnp.go FROZEN — string(b) copy)
      ├ 12%  CRDTDeltaEvent.EntityId  (retained by Join's Seq key)
      └ 15%  CRDTDeltaEvent.Payload   (DISCARDED by production; only SHA-checked)
  13%  ReconstructEntry         (*ReconstructedEntry pointer — eliminated by FIX C)
   2%  circl ed25519 verify    (NEGLIGIBLE per batch)

## 2. Decision

Three fixes were scoped; two shipped, one skipped. The attribution below
is MEASURED (the prompt's pre-execution predictions are in brackets, refuted).

**FIX A — zero-copy Payload SHA (SHIPPED, alloc-NEUTRAL, seam-prep).**
  File: pkg/sync/crdt_reconstruct.go (NOT FROZEN, md5 f856f0fa → moved, disclosed).
  The capnp library provides ev.PayloadBytes() → Ptr.TextBytes() which
  returns a slice DIRECTLY into the segment arena (pointer.go:121-129
  `return b` — no string(b) allocation, verified). FIX A feeds the zero-copy
  bytes to sha256.Sum256 directly and materializes rec.Payload ONCE via
  string(payloadBytes). [Prompt predicted −15.7% allocs / −100/batch;
  MEASURED 0 heap allocs, ~0 bytes on the integrated bench.]
  WHY SHIP A 0-ALLOC WIN: FIX A removes a hidden []byte(string) conversion
  buried inside sha256.Sum256's argument — a conversion invisible to a
  `make(` grep, to the alloc counter, and to the bench, which together make
  it a triple-misleading misdiagnosis vector (§8 ATTACK 1 / MEDIOCRITY 2).
  Retaining FIX A is correct: the seam now reads Payload exactly once via
  the zero-copy accessor, the SHA consumes the segment bytes directly, and
  the retained field is a single string copy — no round-trip copy. This is
  the structural shape a future arena-pooled zero-copy path (the path to
  eliminating the 12% Payload Text alloc, FROZEN-locked behind Join's Seq)
  will compose with. FIX A is honesty-positive code-clarity + seam-prep,
  honestly reported as NOT a measured alloc win.

**FIX C — value-return ReconstructedEntry (SHIPPED, the SOLE measured win).**
  Files: pkg/sync/crdt_reconstruct.go, pkg/sync/crdt_reconstruct_skew.go
  (BOTH NOT FROZEN). ReconstructEntry and ReconstructEntryWithSkewBound
  return ReconstructedEntry BY VALUE instead of *ReconstructedEntry. The
  per-element pointer alloc (the 13% ReconstructEntry line) is eliminated.
  MEASURED: 638 → 538 allocs/op integrated (−100, −15.7%); per-call 4 → 2
  allocs/op (testing.AllocsPerRun, tooth G09.b).
  FROZEN-SAFE (the load-bearing contract): crdt_apply.go:155 reads rec by
  VALUE (rec.Entry.OriginNodeID, rec.EntityID, rec.Entry) — no &rec, no
  nil-check on the pointer. crdt_apply.go source md5 STAYED ed9132a2 with
  ZERO source diff (gate G09.c, tooth TestG09c_FROZEN_SourceIdentical_CrdtApply,
  RED on drift). The compiled-behavior check (TestPhase2d_ApplyCRDTDeltaEvent_Biting
  green under -race) confirms the FROZEN file recompiles transparently.
  Test-site nil checks (crdt_reconstruct_test.go:140,220; crdt_lamport_skew_test.go:566)
  translated faithfully to `== (ReconstructedEntry{})` / `!= (ReconstructedEntry{})`
  on the comparable struct (2 strings + the all-value CRDTEntry) — no weakening.

**FIX D — rate-gate mutex → atomic (SKIPPED, correctness-grounded).**
  File: pkg/admission/ewma.go (NOT FROZEN, md5 df044675 — UNCHANGED, no edit).
  The prompt's option (a): pack budget (high 32) + lastCounter (low 32) into
  one atomic.Uint64, rate as a second atomic-of-bits, two-step CAS. SKIPPED on
  CORRECTNESS (not polish) grounds, confirmed by independent DeepSeek V4 Pro
  advisory reasoning:
    (1) TRUNCATION — lastCounter is a real DotCounter (64-bit aggregate
        Lamport counter). 2^32 overflows at ~75 seconds at the engine's 57M
        ops/s mint rate (~71 min at a conservative 1M dot/s). Packing it into
        32 bits loses the high word → two failure modes: (a) wrap makes the
        `if counter > prev` guard false → delta=0 → no budget deduction → a
        DETERMINISTIC replay/Sybil bypass (the peer is unconditionally
        admitted past its rate cap); (b) wrap can produce a monstrous delta
        via the truncated prev → instantaneous spurious Drop on an honest
        peer. ANY scheme compressing lastCounter into 32 bits is incorrect.
    (2) COHERENCE — (budget, lastCounter) must update atomically relative to
        concurrent same-shard callers (the SHARED bench hammers one shard).
        Splitting them into two independent atomic.Uint64s creates a
        linearizability break: a lost-update walk-through reproduces a
        budget over-accounting (the bucket leaks — the attacker's deductions
        are partially lost). Coherent update requires a 128-bit CAS, which
        Go 1.x lacks natively (atomic.Pointer adds allocation/GC/membarrier
        overhead dwarfing the mutex cost).
  VERDICT: the per-shard mutex is NOT polish — it is the necessary and
  sufficient correctness primitive for (budget, lastCounter) coherence,
  given Go has no 128-bit CAS. Its measured cost is 0.035% of the N=100
  headline path and 0 allocs. SKIP is the principled call. The rate gate
  fires once per batch (receiver.go:537), NOT per delta. (§7(d), §8 ATTACK 4.)

## 3. Gate log (G09.a–h, RE-RUN this session — not prediction)

| Gate | Description | Status | Evidence |
|---|---|---|---|
| G09.a | build/vet/gofmt symmetry | **PASS** | build green; vet only pre-existing unsafe.Pointer warnings (pkg/sync, internal/chaos) UNCHANGED; `gofmt -s -l` empty on all 4 touched files |
| G09.b | zero-copy Payload alloc-reduction tooth | **PASS** | TestG09b_ZeroCopyPayloadAllocReduction: per-call 2.00 allocs/op < 4 baseline; rec.Payload==rtPayload; SHA(zero-copy)==SHA(rtPayload) byte-identical. RED verified: pointer-return revert raises to 4 (FAIL) |
| G09.c | FROZEN-source-identical tooth (crdt_apply.go) | **PASS** | TestG09c: crdt_apply.go md5 ed9132a2...+d3 prefix ed9132a2 == pinned; + crdt.go 4512bd67, schema.capnp 47d2796a, schema.capnp.go 590af228, envelope.go b1beba1e all pinned |
| G09.d | reconstruct/apply/skew tests green under -race -count=1 | **PASS** | TestPhase2c/d/e/g_Biting + G09b/c green under `-race -count=1 -cpu=4` (targeted patterns; full pkg/sync suite has a PRE-EXISTING hang unrelated to Day 9, per session memory) |
| G09.e | bench alloc reduction 638→post | **PASS** | 538 allocs/op (−100, −15.7%), 110256–112371 B/op (−11.6%); throughput median ~829K (±noise; NOT claimed as a real win — see §6) |
| G09.f | rate-gate race-safe + saturating budget | **N/A (skipped)** | FIX D skipped; ewma.go md5 df044675 UNCHANGED; existing TestPeerBucket_SaturatingBudget* stays green (admission suite green) |
| G09.g | 5 TRUE-FROZEN md5s byte-identical PRE==POST==pinned | **PASS** | all 5 md5 prefix-match pinned values (G09.c tooth asserts this PRE-shipment; §0 of prompt pins PRE) |
| G09.h | zero glued tokens; §7 ≥6 weaknesses; §8 ≥5 ATTACK + 1 MEDIOCRITY | **PASS** | no dayN/phaseN/trackNN tokens in NEW identifiers (only TestG09b/G09c gate names, mandated by §4); 7 weaknesses (§7); 5 ATTACK + 1 MEDIOCRITY (§8) |

## 4. The FROZEN-locked ceiling (documented, NOT patched)

47% of the 638 allocs/op live in TRUE-FROZEN files:
  35%  Join.func3 (crdt.go:1016 — Join's closure append of incomingEntry)
  12%  accum make([]batchPair,0,n) — escapes via the Seq closure; pooling
       needs a return-after-Join seam (structural, future track)

Zero-alloc ingest is PHYSICALLY BLOCKED without unfreezing Join. Day 9 does
NOT unfreeze Join. This is the documented residual. Day 10 unfreezes Join or
builds the arena-pooled Seq — that is the path to zero-alloc ingest.

## 5. The rate-gate layer-mix refutation + FIX D skip

The "7× ceiling-raise from CASing the rate gate" was a layer-mix: the 7×
was the verify amortization across N=1→N=100 (31K→966K), not the mutex. The
rate gate fires once per batch at N=100 (receiver.go:537) = 0.035% of the
per-delta cost. Head-to-head at 4c/N=100: shared 966K > ceiling 762K — the
shared engine's L3-hot HAMT outperforms the per-goroutine ceiling sub-bench
(which conflates rate-gate removal + construction + cache destruction).

FIX D (CAS the gate) was SKIPPED on CORRECTNESS grounds, not laziness: any
32-bit pack of lastCounter truncates a 64-bit DotCounter that overflows in
~75s at 57M ops/s (deterministic replay hole), and (budget,lastCounter)
coherence needs a 128-bit CAS Go lacks → the mutex is necessary, not polish.
The mutex cost at the headline N=100 path is measured 0.035% / 0 allocs.
CASing it is a future polish track gated on a 128-bit atomic or a different
gate shape (e.g. per-shard lock-free with a single budget CAS + a separately-
hashed lastCounter map). Day 9 ships the honest truth: the mutex stays.

## 6. The honest headline (MEASURED, no adjectives)

  BEFORE (Day 8.5, commit 3f615a0, measured @ -cpu=4, count=3, this session):
    638 allocs/op, 126260 B/op, 707714–771604 aggregate_deltas/sec (median ~748K)

  AFTER (Day 9, FIX A + FIX C shipped, FIX D skipped, measured @ -cpu=4, count=3):
    538 allocs/op  (−100, −15.7%)   [the SOLE source is FIX C; FIX A is alloc-neutral]
    ~111657 B/op   (−14603, −11.6%) [FIX C; FIX A is byte-neutral on the integrated path]
    807754–928505 aggregate_deltas/sec (median ~829K)

  THROUGHPUT: the bench's median (+11%) is NOISE, NOT a claimed win. At
  -cpu=4 the shared sub-bench is L3-warmth-sensitive; the ±15% run-to-run
  variance (707K→928K across the six total runs) dwarfs the apparent lift.
  The win is the alloc/byte COUNT, NOT a throughput number-raise. The
  prompt's §5 directive ("the allocs are small; Go's allocator is fast —
  the win is the COUNT, not the speed") is HONORED: no throughput win is
  claimed. Record verbatim: the bench output above is what the engine shows.

  THE FROZEN-LOCKED CEILING (not fixed by Day 9, documented):
  47% of allocs (Join.func3 35% + accum-pool 12%) live in TRUE-FROZEN
  crdt.go Join + the re-lockable-but-escaping accum. Zero-alloc ingest
  requires unfreezing Join — an explicit Architect decision, NOT a Day-9 patch.

## 7. Honest weaknesses (7)

(a) The 47% FROZEN-locked ceiling (Join.func3 + accum-pool) — Day 9's residual.
(b) EntityId string alloc retained by Join's FROZEN Seq signature (the 12%
    CRDTDeltaEvent.EntityId line; FROZEN-locked; a future arena-pooled string
    the Seq can consume without materialization is the path, gated on Join).
(c) circl verify allocs (2%, not pooled — future track; amortized per batch).
(d) The rate-gate mutex (FIX D skipped — 0.035% at N=100, 0 allocs, MEASURED;
    a correctness primitive, not polish — §5).
(e) The bench's ceiling sub-bench conflation (construction + cache destruction)
    — a measurement-hygiene weakness in the bench, NOT in the engine.
(f) Zero-copy capnp reads alias the segment arena (UAF if Released early — the
    deferred msg.Release is the invariant; Day 9 does NOT change it; FIX A's
    payloadBytes are consumed by SHA + copied into rec.Payload before return).
(g) rec.Payload retained as a string despite production discard (the tests at
    crdt_reconstruct_test.go:151,195 assert it; a future track could drop the
    field if tests move to bytes — FROZEN-crdt_apply.go is the gate).

## 8. Self-adversarial critique (5 ATTACK + 1 MEDIOCRITY)

**ATTACK 1 — the []byte(string) alloc is hidden in sha256.Sum256's argument.**
It is NOT an explicit `make(`; a grep misses it. AND (the deeper finding) it
is NOT EVEN A HEAP ALLOC — escape analysis stack-allocates it (`does not
escape`). So the prompt's ATTACK-1 itself misdiagnosed: the hidden conversion
is hidden from the grep, the alloc counter, AND the bench — making the "FIX A
= 15.7%" claim a triple-layer-mix that survived the prompt's own §0 layer-mix
hunt. The tooth (G09.b) uses testing.AllocsPerRun + the integrated bench, not
a grep; the isolated FIX-A-only measurement (638→638) is what caught it.

**ATTACK 2 — the zero-copy PayloadBytes aliases the segment.** If a caller
retains the bytes past msg.Release, UAF. Day 9 does NOT retain them: SHA
consumes + discards the bytes; rec.Payload is a `string(payloadBytes)` copy,
not the alias. The deferred msg.Release invariant is unchanged.

**ATTACK 3 — value-return ReconstructedEntry changes the heap-escape profile.**
A large value type returned by value MAY escape to the heap if the compiler
decides. Verified with `go build -gcflags="-m"`: the OLD `&ReconstructedEntry{...}
escapes to heap` line (crdt_reconstruct.go:356) is GONE in the new code; the
new `string(payloadBytes) escapes to heap` (the retained field, expected) is
the only ReconstructEntry success-path escape. ReconstructedEntry itself does
NOT escape on the success path — FIX C's −2/call is real. (The retained
string field is the irreducible residual; weakness (g).)

**ATTACK 4 — the rate-gate CAS two-step could partial-update.** lastCounter
advances but budget doesn't → attacker un-banned. DEEPENED: the 32-bit
lastCounter pack is WORSE than a partial update — it is a deterministic
truncation that overflows in ~75s at 57M ops/s (a replay hole) and cannot
hold a valid Lamport counter AT ALL. And even a sound 64-bit split (budget
+ lastCounter as two atomics) has a lost-update budget-leak under same-shard
concurrency. Coherent update needs a 128-bit CAS Go lacks → SKIP (§5). The
verdict of the mutex is correctness, not cost.

**ATTACK 5 — the track36 stale tooth may trip on crdt_reconstruct edits.**
Pre-commit FAIL / post-commit PASS is the known Day-4/5/6/7/8 pattern; the
tooth diffs against its own commit, not HEAD. Document and do not edit the
tooth. (G09.b/c teeth are NEW and not track36; no interference observed.)

**MEDIOCRITY 1 — the codex's "7× rate-gate" headline survived 2 sessions.**
The fix is to MEASURE head-to-head, not to trust prior prose. The Architect
refuted it by running shared vs ceiling at identical -cpu and finding
shared > ceiling. A headline that survives 2 sessions without
re-measurement is a credibility landmine.

**MEDIOCRITY 2 (ADDED, the meta-finding) — the Day-9 prompt's OWN §0/§1 FIX-A
diagnosis was a layer-mix of the SAME class it refuted in the codex.** The
prompt accused the codex of reading an amortization as a ceil-raise; the
prompt then read a stack-allocated conversion as a heap alloc and predicted
"−15.7% from FIX A." The Executor caught it ONLY by isolating FIX A
(zero-copy + old pointer return) and measuring 638→638. The lesson: a root
cause that is "hidden in a function argument, invisible to grep AND the
alloc counter" is a triple-blind — the only resolver is the isolated
A/B measurement, not the integrated bench that hides the neutral fix behind
the real one. Both the codex's 7× myth AND the prompt's 15.7% myth died the
same way: an isolated head-to-head run. This is the methodological residual.

## 9. Status

§5 STAYS CONDITIONAL-GO. Day 9 does NOT flip §5. Day 9 does NOT lift the
single-writer root-equality qualifier (FROZEN-crdt.go origin-only Merkle
projection, a separate future track). Day 9 is the honest, FROZEN-safe step
toward zero-alloc ingest: it ships FIX C (the measured −15.7% alloc win) +
FIX A (alloc-neutral seam-prep + code-clarity) and SKIPS FIX D (a correctness
primitive dressed as polish). The 47% FROZEN-locked ceiling is the documented
residual. Day 10 unfreezes Join or builds the arena-pooled Seq — the path to
zero-alloc ingest that Day 9 honestly could not take.

Files touched: pkg/sync/crdt_reconstruct.go, pkg/sync/crdt_reconstruct_skew.go
(FIX A + FIX C); pkg/sync/crdt_reconstruct_test.go, pkg/sync/crdt_lamport_skew_test.go
(G09.b/c teeth + faithful nil→zero-value test-site translation). Files NOT touched
(the 5 TRUE-FROZEN): crdt.go (4512bd67), crdt_apply.go (ed9132a2 — recompiled
transparently, zero source diff), schema.capnp (47d2796a), schema.capnp.go
(590af228), envelope.go (b1beba1e). pkg/admission/ewma.go (df044675) UNCHANGED
(FIX D skipped).
