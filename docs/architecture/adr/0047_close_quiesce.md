# ADR-0047: Close Quiesce — the teardown use-after-free + the cold-start Lamport flush

- **Status:** ACCEPTED (silicon-verified 2026-09-05)
- **Date:** 2026-09-04 → 2026-09-05
- **Frozen-file impact:** `pkg/sync/crdt.go` was the ONLY frozen file touched; the other four frozen files stayed byte-identical
- **Outcome:** the teardown use-after-free and the cold-start Lamport flush are both fixed at silicon; the follow-ups are registered in §5.

## 1. Context — two defects in the teardown/cold-start path

**The teardown use-after-free (the live one).** `(*DeltaCRDTEngine).Close` munmap'd the arena with **no quiesce** of EBR reclamation or in-flight `InsertLocal`/`Join`. A reclaimed-then-touched arena slot is a use-after-free — at 50M+ ops/s a corruption vector, and a production ship-blocker (enterprises shut nodes down). It surfaced under `-race` as `SIGSEGV` in `freeVar` via `freeRetiredList`/`AdvanceEpoch`, or in `HAMT.hashKey` on an already-freed arena driven by a lingering VirtualNet delivery goroutine. Control-confirmed before the fix (faults identically on a clean tree). Proven **pervasive** by a prior 32-core mesh `-race` sweep that faulted even *minus* the two named teeth (1917s).

**The cold-start Lamport flush (LOW severity, WAL-authoritative).** `Close` never flushed the final Lamport high-water; the park-handshake's cap-1 buffered ack proves only that the persist worker *executed the ack-send*, not that it had *parked* on the receive — so under scheduler contention the first `NextDot`'s persist send can drop AND `Close` never flushes. Low severity because the WAL is authoritative at recovery (`max(LamportHigh, ClockHigh)`); kill -9 never runs `Close`.

## 2. Decision — Close becomes a graceful, quiescing, monotone-flushing teardown

`Close` now: `SetClosing` → `Quiesce` (waits for active EBR participants) → drains the persist worker → **monotone-flushes** the final Lamport high-water (`max(lastSavedCounter, persisted)`) → **then** `arena.Free`. `InsertLocal`/`Join` **Enter the EBR participant FIRST and check Closing** (panic before the arena, never a use-after-free). The flush is **monotone** so a stale engine (recovered from a different DataDir, then SetDataDir-repointed) cannot clobber a higher persisted high-water — my first-cut *raw* flush regressed `TestDurabilityRoundTrip/Steady_1001NextDot` (flushed `0` over `1001`); I caught it by diffing against base, and it is guarded by the tooth `TestCloseFlushIsMonotone`.

**Completeness sweep.** Engine + arena share ONE `EBRManager`. The ONLY non-guaranteed-Exit participant is `GenerateDelta`'s *carried* pin (the `CRDTDelta` MUST-Release contract in `pkg/sync/crdt.go`: the delta's lazy iterator reads the arena, so `Release` Exit's it). The new `Quiesce` turned 5 durability tests' *forgotten* `Release` from a silent leak into a **deadlock** — a loud contract-violation signal, strictly better than the silent UAF. Fixed test-side (`defer delta.Release()`); production already Releases.

## 3. Silicon evidence (c8g.8xlarge, Graviton4 CPU part `0xd4f`, Go 1.26.1, GOMAXPROCS=32, the `pkg/sync/crdt.go` change verified on-box)

| Gate | Result |
|---|---|
| `TestScalingGate` (RUN_CRUCIBLE=1, -cpu=32) | **69,140,369 ops/s @32c** — linearizable every tier, ≥ 50,736,038 floor. **The closing-flag is OFF the hot path.** |
| Full `pkg/mesh` `-race`, the previous teardown exemptions REMOVED | **114 PASS / 1 FAIL / 10 SKIP, ZERO faults, ZERO data races** over 2426s (vs the pre-fix PERVASIVE faulting). |
| `RoundCount` (teardown tooth) | **PASS `-race`** (90s 32c; 185s 4c) → exemption **LIFTED** |
| `Converges10K` (teardown tooth) | Reaches `Close`/teardown with **NO fault** but FAILs its *convergence* assertion under `-race` (see §4) |
| `pkg/durability` `-race` | **COMPLETED** `ok … 1593.063s` (the 4-core 1500s timeout was incapacity, NOT a hang; Close/Quiesce exercised under `-race` at scale) |

The pervasive teardown use-after-free is gone at scale.

## 4. The Converges10K nuance — a SEPARATE, pre-existing ceiling, NOT the teardown defect

Converges10K FAILs under `-race` with "did NOT converge after 12 rounds; 8 distinct roots". This is **NOT the teardown defect and NOT a regression from this change**: the identical "8 distinct roots" failure is documented at the base commit *before* its SIGSEGV, and the tooth **PASSES non-race at 32c in 1.92s** (converged in 2 rounds, single root). Root cause: the pump (`pumpUntilConverged`) waits a **fixed** quiesce window (4×-scaled to 2s under `-race`) instead of waiting for actual delivery — too short for a 10K-key delta under `-race`. A test-calibration ceiling, not an engine defect (the convergence/delivery path is untouched by this change).

**Disposition:** RoundCount's exemption **lifts**; Converges10K's exemption is **re-scoped** to cite this convergence-timing ceiling (not the teardown use-after-free), with the non-race PASS as its green. The real fix — a wait-for-delivery pump — is registered as follow-up work, NOT this change.

## 5. Consequences

- **Teardown UAF closed.** The teardown-UAF race-skip classification is retired: the convergence-skip now applies ONLY to Converges10K (its separate timing ceiling, §4); a mesh `freeVar` fault now is a **regression**, not this defect. The pkg/sync intermittent 4-core-pressure fault remains separately classified.
- **Cold-start flush closed.** Monotone flush; teeth `TestCloseFlushesFinalHighWater` + `TestCloseFlushIsMonotone` (bug-injection-proven).
- **Follow-up registered:** the Converges10K wait-for-delivery pump (§4).
- **Follow-up (P2):** a BOUNDED Quiesce (timeout → log the leaked participant, SKIP `arena.Free`, return an error) so a forgotten `Release` can never hang `Close`.
- **Open at the time of this decision:** the `internal/database` `fault 0x30` (the MemTable hypothesis is REFUTED), and the WAL group-commit fsync convoy (`AppendClockAdvance`/`AppendCheckpoint` hold `w.mu` across the fsync) as the live convergence-SLO blocker.
