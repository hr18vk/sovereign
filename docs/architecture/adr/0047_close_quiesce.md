# ADR-0047: Quiescent close and monotone Lamport flushing

- **Status:** Accepted; verified on a 32-core c8g.8xlarge on 2026-09-05
- **Date:** 2026-09-04 to 2026-09-05
- **Scope:** `(*DeltaCRDTEngine).Close`, EBR participation, and Lamport persistence in `pkg/sync`

## Context

`Close` unmapped the arena without waiting for EBR reclamation or in-flight `InsertLocal` and `Join` calls. A reclaimed slot could then be touched after unmapping. Failures appeared under `-race` as a SIGSEGV in `freeVar` through `freeRetiredList` or `AdvanceEpoch`, or in `HAMT.hashKey` when a VirtualNet delivery goroutine outlived engine teardown. A prior 32-core mesh race run faulted after 1,917 seconds even without the two tests that most directly exercised teardown. This was a memory-lifetime defect, not a Go data-race report.

The same close path did not flush the final Lamport high-water mark. The persistence worker's capacity-one acknowledgement showed that its send had executed, not that it had parked for the next receive. Under scheduler contention, the first `NextDot` handoff could be dropped and `Close` could exit without writing the final value. The WAL remained authoritative at recovery through `max(LamportHigh, ClockHigh)`, and `kill -9` does not run `Close`, which limited the severity but did not remove the graceful-restart defect.

## Decision

`Close` now performs this order:

1. `SetClosing` rejects new work and stops further reclamation.
2. `Quiesce` waits for active EBR participants to exit.
3. The persistence channel closes and the worker drains.
4. The final Lamport value is flushed as `max(lastSavedCounter, persisted)`.
5. Only then does `arena.Free` unmap the arena.

`InsertLocal` and `Join` enter their EBR participant before checking `Closing`, so a rejected call panics before touching the arena rather than racing the unmap. The maximum in the final flush prevents a stale engine whose `DataDir` was changed from overwriting a newer watermark. An earlier raw flush regressed `TestDurabilityRoundTrip/Steady_1001NextDot` by writing 0 over 1,001; `TestCloseFlushIsMonotone` now covers that case.

The engine and arena share one `EBRManager`. `GenerateDelta` is the participant whose pin is carried into the returned delta: its lazy iterator reads the arena until `CRDTDelta.Release` exits the participant. Quiescence therefore turns a forgotten `Release` from a silent leak into a blocked close. Five durability tests had omitted the call and were corrected with `defer delta.Release()`; production callers already released their deltas. A bounded close that reports a leaked participant instead of waiting forever remains a follow-up.

## Evidence

Measurements ran on a c8g.8xlarge with Graviton4 CPU part `0xd4f`, Go 1.26.1, and `GOMAXPROCS=32`. The scaling figure is the in-process CRDT core benchmark, not network ingest. Of the merge-law and wire-schema files, only `pkg/sync/crdt.go` changed for this decision.

| Check | Result |
|---|---|
| `TestScalingGate` with `RUN_CRUCIBLE=1` and `-cpu=32` | 69,140,369 ops/s, above the 50,736,038 ops/s floor; linearizability held at every tier |
| Full `pkg/mesh` race run with the earlier teardown exemptions removed | 114 passed, 1 failed, 10 skipped over 2,426 seconds; no teardown faults or reported data races |
| `TestLoopbackRoundCount` under `-race` | Passed in 90 seconds at 32 cores; the earlier 4-core run took 185 seconds |
| `TestLoopbackConverges10K` under `-race` | Reached `Close` without a memory fault but did not meet its convergence assertion |
| Full `pkg/durability` race run | Completed in 1,593.063 seconds; the earlier 1,500-second timeout on 4 cores had been too short |

The one mesh failure was a separate fixed-window calibration problem. `TestLoopbackConverges10K` reported 8 distinct roots after 12 rounds under `-race`. The same failure had been observed before this change, and the non-race 32-core test converged to one root in 2 rounds in 1.92 seconds. `pumpUntilConverged` waited a fixed quiescence window, scaled by 4 to 2 seconds under `-race`, instead of waiting for actual delivery. The close tests removed the teardown fault; they did not make that fixed window a delivery guarantee. A wait-for-delivery pump remains the appropriate test correction.

`TestCloseFlushesFinalHighWater` and `TestCloseFlushIsMonotone` cover final persistence and the 1,001-versus-0 regression. Fault-injection controls show that both checks fail when the corresponding protection is removed.

## Consequences

- Arena unmapping now follows participant quiescence and persistence draining. A new mesh `freeVar` or `HAMT.hashKey` teardown fault is a regression of this contract, not an expected test exemption.
- A bounded `Quiesce` that logs the leaked participant, skips `arena.Free`, and returns an error would prevent a missing `Release` from hanging `Close`; that behavior is not implemented here.
- The intermittent `internal/database` SIGSEGV at address `0x30`, still open when this decision was written, was later traced to a resliced-buffer wrong-size free and resolved by [ADR-0052](0052_jemalloc_wrongsize_free.md).
- [ADR-0048](0048_wal_split_completion.md) completed the WAL lock-scope split described here as open. [ADR-0049](0049_causation_checkpoint_flush.md) then showed that synchronous checkpoint flushing, rather than the WAL convoy, caused the long origin commit stall.

