# ADR-0048: Complete the WAL fsync lock-scope split

- **Status:** Accepted. The lock-scope fix stands, but [ADR-0049](0049_causation_checkpoint_flush.md) disproved the proposed cause of the 300-second stall.
- **Date:** 2026-09-06
- **Scope:** `AppendClockAdvance`, `AppendMutation`, `AppendCheckpoint`, and their interaction with `AppendMutations` and `Close`

## Context

The first group-commit change released `w.mu` before the origin batch's fsync, preventing that batch from starving a receive-side `AppendClockAdvance`. The reverse direction remained: `AppendClockAdvance`, `AppendMutation`, and `AppendCheckpoint` still held `w.mu` across fsync. A slow receive-path sync could therefore block the origin's `AppendMutations` at `w.mu.Lock()`.

During a 100-process, three-machine convergence run, the seed's `commit_in_flight` stayed at 1 for more than 300 seconds. The origin never became quiescent, so that run could not supply a valid convergence-from-quiescence measurement. The WAL reverse-convoy was a plausible mechanism, but the observation alone did not establish that it caused the stall.

The lock-scope defect could be established directly from the code and a local blocking-fsync experiment. The decision was to fix that mechanism without claiming that the hardware causation question was settled. A local reproduction could not distinguish mutex convoying from NVMe contention at roughly 34 nodes per host because it stalled deterministically under the injected block.

## Decision

All four append paths now use the same captured-file pattern:

1. Encode and write the record and increment `nextSeq` while holding `w.mu`.
2. Capture `f := w.f` under the same lock.
3. Unlock explicitly on every return path, then call `w.syncFile(f)` outside the critical section.

A deferred unlock would either hold the mutex through fsync or make an explicit unlock redundant and unsafe. The test hook remains the first branch in `syncFile`.

Record bytes and sequence numbers are ordered by the locked write section; fsync is a durability barrier, not the ordering primitive. Each call returns only after its sync completes, so acknowledgment does not move ahead of durability. Concurrent syncs on the shared descriptor may flush additional records but cannot flush fewer than the records already written by the caller.

Capturing the descriptor also defines the race with `Close`: an in-flight sync can return `os.ErrClosed` instead of dereferencing a nil `w.f`, while `Close` performs its own final sync under the lock. [ADR-0053](0053_wal_snapshot_crc32c.md) later added default type `0x06` CRC32C framing to all four paths without changing this lock scope.

Fixing `AppendCheckpoint` removed the production over-hold used by `TestWALLockScopeRedControl`. The test-only `holdMuAcrossSyncForTest` helper now recreates that condition deliberately. Replacing the helper with a non-over-holding version makes the negative control report that it cannot detect the fault, so the control still tests its own apparatus.

## Evidence

The regression checks exercise mechanism rather than claiming hardware causation:

- `TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync`: an injected receive-side sync blocked the origin for 500.8 ms before the fix and about 200 µs after it.
- `TestWALMixedStreamOrderingPreserved`: replay order remains consistent across all four append paths.
- `TestWALEachAppendPathReleasesLockBeforeFsync`: each path is checked while it holds the mutex.
- `TestWALCloseDoesNotRaceInflightFsync`: 40 iterations cover the captured-descriptor shutdown race.
- The four earlier WAL lock-scope checks remained green under `-race`.

The planned hardware comparison used `{fix,no-fix} × {34,8}` nodes per host, with 100 processes in the 34/33/33 configuration on three c7gd.8xlarge machines. It also captured the seed's `PutLocals` stack: a park at `AppendMutations` would support the convoy hypothesis, while a park in `syncFile` would point toward the device.

[ADR-0049](0049_causation_checkpoint_flush.md) executed that comparison with integrity verification and non-destructive profiling. Both 34-per-host arms reached the quiescence cap whether the convoy was fixed or restored, and the 8-per-host arm also stalled, ruling out host density alone as the explanation. No capture showed the seed parked on the WAL append mutex. The actual park was the synchronous per-entity checkpoint flush after the WAL commit. Disabling periodic checkpoints diagnostically allowed the run to quiesce and converge within the target; that diagnostic was not a production configuration.

## Consequences

No production WAL append path holds `w.mu` across its fsync. The change removes the reverse-convoy mechanism and preserves write ordering, batch error semantics, and shutdown behavior.

The lock-scope fix did not resolve the 300-second origin stall, and this record no longer leaves that causation question open. [ADR-0049](0049_causation_checkpoint_flush.md) resolved it as checkpoint I/O on the commit path. [ADR-0050](0050_checkpoint_decouple_delta.md) moved periodic checkpoint work to a background runner and delta-batched the flush. Its seven consecutive 100-process, three-machine runs recorded six passes and one tail miss beyond the 10-second target, so the later result is not described as an unconditional convergence guarantee.

