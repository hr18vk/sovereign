# ADR-0048: Complete the WAL fsync lock-scope split (the reverse-convoy)

- **Status:** ACCEPTED (mechanism fixed + regression-guarded; the 300s-causation question is still pending a silicon A/B)
- **Date:** 2026-09-06
- **Core-file integrity:** none of the five merge-law/wire-schema files changed (`crdt.go`, `crdt_apply.go`, `envelope.go`, `schema.capnp`, `schema.capnp.go` — all byte-identical)

## 1. Context — the incomplete fsync lock-scope split

The earlier WAL fix (ADR-0044/0045) was **one-directional**: `AppendMutations` (the origin's
group-commit) releases `w.mu` before its fsync, so a concurrent `AppendClockAdvance` is not
starved *by* the origin's inject. The **reverse** was left open: `AppendClockAdvance` (the
receive path), `AppendMutation`, and `AppendCheckpoint` still held `w.mu` **across** their
fsync. So one slow receive-path fsync held `w.mu` for its whole duration and the origin's
`AppendMutations` blocked at `w.mu.Lock()` — a WAL-wide commit stall (the reverse-convoy).
It surfaced in the 100-node convergence silicon run: the
seed's `commit_in_flight` pinned at 1 for >300s → the quiescence probe never fired → the
convergence SLO was INVALID (NOT-QUIESCED).

## 2. Why fix the mechanism before the 300s root cause is proven

I had previously deferred this: the 300s **causation** was unproven, and the rule is not to
fix what has no proven root cause. But the convoy **mechanism** is now byte-evident — a mutex
held across a blocking fsync is a lock-ordering fact, independent of timing — and its own root
cause (the incomplete split above) is proven. So I fixed the **proven mechanism** as correct
durability hygiene and deferred only the 300s-causation verdict (convoy-dominant vs
NVMe-density-dominant at ~34 nodes/host) to a silicon A/B, because that causation cannot be
settled by a cheap local experiment: a local repro stalls deterministically, so it cannot
discriminate convoy from device. The convergence SLO is **not** claimed fixed.

## 3. Decision

Release `w.mu` **before** the fsync in `AppendClockAdvance`, `AppendMutation`, and
`AppendCheckpoint`, using the exact captured-fd `syncFile(f)` pattern `AppendMutations` already
uses: write + `nextSeq++` **under** the lock; capture `f := w.f` under the lock; `w.mu.Unlock()`;
then `w.syncFile(f)` **outside** the lock. No `defer` (each error path unlocks explicitly — a
defer would re-hold across the fsync or double-unlock). The `syncHook` test seam is consulted
first in `syncFile`, byte-identical.

**Why safe:** (1) ordering — writes + seq-stamp under the lock; fsync is a durability barrier,
not an ordering primitive. (2) durability floor — the call returns only after the fsync, so no
ACK-before-durability. (3) concurrent fsyncs on a shared fd only ever flush MORE, never fewer.
(4) the captured fd makes a concurrent `Close()` return `os.ErrClosed` (an error, not a panic),
and `Close()`'s own final `Sync` under the lock flushes the tail regardless.

**Regression-control consequence (handled, not vacuous):** fixing `AppendCheckpoint` removed the
over-hold vehicle that `TestWALLockScopeRedControl` relied on. I re-anchored it:
`holdMuAcrossSyncForTest` re-creates the over-hold in explicit test-only code, so the
existing GREEN guard keeps a live apparatus-validation control. Bug-injection-proven (inject a
non-over-holding helper → the control reports itself BROKEN; revert → it detects again).

## 4. Guards (all bug-injection-proven, all GREEN under -race)

- `TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync` — the origin/receive pair (was RED at
  500.8ms pre-fix; GREEN at ~200µs post-fix). It carries an honesty label: it confirms the
  mechanism, it does NOT prove the 300s causation.
- `TestWALMixedStreamOrderingPreserved` — the replay witness across all four paths.
- `TestWALEachAppendPathReleasesLockBeforeFsync` — all four paths as the mutex-holder.
- `TestWALCloseDoesNotRaceInflightFsync` — the captured-fd safety guard (40 iterations).
- The four pre-existing WAL lock-scope guards stay GREEN.

## 5. The silicon A/B (designed, not run here)

`{fix,no-fix} × {34,8}` nodes/host on the three-region diagnostic harness (100 nodes,
3× c7gd.8xlarge, split 34,33,33), integrity checker armed, plus a pprof stack-capture of the
seed's `PutLocals` (parked at the `AppendMutations` `w.mu.Lock()` ⇒ convoy; in `syncFile` ⇒
device). **Convoy is convicted ⟺ (fix,34) clears AND (no-fix,34) stalls.** The cheap local
guards ran before any silicon, so the test-before-silicon ordering held.

## 6. Consequences

The "no mutex across a blocking fsync" class is removed from every production WAL append path.
The WAL no longer lets a receive-path fsync starve the origin's commit at any node count. The
300s-causation verdict and the convergence SLO remain OPEN pending the silicon A/B.
