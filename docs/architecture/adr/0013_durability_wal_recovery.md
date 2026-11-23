# ADR-0013: WAL write-through and recovery bootstrap

**Status:** Accepted; the original replay-seed rule is superseded by [ADR-0045](0045_mesh_transport_invariants.md)  
**Date:** 2026-07-30; receive-side clock recording added 2026-07-31; exact-dot recovery adopted 2026-08-31

## Context

Before this decision, restarting `sovereign-node` constructed a fresh in-memory engine. Its HAMT contents disappeared and its Lamport clock returned to `initialCounter=1`. The node neither appended origin writes to a WAL nor replayed a WAL during boot.

The required substrate already existed. `internal/chaos/wal.go` provided an append-only log, fsync-on-commit, replay, checkpoints, and torn-tail handling. The engine's `InsertLocal` assigned causal dots, and its persistence worker saved Lamport state. `MemTable.Write` supplied a separate durable storage buffer. The chaos supervisor exercised recovery, but the production node had no equivalent path.

The decision was therefore to connect the existing components rather than implement a second log. `pkg/durability/wal.go` aliases the WAL types and functions from `internal/chaos`; production recovery and the recovery tests use the same codecs and append behavior.

An early proposal also included an eager conflict-resolution seam. [ADR-0033](0033_toki_closure_ghost_exorcism.md) removed that unused code and rejected the integration: selecting and deleting a losing dot would change `Join` from a merge-union into lossy last-writer-wins resolution. Conflict selection belongs at read time, where every dot remains available to later merges and recovery.

## Decision

### Write origin mutations before acknowledging them

`Bridge.PutLocal` performs these steps in order:

1. Compute `SHA-256(payload)` and place it in the entry.
2. Call `InsertLocal`, which assigns `DotNodeID`, `DotCounter`, and `OriginNodeID` on its internal copy through `NextDot` and the local node identity.
3. Feed the optional secondary index synchronously.
4. Construct the WAL mutation from the returned dot and full entry, call `AppendMutation`, and return after its fsync completes.

The order of the second and fourth steps is the central write-path invariant. Appending first would persist caller-supplied dot fields rather than the dot the engine actually minted. Replay would then restore a different Merkle root. `TestPutLocalWALStampsEngineDot` checks that the WAL carries the engine-returned dot.

`Gossiper.InsertLocalEvents` records the payload for gossip only after the WAL append succeeds. On failure it logs the error and returns a zero `CausalDot`; `ControlServer.handleInsert` answers HTTP 503 with an empty receipt when the bridge is active. `PutLocal` also returns the error to its caller. A failed append does not roll back the earlier `InsertLocal`: the dot remains in live memory and in the optional index, but it has no cached gossip payload and receives no durability acknowledgment.

[ADR-0044](0044_wal_group_commit.md) added the batch counterpart. `Bridge.PutLocals` inserts every item, then calls `WAL.AppendMutations` once for the batch and pays one fsync. On any write or sync failure, the control response marks every valid entry with code 503. This is all-or-none acknowledgment, not a rollback of records that may already be in the page cache. Single inserts retain the per-mutation fsync path. [ADR-0048](0048_wal_split_completion.md) later moved fsync outside the WAL mutex on every append path without changing record order or acknowledgment semantics.

Durability remains opt-in. An empty `--wal-path` selects the in-memory engine without WAL recovery or fsync. `--wal-checkpoint-interval` defaults to `1000` mutations; zero leaves checkpoints to the caller. Checkpoints anchor state without replacing the mutation's own durability barrier. Their periodic work runs in the background under [ADR-0050](0050_checkpoint_decouple_delta.md), and a periodic-checkpoint failure is logged rather than used to reject mutations that are already durable.

### Record peer-driven clock advances

A foreign `Join` can advance the Lamport clock without creating a local mutation. The first recovery design did not record that advance, so replay could resume below logical time the node had already observed.

The receive seam now records `WALRecClockAdvance=0x03` after a successful apply. `HandleFrame`, `HandleBatchFrame`, and `HandleHybridFrame` capture the clock at handler entry and invoke the recorder only when the post-apply value is greater. A stale or duplicate frame therefore causes no additional WAL append or fsync. The callback is nil unless durability is configured.

The recorded value is the post-apply high-water, which can exceed the exact foreign counter before the next local mint. Replay applies advances as a monotone maximum, so this over-record is safe. A recording failure is logged rather than returned as HTTP 503: the foreign entries have already joined and cannot be removed. This differs deliberately from a local insert, which the client can retry after a 503. A later checkpoint records the clock high-water again; recovery before such a checkpoint cannot make the failed advance durable retroactively.

### Restore recorded identity during recovery

The original design replayed mutations through `InsertLocal` and derived the constructor seed with `LamportHigh - len(Mutations)`. The receive-side amendment substituted `firstMutation.Counter - 1`. [ADR-0045](0045_mesh_transport_invariants.md) superseded both rules. Concurrent writers can reserve counters in one order and append in another, while foreign advances create gaps that mutation counts cannot describe. In one multi-node crash-recovery run, the old approach produced `10,800` live dots for `10,000` keys and did not re-converge.

Current recovery follows these rules:

- `ReplayWAL` checks record-sequence continuity and rejects gaps or reordered records. A partial final record is a crash boundary and is discarded before append resumes. [ADR-0053](0053_wal_snapshot_crc32c.md) adds CRC32C content checks to newly written records and snapshot images; older unframed records remain readable but have no retroactive checksum.
- The engine constructor starts from the durable high-water in the log and final checkpoint. Recovery does not derive a seed from mutation counts or call `AdvanceLamportTo` merely to initialize the clock, because that method also updates ingress-rate state used by the skew bound.
- Every mutation enters through a synthetic-delta `Join` with its recorded `(DotNodeID, DotCounter)`. Replay never calls `InsertLocal`. The complete entry is preserved, and the recovering node becomes `OriginNodeID` so recovered local payloads use the local ship path.
- With `--lsm-root`, a usable snapshot image is joined before the WAL tail. The tail begins at the checkpoint's sequence cut, not at a scalar Lamport counter. Missing, stale, or unusable images select full exact-WAL replay and record the fallback in `RecoveryWitness`.
- A bound, fingerprint-bearing snapshot supports root and state-fingerprint checks before tail replay. `ErrRecoveryRootMismatch` and `ErrRecoveryFingerprintMismatch` refuse startup when those comparisons fail. On that bounded path, a final intact checkpoint also supports a post-tail root check.
- Full replay contains local WAL records but not foreign entries received through gossip. Its origin-only root cannot validly be compared with a checkpoint root that may include those entries. Full replay therefore relies on exact-dot restoration, record integrity, and sequence continuity instead of disabling sequence checks or forcing a root comparison.

## Consequences

- A successful local response means the WAL fsync completed; it does not mean peers have converged. Live state becomes visible before that response, so an unacknowledged write can remain in memory after a failed append. A client retry creates a new causal dot rather than rolling back the first one.
- Batch failure has the same visibility caveat. The handler rejects every valid entry because no subset can be called durable, but previously written bytes and in-memory inserts are not erased.
- Full WAL replay restores local-origin state only. Foreign entries can arrive again through anti-entropy after restart. A bound snapshot can preserve those entries and make root comparison meaningful; falling back to the WAL costs a full replay but does not treat a missing cache image as loss of the authoritative log.
- An empty `--wal-path` remains a non-durable configuration. Documentation and operators must not describe that default as crash-safe.
- The WAL is append-only and is not truncated by checkpoints. Long-running nodes therefore accumulate log records until a separate WAL-retention design exists. LSM compaction in `internal/database/compactor.go` and `internal/database/l1_compactor.go` does not truncate this WAL.
- Recovery constructs its engine in a fresh scratch directory by temporarily assigning the package-global `eng.DataDir`. This prevents a stale Lamport file from overriding the WAL-derived clock seed, but concurrent engine construction would race on the global. Boot recovery is consequently serialized before concurrent construction. `Bridge.Close` owns and removes the scratch directory.
- `Join` remains a merge-union. Read-time selection can choose a dominant entry without deleting the other dots, preserving idempotent replay and later convergence.

## Evidence

### Current regression coverage

The current tree carries these checks for the decision and its later amendments:

| Property | Checks |
|---|---|
| Engine-stamped write order and exact-dot restoration | `TestPutLocalWALStampsEngineDot`, `TestWALRecoveryDeterminism`, `TestMintOrderNeAppendOrderExactRestore` |
| Production recovery without a checkpoint or after a torn tail | `TestRecoveryDeterminism_KillRebuildMerkleEqual`, `TestRecoveryColdBoot_NoCheckpoint`, `TestRecoveryTornTailTruncation` |
| Foreign clock advances and correctly scoped root checks | `TestRecoveryForeignAdvance_RealJoinClockSeedFixed`, `TestRecoveryForeignAdvance_NoFalseMismatch`, `TestRootAssertionArmedWithForeignAdvances`, `TestRecoveryForgedRoot_FullPathBootsLoudly` |
| Sequence continuity across deletion, renumbering, and sync failure | `TestSeqContiguityHoleRefused`, `TestSeqContiguityRenumberRefused`, `TestSeqUniqueAcrossFsyncFailure` |
| Checkpoint coverage, phantom rejection, and scratch cleanup | `TestNoHoleBelowWatermark`, `TestMidBatchPhantomAnchorBootsClean`, `TestRecoveryScratchDirCleaned` |
| Receive-seam recording and suppression of duplicate appends | `TestClockAdvanceSeam_RecordsOneOnActualAdvance`, `TestClockAdvanceSeam_ZeroRecordsOnStaleReReceive` |
| Refusal to acknowledge a failed local WAL append | `TestControlInsert_WALFailureReturns503` |
| One sync per batch, batch-wide failure, and replay determinism | `TestMeshGroupCommitCount`, `TestMeshGroupCommitAck`, `TestMeshGroupCommitDeterminism` |

### Published crash recovery

The [crash-recovery receipt](../../evidence/crash-recovery.txt) records a run on 2026-09-02 using a c7gd.8xlarge with Graviton3, local NVMe, and a WAL plus snapshot. After a batch injection, the seed received `kill -9` and restarted on the same files. Bounded recovery replayed zero post-checkpoint records, and the recovered root equaled the pre-crash fleet root after `14.943s`, within the receipt's `30s` bound. This is evidence for that machine, configuration, and run; it is not a general recovery-time guarantee.

### Historical origin-write latency

The original decision compared `BenchmarkBridgePutLocal` with `BenchmarkBareInsertLocal` on a four-core arm64 development machine. These rows are retained verbatim as historical measurements, not presented as a fresh v0.2.0 benchmark result:

```
BenchmarkBridgePutLocal-4    226173   9175 ns/op   3913 B/op   4 allocs/op
BenchmarkBridgePutLocal-4    258942  10557 ns/op   4463 B/op   4 allocs/op
BenchmarkBridgePutLocal-4    246018  10283 ns/op   4249 B/op   4 allocs/op
BenchmarkBridgePutLocal-4    252913   9884 ns/op   4367 B/op   4 allocs/op
BenchmarkBridgePutLocal-4    252402   9755 ns/op   4355 B/op   4 allocs/op
BenchmarkBareInsertLocal-4   352562  10565 ns/op   5739 B/op   3 allocs/op
BenchmarkBareInsertLocal-4   368989  11312 ns/op   5981 B/op   3 allocs/op
BenchmarkBareInsertLocal-4   358573  10856 ns/op   5831 B/op   3 allocs/op
BenchmarkBareInsertLocal-4   353625  10549 ns/op   5757 B/op   3 allocs/op
BenchmarkBareInsertLocal-4   364358  11005 ns/op   5914 B/op   3 allocs/op
```

The bridge median was approximately `9.9µs/op`, compared with `10.9µs/op` for the bare insert. That ordering does not show that adding fsync is free. HAMT path-copy allocation and working-set differences dominate these measurements, and the two paths allocate different amounts per operation.

The historical fsync comparison also varied more than the sync call: its `Fsync` arm took the WAL mutex and wrote a real temporary file, while its `NoSync` arm skipped the mutex and wrote `/dev/null`. The resulting delta combined locking, write-target, and fsync effects. The separately cited NVMe measurement of approximately `1.5µs` at p99 came from a 32-core measurement and cannot be subtracted cleanly from these rows. A controlled comparison must hold the lock and write target constant while varying only `f.Sync()`.
