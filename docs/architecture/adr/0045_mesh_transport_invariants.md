# ADR-0045: Mesh transport correctness invariants

- **Status:** Accepted
- **Date:** 2026-08-19; recovery amendments through 2026-09-04
- **Scope:** `pkg/mesh`, `pkg/receive`, `pkg/durability`, `internal/chaos`, and the node wiring in `cmd/sovereign-node`

## 1. Context

The multi-region design specified an intra-region full mesh, inter-region fan-out, and IBLT reconciliation, but left three transport assumptions unchecked:

- **The connection graph was asymmetric.** The live-peer map used by `Publish` was populated only by outbound `Dial`. The accept loop could receive frames without registering the inbound peer, so a connection from B to A was a publishable edge for B but not for A. A lost boot dial could therefore exclude a peer permanently.
- **Foreign deltas could not be relayed.** The ship path looked up payloads in an origin-side cache. A peer that had received a delta could not forward it, even though the wire format already carried an embedded payload. Partial-view topology could not converge while relaying depended on that cache.
- **Loopback tests bypassed the transport under test.** The in-process network did not exercise `PeerSet`, TCP, TLS, or the accept path. Connection-graph and relay defects could pass every loopback test and appear only in a multi-node deployment.

Recovery had a related identity problem. A checkpoint could observe state while concurrent writers were still appending to the WAL. Replaying those mutations through `InsertLocal` minted new dots instead of restoring their durable identities, producing duplicate state after a crash.

## 2. Decision: transport invariants

### INV-1: connection symmetry

Every accepted TLS connection registers its inbound peer in the live-peer map, keyed by the node identity decoded from the leaf certificate CN. An accepted connection is consequently a publishable edge in both directions.

`RegisterInbound` keeps an already-live edge instead of evicting it. A declined registration returns no owned connection, and release is identity-checked so cleanup cannot close a newer edge. Connection completion is guarded by `sync.Once`; both read-loop exit and inbound release remove dead address entries. Reconnection checks both the address and peer-identity maps and waits after a successful dial, preventing a close or redundant registration from causing an immediate redial loop.

### INV-2: relay with payload

A node retains a verified foreign envelope after applying it and forwards those received bytes on the next hop. It does not reconstruct the payload from local state or re-sign the envelope as a new origin. Per-frame, batch, and hybrid receive paths install their retainers through the same wiring used by production and tests. Batch entries without dots are not retained, and rejected batches are never retained.

The default TCP frame reader transfers ownership of a fresh frame buffer to the retainer. The build-tagged epoll ingress instead copies out of its reused receive buffer before delivery. Fan-out selection rotates its seed each sweep so a partial view does not pin every round to the same remote peers.

### INV-3: real TCP verification

Transport tests use `net.Listener`, TCP, and TLS before relying on a larger mesh run. The suite includes staggered connection setup and a three-node chain whose endpoints have no direct edge. Disabling relay retention must make the chain test fail; restoring it must let the terminal node converge.

## 3. Decision: scale follows relay

The initial acceptance tier used a full-mesh dial graph. Its connection count grows as O(N²), even when symmetry makes each accepted connection useful in both directions. Embedded-payload relay was therefore a prerequisite for partial-view membership, not an optimization to add afterwards: once a node dials only O(fanout) peers, deltas must travel through intermediate nodes.

The current implementation carries that design forward through [ADR-0062](0062_reconciliation_scale_limits.md), [ADR-0063](0063_partial_intra_view.md), [ADR-0064](0064_iblt_reconciliation.md), and [ADR-0067](0067_ingress_admission_and_relay_resolution.md). The hierarchical gateway topology and its later reconciliation changes are recorded in [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md) and [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md). Measurements from those later systems must not be attributed to the original full-mesh design.

## 4. Decision: the exact-WAL recovery law

Recovery restores durable identity; it does not repeat local minting.

1. **Select the tail by record sequence.** A versioned checkpoint captures `CutSeq` before walking state, and bounded recovery replays records at or after that horizon. A scalar Lamport counter is not a WAL cut: concurrent writers can reserve dots in one order and append them in another. Legacy checkpoints use a repair pass for durable mutations missing below their less precise cut.
2. **Restore the recorded dot.** Each replayed mutation keeps its WAL-recorded `(DotNodeID, DotCounter)` and enters through the synthetic-delta `Join` path. `InsertLocal` is forbidden during replay. The recovering node's identity becomes `OriginNodeID`, because this WAL contains local-origin mutations and recovered local payloads must use the local ship path.
3. **Persist the complete entry.** The versioned mutation record carries the full 120-byte `CRDTEntry`, including its temporal and spatial fields. The versioned checkpoint carries the root, local-dot and clock high-water marks, sequence cut, and state fingerprint. New record types leave legacy mutation, checkpoint, and clock-advance records readable instead of reinterpreting their bytes.
4. **Join image and tail separately, in that order.** On an equal `(EntityID, DotNodeID, DotCounter)`, `Join` retains the existing entry's non-dot bytes. The snapshot image therefore precedes the WAL tail in two calls. Combining them into one incoming buffer would leave the winner to an unstable sort when both copies share a dot.
5. **Bind an image to its anchor.** The image header carries the checkpoint cut and root. A stale or mismatched image falls back to exact-WAL recovery with a witness reason; it is not treated as corrupt merely because it is stale. A duplicate image record is not writer-producible and refuses boot with `ErrRecoveryImageDuplicate`. Local image dots without durable WAL identity are rejected rather than allowed to become phantoms.
6. **Capture a checkpoint in one pinned walk.** `CaptureShardsPinned` derives the root, image, local-dot horizon, and fingerprint without materializing a second merged HAMT. The EBR pin remains held through image encoding and upload because entity identifiers are zero-copy strings into the arena. Snapshot upload uses a temporary file, file and parent-directory fsyncs, and rename; interrupted upload files are hidden and reaped.
7. **Check record continuity independently of state roots.** WAL sequence contiguity covers every record type and rejects a gap before state is rebuilt. A replay-only WAL has no foreign entries, so comparing its root with a checkpoint root that includes foreign state is invalid; that comparison is scoped to the snapshot path. [ADR-0053](0053_wal_snapshot_crc32c.md) adds CRC32C content checks to WAL records and snapshot images.

Recovery seeds the Lamport clock through the constructor from the persisted high-water marks. It does not call `AdvanceLamportTo` merely to raise the clock, because that method also updates ingress-rate state used by the skew bound. Implausible checkpoint clock values are clamped to the log's durable high-water and surfaced in the recovery witness.

## 5. Decision: integrity checks must match their comparand

### 5.1 State fingerprint oracle and equal-root divergence (historical index §15.12)

Because the Merkle root folds causal dots rather than payload bytes, fleet convergence gates (`cmd/fleet-gate`, indexed historically as §15.12) evaluate both root equality and state fingerprint equality. When roots converge but state fingerprints diverge across nodes, the diagnostic asserts an integrity breach.

A Merkle root folds causal dots; it does not cover the payload digest or the other entry fields. A matching root therefore cannot detect equal dots carrying different bytes.

A bound snapshot enables two checks before tail replay: root equality and equality of the payload-covering state fingerprint. An armed mismatch returns `ErrRecoveryRootMismatch` or `ErrRecoveryFingerprintMismatch`. The recovery witness records whether the checks were armed and whether the final checkpoint used a legacy form. Replay-only recovery has no image fingerprint to compare, so it relies on exact-dot restoration, WAL sequence continuity, and content checksums rather than claiming an image-bound check.

## 6. Acceptance criteria

- A staggered TCP+TLS setup must produce a symmetric publishable graph. On a three-node chain with no endpoint connection, the middle node must relay the embedded payload to the terminal node. Hybrid signing must pass the same convergence shape with both signature-verification counters advancing.
- Recovery tests must cover non-quiescent checkpoints, concurrent mint/append reordering, a non-empty replay tail, legacy records, stale and damaged images, duplicate image records, clock corruption, and gaps in the WAL sequence. A check that can be disabled by malformed input is not accepted as an integrity guard.
- A convergence measurement starts only after every injection is acknowledged and the origin is quiescent. Ingest duration is reported separately. Root equality is checked at every node, and scrape failures cannot be counted as agreement.
- Checkpoint tests must show that repeated captures do not grow the arena through a merged-state copy. Shutdown must quiesce reclamation and in-flight state access before unmapping the arena.

## 7. Consequences and current limits

The transport invariants make partial-view relay possible and move connection and relay failures into tests that exercise their actual stack. Exact-WAL recovery makes replay idempotent by dot identity and preserves entry bytes that a dot-only root cannot see.

Several limitations in the original record have since been resolved rather than carried forward:

- [ADR-0047](0047_close_quiesce.md) closes the arena reclamation and teardown ordering hazard.
- [ADR-0049](0049_causation_checkpoint_flush.md) identifies synchronous checkpoint flushing as the cause of the long origin commit stall; [ADR-0050](0050_checkpoint_decouple_delta.md) moves that work off the commit path and records the resulting convergence runs.
- [ADR-0053](0053_wal_snapshot_crc32c.md) adds the content-integrity checks missing from the first exact-WAL implementation.
- [ADR-0067](0067_ingress_admission_and_relay_resolution.md) changes ingress admission and relay resolution so a cold peer does not need the widened Lamport slack used by the early gate runs.

Important boundaries remain. In-memory local state is published before its WAL fsync completes, while gossip payloads are recorded only after a successful append. Recovery can restore only what reached durable storage. Cache retention and digest sizing have their own resource bounds and later decisions; this ADR does not establish a general production memory limit. Hybrid frame signing remains opt-in. Acceptance here is not a claim of production readiness.

### Quiescence amendment

With state visible before the WAL append finishes, a stable root does not prove that no commit is in flight.

`/v1/merkle` therefore exposes `commit_in_flight` and commit-latency statistics. The convergence gate requires both a stable root and `commit_in_flight == 0` throughout its stability streak before starting the convergence clock. Failed or timed-out appends can leave local state without a gossip payload, so sweep statistics distinguish those misses from relay-retention misses.

## 8. Evidence

The executable checks named here are in the current tree:

| Property | Checks |
|---|---|
| Inbound registration and staggered setup | `TestAsymDialAcceptDoesNotRegister`, `TestAsymStaggeredConverges` |
| Embedded-payload relay and connection cleanup | `TestRelayChainLoadBearing`, `TestCloseDoneExactOnce`, `TestB1_ByAddrBoundedByLiveEdges` |
| Hybrid relay over TCP+TLS | `TestB7_ThreeNodeHybridConverges` |
| Checkpoint horizon and arena use | `TestNoHoleBelowWatermark`, `TestCheckpointAllocatesZeroArena` |
| Image binding and payload-covering integrity | `TestStaleImageBindingDisarmsNotBricks`, `TestHeaderRootRotBindingCatchesRootHalf`, `TestNonDotCorruptionBootRefused`, `TestCrashMidInjectOracleArmed`, `TestFingerprintWriterReaderAgreement` |
| Legacy checkpoints and durable upload cleanup | `TestLegacyCheckpointTracksFinalRecord`, `TestOrphanWedgesCompactionAndReaperClosesIt` |
| Commit observation and clock bounds | `TestCommitTailLocalShape`, `TestClockHighClampMaxUint64`, `TestClockHighClampOneBitFlip`, `TestClockHighClampBoundary` |

The published [100-node convergence receipt](../../evidence/convergence-100-node.txt) and [crash-recovery receipt](../../evidence/crash-recovery.txt) describe their workloads, machines, commands, and results. Early convergence measurements are not acceptance evidence when their clocks began with writes still in flight or their crash checks did not arm the integrity comparison. The later records linked above supersede those readings rather than preserving them as passing results.

