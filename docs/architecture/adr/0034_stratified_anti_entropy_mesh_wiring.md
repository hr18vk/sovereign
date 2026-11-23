# ADR-0034: Exchange full IBLT digests for stratified anti-entropy

**Status:** Accepted  
**Date:** 2026-08-11

## Context

The mesh sweep generated a delta against an empty remote IBLT for every peer. This sent every local entry on every sweep, giving O(N×M) traffic for N peers and M entries even when the peer already held almost all of them.

`GenerateDeltaStratified` appeared to offer reconciliation from a StrataEstimator, but it allocated a remote IBLT and never populated it. Subtracting that empty table returned the full local set. Its unit test covered only an empty remote, where this behavior happened to be correct, so the defect did not appear until overlapping state was tested.

A StrataEstimator cannot repair this interface. Its XOR summaries estimate difference size but cannot reconstruct the remote keys. Reconciliation needs the peer's populated IBLT.

## Decision

Exchange a full IBLT over the peer-TLS data plane before generating each peer's delta, then call `GenerateDelta(remoteIBLT)`. The exchange uses a length-prefixed mesh-internal frame identified by `WireDigestMagic`, with `MarshalStrataEstimator` and `MarshalIBLT` for the payload. `DispatchFrame` routes it to `DigestSink.DeliverDigest`, and `PeerSet.SetDigestSink` connects that sink to the gossiper. The estimator is a sizing hint; the populated IBLT supplies the actual set difference.

Delete `GenerateDeltaStratified`. That function also omitted `participantPoolPtr`, so `CRDTDelta.Release` exited its EBR participant without returning it to the pool. The retained `GenerateDelta` path already sets the pointer and recycles the participant, making a separate repair to the deleted primitive unnecessary.

Stratified anti-entropy remains opt-in. A digest timeout, malformed frame, incomplete peel, or publish failure falls back to generating the full delta. `Join` is idempotent, so this fallback costs bandwidth without changing the converged state. `StratifiedAntiEntropyFallback`, exported as `supremum.mesh.stratified_fallback`, records each fallback. Its introduction grew the counter registry from 18 to 19 entries.

## Consequences

Overlapping peers can exchange only the recovered difference instead of the complete local set. Failure always selects the convergence-sufficient superset; no failed peel is presented as a complete delta. With the feature disabled, the original oversend behavior and wire path remain in use.

The original fixed 1,024-bucket digest saturated at high load. A probe recovered 188 differences with 750 total entries and 562 overlapping entries, but fell back to oversend at 800 entries. These are historical in-process measurements, not a current fleet limit.

Later records refine the mechanism without changing the fallback contract:

- [ADR-0055](0055_deterministic_cross_process_iblt_hash.md) makes bucket placement deterministic across processes. The original process-random hash could prevent common keys from cancelling and cause oversend between otherwise identical nodes.
- [ADR-0064](0064_iblt_reconciliation.md) adds opt-in IBLT v2 placement, stable digest snapshots, bounded remote sizes, and adaptive bucket counts behind `--iblt-v2`. The default remains v1 with its fixed 1,024-bucket digest; a mixed-version pair falls back to oversend until both sides use the same scheme.
- Later digest frames carry request roles, seeds, sender identity, and timing information. `DispatchFrame` in `pkg/mesh` is the dispatch point; the early reference to a receive-package handler was not the shipped design.

The current bandwidth tests use smaller overlapping sets than the acceptance measurements to reduce probabilistic peel failures. They test the remote-operand mechanism, not a new throughput claim.

## Evidence

The acceptance tests ran in process on four cores. With stratification enabled and disabled, 1,000 events converged in 1 round to the same Merkle root. The focused primitive measurement returned 150 entries from a 600-entry local set instead of all 600, a 450-entry cut, or 75.0%, using a 1,024-bucket digest at 0.59 load. A negative control with an empty remote IBLT returned all 600, demonstrating that the populated remote operand causes the reduction.

The original wire-cost test measured 72,311 bytes per peer per round: 51,789 bytes of StrataEstimator data, 20,498 bytes of IBLT, and a 24-byte header. At 75% overlap the net saving was 2,689 bytes. The test also exposed the cost when differences are small. These figures describe the original frame and must not be applied to later formats.

`TestPooledBufferNoLeak` completed 2,000 `GenerateDelta` and `Release` cycles; its control demonstrated the missing pool return. `TestCRDTEngine_GenerateDeltaWithRemoteIBLT` covers empty, 3-of-5-overlap, and identical remote tables, yielding respectively the full set, the 2-entry difference, and an empty delta. Current coverage is in `pkg/mesh/stratified_antientropy_test.go` and `pkg/sync/crdt_test.go`, including convergence, fallback telemetry, the bandwidth reduction, race detection, and wire cost.
