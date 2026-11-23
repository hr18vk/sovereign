# ADR-0054: Merkle-root digest change gate

**Status:** Accepted  
**Date:** 2026-09-17

## Context

The stratified anti-entropy sweep in [ADR-0034](0034_stratified_anti_entropy_mesh_wiring.md)
exchanged a digest with every peer on every sweep, even when both nodes already held the
same state. Each frame also serialized a 51,789 B StrataEstimator beside the 1024-bucket
IBLT. The responder built its own IBLT under the request seed and the requester subtracted
that IBLT; no consumer used the estimator on this path. A converged mesh therefore kept
paying for work and bandwidth proportional to the keyset rather than to its divergence.

The measurements also exposed a separate defect. Cross-process exchanges returned the full
10,000-key set to peers that already held those keys. In-process tests had not revealed this:
their engines shared the runtime state used by `maphash.Hash`, so common keys cancelled even
though independently running nodes placed them in different buckets. The earlier statement
that the data delta pruned to approximately zero was therefore valid only for the in-process
test, not for the mesh.

## Decision

Remove the estimator from ordinary digest frames and use the Merkle root to decide whether
an IBLT exchange is necessary. Treat the cross-process pruning defect as a separate change,
recorded in [ADR-0055](0055_deterministic_cross_process_iblt_hash.md).

### IBLT-only digest frames

`buildDigestFrame` writes `seLen == 0` and omits the StrataEstimator. The length field remains
in the mesh-owned frame so receivers can distinguish the estimator body from the IBLT body.
A current receiver can still parse a legacy frame containing an estimator; a legacy receiver
that rejects an IBLT-only frame falls back to the convergence-safe full-keyset path rather
than computing a difference from incompatible data.

For the 1024-bucket frame measured when this decision was made, removing the estimator reduced
the frame from 72,287 B to about 20,531 B. The Cap'n Proto delta schema did not change.

### Merkle-root announcements and the change gate

Every stratified sweep sends a one-way root announcement to each selected peer. At the time
of this decision the announcement was about 65 B. `recordPeerRoot` stores the announced root
in `peerRoots`, and `peerRootFor` returns the most recent value.

`digestGateFire` exchanges digests only when the peer root is unknown or differs from the
local root:

```text
!known || peerRoot != MerkleRootFromShards()
```

Matching roots skip the exchange but do not suppress subsequent announcements. Gating on
movement of the local root would be incorrect: a node that fell behind could remain unchanged
while its peers stayed ahead, and no node would start the exchange needed to recover it.

`MerkleRootFromShards` folds ordered `(DotNodeID, DotCounter)` values through SHA-256. Equal
state therefore produces equal roots across processes. The gate does not depend on IBLT
pruning to remain correct; it avoids the digest exchange for peers whose roots already match.
An unknown or mismatched root still selects reconciliation, and a failed digest still selects
the full-keyset fallback.

### Cross-process hash finding

`hashKeyWithSeed` originally computed bucket placement through `maphash.Hash`. Although
`SeedToUint64` and `Uint64ToSeed` preserve the seed's 8-byte backing word, `maphash.Hash`
also incorporates process-local runtime state. Two processes given the same key and wire
seed could consequently choose different buckets. Subtraction did not cancel common keys,
peeling exceeded the IBLT's capacity, and `GenerateDelta` sent the full keyset.

A five-process probe made the defect visible without a network: the same `(seed, key)` input
produced five distinct digests instead of one. The defect affected bandwidth, not the merge
result, because the fallback sends a superset that still converges. It remained relevant for
exchanges admitted by the new gate and required a deterministic hash and subprocess tests;
ADR-0055 supplies both.

The change gate was kept separate from that fix so the mesh-gating result and the hash result
could be measured independently. Responder drops also needed a counter before the responder
concurrency bound could be checked from run output.

## Consequences

Steady-state traffic falls to root announcements for peers whose roots match. A mismatch or
missing root costs an exchange, which is the safe direction: suppressing an exchange merely
because the local root has not changed could strand a behind node.

The gate introduces peer-keyed root state. That state initially had no eviction, so the bound
was the number of peers ever seen rather than the number currently live. ADR-0055 adds
sweep-time eviction. The original root-announce and IBLT-only sizes above describe the wire
format at this decision's date; later header and request-format changes do not alter the
root-mismatch rule.

The in-process wiring tests remain useful but have a narrow scope. They check `seLen == 0`,
legacy-frame handling, root-mismatch gating, behind-node recovery, and empty deltas for a
converged pair. They cannot establish cross-process hash determinism. The full-keyset
fallback remains available for malformed, timed-out, oversized, or unpeelable exchanges.

A `keyset=1500` subtest was removed after it timed out under the race detector. Its exchange
built approximately three keyset-sized IBLTs and exceeded the harness's 200ms digest wait;
extending the wait to 5s produced `delta=0`, while 200ms produced `delta=1500` through the
fallback. The retained `keyset=100` test asserts the same empty-delta behavior and passed
`-race -count=3` in about 2.6s. Removing the timing-sensitive case did not weaken that
assertion or substitute for cross-process coverage.

## Evidence

### Multi-region mesh

The comparison used 100 node processes on three c7gd.8xlarge machines, one per AWS region,
with 10,000 keys. Seven runs had the change gate disabled and seven had it enabled. These
are convergence-layer measurements, not core microbenchmarks or receive-path throughput.

| Measurement | Gate disabled | Gate enabled |
|:--|:--|:--|
| Runs | 7 | 7 |
| Median time to all 100 nodes | 8.934s | 7.258s |
| Runs meeting the 10s target | 6 of 7; one run took 15.282s | 7 of 7 |
| Steady-state NIC transmit per region | about 850–1082 MB/s | about 40–85 MB/s |
| Digest exchanges skipped per run | not applicable | 6950–10324 |

The enabled arm reduced steady-state transmit by about 13–19×. Its bandwidth was still
falling at the measurement cut, so these figures describe the measured window rather than a
long-run floor. The gate also removed the convergence-tail miss in this seven-run comparison;
that is not a claim that every later topology or workload has the same tail behavior.

### Regression checks

The mesh tests exercised IBLT-only and legacy frames, mixed-version convergence, matching-root
skips, disabled-gate negative controls, and a behind node rejoining after a partition. The
in-process exchange test used 100 keys and required six forced exchanges with a converged peer
to return empty deltas. Subprocess determinism was deliberately left to ADR-0055.

On a 32-core c8g.8xlarge, the selected race-detector runs passed with these durations:
durability 1503s, filtered mesh 265s, receive 519s, chaos 791s, database 654s, attribution 14s,
and admission 1s. The hot-path allocation check also passed. Separate full-suite timeouts are
addressed in ADR-0056. The same machine measured 70,954,377 ops/s in a
fresh in-process core microbenchmark,
with a standalone rerun at 69,781,746 ops/s against the 50,736,038 ops/s floor. Those figures
omit networking, TLS, signature verification, and persistence; they are not ingest rates.

