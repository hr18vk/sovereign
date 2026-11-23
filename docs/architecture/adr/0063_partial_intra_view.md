# ADR-0063: Partial intra-region view

**Status:** Accepted  
**Date:** 2026-10-02

## Context

Region-aware gossip selected every same-region peer on every sweep, so the
intra-region selection count grew linearly with region size and every pair
repeated the same exchange each round. A rotating subset could reduce that
work only if selection remained deterministic, uniform across rounds, and
capable of reaching every peer in both directions.

Synchronised rounds also concentrated digest responses. The responder bound
limits concurrent digest construction, not the total number of requests that
can arrive during a round; a correct selector could therefore still produce
an in-degree tail above that bound.

## Decision

Add `--partial-intra-view`, disabled by default and requiring
`--region-aware` at command startup. When it is armed on the non-hierarchical
topology path, `(*TopologyManager).drawIntraView` selects
`min(8, n_r-1)` distinct intra-region peers per sweep. It applies a partial
Fisher–Yates shuffle to the sorted candidate list with
`rand.NewPCG(seed, intraViewPCGStream)`. The seed is
`sweepRound ^ LittleEndian.Uint64(nodeID[:8])`, and the domain-separation
stream is `0x1D5EED5EEDB5EED`.

A region with at most 8 eligible peers retains the full intra-region mesh.
The non-region-aware path also remains a full mesh. Without hierarchical
gateways, inter-region selection is unchanged; [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md)
later defines how gateway pinning shares the same view budget.

At library level, enabling the view without a bound topology and region-aware
routing leaves the full mesh in use and logs one warning. `SetTopology(nil)`
is a valid unbind, and a later non-nil bind forwards the current setting.

Raise `digestRespondMaxConcurrent` from 8 to 16. This is twice the partial
view's expected in-degree, and the bound is independent of the flag. An armed
sweep adds `view_intra=%d/%d` and a zero-padded, 16-digit hexadecimal
`view_xor` field to its round log; an inactive view adds nothing. The
telemetry registry remains at 25 counters.

## Consequences

The selection-count reduction does not itself prove delivery: a census still
counts selections on a mesh that cannot receive, while the convergence tests
assert actual state agreement. Rotation supplies eventual pair coverage but
does not isolate a node from inter-region picks.

The responder semaphore can drop a response when all 16 slots are occupied;
the requester then uses its fallback. The measured static in-degree tail can
exceed 16 without drops on loopback because requests do not all overlap.
[ADR-0066](0066_sweep_phase_jitter.md) addresses that overlap rather than
removing the responder bound.

The draw itself measured 0 heap allocations per run on 33 candidates. This
does not make the surrounding `Select` allocation-free. The test-only
`StarveViewPeerOf` exclusion is compacted before the small-region return, so
its contract holds even when the production view would be the full mesh.

The convergence harness has two arms. The non-race arm uses N=100 and D=10K;
the race arm uses N=30 and D=200. On the 64-core test machine with 32 lanes,
building the N=100 race mesh took about 30 minutes, and D=10K saturated the
1,024-bucket digest into full-keyset oversend. Assertions that depend on the
large divergence remain in the non-race arm.

## Evidence

At N=100 in regions of 33/33/34, the armed census selected 1,000 peers per
sweep against 3,434 with the view disabled, a 3.43× reduction. The non-race
D=10K run converged in round 3.

All 120 views in the N=100 rotation run were distinct. Its chi-square value
was 39.3 against a critical value of 78.5. Across N=100/333/1000/3333 with
R=10,000; the worst chi-square values were
41.9/140.8/395.9/1163.4 against family-wise critical values of
78.5/182.0/449.6/1316.3; no peer was censored. The bidirectional live-pair
run observed A→B in 26/40 rounds and B→A in 23/40, with each firing checked
against that round's view checksum.

Synchronised static-round maximum in-degrees were 15/17/19/20 at
N=100/333/1000/3333, with zero drops in those loopback runs. The selector's
negative controls cover permanent exclusion, frozen seeds, correlated seeds,
and a mesh that cannot receive.

The current guards are `TestViewSize`, `TestViewRotation`,
`TestViewOffByteIdentical`, `TestViewConvergence`,
`TestViewConvergenceRaceFast`, `TestViewRotationBidirectionalLive`,
`TestViewStarveDegenerate`, `TestK8IntraViewSim`, and
`TestRegionFlags_DefaultOffAndOrphanGuard`.
