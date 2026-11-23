# ADR-0067: Ordered ingress and two-layer relay resolution

- **Status:** Accepted; the pre-apply clock advance is superseded by
  [ADR-0069](0069_trust_quintet.md).
- **Date:** 2026-10-10

## Context

Three defects prevented partitioned nodes from healing safely.

First, `Gossiper.shipBatchedDelta` walked self-originated deltas in hash order
and flushed every 100 entries, the default batch size. With a backlog of 6,000
dots and an admission bound of roughly `1001`, a random 100-element chunk has
probability `(1000/6000)^100 ≈ 1.5e-78` of staying within the bound.
`ReconstructEntryWithSkewBound` therefore rejected the whole batch, the
receiver's clock never advanced, and the next sweep sent the same ordering.
This was not a cliff immediately above the bound: for a backlog just above that
bound, `(1000/1002)^100 ≈ 0.82`, so small excesses can heal by chance.
`Receiver.HandleHybridFrame` reached the same atomic batch apply and had the
same failure mode.

Second, `IngressHLCScalarCap.Admit` advanced the receiver's Lamport clock during
its inexpensive drift check, before the Directory lookup and signature check.
An unregistered or forged origin could consequently move the clock without
proving possession of a registered key.

Third, relay retention had two layers but each send path consulted only one.
`shipDelta` missed foreign entries retained from batches, while
`shipBatchedDelta` missed entries retained from per-frame envelopes. A mixed
deployment could therefore stop propagating after one hop.

## Decision

### Sort self-originated deltas before publication

`shipBatchedDelta` accumulates the selected self diff, sorts it by ascending
`Entry.DotCounter`, and then divides it into batches. Each accepted prefix
advances the receiver's Lamport window for the next prefix, replacing random
hash-order progress with a monotone crawl. The sort is sender-side and costs
`O(D log D)` for a selected diff of size `D`; it does not add receive-path
allocation.

Receiver-side gate insertion alone could not heal an unordered multi-window
batch: its hash-ordered chunks still exceeded the bound, so sender ordering was
required under either design. Advancing before the apply snapshot would also
recreate the skew-check tautology on the batch path.

ADR-0069 extends ordered publication to `shipDelta`. When stratified
anti-entropy and the defer handler are both disabled, the shared-delta path
also builds and sorts the common self-event buffer once per sweep rather than
once per peer. Per-peer deltas and active defer windows retain their own walks.

### Advance Lamport time only after authentication

The original decision made `Admit` a pure drift check and moved
`IngressHLCScalarCap.Advance` after signature verification but before apply.
That stopped unverified frames from stamping the clock while allowing a
verified large-dot event to pass the apply path's skew check.

It also left a verified but compromised origin able to poison the clock: the
pre-apply advance made the subsequent skew comparison tautological.
[ADR-0069](0069_trust_quintet.md) removes the production pre-apply advance.
`ApplyCRDTDeltaEvent` takes the pre-event snapshot, and
`DeltaCRDTEngine.Join` calls `AdvanceLamportTo` only for an entry that passes
reconstruction and joins. Ordered self-delta delivery supplies the progression
that the removed advance previously masked. `IngressHLCScalarCap.Advance`
remains for tests and the fault control, not the production receive path.

### Resolve both relay layers under one budget

A foreign entry remains in the layer in which it arrived. `shipDelta` first
uses `relayCache.lookup` and falls back to `lookupBatchCounted`;
`shipBatchedDelta` performs the reverse fallback through `resolveForeign`.
The relayer republishes the retained origin-signed bytes rather than signing
for another origin.

Both paths pass a `costOf` function to `walkDeferWindow`. Self and per-frame
entries cost one received element, a retained batch costs its decoded element
count, and misses or duplicate batches cost zero. The single
`deferSliceMaxEntries = 608` budget therefore covers fallback traffic as well
as ordinary traffic in each peer's escalation round. Lazy relay-map allocation
and the canonical counted batch lookup avoid adding redundant cache work.

## Consequences

Ordered batches heal a multiple-window backlog in one or two driven sweeps in
the loopback regression tests, for both classical and hybrid signatures. Mixed
batch and per-frame relays now converge in either direction. The receive-side
skew bound remains in force; sender ordering supplies valid prefixes rather
than weakening admission.

The sender buffer holds the selected self diff until publication. Its memory
must be bounded by delta generation, not by truncating every walk to the same
prefix. Later shared-delta construction reduces repeated sorting only when all
peers really do share the same delta.

A receiver cannot rely on every sender to order chunks. ADR-0069's subset
admission lets valid elements join while holding only over-bound elements, so
an old or hostile ordering no longer rejects every valid element with them.
The sender still has to re-ship held entries after the window advances.

## Evidence

These are in-process and loopback TLS regression tests, not multi-region
performance measurements.

- `TestSkewConvergenceDefaultPath`, `TestSkewConvergenceBatchedPath`, and
  `TestSkewConvergenceUnderBound` in
  `pkg/mesh/lamport_skew_convergence_test.go` cover ordered healing and events
  already inside the admission window.
- `TestI2HybridHeal` in `pkg/mesh/ingress_test.go` creates a partition backlog
  of 6,000 entries and requires hybrid batches to converge in one or two
  driven sweeps with no skew refusals and matching roots.
- `TestI3A1ClockBrick` checks that an unverified origin cannot advance the
  receiver's clock or keyset. The gateway drop counter proves that the sweeps
  attempted to send.
- `TestI4MixedRelay` and `TestI4Mirror` each relay 100 keys through the mixed
  retention direction and require all three roots to converge with no relay
  misses at the middle node.
- `TestRelayFallbackOneBudgetPerFramePath` in
  `pkg/mesh/relay_fallback_budget_test.go` offers seven 100-entry batches
  during defer escalation. Every round must remain within the 608-element
  received-cost budget; charging one per envelope instead of per element would
  admit all 700 entries and fail the test.
- ADR-0069 records the tests for subset admission and the later removal of the
  pre-apply advance, including `TestClockBrick_BoundedAdvance` and
  `TestSubsetAdmission_AdversarialBatch`.
