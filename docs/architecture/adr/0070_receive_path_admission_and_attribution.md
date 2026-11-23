# ADR-0070: Receive-path admission and attribution

- **Status:** Accepted
- **Date:** 2026-10-12

## Context

Four receive-path seams allowed unabsorbed work to affect later traffic.
`PeerBucket.Accept` committed a sequence watermark when it charged a frame, so
a rejected impostor could make its next frame at that sequence look free.
Declined-connection challenge reservations never expired, eventually blocking
a legitimate peer's re-verification. A partially applied batch was retained
even though replaying it could not heal its held tail. Finally, a partial join
could leave the delta origin blank when element zero was held.

These are accounting and attribution errors, not changes to the CRDT merge or
wire format.

## Decision

### Commit sequence watermarks after authentication

`PeerBucket.Accept` computes and charges sequence advancement but normally
leaves `lastCounter` unchanged. It returns the charged delta so failures before
authentication can call `Refund` without rolling back another frame's
watermark.

`PeerBucket.CommitHWM` is the separate post-authentication writer. Under the
shard lock it sets `lastCounter = max(lastCounter, counter)`. The per-frame
path calls it after the relay envelope opens; classical and hybrid batch paths
call it after their origin signatures verify. Calls are gated on a positive
charge because duplicates neither consume budget nor need a commit.

Refund and commit sites cover disjoint outcomes. A frame rejected before its
charged identity is authenticated is refunded with no watermark advance. Once
authenticated, later origin or apply failures keep both the charge and the
committed watermark; there is no post-authentication refund path.

### Expire declined-challenge reservations

A live-edge decline in `RegisterInbound` records the peer's suspect key in
`challengeDeclinedLiveEdge` after releasing the peer-map lock. A fresh mark
exempts that peer's stateless challenges from the ordinary per-key limit of 64
because its working connection already establishes the legitimate mutual-dial
case. The global ceiling still applies.

Each `declinedRes` stores a count and its latest reservation time. Records
expire after 10 minutes and are reclaimed lazily, allowing a fresh allowance
without a restart. At the global ceiling of 65,536 reservations, expired-record
sweeps are rate-limited to one per second rather than walking the map for every
53-byte challenge. The global count is re-derived from the surviving map sum.

Live-edge reservations also have map records even though the per-key limit does
not bind for them. This keeps the global count equal to the map sum when a
sweep runs; otherwise repeated sweeps could restart an attacker's window. The
600-second TTL permits about 109 answers per second across the PeerSet rather
than approximately 65,536 per second through that accounting hole.

`refundDeclinedReservation` decrements a live record and the global count only
when both are present and positive. A signing failure after lazy expiry or a
ceiling sweep therefore cannot create a zero-value record, wrap a counter, or
refund the same reservation twice.

### Do not retain partially held batches

When `BatchApplyResult.Held > 0`, both `Receiver.HandleBatchFrame` and
`HandleHybridFrame` skip relay retention. One origin signature covers the
complete batch wire, so a relayer cannot split off and re-sign only the joined
subset. Replaying the complete frame cannot merge the held tail while its skew
bound still fails; retaining it would only pin relay memory after the sender
has paid the OriginSeq charge.

The sender re-ships after other accepted entries advance the window. A complete
later apply is retained normally. The trade-off is that the initially joined
subset also waits for that full join before this receiver relays it.

`Receiver.noteHeldTail` shares the batch and hybrid accounting. It increments
`batchSkewHeldTail` by the exact held count and limits diagnostic messages to
the first eight and every 1000th occurrence.

### Attribute a partial join to its first joined element

`DeltaCRDTEngine.ApplyCRDTDeltaBatch` sets `batchOrigin` only when the
accumulated join set is empty. If element zero is skew-held, the first element
that actually reconstructs supplies the origin instead of leaving the zero
value. A full apply still takes element zero as before.

`BatchApplyResult.DeltaOriginNodeID` exposes that `[16]byte` origin for tests
and receive-side attribution. `Join` does not read the result field, so this
observation does not alter delta wire bytes.

### Make recovery tests wait for observed state

`TestDeferRecovery` replaces a fixed five-round sleep with a poll bounded by 60
seconds. It waits for `digestGateSkips` to exceed its pre-poll value while
checking that defer counts stay reset and gated rounds remain no-ops. The test
now observes asynchronous convergence instead of assuming a wall-clock delay is
sufficient on a loaded machine.

## Consequences

An unauthenticated frame cannot consume a victim's sequence allowance by
advancing its committed watermark. Declined peers recover after reservation
expiry, while the global ceiling continues to bound stateless signing work; a
flood can still exhaust that shared allowance until records expire.

Partial batches trade immediate relay of their joined subset for avoiding
retention that cannot repair the held tail. Exact counters remain available
when repetitive logs are suppressed. Partial joins retain a meaningful origin
without changing merge behavior or signed bytes.

## Evidence

These are in-process and loopback TLS regression tests with direct counter and
state assertions.

- `TestPendingWatermark_CommitAndRollback` in
  `pkg/receive/watermark_and_partial_retain_test.go` covers relay-signature,
  batch-signature, and hybrid-directory failures. Each rejected sequence is
  charged in full on retry, while a successfully applied frame's duplicate is
  free.
- `TestPendingHWMFaultControl` in `pkg/admission/pending_hwm_fault_test.go`
  restores charge-time watermark writes under
  `SOVEREIGN_TEST_FAULT_SEAMS=pendhwm` to exercise the old admission bypass.
- `TestN2DeclinedPolicy` in `pkg/mesh/seams_test.go` sends 70 challenges over a
  declined connection after one on another declined connection. It requires 70
  answers on the flood connection, 71 reservations recorded per key and
  globally, and no drops despite the ordinary 64-answer per-key limit.
- `TestN2TTLRecoveryUnderflowGuard` covers expiry after a shortened TTL and
  directly exercises refunds against absent, live, and disconnected records.
  `TestSweepRetainsLiveEdgeSpends` in `pkg/mesh/sweep_collapse_test.go` checks
  global accounting across a ceiling sweep.
- `TestPartialBatch_SkipRetentionForSkewedFrames` joins two of three elements
  without retaining the partial frame, advances the skew window, and requires
  the re-shipped full batch to join and be retained.
  `TestPartialBatchFault_RetainOnHoldControl` in
  `pkg/receive/partial_batch_retain_fault_test.go` restores the old behavior
  under `SOVEREIGN_TEST_FAULT_PARTIAL_RETAIN=retain`.
- `TestBatchApply_SpikeAtIndexZeroJoinsSubset` and
  `TestBatchApply_OriginTakenFromFirstJoinedElement` in
  `pkg/sync/first_joined_origin_test.go` cover a held first element and a
  distinct origin on the joined elements. `TestFirstJoinedOriginFault_BlankOriginReturns`
  in `pkg/sync/first_joined_origin_fault_test.go` provides the fault control.
- `TestDeferRecovery` in `pkg/mesh/defer_test.go` covers the driven 60-second
  recovery poll.
