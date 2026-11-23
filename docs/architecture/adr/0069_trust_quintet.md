# ADR-0069: Admission bounds for unauthenticated work

- **Status:** Accepted, with later amendments in [ADR-0070](0070_receive_path_admission_and_attribution.md).
- **Date:** 2026-10-12

## Context

[ADR-0067](0067_ingress_admission_and_relay_resolution.md) moved Lamport
advancement after relay verification, but the receiver still advanced its clock
before applying the inner event. `ReconstructEntryWithSkewBound` therefore
compared an event's dot with a clock that had already advanced to that dot. A
registered but compromised origin could send one verified zero-hop event with a
dot of `2^62`, move `NextDot` beyond the useful range, and have the receiver
record the poisoned high-water in the WAL.

Four other paths trusted unauthenticated input with too much work or state:

- The atomic batch rejection introduced in [ADR-0010](0010_batched_delta_wire_v1.md)
  treated a Lamport-skew error like a digest or attribution error. One
  over-bound element rejected every valid element in the batch, so re-shipping
  the same batch could not heal the tail.
- `PeerBucket.Accept` charged a claimed identity before authenticating it. An
  impostor could consume a victim's sequence-advance budget with frames that
  failed clock, depth, directory, or signature checks.
- The connection challenge responder in [ADR-0068](0068_gateway_anchor_pinning.md)
  would sign an answer for every well-formed challenge. A caller could request
  Ed25519 work without first proving possession of a registered key.
- A zero-value `Gossiper` has no `PeerSet`. `DeliverDigest` could dereference
  that nil pointer while checking `egressVerified` instead of rejecting the
  frame.

Self-originated deltas also arrived in delta-walk order. Sorting them by dot
before publication lets each accepted event advance the receiver's clock for
the next one, rather than relying on the pre-apply advance to hide skew.

## Decision

### Advance Lamport time only for an applied entry

Remove the production pre-apply `r.cap.Advance(dotCounter)` call from
`Receiver.HandleFrame`. `ApplyCRDTDeltaEvent` takes the pre-event Lamport
snapshot, and `DeltaCRDTEngine.Join` calls `AdvanceLamportTo` only for an entry
that passes reconstruction and joins the engine. A verified event outside the
skew window returns `DropVerify` with
`WireIntegrityLamportSkewPoisoning`; it changes neither the clock nor
`NextDot`.

The receiver brackets the apply with `LamportCounter` calls and invokes
`onClockAdvance` only when the post-apply value is higher. The WAL therefore
records advances made by applied entries, not advances merely claimed by an
inbound frame. `IngressHLCScalarCap.Advance` remains for tests and for the
fault control that restores the old ordering; production receive code does not
call it.

`Gossiper.shipDelta` buffers selected self-originated events, sorts them by
`Entry.DotCounter`, and only then signs and publishes them. Cancellation stops
the publication loop; unsigned events are left for a later sweep rather than
incurring new signing work during teardown.

### Admit the valid subset of a batch

`DeltaCRDTEngine.ApplyCRDTDeltaBatch` takes one `LamportSnapshot` for the whole
batch and returns `BatchApplyResult{Joined, Held, HeldDots}`. A
`WireIntegrityLamportSkewPoisoning` error holds only that element and decoding
continues, allowing valid elements at any position to join through one `Join`
call.

All other integrity failures retain ADR-0010's atomic rejection. A digest,
attribution, version, or wire-read error returns a zero result and an error
identifying the failing element; no accumulated element is joined. An empty
batch remains an accepted no-op. A batch with `Joined == 0 && Held > 0` returns
`DropVerify` and increments `batchSkewHeldTail`, distinguishing a fully held
batch from an empty one.

The index feed receives only joined elements. As amended by ADR-0070, the
reported delta origin comes from the first joined element rather than element
zero, which may have been held. A batch with any held elements is not retained
for relay: its single signature covers the full wire, so a relayer cannot split
off and re-sign the joined subset, and replaying the full frame cannot heal the
held tail. The sender re-ships it after the acceptance window advances.

### Refund charges made before authentication

`PeerBucket.Accept` returns both its decision and the counter delta charged to
the identity. `PeerBucket.Refund` returns that delta to the budget, capped at
`initialBudget` (`1 << 20`), without rewinding a committed
high-water mark.

The receive paths refund failures that occur before the charged identity is
authenticated:

- per-frame physical-clock rejection and relay-envelope open failures,
  including excessive depth and relay-signature failures;
- classical and hybrid batch directory misses and signature failures; and
- strict hybrid `LookupBoth` and `VerifyBatchHybrid` failures.

Drops after the relevant authentication point keep the charge. Otherwise a
verified relay could forward an unlimited stream of frames with invalid
origins without spending its own budget. An authenticated frame that later
fails origin verification or integrity checks therefore remains charged.

ADR-0070 completes this boundary by splitting the sequence watermark from the
charge. `Accept` normally leaves `lastCounter` unchanged;
`CommitHWM(pub, counter)` advances it only after the relay envelope, batch
signature, or hybrid batch signature verifies. Without that amendment, a
refunded impostor frame could still advance the victim's watermark and make
the impostor's next frame at the same counter look like a free duplicate.

### Bound challenge-answer signing

A connected peer may receive at most 16 challenge answers per connection,
tracked by `challengeAnswers`. The stateless responder for a declined or
unregistered connection has no persistent per-connection counter, so it uses
both a per-suspect-key limit of 64 and a `PeerSet`-wide ceiling of 65,536
reservations. After a decode failure the suspect key is the remote address,
which an attacker can rotate; the global ceiling is the bound that address
rotation cannot reset.

Both paths reserve budget before calling `identity.SignCRDTFrame` and refund
the reservation if signing fails. A fresh connection can still receive the
one answer required by the handshake. The reservation maps are allocated
lazily in the cold portion of `PeerSet`, away from frequently accessed state.

The original decision used lifetime declined reservations. ADR-0070 replaces
that policy with a 10-minute TTL, reclamation on lookup, and rate-limited
sweeps when the global ceiling is reached. A fresh live-edge mark exempts a
peer from the per-key cap so that mutual-dial reconnects can verify, but its
answers still count toward the global ceiling. Expiry permits recovery
without a periodic refill or restart; exhausting the live global budget still
suppresses further stateless answers.

### Reject digest delivery without a peer set

`Gossiper.DeliverDigest` checks `g.peers == nil` before calling
`egressVerified`. It drops the frame, increments
`deliverDigestNilGuardDrops` separately from `digestUnverifiedDrops`, and logs
the first eight occurrences and every 1000th thereafter. The guard matters
for zero-value and test harness gossipers even though normal production
construction installs a `PeerSet`.

## Consequences

- A verified but over-bound dot no longer changes Lamport time or produces a
  clock-advance WAL record. Ordered self-delta delivery supplies the clock
  progression that the removed pre-apply advance previously masked.
- `Accept` rejects a positive delta greater than or equal to the remaining
  budget without charging it. A charged budget therefore has a floor of one,
  not zero: 1,023 charges of 1,024 units followed by one charge of 1,023 units
  consume `2^20-1` units and leave one. Any later positive advance drops;
  duplicates still have a zero delta. `Budget` returns zero for a key that has
  no entry, rather than the initial allowance.
- The sequence budget has no time-based replenishment. Refund and high-water
  commit are separate operations, so a caller cannot use a pre-authentication
  failure to rewind another frame's committed watermark.
- `selfShip` holds the complete selected self diff until publication. A fixed
  collection cap is not a sound memory bound: with a deterministic digest-less
  walk, every sweep would select and truncate the same prefix and the omitted
  tail would never ship. Bounding the generated diff is the appropriate place
  to limit this buffer.
- Replayed all-held batches still require decoding and reconstruction on each
  arrival. Capping their log messages limits diagnostic volume, not that CPU
  work. Held-batch, challenge-budget, malformed-challenge, and nil-peer
  counters remain exact when their logs are suppressed.
- Skipping retention for a partially held batch also delays relaying its joined
  subset from that receiver. Onward propagation resumes after a later full
  join; this is preferable to pinning a frame that cannot heal its held tail.
- The connected-arm signing-failure log remains uncapped. Signing uses a
  fixed-size local message and the owner's seed, so a remote caller cannot
  induce this failure class; it indicates local misconfiguration or a test
  fault.

## Evidence

These are in-process and loopback regression tests, not multi-region
performance measurements.

- `TestClockBrick_BoundedAdvance` in
  `pkg/receive/admission_trust_test.go` sends a verified zero-hop event with
  dot `2^62`. It checks the skew error kind, unchanged clock and `NextDot`,
  and the absence of a clock-advance record.
- `TestSubsetAdmission_AdversarialBatch` places an over-bound element first
  and at position 50 in separate 100-element batches. The other 99 elements
  join in each case and one element is held.
  `TestSubsetAdmission_NonSkewDigestPreserved` checks that digest corruption
  still rejects the whole batch with zero joins.
  `TestSubsetAdmission_PureHoldReturnsDropVerify`,
  `TestSubsetAdmission_HeldTailSuppressesSideEffects`, and
  `TestAcceptVerdict_AcceptedCountsJoined` cover the pure-hold verdict,
  joined-only side effects, and acceptance accounting.
- `TestPreVerifyRateBudget_RefundPerFrame`,
  `TestPreVerifyRateBudget_RefundBatch`, and
  `TestPreVerifyRateBudget_AcceptedChargeStands` exercise the refund sites,
  the one-unit budget floor, and the rule that authenticated work remains
  charged.
- `TestQ5AnswerBudgetConnectedArm` sends 100 challenges and checks 16 answers
  and 84 drops, then checks that a fresh connection receives its first answer.
  `TestQ5AnswerBudgetDeclinedArm` checks the fresh-connection margin, the
  64-answer per-key cap, and the 65,536-reservation global composition across
  1,024 rotating connections. Attempts above the ceiling produce 1,095 drops.
  Race builds run the margin, per-key, and concurrent cases but skip the full
  global composition because it is too slow under race instrumentation.
- `TestQ5bSignFailBurnConnectedArm` covers refunds after signing failures.
  `TestQ5cPreBudgetNoiseCap` sends 100 malformed challenges and permits at
  most eight parse-failure messages. `TestI7NilPeersGossiperDeliverDigestNoPanic`
  and `TestI7bNilGuardCounterSplit` cover the nil-peer guard, its dedicated
  counter, and its log cap.
- `TestQ1HashOrderHealBoundedRefusals` restores unordered delivery for 3,000
  writes made during a partition. It requires all 3,000 keys, a final Lamport
  counter of 3,001 and convergence within four driven rounds. Skew-refusal
  totals vary with walk order and the time-dependent admission envelope, so
  they are recorded rather than asserted.
- The order control recorded zero descents with sorting and 1,487 descents
  without it over 3,000 arrivals in three consecutive runs. The permanent
  `TestNegativeControlOrderControl` asserts ascending arrival normally and at
  least one descent with sorting disabled, rather than depending on the
  incidental descent total.
- Fault controls restore each removed defect:
  `TestAdmissionFault_ClockAdvanceDeferControl`,
  `TestAdmissionFault_PreVerifyRefundControl`,
  `TestSubsetAdmissionFault_RejectWholeBatchOnSkew`,
  `TestNegativeControlBudgetControl`, and
  `TestNegativeControlNilGuardControl`. Ordinary test runs leave these
  controls disabled.
- `TestSkewConvergenceDefaultPath`, `TestSkewConvergenceBatchedPath`, and
  `TestSkewConvergenceUnderBound` retain coverage of ordered per-frame and
  batched healing and of events already within the skew window.

