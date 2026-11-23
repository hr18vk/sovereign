# ADR-0001: Reject TrueTime commit-wait in the CRDT join path

> **Status:** Accepted
> **Date:** 2026-07-25
> **Supersedes:** none
> **Superseded by:** none

## Context

Sovereign Engine stores state as a delta CRDT. Its states form a
join-semilattice whose join is commutative, associative, and idempotent. Once
every mutation reaches every node, delivery order, duplication, and
retransmission therefore do not change the final dot set. The derivation is in
[Network Consensus and Distributed State](../4_NETWORK_CONSENSUS.md), §4.1.

TrueTime-style commit-wait serves a different purpose. Spanner waits out clock
uncertainty before acknowledging a transaction to provide external consistency.
That delay is not a prerequisite for CRDT convergence, and adding it to every
`(*DeltaCRDTEngine).Join` would tax an in-memory merge for a property the merge
does not need.

The receive path separately bounds untrusted timing and sequence inputs before
signature verification. `IngressHLCScalarCap.Admit` rejects a relay timestamp
too far ahead of the local physical clock, while `admission.PeerBucket` applies
a per-peer sequence-advance budget and maintains an EWMA of positive counter
deltas. These gates reject excessive inputs; they do not make a frame wait
until its timestamp becomes safe.

The original design assumed a host clock synchronized through Amazon Time Sync.
The implementation does not manage that service or measure its uncertainty:
`clock.SystemClock` reads the host operating-system clock with
`time.Now().UnixMicro()`. Clock synchronization is consequently a deployment
assumption, not a clock protocol implemented by the engine.

## Decision

Do not introduce a timer, sleep, or clock-uncertainty wait into `Join` or its
direct merge helpers. Keep physical-clock and sequence-admission checks at the
frame boundary, before signature verification and application. `Admit` performs
only the physical-time comparison; logical-clock advancement belongs to the
engine's apply path after validation.

This decision rejects commit-wait as a convergence mechanism. It does not claim
linearizability, a measured bound on host clock error, or Byzantine fault
tolerance from the scalar clock cap alone.

## Consequences

- `Join` merges and advances Lamport state without waiting for physical time to
  elapse. Write-ahead-log durability remains separate from this in-memory
  operation; no fsync latency is attributed to `Join` by this decision.
- A frame with an excessive future timestamp is rejected rather than delayed.
  The quality of host clock synchronization affects that admission decision and
  must be handled by the deployment environment.
- The scalar cap and per-peer sequence budget address different inputs. Neither
  replaces signature verification or establishes a global order of operations.
- A future design that needs external consistency must reassess this decision
  with new evidence rather than add a hidden wait to the merge path.

## Evidence

`TestNoTrueTimeWaitUntilSafe` in `pkg/sync/truetime_wait_guard_test.go` scans `Join`
and its direct callees in the join-path files. It rejects sleeps, timer-based
waits, clock-keyed condition waits, and receives from channels named for an
uncertainty window. The scan has depth 1: it is a focused regression check, not
a proof that an indirect call can never block.

The join-semilattice argument is documented in
[§4.1 of the network-consensus document](../4_NETWORK_CONSENSUS.md). The actual
clock comparison is in `pkg/clock/admission.go`, and the host-clock boundary is
in `pkg/clock/clock.go`.
