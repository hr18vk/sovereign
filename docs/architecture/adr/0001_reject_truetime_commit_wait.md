# ADR-0001: Reject TrueTime commit-wait; HLC + Amazon Time Sync ε suffices

> Status: Accepted
> Date: 2026-07-25
> Supersedes: none
> Superseded by: none

## 1. Context

The engine is a state-based δ-CRDT. Per `docs/architecture/4_NETWORK_CONSENSUS.md`
§4.1, δ-CRDT states form a join-semilattice `(S, ⊔, ⊥)` where `⊔` is commutative,
and the engine converges regardless of delivery order, duplication, or transient
loss. The convergence guarantee is a property of the lattice, not of clock
agreement.

Causal consistency — the property a CRDT mesh actually needs — is a partial-order
property, not absolute linearizability. My reasoning:

CRDT convergence operates on causal partial ordering, so bounding a Hybrid Logical
Clock against the Amazon Time Sync Service (`169.254.169.123`), which yields a
reliable error margin of ~26-50µs, is mathematically sufficient to thwart
Byzantine Sybil inflation without the commit-wait throughput penalties of
Spanner-like architectures. Imposing commit-wait delays contradicts the
offline-first, high-fanout objectives of the P2P synchronization architecture;
because CRDTs natively converge on causal partial ordering, absolute
linearizability is superfluous. The HLC, paired with the microsecond accuracy of
Amazon Time Sync and per-peer EWMA bounds, provides a partial ordering sufficient
for causal consistency and Byzantine fault tolerance without the latency penalties
of wait-until-safe consensus.

The temporal substrate in production is Amazon Time Sync PTP (`169.254.169.123`),
documented error margin ~26-50µs, sourced from standard Graviton4 hardware
timestamping.

The open question this record closes (the commit stage): does causal consistency
require TrueTime-style commit-wait (sleep ε before ack), as Spanner imposes for
strict linearizability? No. This record documents that decision and the
causal-sufficiency argument behind it, and it is enforced structurally by the
wait-until-safe guard at `pkg/sync/truetime_wait_guard_test.go`
(`TestNoTrueTimeWaitUntilSafe`).

## 2. Decision Drivers

- **D1: Throughput.** CRDT ingress is O(1)-admit (`pkg/clock/admission.go`,
  `IngressHLCScalarCap.Admit`); a commit-wait inserts an O(ε) sleep per Join,
  directly taxing the ingress hot path.
- **D2: Offline-first / high-fanout objective.** The P2P synchronization
  architecture targets high-fanout, intermittently-connected peers; a per-Join
  commit-wait contradicts that objective at the architectural level.
- **D3: Causal-sufficiency.** CRDTs converge on delivery, not on clock agreement —
  the join-semilattice property (`4_NETWORK_CONSENSUS.md` §4.1). The convergence
  guarantee does not depend on bounding clock uncertainty at commit time.
- **D4: Byzantine Sybil inflation is already thwarted by the HLC scalar cap**
  (`pkg/clock/admission.go`, `IngressHLCScalarCap`), not by commit-wait. The
  defense is a clock-reject, not a sleep-wait.

## 3. Considered Options

- **Option A: Adopt TrueTime commit-wait.** Sleep ε before ACK, bounding
  physical-clock uncertainty at the commit stage, as Spanner does for strict
  linearizability. **Rejected** — see §4/§5.
- **Option B: Reject TrueTime; keep O(1) non-blocking Join + HLC scalar-cap bound
  against Amazon Time Sync ε + per-peer EWMA drift.** **Accepted.**

## 4. Decision (the load-bearing claim)

I accept Option B. The engine never introduces a TrueTime commit-wait interval in
the Join path. HLC + Amazon Time Sync ε (~26-50µs) + per-peer EWMA bounds are
mathematically sufficient for CRDT causal consistency (which requires only causal
partial ordering, not absolute linearizability). TrueTime is the right tool for
Spanner's strict linearizability; it is superfluous for a CRDT mesh.

This decision is enforced structurally, not merely documented:
`TestNoTrueTimeWaitUntilSafe` (`pkg/sync/truetime_wait_guard_test.go`) performs a
depth-1 AST scan of the Join call graph and fails at CI time if a wait-until-safe
primitive (`time.Sleep`, `time.After`+receive, a clock-keyed `Wait`, or a `<-` on a
channel named for the uncertainty window) is introduced into Join or its direct
callees. A future change adding commit-wait breaks the guard before merge.

## 5. Rationale — the causal-sufficiency argument (C1-C5)

This argument rests on the join-semilattice math (`4_NETWORK_CONSENSUS.md` §4.1)
and on the properties of an HLC bounded against a physical reference. I record it
here as the canonical citable home for the decision.

- **C1 (lattice):** δ-CRDT states form a join-semilattice `(S, ⊔, ⊥)`;
  `⨆ᵢ δᵢ = ⨆ᵢ sᵢ` regardless of order (`4_NETWORK_CONSENSUS.md` §4.1). Convergence
  is a lattice property, independent of commit timing.
- **C2 (causality needs only partial):** causal consistency is a partial-order
  property; it needs Lamport-style "happens-before", not a total linear order.
  Linearizability is a strictly stronger property than causal consistency.
- **C3 (HLC provides the partial order):** a Hybrid Logical Clock bounds the
  logical Lamport clock against physical Amazon Time Sync ε, yielding a causal
  partial order with a ~26-50µs physical bound — sufficient density to neutralize
  malicious sequence inflation.
- **C4 (EWMA absorbs drift):** per-peer EWMA bounds tighten the inter-peer drift
  below ε, defeating Sybil inflation without blocking.
- **C5 (commit-wait buys nothing on a CRDT):** linearizability (TrueTime's target)
  is a strictly stronger property than causal consistency; adopting the stronger
  property leaves the convergence guarantee unchanged (already guaranteed by C1)
  but adds per-op latency. Negative latency-after-free.

Therefore TrueTime commit-wait is superfluous and penalizing → reject.

## 6. Consequences (N1-N4)

- **N1:** Join is O(1)-non-blocking; per-op fsync (NVMe, ~1.5µs p99) is the only
  durability latency; no ε sleep on top.
- **N2:** The throughput ceiling is the HLC scalar cap + NVMe fsync, not clock
  uncertainty. The ~60µs 32c verify is the cap divisor.
- **N3:** Byzantine Sybil inflation is a clock-reject, not a sleep-wait
  (`IngressHLCScalarCap.Admit` returns `bool` in O(1), `pkg/clock/admission.go`).
- **N4:** A future change to introduce commit-wait must amend this ADR
  (ADR-0001b) and re-open the math — see the wait-until-safe guard
  (`pkg/sync/truetime_wait_guard_test.go`). The guard fails on such a change; the
  correct response is to amend the ADR with new evidence, not to loosen the guard.

## 7. Relationships

- **R1:** `docs/architecture/4_NETWORK_CONSENSUS.md` §4.1 — the join-semilattice
  math this decision relies on.
- **R2:** Enforced structurally by the guard at
  `pkg/sync/truetime_wait_guard_test.go` (`TestNoTrueTimeWaitUntilSafe`).
