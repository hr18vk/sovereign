# ADR-0001: Reject TrueTime commit-wait; HLC + Amazon Time Sync ε suffices
> Status: ACCEPTED     Date: 2026-07-25     Track: Phase 3 Track 3.3
> Supersedes: none     Superseded by: none

## 1. Context

The Sovereign-Engine is a state-based δ-CRDT engine. Per
`docs/architecture/4_NETWORK_CONSENSUS.md` §4.1 (lines 3-17), δ-CRDT states
"form a join-semilattice `(S, ⊔, ⊥)` where `⊔` is commutative" and the engine
"converge[s], regardless of delivery order, duplication, or transient loss."
The convergence guarantee is a property of the lattice, not of clock agreement.

Causal consistency — the property a CRDT mesh actually needs — is a **partial
order** property, not an absolute linearizability property. This is transcribed
verbatim from the source prose at
`phase-03/Final_Sovereign_Architecture_Phase3.md:356-361` (the §2.X1(b) ruling):

> "(b) HLC + Amazon Time Sync vs TrueTime: PROVEN. ... CRDT convergence
> algorithms inherently operate on causal partial ordering. Therefore, bounding
> a Hybrid Logical Clock against the Amazon Time Sync Service (169.254.169.123),
> which yields a highly reliable error margin of ~26-50µs, is mathematically
> sufficient to thwart Byzantine Sybil inflation without the commit-wait
> throughput penalties associated with Spanner-like architectures."
>
> "[§2.X1(b)] CROSS-DOMAIN RULINGS (REVISED) ... imposing commit-wait delays
> fundamentally contradicts the offline-first, high-fanout objectives of the
> P2P synchronization architecture. Because Conflict-Free Replicated Data Types
> natively converge upon eventual consistency utilizing causal partial ordering,
> absolute linearizability is mathematically superfluous."

The precursor paragraph at `phase-03/CRDT Sync Engine Phase 3.md:106` states the
same decision: "The HLC, paired with the microsecond accuracy of the Amazon Time
Sync Service and per-peer EWMA bounds, provides a mathematically sufficient
partial ordering that guarantees causal consistency and Byzantine fault tolerance
without the latency penalties of wait-until-safe consensus protocols."

The temporal substrate in production is Amazon Time Sync PTP (`169.254.169.123`),
documented error margin ~26-50µs, sourced from standard Graviton4 hardware
timestamping (Final_Sovereign_Architecture_Phase3.md:361).

The open question this ADR closes (the commit stage): does causal consistency
require TrueTime-style commit-wait (sleep ε before ack), as Spanner imposes for
strict linearizability? **No.** This ADR records that decision and the
causal-sufficiency argument behind it, and is enforced structurally by the
wait-until-safe anti-regression tooth at `pkg/sync/truetime_tooth_test.go`
(`TestNoTrueTimeWaitUntilSafe`).

## 2. Decision Drivers

- **D1: Throughput.** CRDT ingress is O(1)-admit
  (`pkg/clock/admission.go:97`, `IngressHLCScalarCap.Admit`); a commit-wait
  inserts an O(ε) sleep per Join, directly taxing the ingress hot path.
- **D2: Offline-first / high-fanout objective.** The P2P synchronization
  architecture targets high-fanout, intermittently-connected peers
  (Final_Sovereign_Architecture_Phase3.md:361 transcribes this); a per-Join
  commit-wait contradicts that objective at the architectural level.
- **D3: Causal-sufficiency.** CRDTs converge on delivery, NOT on clock agreement
  — the join-semilattice property (4_NETWORK_CONSENSUS.md §4.1). The convergence
  guarantee does not depend on bounding clock uncertainty at commit time.
- **D4: Byzantine Sybil inflation is ALREADY thwarted by the HLC scalar cap**
  (`pkg/clock/admission.go`, `IngressHLCScalarCap`), NOT by commit-wait. The
  defense is a clock-reject, not a sleep-wait.

## 3. Considered Options

- **Option A: Adopt TrueTime commit-wait.** Sleep ε before ACK, bounding
  physical-clock uncertainty at the commit stage, as Spanner does for strict
  linearizability. **REJECTED** — see §4/§5.
- **Option B: Reject TrueTime; keep O(1) non-blocking Join + HLC scalar-cap
  bound against Amazon Time Sync ε + per-peer EWMA drift.** ✅ **ACCEPTED.**

## 4. Decision (the load-bearing claim)

**ACCEPT Option B.** The engine NEVER introduces a TrueTime commit-wait interval
in the Join path. HLC + Amazon Time Sync ε (~26-50µs) + per-peer EWMA bounds are
mathematically SUFFICIENT for CRDT causal consistency (which requires only causal
partial ordering, NOT absolute linearizability). TrueTime is the right tool for
Spanner's strict linearizability; it is superfluous for a CRDT mesh.

This decision is enforced structurally, not merely documented: the
`TestNoTrueTimeWaitUntilSafe` tooth (`pkg/sync/truetime_tooth_test.go`) performs
a depth-1 AST scan of the Join call graph and FAILS at CI time if a
wait-until-safe primitive (`time.Sleep`, `time.After`+receive, clock-keyed
`Wait`, or a `<-` on a channel named for the uncertainty window) is introduced
into Join or its direct callees. A future contributor adding commit-wait would
break the tooth before merge.

## 5. Rationale — the causal-sufficiency argument (C1-C5; TRANSCRIBED, not re-proven)

This argument is transcribed from the source prose
(Final_Sovereign_Architecture_Phase3.md:356-361, CRDT Sync Engine Phase 3.md:106)
and the join-semilattice math (4_NETWORK_CONSENSUS.md §4.1). This ADR does NOT
re-prove it; it is the canonical citable home for a decision that already exists
in prose.

- **C1 (lattice):** δ-CRDT states form a join-semilattice `(S, ⊔, ⊥)`;
  `⨆ᵢ δᵢ = ⨆ᵢ sᵢ` regardless of order (4_NETWORK_CONSENSUS.md §4.1). Convergence
  is a lattice property, independent of commit timing.
- **C2 (causality needs only partial):** causal consistency is a partial order
  property; it needs Lamport-style "happens-before", NOT a total linear order.
  Linearizability is a strictly stronger property than causal consistency.
- **C3 (HLC provides the partial order):** a Hybrid Logical Clock (HLC) bounds
  logical Lamport against physical Amazon Time Sync ε, yielding a causal partial
  order with a ~26-50µs physical bound — sufficient density to neutralize
  malicious sequence inflation (Final_Sovereign_Architecture_Phase3.md:359).
- **C4 (EWMA absorbs drift):** per-peer EWMA bounds tighten the inter-peer drift
  below ε, defeating Sybil inflation WITHOUT blocking (CRDT Sync Engine Phase
  3.md:106).
- **C5 (commit-wait buys nothing on a CRDT):** linearizability (TrueTime's
  target) is a strictly STRONGER property than causal consistency; adopting the
  stronger property UNCHANGES the convergence guarantee (already guaranteed by
  C1) but ADDS per-op latency. Negative latency-after-free.

Therefore TrueTime commit-wait is superfluous AND penalizing → **REJECT**.

## 6. Consequences (N1-N4)

- **N1:** Join is O(1)-non-blocking; per-op fsync (NVMe, ~1.5µs p99 per Track
  4.E5) is the only durability latency; NO ε sleep on top.
- **N2:** Throughput ceiling is the HLC scalar cap + NVMe fsync, NOT clock
  uncertainty. The ~60µs 32c Verify (Track 4.M) is the cap divisor.
- **N3:** Byzantine Sybil inflation is a CLOCK-REJECT, not a SLEEP-WAIT
  (`IngressHLCScalarCap` returns `bool` in O(1), `pkg/clock/admission.go:97`).
- **N4:** A future change to introduce commit-wait MUST amend this ADR
  (ADR-0001b) AND re-open the math — see the Wait-Until-Safe Tooth
  (`pkg/sync/truetime_tooth_test.go`). The tooth will FAIL on such a change; the
  correct response is to amend the ADR with new evidence, NOT to loosen the
  tooth.

## 7. Relationships

- **R1:** Cites `phase-03/Final_Sovereign_Architecture_Phase3.md:356-361` (the
  source prose for the §2.X1(b) decision).
- **R2:** Cites `docs/architecture/4_NETWORK_CONSENSUS.md` §4.1 (the
  join-semilattice math).
- **R3:** Enforced structurally by the TOOTH at
  `pkg/sync/truetime_tooth_test.go` (`TestNoTrueTimeWaitUntilSafe`).
