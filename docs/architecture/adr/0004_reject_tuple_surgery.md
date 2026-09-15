# ADR-0004: Reject per-entry physical-time tuples in the CRDT core

> **Status:** Rejected
> **Date:** 2026-07-26

## Context

A proposal called for replacing the compact 16-byte causal-dot node ID
(`DotNodeID`) in the CRDT state with a wide hybrid-logical-clock timestamp
tuple — `(physicalMs, logical, nodeID)` — embedded in every entry. The goal was
per-record physical-time precision: each value would carry the wall-clock time
at which it was written, not just a causal dot.

The catch is where that tuple would live. `DotNodeID` is a field of
`CRDTEntry`, the in-memory record the hot path operates on. That struct is
exactly 120 bytes wide today — a width statically asserted by
`TestCRDTEntryWidthStaticAudit`, which fails the build if the layout drifts.
The width is load-bearing: it sets how many entries fit in a cache line and a
page, and that density is what the zero-allocation hot path spends its budget
on. The proposed tuple is roughly twice the width of the 16-byte dot it would
replace, and the cost would be paid on every entry, on every operation.

## Decision

I rejected it. The per-entry layout stays exactly as it is — a compact 16-byte
dot, no embedded physical timestamp — and the core data structures (`crdt.go`
and the `DotNodeID` references) remain frozen in their current lock-free,
cache-aligned form.

Two reasons, in order of weight:

1. **Cache density is the throughput.** Widening `CRDTEntry` shrinks the number
   of entries per cache line and per page, raising the miss rate on the exact
   path the engine's speed comes from. The core's baseline cost is ~2.5 ns/op;
   bloating the record with a time tuple would destroy that budget through
   cache misses alone. That is not a trade worth making for timestamp
   precision (the measured numbers are below).
2. **The causality is already covered, and cheaper.** The physical-time defense
   the tuple was meant to add already exists at the ingress boundary.
   `IngressHLCScalarCap` (`pkg/clock/admission.go`) is a Byzantine-clock
   admission controller that caps an inbound frame's physical timestamp against
   local wall time — a cheap scalar comparison applied per frame *before* the
   expensive verify step. It delivers the clock-drift/causality rejection the
   proposal wanted without putting a timestamp in every record. The tuple would
   re-buy a property the engine already has, at a memory cost it does not need
   to pay.

## Alternatives considered

- **Embed the full `(physicalMs, logical, nodeID)` tuple per entry** (the
  proposal). Rejected for the two reasons above.
- **A narrower physical-time field.** Even a single 8-byte `physicalMs` is an
  8-byte tax on a 120-byte record, paid on every operation, for a value the
  ingress cap already supplies at the boundary. Rejected on the same
  cost/benefit ground.

## Consequences

The CRDT core keeps its 120-byte entry and its measured throughput. The core
microbenchmark (`TestScalingGate` — an in-process producer/consumer
crucible over the CRDT/HAMT data structures, with no crypto, network, or disk
in the loop) holds a gate floor of 50,736,038 ops/s at 32 cores and was
re-measured on this tree at 68,278,197 ops/s at 32 cores on 2026-09-03 (AWS
Graviton, c8g.8xlarge, Go 1.26.1) — an honest range of 50.7M–68.3M ops/s, with
0 allocs/op on the hot path. (The 57.6M figure sometimes cited from earlier
runs was a residency high-end, not a sustained number.) That figure is the
in-process data-structure floor, not the production ingest rate (5.7M–6.0M
deltas/sec at 32 cores, which additionally pays for Ed25519 verification and
the wire envelope). Physical-time causality is preserved by the ingress scalar
cap, so nothing the proposal was for is actually lost.

I would revisit this only if a hard requirement for per-record physical
timestamps ever appeared — for example, a legal or compliance mandate.
Accepting it would mean consciously trading away part of the 50.7M–68.3M ops/s
core throughput range, and that trade should be made deliberately, with the
cost acknowledged up front — never by default.
