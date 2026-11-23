# ADR-0004: Reject per-entry physical-time tuples in the CRDT core

> **Status:** Rejected
> **Date:** 2026-07-26

## Context

A proposal called for replacing the compact 16-byte causal-dot node ID in
`CRDTEntry` with a wider `(physicalMs, logical, nodeID)` tuple. Its aim was to
put hybrid-logical-clock information directly into each entry's causal dot.

That change affects the fixed-size record used by the HAMT and arena. The
layout in `pkg/sync/hamt.go` keeps `DotNodeID` and `DotCounter` flat, alongside
the entry's existing temporal fields. `CRDTEntry` is exactly 120 bytes wide,
with no padding, and `TestCRDTEntryWidthStaticAudit` fails if that
width changes. Widening the dot would reduce entry density and increase the
memory traffic paid by every operation.

Physical-clock admission already occurs at a different layer.
`IngressHLCScalarCap` compares a relay's physical timestamp with local wall
time before signature verification, and the per-peer sequence budget limits
counter advancement. Those mechanisms do not require a wider causal identity
in every stored entry.

## Decision

Reject the proposed replacement of `DotNodeID` with a physical-time tuple.
Keep the flattened causal dot in `CRDTEntry`; do not add a separate
`physicalMs` field to the causal identity as a smaller version of the same
change.

Physical-time screening remains at frame ingress rather than becoming part of
the dot. This decision concerns the causal identity, not the entry's existing
system, valid, assertion, and decision-time fields.

A requirement for new per-record time-query semantics would need a separate
design and measurement. Ingress admission is not a substitute for historical
time semantics, so such a requirement cannot be dismissed merely by pointing
to the clock cap.

## Consequences

- The 120-byte entry layout remains protected by a static regression test.
  Changes to `DotNodeID`, field order, or padding must account for the arena
  and wire assumptions attached to that layout.
- The engine does not pay the storage and memory-bandwidth cost of the rejected
  tuple. No performance figure for the unimplemented alternative is claimed.
- Clock-skew rejection stays outside the CRDT record. Existing temporal fields
  continue to serve their own purposes; they are not collapsed into the causal
  dot.
- A future proposal must state the required time semantics and measure its
  effect on the core layout and receive path before superseding this decision.

## Evidence

`TestCRDTEntryWidthStaticAudit` in `pkg/sync/crdt_entry_width_test.go` asserts
the 120-byte `CRDTEntry` width. The flattened fields are defined in
`pkg/sync/hamt.go`, while `pkg/clock/admission.go` contains the ingress scalar
comparison.

The current design's core benchmark supplies context, not a benchmark of the
rejected alternative. `TestScalingGate` has a gate-passing floor of 50,736,038
ops/s at 32 cores and was re-measured at 68,278,197 ops/s on 2026-09-03 using a
c8g.8xlarge with Graviton4 and Go 1.26.1. This is an in-process HAMT test with
no signature verification, network, TLS, or persistence; see the
[`core-crucible.txt`](../../evidence/core-crucible.txt).

That core result is distinct from the receive-path benchmark, which includes
Ed25519 verification, envelope processing, and CRDT application. Its published
single-origin result is 5.7M–6.0M deltas/sec at 32 cores with batches of
N=100–256; see the [ingest receipt](../../evidence/ingest-ed25519.txt).
