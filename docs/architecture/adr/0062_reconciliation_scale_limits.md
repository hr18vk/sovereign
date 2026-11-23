# ADR-0062: Reconciliation scale limits

**Status:** Accepted  
**Date:** 2026-09-27

## Context

The scale-out design assumed that about 7 rounds of 100 ms sweeps, roughly
700 ms of gossip, would reconcile 1K nodes within a 10 s target. The code and
the 100-node measurements did not support that model. A full intra-region
sweep took 2–6 s while writes to same-region peers were serialised on one
goroutine without a per-frame deadline. Extrapolating that shape to 1K nodes
gave 34–101 s even without any increase in per-sweep latency.

The reconciliation primitives had independent limits. A `StrataEstimator`
occupied a fixed 51,789 B, larger than the 20,498-B digest from a
1,024-bucket IBLT, so it added bytes at every difference size. The legacy
double-hash IBLT exhibited failure floors between approximately D=72 and
D=400; these floors are 25–100× below the 10K-difference target. Partition healing took at
least 9–41 rounds and became unbounded beyond approximately D=900.

`TopologyManager.Select` rotated through a static peer registry; it did not
provide a partial membership view. No Raft membership plane had been built.
The design also lacked a durable origin payload store and a delivery
acknowledgement rule, so a bounded relay cache alone could not establish a
safe retention policy.

## Decision

Replace the assumed sweep cost and reconciliation bounds with the measured
constraints. Wall-clock claims at 100 nodes or more must come from runs at
that scale and record per-sweep `durMs`; an extrapolation is a design bound,
not a measurement.

Split the work into separately testable decisions:

- bound mesh writes and close failed connections, with an address-keyed
  suspect breaker ([ADR-0059](0059_write_deadline_close_on_error_suspect_breaker.md));
- rotate a bounded intra-region view ([ADR-0063](0063_partial_intra_view.md));
- replace the estimator and legacy placement with bounded, negotiated IBLT
  reconciliation ([ADR-0064](0064_iblt_reconciliation.md));
- desynchronise sweep phases ([ADR-0066](0066_sweep_phase_jitter.md)); and
- define payload retention and acknowledgement semantics before imposing a
  global relay-cache retention bound.

Dynamic membership and the durable origin payload store remain outside these
changes. A later topology or wire optimisation does not by itself supply
either one.

## Consequences

The write deadline, partial view, IBLT v2, and sweep jitter mechanisms have
subsequently been implemented. Hierarchical gateways and header-only v2
digest requests later reduced topology and request-byte costs further
([ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md),
[ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md)). The partial
view, IBLT v2, sweep jitter, and defer handler remain opt-in; their flags are
false by default.

Raft-based dynamic membership, the durable origin payload store, and the
delivery acknowledgement rule are still not built. No global retention bound
is claimed without them. The historical 34–101 s extrapolation is not a
current convergence result, and the 100-node sweep measurements do not
establish latency at any larger fleet size.

## Evidence

The decision record's 100-node runs measured 2–6 s per sweep on the serial,
deadline-less write path. Its digest accounting compared the fixed
51,789 B `StrataEstimator` with the 20,498-B, 1,024-bucket IBLT digest. The heal
experiments measured at least 9–41 rounds and failed to bound healing past
approximately D=900. These are the conditions that motivated the decision,
not evidence for a later fleet configuration.

The implementation references are `(*DeltaCRDTEngine).GenerateDigestWithSeed`
and `GenerateDigestSizedWithSeed`, `(*Gossiper).AntiEntropySweep`, and
`digestFrameSplit`. Symbol references replace the original line-number
citations, which no longer match the source.
