# ADR-0057: Cross-entity secondary index design

**Status:** Proposed; implemented by [ADR-0058](0058_secondary_index_production_wiring.md)  
**Date:** 2026-09-21

## Context

Each `CRDTEntry` already carried `h3_index` and `system_time` through the wire format, batches,
and recovery image, but no secondary index used those fields. At the time of this decision the
control port did not accept `h3_index` on inserts, and queries could find an entity only by its
primary key. A cross-entity index needed to make cell and system-time candidates available
without weakening the resolver's temporal visibility rules.

The design had to answer three questions: how to update memberships when an entity moves,
how to feed every write before its caller can observe a successful return, and how to prevent
an over-approximate candidate set from returning a row that the resolver would reject.

## Decision

Build `internal/index` as a design-stage prototype with no production importers. Evaluate its
dominance rules, synchronous feed, query resolution, and resource costs before wiring it into
the node. Production integration is a separate decision in ADR-0058.

### Index structure and dominance

Shard by `entityID`, with a per-shard compare-and-swap spinlock rather than a `sync.Mutex`.
Each shard contains:

- `latest`, the entity's current dominance key and retained cells;
- `byH3`, mapping an H3 cell to its candidate entities; and
- `bySys`, mapping 1-hour system-time buckets to candidate entities, with sorted bucket keys.

An observation with a strictly greater `SystemTime` moves the entity and removes its old
memberships in one shard critical section. An equal-time observation retains both cell
memberships because the resolver's encounter-ordered tie rule can choose either row. Retain at
most 8 cells per entity and count further tie drops. An older observation leaves the current
entry unchanged.

Equal-time cell retention can produce extra candidates, not a different dominant row: the
query path resolves each candidate and applies the H3 filter afterwards. System-time buckets
can likewise include entities from earlier in the boundary bucket, which resolution trims.
The prototype covers current-state cell and time queries; historical cell queries remain out
of scope.

### Synchronous feed

Feed the index synchronously before each write operation returns. The design identifies local
bridge writes, the gossiper's local-write branch, the three remote receive handlers, and
recovery replay. Read-your-writes requires this ordering; an asynchronous queue could let a
successful write return before a query could find it.

Remote feeds use the light Cap'n Proto decode to acquire only the fields the index needs. The
engine-side batch-apply tap remains the fallback if the measured receive-path cost is too high.

### Query resolution

The query path is candidate lookup followed by `Resolver.AsOf` and then the H3 filter. Only
the resolver's visible dominant row can be returned. A candidate with no visible row at the
query's transaction time is skipped rather than treated as an error. Other candidates that do
not match the requested cell are discarded after resolution.

### Resource envelope

The prototype remains O(entities): admitted entities have a latest entry, a system-time
membership, and one or more retained cell memberships. The Go-map implementation measured
140 B/entity in steady state and 3.06 mallocs per move, with 0.0 MB growth when rewriting the
same live set. These are prototype microbenchmarks, not a bound for every workload.

Extrapolating that footprint to 100M entities gives approximately 14 GB. An off-heap layout
with a 10-20x lower constant was a production design direction, not something this prototype
implemented or measured at that scale.

## Consequences

This decision establishes and tests the index semantics without making the index available on
a production API. Production wiring must accept `h3_index` on local inserts, connect every
write and recovery path, preserve the synchronous return contract, and expose the query routes
only when the feature is enabled. ADR-0058 records that work and its opt-in configuration.

The resolver remains authoritative. The index can reduce the entities examined by a query,
but it cannot override temporal visibility or turn a candidate into a result without
resolution. Tie-cap drops and any future entity-capacity policy must be observable because
they can omit candidates.

The design uses fields already present in entries and frames, so it requires no change to the
CRDT merge or wire schema. Current-state queries do not imply historical H3 queries; those
need a durable-tier design of their own.

## Evidence

Prototype tests cover newer, older, and equal-`SystemTime` observations, movement between
cells, the tie cap, deterministic candidate sets, and resolution of over-approximate
candidates. Feed tests check synchronous visibility across local, remote, and recovery paths.
Negative controls disable movement and visibility checks to show that the corresponding
assertions can fail.

The light Cap'n Proto decode benchmark measured 461 ns/frame and approximately 193 ns/delta
on batches. Comparing that delta cost with the approximately 163 µs batch-accept path gave an
estimated 11.8% addition; it was not yet a production ingest measurement. The stale or
duplicate steady-state path measured 20.35 ns with 0 allocations.

Memory measurements reported 140 B/entity in steady state and 3.06 mallocs per move. Rewriting
the same entities showed 0.0 MB growth, supporting the no-eviction steady-state model for that
workload. The 100M-entity and off-heap figures above are extrapolation and design estimates,
not measured fleet results.

