# ADR-0058: Wire the cross-entity secondary index into production paths

- **Status:** Accepted
- **Date:** 2026-09-23

## Context

[ADR-0057](0057_secondary_index_design.md) introduced the sharded secondary
index in `internal/index`, including strict-`>` moves, retention of tied
cells, and rejection of stale updates. No production write or query path used
it. This decision wires the index to local writes, remote frames, and recovery
while leaving the default configuration unchanged.

## Decision

1. Feed the index synchronously before each write returns. The durability
   bridge calls the feeder immediately after `InsertLocal`, before the WAL
   append result, because the engine already contains the dot even when the
   WAL failure produces a 503. The gossiper's in-memory branches do the same
   when no bridge is configured. The receiver's frame, batch, and hybrid
   handlers extract the fields with one Cap'n Proto unmarshal and three
   accessor reads. Recovery feeds the snapshot image, WAL tail, and legacy
   `0x01` hole-repair entries; legacy records supply an H3 value of zero.
2. Skip a candidate only when resolution returns `ErrEntityNotFound`, as for
   a future-dated write. Any other error aborts the query rather than
   returning an incomplete result as though it were complete.
3. Make the feature opt-in with `--secondary-index`, which defaults to false.
   When disabled, no index or feeder is constructed, `/v1/querybyh3` and
   `/v1/querybysystime` are not registered and return 404, and `h3_index` is
   ignored. `--secondary-index-max-entities=0` leaves the index uncapped.
4. Keep `*index.Index` behind the `cmd/sovereign-node` wiring boundary. Other
   packages receive a feeder function with primitive arguments or depend on
   `internal/database.SecondaryIndexSource`.
5. At a positive entity ceiling, drop and count new-entity records without
   evicting existing entities, set a sticky degraded flag, and return 503
   from queries. Existing entities continue to move in bounded O(1) work.
6. Validate only the opaque cell's syntax: the mode nibble in bits [59,63)
   must be 1. The resolution field is inherently four bits. Absent and
   explicitly zero values both store `h3=0`; geographic validity is not
   inferred, and no H3 library is called.
7. Measure the feed on the receive path, separately from the CRDT core
   microbenchmark. Compare enabled and disabled feeds in the same boot. If
   the batch cost regresses, the engine-side tap in `crdt_apply_batch.go` is
   the fallback for the two batch paths.

## Consequences

- An insert is visible to an immediately following H3 or system-time query
  across the four production write paths. Both routes return
  `indexed_entities` and `current_state`; the entity count includes admitted
  inserts in both capped and uncapped modes.
- The index describes current state. Historical cell queries still require a
  durable-tier H3 index. Repair-pass feeding, the off-heap layout at 100M
  entities, and live-tie deduplication remain open design work.
- The two JSON response structs add two fieldalignment findings to the
  baseline. Their layouts were not changed merely to silence that report.

## Evidence

- Route, write, recovery, ceiling, error-handling, and disabled-mode behavior
  is covered by tests in `pkg/mesh`, `pkg/durability`, `internal/index`, and
  `internal/database`. `BenchmarkIngestGateFeedOff` and
  `BenchmarkIngestGateFeedOn` compare the receive-path cost.
- At 32 cores with N=100 the enabled feed cost 3.3% more than the disabled
  feed within one boot, compared with the earlier 11.8% estimate.
  `BenchmarkIndexApply_Fresh` measured 363.6 ns/op. Light field extraction
  measured approximately 461 ns/frame and 193 ns/delta on the batch path.
- The feed belongs to the receive layer measured at 5.7M-6.0M deltas/sec at
  32 cores, not the 50.7M-68.3M ops/s core layer. Accompanying core runs
  measured 68,819,837 / 63,040,871 and 68,964,565 / 64,540,035 ops/s at 32
  cores, all above the 50,736,038 ops/s floor.
