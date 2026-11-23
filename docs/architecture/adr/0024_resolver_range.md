# ADR-0024: Range reads over bitemporal history

**Status:** Accepted  
**Date:** 2026-08-04  
**Builds on:** [ADR-0017](0017_query_resolver_read_half.md), [ADR-0018](0018_per_entity_l0_split.md), and [ADR-0019](0019_l0_l1_per_entity_compaction.md)

## Context

`Resolver.AsOf` and `/v1/query` return the dominant event for one entity at a valid-time point and transaction-time horizon. They cannot reconstruct every state whose valid-time interval overlaps a window. Range reads serve that separate question without changing the point-read contract.

A bitemporal row carries `[validTimeStart, validTimeEnd)`, not a single valid-time point. Testing only whether selected points from the query window fall inside that interval would miss overlapping rows between those points. The read must therefore compare intervals directly.

Unlike a point read, a range can return the entity's entire history. Without a bound, the collected slice and its JSON response grow with that history. The API needs a result limit and an explicit truncation signal.

## Decision

### Match interval intersection and transaction visibility

`Resolver.Range(ctx, entityID, validTimeLo, validTimeHi, txTime)` returns every visible row for the entity whose interval intersects `[validTimeLo, validTimeHi)`. A row matches when:

- `validTimeStart < validTimeHi` and `validTimeEnd > validTimeLo`;
- `SystemTime <= txTime`;
- the full `entity_id_hash` and the stored entity ID match the requested entity.

The skip condition is `validStart >= validHiNs || validEnd <= validLoNs`. A row beginning at the window's high endpoint or ending at its low endpoint does not intersect the half-open window. These comparisons preserve the boundary discipline of the point read's `validStart <= validTime < validEnd` predicate.

`scanWindowRecordBatch` applies the same hash, transaction-time, and exact-entity checks as `scanRecordBatch`, replacing only point membership with interval intersection. `scanWindowFile` and the range scanner collect every match instead of retaining one dominant row. Returned rows are sorted by `ValidTimeStart` ascending.

### Bound the result before marshaling

`ResolverConfig.MaxRangeRows` defaults to 4096. `scanWindowRecordBatch` checks the limit before copying and appending another matching row. Once the collector is full, finding another match stops the scan and sets `truncated=true`; the response never contains more than the configured number of rows.

A zero limit means unlimited results. `NewResolver` preserves zero and normalizes a negative value to zero, rather than silently replacing either with the default. Callers that disable the bound accept the corresponding memory and response-size cost.

Truncation reports that matching rows remain; it is not a pagination token. The caller can narrow the window or issue another query with different bounds. Coalescing is applied after collection, so it does not recover rows omitted by the limit.

### Read the same durable surface as AsOf

Range uses the same per-entity L1 and L0 prefixes, compaction-manifest supersession, `MaxL0Files` tail limit, reverse key ordering, and cancellation checks as AsOf. Reverse lexicographic order places L1 keys before L0 keys and orders higher filename-encoded system times first within each prefix. Range then returns rows in valid-time order.

Keeping discovery and supersession aligned gives the central consistency invariant: for the same entity and transaction time, a row selected by `AsOf` at any point inside the window also appears in the uncapped Range result. Reading only compacted files or only the uncompacted tail would violate that invariant.

When `EnableFirstSysSkip` is enabled, Range also skips Arrow files and compaction manifests whose filename-encoded minimum system time is greater than `txTime`. Such objects cannot contribute a visible row. Unparseable names retain the normal download path. [ADR-0029](0029_filename_bounded_download_skip.md) and [ADR-0030](0030_manifest_channel_download_skip.md) record this refinement.

### Merge live rows when a source is configured

The original implementation read only durable Arrow files. [ADR-0032](0032_live_source_read_your_writes.md) adds an optional `LiveSource`, also used by AsOf, so an acknowledged write can appear before the next checkpoint. A nil source retains durable-only behavior; the default configuration leaves it nil.

For Range, live entries use the same transaction-time and interval-intersection predicates. Rows already present in the durable result are deduplicated by `(SystemTime, PayloadDigest)`, and `MaxRangeRows` still bounds the merged result. A live-source read error leaves the durable answer intact. This is a per-entity read of live HAMT state, not a general join against the MemTable SkipList.

### Keep coalescing optional

`CoalesceRange` sorts the collected events by `ValidTimeStart`, then by descending `SystemTime` within equal starts, and retains one event per exact start timestamp. It does not merge arbitrary overlapping intervals and does not rescan storage.

The raw Range result remains the default. A caller can request the coalesced projection with `coalesce=true` on `/v1/range`; [the handler](../../../pkg/mesh/control.go) applies it after the resolver returns.

### Expose the window through the control API

`GET /v1/range` accepts `key`, `valid_time_lo`, `valid_time_hi`, and `tx_time`, with optional `coalesce=true`. Timestamps use RFC3339Nano. The handler rejects unsupported methods, missing or malformed parameters, and windows whose high bound is not after the low bound. Its disabled-resolver check precedes parameter validation, and its remaining error mapping follows `/v1/query`.

Each `windowRow` carries the stored temporal fields, entity ID, and payload digest. It omits the `present` flag used by the point response because every returned row is present. No payload body is fabricated: the Arrow query tier stores a digest and does not necessarily contain the corresponding value. `rangeResponse` adds the entity, row list, and truncation flag.

## Consequences

### Entity integrity is checked at two widths

The `l0/<hex8>/` object prefix contains only the first 8 bytes of the entity hash to scope storage listing. `ArrowSchema.entity_id_hash` is a 16-byte, 128-bit value, and the scanner compares all 16 bytes before comparing the complete entity ID. A prefix-only collision is therefore not enough to reach the wrong entity's result.

The integrity test cannot depend on finding such a collision. `rangeWinInsertRowDecoupled` instead constructs a row whose hash column names one entity while its packed value names another. This deterministically exercises the exact-entity check after the hash check has passed. Production flushing normally derives both fields from the same entity; the test covers a corrupted or inconsistent write.

### Checkpoints retain one query-tier representative per entity

A checkpoint's recovery image contains the captured dots, but its Arrow query tier retains the latest entry per entity from the pinned capture. Multiple writes to one entity within one checkpoint therefore collapse to one query-tier row. Tests that need a multi-file durable history write one event per checkpoint; tests that need several rows in one Arrow file use `SkipListArena` and `L0Flusher.FlushFromArena` directly.

[ADR-0045](0045_mesh_transport_invariants.md) and [ADR-0050](0050_checkpoint_decouple_delta.md) later moved capture to `CaptureShardsPinned` under an EBR pin and changed periodic query-tier flushing to changed entities only. `Bridge.AppendCheckpoint` releases the engine pin before calling `stageAndFlushQueryTierDelta` for Arrow I/O. These changes alter checkpoint cost and timing, not Range's filtering semantics.

### Range has a different allocation profile

AsOf tracks the best row index and allocates its result after scanning a batch. Range must copy every matching row before the Arrow buffer is released. Each emitted row copies the entity ID and payload bytes, so allocation grows with the number of matches. The range scanner leaves `scanRecordBatch` unchanged and does not weaken the point read's deferred-allocation behavior.

### Some optimizations remain open

[ADR-0028](0028_skiplist_seek_window_lower_bound.md) adds `SkipListArena.Seek` and `NewSeekIterator`, but neither has a production caller in the Range path. `scanWindowRecordBatch` still scans Arrow batches linearly. The primitive's existence is not wired range acceleration.

Pagination remains unimplemented, coalescing remains opt-in, and the optional live source does not add a cross-entity MemTable query path.

## Evidence

The acceptance record reports successful builds, vetting, and race-enabled tests for `internal/database`, `pkg/durability`, and `pkg/mesh`. The range-specific coverage is:

- `internal/database/range_test.go`
  - `TestRangeHeadlineIntervalIntersectionNotPointInWindow` distinguishes interval intersection from point sampling and checks valid-time ordering.
  - `TestEmptyWindowRangeReturnsErrEntityNotFound` covers a window disjoint from the stored history.
  - `TestHalfOpenBoundsRangeCarriesFilter3Discipline` covers exact overlaps, partial overlaps, endpoint contact, and disjoint windows.
  - `TestAsOfConsistencyRangeSupersetOfEveryPoint` compares point-read selections with the Range result set.
  - `TestFilter4IntegrityDecoupledCol0NotEntityID` rejects a row whose hash and stored entity ID disagree.
  - `TestMaxRangeRowsCapTruncatedPreMarshal` checks a 10-row history with `MaxRangeRows` set to 4 and then verifies that a zero limit returns all 10 rows without truncation.
- `pkg/durability/range_test.go`
  - `TestRangeHeadlineIntervalIntersectionRealLocalFS` exercises intersection through on-disk Arrow files.
  - `TestRangeScansL1PlusUncompactedTail` verifies that compacted and uncompacted tiers both contribute to the result.
  - `TestRangeMaxRowsCapTruncatedRealLocalFS` checks truncation over the durable filesystem index.
- `pkg/mesh/query_range_test.go`
  - `TestAsOfConsistencyRangeSupersetOverLocalFS` checks the superset invariant across a multi-file history produced by separate checkpoints.
  - `TestRangeRouteContract` covers sorted successful responses, method and parameter errors, disabled resolver behavior, empty windows, and missing entities. It also checks that the response contains no payload field.

The later live-source, download-skip, skiplist, and checkpoint decisions carry their own regression evidence in the ADRs linked above.

