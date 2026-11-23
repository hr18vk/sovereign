# ADR-0032: Read your writes through a live HAMT source

**Status:** Accepted  
**Date:** 2026-08-10

## Context

`Resolver.AsOf` and `Resolver.Range` originally read only durable Arrow files. An insert reached the live delta-CRDT HAMT immediately, but appeared in those query results only after `Bridge.AppendCheckpoint` copied a snapshot into L0. The default checkpoint interval was 1,000 mutations, so a query immediately after an acknowledged insert commonly returned 404 even though the write-ahead log already held the mutation. Setting `--wal-checkpoint-interval=1` hid the problem by forcing frequent checkpoints; it did not fix read visibility.

The durable and live representations also overlap after a checkpoint. A correct merge therefore has to make a recent write visible without returning the same row twice.

## Decision

Add an optional live source to the existing resolver rather than change the write path or checkpoint cadence.

- `internal/database` owns the `LiveSource` interface and the `LiveEvent` result type. Its `LiveRead(ctx, entityID, txTimeNs)` method returns the entity's live entries visible at the requested transaction time. Keeping this interface out of `pkg/sync` preserves the package boundary; `cmd/sovereign-node` supplies the concrete engine adapter.
- `ResolverConfig.LiveSource` and `SetLiveSource` install the source. Its nil default retains durable-only behavior. The command wires the adapter when it constructs the query resolver for a durable node.
- `AsOf` and `Range` skip their empty-durable early returns when a live source is configured. Both recheck the transaction-time bound in the resolver even though the adapter also applies it, so another implementation cannot expose a future entry.
- `AsOf` applies the same valid-time predicate and strict `SystemTime` dominance rule to live and durable candidates. A durable row wins a tie. A live-source error leaves the durable answer intact.
- `Range` applies the half-open valid-time intersection and deduplicates by `(SystemTime, PayloadDigest)`. The 32-byte content digest is available in both representations, whereas the Arrow rows do not carry causal-dot columns. `MaxRangeRows` still bounds the merged result.
- `QueryLiveSourceReads` increments once per query that consults the live source, including an empty result. The metric is `supremum.query.live_source_reads`; it reports use of the path, not the number of entries returned. This raised the counter registry from 17 to 18 entries when introduced.

The original adapter used an EBR-pinned `State().Get`. The rejected alternative was to freeze and read the live SkipList through `Seek`: the current write state is a sharded HAMT rather than a frozen SkipList, an entity's dots are already available through the HAMT read API, and coupling queries to the SkipList freeze/free lifecycle would add risk without closing the visibility gap.

## Consequences

An inserted row can now satisfy point and range queries before the first checkpoint. Disabling the live source preserves the former durable-only behavior, including not-found results for an empty durable tier. Checkpoints make live rows durable but do not duplicate range results.

The implementation later replaced `State().Get` with `PointGet`, recorded in [ADR-0051](0051_pointget_readpath_oom.md). `PointGet` reads only the entity's shard, acquires its own EBR pin, and copies the entries into caller-owned memory before releasing that pin. It avoids constructing and retiring a merged HAMT view for every query, so the adapter no longer needs an outer pin. The merge and visibility rules above are unchanged.

This decision does not add the cross-entity Resolver/MemTable path. The `eng.DataDir` race and `MaxValidTime.UnixNano()` overflow tracked by ADR-0021 and ADR-0017 also remain outside its scope.

## Evidence

The regression coverage lives in `internal/database/live_source_merge_test.go`, `internal/telemetry/live_source_counter_test.go`, and `pkg/durability/read_your_writes_test.go`. It covers nil-source compatibility, live/durable equivalence, strict tie handling, range deduplication and empty-durable ranges, rejection of entries beyond the transaction horizon, counter registration, read-before-checkpoint behavior, and concurrent readers and writers under the race detector.

At acceptance, the focused tests comprised 8 cases in `internal/database`, 2 in `internal/telemetry`, and 2 in `pkg/durability`. Their measured package times were 2.781 s, 0.007 s, 0.024 s, and 0.006 s respectively on a four-core machine. The fieldalignment counts remained 11 in `internal/database`, 1 in `internal/telemetry`, and 0 in `pkg/metrics`.

The runtime check used the real mTLS node with the default checkpoint interval and an empty durable tier. All 5 checks passed: an immediate point query returned 200, an immediate range returned 200, a never-inserted key returned `404`, the live-source counter reached 3, and the durable tier remained empty. A separate full `internal/database` race run exceeded its approximately 600 s budget in a pre-existing differential fuzz test; the focused live-source race tests passed. These timings are historical test conditions, not performance claims for v0.2.0.
