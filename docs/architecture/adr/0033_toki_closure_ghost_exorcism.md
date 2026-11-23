# ADR-0033: Remove the unused TOKI conflict resolver

**Status:** Accepted; the proposed TOKI integration is rejected  
**Date:** 2026-08-11

## Context

`internal/temporal_store` was early scaffolding for two facilities the engine did not use. `LWWOperator.Resolve` selected a winner and loser for eager conflict resolution, while a Temporal workflow and activity orchestrated L0-to-L1 compaction. No production package imported this code. `L1Compactor.Compaction` already performed compaction in process, and `selectLatestDot` selected a response from the complete dot set without deleting losing writes.

Wiring `Resolve` into `DeltaCRDTEngine.Join` would have changed the merge from union of causal dots into eager last-writer-wins deletion. Once a loser were discarded, a later WAL replay or foreign merge could not restore it. That violates the append-only merge semantics on which convergence depends. Read-time selection does not have this problem: it chooses which entry to return while retaining every dot for later queries and merges.

## Decision

Delete `internal/temporal_store` and reject the proposed eager resolver integration rather than leave an unused alternative merge law in the tree.

The deletion removed 10 files containing 1,576 lines: 1,555 lines of Go and a 21-line README. The four isolated test files accounted for approximately 582 of those lines and did not exercise a production integration.

Remove the dependencies used only by that package from `go.mod`:

- `go.temporal.io/sdk v1.45.0`
- `go.temporal.io/api v1.62.12`
- `github.com/gogo/protobuf v1.3.2`

Keep `github.com/google/uuid v1.6.0` as a direct dependency because the OpenTelemetry resource SDK and node identity generation still use it. Checksum entries for removed modules may remain in `go.sum`; they are ignored while those modules are absent from the build graph and can be removed by a later `go mod tidy`.

`Join` remains a merge-union semilattice. `perShardMerge` inserts incoming causal dots keyed by `HashCausalDot`, retaining idempotence, commutativity, and the ability to merge state after recovery. Conflict selection stays at read time, and compaction stays in `L1Compactor` rather than an external workflow service.

## Consequences

The deletion changes no production read, write, merge, or compaction path. It removes an unused Temporal dependency chain and prevents an eager-lossy resolver from being mistaken for an optional optimization.

The live-source path introduced by [ADR-0032](0032_live_source_read_your_writes.md) makes uncheckpointed entries available to the resolver, but it is not itself the conflict-resolution algorithm. The resolver and `selectLatestDot` choose a dominant entry from the retained dot set; neither discards the other entries. The current engine adapter uses `PointGet`, so this reasoning still holds after [ADR-0051](0051_pointget_readpath_oom.md).

This record does not close the separate cross-entity query work or the `eng.DataDir` and `MaxValidTime.UnixNano()` issues carried by ADR-0021 and ADR-0017.

## Evidence

A build after the deletion succeeded, no surviving Go file referenced `temporal_store`, and the three removed modules were absent from the module graph. `go mod why` reported that the main module did not need them, while `github.com/google/uuid v1.6.0` remained required.

The read-your-writes runtime check from ADR-0032 still passed all 5 checks after rebuilding the node: immediate point and range queries returned 200, an unknown key returned 404, the live-source counter reached 3, and the durable tier was empty. `TestHotPathZeroAllocations` also passed.

The focused live-source package tests took 1.988 s, 0.006 s, 0.011 s, and 0.004 s on the four-core test machine. Repo-wide vet still reported the same 35 pre-existing `unsafe.Pointer` warnings in `pkg/sync`; the deleted package had none. Fieldalignment findings stayed at 11 in `internal/database`, 1 in `internal/telemetry`, and 0 in `pkg/metrics`. The focused race tests passed, while the unrelated long differential fuzz test again exceeded the approximately 600 s full-package race budget. These are measurements of the deletion's test environment, not v0.2.0 benchmark results.
