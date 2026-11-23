# ADR-0051: A per-shard PointGet retires the production read-path OOM

**Status:** Accepted  
**Date:** 2026-09-08

## Context

ADR-0032 §6 had already disclosed that `State()` costs O(total entries). The availability impact
became clear when repeated point reads exhausted the arena.

Each `State()` call rebuilds the merged HAMT. `Set` uses functional path copying, allocating
O(log N) path nodes and a wrapper for every inserted entity, but the intermediate roots produced
during the rebuild are not retired. Retiring the previous merged view releases only the subtree
reachable from its final root. Repeated calls therefore grow arena use by O(N·log N), independently
of the EBR grace window, until allocation panics against the arena's 64 MiB limit.

The pre-fix `TestPointGet_StateLeakNegativeControl` measured 64 `State()` calls over 512 entities:
the arena high-water grew from 8,876,096 to 43,509,944 bytes, an increase of 34.6 MB or about
541 KB per call. Extrapolating that rate across the verify harness's approximately 2000 sequential
`/v1/get` requests exceeds 1 GB against the 64 MiB arena.

## Decision

Add `(*DeltaCRDTEngine).PointGet(entityID string) []CRDTEntry` in `pkg/sync/point_get.go` and route
production point reads through it. Leave `State()` unchanged for callers that need a merged view.

`routeShard` is a deterministic function of `(entityID, routeSeed)`, so all entries for an entity
reside in one shard. PointGet loads that shard's HAMT root and calls `HAMT.Get`, giving an O(log N)
lookup without path copying or arena allocation. It then copies the entity's k entries in O(k).

Each call acquires and enters a distinct EBR `Participant`, reads and copies under that pin, and
releases it afterward. Reclamation waits for the minimum epoch across active participants, so an
inner PointGet cannot release a caller's outer pin. This also protects the previously unpinned
`handleGet` path.

`HAMT.Get` returns an arena-backed `unsafe.Slice`. A concurrent root replacement and the three-epoch
grace period can make that memory reusable after the pin is released. PointGet therefore copies the
values before releasing its pin. The returned slice belongs to the caller and is reclaimed by the
Go garbage collector. `CRDTEntry` is a 120-byte value type with no pointers, so the copy has no
remaining arena references.

## Consequences

`ControlServer.handleGet` now uses PointGet for `/v1/get`.
`engineHAMTAdapter.LiveRead` uses it as the resolver's read-your-writes source for `/v1/query`; its
outer EBR pin was removed because it had protected only the old arena-backed `State().Get` result.
`Gossiper.LatestPayload` was also migrated for consistency, although it had no callers when this
change was made.

Point reads no longer construct a merged HAMT or allocate arena nodes. They still allocate a
caller-owned Go slice proportional to the number of dots for the requested entity. Callers must not
use PointGet after engine teardown.

`State()` retains its existing cost and arena-growth behavior. The production Merkle root paths use
`MerkleRootFromShards`, not `State()`. Apart from tests, the remaining `State()` caller is
`WorkerExecuteCrashProbe`, which uses a merged view to prepare a deliberate crash in the test
harness.

## Evidence

The regression tests ran under the race detector:

- `TestPointGet_StateLeakNegativeControl` repeats the pre-fix measurement above, demonstrating that
  the arena gauge detects the leak.
- `TestPointGet_ArenaStaysFlat` performs 40,000 PointGet reads over 512 entities. The arena
  high-water remains 235,960 bytes; the reads allocate no arena memory.
- `TestPointGet_MatchesStateGet` compares PointGet and `State().Get` dot sets for 256 entities,
  including multi-dot entities. Selecting the wrong shard makes the test fail.
- `TestHandleGetSustainedReadsNoOOM` issues 5,000 `/v1/get` requests through the real `handleGet`
  over 1,000 entities. Every request returns HTTP 200 and the arena remains 392,712 bytes. Routing
  the handler back through `State().Get` makes 300 reads grow the arena by 350 MB, about
  1.17 MB per read.

Build, vet, the package tests, and `TestHotPathZeroAllocations` passed. The full `pkg/sync` suite
was also run on a 32-core machine because `TestScalingGate` skips below 32 cores; a 4-core run
cannot exercise that gate.

The arena-leak negative control and the sustained HTTP test guard against returning production point
reads to `State().Get`. The CRDT merge-law and wire-schema files were unchanged by this decision.
