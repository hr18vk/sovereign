# ADR-0017: The Query Resolver — the Read Half of the Durability Tier (/v1/query over Resolver.AsOf)

**Status:** Accepted  
**Date:** 2026-08-02  
**Builds on:** [ADR-0016](0016_lsm_durability_seam.md) (checkpoint persistence), [ADR-0011](0011_sdk_control_port.md) (the control port and digest boundary), and [ADR-0013](0013_durability_wal_recovery.md) (WAL recovery and the original seed-by-trace proof)

## 1. Context

ADR-0016 connected checkpoints to two durable artifacts: a dot-bearing recovery
image and a latest-entry-per-entity Arrow query index. `SnapshotToLSM` wrote both
through `LocalFS`, bounding WAL replay to the post-checkpoint tail. The Arrow
index had storage-level tests, but `Resolver.AsOf` had no production importer.
Its tests used a mock object store rather than the `LocalFS` that received the
checkpoint files.

A node could therefore write, checkpoint, crash, and recover without exposing a
read of its persisted bitemporal history. `ControlServer` already served
`/v1/insert`, `/v1/get`, and `/v1/merkle`, but none of those routes answered the
question the index stored: which event for an entity was dominant at a requested
valid time and transaction time? `/v1/get` selected current live state; it did
not evaluate that temporal predicate over Arrow history.

This decision wires the existing resolver into the production control server. It
does not create another query store or change the checkpoint representation.

## 2. Decision

### Inject the resolver without expanding the control-server constructor

Add a `resolver *database.Resolver` field and a `SetResolver` method to
`ControlServer`, and register `GET /v1/query`. Keeping injection separate
preserves the four-argument `NewControlServer(g, nodeID, peers, metrics)` API,
following the existing `SetSnapshotter` pattern. `startControlPort` receives the
resolver and installs it before calling `Handler`.

On a durable node where `--lsm-root` supplies a snapshot store,
`cmd/sovereign-node` constructs the resolver over the same `LocalFS` passed to
`bridge.SetSnapshotter(lfs, true)`.
The same object store therefore backs both `S3Lister` and `S3Downloader`; its
`"local"` bucket argument is ignored by `LocalFS`. Without that store the
resolver remains nil. The query allocator is `NewJemallocAllocator`, and the
configuration comes from `DefaultResolverConfig`.

The new dependency remains acyclic: `pkg/mesh` imports `internal/database`, while
`internal/database` imports neither `pkg/mesh` nor `pkg/durability`. Concrete
engine and storage adapters stay at the command wiring boundary.

### Make availability and absence distinct

The route has this form:

```text
GET /v1/query?key=<entityID>&valid_time=<rfc3339nano>&tx_time=<rfc3339nano>
```

`handleQuery` calls `Resolver.AsOf` once and encodes one `queryResponse`. A hit
returns HTTP 200 with `entity_id`, `system_time_ns`, `valid_time_start_ns`,
`valid_time_end_ns`, `assertion_time_ns`, `h3_index`, `payload_digest_hex`, and
`present`. Invalid parameters return HTTP 400. `database.ErrEntityNotFound`
returns 404 with `{"error":"not found","entity":<key>}`. Other resolver errors
that reach the handler return 500; non-GET requests are rejected.

A nil resolver returns 503 with
`{"error":"query-tier disabled (no --lsm-root)"}` before parameter validation.
An unavailable query tier must not look like a missing entity or malformed
request. This also covers an empty query against a disabled tier.

### Return the stored digest, never a reconstructed value

`(*Bridge).PutLocal` computes `sha256(payload)` and assigns it to
`entry.PayloadDigest`. `(*DeltaCRDTEngine).InsertLocal` replaces the dot node,
dot counter, and origin node fields; it preserves the supplied digest and
temporal fields. `SnapshotToLSM` converts the entry with `queryTierEvent`, which
sets the Arrow payload body to nil and retains that digest.

The handler hex-encodes `entry.PayloadDigest` as returned by `AsOf`. It does not
recompute a digest from the empty Arrow body, and `queryResponse` deliberately
has no `payload` field. The index establishes payload identity, not payload
contents. `/v1/get` can additionally return a value from the originator's live
payload cache; `/v1/query` does not claim that the durable index contains one.

### Use identical entity hashes on the write and read paths

The round trip depends on byte-for-byte agreement between the MemTable key,
Arrow row, object key, and resolver filter:

1. `(*MemTable).Write` hashes the entity ID with SHA-256. It copies the first
   16 bytes into `key[0:16]` and stores `SystemTime` in `key[16:24]`.
2. The L0 flusher writes those 16 hash bytes to the `entity_id_hash` Arrow
   column. `(*Resolver).scanRecordBatch` compares that column with the same
   16-byte prefix computed from the queried entity ID, then verifies the full
   entity ID before accepting a row.
3. The resolver lists `l0/{hex(sha256(entityID)[:8])}/`. At acceptance, the L0
   writer used the first SkipList key to choose this directory. For a
   single-entity checkpoint, that was the queried entity's own prefix, so the
   write and read paths addressed the same object.

The original growth test supplied an empirical check as well: 50 checkpoints of
`"alpha"` produced 50 objects under `l0/8ed3f6ad685b959e/`, and
`8ed3f6ad685b959e` is `hex(sha256("alpha")[:8])`.

The single-entity proof exposed a boundary rather than hiding it. A checkpoint
containing several entities was stored under the lexicographically smallest
entity hash. A query for any other entity listed a different prefix and could
not discover the file, although its row was present. ADR-0018 later replaced
that one-file layout with per-entity partitions; the current writer and reader
both derive the directory from the entity being stored or queried.

### Supply a non-empty valid-time interval at the HTTP boundary

The first resolver tests called `bridge.PutLocal` with an explicit open-ended
valid-time interval. They proved the `Resolver.AsOf`–`LocalFS`–Arrow seam, but
bypassed `handleInsert`. The production HTTP path initially supplied an empty
`CRDTEntry`, leaving `[ValidTimeStart, ValidTimeEnd)` as `[0, 0)`. AsOf excludes
that empty interval at every query point, so an insert could return 200 and
appear through `/v1/get` while `/v1/query` returned 404.

`handleInsert` now stamps `SystemTime` and `AssertionTime` from the write time.
An omitted `valid_from_ns` starts validity at that time; an omitted or zero
`valid_for_ns` selects `OpenEndedValidEndNs`, `9e18` nanoseconds after the Unix
epoch. A positive duration supplies an explicit end,
with overflow clamped to the open-ended sentinel. These defaults define the
meaning of an insert that makes no temporal assertion instead of persisting an
unqueryable zero interval.

The older `MaxValidTime` sentinel represented year-9999 as `time.Time`. Calling
`UnixNano` on it exceeded the int64 nanosecond range and wrapped to
`-4,852,116,232,933,722,624`, which also produced an unusable interval. There
were no production callers of that conversion. The HTTP path used the integer
sentinel directly, and ADR-0021 later replaced `MaxValidTime` with the matching
`MaxValidTimeEndNs` constant.

`TestQuery_InsertEndpointToQueryEndpoint_RoundTrip` covers the corrected path:
it posts through `handleInsert`, waits for the asynchronous checkpoint flush,
and queries through `handleQuery`. The response must contain the write's digest
and no payload field.

### Release each scan buffer, not a resolver-wide arena

`NewJemallocAllocator` is a small accounting handle with no `Close` method.
Each `scanFile` allocates its Arrow input buffer, grows it when necessary, and
frees it with a defer. Closing the downloaded object and Arrow reader is
similarly scoped to that file. The resolver can therefore retain its allocator
for the process lifetime without a separate arena shutdown operation.

## 3. Consequences

The decision closed the production read path from a checkpointed write to a
bitemporal HTTP query. It also made the storage boundaries explicit: the query
index carries temporal metadata and a digest, while the recovery image and WAL
remain responsible for reconstructing engine state. A query response is not
evidence that the original payload body exists in the index.

### Acceptance-time costs and their later resolutions

**Scan cost and L0 growth.** At acceptance, `AsOf` listed and scanned L0 files
for an entity and kept the qualifying row with the greatest `SystemTime`. Cost
grew with the number of checkpoint files. `ResolverConfig.MaxL0Files`, default
1000, bounded the scan but could make older history invisible. Each checkpoint
also left another object; this decision did not add merge compaction or a live
delete operation.

[ADR-0019](0019_l0_l1_per_entity_compaction.md) added per-entity L0-to-L1
compaction. The current resolver scans compacted L1 history and applies
`MaxL0Files` only to the uncompacted L0 tail after manifest supersession.
`QueryL0ListCapped` reports tail truncation; it does not make a truncated result
complete. [ADR-0021](0021_l0_reaper.md) added an opt-in reaper that removes
superseded L0 objects only after their replacement L1 can be downloaded.
[ADR-0050](0050_checkpoint_decouple_delta.md) moved periodic checkpoint work off
the commit path and limited later query-tier flushes to changed entities.

**Multi-entity discovery.** The smallest-hash directory rule made entities
other than the smallest in a shared checkpoint file undiscoverable through
their own prefixes. [ADR-0018](0018_per_entity_l0_split.md) replaced the old
`UploadBuffer` path with streaming per-entity serialization and
`UploadPartition`, closing that read miss without adding a global manifest.

**Open-ended timestamps.** The year-9999 `time.Time` sentinel could not be
converted safely to Unix nanoseconds. The HTTP fix used `OpenEndedValidEndNs`,
and [ADR-0021](0021_l0_reaper.md) removed the hazardous variable in favor of
`MaxValidTimeEndNs`. The Arrow timestamp representation did not change.

**Read visibility and query surfaces.** The original resolver read durable
Arrow objects only, so a write became visible to `/v1/query` after a checkpoint.
[ADR-0032](0032_live_source_read_your_writes.md) added an optional `LiveSource`;
the node now installs its engine adapter, allowing live and durable candidates
to compete under the same temporal filters and `SystemTime` dominance rule. A
durable row wins an equal-`SystemTime` tie, and a live-source error leaves the
durable answer intact. The HTTP response still exposes no payload field.

[ADR-0024](0024_resolver_range.md) added `Resolver.Range` and `/v1/range` over
the same storage boundary. [ADR-0029](0029_filename_bounded_download_skip.md)
and [ADR-0030](0030_manifest_channel_download_skip.md) later avoided downloads
whose filename bounds exclude them at the requested transaction time.
[ADR-0058](0058_secondary_index_production_wiring.md) added optional
`/v1/querybyh3` and `/v1/querybysystime` routes behind `--secondary-index`,
which defaults to false. Those extensions do not alter this decision's point
query, disabled-tier, or digest contracts.

### Incomplete files degrade the answer, not the digest contract

A reader concurrent with checkpoint upload can encounter an incomplete or
undecodable object. `scanFile` skips a corrupt record batch, and `AsOf` skips a
file whose download, open, or scan fails, then continues across the remaining
objects. A query can therefore return an earlier valid event while an upload is
in flight. Once the final checkpoint is complete, the quiescent-query test
requires the latest checkpointed event. L0 and L1 listing failures propagate to
the handler. Compaction-manifest listing or download failures do not: the
resolver leaves the affected L0 objects eligible for scanning instead of
treating them as superseded. The per-file skip policy must not be mistaken for
a successful decode.

This behavior does not synthesize a payload or digest. It also does not promote
the Arrow index above recovery: a skipped or unusable recovery image and the
rows left in the query tier are separate durability concerns. Later recovery
changes are recorded in ADR-0016 and its successors.

## 4. Evidence

### Integration coverage

The principal tests use a real `LocalFS`, WAL, and bridge rather than
constructing the object layout that they are meant to verify. The round-trip
tests also exercise the control handlers.

| Test | Property exercised |
|:--|:--|
| `TestQuery_RoundTrip_WritesThenQueriesPersistedHistory` | A checkpointed write is returned by both `AsOf` and `/v1/query` with the original system time and payload digest. The response has `present:true` and no `payload` field. With Arrow index writing disabled, the negative control returns `ErrEntityNotFound` and HTTP 404. |
| `TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash` | Two checkpointed versions survive an engine and WAL close. Recovery reports `witness.Bounded == true`; the later event is available at its horizon and the earlier event remains queryable at the earlier horizon. |
| `TestQuery_RaceClean_ConcurrentQueryAndCheckpoint` | A sequential writer performs 80 writes while checkpointing and querying run concurrently. Under the race detector, the acceptance run reported no data race. After the final checkpoint, `AsOf` returns the last written system time. |
| `TestQuery_DisabledWhenNoLSMRoot_Honest503` | A nil resolver returns 503 with the disabled-tier body rather than 404. A request with no parameters also returns 503, pinning the availability check before validation. |
| `TestQueryL0FileGrowthDisclosed` | Fifty checkpoints of one entity produce 50 L0 files, and a query across them returns the latest system time. This records the original append-only growth behavior; it does not claim that compaction was part of this decision. |
| `TestQuery_InsertEndpointToQueryEndpoint_RoundTrip` | The production `POST /v1/insert` and `GET /v1/query` handlers close the HTTP round trip with the corrected valid-time default and the stored digest. The test waits for the asynchronous L0 object before querying. |

The first five tests are in `pkg/mesh/query_test.go`. The HTTP insert test is in
`pkg/mesh/query_insert_endpoint_test.go`, which the original files-touched
summary omitted even though its follow-up valid-time fix was already documented.

### Original acceptance results

These are the results recorded for the original decision, not fresh performance
measurements of the current tree. The acceptance table did not preserve host
metadata for the package timings or benchmark.

| Check | Recorded result |
|:--|:--|
| `go build ./...` | 0 errors |
| `go vet ./...` | 35 pre-existing `unsafe.Pointer` notes in `pkg/sync`, `internal/chaos/probe.go`, and tests; 0 in the packages changed by this decision |
| `gofmt -l` on changed files | Empty output |
| `go test -race -count=1 ./pkg/mesh/` | Passed in 29.8s |
| `go test -race -count=1 ./internal/database/` | Passed in 2.2s |
| `go test -race -count=1 ./pkg/durability/` | Passed in 9.6s |
| `go test -count=1 ./pkg/receive/` | Passed in 3.9s |
| `internal/chaos` tests without `-race` | Passed in 5.4s |
| `TestHotPathZeroAllocations` | Passed without `-race`; the test skips under race instrumentation because that instrumentation changes `AllocsPerRun` |
| `BenchmarkHAMTInsertZeroAlloc -benchmem` | `BenchmarkHAMTInsertZeroAlloc-4: 11797 ns/op, 0 B/op, 0 allocs/op` |

The benchmark measures the in-process HAMT insertion path. It shows that adding
the query surface did not change that path's zero-allocation result; it is not a
query-latency or ingest-throughput measurement.

The production change touched `pkg/mesh/control.go` and
`cmd/sovereign-node/main.go`. Its coverage was added in the two mesh test files
named above. The decision consumed the existing resolver, allocator, and default
configuration rather than rewriting `internal/database`; later ADRs changed that
package for the reasons described under Consequences.

