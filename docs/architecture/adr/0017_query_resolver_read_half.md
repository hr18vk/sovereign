# ADR-0017: The Query Resolver — the Read Half of the Durability Tier (/v1/query over Resolver.AsOf)

**Status:** Accepted
**Date:** 2026-08-02
**Author:** Harsh Rawat
**Builds on:** ADR-0016 (the LSM↔durability seam — the write half), ADR-0011 (the control port + read-path honesty), ADR-0013 (WAL recovery), ADR-0014 §0 (the seed-by-trace proof)

---

## §1. Context (the root cause)

ADR-0016 shipped the **write** half of the durability tier: `pkg/durability/snapshot.go`
`SnapshotToLSM` writes a dot-bearing recovery image (`ckpt/<LamportHigh>`) and a
bitemporal Arrow query index (`l0/{hashPrefix}/{txTimeNs}.arrow`) per checkpoint, so
crash recovery bounds to `O(post-checkpoint)` (ADR-0016 §2). The Arrow index existed,
vet-clean, its own tests green.

But the **read** half was dead code. `internal/database/query.go` `Resolver.AsOf(ctx,
entityID, validTime, transactionTime)` — the bitemporal point-query — had **zero
production importers** outside `internal/database` and its own tests (which ran against a
`mockS3Store`, never the `*LocalFS` ADR-0016 wired as the real S3). So the tier was
**half-closed**: a node could write → checkpoint → crash → recover, but could NOT
*query the persisted history*. A "durable database" that cannot be read is durable
storage, not a database. Closing the round-trip
`write → checkpoint → recover → query-the-history` is the gap this ADR closes.

`pkg/mesh/control.go` `ControlServer` already served `/v1/insert`, `/v1/get` (the live
HAMT — current state at now, ADR-0011 §1.1), `/v1/merkle`. There was no read of the
persisted bitemporal index. The `/v1/get` route answers "what is this entity's value
now?" (live state); the question the persisted index *exists to answer* — "what was this
entity's value as observed at valid-time V, transaction-time T?" — had no surface.

## §2. The seam (what was built)

Three edits, surgical, read-only — the write path (`bridge.PutLocal`,
`bridge.AppendCheckpoint`, `SnapshotToLSM`, `l0_flusher.go`, `memtable.go`) is
**untouched**.

### §2.1 The control surface (`pkg/mesh/control.go`)

- A `/v1/query` route: `mux.HandleFunc("/v1/query", s.handleQuery)`.
- A `resolver *database.Resolver` field on `ControlServer` (nil by default).
- A `SetResolver(r *database.Resolver)` method — the separate seam that wires the
  tier. **Chosen over a `NewControlServer` arg** to keep the 4-arg constructor
  signature stable for the existing `pkg/mesh` tests (which call
  `NewControlServer(g, nodeID, peers, metrics)`) — mirroring the `SetSnapshotter`
  precedent on a separate method, not the constructor. One call-site touched
  (`cmd/sovereign-node`).
- `handleQuery`: `GET /v1/query?key=<entityID>&valid_time=<rfc3339nano>&tx_time=<rfc3339nano>`
  → one `Resolver.AsOf` + one `json.Encode` (mirrors `/v1/get`'s one-Get-one-encode
  discipline). Status: 200 on hit, 404 on `ErrEntityNotFound` (with the honest
  `{error:"not found", entity:<key>}` body), 400 on bad params, 500 on a wrapped
  list/download/scan error (surfaced, never swallowed), 503 when the resolver is nil
  (§3). The 200 body is a `queryResponse{entity_id, system_time_ns,
  valid_time_start_ns, valid_time_end_ns, assertion_time_ns, h3_index,
  payload_digest_hex, present}`.

### §2.2 The wiring (`cmd/sovereign-node/main.go`)

- `var queryResolver *database.Resolver` (nil default — research/in-memory nodes, or a
  durable node started without `--lsm-root`, never construct it).
- Inside the `if snapshotStore != nil` block (where `--lsm-root` bound the `*LocalFS`),
  after `bridge.SetSnapshotter(lfs, true)`: construct the Resolver over the **same**
  `lfs` (one FS handle, one root — `S3Lister` + `S3Downloader` both backed by LocalFS;
  bucket `"local"` is cosmetic, LocalFS ignores it). Gated on `enableIndex=true` — the
  **same flag** `SetSnapshotter` flips — so the resolver stays nil exactly when the
  index is off: a clean 503 path, no orphaned query tier over a non-existent index.
- `startControlPort` gains a `resolver` arg (an internal function — the only caller is
  `main.run`, touched in lockstep); the inline `NewControlServer(...).Handler()` is split
  to `cs := NewControlServer(...); cs.SetResolver(resolver); cs.Handler()`.

### §2.3 The `pkg/mesh` import of `internal/database`

`pkg/mesh` → `internal/database` is acyclic: `internal/database` imports neither
`pkg/mesh` nor `pkg/durability` (verified by grep), so the new import adds no cycle.
`pkg/mesh` already imported `pkg/durability` (the Gossiper holds a `*durability.Bridge`,
ADR-0013), so the durability surface was already in `pkg/mesh`'s dependency set; the
*Resolver* was the missing link.

## §3. The honest-availability + no-recompute contracts

**503-honest-disabled.** When `s.resolver == nil` — a research node, or `--lsm-root`
absent — `/v1/query` returns `503` with `{"error":"query-tier disabled (no
--lsm-root)"}`. It does NOT return `404`: a route-absent `404` is indistinguishable to
a client from "entity not found", so a disabled query tier that 404'd would be a silent
lie — the same class as the ACK-before-durability 503 in `handleInsert`
(control.go:137). The 503 makes the unavailable tier *observable*. (Verified
red-before-fix: before this change the mux registered no `/v1/query` route, so
`GET /v1/query` hit ServeMux's default 404 — exactly the misreadable behavior; the fix
registers the route plus the nil-resolver 503 guard. T4 reproduces the 503, not the
404.)

**No-recompute digest law.** The `queryResponse.PayloadDigestHex` is echoed verbatim
from `entry.PayloadDigest` (the index's honest digest). The write path stamps it in
`bridge.PutLocal` (`sha256(payload)`, bridge.go:182); `InsertLocal` preserves the
caller's digest (crdt.go:949-951 override only the dot fields); `SnapshotToLSM` emits it
into the Arrow row with a **sentry** (empty) payload body (snapshot.go:445). AsOf echoes
that digest. Recomputing it — or, worse, reporting a `payload` value — would fabricate
a value the index may never have held: the "digest-is-not-value" fabrication class
(ADR-0011 §1.1, the read-path honesty guard). So the `queryResponse` has **intentionally
no `payload` field** (T1 asserts this). The persisted index carries an empty body by
design (the value survives on the originator, the digest on the index). The control port
now has two honest reads: `/v1/get` (live value/digest from the HAMT) and `/v1/query`
(persisted digest from the index, no body).

## §4. The round-trip byte-identity proof (verified before T1)

The first thing I verified, before writing T1, was the write-side key prefix vs the
read-side key prefix byte identity — the round-trip's biggest false-failure mode is an
encoding mismatch the prose glosses over. Verified by reading the bytes, not the prose:

**Write key construction** (`internal/database/memtable.go:144`):
```go
entityIDBytes := unsafe.Slice(unsafe.StringData(event.EntityID), len(event.EntityID))
h := sha256.Sum256(entityIDBytes)
var key [keySize]byte
copy(key[0:16], h[:16])                       // key[0:16] = sha256(entityID)[:16]
binary.BigEndian.PutUint64(key[16:24], uint64(event.SystemTime))
```

**Write dir prefix** (`internal/database/l0_flusher.go:218-229`, `UploadBuffer`):
```go
firstKey := it.Key()                          // the SMALLEST-hash SkipList entry
var hexPrefix [16]byte
hex.Encode(hexPrefix[:], firstKey[:8])        // hex(firstKey[:8]) = hex(sha256(smallestEid)[:8])
key := "l0/" + hexPrefix + "/" + txTime + ".arrow"
```

**Write col[0]** (`internal/database/l0_flusher.go:147`, `entityHashBuilder.Append(entityHash)`
where `entityHash = key[0:16]`): the 16-byte `sha256(entityID)[:16]`.

**Read hash** (`internal/database/query.go:119-126`):
```go
entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
fullHash := sha256.Sum256(entityIDBytes)
var hashPrefix [16]byte
copy(hashPrefix[:], fullHash[:16])            // hashPrefix = sha256(queriedEntity)[:16]
prefix := "l0/" + hex(hashPrefix[:8]) + "/"   // hex(sha256(queriedEntity)[:8])
```

**Read col[0] filter** (`internal/database/query.go:346`): `bytes.Equal(rowHash, hashPrefix[:])`
— compares the 16-byte row hash to `sha256(queriedEntity)[:16]`.

`hex(sha256(eid)[:8])` is the write dir prefix AND the read dir prefix; the 16-byte
`sha256(eid)[:16]` is the write col[0] AND the read col[0] filter. **Byte-identical.**

**Empirical confirmation (the T-WITNESS output):** 50 checkpoints of entity
`"alpha"` landed at `l0/8ed3f6ad685b959e/{txTime}.arrow` — and
`hex(sha256("alpha")[:8]) == "8ed3f6ad685b959e"`. The files exist at the exact directory
the read path computes for `"alpha"`. The byte identity holds; the round-trip closes.

**Honest residual (§6):** for a single entity the smallest-hash SkipList entry IS that
entity, so write `hex(sha256(eid)[:8])` == read `hex(sha256(eid)[:8])`. For a
**multi-entity** flush, the file is keyed by the smallest-hash entity in the SkipList; a
per-entity read computes the prefix from the queried entity — so a multi-entity flush
file is only retrievable for the smallest-hash entity. This is pre-existing write-path
behavior (l0_flusher.go:218-229); this change is read-only. The teeth use a single
entity so the round-trip closes; the residual is disclosed in §6, not fixed.

## §5. The teeth (T1–T4 + T-WITNESS) and the gate

All teeth in `pkg/mesh/query_test.go` (package mesh — `pkg/mesh` already imported
`pkg/durability`, acyclic to `internal/database`; T1–T4 + T-WITNESS drive the full
`bridge → SetSnapshotter → PutLocal → AppendCheckpoint → Resolver.AsOf → /v1/query`
stack over a real `*LocalFS`, the end-to-end that was missing). Each tooth fails before
the fix and passes after (no green-by-construction): the red-control sub-stages cut the
index write (`enableIndex=false`) so AsOf returns `ErrEntityNotFound` — the honest
observable of "the round-trip needs the write half," not a constructed green for the
read wire.

- **T1** `TestQuery_RoundTrip_WritesThenQueriesPersistedHistory` — the headline. One
  `PutLocal("alpha", payload, entry{SystemTime=T_alpha, ValidTime=[T_alpha, open)})` +
  one `AppendCheckpoint` writes `l0/{sha256("alpha")[:8]}/{T_alpha}.arrow`; a Resolver
  over the same `lfs` returns the persisted `TriTemporalEvent` — `SystemTime == T_alpha`
  and `PayloadDigest == sha256(payload)` verbatim. Then mounts the `/v1/query` surface
  (`SetResolver` + `httptest`) and asserts a 200 with `system_time_ns == T_alpha` and
  `payload_digest_hex == sha256(payload)` (the wire surface, not just the seam) and
  `present:true` and no `payload` field (the digest-is-not-value guard). Red-control sub-stage:
  `enableIndex=false` → AsOf → `ErrEntityNotFound` → handler 404 (the honest
  persistent-"not-found" sentinel), proving the 200 is not a constructed green.

- **T2** `TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash` — the
  round-trip across a crash. `PutLocal(alpha@T1)+AppendCheckpoint`;
  `PutLocal(alpha@T2)+AppendCheckpoint`; crash (WAL+engine Close);
  `RecoverEngineWithSnapshot(lfs)` → `witness.Bounded == true` (the latest dot-bearing
  image loaded, post-checkpoint tail only); a Resolver over the same `lfs` returns the
  persisted event @ T2 (the `l0/*.arrow` files survived the crash — they are a query
  tier, independent of the recovered HAMT). Plus the T1 history is queryable at a T1
  horizon (the index retained it, not overwrote it — a different file per checkpoint),
  and `ListObjects("l0/")` shows both T1+T2 files (the unbounded-growth witness). The
  durability tier is round-trip-closed: write → checkpoint → crash → recover →
  query-the-history.

- **T3** `TestQuery_RaceClean_ConcurrentQueryAndCheckpoint` — `-race -count=5` ready. A
  sequential writer (dot order == SystemTime order → deterministic latest-dot alpha at
  quiescence), a concurrent checker (`AppendCheckpoint` in a tight loop), and a
  concurrent querier (`AsOf` in a tight loop). `-race` flags no data race: LocalFS
  `ListObjects`/`Download` + the off-heap Arrow reads are concurrent-safe. At
  quiescence AsOf returns the latest checkpointed value exact — no torn-read
  false-positive (a file listed mid-Upload is continue-on-error'd by `scanFile`,
  keeping an earlier valid event; the final checkpoint is fully on disk, so the final
  AsOf is exact). Write-write concurrency is the engine's CAS, tested elsewhere; T3
  stresses the read-side torn-read race — the surface this change adds.

- **T4** `TestQuery_DisabledWhenNoLSMRoot_Honest503` — a ControlServer with no
  resolver (research/in-memory) returns 503 + the honest disclosure body, not 404. A
  second sub-tooth pins the order: a query to a disabled tier with no params still
  returns 503 (the 503 guard runs before param validation), so a future refactor can't
  400 a request that should be 503 (hiding the disabled state behind a 400).

- **T-WITNESS** `TestQuery_L0FileGrowthDisclosed` — the honest-negative tooth. N
  AppendCheckpoints → N `l0/*.arrow` files (no merge, no compaction). It asserts
  `fileCount == N` (the debt's existence — never `< N`, which would be a false-fix
  fabricated green) and logs (not assert-fails) the disclosure: "L0 unbounded growth
  disclosed: N files after N checkpoints; level-overwrite compaction is future work;
  the epoch tombstone compactor is dead-to-dead (no production DELETE operator) and is
  not the fix for this debt." It then verifies AsOf still functions over an unbounded L0
  (correctness preserved; the cost is `O(L0-files)` per query — the disclosed scope,
  not a target of this change).

### The gate

| Gate | Result |
|------|--------|
| `go build ./...` | **0 errors** |
| `go vet ./...` | 35 `unsafe.Pointer` notes, all pre-existing in `pkg/sync/{hamt_arena,iblt,crdt,reclamation,residency}.go` + `internal/chaos/probe.go` + their tests; **zero** in the packages touched here (`pkg/mesh`, `cmd/sovereign-node`, `internal/database` vet clean) |
| `gofmt -l` (all touched) | **empty** |
| `go test -race -count=1 ./pkg/mesh/` | **ok** 29.8s (T1–T4 + T-WITNESS + the existing control/batch/convergence/selectlatestdot/partition tests; **no data race**) |
| `go test -race -count=1 ./internal/database/` | **ok** 2.2s (the `.AsOf` + `JemallocAllocator` this change consumes, race-clean) |
| `go test -race -count=1 ./pkg/durability/` | **ok** 9.6s (the write half — no regression) |
| `go test -race ./pkg/sync/` (subset) + `TestHotPathZeroAllocations` (no-race) + `BenchmarkHAMTInsertZeroAlloc -benchmem` | **ok** fast subset; `TestHotPathZeroAllocations PASS` (it self-skips under `-race` by design — physics_test.go:198: race instrumentation perturbs `AllocsPerRun`); bench `0 B/op, 0 allocs/op` |
| `go test -count=1 ./pkg/receive/` (no `-race`) | **ok** 3.9s — the receive core passes. |
| `internal/chaos` (no `-race`) | **ok** 5.4s |
| T-WITNESS L0-growth disclosure | **Logged** in `TestQuery_L0FileGrowthDisclosed`: "50 files after 50 checkpoints; level-overwrite compaction is future work; epoch tombstone compactor dead-to-dead (no production DELETE operator) and not the fix." |

## §6. Honest scope (what this change does NOT claim)

1. **AsOf is `O(L0-files)` per query, NOT constant-time.** A query lists every `l0/*.arrow`
   under the entity's prefix (`ListObjects(ctx, bucket, prefix, MaxL0Files=1000)`,
   query.go:155), downloads + scans each, keeping the dominant (max SystemTime) match.
   With one file per checkpoint and no merge (§6.2), a query's cost grows with checkpoint
   count — bounded only by `ResolverConfig.MaxL0Files` (default 1000, query.go). This is
   the disclosed scope: unbounded ≠ broken (T-WITNESS proves correctness over an
   unbounded L0), it is bounded only by the cap + the cost. A constant-time read needs
   level-overwrite compaction (§6.2), future work.

2. **L0 unbounded growth is disclosed, NOT fixed.** Each `AppendCheckpoint` writes a
   fresh `l0/{prefix}/{txTimeNs}.arrow` (the write model — one append-only file per
   flush, no merge, no overwrite). T-WITNESS asserts `fileCount == N`. The compactor that
   would merge L0 files into sorted runs is deliberately **not wired** by this change.
   The epoch-tombstone compactor referenced in the tree is **dead-to-dead**: there is no
   production `DELETE` operator, so tombstones have nothing to reap and
   compaction-by-tombstone is a no-op the engine has no need of yet. Level-overwrite
   compaction (the real fix — merge N L0 files into one sorted L1 per entity) is future
   work, deliberately out of scope here.

3. **Multi-entity flush directory-keying residual.** A single checkpoint flush keys the
   file by the smallest-hash entity in the SkipList (`l0_flusher.go:218-229`
   `firstKey[:8]`); a per-entity read computes the prefix from the queried entity (§4).
   So a multi-entity flush file is only retrievable for the smallest-hash entity; other
   entities in that flush are not retrievable by their own prefix. This is the same
   pre-existing write-path behavior; this change is read-only, and the teeth use a
   single entity so the round-trip closes. Disclosed, not fixed (the fix is a per-entity
   index sub-key or a write-side change, both write-path, out of scope).

4. **`MaxValidTime.UnixNano()` overflow — latent landmine, disclosed, out of read-only
   scope.** `internal/database/l0_flusher.go:20` defines
   `var MaxValidTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)` — the documented
   "open-ended (year 9999)" sentinel. Its `.UnixNano()` **overflows int64**: year-9999 is
   ~2.5e26 ns from epoch, beyond int64's 9.2e18 ceiling, so it wraps to
   **-4,852,116,232,933,722,624** — a huge negative. A CRDTEntry with
   `ValidTimeEnd == MaxValidTime.UnixNano()` would fail AsOf's Filter3
   (`validTime >= validEnd`) for every positive validTime → the entity is unqueryable.
   **No production code calls `.UnixNano()` on `MaxValidTime`** (verified by grep: only
   the var's own definition + a docstring reference it), so the read tier is not broken in
   prod. The teeth sidestep it with a concrete int64-safe sentinel
   (`queryValidEndNs = 9e18`, `pkg/mesh/query_test.go`). This is a write-path-var contract
   landmine (the var invites the overflow by existing as a `time.Time` with a documented
   "open-ended" intent that `.UnixNano()` silently breaks); fixing it is write-path work
   (change the var to an int64 sentinel, or teach the writer to never persist the
   overflow), out of this change's read-only mandate. **Disclosed here, not fixed.**

6. **The `/v1/insert` ↔ `/v1/query` ValidTime interlock — disclosed, then closed.** The
   headline "round-trip-closed" was claimed in the original version of this change, but the
   production HTTP flow POST `/v1/insert` → GET `/v1/query` did NOT close: `handleInsert`
   (control.go) stamped `entry := eng.CRDTEntry{}` — all-zero ValidTime — and
   `InsertLocal` (crdt.go:949) + `bridge.PutLocal` preserve the caller's ValidTime
   verbatim, so the persisted row's `[validStart, validEnd) = [0, 0)` interval was empty
   by construction. AsOf's Filter 3 (`query.go:360`: `validTimeNs >= validEnd`) then
   skipped the row for every query point → a live-reproduced 404 on a 200-Put event
   (POST wonder → 200, GET /v1/get → 200 present, GET /v1/query → 404). The original
   T1–T4 teeth passed because they called `bridge.PutLocal(.., queryTestEntry(..))`
   directly with a real open-ended range, bypassing `handleInsert` — they proved the
   `Resolver.AsOf ↔ LocalFS ↔ Arrow` seam, never the production HTTP round-trip. The
   defect predated this ADR (`CRDTEntry{}` was introduced by an earlier change); the false
   "round-trip-closed" claim was mine. Both fixed in a follow-up commit: `handleInsert`
   stamps the honest open-ended default (`ValidTimeStart = now`,
   `ValidTimeEnd = mesh.OpenEndedValidEndNs = 9e18` — year ~2253, int64-safe, the same
   sentinel the teeth pin via `queryValidEndNs`; NOT `database.MaxValidTime.UnixNano()`,
   which overflows — see §6.4) for a client that asserts no bitemporal window; the
   optional `valid_from_ns` / `valid_for_ns` fields let a client override the default
   explicitly. The default is the documented default for a documented absence (a client
   that asserts no bitemporal window means "valid from write-time, indefinitely" — the
   only honest semantics a non-bitemporal write API carries); it is not a fabricated
   range asserted as if the client had claimed it (the "digest-as-value"
   honesty-guard class). The production round-trip is now closed through the HTTP
   surface by the `TestQuery_InsertEndpointToQueryEndpoint_RoundTrip` tooth (T-I2) — the
   tooth T1 should have been — which drives the real write surface (`handleInsert`),
   not the bypass.

5. **Allocator lifecycle.** `database.NewJemallocAllocator()` is a stateless handle
   (`struct{bytesAllocated atomic.Int64}`; the constructor is trivial, no arena init —
   the same handle `NewSnapshotMemTable` constructs per-checkpoint). It has **no
   `Close`**: AsOf releases each read buffer per `scanFile` via `defer`
   (query.go:216-220), so no off-heap bytes survive a query; the handle itself holds
   nothing. Zero shutdown teardown needed; the per-buffer `Free` IS the lifecycle. The
   read allocator is constructed once (when `--lsm-root` binds), used for the process
   lifetime, and dropped at exit — no leak, no arena to tear down.

## §7. Attack surface (and the mitigations)

- **Torn read mid-Upload.** A query concurrent with a checkpoint may `ListObjects` a
  file that is mid-`Upload` (the L0 flush is a streaming S3 PutObject; a partial file is
  observable to ListObjects before the upload completes). `scanFile` is
  continue-on-error (query.go:233): a row that fails to decode is skipped, the scan
  keeps earlier valid events, so a torn file degrades to an earlier dominant match —
  not a crash, not a fabricated value. T3 (the race tooth) exercises this and asserts no
  crash + no race. A torn file is the disclosed failure mode; it does not corrupt the
  read (the index is append-only — a torn file is a strictly-worse index, never a wrong
  one, because the dominant match ignores the undecodable rows).

- **The query tier is NOT the source of truth.** AsOf reads the persisted Arrow index;
  the recovered HAMT (`RecoverEngineWithSnapshot`) is. A checkpoint the bounded-recovery
  skipped (a corrupt image, ADR-0016 §6) leaves that checkpoint's `l0/*.arrow` on disk
  but does NOT load it into the HAMT — so a query against those rows returns a persisted
  event independent of the recovered state. This is correct (the index is a durable
  record; the HAMT is the live state) and the same class as the
  "digest-is-not-value" boundary: `/v1/query` reports what the index durably holds,
  `/v1/get` reports what the live HAMT holds; the two can disagree after a
  skipped-checkpoint recovery, and the SDK must not conflate them. The `no payload`
  field + the verbatim digest make the index's claim honest (a digest, not a value).

## §8. The headline (honest integers — measured, not predicted)

**Update:** "round-trip-closed" is now closed through the HTTP surface (T-I2), not just
the direct-bridge seam (T1–T4). The default ValidTime the `/v1/insert` path stamps is
documented + disclosed (§6.6); no fabricated range, no swallowed default. A re-audit of
the original claim exposed the false headline; the follow-up fix closed it,
byte-verified.

- **Byte-identity:** empirical. 50 checkpoints of `"alpha"` → 50 files at
  `l0/8ed3f6ad685b959e/`; `hex(sha256("alpha")[:8]) == "8ed3f6ad685b959e"`. The files
  exist at the exact prefix the read path computes. The round-trip closes.
- **Round-trip across a crash (T2):** `witness.Bounded == true`; post-recover AsOf
  returns `SystemTime == T2` (the latest checkpointed value), digest verbatim; T1
  history queryable at the T1 horizon.
- **Race-clean (T3):** `-race` over 80 writes + continuous checkpoint + continuous query
  → no data race, quiescent AsOf returns the latest checkpointed value exact.
- **503-honest (T4):** nil-resolver `/v1/query` → 503 + `{"error":"query-tier disabled
  (no --lsm-root)"}`, not 404.
- **Production round-trip (T-I2 — the load-bearing closure):** POST `/v1/insert` →
  `handleInsert` stamps the open-ended ValidTime default → interval-triggered
  `AppendCheckpoint` writes the index → GET `/v1/query` returns 200 with the same
  `PayloadDigest` the write stamped (`sha256(val)`). The round-trip is closed through
  the HTTP surface. Red→green chronology byte-verified: at the un-fixed `handleInsert`
  (stashed `CRDTEntry{}`), the same POST + GET returned `404 {"error":"not found",...}`
  on the just-written event (the live drive + the tooth reproducing it); post-fix → 200
  + the honest digest. The T1–T4 teeth prove the seam (the `Resolver.AsOf ↔ LocalFS ↔
  Arrow` boundary); T-I2 proves the production flow through `handleInsert`. Both green.
- **L0-growth disclosed (T-WITNESS):** 50 files after 50 checkpoints (asserted), the
  debt disclosed + not fixed.
- **Hot path unchanged:** `BenchmarkHAMTInsertZeroAlloc-4: 11797 ns/op, 0 B/op,
  0 allocs/op` — the query path is off the hot path; the zero-GC invariant is untouched.
- **Files touched (surgical):** `pkg/mesh/control.go` (the route + `SetResolver` +
  `handleQuery`), `cmd/sovereign-node/main.go` (the Resolver construction + wiring),
  `pkg/mesh/query_test.go` (new — the teeth). `internal/database` unrewritten (this
  change consumes the existing `Resolver`/`NewJemallocAllocator`/`DefaultResolverConfig`/
  `ErrEntityNotFound` — interface conformance only, no edit). The write path untouched.

## §9. Verdict

**Conditionally approved.** This change advances the claim from "the durability tier is
half-closed (write → checkpoint → recover)" (ADR-0016) to "the durability tier is
round-trip-closed (write → checkpoint → crash → recover → query-the-history)". The read
half is wired; the index has a production importer (the control port) for the first
time. The disclosed residuals (AsOf `O(L0-files)`, unbounded L0 growth, multi-entity
directory-keying, the `MaxValidTime.UnixNano()` overflow landmine, the unwired
compactor) are all write-path or future work, none a correctness regression introduced
here, all disclosed, none silently accrued. The hot path is unchanged; the zero-GC
invariant holds; the durability invariant is strengthened (the tier is now
interrogable); determinism is preserved (the byte-identity is machine-verified +
empirically confirmed).
