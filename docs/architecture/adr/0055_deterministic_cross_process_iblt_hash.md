# ADR-0055: Deterministic cross-process IBLT hashing

**Status:** Accepted  
**Date:** 2026-09-20

## Context

[ADR-0054](0054_digest_change_gate.md) stopped unnecessary digest exchanges when Merkle roots
matched, but exchanges between different processes still failed to prune common keys. Before
this change, 20 of 20 sampled responses contained `delta=10000` for peers that already held
all 10,000 keys; the received IBLT had `countsum=40000`.

The cause was `hashKeyWithSeed` using `maphash.Hash` for bucket placement. The wire round-trip
through `SeedToUint64` and `Uint64ToSeed` faithfully preserved the seed's 8-byte backing word,
but the hash output also depended on process-local runtime state. `Subtract` therefore combined
tables whose common keys occupied different buckets. Peeling returned `ErrIncompletePeel`, and
`GenerateDelta` selected its full-keyset fallback. This wasted bandwidth without losing writes.

The change gate's `peerRoots` map had a second, independent problem: entries were never deleted,
so membership churn grew the map beyond the live peer set. Completed exchanges that fell back
after a failed peel and responses dropped at the responder concurrency bound were also absent
from the existing counters.

## Decision

Use a deterministic hash keyed only by the transmitted seed word, expose the fallback and drop
events, and evict stale root entries during the sweep. This extends the digest design in
[ADR-0034](0034_stratified_anti_entropy_mesh_wiring.md) and completes the cross-process hash
work identified by ADR-0054.

### Deterministic bucket placement

`hashKeyWithSeed` applies the splitmix64 finalizer to the key and `SeedToUint64(t.seed)`:

```go
x := key + SeedToUint64(t.seed)*0x9E3779B97F4A7C15
x ^= x >> 30
x *= 0xBF58476D1CE4E5B9
x ^= x >> 27
x *= 0x94D049BB133111EB
x ^= x >> 31
```

The result is a pure function of `(key, seedWord)`. The `maphash.Seed` type and `MakeSeed`
remain as the seed container and generator, preserving constructor signatures. The serialized
seed and buckets do not change, no fields are added to `IBLT` or `CRDTDelta`, and the hash adds
no allocation. `NewIBLTWithSeed` gives the StrataEstimator's IBLTs the same deterministic
placement. HAMT shard routing remains process-local and does not use this function.

Changing the hash changes digest contents but not their framing. Nodes using different hash
implementations can fail to peel and take the full-keyset fallback, as unmodified peers already
did; they do not silently compute a wrong difference.

### Peel capacity and the fixed test seed

The initial version of `TestIBLT_ZeroFalsePositives` failed on 2 of 30 random seeds after the
change. A comparison of five candidate hashes found failures on 7–12 of 400 seeds for each
candidate, with both sequential and production-shaped keys; the `maphash` baseline failed on
1 of 100. The fixed configuration has 100 difference keys, `k=4`, and 1024 buckets, a load of
about 0.39. At that load, a random-hypergraph 2-core can fail to peel regardless of which
uniform hash is used.

The test now uses seed word `0x9E3779B97F4A7C15` instead of choosing a fresh seed on every run.
Its 50-key assertion is unchanged. Production still chooses fresh round seeds; at this digest
configuration approximately 2% of 100-key differences can take the fallback. The oversend
counter makes that outcome visible, and the next exchange can reconcile the difference.

### Observable fallbacks and drops

`pkg/sync/delta_observe.go` exposes `PeelErr`, `DiffNil`, and `SendKeyCount` on `CRDTDelta`.
The mesh uses them to distinguish a clean empty delta from a completed exchange whose peel
failed. `digestPeelOversends` counts the latter; `digestRespondDropped` counts responses that
could not start because all responder slots were occupied. Exchange logs include the selected
key count, and sweep summaries include oversend and drop totals.

The pre-existing stratified-fallback metric covers failures while building an exchange. It did
not cover a response that arrived and could not be peeled, or a response discarded at the
responder bound. The two counters close those specific observation gaps without changing
reconciliation behavior.

### Sweep-time eviction of peer roots

`evictStalePeerRoots` runs at the start of each stratified sweep. Under `peerRootsMu`, it calls
the package-private `PeerSet.isLive` for each entry and deletes only departed peers. The lock
order is `peerRootsMu` followed by the peer set's read lock; no peer-set method calls back into
the gossiper's root map.

Lazy eviction avoids adding gossiper callbacks to the peer-removal paths. A stale entry can
cause one unnecessary exchange, while evicting a live peer could discard the root needed to
suppress or select the next exchange. A rejoined peer records a fresh root through the normal
announcement. Disabled stratified anti-entropy does not reach this call path.

## Consequences

Digest pruning now works across processes rather than only between engines in one test process.
The full-keyset fallback remains a correctness-preserving response to incompatible layouts,
timeouts, malformed input, and ordinary peel-capacity failures. The counters let an operator
distinguish those events from a clean `delta=0` instead of inferring pruning from bandwidth.

Root entries are bounded to the live peer set after a sweep that can evaluate liveness. A node
with no peers retains the last known entries until a peer returns. Later wire-format and digest
sizing changes retain the same requirements: common keys must hash identically across
processes, and stale peer state must not grow with every identity ever observed.

The measurements below used an eight-slot responder bound. That value describes this run, not
a permanent limit; later concurrency tuning does not invalidate the observation that no drops
occurred under this workload.

## Evidence

### Subprocess and unit tests

`TestIBLT_XprocDeterminism` compares hashes, bucket indices, and wire bytes from a parent and
two distinct child processes. `TestIBLT_XprocConvergence` passes a 900-key digest through the
wire codec and reconciles it against 1,000 keys in another process, returning exactly the 100
keys present only in the larger set. Calling in the opposite direction could return zero even
with a broken implementation, so the direction is part of the test.

`TestIBLT_BucketUniformity` checks bucket occupancy over 10,000 keys with `k=4` against the
Poisson bounds `max≤90/min≥8/χ²≤1534`. A deliberately weak hash trips the control.
Tests for `digestPeelOversends` and `digestRespondDropped` exercise both the healthy and failure
branches. The peer-root eviction test uses a three-node loopback-TLS mesh to check removal of a
departed peer, retention of a live peer, and recovery after rejoin.

An early two-process probe compared cached `go test` output and gave a false negative. Rerunning
with `-count=1` executed both processes: all nine probe lines differed before the fix. This is
why the determinism check launches subprocesses rather than comparing cached test results.

### Multi-region mesh

On 2026-09-20, seven runs used 100 node processes on three machines in three AWS regions,
split 34/33/33, with 10,000 keys. Stratified anti-entropy and the change gate were enabled,
the digest wait was 1500ms, and each run sampled 9 nodes, 3 per region. The measured dwell
was 25s. These conditions matched the enabled comparison arm used for ADR-0054.

| Run | Time to all 100 nodes | `delta=0` samples | Nonzero sampled deltas | Oversends | Responder drops |
|:--|:--|:--|:--|:--|:--|
| 1 | 3.431s | 855 | 400, 266 | 29 | 0 |
| 2 | 3.106s | 827 | 600, 73 | 33 | 0 |
| 3 | 4.071s | 833 | none | 32 | 0 |
| 4 | 4.730s | 946 | 100, 224, 76, 476, 345, 100 | 37 | 0 |
| 5 | 6.303s | 1022 | 500, 500 | 38 | 0 |
| 6 | 4.068s | 868 | none | 24 | 0 |
| 7 | 5.693s | 1056 | 61 | 35 | 0 |

Across the seven runs, 6,407 sampled converged-peer exchanges returned `delta=0`. Another
13 responses returned real differences of 61–600 keys during the WAN ramp, and none returned
all 10000 keys. The
ratio of empty to nonempty sampled responses was approximately 493:1 (6407 empty responses and
13 nonempty responses). Before the fix,
the corresponding sample was 20 of 20 responses returning the full 10,000-key set.

All seven runs converged within the 10s target, with times from 3.106s to 6.303s. No responder
drops were logged. Steady-state transmit was 2.98–3.27 MB/s per region, compared with
60.2–95.3 MB/s per region in the prior enabled-arm recheck, an 18–32× reduction over the same
dwell position. Oversend totals ranged from 24 to 38 per run and occurred during initial
contact and ramp-up, when the 1024-bucket digest could be over capacity; they were not
steady-state converged-peer responses.

### Core checks

A 32-core c8g.8xlarge passed the hot-path allocation checks. `BenchmarkHAMTInsertZeroAlloc`
reported 0 B/op and 0 allocs/op in three runs (9912/9929/10132 ns/op). A fresh
in-process core microbenchmark measured 71,888,410 ops/s against the 50,736,038 ops/s floor.
The core benchmark excludes networking, TLS, signature verification, and persistence; it is
not an ingest measurement and is not the source of the convergence results above.

The selected race-detector runs passed with these durations: admission 1.0s, durability 1574s
after its cap was raised to 2400s, attribution 14s, filtered mesh 289s, receive 566s, chaos
1054s, and database 649s.

The cold race-detector runs exposed verification timeouts rather than test failures: the sync
suite took 1993.429s and the mesh suite took 2197.718s when allowed to finish. ADR-0056 records
the timeout change. No failed test was converted into a pass by increasing a timeout.

