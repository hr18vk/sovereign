# ADR-0064: Bounded-bytes IBLT reconciliation

- **Status:** Accepted
- **Date:** 2026-10-04

## Context

Digest-based anti-entropy used a fixed 1,024-bucket IBLT. Its v1 placement,
`idx_i = (h1 + i*h2) mod B`, derives every index from the pair `(h1 mod B,
h2 mod B)`. There are approximately `B^2/4` such pairs, so two difference keys
share all `k` cells with probability approximately `4/B^2`, independent of `k`.
At `B=1024` this gives a `2^-18` floor; the corresponding model predicts 26%
failure at `D=400`. Growing `B` in proportion to `D` does not remove that term.

Three other constraints prevented dynamic sizing from helping. `NewArenaIBLT`
accepted only the fixed remote size, digest construction walked live shard
roots while concurrent writes could replace them, and an oversized arena
request could clear beyond the largest variable-size block. A digest also has
to remain bounded when its size is influenced by a remote peer.

The design therefore needed new key placement, a wire format that cannot mix
placements, in-band size negotiation, a bounded sizing policy, and a consistent
snapshot. It had to leave the default v1 exchange unchanged.

## Decision

Enable IBLT v2 with `--iblt-v2`, default false. The option requires
`--stratified-anti-entropy` and is selected during initialization, before any
engine or table is constructed. Each table captures the selected scheme for its
lifetime.

### Decorrelated placement

For each index, v2 adds a different golden-ratio multiple to the primary hash,
applies three splitmix64 finalizer rounds, and reduces the result modulo `B`.
Placement is a pure function of the key and transmitted seed word. The indices
use stack storage, including for wire values of `k` through `ibltMaxK=8`.

This removes v1's shared-arithmetic-progression mechanism. A simplified model
puts the corresponding pair-collision term at `B^-k`, or `2^-40` at `B=1024`
and `k=4`, leaving the 2-core threshold `B > c_k*D`, with `c_4 = 1.295`
(Goodrich–Mitzenmacher, Theorem 1), as the useful sizing guide. The deterministic
rounds are not proven `k`-wise independent, and this expression is not a peel
guarantee. [ADR-0065](0065_reconciliation_campaign_test_design.md) later measured
a residual `k=4` failure floor across the bucket ladder; increasing `B` alone
does not make failures arbitrarily unlikely.

Disjoint 16-bit hash fields were rejected. They require a power-of-two table,
and shifts beyond 64 bits collapse indices above `k=4` to bucket zero even
though the wire decoder accepts `k` through 8.

### Versioned tables and frames

`MarshalIBLT` writes `IBL1` for v1 tables and `IBL2` for v2 tables.
`UnmarshalIBLT` accepts only the active process scheme, and subtraction requires
matching bucket counts, `k`, and placement schemes. Mesh requests and responses
use roles `0x11` and `0x12` for v2; root announcements retain their shared role.

A mixed v1/v2 pair does not attempt cross-scheme peeling. Requests receive no
incompatible response, parsing rejects the other scheme, and the exchange falls
back to sending the full keyset. `Join` is idempotent, so this preserves
convergence at additional bandwidth cost until the fleet uses one scheme.

### Size propagation and stable snapshots

`GenerateDigestSizedWithSeed` builds a table at a requested size after
`ClampIBLTBuckets` bounds it to `[128, 21845]`. `GenerateDigestWithSeed` remains
a wrapper at the default 1,024 buckets. `GenerateDelta` adopts the remote
digest's seed and bucket count directly, rather than storing a mutable size on
the engine that concurrent sweeps and responders could race over.

The responder reads the little-endian scheme magic and bucket count from the
request's eight-byte IBLT prefix. Invalid or truncated prefixes receive no
response. The response contains the populated table; the requester rebuilds its
own table when that response arrives.

Digest construction captures all shard roots, inserts from that captured view,
and compares the roots again. Any changed root restarts the entire build, up to
three attempts, and increments `DigestSnapshotRestarts`. Retrying one shard is
invalid because XOR-additive insertion would cancel keys inserted on the first
pass. If the last attempt still changes, the digest is returned as a hint;
reconciliation falls back to the full set when it cannot peel a valid
difference. Quiescent same-seed builds are deterministic and do not restart.

### Adaptive sizing within the arena bound

Each peer starts at 1,024 buckets. An observed `PeelErr` doubles that peer's
size; `DiffNil` denotes incompatible configurations and does not escalate it.
Four consecutive clean peels halve the size. This delays decay and reduces
oscillation frequency near the peel threshold, but a failed peel and
re-escalation can still immediately follow decay, with a full-keyset oversend.
Sizes remain within
`[1024, 21845]`. Only the `SweepLoop` goroutine writes the ladder, including
eviction of dead peers, so the map needs neither a lock nor atomics.

With `--defer-handler` disabled, a failed peel sends the full keyset and
resynchronizes the peer, removing the large difference that caused escalation.
The ladder mainly bounds steady-state digest sizes in that configuration.
Enabling the defer handler preserves divergence across rounds and lets sizing
adapt without immediately resynchronizing the peer.

The largest arena variable block has 524,288 bytes. After its 8-byte header,
524,280 bytes hold exactly 21,845 buckets of 24 bytes each. `NewArenaIBLT`
panics above that boundary because the allocator would otherwise clear beyond
the returned block. Remote-controlled counts pass through the clamp before
allocation. A 699,050-bucket table at the decoder's 16 MiB heap-allocation
bound therefore produces a size mismatch and full-keyset fallback, not an arena
panic.

At `k=4`, the 21,845-bucket ceiling puts the `c_4` transition near `D=16.8K`;
the literature's approximately 2.8 sizing margin corresponds to about `D=7.8K`.
These are capacity guides, not guarantees. Larger differences require a
rateless, multi-frame continuation mechanism that the mesh does not provide.

### Compatibility and observability

With v2 disabled, placement remains `(h1 + i*h2) mod B`, the wire magic remains
`IBL1`, digest wrappers produce identical bytes at 1,024 buckets, and the sweep
log receives no v2 suffix. With both v2 and stratified anti-entropy enabled,
the suffix reports the peer bucket range, escalation and decay counts, and
snapshot restarts. Enabling v2 without stratified anti-entropy is rejected at
startup rather than leaving an ineffective option.

CRDT merge and application remain unchanged in `Join` and
`pkg/sync/crdt_apply.go`. The signed-delta envelope in
`pkg/attribution/envelope.go` and the Cap'n Proto wire schema in
`api/capnp/api/capnp/schema.capnp` and `schema.capnp.go` also remain
unchanged. This decision redesigns digest construction and IBLT exchange, not
CRDT merging or delta wire formats.

Deployment is fleet-wide: there is no per-exchange downgrade. Rolling back
means disabling the flag throughout the fleet. Full-keyset fallback remains
the correctness path during a mixed deployment.

## Consequences

Successful peels send a delta proportional to the actual difference instead of
the full set, while bounded digests bound the reconciliation hint's memory and
wire cost. Peel failure, incompatible versions, malformed input, and excessive
size still resolve to idempotent full-state transmission or configured
deferral, never a knowingly partial difference.

The stable cut adds root comparison and occasional whole-build restarts.
Snapshot restarts are visible in sweep logs. Three attempts do not guarantee a
stable snapshot under a sustained writer, and a clean finite-seed sample does
not establish a universal failure bound.

Later decisions retain this design while refining its receive path and sizing:

- [ADR-0072](0072_ebr_hoist_mesh_dial_and_digest_gating.md) restricts wait-channel
  deposits to response roles, so requests cannot be drained as responses.
- [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md) adds
  `--iblt-v2-min-buckets` as an optional starting and decay floor and returns
  goroutine-local digest slabs directly to the arena free list.
- [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md) replaces the full
  request table with the eight-byte header described above, adds arena-size
  validation for large bucket floors, and protects the now-concurrent direct
  free-list returns against ABA and torn headers.

## Evidence

### Placement, compatibility, and sizing

`TestIBLT_V2DecorrelatedFloor` in `pkg/sync/iblt_v2_test.go` pins these outcomes
for 12 deterministic seeds per arm. Counts are successful pruned peels; every
remaining seed used the full-keyset fallback, and no arm returned a wrong diff.

| Differences | Buckets | v1 | v2 |
|---|---|---|---|
| 400 | 1,024 | 11/12 | 12/12 |
| 700 | 1,024 | 8/12 | 12/12 |
| 780 | 1,024 | not measured | 11/12 |
| 900 | 1,024 | not measured | 0/12 |
| 900 | 2,048 | not measured | 12/12 |

The `D=780` case sits just below the asymptotic threshold and still loses one
seed. The `D=900` cases show both failure above the threshold and recovery
after doubling the table. These deterministic cases characterize the tested
shapes; they do not replace the larger residual-floor study in ADR-0065.

`TestIBLT_V2XprocDeterminism` compares a parent and two distinct child processes
on every v2 bucket index and the complete `IBL2` wire encoding.
`TestIBLT_V1LegacyCompatAndVersionLockstep` checks v1 arithmetic, both wire
magics, rejection in both directions, byte-equal default digest wrappers, and
the one-bucket remote fallback.

In `pkg/mesh/iblt_mesh_test.go`, `TestIBLTVersionLockstep` converges a
homogeneous v2 pair over loopback TLS in one round with 25 differences per
direction, no peel oversends, and no fallbacks. Its mixed-scheme arm converges
without either side building an incompatible response.
`TestIBLTSizeAdopt` accepts a 2,048-bucket v2 prefix and rejects v1 magic and
truncated input. `TestIBLTAdaptiveLadder` drives 900 differences through failure
at 1,024 buckets, four clean peels at 2,048 buckets, decay to 1,024, and another
failure and escalation. `TestIBLTSweepSuffixObservability` checks the empty disabled
suffix, the enabled fields, and the warning for an ineffective configuration.

### Snapshot and arena boundaries

`TestIBLT_DigestStableCutSnapshot` requires byte-identical quiescent builds and
no restarts, then uses concurrent inserts across shards to require a detected
restart. Its ordinary, non-race allocation check requires zero allocations for
digest construction and the stable cut. Race instrumentation is measured
separately because it perturbs allocation counters.

`TestIBLT_ArenaBucketCeiling` accepts 21,845 buckets, recovers the constructor
panic at 21,846 buckets, and checks clamp mappings including `0` to `128`, `5000` to
`5000`, and `699050` to `21845`. A 699,050-bucket remote digest must produce
`DiffNil` and full-keyset fallback without a panic or a quiescent snapshot
restart.

### Digest-build cost

`BenchmarkIBLT_DigestBuildCost` measures a 10K-key digest build. A
c8g.16xlarge run with `GOMAXPROCS=32`, `-benchmem`, and `-count=3` measured
medians of 1,366,956 ns/op for v1 and 1,425,584 ns/op for v2: 4.3% higher, or
about 5.9 ns/key at `k=4`. Both reported the harness's one allocation per
operation; the arena-backed build itself allocates no heap storage. This cost
is on digest construction, not the per-operation ingest path.

The rejected bit-field calculation took 3,837 ns/op with `0 B/op` and
`0 allocs/op` in its separate 1,024-key arithmetic benchmark. That figure does
not include digest construction and is not directly comparable with the
10K-key build medians.

The benchmark is available as:

```bash
go test -bench=IBLT_DigestBuildCost -benchmem -count=3 ./pkg/sync/
```

These are in-process and loopback tests plus a digest-build microbenchmark,
not a multi-machine convergence measurement.
