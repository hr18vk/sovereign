# ADR-0039: Region-Aware Gossip Data-Plane

- **Status:** ACCEPTED
- **Date:** 2026-08-12
- **Scope:** the data-plane half of the region-aware topology — the
  loopback-provable substrate the Raft metadata-plane work builds on.
- **Telemetry:** the distinct-counter set grows 23 → 24 (one counter —
  `InterRegionEnvelopesShipped`, the inter-region-envelope disclosure).
- **Protected-core surface:** the 4 core CRDT/wire files are untouched. This is
  a mesh/cmd/telemetry addition, not a CRDT/data-layer change.

## Context

The target topology is a region-aware gossip that turns the per-sweep
**full-mesh O(N²)** iteration (every peer every round) into the
**intra-region full-mesh + inter-region fan-out-N** O(log N)-rounds
convergence. At 100 nodes the full-mesh is 10,000 connections per sweep per
node; the fan-out-3 region-aware path is ≤45 (≤10 intra/AZ + ≤3 inter
fan-out × a few regions). The `supremum.mesh.inter_region_envelopes` counter
discloses that connection-count cut.

The post-quantum verify + sign-wire work and the wire-protocol fuzz harness
(the crash-surface falsifier) were already in place. This change ships the
**region-aware data-plane** — the loopback-provable substrate for the Raft
metadata-plane work that follows. The data-plane half is the iteration-source
swap: the per-peer body (generateSweepDelta → the digest exchange →
GenerateDelta → the batched ship) is byte-unchanged; the wiring change is one
iteration source plus the selector. The wire shape is byte-identical — the
fan-out selector chooses WHICH peers to send the SAME batch/digest/hybrid
frames to, not a new frame shape, so the fuzz harness stays load-bearing
without re-work.

## Decision

Add a new `pkg/mesh` seam — the `TopologyManager` (a peer registry keyed by
`[16]byte` carrying a `RegionTag` per peer) plus the `Select(ctx)` iteration
source `AntiEntropySweep` calls when `--region-aware` is ON. `Select` returns
intra-region peers (full-mesh — all peers with the same region as
`SelfRegion`) plus inter-region peers (fan-out N, prefer cross-region,
seeded-deterministic random tie-break — the epidemic-spreading property).

### The 6 files

- **`pkg/mesh/region.go`** (NEW): the `RegionTag` type (a `uint8` —
  cache-friendly; 0 = `RegionUnset`) + the `sameRegion`/`crossRegion`
  comparators + the `pickInterRegionFanout` partial-Fisher-Yates helper.
- **`pkg/mesh/topology.go`** (NEW): the `TopologyManager` (the
  `RWMutex`-guarded peer registry + the seeded-deterministic `Select`) + the
  `newSeededRand` helper (`math/rand/v2` `NewPCG` — goroutine-local and
  reproducible under the seed).
- **`pkg/mesh/gossip.go`** (MODIFIED): the `topology` + `regionAware` +
  `interRegionReporter` fields + the `SetTopology`/`SetRegionAware`/
  `SetInterRegionReporter` setters + the `AntiEntropySweep` iteration-source
  swap (the load-bearing wiring change — one branch: `topology != nil &&
  regionAware` → `topology.Select(ctx)`, else the full-mesh `peers.Peers()`).
- **`cmd/sovereign-node/main.go`** (MODIFIED): the `--region-aware` flag
  (opt-in, default false = byte-identical pre-change behavior) +
  `--self-region` + `--region-fanout` + the `addr@region` peer-suffix parsing
  (`parsePeerRegions` + `peerIDForAddr` — the deterministic addr-derived
  `[16]byte` surrogate) + the one-block
  `SetTopology`/`SetRegionAware`/`SetInterRegionReporter` wiring.
- **`internal/telemetry/registry.go`** (MODIFIED): the
  `InterRegionEnvelopesShipped` counter (the 24th distinct counter) —
  constructed in all four sites (the package var + `allCounters()` + `init()`
  + `rebuildCounters()`; a counter missing from `rebuildCounters()` silently
  drops to nil under `--otel`).
- **`pkg/mesh/region_fanout_test.go`** (NEW): the §III gate — 10 guards.

### The §III gate (10 guards, all GREEN)

1. **T-TOPO-OFF-IS-BYTE-IDENTICAL** — `--region-aware` OFF (the default)
   converges 1000 events in 1 round, inter-region counter silent
   (byte-identical to the pre-change path).
2. **T-TOPO-ON-INTRA-CONVERGES** — ON with both peers in the same region (the
   N=2 no-op) converges in 1 round, counter silent (the fan-out selector
   routes intra-only).
3. **T-TOPO-ON-INTER-CONVERGES** — ON with the 2 peers in different regions
   converges in 1 round; the inter-region counter fires A=1 B=1 (the
   inter-region arm is in use).
4. **T-TOPO-DETERMINISTIC** — `Select(seed=42)` is deterministic (same seed →
   same output every run); a different seed → a different inter subset (the
   epidemic-spreading property).
5. **T-TOPO-CONNECTION-CUT** — fan-out 3 selects 4/10 peers (a 60%
   connection-count cut); fan-out 0 selects 1 (intra-only).
6. **T-TOPO-RACE** — the `TopologyManager` is race-free under concurrent
   `SetRegion` + `SetSeed` + `Select` (the `RWMutex` discipline; green under
   `-race` at GOMAXPROCS=4).
7. **T-TOPO-24** — the 24th distinct counter is present + named + a
   modeCounter (not a gauge — the gauge count stays 3).
8. **T-TOPO-ROUND-COUNT** (the load-bearing headline) — a simulated N=100
   mesh (10 regions, fan-out 3, per-node-per-round seeded) converges in
   **K=3 rounds** (gate ≤ 5; O(log_3 100) ≈ 4-5); deterministic under the
   seed (run1 == run2 == 3); the full-mesh baseline is K=1 but 9,900
   connections vs the fan-out ~1,300 (the connection-count cut the rounds
   trade against). A simulated round-count is a number, not a silicon proof —
   the 100-node wall-time gate is separate multi-machine work.
9. **T-TOPO-NO-FROZEN-TOUCH** — the 4 core files + envelope.go are
   unchanged by this change.
10. **T-TOPO-SUBSTRATE-UNCHANGED** — the pre-existing substrate tests compile
    and run green after this change (the build-green is the load-bearing
    signal: the selector is the iteration-source swap; the per-peer body, the
    wire shape, and the read path are unchanged).

### The distinct-region fan-out discovery (a real finding)

The first `pickInterRegionFanout` implementation was a partial Fisher-Yates
over the cross-region candidate PEERS — it picked fan-out-N peers, possibly
all in the same region (the docstring claimed "preferring cross-region
diversity" but the implementation did not enforce it). The
`T-TOPO-ROUND-COUNT` guard caught the divergence: the peer-Fisher-Yates
variant converged the simulated N=100 mesh in K=7-10 rounds (vs the
O(log_3 100) ≈ 4-5 prediction) — a fan-out that picks the same region twice
wastes a slot (the delta already reaches that region; the second pick's
intra-region full-mesh would have spread it anyway).

The fix: `pickInterRegionFanout` now groups the cross-region candidates by
REGION, picks up to fanout-N distinct regions under the seeded tie-break,
then chooses one peer per region (a second seeded tie-break). This honors the
"prefer cross-region diversity" promise — each round spreads the delta to
fanout-N distinct regions → O(log_fanout N) convergence. The
`T-TOPO-ROUND-COUNT` guard then converged in **K=3** (well within the ≤5
gate).

A second finding the guard caught: the per-sweep seed must be per-node (not a
single global round-based seed). With a single `seed = round+1`, every
infected node's `Select` in a given round used the same seed → the
distinct-region tie-break routed them all to the same 3 regions → no
additional spread (K=10). The honest model: each node uses a distinct
per-node-per-round seed (`round*N + nodeIndex`) so different nodes fan out to
different regions in the same round (the epidemic-spreading property). The
production `SweepLoop` stamps the seed per-sweep; a per-node seed component
(the nodeID XOR the round) is the production-honest model the guard mirrors.

## Consequences

- **Positive:** the region-aware data-plane substrate is loopback-proven (the
  fan-out selector is correct, deterministic, byte-identical-when-OFF,
  race-free, and the counter discloses the inter-region arm firing). The Raft
  metadata-plane work builds on this substrate. The connection-count cut is a
  number (60% at fan-out 3 over 10 peers), not an adjective.
- **Negative / honest residual:** the cmd dial loop uses a placeholder zero
  peerID — the peer's real nodeID is unknown until the peer presents its
  leaf; out-of-band pubkey provisioning is later work. So `--region-aware` ON
  at N=2 in the cmd binary is a no-op: the dial loop's zero peerID does not
  match the addr-derived region keys, so every peer routes as `RegionUnset` =
  intra = byte-identical full-mesh. The loopback gate is the simulated N=100
  mesh (in-process, real peerIDs), not the 2-node binary run. This change
  ships the selection logic, not the provisioning logic.
- **The determinism bug, caught and fixed:** the initial `Select` built the
  cross-region candidate list via map iteration (non-deterministic order in
  Go), so the same seed yielded a different selection per call — a flaky
  selector. The fix: sort the inter-region candidates by `[16]byte` (in
  lockstep with their regions) before the partial Fisher-Yates shuffle, so
  the shuffle permutes a deterministic input → the same seed yields the same
  output every run. T-TOPO-DETERMINISTIC caught this; the fix is in
  `topology.go` `sortInterCandidates`.
- **Known limitations & follow-ups:** the 32-bit length-bomb residual; the
  out-of-band peer-directory pubkey provisioning; the 100-node silicon
  convergence gate (the loopback gate here is the simulated N=100 mesh
  round-count, not silicon wall-time); the Raft metadata-plane.

## §7.1 The N=2 no-op (the cmd-binary consequence)

With `--region-aware` ON in the cmd binary at N=2, the region routing is a
no-op: the dial loop stores every peer under a placeholder zero peerID (the
peer's real nodeID is unknown until the peer presents its leaf), while the
`TopologyManager` keys region tags under `peerIDForAddr(addr)` (a SHA-256
addr surrogate). The zero peerID never matches the addr-derived keys, so the
region lookup misses and every peer routes as `RegionUnset` = intra =
byte-identical full-mesh. The loopback gate is therefore the simulated N=100
mesh (in-process, real peerIDs), not the 2-node binary run; the out-of-band
peer-directory provisioning of ADR-0040 retires the zero peerID and activates
the region routing in the binary.

## Test-environment honesty

These tests run on a 4-core development box over loopback TLS 1.3, not on
named cloud silicon. The connection-count cut is measured in-process (the
selector's output length); the silicon-scale 100-node convergence gate is
separate multi-machine work. The tests prove the correctness
(byte-identity-when-OFF + convergence under inter-region + determinism), the
mechanism (the fan-out selector routes the cross-region peer), and the
disclosure (the counter fires) — the silicon-scale number is separate work.
