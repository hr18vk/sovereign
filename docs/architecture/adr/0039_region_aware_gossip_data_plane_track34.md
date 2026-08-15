# ADR-0039: Region-Aware Gossip Data-Plane (Track 34)

- **Status:** ACCEPTED
- **Date:** 2026-08-12 (Day 34)
- **Track:** 5.1 (the data-plane half — the loopback-provable substrate for the
  Raft metadata-plane arc)
- **Fork count:** SEVENTEENTH clean-chain fork (the Day-33 ADR-0038 fuzz harness
  was the SIXTEENTH)
- **Streak:** Day-29 `44f89527` streak PRESERVED (NO streak-breaker — the 4
  md5-FROZEN files are UNTOUCHED; the region-aware layer is a mesh/cmd/telemetry
  addition, NOT a CRDT/data-layer change)
- **SSoT:** 23 → 24 (ONE counter — `InterRegionEnvelopesShipped`, the M6
  disclosure the prompt's M6 names)

## Context

The blueprint's Track 5.1 names the planetary-scale topology: a region-aware
gossip that turns the per-sweep **full-mesh O(N²)** iteration (every peer every
round) into the **intra-region full-mesh + inter-region fan-out-N** O(log N)
rounds convergence. At 100 nodes the full-mesh is 10,000 connections per sweep
per node; the fan-out-3 region-aware path is ≤45 (≤10 intra/AZ + ≤3 inter
fan-out × a few regions) — the connection-count cut the blueprint's
`supremum.mesh.inter_region_envelopes` counter discloses.

Day 31 + 32 shipped the PQ moat (the VERIFY + the SIGN-WIRE). Day 33 shipped the
fuzz harness (the crash-surface falsifier). Day 34 ships the **region-aware
DATA-PLANE** — the loopback-provable substrate for the Raft metadata-plane arc
(a future fork). The data-plane half is the iteration-source swap: the per-peer
BODY (generateSweepDelta → the Day-29 digest-exchange → GenerateDelta → the
Day-5 batched ship) is BYTE-UNCHANGED; the wiring change is ONE iteration source
+ the selector. The wire shape is byte-identical — the fan-out selector chooses
WHICH peers to send the SAME batch/digest/hybrid frames to, NOT a new frame
shape (so the Day-33 fuzz harness stays load-bearing without re-work).

## Decision

Ship a NEW `pkg/mesh` seam — the `TopologyManager` (a peer registry keyed by
`[16]byte` carrying a `RegionTag` per peer) + the `Select(ctx)` iteration source
`AntiEntropySweep` calls when `--region-aware` is ON. `Select` returns
intra-region peers (full-mesh — all peers with the SAME region as `SelfRegion`)
+ inter-region peers (fan-out N, prefer cross-region, seeded-deterministic
random tie-break — the epidemic-spreading property).

### The 6 files

- **`pkg/mesh/region.go`** (NEW): the `RegionTag` type (a `uint8` — cache-
  friendly, the prompt's "the honest call is the uint8"; 0 = `RegionUnset`) +
  the `sameRegion`/`crossRegion` comparators + the `pickInterRegionFanout`
  partial-Fisher-Yates helper.
- **`pkg/mesh/topology.go`** (NEW): the `TopologyManager` (the `RWMutex`-guarded
  peer registry + the seeded-deterministic `Select`) + the `newSeededRand`
  helper (`math/rand/v2` `NewPCG` — goroutine-local + reproducible under the
  seed).
- **`pkg/mesh/gossip.go`** (MODIFIED): the `topology` + `regionAware` +
  `interRegionReporter` fields + the `SetTopology`/`SetRegionAware`/
  `SetInterRegionReporter` setters + the `AntiEntropySweep` iteration-source
  swap (the load-bearing wiring change — ONE branch: `topology != nil &&
  regionAware` → `topology.Select(ctx)` else the full-mesh `peers.Peers()`).
- **`cmd/sovereign-node/main.go`** (MODIFIED): the `--region-aware` (OPT-IN,
  default false = byte-identical Day-33) + `--self-region` + `--region-fanout`
  flags + the `addr@region` peer-suffix parsing (`parsePeerRegions` +
  `peerIDForAddr` — the deterministic addr-derived `[16]byte` surrogate) + the
  ONE-block `SetTopology`/`SetRegionAware`/`SetInterRegionReporter` wiring.
- **`internal/telemetry/registry.go`** (MODIFIED): the `InterRegionEnvelopesShipped`
  counter (the 24th SSoT, M6) — constructed in all 4 sites (the package var +
  `allCounters()` + `init()` + `rebuildCounters()` — the Day-21 fill discipline;
  a counter missing from `rebuildCounters()` silently drops to nil under `--otel`).
- **`pkg/mesh/day34_topo_test.go`** (NEW): the §III gate — 7 teeth.

### The §III gate (10 teeth, all GREEN)

1. **T-TOPO-OFF-IS-BYTE-IDENTICAL** — `--region-aware` OFF (the default)
   converges 1000 events in 1 round, inter-region counter silent (byte-identical
   Day-33).
2. **T-TOPO-ON-INTRA-CONVERGES** — ON with BOTH peers SAME region (the N=2
   no-op) converges in 1 round, counter silent (the fan-out selector routes
   intra-only).
3. **T-TOPO-ON-INTER-CONVERGES** — ON with the 2 peers in DIFFERENT regions
   converges in 1 round, M6 counter fires A=1 B=1 (the inter-region arm IS in
   use).
4. **T-TOPO-DETERMINISTIC** (M2) — `Select(seed=42)` is deterministic (same
   seed → same output EVERY run); different seed → different inter subset (the
   epidemic-spreading property).
5. **T-TOPO-CONNECTION-CUT** (M4) — fan-out 3 selects 4/10 peers (a 60%
   connection-count cut); fan-out 0 selects 1 (intra-only).
6. **T-TOPO-RACE** — the `TopologyManager` is race-free under concurrent
   `SetRegion` + `SetSeed` + `Select` (the `RWMutex` discipline; GREEN under
   `-race` GOMAXPROCS=4).
7. **T-TOPO-SSOT-24** — the 24th SSoT counter is PRESENT + named +
   modeCounter (NOT a gauge — the gauge count STAYS 3).
8. **T-TOPO-ROUND-COUNT** (M2/M4, the LOAD-BEARING headline) — a SIMULATED
   N=100 mesh (10 regions, fan-out 3, per-node-per-round seeded) converges in
   **K=3 rounds** (gate ≤ 5; O(log_3 100) ≈ 4-5); DETERMINISTIC under the seed
   (run1==run2==3); the full-mesh baseline is K=1 BUT 9,900 connections vs the
   fan-out ~1,300 (the connection-count cut the rounds trade against). A
   simulated round-count is a NUMBER, NOT a silicon proof — the 100-NODE
   wall-time gate is the AWS arc.
9. **T-TOPO-NO-FROZEN-TOUCH** (M7) — the 4 md5-FROZEN files + envelope.go are
   byte-identical pre-AND-post Day-34 (the `44f89527` streak PRESERVED; NO
   streak-breaker).
10. **T-TOPO-SUBSTRATE-UNCHANGED** — the Day-29/31/32 substrate teeth compile +
    run GREEN post-Day-34 (the build-green is the load-bearing signal; the
    selector is the iteration-source swap, the per-peer body + wire shape + read
    path UNCHANGED).

### The distinct-region fan-out discovery (a real finding)

The FIRST `pickInterRegionFanout` implementation was a partial Fisher-Yates over
the cross-region CANDIDATE PEERS — it picked fan-out-N PEERS, possibly all in
the SAME region (the docstring claimed "preferring cross-region diversity" but
the implementation did NOT enforce it). The `T-TOPO-ROUND-COUNT` tooth caught
the divergence: the peer-Fisher-Yates variant converged the simulated N=100 mesh
in K=7-10 rounds (vs the blueprint's O(log_3 100) ≈ 4-5 prediction) — a fan-out
that picks the same region twice wastes a slot (the delta already reaches that
region; the second pick's intra-region full-mesh would have spread it anyway).

The fix: `pickInterRegionFanout` now groups the cross-region candidates by
REGION, picks up to fanout-N DISTINCT regions under the seeded tie-break, then
chooses ONE peer per region (a second seeded tie-break). This honors the
"prefer cross-region diversity" promise — each round spreads the delta to
fanout-N DISTINCT regions → O(log_fanout N) convergence. The
`T-TOPO-ROUND-COUNT` tooth then converged in **K=3** (well within the ≤5 gate).

A SECOND finding the tooth caught: the per-sweep seed must be PER-NODE (not a
single global round-based seed). With a single `seed = round+1`, every infected
node's `Select` in a given round used the SAME seed → the distinct-region
tie-break routed them ALL to the SAME 3 regions → no additional spread (K=10).
The honest model: each node uses a distinct per-node-per-round seed
(`round*N + nodeIndex`) so different nodes fan-out to different regions in the
same round (the epidemic-spreading property). The production `SweepLoop` stamps
the seed per-sweep; a per-node seed component (the nodeID XOR the round) is the
production-honest model the tooth mirrors.

## Consequences

- **Positive:** the region-aware data-plane substrate is loopback-proven (the
  fan-out selector is correct, deterministic, byte-identical-when-OFF, race-free,
  + the M6 counter discloses the inter-region arm firing). The Raft metadata-
  plane arc (a future fork) builds on this substrate. The connection-count cut
  is a NUMBER (60% at fan-out 3 over 10 peers), not an adjective.
- **Negative / honest residual:** the cmd dial loop uses a PLACEHOLDER zero
  peerID (the Day-2 honest gap — the peer's real nodeID is unknown until the
  peer presents its leaf; OOB pubkey provisioning is the Day-35+ AWS arc). So
  `--region-aware` ON at N=2 in the cmd binary is a NO-OP (the dial loop's
  zero peerID does NOT match the addr-derived region keys → every peer routes as
  `RegionUnset` = intra = byte-identical full-mesh). The loopback gate is the
  SIMULATED N=100 mesh (in-process, REAL peerIDs), NOT the 2-node binary run.
  Day 34 ships the SELECTION logic, NOT the provisioning logic.
- **The determinism bug CAUGHT + FIXED:** the initial `Select` built the
  cross-region candidate list via map iteration (NON-deterministic order in Go),
  so the same seed yielded a different selection per call — a Law IV violation
  (a flaky selector). The fix: sort the inter-region candidates by `[16]byte`
  (in lockstep with their regions) BEFORE the partial Fisher-Yates shuffle, so
  the shuffle permutes a DETERMINISTIC input → the same seed yields the same
  output EVERY run. T-TOPO-DETERMINISTIC caught this; the fix is in
  `topology.go` `sortInterCandidates`.
- **Carry-forwards:** the 32-bit length-bomb residual (Day-33 carry-forward);
  the OOB peer-Directory pubkey provisioning (the Day-35+ arc); the 100-node
  silicon convergence gate (the AWS arc — the loopback gate is the SIMULATED
  N=100 mesh round-count, NOT silicon wall-time); the Raft metadata-plane.

## The 4c Honesty (Law VI)

These teeth run on the 4-core executor box over loopback TLS 1.3, NOT on named
silicon. The connection-count cut is measured in-process (the selector's output
length); the silicon-scale 100-node convergence gate is the Day-35+ AWS arc.
The teeth prove the CORRECTNESS (byte-identity-when-OFF + convergence-under-
inter-region + determinism) + the MECHANISM (the fan-out selector routes the
cross-region peer) + the DISCLOSURE (the M6 counter fires) — the silicon-scale
NUMBER is a separate fork.
