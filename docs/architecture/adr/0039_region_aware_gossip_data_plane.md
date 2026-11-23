# ADR-0039: Region-Aware Gossip Data Plane

**Status:** Accepted

**Date:** 2026-08-12

## Context

A full-mesh anti-entropy sweep contacts every peer on every round. At 100 nodes that is 9,900 directed edges in total, not 10,000 connections per node. Region-aware selection should retain the local full mesh while limiting remote contact to a seeded fan-out, without changing delta encoding or the receive path.

The round-count evidence for this decision is a selector simulation. It is not a deployed-fleet latency measurement and does not establish a convergence bound under arbitrary network partitions.

## Decision

Add `TopologyManager`, a mutex-guarded registry of peer IDs and `RegionTag` values. A tag is a `uint8`; `RegionUnset` is zero and compares as local to every region so incomplete provisioning does not remove peers from a sweep.

When `--region-aware` is enabled, `Select` returns all same-region peers in deterministic order followed by at most `--region-fanout` remote peers. The default fan-out is 3 and `MaxFanout` is 16. `pickInterRegionFanout` chooses distinct remote regions first and then one peer per selected region. `--self-region` supplies the local tag, and region-aware selection remains disabled by default.

`sortInterCandidates` sorts peer IDs and their region tags together before the seeded `math/rand/v2` PCG shuffle. Sorting makes a given seed and registry produce the same selection despite randomized Go map iteration. The original region-aware sweep did not call `SetSeed`, so selection retained the manager's initial seed. A later change makes each sweep seed selection with the round number XOR the low 64 bits of the node ID, decorrelating different nodes in the same round.

`AntiEntropySweep` changes only its peer iteration source. Digest exchange, batch and hybrid framing, signing, and CRDT application are unchanged. `InterRegionEnvelopesShipped` increments when a sweep selects a cross-region peer, before publishing; it measures routing choices rather than confirmed successful sends.

## Consequences

With region awareness disabled, the full peer set remains the iteration source. Unset region tags also retain full-mesh behavior rather than silently partitioning an unprovisioned deployment.

The first selector shuffled individual remote peers, allowing several fan-out slots to land in one region. The simulated 100-node workload then took K=7–10 rounds. Grouping by region reduced that run to K=3. A second experiment showed that using only the round as every node's seed correlated their choices and took K=10; the later per-node seed component addresses that correlation.

[ADR-0040](0040_oob_peer_directory_provisioning.md) replaces the original placeholder peer identity with provisioned identities, so the early two-node command-binary no-op is not the current behavior. [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md) later adds optional regional gateways and boot dialing, plus `--partial-intra-view` and `--gateways-per-region`; those options are also off by default.

The tests establish selector behavior and loopback convergence. They do not measure multi-machine convergence time, and the inter-region counter does not prove successful delivery.

## Evidence

`TestTopologyOffIsByteIdentical`, `TestTopologyOnIntraRegionConverges`, and `TestTopologyOnInterRegionConverges` use two loopback TLS nodes with real peer IDs and a 1,000-event split. They cover the disabled, same-region, and cross-region paths and their counter behavior.

`TestTopologyDeterministic` repeats seed 42 and permits a different seed to collide on the same subset. `TestTopologyConnectionCut` checks that fan-out 3 selects 4 of 10 peers (a 60% reduction) and fan-out 0 selects only the local peer. `TestTopologyRace` exercises concurrent registration, seed updates, and selection under the race detector. `TestTopologyCounter` checks registration of `supremum.mesh.inter_region_envelopes`.

`TestTopologyRoundCount` simulates 100 synthetic nodes in ten regions with fan-out 3 and per-node, per-round seeds. The recorded run reached every node in K=3 rounds against a limit of K<=5 and repeated with the same result. In that layout each node has nine local peers and at most three remote selections; the full-mesh comparison is 9,900 directed edges. The simulation has no sockets or TLS.

`TestTopologySubstrateUnchanged` checks that the stratified anti-entropy and post-quantum test symbols remain available. The two-node tests ran on a four-core development machine; no 100-node wall-time result is claimed here.
