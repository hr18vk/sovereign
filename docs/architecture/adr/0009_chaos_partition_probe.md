# ADR-0009: Partition probe and convergence after healing

- **Status:** Accepted
- **Date:** 2026-07-28
- **Predecessor:** [ADR-0008](0008_prometheus_metrics.md)

## Context

The encrypted transport, two-node gossip mesh, and Prometheus metrics were in
place, but no test had closed a peer connection, introduced writes during the
partition, restored connectivity, and checked reconvergence. The missing
property was recovery without losing the writes made while partitioned.

This decision adds a two-node probe over real loopback TLS connections. It uses
equal Merkle roots as the convergence condition and a target of less than 100ms
from healing to equal roots. The `sovereign_convergence_lag_seconds` gauge
exposes the interval, while `sovereign_gossip_rounds_total` records completed
gossip rounds.

The target has a deliberately narrow meaning. The in-process test establishes
partition recovery on one kernel; it does not establish the same latency across
machines or availability zones.

---

## Decision

### Close one transport peer

`(*PeerSet).ClosePeer(peerID [16]byte) error` removes the peer from both the
`peers` and `byAddr` maps under the write lock, then cancels its reader and
closes the connection. Removing the map entries first makes a concurrent
`Publish` fail its live-peer lookup instead of writing to a closed connection.
A later `Dial` or `ReconnectLoop` can restore the peer; closing a missing peer
is an idempotent no-op.

The current implementation also calls `closeDone` before waiting on `pc.done`.
Inbound peer connections have no read loop that would otherwise close that
channel, so this prevents `ClosePeer` from waiting forever. `sync.Once` handles
the outbound reader closing it concurrently.

### Compose the probe from production components

`ConvergenceProbe` drives the two existing peer sets and gossipers:

- `Partition` closes both directions and records `partitionAt`.
- `Heal` re-dials both sides through `PeerSet.Dial` and records `healAt` only
  after both peer maps contain the restored edges.
- `StartSweepLoops` starts the ordinary `SweepLoop` before the partition.
- `WaitForConvergence` polls both engines with `MerkleRootFromShards` and
  returns `time.Since(healAt)` when the roots match. Reading shard roots avoids
  constructing a merged state snapshot on every poll.

The probe changes no receive-path behavior. Frames after healing still pass
through `HandleFrame`, `VerifyCRDTFrame`, and `ApplyCRDTDeltaEvent`.

### Report gossip rounds without a metrics dependency

`Gossiper` holds a nil-safe `roundReporter func()` and exposes
`SetRoundReporter(fn func())`. `SweepLoop` invokes the callback after each
executed round. The command binds it to `Recorder.IncGossipRound` immediately
after constructing the gossiper.

This callback keeps `pkg/mesh` independent of `pkg/metrics` and leaves the
`NewGossiper` signature unchanged. A gossiper constructed without a recorder,
including the `--selftest` path, retains a scrapeable counter whose value is 0.

---

### Include the sweep wait in the latency target

The measured interval is:

```
heal to equal roots = sweep wait + RTT + IBLT reconciliation + apply
```

With a running sweep, the wait for the next tick is in `[0, tick)`. At the
default 100ms tick, that wait alone can exhaust the 100ms target. The in-process
test therefore uses `--gossip-tick=50ms` as an explicit fixture, leaving the
remaining budget for the round trip, reconciliation, and application.

`StartSweepLoops` runs before the partition. Starting a ticker at `healAt` would
instead add a full tick before its first fire and measure a different setup.
During the partition, `AntiEntropySweep` returns early when no peers remain; the
same running loop resumes within `[0, tick)` after `Heal` re-dials.

### Start the clock when connectivity returns

In the in-process probe, `healAt` is recorded after the re-dials and peer-map
checks complete. The returned interval is `time.Since(healAt)`.

A security-group partition on AWS has a different boundary. The CLI request can
return before the datapath rule changes, with propagation taking from 100ms to
minutes. Starting the mesh latency measurement at that CLI return would include
cloud control-plane delay. The multi-machine procedure therefore starts at the
first successful gossip round after connectivity returns, detected through
`sovereign_gossip_rounds_total`, and records both timestamps so the exclusion is
visible.

### Keep loopback and multi-machine results separate

The in-process test uses loopback TLS on `127.0.0.1`, with an RTT of roughly
10µs rather than the approximately 0.3–1.0ms expected within an availability
zone. Its less-than-100ms assertion covers convergence behavior and the tick
budget; it is not a multi-machine latency receipt.

The separate security-group procedure applies the same roots-equal and latency
checks across two machines. A result such as 140ms would be recorded as a missed
target. Restating the target as less than 200ms, using a 25ms tick, or reporting
a different cross-zone bound would each be a separate, explicitly labeled
result rather than a reinterpretation of the loopback measurement.

---

### Exercise divergence during a partition

`TestPartitionHeal_ConvergesUnder100ms` builds on the two-node loopback TLS
harness used by `TestTwoNodeConvergence_InMemory`. It performs this sequence:

1. Write to A and let the ordinary sweep converge both roots.
2. Close both directions with `probe.Partition`.
3. Write three more events to A and verify that B does not receive them.
4. Restore both connections with `probe.Heal`.
5. Call `WaitForConvergence` with a 100ms deadline and 50ms tick, then check
   equal roots and the presence of every partitioned write on B.

The test records that its latency is loopback-only and runs under the race
detector in the recorded gate. Failure to converge is a correctness failure;
convergence beyond the deadline is a missed latency target.

---

### Multi-machine security-group procedure

The proposed multi-machine procedure uses two nodes in one availability zone
and the same 50ms gossip-tick fixture. The peer port is 8443 and the metrics
port is 7431. It revokes and restores security-group ingress, polls metrics
every 10ms, and subtracts the first successful post-restore gossip round from
the time the roots
become equal. Both the security-group grant and first-round timestamps must be
recorded.

That procedure was conditional on provisioning. This ADR records no completed
multi-machine run and no intra-zone latency measurement.

---

## Consequences

- Partitioning is a transport operation. The receive verification and merge path
  is unchanged, and the independent chaos orchestrator remains a separate test
  harness.
- The 50ms tick is part of the measurement conditions. The default 100ms tick
  cannot support the same worst-case bound because its sweep wait can consume
  the entire target.
- Three events per phase exercise a small apply phase. The recorded envelope
  cost was ~8ms/envelope over loopback TLS, or ~24ms for the three-event phase.
  This does not bound convergence for 10K+ divergent events;
  a 20-event example already implied approximately 160ms of apply time before
  batching.
- The probe covers two nodes, not a three-node partition whose peers heal at
  different times. It also measures healing rather than throughput or the
  approximately 60µs per-delta signing cost at scale.
- Closing a connection does not model security-group propagation. Excluding
  that propagation keeps the measurement scoped to the mesh, but an operational
  SLO that includes the cloud control plane would be longer and separate.

---

## Evidence

- `TestPartitionHeal_ConvergesUnder100ms` in `pkg/mesh/partition_test.go` is the
  primary regression test. It drives real loopback TLS connections, checks that
  partitioned writes replicate after healing, and applies the 100ms deadline
  with the explicit 50ms tick. The recorded gate also ran it with `-race`.
- `TestTwoNodeConvergence_InMemory` in `pkg/mesh/gossip_test.go` supplies the
  underlying two-node convergence harness.
- `WaitForConvergence` compares roots through `MerkleRootFromShards`, the same
  shard-root mechanism used by the convergence gauge. `ClosePeer` covers both
  inbound and outbound connection shutdown without bypassing the receive path.
- No completed two-machine security-group run is cited as evidence for this
  decision. The loopback test and the proposed multi-machine procedure are
  separate evidence tiers.
