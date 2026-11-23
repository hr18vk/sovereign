# ADR-0007: Real-socket mesh with signed-envelope gossip over TLS 1.3

**Status:** Accepted  
**Date:** 2026-07-28

## Context

[ADR-0006](0006_tls13_transport_default_tier.md) supplied a mutual-TLS
listener and a node binary, but the initial binary did not dial peers or run a
gossip sweep. Tests could join engines directly in memory; a network mesh
needed to serialize deltas and digests, authenticate their origins, and pass
through the same receive gates as other writes.

TLS authenticates the connection, while CRDT-frame signatures authenticate the
origin and payload carried by an envelope. The mesh needed both rather than
treating an encrypted connection as sufficient authority to apply a delta.

## Decision

Add `pkg/mesh` as a caller of the existing transport and receive path. The
publication chain is:

```text
GenerateDelta(remoteDigest).Entries(entityID, entry)
  -> BuildCRDTDeltaEvent(entityID, payload, entry)
  -> SignCRDTFrame(ownerSeed, innerWire)
  -> NewSignedRelayEnvelopeV3(innerWire, signature, dot, origin, nil)
  -> LengthPrefixFrame(envelope.Marshal())
  -> PeerSet.Publish
  -> TransmitTLSFrame
```

The receiver performs `FrameReader.ReadFrame`, `Receiver.HandleFrame`, origin
key lookup, `VerifyCRDTFrame`, and `ApplyCRDTDeltaEvent`. It never substitutes
a direct engine `Join` for frame authentication.

At acceptance, the mesh and its two wire serializers were callers of the
existing CRDT, envelope, receiver, and IBLT implementations. The change did not
alter `crdt.go`, `crdt_apply.go`, the Cap'n Proto schema pair, `envelope.go`,
`receiver.go`, `ingress_epoll.go`, `ForwardEnvelope`, or `iblt.go`. It also did
not include the partition probe, Prometheus metrics, batched envelopes, an SDK,
a three-node mesh, multi-NIC eBPF, or AF_XDP. The gossip tick defaulted to
100ms, with 50ms reserved for the control-plane partition-probe override.

`BuildCRDTDeltaEvent` in `pkg/sync/crdt_capnp_wire.go` is the non-test Cap'n
Proto producer for the same schema and wire version consumed by
`ApplyCRDTDeltaEvent`. It returns `([]byte, error)` and carries the payload as
well as its digest so the receiver can check their correspondence.

`MarshalIBLT` and `UnmarshalIBLT` in `pkg/sync/iblt_wire.go` serialize a digest
as `[4]magic 'IBL1' | [4]numBuckets | [2]k | [8]seed | [N*20]buckets`. The
seed must survive the round trip because `GenerateDelta` rebuilds its local
digest with the remote seed. The conversion of the opaque `maphash.Seed`
backing word uses `unsafe.Pointer`, with size checks and round-trip tests for
the eight-byte layout assumed by Go 1.26.1.

Each `NodeIdentity` owns a 32-byte Ed25519 seed, distinct from its TLS leaf
key, and derives its node ID from the first 16 bytes of the signing public key.
That ID must match the engine's local node ID. Each peer registers the other's
public key in its `identity.Directory` before frames can be accepted.

The initial sweep calls `GenerateDelta` with an empty remote IBLT and sends the
full delta to every peer on every round. Idempotent join makes this correct,
and it avoids adding a digest-control protocol to the receive path in the same
change. Its costs are repeated bandwidth and one signature verification per
delta rather than work proportional to the set difference.

## Consequences

1. **The first convergence result was loopback-only.** Two endpoints ran in one
   process on one machine, not on two `c8g.8xlarge` machines. The two-machine
   run was deferred pending a 64-vCPU quota, so this result did not settle
   multi-machine readiness.
2. **Full-delta oversend trades bandwidth for a smaller change.** Every round
   sends the full delta rather than the `|d|`-entry set difference. Idempotent
   join preserves convergence, but bandwidth and verification work grow with
   the full entry count. [ADR-0034](0034_stratified_anti_entropy_mesh_wiring.md)
   later wires digest exchange behind `--stratified-anti-entropy`.
3. **Per-delta signing leaves verification on the sweep path.** The recorded
   32-core baseline measured 60.19 µs per Ed25519 verification. At that cost,
   verification work grows linearly with the number of individually signed
   deltas on one core.
   [ADR-0010](0010_batched_delta_wire_v1.md) later adds batched envelopes to
   amortize signatures across deltas.
4. **Peer keys initially required manual provisioning.** The node registered
   its own public key, but each peer key had to be supplied out of band. Dial
   bookkeeping used a zero placeholder peer ID; acceptance still keyed on the
   signed `OriginNodeID`. [ADR-0040](0040_oob_peer_directory_provisioning.md)
   later adds `--peer-dir`; TLS identity alone does not provision a CRDT key.
5. **The initial sweep did not exercise the IBLT wire.** `MarshalIBLT` and
   `UnmarshalIBLT` established and tested the serialization seam before digest
   exchange used it, but oversend left that exchange off the hot path. A wrong
   seed makes subtraction compare buckets hashed under different seeds; the
   resulting full-set fallback still converges at higher bandwidth cost.
   [ADR-0055](0055_deterministic_cross_process_iblt_hash.md) and
   [ADR-0064](0064_iblt_reconciliation.md) later define IBL2, selected with
   `--iblt-v2`.
6. **The payload cache is unbounded.** `InsertLocalEvents` retains
   entity-and-dot to payload mappings without eviction, so memory grows with
   causal history. That bound remains absent in v0.2.0.
7. **The insertion wrapper owns the digest contract.** `InsertLocalEvents` sets
   `PayloadDigest` to the payload's SHA-256 before insertion, keeping the engine
   entry and wire payload consistent. A caller that bypasses this seam with a
   mismatched digest is rejected during verification.
8. **The initial mesh had no convergence-lag metric.** It reported rounds
   through test logs rather than `/metrics`.
   [ADR-0008](0008_prometheus_metrics.md) adds the gauge.

The current default `SignCRDTFrame` uses randomized-nonce Ed25519. Its nonce
hashes 64 random bytes and the message without the secret-key prefix, so it
relies on `crypto/rand`; it is not hedged against random-number-generator
failure.

## Evidence

The original acceptance checks and their recorded results were:

| Area | Check | Result |
|---|---|---|
| Build and static checks | Build all packages; vet the mesh and node; check formatting; run the mesh tests with the race detector | Passed |
| Authenticated wire | Signed-envelope construction and TLS transmission appear in the mesh path; no direct raw `Join` shortcut | Passed |
| Loopback convergence | Two engines, 1000 events, equal Merkle roots within 10 rounds | Passed in 2 rounds, race-clean |
| Two-machine convergence | Two `c8g.8xlarge` machines converge | Deferred pending the 64-vCPU quota |
| Core boundaries | Seven CRDT, schema, envelope, and receive files remain unchanged; `forward.go` and `iblt.go` also remain unchanged | Passed |
| Change scope | Only the mesh, two wire serializers, node wiring, and documentation change | Passed |
| Gossip tick | Document the 100ms default and 50ms control-plane override | Passed |
| Limitations | Record the initial simplifications and unmeasured scope | Eight limitations recorded under Consequences |

Acceptance remained conditional: it established signed convergence between two
in-process endpoints, not a two-machine or wide-area readiness result.

The original `TestTwoNodeConvergence_InMemory` run inserted 1,000 events,
split 500/500 between two engines, and reached equal Merkle roots with all
1,000 entries on both sides in 2 sweep rounds, below the 10-round limit. The
recorded test duration was 7.48 seconds and the package test was race-clean.
With the 500/500 split, each peer initially sent approximately its own half of
the entries on every round. Re-shipping an entry that the receiver had just
joined could produce a payload-miss notice; the following sweep resolved it.
These notices were part of the oversend behavior rather than a convergence
failure.

This was an in-process test over real TLS 1.3 loopback sockets on one machine,
including kernel framing, signatures, and the production receive gates. It was
not a two-machine or wide-area measurement; that run was still pending when
the decision was accepted.
