# ADR-0037: Hybrid Post-Quantum Batch Signing

**Status:** Accepted

**Date:** 2026-08-11

## Context

[ADR-0036](0036_post_quantum_transport_readiness.md) added strict two-signature verification, but v1 envelopes still carried only Ed25519 signatures. Hybrid verification therefore rejected every classical v1 frame. A usable hybrid mode needed a signed batch format, public-key lookup for both algorithms, dispatch support on dialled and accepted connections, and acceptance telemetry.

Batching also bounds signing cost. Signing each delta separately would pay the ML-DSA-65 cost per delta instead of per batch.

## Decision

`HashBatchWireToFrame120` expands SHAKE256 over the marshaled `CRDTDeltaBatch` into a deterministic 120-byte pad. `SignCRDTFrame_Hybrid` signs that pad with both Ed25519 and ML-DSA-65 and returns a 64-byte signature, a 3,309-byte signature, and an error. `VerifyBatchHybrid` recomputes the pad and requires both signatures to verify. The receiver applies the original `batchWire`, never the pad.

`ShipBatchHybrid` emits a `HybridEnvelope` with the `SHYB` magic, version 1, origin identity and sequence, both signatures, an informational batch count, and the verbatim batch wire. Its 3,404-byte fixed header precedes the batch wire. Enabling `--hybrid-sign` forces the batch path even when `--batch-size <= 1`; only the origin signs new hybrid batches, while relays retain and republish origin-signed envelopes.

`Directory.RegisterPQ` stores ML-DSA-65 keys separately from classical keys. `LookupBoth` derives its `ok` result from the classical registration, so a PQ-only registration is still an identity miss. A classical registration without a PQ key returns a nil PQ key and fails hybrid verification.

`DispatchFrame` and the command's accept loop route batch, digest, hybrid, and relay frames to their respective handlers. `HandleHybridFrame` rejects immediately when `--hybrid-verify` is disabled, before decoding, charging a rate budget, or consulting the directory. After verification and application succeed, it reports `HybridFrameAccepted` and returns the number of joined deltas rather than trusting the header count.

The two flags default to false and have no cross-format fallback: hybrid senders require hybrid-verifying receivers, and strict hybrid receivers reject classical-only frames.

## Consequences

The default wire and receive behavior remain classical. A mixed deployment must provision both public keys and enable both options deliberately; enabling signing alone does not make deltas acceptable to a default receiver.

Each hybrid batch carries a 3,309-byte ML-DSA-65 signature, 51.7× the 64-byte Ed25519 signature. On the four-core loopback microbenchmark, signing costs about 585.8 µs and verification about 73.7 µs per batch. These are distinct operations and are not multi-node throughput measurements.

Deriving both keypairs from one seed preserves signature-forgery independence between the algorithms; it does not provide key-compromise independence if that seed is disclosed. Large-fleet bandwidth and signing overhead were not measured by this change.

[ADR-0040](0040_oob_peer_directory_provisioning.md) later adds peer-directory provisioning. [ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md) records the later boot-dial work; the original single-node runtime limitation is not a current description of mesh dialing.

## Evidence

The four-core `GOMAXPROCS=4` microbenchmarks over a 120-byte payload recorded 585,837 ns/op for ML-DSA-65 signing and 73,662 ns/op for verification. The signing figure is not a reused verification result.

The 2026-08-11 two-node in-process run converged a 1,000-event split in one round through hybrid frames, with `acceptA=5` and `acceptB=5`. `TestPQ_HybridE2EByteIdentity` compares Merkle roots for the same seeded workload over v1 and hybrid framing. `TestPQ_HybridOffIsByteIdentical` covers the default path, and `TestPQ_HybridSignVerifyOff` requires rejection when verification is disabled.

The identity tests cover signing, verification, pad determinism and length, invalid inputs, and directory semantics. The six wire tests in `pkg/attribution/wire_hybrid_test.go` cover layout, marshalling, classification, unsigned input, malformed input, and header length. `TestPQ_HybridDispatch4Way` and `TestPQ_HybridAcceptDispatchParity` cover both dispatch paths; `TestPQ_HybridRateGateOrdering` checks that disabled verification leaves the origin budget unchanged. `TestPQHybridCounter` checks registration of `supremum.hybrid.frame_accepted`.
