# ADR-0006: TLS 1.3 transport and node binary

**Status:** Accepted  
**Date:** 2026-07-27

## Context

The engine had a δ-CRDT substrate, a receive gate stack, and socket transmit
helpers, but no network listener or node executable joined them into a running
system. The default peer transport needed encryption and peer authentication
without changing the CRDT or receive implementations.

The existing `TransmitHeapBuffer` and `SendPinnedHeap` helpers can attempt
`MSG_ZEROCOPY` on a plain socket. That property does not carry through TLS.
Go's `crypto/tls` `Conn.Write` copies plaintext into the record `outBuf`,
AEAD-encrypts into `c.out`, and then uses the ordinary TCP `netFD.Write`. That
write does not set `MSG_ZEROCOPY`, call `runtime.Pinner.Pin`, or perform the
copy-pin-sendmsg-unpin sequence used by `TransmitHeapBuffer`. The transport
decision therefore had to distinguish TLS framing from the zero-copy socket
path rather than describe both as zero-copy.

## Decision

Use TLS 1.3 over TCP with mutual certificate authentication as the default
peer transport. `ServerConfig` and `ClientConfig` set both version bounds to
`tls.VersionTLS13`; the server uses `tls.RequireAndVerifyClientCert`. There is
no plaintext or earlier-TLS fallback. `CipherSuites` remains unset because it
does not select TLS 1.3 suites.

`NewTLSTransport` loads the leaf keypair and CA pool and provides `Listen` and
`Dial`. Certificate callbacks serve the current leaf, allowing `Reload` to
replace it without closing the listener. `pkg/crypto/certgen.go` supplies an
in-process Ed25519 development CA and leaf generator; these keys are separate
from the keys used to sign CRDT frames.

The `cmd/sovereign-node` binary wires the existing engine, clock, admission,
identity, and receiver constructors. `NewDeltaCRDTEngine` takes a 16-byte node
ID, and `State().MerkleRoot()` exposes a 32-byte root.
`NewIngressHLCScalarCap` takes no epsilon argument: `maxDriftEpsilon` is the
compile-time constant 2000 µs, and the engine supplies `LogicalAdvancer` through
`AdvanceLamportTo`. `NewPeerBucket` and `NewDirectory` take no arguments. For
each accepted connection, `NewFrameReader` reassembles length-prefixed frames
and `Receiver.HandleFrame` applies the existing admission and verification
path. The initial binary exposes `/livecheck` over plain HTTP on
`--metrics-addr`; at acceptance it reports the node ID, peers, and TLS version,
not the Merkle root.

`TransmitTLSFrame` is deliberately `conn.Write(frame)`. It does not call
`TransmitHeapBuffer`, pin a buffer, or set `MSG_ZEROCOPY`. The acceptance record
gives AES-128-GCM encryption at approximately 30–50 ns per record on Graviton4
(Neoverse V2 ARMv8 AES instructions) and the record copy as
approximately 120B. The Ed25519 verification benchmark recorded 60.19 µs with
circl v1.6.4. Verification therefore cost more than 1000 times the upper end of
the record-encryption range, before accounting for the copy, making it the
dominant receive-path cost when this decision was made. That comparison explains
the copy-mode default; it does not make the TLS path zero-copy.

## Consequences

- A client cannot negotiate an earlier TLS version, and a client without a
  trusted certificate cannot complete the server handshake. Go selects the TLS 1.3
  AEAD suites, including `TLS_AES_128_GCM_SHA256` and
  `TLS_AES_256_GCM_SHA384`.
- The default transport copies through the TLS record layer. AF_XDP is not
  built in v0.2.0, and the node has no `--steering` flag. The build-tagged
  reuseport helper is separate from this default path.
- The development CA is not a production PKI.
  [ADR-0035](0035_pki_leaf_rotation_crl_revocation.md) later adds CA reload,
  CRL rejection, and opt-in certificate rotation;
  [ADR-0036](0036_post_quantum_transport_readiness.md) adds hybrid
  post-quantum key establishment.
- `/livecheck` is unauthenticated plain HTTP on the operational listener, not
  the peer data plane. [ADR-0008](0008_prometheus_metrics.md) later adds
  `/metrics` to that listener.
- The initial change accepts connections but does not implement dialing or
  gossip. [ADR-0007](0007_real_socket_mesh.md) supplies those paths.

## Evidence

- `TestTLSHandshake_13_Only` checks both version bounds, the negotiated
  protocol, and the negotiated AEAD cipher suite on a loopback connection.
- `TestTLSRejectWithoutClientCert` drives a server-side handshake failure when
  the client presents no certificate.
- `TestTLSCertRotation_SIGHUP` replaces the leaf on disk, calls `Reload`, and
  requires a subsequent dial to observe the new serial within five seconds.
- `TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild` preserves the heap
  pinning contract on the separate zero-copy helpers; `TransmitTLSFrame`
  contains no pinning call.

The original acceptance used build, vet, and race-enabled loopback tests on a
development machine with at least four cores. A 32-core `c8g.8xlarge` run was
conditional on provisioning; without that machine, the development-box results
were not presented as 32-core measurements. The TLS handshake and record-layer
checks had no 32-core-sensitive throughput claim. Acceptance did not measure
multi-machine throughput or a long-running soak.
