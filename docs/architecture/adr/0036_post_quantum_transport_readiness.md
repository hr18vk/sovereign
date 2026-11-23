# ADR-0036: Post-Quantum Transport and Hybrid Signature Verification

**Status:** Accepted

**Date:** 2026-08-11

## Context

The transport needed post-quantum key establishment without dropping peers that only support classical TLS. Signature verification needed a separate, opt-in contract: a frame must pass both Ed25519 and ML-DSA-65 verification, rather than treating either algorithm as a fallback for the other.

Go 1.24 and later advertise X25519MLKEM768 by default. Forcing `CurvePreferences` would remove the classical fallback, while leaving them unset lets the negotiated connection state show what actually happened.

## Decision

Leave `ServerConfig` and `ClientConfig` curve preferences unset. After an outbound handshake, `NegotiatedPQKEM` checks for `tls.X25519MLKEM768` (`CurveID=4588`) and `RecordHandshake` reports only that result. A peer that negotiates X25519 (`CurveID=29`) does not increment `PQHandshakeNegotiated`.

Promote `pkg/identity/pq_mldsa.go` from the `pq_preview` build tag into the default build. The `pqecobench` benchmark remains behind that tag. `VerifyCRDTFrame_Hybrid` accepts only a 120-byte message with a non-nil ML-DSA-65 public key, verifies Ed25519 first, and then verifies ML-DSA-65. Both must succeed.

Hybrid signature verification is controlled by `--hybrid-verify`, which defaults to false. The default receive path therefore retains classical `VerifyCRDTFrame`; strict hybrid mode rejects classical-only v1 frames because they have no ML-DSA-65 signature. [ADR-0037](0037_hybrid_pq_sign_wire.md) adds the corresponding signed batch envelope.

## Consequences

Capable Go peers negotiate the hybrid key exchange without a configuration change, but the engine does not force it on peers that lack support. Key exchange and signature policy remain independent: negotiating X25519MLKEM768 does not mean a frame carries an ML-DSA-65 signature.

The handshake counter is attached to `TLSConnections.Dial`. The server-side control-port accept path does not call this reporter, so the metric is not a count of all accepted handshakes.

Hybrid verification needs deployment-time ML-DSA-65 public keys as well as Ed25519 keys. [ADR-0040](0040_oob_peer_directory_provisioning.md) later adds file-based peer provisioning. The 3,309-byte ML-DSA-65 signature is 51.7× the 64-byte Ed25519 signature; hybrid framing must account for that cost separately from key exchange.

The loopback measurements below do not establish multi-node handshake overhead or a large-fleet signature budget.

## Evidence

A direct loopback probe on a four-core Graviton machine with Go 1.26.1 recorded `CurveID=4588` with the default configuration. Forcing X25519 or setting `GODEBUG=tlsmlkem=0` produced `CurveID=29`, providing a classical control for the assertion.

`BenchmarkMLDSA65_Verify_120B-4` measured 73,662 ns/op (about 73.7 µs), 0 B/op, and 0 allocs/op with `GOMAXPROCS=4`. This is a four-core verification microbenchmark over a 120-byte payload, not a signing or ingest measurement.

The eight transport tests in `pkg/transport/tls_pq_test.go` cover negotiation, the classical control, reporting, telemetry, outbound dialing, and a nil reporter. The six tests in `pkg/identity/hybrid_verify_test.go` cover dual-signature acceptance, corruption of either signature, a missing post-quantum key, the either-or negative control, and rejection of a 200-byte message. The 2026-08-11 race runs completed in 1.096 s for transport and 1.116 s for identity without a reported data race.
