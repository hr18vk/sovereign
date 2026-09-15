# ADR-0006: TLS 1.3 transport + production node binary (default tier)
> Status: ACCEPTED     Date: 2026-07-27
> Supersedes: none     Superseded by: none

## 1. Context

This is the first change that gives the engine an encrypted pipe and a
production binary. Before it, the engine had a frozen δ-CRDT substrate
(`pkg/sync/crdt.go` — deliberately not edited, because the CRDT merge law is
load-bearing), a receive gate stack (`pkg/receive`), a zero-copy egress
boundary (`pkg/transport/transport.go`), and an eBPF steering half
(`pkg/transport/ebpf_reuseport.go`) — but no wire listener that bound them
into a running node, no TLS, and no compiled binary. This change ships the
default transport tier (TCP+TLS 1.3) and the first binary,
`cmd/sovereign-node`, that constructs the frozen engine + the receive gate
stack and drives the length-prefixed frame reassembler into
`Receiver.HandleFrame` per accepted connection.

The zero-copy boundary is load-bearing for this change and is reproduced
verbatim in §3 below.

## 2. Decision Drivers

- **D1: Encryption by default.** Every subsequent wire is encrypted because
  this change lands first; it is the encryption ground. The default tier is
  TLS 1.3 over TCP, not plaintext.
- **D2: The frozen substrate is not edited.** This change does NOT touch
  `crdt.go`, `crdt_apply.go`, the Cap'n Proto schema pair, `envelope.go`,
  `receiver.go`, or `ingress_epoll.go`. The new binary is a CALLER of the
  frozen constructors; it does not edit them.
- **D3: Honesty over fabrication.** The zero-copy boundary (§3) is the
  guard that keeps this change honest. An honest "the default tier ships COPY
  mode; zero-copy arrives with the AF_XDP tier" is the correct framing —
  physics, not compromise. Any prose that implies MSG_ZEROCOPY survives over
  TCP+TLS is a fabrication.
- **D4: 1.3-only, mutual-TLS, no fallback.** The transport enforces
  `Min==Max==tls.VersionTLS13` and `ClientAuth: tls.RequireAndVerifyClientCert`.
  No TLS 1.2/1.1/1.0, no PSK-only, no downgrade. The gate is the tooth.

## 3. The zero-copy boundary (verbatim, the load-bearing physics truth)

> MSG_ZEROCOPY does NOT transfer to TCP+TLS. `TransmitTLSFrame` over a
> `*tls.Conn` is a PLAIN `conn.Write`. Go's `crypto/tls` `Conn.Write` (the AEAD
> record layer) copies plaintext into the record `outBuf`, AEAD-encrypts into
> `c.out`, then the underlying TCP write is Go's ordinary `netFD.Write` -- which
> does NOT set `MSG_ZEROCOPY`, does NOT call `runtime.Pinner.Pin`, and does NOT
> go through the copy-pin-sendmsg-unpin dance. The zero-copy semantics of
> `TransmitHeapBuffer` (make -> copy -> Pin -> sendmsg(MSG_ZEROCOPY) -> Unpin)
> live ONLY on the AF_XDP turbo tier (the UMEM ring hands the NIC a userspace
> address with no sk_buff). The earlier phrasing "wraps TransmitHeapBuffer
> behind a TLS conn write" was INCOHERENT and is forbidden; the default tier
> ships `TransmitTLSFrame` as a plain `conn.Write(frame)`. This is not a
> regression: AES-128-GCM is ~30-50 ns/record on Graviton4 (Neoverse V2 ARM v8
> AES insns AESE/AESD/AESMC) and the copy is ~120B; both are dominated by the
> 60.19 us Ed25519 verify (PROVEN, circl v1.6.4, `pkg/identity/bench_test.go`)
> by >1000x. The zero-copy-vs-copy delta at the default tier is INVISIBLE
> against verify.

`TransmitTLSFrame` (`pkg/transport/transport.go`) is therefore a one-liner:
`return conn.Write(frame)`. It does NOT call `TransmitHeapBuffer`, does NOT
Pin, and does NOT set MSG_ZEROCOPY. The source-guard test
`TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild` (which scans
`transport.go` for forbidden `.Pin(` calls) still PASSES — the new function is
invisible to the `.Pin(` detector because it contains no Pin.

## 4. Decision (Option C, TCP+TLS default tier)

**ACCEPT Option C.** The default transport tier is TLS 1.3 over TCP, shipped
as:

- **T1** `pkg/transport/tls_transport.go` (NEW) — `NewTLSTransport`,
  `ServerConfig`, `ClientConfig`, `Reload`, `Listen`, `Dial`. Min==Max==1.3;
  `RequireAndVerifyClientCert`; live leaf via `GetCertificate` /
  `GetClientCertificate` (the SIGHUP live-reload seam). `CipherSuites` is NOT
  set (a documented no-op + footgun for a 1.3-only config; the AEAD suites
  auto-negotiate).
- **T2** `pkg/transport/tls_transport_test.go` (NEW) — `TestTLSHandshake_13_Only`
  (Version==1.3 + cipher in the AEAD set), `TestTLSRejectWithoutClientCert`
  (mTLS reject, asserted on the deterministic server-side Handshake error),
  `TestTLSCertRotation_SIGHUP` (new leaf live within 5s via `Reload()`).
- **T3** `pkg/crypto/certgen.go` (NEW pkg `crypto`) — dev-mesh CA + leaf
  generator. Ed25519 keys (`crypto/ed25519.GenerateKey` +
  `x509.CreateCertificate` with `PublicKeyAlgorithm: x509.Ed25519`). This is a
  DEV mesh CA; a production PKI is deferred future work (§8).
- **T4** `cmd/sovereign-node/main.go` (NEW cmd, the FIRST binary) — parses
  `--bind`, `--peers`, `--tls-cert`, `--tls-key`, `--tls-ca`, `--node-id`,
  `--metrics-addr`; loads `NewTLSTransport`; constructs the frozen engine +
  the receive gate stack; binds a TLS listener; serves `/livecheck` (plain
  HTTP) on `--metrics-addr`; SIGHUP -> `Reload()`.
- **T5** `pkg/transport/transport.go` (MODIFIED) — `TransmitTLSFrame` (the
  §3 one-liner). `TransmitHeapBuffer` (line 70) and `SendPinnedHeap` (line 91)
  are UNTOUCHED.
- **T-A** this ADR + the `docs/architecture/adr/README.md` index line.

The eBPF `--steering` flag and the AF_XDP turbo tier (where zero-copy actually
lives) are later, opt-in work. The default tier has no build tags and no
capability gates.

## 5. Physics (AES-GCM vs Ed25519, the >1000x domination)

The default-tier per-record cost is AES-128-GCM at ~30-50 ns/record on
Graviton4 (Neoverse V2 ARM v8 AES insns `AESE`/`AESD`/`AESMC`) plus a ~120B
record copy. The receive-side gate stack is dominated by the 60.19 µs
Ed25519 verify (PROVEN, circl v1.6.4, `pkg/identity/bench_test.go`). The
zero-copy-vs-copy delta at the default tier is therefore INVISIBLE against
verify (>1000x). This is why an honest COPY-mode default is correct physics,
not a compromise: the copy is not the bottleneck, the verify is, and
zero-copy does not survive the TLS record layer regardless (§3).

## 6. The 1.3-only + mTLS + no-fallback gate

- **1.3-only:** `MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13`.
  A 1.2/1.1/1.0 negotiation is impossible when Min==Max==1.3.
  `TestTLSHandshake_13_Only` asserts `conn.ConnectionState().Version ==
  tls.VersionTLS13` and the cipher is in
  `{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}`.
- **mTLS:** `ClientAuth: tls.RequireAndVerifyClientCert` in the ServerConfig
  bytes (grep-verified). `TestTLSRejectWithoutClientCert` asserts a no-cert
  dial FAILS the handshake (the deterministic server-side Handshake error).
- **no-fallback:** no PSK-only, no downgrade. The 1.3-only Min==Max config is
  the tooth; there is no fallback path to weaken.

## 7. Symbol Gate (grep-verified before wiring)

Every constructor the binary wires to was grep-verified against the real
package APIs before any wiring was written. The real signatures:

- `eng.NewDeltaCRDTEngine(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, error)` — `pkg/sync/crdt.go:244` (frozen).
- `clock.NewIngressHLCScalarCap(clock clock.WallClock, engine clock.LogicalAdvancer) *clock.IngressHLCScalarCap` — `pkg/clock/admission.go:72`. **NO epsilon arg**; CONSTRAINT Z (`maxDriftEpsilon = 2000` us, `admission.go:26`) is a compile-time constant, not a ctor param. The `DeltaCRDTEngine` satisfies `LogicalAdvancer` via its pointer-receiver `AdvanceLamportTo(uint64)` (`crdt.go:1639`); the engine IS the advancer arg.
- `admission.NewPeerBucket() *admission.PeerBucket` — `pkg/admission/ewma.go:150`. **Zero args** (an earlier draft's `NewPeerBucket(...)` was a placeholder; the real arity is empty).
- `identity.NewDirectory() *identity.Directory` — `pkg/identity/directory.go:47`. **Zero args**.
- `receive.NewReceiver(bucket *admission.PeerBucket, cap *clock.IngressHLCScalarCap, wallClock clock.WallClock, dir *identity.Directory, engine *eng.DeltaCRDTEngine, budget int64) *Receiver` — `pkg/receive/receiver.go:173` (API-locked).
- `receive.NewFrameReader(r io.Reader) *FrameReader` — `pkg/receive/receiver.go:474` (API-locked).
- `(*receive.FrameReader).ReadFrame() ([]byte, error)` — `pkg/receive/receiver.go:486` (API-locked).
- `(*receive.Receiver).HandleFrame(frameBytes []byte) AcceptVerdict` — `pkg/receive/receiver.go:253` (API-locked).
- `clock.NewSystemClock() *SystemClock` (implements `WallClock` via `PhysicalNowUSec() int64`) — `pkg/clock/clock.go:48`.

The gate-stack order at `receiver.go:244` is PROVEN and UNTOUCHED; the binary
is a CALLER, not an editor. The `eng.State() *HAMT` method (`crdt.go:1225`,
returning a `*HAMT` with `MerkleRoot() [32]byte` at `hamt.go:265`) is
available for the `/livecheck` merkle root (optional in this change,
load-bearing for the follow-up dial work); this change serves node_id +
peers + tls_version and does not yet expose the merkle root.

## 8. What this is NOT (the honesty section)

1. **The default tier is COPY mode (§3).** Zero-copy is the later AF_XDP
   UMEM tier only. This change does NOT claim zero-copy; `TransmitTLSFrame`
   is a plain `conn.Write`.
2. **The dev CA is NOT a production PKI.** `pkg/crypto/certgen.go` mints an
   in-process Ed25519 root + per-node leaves for the dev mesh. A production
   PKI (offline root, intermediate CAs, HSM-backed key custody, OCSP/CRL
   revocation, automated rotation) is deferred future work. CA rotation is a
   trust-root change that requires a transport restart; only the leaf rotates
   live via SIGHUP `Reload()`.
3. **The `/livecheck` control port is plain HTTP (ops debug), NOT the data
   plane.** A TLS-protected `/metrics` surface + a security review are
   follow-up work. This change's `/livecheck` is intentionally unencrypted
   for ops liveness probing.
4. **This change does NOT connect two machines.** The dial loop + gossip are
   follow-up work. The accept loop runs and serves `/livecheck`, but carries
   NO mesh convergence yet. `--peers` is parsed and logged ("peers
   configured, dial loop pending"); it is NOT dialed in this change.
5. **No long-soak.** This change is a build+test+binary gate, not a soak run.
   The SIGHUP reload is asserted within 5s by `TestTLSCertRotation_SIGHUP`; a
   real-world reload latency > 5s would be an honest NEGATIVE recorded here
   (the test measured < 5s on the development box).
6. **No AF_XDP / eBPF this tier.** AF_XDP and the eBPF `--steering` flag are
   later tiers. The default transport is TLS over TCP with no build tags.
7. **No PQ promotion.** TLS 1.3 is the prerequisite for the post-quantum
   work; this change does NOT bundle a PQ change. `crdt.go` is NOT re-opened
   (see ADR-0004).

## 9. Scope hygiene

**Scope:** only NEW `pkg/crypto/`, NEW `pkg/transport/tls_transport.go` + its
test, the one-line `TransmitTLSFrame` in `transport.go`, NEW
`cmd/sovereign-node/`, this ADR + the README-index line, and the run-log
artifact (§10). NOTHING else. No `pkg/mesh/`, no `/metrics`, no `--steering`,
no `--transport` flag. `crdt.go` etc. UNTOUCHED. No PQ change bundled.

This change introduces only professional names (`NewTLSTransport`,
`TransmitTLSFrame`, `TestTLSHandshake_13_Only`, `cmd/sovereign-node`,
`pkg/crypto/certgen.go`).

## 10. The silicon run (conditional)

This change is largely box-independent (TLS + the binary compile + race-clean
on any 4c+ box). The 32-core silicon run is conditional: if a Spot
c8g.8xlarge is provisioned, the `.log` records the gear header + the build
gate + the three TLS test runs + the binary `file` output verbatim. If
silicon is not provisioned, the gates run on the 4c+ development box, and the
32c gear header is deferred — this change has NO 32c-sensitive number (TLS
handshake + AES-GCM are gear-light), so a 4c TLS test is not elevated to a
32c claim.

## 11. Relationships

- Builds on ADR-0001 (the ADR convention) and the frozen substrate it leaves
  untouched (`pkg/sync/crdt.go` et al.).
- Enforced structurally by `TestTLSHandshake_13_Only`,
  `TestTLSRejectWithoutClientCert`, `TestTLSCertRotation_SIGHUP`
  (`pkg/transport/tls_transport_test.go`) and the pre-existing
  `TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild` (the §3 guard —
  `TransmitTLSFrame` contains no Pin, so the guard holds).
- This change does not alter any prior performance verdict and does not
  re-prove a throughput number; it is the encryption ground.
