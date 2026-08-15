# ADR-0006: TLS 1.3 transport + production node binary (Day 1, default tier)
> Status: ACCEPTED     Date: 2026-07-27     Track: Phase 3 Day 1
> Supersedes: none     Superseded by: none

## 1. Context

Phase 3 Day 1 is the FIRST day the Sovereign Engine has an encrypted pipe and
a production binary. Before this track the engine had a FROZEN δ-CRDT
substrate (`pkg/sync/crdt.go`), a receive gate stack (`pkg/receive`), a
zero-copy egress boundary (`pkg/transport/transport.go`), and an eBPF
steering half (`pkg/transport/ebpf_reuseport.go`) — but no wire listener that
bound them into a running node, no TLS, and no compiled binary. Day 1 ships
the default transport tier (TCP+TLS 1.3) and the first binary,
`cmd/sovereign-node`, that constructs the FROZEN engine + the receive gate
stack and drives the length-prefixed frame reassembler into
`Receiver.HandleFrame` per accepted connection.

The Battle Plan ed.2.1 (`phase-03/WORLD_NO1_BATTLE_PLAN.md`, commit 2bb62b1)
§Day 1 is the scope baseline. The three architectural-review corrections
(REVISIONS APPLIED, ed.2.1) are in force; **C1** (the zero-copy boundary) is
load-bearing for Day 1 and is reproduced verbatim in §3 below.

## 2. Decision Drivers

- **D1: Encryption by default.** Every subsequent day's wire is encrypted
  BECAUSE Day 1 landed. Day 1 is the encryption ground; the default tier is
  TLS 1.3 over TCP, not plaintext.
- **D2: The FROZEN substrate is byte-locked.** Day 1 does NOT touch
  `crdt.go`, `crdt_apply.go`, the Cap'n Proto schema pair, `envelope.go`,
  `receiver.go`, or `ingress_epoll.go`. The new binary is a CALLER of the
  FROZEN constructors; it does not edit them. All seven FROZEN md5s are
  re-verified PRE and POST (§7).
- **D3: Honesty over fabrication.** The C1 zero-copy boundary (§3) is the
  tooth that keeps Day 1 honest. An honest "Day 1 ships COPY mode; zero-copy
  is Day 9" is the correct framing — physics, not compromise. Any prose that
  implies MSG_ZEROCOPY survives over TCP+TLS is a fabrication and resets the
  verdict to NO-GO.
- **D4: 1.3-only, mutual-TLS, no fallback.** The transport enforces
  `Min==Max==tls.VersionTLS13` and `ClientAuth: tls.RequireAndVerifyClientCert`.
  No TLS 1.2/1.1/1.0, no PSK-only, no downgrade. The gate is the tooth.

## 3. The C1 zero-copy boundary (verbatim, the load-bearing physics truth)

> MSG_ZEROCOPY does NOT transfer to TCP+TLS. `TransmitTLSFrame` over a
> `*tls.Conn` is a PLAIN `conn.Write`. Go's `crypto/tls` `Conn.Write` (the AEAD
> record layer) copies plaintext into the record `outBuf`, AEAD-encrypts into
> `c.out`, then the underlying TCP write is Go's ordinary `netFD.Write` -- which
> does NOT set `MSG_ZEROCOPY`, does NOT call `runtime.Pinner.Pin`, and does NOT
> go through the copy-pin-sendmsg-unpin dance. The zero-copy semantics of
> `TransmitHeapBuffer` (§3 of the Phase-3 architecture spec: make -> copy ->
> Pin -> sendmsg(MSG_ZEROCOPY) -> Unpin) live ONLY on the AF_XDP turbo tier
> (Day 9, the UMEM ring hands the NIC a userspace address with no sk_buff).
> The ed.2 phrasing "wraps TransmitHeapBuffer behind a TLS conn write" was
> INCOHERENT and is forbidden; Day 1 ships `TransmitTLSFrame` as a plain
> `conn.Write(frame)`. This is not a regression: AES-128-GCM is ~30-50 ns/record
> on Graviton4 (Neoverse V2 ARM v8 AES insns AESE/AESD/AESMC) and the copy is
> ~120B; both are dominated by the 60.19 us Ed25519 verify (PROVEN, circl
> v1.6.4, `pkg/identity/bench_test.go`) by >1000x. The zero-copy-vs-copy delta
> at the default tier is INVISIBLE against verify.

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
  DEV mesh CA; a production PKI is post-10-day (§8).
- **T4** `cmd/sovereign-node/main.go` (NEW cmd, the FIRST binary) — parses
  `--bind`, `--peers`, `--tls-cert`, `--tls-key`, `--tls-ca`, `--node-id`,
  `--metrics-addr`; loads `NewTLSTransport`; constructs the FROZEN engine +
  the receive gate stack; binds a TLS listener; serves `/livecheck` (plain
  HTTP) on `--metrics-addr`; SIGHUP -> `Reload()`.
- **T5** `pkg/transport/transport.go` (MODIFIED) — `TransmitTLSFrame` (the C1
  one-liner). `TransmitHeapBuffer` (line 70) and `SendPinnedHeap` (line 91)
  are UNTOUCHED.
- **T-A** this ADR + the `docs/architecture/adr/README.md` index line.

The eBPF `--steering` flag is Day 8 (opt-in); AF_XDP is Day 9 (the turbo
tier where zero-copy actually lives). The default tier has no build tags and
no capability gates.

## 5. Physics (AES-GCM vs Ed25519, the >1000x domination)

The default-tier per-record cost is AES-128-GCM at ~30-50 ns/record on
Graviton4 (Neoverse V2 ARM v8 AES insns `AESE`/`AESD`/`AESMC`) plus a ~120B
record copy. The receive-side gate stack is dominated by the 60.19 µs
Ed25519 verify (PROVEN, circl v1.6.4, `pkg/identity/bench_test.go`). The
zero-copy-vs-copy delta at the default tier is therefore INVISIBLE against
verify (>1000x). This is why an honest COPY-mode default is correct physics,
not a compromise: the copy is not the bottleneck, the verify is, and
zero-copy does not survive the TLS record layer regardless (C1).

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

## 7. Symbol Gate (grep-verified BEFORE wiring — UNVERIFIED was the default)

Every constructor the binary wires to was grep-verified against the real
package APIs this turn. The real signatures:

- `eng.NewDeltaCRDTEngine(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, error)` — `pkg/sync/crdt.go:244` (FROZEN).
- `clock.NewIngressHLCScalarCap(clock clock.WallClock, engine clock.LogicalAdvancer) *clock.IngressHLCScalarCap` — `pkg/clock/admission.go:72`. **NO epsilon arg**; CONSTRAINT Z (`maxDriftEpsilon = 2000` us, `admission.go:26`) is a compile-time constant, not a ctor param. The `DeltaCRDTEngine` satisfies `LogicalAdvancer` via its pointer-receiver `AdvanceLamportTo(uint64)` (`crdt.go:1639`); the engine IS the advancer arg.
- `admission.NewPeerBucket() *admission.PeerBucket` — `pkg/admission/ewma.go:150`. **Zero args** (the prompt's `NewPeerBucket(...)` was a placeholder; the real arity is empty).
- `identity.NewDirectory() *identity.Directory` — `pkg/identity/directory.go:47`. **Zero args**.
- `receive.NewReceiver(bucket *admission.PeerBucket, cap *clock.IngressHLCScalarCap, wallClock clock.WallClock, dir *identity.Directory, engine *eng.DeltaCRDTEngine, budget int64) *Receiver` — `pkg/receive/receiver.go:173` (12.2-locked).
- `receive.NewFrameReader(r io.Reader) *FrameReader` — `pkg/receive/receiver.go:474` (12.2-locked).
- `(*receive.FrameReader).ReadFrame() ([]byte, error)` — `pkg/receive/receiver.go:486` (12.2-locked).
- `(*receive.Receiver).HandleFrame(frameBytes []byte) AcceptVerdict` — `pkg/receive/receiver.go:253` (12.2-locked).
- `clock.NewSystemClock() *SystemClock` (implements `WallClock` via `PhysicalNowUSec() int64`) — `pkg/clock/clock.go:48`.

The gate-stack order at `receiver.go:244` is PROVEN and UNTOUCHED; the binary
is a CALLER, not an editor. The `eng.State() *HAMT` method (`crdt.go:1225`,
returning a `*HAMT` with `MerkleRoot() [32]byte` at `hamt.go:265`) is
available for the `/livecheck` merkle root (optional Day 1, load-bearing Day
2); Day 1 serves node_id + peers + tls_version and does not yet expose the
merkle root.

## 8. What this is NOT (the honesty section)

1. **The default tier is COPY mode by C1.** Zero-copy is Day 9 (AF_XDP UMEM)
   only. Day 1 does NOT claim zero-copy; `TransmitTLSFrame` is a plain
   `conn.Write`.
2. **The dev CA is NOT a production PKI.** `pkg/crypto/certgen.go` mints an
   in-process Ed25519 root + per-node leaves for the dev mesh. A production
   PKI (offline root, intermediate CAs, HSM-backed key custody, OCSP/CRL
   revocation, automated rotation) is post-10-day. CA rotation is a trust-root
   change that requires a transport restart; only the leaf rotates live via
   SIGHUP `Reload()`.
3. **The `/livecheck` control port is plain HTTP (ops debug), NOT the data
   plane.** Day 3 adds the TLS-or `/metrics` surface + a security review. Day
   1's `/livecheck` is intentionally unencrypted for ops liveness probing.
4. **Day 1 does NOT connect two machines.** The dial loop + gossip are Day 2.
   The accept loop runs and serves `/livecheck`, but carries NO mesh
   convergence yet. `--peers` is parsed and logged ("peers configured, dial
   loop pending Day 2"); it is NOT dialed this track.
5. **No long-soak.** Day 1 is a build+test+binary gate, not a soak run. The
   SIGHUP reload is asserted within 5s by `TestTLSCertRotation_SIGHUP`; a
   real-world reload latency > 5s would be an honest NEGATIVE recorded here
   (the test measured < 5s on the executor box).
6. **No AF_XDP / eBPF this tier.** AF_XDP is Day 9; the eBPF `--steering`
   flag is Day 8. The default transport is TLS over TCP with no build tags.
7. **No PQ promotion.** TLS 1.3 is GATED on PQ; Day 1 does NOT bundle a PQ
   re-bite. `crdt.go` is NOT re-opened (Track 9.0 is BLOCKED-BY-POLICY,
   ADR-0004).
8. **Pre-existing `trackN`/`phaseN`/`dayN` token sweep.** Per the NAMING
   block, a scan for legacy tokens inside `*.go`/`*.sh`/`*.tf` was executed
   this track. The hit set + the disposition is recorded in §9 (scope
   hygiene). The ONE FROZEN exception (`crdt.go:42
   phase25aDefaultShardCount`) stays UNRENAMED — FROZEN beats naming hygiene.

## 9. Scope hygiene + the naming-token sweep

**Scope (G01.g):** only NEW `pkg/crypto/`, NEW
`pkg/transport/tls_transport.go` + its test, the one-line `TransmitTLSFrame`
in `transport.go`, NEW `cmd/sovereign-node/`, this ADR + the README-index
line, and the `.log` artifact (§10). NOTHING else. No `pkg/mesh/`, no
`/metrics`, no `--steering`, no `--transport` flag. `crdt.go` etc. UNTOUCHED.
No PQ re-bite bundled.

**Naming-token sweep (G01.h item 5):** the scan
(`git grep -E '[Tt]rack[0-9]|[Pp]hase[0-9]|[Dd]ay[0-9]' -- '*.go' '*.sh' '*.tf'`)
was executed this track. The pre-existing Tier-2 hit set (~30 `.go` files + 2
infra `.sh`) is logged verbatim in the `.log` artifact and in the commit
message: `track36_crosscheck_test.go` / `TestTrack36_ScopeTooth`,
`track36_bench_test.go` / `BenchmarkTrack36_*`, `track36_v3_header_test.go` /
`TestTrack36_*`, `phase25a1_test.go`, the `phase25a-2l_test.go` family,
`phase25b1_release_test.go`, the `phase2i/2j/2l_test.go` family, the
`crdt_apply_*_test.go` `TestPhase2d`/`TestPhase2e` tokens, and 2 infra
`.sh` scripts. These are PRE-EXISTING legacy tokens, NOT minted by Day 1.
Day 1 MINTS only professional names going forward (`NewTLSTransport`,
`TransmitTLSFrame`, `TestTLSHandshake_13_Only`, `cmd/sovereign-node`,
`pkg/crypto/certgen.go`). The mechanical rename of the pre-existing hit set
is deferred to a dedicated hygiene track (a rename is a 0-behavior-change;
it does NOT earn a new capability claim and does NOT get its own ADR). The
ONE FROZEN exception (`crdt.go:42 phase25aDefaultShardCount`, inside the
FROZEN md5-locked file) stays UNRENAMED — FROZEN beats naming hygiene.

## 10. The silicon run (§4 conditional)

Day 1 is largely BOX-INDEPENDENT (TLS + the binary compile + race-clean on
any 4c+ box). The silicon run is CONDITIONAL: IF a Spot c8g.8xlarge is
provisioned this track, the `.log` records the gear header + the build gate
+ the three TLS test runs + the binary `file` output verbatim. IF silicon is
NOT provisioned, the gates run on the 4c+ executor box and the ADR records
that the 32c-silicon gear header is a Day-7 conditional (Day 1 has NO
32c-sensitive number — TLS handshake + AES-GCM are gear-light; the SCISSORS
rule does not elevate a 4c TLS test to a 32c claim). The track is DONE [x]
when G01.a–h pass on the box you have.

## 11. Relationships

- **R1:** Cites the Day-1 executor prompt §0 (C1, verbatim) and
  `phase-03/WORLD_NO1_BATTLE_PLAN.md` ed.2.1 §Day 1 (the scope baseline).
- **R2:** Builds on ADR-0001 (the ADR-tooth convention) and the FROZEN
  substrate it byte-locks (`pkg/sync/crdt.go` et al.).
- **R3:** Enforced structurally by `TestTLSHandshake_13_Only`,
  `TestTLSRejectWithoutClientCert`, `TestTLSCertRotation_SIGHUP`
  (`pkg/transport/tls_transport_test.go`) and the pre-existing
  `TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild` (the C1 tooth —
  `TransmitTLSFrame` contains no Pin, so the guard holds).
- **R4:** The §5 verdict STAYS CONDITIONAL-GO. Day 1 is NOT a §5
  verdict-blocker (it is NOT E1/E2/E3/E5). Day 1 does NOT flip §5, does NOT
  upgrade UNCONDITIONAL-GO, does NOT re-prove a §5 number. Day 1 is the
  encryption ground.
