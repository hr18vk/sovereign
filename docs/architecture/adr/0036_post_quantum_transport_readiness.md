# ADR-0036: Post-Quantum Transport Readiness — the X25519MLKEM768 KEM Proof + the Hybrid (Ed25519 + ML-DSA-65) Signature Verify

**Status:** Accepted (2026-08-11).

**Date:** 2026-08-11

This is the first step of the post-quantum transport-readiness work: prove the engine's TLS transport already negotiates the X25519MLKEM768 hybrid post-quantum key exchange, and wire the hybrid (Ed25519 + ML-DSA-65) signature verify.

## §1 — The Decision

Prove that the engine's TLS transport already negotiates the X25519MLKEM768 hybrid post-quantum key exchange (the "prove, not enable" posture — Go 1.24+ advertises MLKEM by default; the engine's `ServerConfig`/`ClientConfig` set no `CurvePreferences`, so two Go 1.24+ peers already negotiate the PQ KEM), wire the disclosure counter (`PQHandshakeNegotiated` — it fires iff the negotiated `CurveID == tls.X25519MLKEM768`, not on every handshake), and wire the hybrid (Ed25519 + ML-DSA-65) signature verify (`VerifyCRDTFrame_Hybrid` — the defense-in-depth both-required gate). The change is opt-in: the `--hybrid-verify` flag (default false) keeps the receive path on the classical-only `VerifyCRDTFrame` seam, byte-identical to prior behavior; the PQ-KEM counter is wired unconditionally (the KEM disclosure is a transport seam, not the signature verify — the `SetRevocationReporter` precedent). None of the merge-law/wire-schema files is touched (`crdt.go` is byte-identical); the PQ layer is a transport/identity addition, not a CRDT/data-layer change.

**The already-negotiates-PQ finding (verified by direct probe).** The premise that the engine already performs the PQ KEM — prove it, do not enable it — was verified by direct probe on a 4-core Graviton loopback box (Go 1.26.1):

- default engine config (no `CurvePreferences`) → `ConnectionState().CurveID == 4588` (`tls.X25519MLKEM768`)
- forced `CurvePreferences=[X25519]` → `CurveID == 29` (`tls.X25519`) — the bug-inject control: the signal vanishes under the inject, proving the default is load-bearing rather than a tautology (a misconfigured engine would pass the assertion's negation)
- `GODEBUG=tlsmlkem=0` → `CurveID == 29` — the stdlib knob: the KEM is the Go default, not an engine choice

The result is proven, not forced. Forcing `CurvePreferences=[X25519MLKEM768]` would break a peer lacking MLKEM. A peer that does not advertise MLKEM gets the classical X25519 fallback (the next default curve) — backward compatibility preserved.

**The both-gate (defense in depth).** The hybrid verify checks both the Ed25519 signature and the ML-DSA-65 signature; either failure rejects the frame. The both gate (return `edOK && pqOK`) is the load-bearing choice — the either-or gate (return `pqOK || edOK`) is the defense-in-depth inversion: a classical break (a future Ed25519 fault) would compromise a PQ frame under either-or (the PQ sig still verifies, so the frame accepts), but under the both gate the classical break rejects. The `TestPQ_HybridEitherOrControl` bug-inject tooth proves the both gate is load-bearing (the either-or accepts a classical-corrupt + PQ-valid frame; the both gate rejects; they differ).

**The honest not-yet (scope disclosure).** The hybrid sign (a frame carries both signatures) is future work — a CRDT-delta wire shape change. The v1 envelope carries only the Ed25519 `originSig` (no PQ sig), and the identity Directory does not yet carry a peer's ML-DSA-65 pubkey. So under `--hybrid-verify` a v1 frame is rejected (strict mode: a hybrid verifier never accepts a classical-only frame; both is the contract). This change wires the verify and the KEM proof, not the production sign. The hybrid sign change (the wire shape change that may or may not touch `pkg/sync/crdt.go` — whether the core merge-law file's seam is involved is the open question a future change answers) is the next PQ work.

## §2 — The Premise Audit (verified before code)

- **Substrate exists:** `crypto/tls.X25519MLKEM768 = 4588` in `crypto/tls/common.go:153` (Go 1.26.1). `VerifyCRDTFrame_PostQuantum` exists at `pkg/identity/pq_mldsa.go:117` (build tag `pq_preview`, zero production callers before this change). `VerifyCRDTFrame` (classical) at `pkg/identity/verify.go:68`. The `filippo.io/mldsa` dependency is pinned (go.mod + go.sum, added via `bridges.go`'s blank import).
- **Already-does-PQ (prove, not enable):** verified by the loopback probe: default engine config → `CurveID == 4588` (X25519MLKEM768); forced `[X25519]` → `29` (bug-inject control confirms load-bearing); `GODEBUG=tlsmlkem=0` → `29`. The engine already negotiates PQ. No `CurvePreferences` set in `pkg/transport` before this change (grep-verified zero references). The change sets no `CurvePreferences` — keeping the default is the load-bearing choice.
- **Hybrid = both-required:** `VerifyCRDTFrame` (classical, circl Ed25519) + `VerifyCRDTFrame_PostQuantum` (PQ, ML-DSA-65) both exist; the hybrid wraps both and returns `classicalOK && pqOK` (short-circuit AND — the cheap classical gate first; the 73.7µs PQ verify runs only if classical passed). The `TestPQ_HybridEitherOrControl` tooth proves the both gate is load-bearing.
- **Honest 4-core bench:** `BenchmarkMLDSA65_Verify_120B-4` = **73,662 ns/op** (~73.7µs, under the 100µs threshold), 0 B/op, 0 allocs/op, GOMAXPROCS=4, loopback Graviton. The 32-core gate is deferred (no multi-node AWS run for this change).
- **PQ orthogonal to mTLS/PKI/read-your-writes:** the KEM is inside the TLS handshake; the `VerifyPeerCertificate` cert-serial check runs after the KEM completes — the key exchange is independent of the cert rejection. Confirmed in the runtime verify (the read-your-writes seam is byte-identical after this change; the mesh sweep is read-path-orthogonal).
- **The counter (optional, shipping):** `PQHandshakeNegotiated` (a new telemetry counter, a modeCounter — the gauge count is unchanged at 3) in all four registry sites (var block + `allCounters()` + `init()` + `rebuildCounters()`). The bridge auto-surfaces it with zero bridge edit (the generic `Counters()` enumeration). The counter fires on the production dial seam (`transport.Dial → RecordHandshake`); a classical fallback does not fire it (PQ-KEM-only, not every handshake).
- **No core-file change:** all edits in `pkg/transport`, `pkg/identity`, `internal/telemetry`, `cmd/sovereign-node`, `pkg/receive`, `pkg/mesh`, `internal/database`. None of the merge-law/wire-schema files (`crdt.go`, `crdt_apply.go`, `schema.capnp`, `schema.capnp.go`, `envelope.go`) change; `crdt.go` is byte-identical.

## §3 — The Wiring (the load-bearing artifacts)

**`pkg/identity/pq_mldsa.go`** (promoted from the `pq_preview` build tag to the default build):
- The `//go:build pq_preview` tag is removed — `VerifyCRDTFrame_PostQuantum` + `SignCRDTFrame_PostQuantum` + `GeneratePreviewKey65` are now reachable in the default build so the hybrid verify can call them. The Sign/Verify bodies are byte-identical to the pre-promotion `pq_preview` form (build-tag removal only — the symbol call sites cite the same module-cache file:lines). The file's own earlier doc named promotion as "a future change that removes this build tag" — this change is that promotion. The PQ microbenchmark stays under the `pq_preview` tag (a bench, not a production symbol — the tag there is the bench-gating choice, unaffected by the promotion).

**`pkg/identity/hybrid_verify.go`** (the defense-in-depth both-required gate — new):
- `VerifyCRDTFrame_Hybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, msg, edSig, pqSig []byte, ctx string) bool` — checks the classical `VerifyCRDTFrame` first (short-circuit AND), then the PQ `VerifyCRDTFrame_PostQuantum` (bridges the `[]byte` classical seam to the `[120]byte` PQ seam via `hybridFrameSize=120`; rejects if `len(msg) != 120` — the hybrid honors the stricter of the two seams). A nil `pqPub` is a hard reject (strict mode — a hybrid verifier never accepts a classical-only frame; both is the contract).

**`pkg/transport/tls_pq.go`** (the prove-not-enable KEM disclosure seam — new):
- `NegotiatedPQKEM(connState tls.ConnectionState) bool` — the load-bearing probe (reads `ConnectionState().CurveID == tls.X25519MLKEM768` after the handshake completes — the negotiated KEM, not the configured preference). Proof-only: does not set `CurvePreferences`, does not enable the KEM, does not mutate any config.
- `PQKEMCurveID = tls.X25519MLKEM768` — the exported constant (4588) the assertion compares against (the constant is the load-bearing comparison, not a magic number).
- `SetPQHandshakeReporter(fn func())` + `RecordHandshake(connState)` — the counter seam. `RecordHandshake` fires the reporter iff `NegotiatedPQKEM(connState)` (PQ-KEM-only — a classical fallback does not fire). A nil reporter is a no-op (the `SetRevocationReporter` precedent).

**`pkg/transport/tls_transport.go`** (the `TLSConnections` struct + `Dial`):
- `pqHandshakeReporter func()` field on `TLSConnections` (packed alongside `revocationReporter` — the fieldalignment reorder packed the struct down, reducing the finding count 79→77).
- `Dial` fires `RecordHandshake(conn.ConnectionState())` before returning — `tls.Dial` drives the handshake synchronously, so `ConnectionState()` is populated when `Dial` returns. This is the production firing point for every peer the node dials (the mesh `PeerSet.Dial → ps.dialer.Dial → here`). The server-side control-port accept uses `tls.Listen` directly and does not fire the counter here (the client-side `ConnectionState` is the load-bearing proof the runtime verify asserts; a server-side firing is a separate seam — §6).

**`pkg/receive/receiver.go`** (the hybrid-verify opt-in gate):
- `hybridVerify bool` field on `Receiver` + `SetHybridVerify(enable bool)` setter (the `SetClockAdvanceRecorder` precedent — set once at construction before the accept loop starts).
- The two verify call sites (`HandleFrame` + `HandleBatchFrame`) gated: `r.hybridVerify` → `VerifyCRDTFrame_Hybrid(originPub, nil, verifiedInner, originSig[:], nil, "")` (the nil `pqPub` + nil `pqSig` is the honest not-yet — the v1 envelope carries no PQ sig and the Directory carries no PQ pubkey → the hybrid verify rejects under strict mode until the hybrid-sign change ships); `else` → the classical `VerifyCRDTFrame` (byte-identical to prior behavior).

**`internal/telemetry/registry.go`** (the new counter):
- `PQHandshakeNegotiated *Counter` — a new counter (a modeCounter — the gauge count is unchanged at 3), in all four sites (var block + `allCounters()` + `init()` + `rebuildCounters()`). Named `supremum.pki.pq_handshake_negotiated` (the bridge surfaces it as `supremum_pki_pq_handshake_negotiated`).

**`cmd/sovereign-node/main.go`** (the binary):
- `--hybrid-verify` (false default = byte-identical prior behavior) — the opt-in flag that switches the receive path to the hybrid verify.
- `tr.SetPQHandshakeReporter(telemetry.PQHandshakeNegotiated.Inc)` — wired unconditionally (the KEM disclosure is a transport seam, not the signature verify).
- `recv.SetHybridVerify(cfg.hybridVerifyEnable)` — the receive-path gate.

## §4 — The Teeth (14, byte-proven on loopback — not silicon)

**Transport (8) — `pkg/transport/tls_pq_test.go`:**

| Tooth | Proof |
|---|---|
| `TestPQ_KEMNegotiated` | The engine's default config (no `CurvePreferences`) negotiates `X25519MLKEM768` (`CurveID=4588`) on a real loopback handshake — the prove-not-enable posture (Go 1.24+ default inherited). |
| `TestPQ_KEMClassicalControl` | Bug-inject: forced `CurvePreferences=[X25519]` → `CurveID=29` (X25519). The cut vanishes under the inject — proves `TestPQ_KEMNegotiated` is load-bearing (not a tautology). |
| `TestPQ_KEMRecordHandshake` | `tr.RecordHandshake` fires the reporter exactly once on a PQ (X25519MLKEM768) handshake. |
| `TestPQ_KEMClassicalNoFire` | Bug-inject: a classical (X25519) handshake does not fire the reporter (the counter is PQ-KEM-only). |
| `TestPQ_CounterFire` | `PQHandshakeNegotiated` increments on `.Inc()` (the direct-seam proof). |
| `TestPQ_Counter22` | `Counters()` carries the new counter (the PQ counter name present). |
| `TestPQ_DialFiresCounter` | `tr.Dial` (the production dial seam) negotiated X25519MLKEM768 and fired the reporter (fires=1) — the end-to-end wiring proof. |
| `TestPQ_OffIsByteIdentical` | A nil-reporter transport's `RecordHandshake` is a no-op (the opt-out default is byte-identical to prior behavior; the PQ seam is dormant until the reporter is bound). |

**Identity (6) — `pkg/identity/hybrid_verify_test.go`:**

| Tooth | Proof |
|---|---|
| `TestPQ_HybridVerifyDual` | A frame signed under both Ed25519 + ML-DSA-65 verifies under the hybrid gate (the both-required accept path). |
| `TestPQ_HybridClassicalReject` | A frame whose Ed25519 sig is corrupted is rejected (the classical break does not pass — defense in depth). |
| `TestPQ_HybridPQReject` | A frame whose ML-DSA-65 sig is corrupted is rejected (the PQ break does not pass). |
| `TestPQ_HybridNilPQReject` | A frame with a nil PQ pubkey (the honest not-yet) is rejected (strict mode — a hybrid verifier never accepts a classical-only frame). |
| `TestPQ_HybridEitherOrControl` | Bug-inject: the either-or gate would accept a classical-corrupt + PQ-valid frame; the both gate rejects; they differ — proves the both gate is load-bearing. |
| `TestPQ_HybridLenMismatch` | A 200-byte frame (len != 120) is rejected (the hybrid honors the stricter of the two seams — the classical tolerates any length, the PQ does not). |

## §5 — Verification

- build / gofmt / vet clean (the `go vet ./...` 35 `unsafe.Pointer` warnings are all pre-existing in the `pkg/sync` CRDT, unchanged 35→35).
- None of the merge-law/wire-schema files touched — `crdt.go`, `crdt_apply.go`, `schema.capnp`, `schema.capnp.go`, `envelope.go` all byte-identical.
- fieldalignment: zero new debt (net −2 — the `pqHandshakeReporter func()` field on `TLSConnections` packed the struct down, reducing the finding count 79→77; the pre-existing `nodeConfig` + `Receiver` findings are unchanged pre-existing debt, not new).
- Hot-path zero-alloc + gear-honesty green (the PQ work is off the hot path — handshake-time + verify-time, not the insert path; the 73.7µs PQ verify is the receive-path signature gate, not the origin write path).
- 14 teeth green (8 transport + 6 identity) under -race (transport 1.096s, identity 1.116s — no data race).
- The PKI teeth and the stratified teeth stay green with the new counter registered.
- All per-package suites green (`pkg/transport`, `pkg/identity`, `pkg/receive`, `pkg/mesh`, `internal/telemetry`, `internal/database`, `pkg/metrics`, `pkg/crypto`).
- Runtime verify pass 7/7 (the harness drives the real binary): the real binary boots, the mTLS control-port handshake negotiates **X25519MLKEM768 (`ConnectionState.CurveID=4588`)** — the PQ-KEM proof on the real binary (the runtime counterpart of the `TestPQ_KEMNegotiated` loopback tooth; the engine's `ServerConfig` sets no `CurvePreferences`, so two Go 1.24+ peers already negotiate the PQ KEM — this change proves, not enables), `/metrics` surfaces `supremum_pki_pq_handshake_negotiated` present (the auto-surface; zero bridge edit — the new counter is registered and the bridge enumerates it without a per-counter edit), and the read-your-writes seam is byte-identical after this change (insert → immediate query → 200 + immediate range → 200 + RED → 404 + `supremum_query_live_source_reads==3` + durable tier empty). The counter's value is 0 in the single-node run by construction (no mesh peer dials — the node log: "no peers configured (single-node); sweep idle"); the `tr.Dial → RecordHandshake` fire is proven by the `TestPQ_DialFiresCounter` unit tooth (the loopback two-socket mesh-dial proof), not the runtime harness — the runtime harness proves presence (the load-bearing auto-surface), not value. A two-node mesh run (the silicon-scale future work, §6) would fire the counter `>=1` via the mesh peer dials.

## §6 — Known Limitations / Future Work

- **The hybrid sign (a frame carries both signatures)** — the CRDT-delta wire shape change. The v1 envelope carries only the Ed25519 `originSig`; the hybrid sign needs a new wire shape (a frame carries both the Ed25519 + ML-DSA-65 sigs) plus the identity Directory carrying each peer's ML-DSA-65 pubkey (the peer-pubkey directory provisioning). The hybrid sign change may or may not touch `pkg/sync/crdt.go` — whether the core merge-law file's seam is involved is the open question a future change answers (the sign is at the origin write path, the verify is at the receive path; the wire shape is `pkg/attribution/envelope.go` — that core wire-schema file is the load-bearing question). Until the hybrid sign ships, `--hybrid-verify` rejects every v1 frame (strict mode — the honest not-yet: this change wires the verify, not the sign).
- **The silicon-scale PQ-KEM gate** — the loopback teeth prove correctness and the 4-core ML-DSA-65 verify bench (73.7µs) is recorded, but the 32-core gate (the 100-node silicon run) is deferred. The silicon-scale handshake overhead of the PQ KEM on a 100-node mesh is separate work.
- **The server-side PQ counter firing** — `tr.Dial` fires the counter (client side); the server-side control-port accept uses `tls.Listen` directly and does not fire the counter here (the client-side `ConnectionState` is the load-bearing proof the runtime verify asserts). A server-side firing seam (a custom accept wrapper that calls `RecordHandshake` on each accepted `*tls.Conn`) is separate work for a server-side PQ-KEM disclosure.
- **The PQ sig on the CRDT delta wire** — even after the hybrid sign change, the 3309-byte ML-DSA-65 sig (vs the 64-byte Ed25519 sig — the 51.7× size cost) is a per-frame wire cost the hybrid sign change must disclose (the saturation-limit class already disclosed for the IBLT digest applies to the PQ sig too).
- **The deployment-time peer-pubkey provisioning** — the identity Directory carries each peer's Ed25519 pubkey (registered out-of-band at deploy time, as the node binary documents); the ML-DSA-65 pubkey provisioning is the same deploy-time step the hybrid sign change adds.

## §7 — Enforced by

`pkg/transport/tls_pq_test.go` (the 8 transport teeth) + `pkg/identity/hybrid_verify_test.go` (the 6 identity teeth) + `TestHotPathZeroAllocations` (the zero-alloc gate) + the distinct-counter teeth across the affected packages + the runtime verify harness (the real binary `/metrics` + read-your-writes + PQ-KEM proof).
