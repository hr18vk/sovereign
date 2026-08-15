# ADR-0036: Post-Quantum Transport Readiness — the X25519MLKEM768 KEM Proof + the Hybrid (Ed25519 + ML-DSA-65) Signature Verify (Day 31)

**Status:** ACCEPTED (Day 31, 2026-08-11) — the FOURTEENTH clean-chain fork (the THIRD security-gate wiring fork after Day-1 + Day-30; the FIRST Day-31 fork).

**Date:** 2026-08-11

**Tracks:** Phase-5 Track-5.3 (the post-quantum transport-readiness FIRST stake — the blueprint's "Post-quantum from day 1 — ML-DSA-65 + X25519MLKEM768" line).

## §1 — The Decision

PROVE the engine's TLS transport already negotiates the X25519MLKEM768 hybrid post-quantum key exchange (the M2 "prove, NOT enable" posture — Go 1.24+ advertises MLKEM by DEFAULT; the engine's `ServerConfig`/`ClientConfig` set NO `CurvePreferences`, so two Go 1.24+ peers ALREADY negotiate the PQ KEM), wire the operator-visible disclosure counter (`PQHandshakeNegotiated` — Law V; the counter fires IFF the negotiated `CurveID == tls.X25519MLKEM768`, NOT on every handshake), and wire the hybrid (Ed25519 + ML-DSA-65) signature verify (`VerifyCRDTFrame_Hybrid` — the M3 defense-in-depth BOTH-required gate). The fork is OPT-IN (the Day-19/23/29/30 opt-IN precedent): the `--hybrid-verify` flag (default false) keeps the receive path on the classical-only `VerifyCRDTFrame` seam — byte-identical Day-30; the PQ-KEM counter is wired unconditionally (the KEM disclosure is the transport seam, NOT the signature verify — the `SetRevocationReporter` precedent). NONE of the 5 FROZEN files are touched (the Day-29 `44f89527` streak is PRESERVED — NO streak-breaker this fork; the PQ layer is a transport/identity addition, NOT a CRDT/data-layer change).

**THE M2 FINDING (the load-bearing mid-audit discovery — EMPIRICALLY PROVEN).** The premise-audit M2 ("the engine ALREADY does the PQ KEM — prove it, do NOT enable it") was VERIFIED by direct probe on the 4c Graviton loopback box (Go 1.26.1, GOROOT `/home/ubuntu/go`):

- DEFAULT engine config (no `CurvePreferences` set) → `ConnectionState().CurveID == 4588` (`tls.X25519MLKEM768`) ✅
- forced `CurvePreferences=[X25519]` → `CurveID == 29` (`tls.X25519`) ✅ the BUG-INJECT control — the cut vanishes under the inject, PROVING the default is load-bearing (NOT a tautology; a misconfigured engine would PASS the assertion's negation)
- `GODEBUG=tlsmlkem=0` → `CurveID == 29` ✅ the stdlib knob — the KEM is the Go default, NOT an engine choice

The headline is PROVEN, NOT FORCED. A forced `CurvePreferences=[X25519MLKEM768]` would BREAK a peer lacking MLKEM (the Day-29 "opt-IN zero-value = byte-identical" precedent FORBIDS it). A peer that does NOT advertise MLKEM gets the classical X25519 fallback (the next default curve) — backward-compat preserved.

**THE M3 BOTH-GATE (defense-in-depth).** The hybrid verify checks BOTH the Ed25519 sig AND the ML-DSA-65 sig; EITHER failure rejects the frame. The BOTH gate (return `edOK && pqOK`) is the load-bearing choice — the EITHER-or gate (return `pqOK || edOK`) is the defense-in-depth INVERSION: a classical break (a future Ed25519 fault) would compromise a PQ frame under EITHER-or (the PQ sig still verifies, so the frame accepts), but under BOTH the classical break rejects. The `T-PQ-HYBRID-EITHER-OR-CONTROL` BUG-INJECT tooth PROVES the BOTH gate is load-bearing (the EITHER-or accepts a classical-corrupt+PQ-valid frame; the BOTH rejects; they DIFFER — the Day-25 dominant-divergence class Law 5).

**THE HONEST NOT-YET (the load-bearing scope disclosure).** The hybrid SIGN (a frame carries BOTH sigs) is a FUTURE fork — the CRDT-delta wire shape change. The v1 envelope carries ONLY the Ed25519 `originSig` (NO PQ sig) + the identity Directory does NOT yet carry a peer's ML-DSA-65 pubkey. So under `--hybrid-verify` a v1 frame is REJECTED (the STRICT mode: a hybrid verifier NEVER accepts a classical-only frame; BOTH is the contract). This is the honest `NOT-YET` — Day 31 wires the VERIFY + the KEM proof, NOT the production sign. The hybrid SIGN fork (the wire shape change that may or may not touch `pkg/sync/crdt.go` — the FROZEN-crdt.go seam is the HONEST question a future fork answers) is the NEXT PQ fork.

## §2 — The Premise Audit (M1–M7, verified BEFORE code)

- **M1 (substrate exists):** ✅ — `crypto/tls.X25519MLKEM768 = 4588` in `crypto/tls/common.go:153` (Go 1.26.1, GOROOT `/home/ubuntu/go`). `VerifyCRDTFrame_PostQuantum` exists at `pkg/identity/pq_mldsa.go:117` (build-tag `pq_preview`, 0 production callers pre-Day-31). `VerifyCRDTFrame` (classical) at `pkg/identity/verify.go:68`. The `filippo.io/mldsa` dep is PINNED (go.mod line 8 + go.sum lines 5-6, added by commit 6db6132 via `bridges.go`'s blank import).
- **M2 (already-does-PQ — prove, NOT enable):** ✅ EMPIRICALLY PROVEN — the 4c loopback probe (the `zz_m2_pq` probe, NOT committed): DEFAULT engine config → `CurveID == 4588` (X25519MLKEM768); forced `[X25519]` → `29` (BUG-INJECT control confirms load-bearing); `GODEBUG=tlsmlkem=0` → `29`. The engine ALREADY negotiates PQ. NO `CurvePreferences` set in `pkg/transport` pre-Day-31 (grep-verified ZERO references). The fork sets NO `CurvePreferences` — keeping the default is the load-bearing choice.
- **M3 (hybrid = BOTH-required):** ✅ — `VerifyCRDTFrame` (classical, circl Ed25519) + `VerifyCRDTFrame_PostQuantum` (PQ, ML-DSA-65) both exist; the hybrid wraps both, returns `classicalOK && pqOK` (short-circuit AND — the cheap classical gate first; the 73.7µs PQ verify runs only if classical passed). The `T-PQ-HYBRID-EITHER-OR-CONTROL` tooth PROVES the BOTH gate is load-bearing.
- **M4 (honest 4c bench):** ✅ RECORDED — `BenchmarkMLDSA65_Verify_120B-4` = **73,662 ns/op** (~73.7µs, UNDER the 100µs threshold), 0 B/op, 0 allocs/op, GOMAXPROCS=4, loopback Graviton. The 32c gate is carry-forward (AWS — the Day-29 "NO AWS this turn" precedent).
- **M5 (PQ orthogonal to mTLS/PKI/read-your-writes):** ✅ — the KEM is inside the TLS handshake; the Day-30 `VerifyPeerCertificate` (cert serial check) runs AFTER the KEM completes — the key exchange is independent of the cert rejection. Confirmed in runtime /verify (the read-your-writes seam is byte-identical post-Day-31; the mesh sweep is read-path-orthogonal).
- **M6 (counter — optional, shipping):** ✅ — `PQHandshakeNegotiated` (the 22nd distinct SSoT counter, a modeCounter — the gauge count STAYS 3) in all 4 registry sites (var block + `allCounters()` + `init()` + `rebuildCounters()` — the Day-21 fill discipline). The bridge auto-surfaces it (§0.f — ZERO bridge edit; the generic `Counters()` enumeration). The counter fires on the production dial seam (`transport.Dial → RecordHandshake`); a classical fallback does NOT fire it (PQ-KEM-only, NOT every handshake).
- **M7 (no FROZEN touch):** ✅ — all edits in `pkg/transport`, `pkg/identity`, `internal/telemetry`, `cmd/sovereign-node`, `pkg/receive` (the scope-gate re-pin), `pkg/mesh` (the SSoT re-pin), `internal/database` + `internal/telemetry` (the SSoT re-pins). NONE of the FROZEN 5 (`crdt.go`, `crdt_apply.go`, `schema.capnp`, `schema.capnp.go`, `envelope.go`) or the verifier-side 4. `crdt.go` stays `44f89527` (the Day-29 streak PRESERVED — NO streak-breaker this fork).

## §3 — The Wiring (the load-bearing artifacts)

**`pkg/identity/pq_mldsa.go`** (PROMOTED from `pq_preview` build tag to the DEFAULT build):
- The `//go:build pq_preview` tag is REMOVED — `VerifyCRDTFrame_PostQuantum` + `SignCRDTFrame_PostQuantum` + `GeneratePreviewKey65` are now reachable in the default build so the hybrid verify can call them. The Sign/Verify bodies are BYTE-IDENTICAL to the pre-Day-31 `pq_preview` form (build-tag-removal ONLY — the symbol call sites cite the SAME module-cache file:lines). The file's OWN pre-Day-31 doc named promotion as "a FUTURE track that removes this build tag" — Day 31 IS that track. The `pqecobench` bench STAYS under the `pq_preview` tag (a bench, not a production symbol — the tag there is the bench-gating choice, unaffected by the promotion).

**`pkg/identity/hybrid_verify.go`** (the M3 defense-in-depth BOTH-required gate — NEW):
- `VerifyCRDTFrame_Hybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, msg, edSig, pqSig []byte, ctx string) bool` — checks the classical `VerifyCRDTFrame` first (short-circuit AND), then the PQ `VerifyCRDTFrame_PostQuantum` (bridges the `[]byte` classical seam to the `[120]byte` PQ seam via `hybridFrameSize=120`; rejects if `len(msg) != 120` — the hybrid honors the STRICTER of the two seams). A nil `pqPub` is a hard reject (the STRICT mode — a hybrid verifier NEVER accepts a classical-only frame; BOTH is the contract).

**`pkg/transport/tls_pq.go`** (the M2 prove-NOT-enable KEM disclosure seam — NEW):
- `NegotiatedPQKEM(connState tls.ConnectionState) bool` — the load-bearing probe (reads `ConnectionState().CurveID == tls.X25519MLKEM768` AFTER the handshake completes — the negotiated KEM, NOT the configured preference). PROOF-ONLY: does NOT set `CurvePreferences`, does NOT enable the KEM, does NOT mutate any config.
- `PQKEMCurveID = tls.X25519MLKEM768` — the exported constant (4588) the assertion compares against (the Day-29 T-STRUCE-M2-CUT-Proven mold — the constant is the load-bearing comparison, NOT a magic number).
- `SetPQHandshakeReporter(fn func())` + `RecordHandshake(connState)` — the counter seam. `RecordHandshake` fires the reporter IFF `NegotiatedPQKEM(connState)` (PQ-KEM-only — a classical fallback does NOT fire; M6). Nil reporter = no-op (the `SetRevocationReporter` precedent).

**`pkg/transport/tls_transport.go`** (the `TLSConnections` struct + `Dial`):
- `pqHandshakeReporter func()` field on `TLSConnections` (packed alongside `revocationReporter` — the fieldalignment reorder packed the struct down, REDUCING the debt count 79→77).
- `Dial` fires `RecordHandshake(conn.ConnectionState())` before returning — `tls.Dial` drives the handshake synchronously, so `ConnectionState()` is populated when `Dial` returns. This is the production firing point for every peer the node dials (the mesh `PeerSet.Dial → ps.dialer.Dial → here`). The server-side control-port accept uses `tls.Listen` directly + does NOT fire the counter here (the client-side `ConnectionState` is the load-bearing proof the runtime /verify harness asserts; a server-side firing is a SEPARATE seam — disclosed §6).

**`pkg/receive/receiver.go`** (the hybrid-verify opt-IN gate):
- `hybridVerify bool` field on `Receiver` + `SetHybridVerify(enable bool)` setter (the `SetClockAdvanceRecorder` precedent — set once at construction before the accept loop starts).
- The two verify call sites (`HandleFrame :380` + `HandleBatchFrame :556`) gated: `r.hybridVerify` → `VerifyCRDTFrame_Hybrid(originPub, nil, verifiedInner, originSig[:], nil, "")` (the nil `pqPub` + nil `pqSig` is the honest NOT-YET — the v1 envelope carries no PQ sig + the Directory carries no PQ pubkey → the hybrid verify REJECTS under STRICT mode until the hybrid-SIGN fork ships); `else` → the classical `VerifyCRDTFrame` (byte-identical Day-30).

**`internal/telemetry/registry.go`** (the 22nd SSoT counter):
- `PQHandshakeNegotiated *Counter` — the 22nd distinct counter (a modeCounter — the gauge count STAYS 3), in all 4 sites (var block + `allCounters()` + `init()` + `rebuildCounters()` — the Day-21 fill discipline). Named `supremum.pki.pq_handshake_negotiated` (the bridge surfaces it as `supremum_pki_pq_handshake_negotiated`).

**`cmd/sovereign-node/main.go`** (the binary):
- `--hybrid-verify` (false default = byte-identical Day-30) — the opt-IN flag that switches the receive path to the hybrid verify.
- `tr.SetPQHandshakeReporter(telemetry.PQHandshakeNegotiated.Inc)` — wired unconditionally (the KEM disclosure is the transport seam, NOT the signature verify).
- `recv.SetHybridVerify(cfg.hybridVerifyEnable)` — the receive-path gate.

## §4 — The Teeth (14, byte-proven on loopback — NOT silicon)

**Transport (8) — `pkg/transport/tls_pq_test.go`:**

| Tooth | Proof |
|---|---|
| `T-PQ-KEM-NEGOTIATED` | The engine's DEFAULT config (no `CurvePreferences`) negotiates `X25519MLKEM768` (`CurveID=4588`) on a real loopback handshake — the M2 prove-NOT-enable posture (Go 1.24+ default inherited). |
| `T-PQ-KEM-CLASSICAL-CONTROL` | BUG-INJECT: forced `CurvePreferences=[X25519]` → `CurveID=29` (X25519). The cut vanishes under the inject — PROVES `T-PQ-KEM-NEGOTIATED` is load-bearing (NOT a tautology). |
| `T-PQ-KEM-RECORD-HANDSHAKE` | `tr.RecordHandshake` fires the reporter exactly once on a PQ (X25519MLKEM768) handshake. |
| `T-PQ-KEM-CLASSICAL-NO-FIRE` | BUG-INJECT: a classical (X25519) handshake does NOT fire the reporter (the counter is PQ-KEM-only — M6). |
| `T-PQ-COUNTER-FIRE` | `PQHandshakeNegotiated` increments on `.Inc()` (the direct-seam proof). |
| `T-PQ-SSOT-22` | `Counters()` carries 22 DISTINCT (21→22), the Day-31 PQ name present. |
| `T-PQ-DIAL-FIRES-COUNTER` | `tr.Dial` (the production dial seam) negotiated X25519MLKEM768 + fired the reporter (fires=1) — the end-to-end wiring proof. |
| `T-PQ-OFF-IS-BYTE-IDENTICAL` | A nil-reporter transport's `RecordHandshake` is a no-op (the opt-OUT default is byte-identical Day-30; the PQ seam is dormant until the operator binds the reporter). |

**Identity (6) — `pkg/identity/hybrid_verify_test.go`:**

| Tooth | Proof |
|---|---|
| `T-PQ-HYBRID-VERIFY-DUAL` | A frame signed under BOTH Ed25519 + ML-DSA-65 VERIFIES under the hybrid gate (the BOTH-required accept path). |
| `T-PQ-HYBRID-CLASSICAL-REJECT` | A frame whose Ed25519 sig is CORRUPTED is REJECTED (the classical break does NOT pass — defense-in-depth). |
| `T-PQ-HYBRID-PQ-REJECT` | A frame whose ML-DSA-65 sig is CORRUPTED is REJECTED (the PQ break does NOT pass). |
| `T-PQ-HYBRID-NIL-PQ-REJECT` | A frame with a nil PQ pubkey (the honest NOT-YET) is REJECTED (the STRICT mode — a hybrid verifier NEVER accepts a classical-only frame). |
| `T-PQ-HYBRID-EITHER-OR-CONTROL` | BUG-INJECT: the EITHER-or gate would ACCEPT a classical-corrupt+PQ-valid frame; the BOTH gate REJECTS; they DIFFER — PROVES the BOTH gate is load-bearing (the Day-25 Law 5 inversion the BOTH gate forbids). |
| `T-PQ-HYBRID-LEN-MISMATCH` | A 200-byte frame (len != 120) is REJECTED (the hybrid honors the STRICTER of the two seams — the classical tolerates any length, the PQ does not). |

## §5 — The Gate (§III, all GREEN)

- build / gofmt / vet clean (the `go vet ./...` 35 `unsafe.Pointer` warnings are ALL pre-existing in `pkg/sync` FROZEN CRDT, UNCHANGED 35→35).
- FROZEN 5-file md5 gate GREEN — **NONE of the 5 FROZEN files touched** (crdt.go `44f89527`, crdt_apply.go `ed9132a2`, schema.capnp `47d2796a`, schema.capnp.go `590af228`, envelope.go `b1beba1e` — the Day-29 `44f89527` streak is PRESERVED — NO streak-breaker this fork). Verifier-side 4 byte-UNCHANGED.
- Scope gate GREEN — the `track36ExemptDay31` map (the Day-31 edited set: `pq_mldsa.go`, `hybrid_verify.go`, `hybrid_verify_test.go`, `tls_pq.go`, `tls_pq_test.go`, `tls_transport.go`, `receiver.go`, `day29_stratified_test.go`); the per-track scope tooth EXEMPTS them with disclosure.
- fieldalignment: ZERO new debt (NET −2 — the `pqHandshakeReporter func()` field on `TLSConnections` packed the struct down, REDUCING the finding count 79→77; the pre-existing `nodeConfig` 344→296 + `Receiver` 72→56 findings are UNCHANGED pre-existing debt, NOT new).
- HotPath zero-alloc + GearHonesty GREEN (the PQ work is OFF the hot path — handshake-time + verify-time, not the 57M ops/s insert path; the 73.7µs PQ verify is the receive-path signature gate, NOT the origin write path).
- 14 Day-31 teeth GREEN (8 transport + 6 identity) under -race (transport 1.096s, identity 1.116s — no DATA RACE).
- Day-30 PKI teeth GREEN (the `day30_track30_test.go` SSoT re-pin 21→22 holds) + Day-29 STRUCE teeth GREEN (the `day29_stratified_test.go` T-STRUCE-SSOT-19 re-pin 21→22 holds).
- All per-package suites GREEN (`pkg/transport`, `pkg/identity`, `pkg/receive`, `pkg/mesh`, `internal/telemetry`, `internal/database`, `pkg/metrics`, `pkg/crypto`).
- RUNTIME /verify PASS 7/7 (harness `/tmp/verify_day31_run.go`, `D31_BINARY` env): the REAL Day-31 binary boots, the mTLS control-port handshake negotiates **X25519MLKEM768 (`ConnectionState.CurveID=4588`)** — the **M2 PQ-KEM proof on the REAL binary** (the runtime counterpart of the `T-PQ-KEM-NEGOTIATED` loopback tooth; the engine's `ServerConfig` sets NO `CurvePreferences`, so two Go 1.24+ peers ALREADY negotiate the PQ KEM — Day 31 PROVES, NOT enables), `/metrics` surfaces `supremum_pki_pq_handshake_negotiated` **PRESENT** (the §0.f auto-surface; ZERO bridge edit — the 22nd SSoT counter is registered + the bridge enumerates it WITHOUT a per-counter edit), the read-your-writes seam is byte-identical post-Day-31 (insert→IMMEDIATE query→200 + IMMEDIATE range→200 + RED→404 + `supremum_query_live_source_reads==3` + durable tier EMPTY). The counter's VALUE is 0 in the single-node run by CONSTRUCTION (NO mesh peer dials — the node log: "no peers configured (single-node); sweep idle"); the `tr.Dial → RecordHandshake` fire is proven by the `T-PQ-DIAL-FIRES-COUNTER` UNIT tooth (the loopback 2-socket mesh-dial proof), NOT the runtime harness — the runtime harness proves PRESENCE (the load-bearing auto-surface), NOT value. A 2-node mesh run (the silicon-scale carry-forward, §6) would fire the counter `>=1` via the mesh peer dials.

## §6 — Carry-forwards (disclosed, NOT closed)

- **The hybrid SIGN (a frame carries BOTH sigs)** — the CRDT-delta wire shape change. The v1 envelope carries ONLY the Ed25519 `originSig`; the hybrid SIGN needs a NEW wire shape (a frame carries BOTH the Ed25519 + ML-DSA-65 sigs) + the identity Directory carrying each peer's ML-DSA-65 pubkey (the peer-pubkey directory provisioning). The hybrid SIGN fork may or may not touch `pkg/sync/crdt.go` — the FROZEN-crdt.go seam is the HONEST question a future fork answers (the sign is at the origin write path, the verify is at the receive path; the wire shape is `pkg/attribution/envelope.go` — the FROZEN envelope.go is the load-bearing question). Until the hybrid SIGN ships, `--hybrid-verify` REJECTS every v1 frame (the STRICT mode — the honest NOT-YET this fork wires the verify for, NOT the sign).
- **The silicon-scale PQ-KEM gate** — the loopback teeth prove correctness + the 4c ML-DSA-65 verify bench (73.7µs) is RECORDED, but the 32c gate (the 100-node silicon run) is carry-forward (the Day-29 "NO AWS this turn" precedent). The silicon-scale handshake overhead of the PQ KEM on a 100-node mesh is a SEPARATE fork.
- **The server-side PQ counter firing** — `tr.Dial` fires the counter (client side); the server-side control-port accept uses `tls.Listen` directly + does NOT fire the counter here (the client-side `ConnectionState` is the load-bearing proof the runtime /verify harness asserts). A server-side firing seam (a custom accept wrapper that calls `RecordHandshake` on each accepted `*tls.Conn`) is a SEPARATE fork for a server-side PQ-KEM disclosure.
- **The PQ sig on the CRDT delta wire** — even after the hybrid SIGN fork, the 3309-byte ML-DSA-65 sig (vs the 64-byte Ed25519 sig — the 51.7× size cost, the pqecobench SIZE gate) is a per-frame wire-cost the hybrid SIGN fork must disclose (the saturation-limit class Day-29 disclosed for the IBLT digest applies to the PQ sig too — a wire-cost honest fork).
- **The operator-path peer-pubkey provisioning** — the identity Directory carries each peer's Ed25519 pubkey (registered out-of-band by the deploy — the Day-2 binary documents this honestly); the ML-DSA-65 pubkey provisioning is the SAME deploy-time step the hybrid SIGN fork adds.

## §7 — Enforced by

`pkg/transport/tls_pq_test.go` (the 8 transport teeth) + `pkg/identity/hybrid_verify_test.go` (the 6 identity teeth) + `TestGate_FrozenMD5`/`TestGate_UntouchedFrozenAndOutOfScope`/`TestGate_GearHonesty`/`TestBench_FrozenMD5` (the authoritative `pkg/receive` gate — crdt.go `44f89527` streak PRESERVED) + `TestTrack36_ScopeTooth` (the per-track scope gate, the `track36ExemptDay31` map) + `TestHotPathZeroAllocations` (the zero-alloc gate) + the re-pinned SSoT teeth (`day18`/`day21`/`day22`/`day24`/`day25`/`day26`/`day27`/`day29`/`day30` — all `wantDistinct` 21→22) + the `verify_day31` runtime harness (the REAL binary /metrics + read-your-writes + PQ-KEM proof).
