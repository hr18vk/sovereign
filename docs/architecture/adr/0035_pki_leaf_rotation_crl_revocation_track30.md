# ADR-0035: PKI Leaf Rotation + CRL Revocation — the Phase-5 Track-5.2 FIRST Stake (Day 30)

**Status:** ACCEPTED (Day 30, 2026-08-11) — the THIRTEENTH clean-chain fork (the SECOND security-gate wiring fork after Day-1; the FIRST Day-30 fork).

**Date:** 2026-08-11

**Tracks:** Phase-5 Track-5.2 (the PKI leaf-rotation + CRL revocation FIRST stake).

## §1 — The Decision

WIRE the dormant blueprint Track-5.2 security gate on the TLS transport: a node presenting an EXPIRED OR REVOKED leaf is REJECTED at the TLS handshake (the BOTH-sides mTLS enforcement), AND a zero-downtime leaf cert rotation every 30 days (the automated rotation trigger). The gate was DORMANT — Day-1 shipped the TLS 1.3 mTLS pipe + the SIGHUP leaf-reload seam, but NO CRL consult (a revoked serial was accepted until the leaf expired) + NO automated rotation (an operator had to SIGHUP before the 30-day window closed, or the cert expired mid-mesh). Day 30 closes the dormancy with the CRL revocation consult + the CA/CRL hot-reload (the M3 triple) + the rotation manager (the automated trigger), all OPT-IN (the Day-19/23/29 opt-IN precedent; the DEFAULTS leave the transport byte-identical Day-29).

**THE M2(a) FINDING (the load-bearing mid-audit discovery).** The premise-audit M2(a) ("an EXPIRED leaf is rejected by default Go-tls chain validation — the EXPIRED claw is met by the stdlib, NOT new work this fork claims") was VERIFIED by direct probe (loopback, the repo's `pkg/crypto` certgen + `tls.Dial`): an expired CLIENT leaf surfaces `remote error: tls: bad certificate` on the SERVER side + `failed to verify certificate: x509: certificate has expired` on the CLIENT side, BOTH with AND without `VerifyPeerCertificate` wired — the callback runs AFTER normal verification ("If normal verification fails then the handshake will abort before considering this callback" — the Go docs), so an expired leaf never REACHES the CRL consult. The EXPIRED claw is genuinely free (inherited); the REVOKED claw is the load-bearing new work (the CRL consult the callback performs). The tooth `T-PKI-EXPIRED-REJECTED` proves the inheritance; it is NOT a claim of new work.

**THE M3 TRIPLE.** A SIGHUP reloads the FULL triple — leaf, CA pool, CRL — NOT just the leaf (the pre-Day-30 `:126` behavior). Each reload is INDEPENDENT + atomic under the transport's RWMutex; a FAILED reload of one surface leaves the stale version in place (the honest-negative posture — the transport NEVER trust-degrades OR revocation-degrades on a failed reload). The leaf reload stays FIRST (the byte-identical pre-Day-30 seam + the existing `TestTLSCertRotation_SIGHUP` contract). The CA reload uses `GetConfigForClient` (the ONLY dynamic-CA hook Go's `tls.Config` offers — `ClientCAs`/`RootCAs` are static fields; `GetCertificate` is the leaf's dynamic hook, but there is NO CA equivalent, so the per-connection config returned by `GetConfigForClient` reads the live pool under the RLock). The CRL reload swaps the `revokedSerials` map.

## §2 — The Premise Audit (M1–M6, verified BEFORE code)

- **M1 (gate dormant + Day-1 substrate present):** ✅ — Day-1 shipped the TLS 1.3 mTLS pipe (`RequireAndVerifyClientCert` + `GetCertificate` + the SIGHUP `Reload` seam). The CRL consult + the CA/CRL hot-reload + the rotation manager were absent (dormant). The `ServerConfig`/`ClientConfig` had NO `VerifyPeerCertificate`; the only reload was `Reload` (leaf only).
- **M2(a) (EXPIRED claw inherited):** ✅ VERIFIED by probe — an expired leaf is rejected by normal chain validation BEFORE the CRL callback. The `VerifyPeerCertificate` callback does NOT skip normal verification (Go docs + probe: both with + without the callback, the expired leaf is rejected). The EXPIRED claw is FREE; `T-PKI-EXPIRED-REJECTED` proves the inheritance, NOT a new-work claim.
- **M2(b) (CRL is serial-scoped, NOT CA-scoped):** ✅ — the CRL lists SERIALS, not CA identity. Revoking one leaf does NOT revoke the CA's other leaves. `T-PKI-SIBLING-NOT-REVOKED` proves a sibling leaf NOT in the CRL PASSES (the honest scope: a compromised-serial reject does NOT take down the whole mesh).
- **M3 (triple hot-reload, independent + atomic):** ✅ — the SIGHUP handler reloads leaf + CA + CRL in sequence, each under the RWMutex, each independent (a failed leaf reload does NOT block a CA or CRL update). `T-PKI-CA-HOT-RELOAD` + `T-PKI-CRL-HOT-RELOAD` prove the live swap. The CA swap uses `GetConfigForClient` (the dynamic-CA hook); the CRL swap swaps the `revokedSerials` map.
- **M4 (operator-path rotation needs an out-of-process minter):** ✅ DISCLOSED — the `--selftest` path mints an in-process CA (`mintSelftestCerts` returns the `*MeshCA`), so `buildRotationMinter` mints new leaves via the SAME CA. The operator path (NOT `--selftest`) loads PEMs from disk + has NO in-process CA → `--cert-rotation-enable` on the operator path returns a clear error ("requires an in-process CA — supply an out-of-process minter via `transport.RotationMinter` for operator-path rotation"). A production fork that wants operator-path automated rotation supplies a KMS/HSM-backed CA via the `RotationMinter` seam directly. The trigger's polling + reload mechanism is the load-bearing wiring; the minter is the swappable seam.
- **M5 (fallback honest + never trust-degrade):** ✅ — a failed CA/CRL reload leaves the OLD pool/set in place (the transport NEVER trust-degrades). The reject fires the 20th SSoT counter `CertRevokedRejected` (the Law V security-gate disclosure); the rotation trigger fires the 21st `CertRotationTriggered`. Both are modeCounters (the gauge count STAYS 3).
- **M6 (SSoT 19→21):** ✅ — `CertRevokedRejected` + `CertRotationTriggered` (modeCounters) in all 4 registry sites (var block + `allCounters()` + `init()` + `rebuildCounters()`); the bridge auto-surfaces them (§0.f — ZERO bridge edit; RUNTIME /verify PASS 7/7 proves BOTH appear on `/metrics`).

## §3 — The Wiring (the load-bearing artifacts)

**`pkg/transport/tls_transport.go`** (the transport's `TLSConnections`):
- `VerifyPeerCertificate` callback — the CRL consult. Parses the peer's leaf, extracts the serial (`serial.Text(10)`), checks `revokedSerials[serial]`; on a hit returns `ErrCertRevoked` + fires `revocationReporter` (the `CertRevokedRejected` counter seam). On an empty `revokedSerials` set (the opt-OUT default — no `SetCRLPath`), returns nil (byte-identical pre-Day-30 — `T-PKI-OFF-IS-BYTE-IDENTICAL`).
- `SetCRLPath` + `LoadCRL` + `ReloadCRL` — the CRL disk round-trip. `LoadCRL` parses the PEM (`pem.Decode` → `x509.ParseRevocationList`), extracts the revoked serials into `revokedSerials`. `ReloadCRL` re-reads `crlPath` + swaps the map under the write-Lock. `ErrNoCRLPath` on a no-CRL transport.
- `ReloadCA` — re-reads `caPath` + rebuilds the pool under the write-Lock. The pool swap is picked up by the NEXT handshake via `GetConfigForClient` (the dynamic-CA hook — the per-connection config reads `caPool` under the RLock). A failed rebuild leaves the OLD pool.
- `SetRevocationReporter(fn func())` — the counter seam (the cmd wires `telemetry.CertRevokedRejected.Inc`).
- `StartRotationManager(ctx, poll, preExpiry, minter, reporter)` — the automated trigger. A goroutine polls the live leaf's `NotAfter` every `poll`; when `time.Until(NotAfter) < preExpiry`, it calls `minter()` (which mints a new leaf + writes the PEM + `Reload`s) + fires `reporter` (the `CertRotationTriggered` counter). Returns a `stop()` func. The default `--cert-rotation-poll` is 1m; `--cert-rotation-lifetime` is 7 days (the pre-expiry window — a 30-day cert rotated at day 23).
- `RotationMinter` alias — `func() (*big.Int, error)` (returns the new serial).

**`pkg/crypto/certgen.go`** (the dev-mesh CA):
- `RevokeLeaf(serial *big.Int)` — adds the serial to the CA's revoked set.
- `IssueCRL(crlNumber int64)` — mints an Ed25519-signed X.509 v2 CRL listing the revoked serials (the `CheckSignatureFrom` consult the CRL parser uses).
- `WriteCRLPEM(dir, der)` — writes `crl.pem` (PEM `X509 CRL` block).
- `IssueLeafWithLifetime(nodeID, notBefore, notAfter)` — the rotation-trigger test's short-lived leaf (compresses the 30-day cadence into a wall-clock test).

**`cmd/sovereign-node/main.go`** (the binary):
- `--crl-path` (empty default = no CRL consult = byte-identical Day-29).
- `--cert-rotation-enable` (false default) + `--cert-rotation-poll` (1m) + `--cert-rotation-lifetime` (7d).
- The SIGHUP handler reloads the triple (leaf + CA + CRL, each independent).
- `buildRotationMinter(selftestCA, nodeID, certPath, keyPath, tr)` — mints via the in-process CA (selftest only); the operator path returns a clear error.

## §4 — The Teeth (10, byte-proven on loopback — NOT silicon)

| Tooth | Proof |
|---|---|
| `T-PKI-REVOKED-REJECTED` | A leaf whose serial is in the CRL is REJECTED at the handshake + `CertRevokedRejected` fires (rejects=1). FULL disk round-trip (`RevokeLeaf` → `IssueCRL` → `WriteCRLPEM` → `SetCRLPath` → `LoadCRL`). |
| `T-PKI-SIBLING-NOT-REVOKED` | A sibling leaf NOT in the CRL PASSES + the counter does NOT fire (the CRL is serial-scoped, NOT CA-scoped — the M2(b)). |
| `T-PKI-EXPIRED-REJECTED` | An expired leaf (NotAfter in the past) is REJECTED by default Go-tls chain validation (the EXPIRED claw — met by the stdlib, NOT new work; the M2(a) probe). |
| `T-PKI-CA-HOT-RELOAD` | A NEW-CA client leaf is REJECTED by the OLD server pool, then ACCEPTED after `ReloadCA` loads the NEW CA into the server's `ClientCAs` (the `:126` restriction lifted). |
| `T-PKI-CRL-HOT-RELOAD` | A leaf PASSES, then after `ReloadCRL` adds its serial, the SAME leaf is REJECTED (the live-revocation gate — an operator revokes a serial by publishing a new `crl.pem` + SIGHUP). |
| `T-PKI-ROTATION-TRIGGER` | `StartRotationManager` fires the rotation when the live leaf is within the pre-expiry lifetime (a 2s leaf + 1s pre-expiry + 100ms poll compresses the 30-day cadence into a wall-clock test) + `CertRotationTriggered` fires. |
| `T-PKI-OFF-IS-BYTE-IDENTICAL` | No CRL → the callback returns nil → handshake PASSES (byte-identical pre-Day-30). |
| `T-PKI-LEAF-ROTATION` | (the EXISTING `TestTLSCertRotation_SIGHUP`) the SIGHUP seam still swaps the leaf — the regression guard. |
| `T-PKI-SSOT-21` | `Counters()` carries 21 DISTINCT (19→21), both Day-30 PKI names present. |
| `T-PKI-COUNTERS-FIRE` | `CertRevokedRejected` + `CertRotationTriggered` both INCREMENT. |

## §5 — The Gate (§III, all GREEN)

- build / gofmt / vet clean (Day-30 packages vet-clean; only the PRE-EXISTING 35 `unsafe.Pointer` warnings in FROZEN `crdt.go`/`hamt_arena.go`/`internal/chaos/probe.go` — UNCHANGED 35→35).
- FROZEN 5-file md5 gate GREEN — **NONE of the 5 FROZEN files touched** (the Day-29 `44f89527` streak is PRESERVED — NO streak-breaker this fork).
- Scope gate GREEN — the Day-30 edited set (`pkg/crypto/certgen.go`, `pkg/transport/tls_transport.go`, `pkg/transport/day30_track30_test.go`, `pkg/mesh/day29_stratified_test.go`) exempted with disclosure (the `track36ExemptDay30` map).
- fieldalignment: ZERO new debt (the `TLSConnections` reorder packed it down — the pre-existing 88→56 finding is GONE too).
- HotPath zero-alloc + GearHonesty GREEN (the Day-30 PKI work is OFF the hot path — handshake-time, not the 57M ops/s insert path).
- 9 new Day-30 teeth GREEN + 3 existing Day-1 teeth GREEN + all per-package suites GREEN (the 3 full-sweep failures all classified: the scope exemption now fixed; `TestPhase25A1` + `TestReceiver_AcceptDedupBaitNegativeControl_4c` are load-induced 4c-box measurement flakes, pass in isolation — the memory-noted class).
- RUNTIME /verify PASS 7/7 (harness `$JOB_DIR/tmp/verify_day30.go`, `D30_BINARY` env — the FULL mTLS control-port drive, NOT the insufficient selftest 4/4 path): the REAL Day-30 binary boots, `/metrics` surfaces BOTH new PKI counters (the §0.f auto-surface; PRESENCE not value — a selftest boot with `--crl-path` empty + `--cert-rotation-enable=false` fires NEITHER, but the series MUST appear so the bridge enumerates the counter the cmd wiring binds).

## §6 — Carry-forwards (disclosed, NOT closed)

- **Silicon-scale CRL consult latency gate** — the loopback teeth prove correctness, NOT the silicon-scale handshake overhead of a 10k-entry CRL parse on every handshake. A 100-node silicon run is a SEPARATE fork (the Day-29 "NO AWS this turn" precedent).
- **Operator-path automated rotation** — the `--selftest` path mints the in-process CA; the operator path needs an out-of-process KMS/HSM-backed minter via the `RotationMinter` seam (M4).
- **Delta-CRLs / partitioned CRLs** — the current CRL is a full serial list re-parsed on every reload; a delta-CRL (RFC 5280 §5) + a Bloom-filter fast-path (a serial lookup that skips the map on a likely-not-rejected fast path) are SEPARATE forks for a 10k+ revoked-serial mesh.
- **OCSP stapling** — the CRL is the push model (the operator publishes the list); OCSP stapling (the pull model, the leaf carries a freshness proof) is a SEPARATE fork for a low-latency revocation surface.
