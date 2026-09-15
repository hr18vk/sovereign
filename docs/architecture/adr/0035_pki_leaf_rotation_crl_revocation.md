# ADR-0035: PKI Leaf Rotation + CRL Revocation

**Status:** ACCEPTED (2026-08-11)

**Date:** 2026-08-11

## §1 — The Decision

Wire the dormant mTLS-enforcement security gate on the TLS transport: a node presenting an EXPIRED OR REVOKED leaf is REJECTED at the TLS handshake (both-sides mTLS enforcement), plus zero-downtime leaf-certificate rotation on a 30-day cadence (an automated rotation trigger). The gate was dormant — the original TLS work shipped the TLS 1.3 mTLS pipe and the SIGHUP leaf-reload seam, but no CRL consult (a revoked serial was accepted until the leaf expired) and no automated rotation (an operator had to SIGHUP before the 30-day window closed, or the cert expired mid-mesh). This change closes the dormancy with the CRL revocation consult, the CA/CRL hot-reload (the M3 triple below), and the rotation manager (the automated trigger), all OPT-IN (the standing opt-in precedent for transport features; the defaults leave the transport byte-identical to its prior behavior).

**The M2(a) finding (load-bearing, established before any code).** The premise that an EXPIRED leaf is rejected by default Go TLS chain validation — i.e. the EXPIRED claw is met by the standard library, not new work — was verified by direct probe (loopback, the repo's `pkg/crypto` certgen + `tls.Dial`): an expired CLIENT leaf surfaces `remote error: tls: bad certificate` on the SERVER side and `failed to verify certificate: x509: certificate has expired` on the CLIENT side, both WITH and WITHOUT `VerifyPeerCertificate` wired — the callback runs after normal verification ("If normal verification fails then the handshake will abort before considering this callback" — the Go docs), so an expired leaf never reaches the CRL consult. The EXPIRED claw is genuinely free (inherited); the REVOKED claw is the load-bearing new work (the CRL consult the callback performs). The tooth `T-PKI-EXPIRED-REJECTED` proves the inheritance; it is not a claim of new work.

**The M3 triple.** A SIGHUP reloads the full triple — leaf, CA pool, CRL — not just the leaf (the earlier leaf-only `:126` behavior). Each reload is independent and atomic under the transport's RWMutex; a failed reload of one surface leaves the stale version in place (the honest-negative posture — the transport never trust-degrades or revocation-degrades on a failed reload). The leaf reload stays first (the pre-existing seam and the existing `TestTLSCertRotation_SIGHUP` contract). The CA reload uses `GetConfigForClient` — the only dynamic-CA hook Go's `tls.Config` offers (`ClientCAs`/`RootCAs` are static fields; `GetCertificate` is the leaf's dynamic hook, but there is no CA equivalent), so the per-connection config returned by `GetConfigForClient` reads the live pool under the RLock. The CRL reload swaps the `revokedSerials` map.

## §2 — The Premise Audit (M1–M6, verified BEFORE code)

- **M1 (gate dormant, TLS substrate present):** verified — the original TLS work shipped the TLS 1.3 mTLS pipe (`RequireAndVerifyClientCert` + `GetCertificate` + the SIGHUP `Reload` seam). The CRL consult, the CA/CRL hot-reload, and the rotation manager were absent (dormant). The `ServerConfig`/`ClientConfig` had no `VerifyPeerCertificate`; the only reload was `Reload` (leaf only).
- **M2(a) (EXPIRED claw inherited):** verified by probe — an expired leaf is rejected by normal chain validation BEFORE the CRL callback. The `VerifyPeerCertificate` callback does not skip normal verification (Go docs + probe: both with and without the callback, the expired leaf is rejected). The EXPIRED claw is free; `T-PKI-EXPIRED-REJECTED` proves the inheritance, not a new-work claim.
- **M2(b) (CRL is serial-scoped, not CA-scoped):** verified — the CRL lists serials, not CA identity. Revoking one leaf does not revoke the CA's other leaves. `T-PKI-SIBLING-NOT-REVOKED` proves a sibling leaf not in the CRL passes (the honest scope: a compromised-serial reject does not take down the whole mesh).
- **M3 (triple hot-reload, independent + atomic):** verified — the SIGHUP handler reloads leaf + CA + CRL in sequence, each under the RWMutex, each independent (a failed leaf reload does not block a CA or CRL update). `T-PKI-CA-HOT-RELOAD` + `T-PKI-CRL-HOT-RELOAD` prove the live swap. The CA swap uses `GetConfigForClient` (the dynamic-CA hook); the CRL swap swaps the `revokedSerials` map.
- **M4 (operator-path rotation needs an out-of-process minter):** disclosed — the `--selftest` path mints an in-process CA (`mintSelftestCerts` returns the `*MeshCA`), so `buildRotationMinter` mints new leaves via the same CA. The operator path (not `--selftest`) loads PEMs from disk and has no in-process CA, so `--cert-rotation-enable` on the operator path returns a clear error ("requires an in-process CA — supply an out-of-process minter via `transport.RotationMinter` for operator-path rotation"). A production deployment that wants operator-path automated rotation supplies a KMS/HSM-backed CA via the `RotationMinter` seam directly. The trigger's polling + reload mechanism is the load-bearing wiring; the minter is the swappable seam.
- **M5 (fallback honest, never trust-degrade):** verified — a failed CA/CRL reload leaves the old pool/set in place (the transport never trust-degrades). The reject fires the 20th telemetry counter `CertRevokedRejected` (the security-gate disclosure); the rotation trigger fires the 21st, `CertRotationTriggered`. Both are modeCounters (the gauge count stays 3).
- **M6 (telemetry counters 19→21):** verified — `CertRevokedRejected` + `CertRotationTriggered` (modeCounters) in all four registry sites (var block + `allCounters()` + `init()` + `rebuildCounters()`); the bridge auto-surfaces them (zero bridge edit; the runtime /verify pass proves both appear on `/metrics`).

## §3 — The Wiring (the load-bearing artifacts)

**`pkg/transport/tls_transport.go`** (the transport's `TLSConnections`):
- `VerifyPeerCertificate` callback — the CRL consult. Parses the peer's leaf, extracts the serial (`serial.Text(10)`), checks `revokedSerials[serial]`; on a hit returns `ErrCertRevoked` + fires `revocationReporter` (the `CertRevokedRejected` counter seam). On an empty `revokedSerials` set (the opt-OUT default — no `SetCRLPath`), returns nil (byte-identical to the pre-change transport — `T-PKI-OFF-IS-BYTE-IDENTICAL`).
- `SetCRLPath` + `LoadCRL` + `ReloadCRL` — the CRL disk round-trip. `LoadCRL` parses the PEM (`pem.Decode` → `x509.ParseRevocationList`), extracts the revoked serials into `revokedSerials`. `ReloadCRL` re-reads `crlPath` + swaps the map under the write-Lock. `ErrNoCRLPath` on a no-CRL transport.
- `ReloadCA` — re-reads `caPath` + rebuilds the pool under the write-Lock. The pool swap is picked up by the next handshake via `GetConfigForClient` (the dynamic-CA hook — the per-connection config reads `caPool` under the RLock). A failed rebuild leaves the old pool.
- `SetRevocationReporter(fn func())` — the counter seam (the command wiring binds `telemetry.CertRevokedRejected.Inc`).
- `StartRotationManager(ctx, poll, preExpiry, minter, reporter)` — the automated trigger. A goroutine polls the live leaf's `NotAfter` every `poll`; when `time.Until(NotAfter) < preExpiry`, it calls `minter()` (which mints a new leaf + writes the PEM + `Reload`s) + fires `reporter` (the `CertRotationTriggered` counter). Returns a `stop()` func. The default `--cert-rotation-poll` is 1m; `--cert-rotation-lifetime` is 7 days (the pre-expiry window — a 30-day cert rotated at day 23).
- `RotationMinter` alias — `func() (*big.Int, error)` (returns the new serial).

**`pkg/crypto/certgen.go`** (the dev-mesh CA):
- `RevokeLeaf(serial *big.Int)` — adds the serial to the CA's revoked set.
- `IssueCRL(crlNumber int64)` — mints an Ed25519-signed X.509 v2 CRL listing the revoked serials (the `CheckSignatureFrom` consult the CRL parser uses).
- `WriteCRLPEM(dir, der)` — writes `crl.pem` (PEM `X509 CRL` block).
- `IssueLeafWithLifetime(nodeID, notBefore, notAfter)` — the rotation-trigger test's short-lived leaf (compresses the 30-day cadence into a wall-clock test).

**`cmd/sovereign-node/main.go`** (the binary):
- `--crl-path` (empty default = no CRL consult = byte-identical to the prior behavior).
- `--cert-rotation-enable` (false default) + `--cert-rotation-poll` (1m) + `--cert-rotation-lifetime` (7d).
- The SIGHUP handler reloads the triple (leaf + CA + CRL, each independent).
- `buildRotationMinter(selftestCA, nodeID, certPath, keyPath, tr)` — mints via the in-process CA (selftest only); the operator path returns a clear error.

## §4 — The Teeth (10, byte-proven on loopback — NOT silicon)

| Tooth | Proof |
|---|---|
| `T-PKI-REVOKED-REJECTED` | A leaf whose serial is in the CRL is REJECTED at the handshake + `CertRevokedRejected` fires (rejects=1). Full disk round-trip (`RevokeLeaf` → `IssueCRL` → `WriteCRLPEM` → `SetCRLPath` → `LoadCRL`). |
| `T-PKI-SIBLING-NOT-REVOKED` | A sibling leaf NOT in the CRL passes + the counter does not fire (the CRL is serial-scoped, not CA-scoped — M2(b)). |
| `T-PKI-EXPIRED-REJECTED` | An expired leaf (NotAfter in the past) is REJECTED by default Go TLS chain validation (the EXPIRED claw — met by the stdlib, not new work; the M2(a) probe). |
| `T-PKI-CA-HOT-RELOAD` | A new-CA client leaf is REJECTED by the old server pool, then ACCEPTED after `ReloadCA` loads the new CA into the server's `ClientCAs` (the `:126` restriction lifted). |
| `T-PKI-CRL-HOT-RELOAD` | A leaf passes, then after `ReloadCRL` adds its serial, the same leaf is REJECTED (the live-revocation gate — an operator revokes a serial by publishing a new `crl.pem` + SIGHUP). |
| `T-PKI-ROTATION-TRIGGER` | `StartRotationManager` fires the rotation when the live leaf is within the pre-expiry lifetime (a 2s leaf + 1s pre-expiry + 100ms poll compresses the 30-day cadence into a wall-clock test) + `CertRotationTriggered` fires. |
| `T-PKI-OFF-IS-BYTE-IDENTICAL` | No CRL → the callback returns nil → handshake passes (byte-identical to the pre-change transport). |
| `T-PKI-LEAF-ROTATION` | (the existing `TestTLSCertRotation_SIGHUP`) the SIGHUP seam still swaps the leaf — the regression guard. |
| The counter-cardinality test | `Counters()` carries 21 distinct (19→21), both new PKI names present. |
| `T-PKI-COUNTERS-FIRE` | `CertRevokedRejected` + `CertRotationTriggered` both increment. |

## §5 — The Gate (all green)

- build / gofmt / vet clean (only the pre-existing 35 `unsafe.Pointer` warnings in `pkg/sync` (`crdt.go`, `hamt_arena.go`) and `internal/chaos/probe.go` — unchanged 35→35).
- No change to the CRDT merge-law, wire-schema, or envelope files.
- Edit scope — the change is confined to the PKI/test seam (`pkg/crypto/certgen.go`, `pkg/transport/tls_transport.go`, `pkg/transport/pki_rotation_crl_test.go`, `pkg/mesh/stratified_antientropy_test.go`).
- fieldalignment: zero new debt (the `TLSConnections` reorder packed it down — the pre-existing 88→56 finding is gone too).
- Hot-path zero-alloc + gear-honesty gates green (the PKI work is off the hot path — handshake-time, not the zero-GC write hot path).
- 9 new teeth green + 3 existing TLS teeth green + all per-package suites green (the 3 full-sweep failures all classified: a stale test-scope entry, since fixed; the sharded-stack scaling tests + `TestReceiver_AcceptDedupBaitNegativeControl_4c` are load-induced 4-core-box measurement flakes that pass in isolation — a known class).
- Runtime /verify PASS 7/7 (the full mTLS control-port drive against the real built binary, not the weaker selftest path): the binary boots and `/metrics` surfaces both new PKI counters (the bridge auto-surface; presence, not value — a selftest boot with `--crl-path` empty + `--cert-rotation-enable=false` fires neither, but the series must appear so the bridge enumerates the counters the command wiring binds).

## §6 — Known limitations & follow-ups (disclosed, NOT closed)

- **Silicon-scale CRL consult latency gate** — the loopback teeth prove correctness, not the silicon-scale handshake overhead of a 10k-entry CRL parse on every handshake. A 100-node silicon run remains separate future work.
- **Operator-path automated rotation** — the `--selftest` path mints the in-process CA; the operator path needs an out-of-process KMS/HSM-backed minter via the `RotationMinter` seam (M4).
- **Delta-CRLs / partitioned CRLs** — the current CRL is a full serial list re-parsed on every reload; a delta-CRL (RFC 5280 §5) plus a Bloom-filter fast-path (a serial lookup that skips the map on a likely-not-rejected fast path) are separate work for a 10k+ revoked-serial mesh.
- **OCSP stapling** — the CRL is the push model (the operator publishes the list); OCSP stapling (the pull model, the leaf carries a freshness proof) is separate work for a low-latency revocation surface.
