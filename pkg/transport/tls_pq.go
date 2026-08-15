package transport

import "crypto/tls"

// ──────────────────────────────────────────────────────────────────────────
// Day 31 (ADR-0036): post-quantum transport readiness — the X25519MLKEM768 KEM
// PROOF surface.
//
// The load-bearing physics truth (M2, EMPIRICALLY PROVEN on the 4c Graviton
// loopback box with Go 1.26.1 — the zz_m2_pq probe, NOT committed):
//
//	The engine's ServerConfig()/ClientConfig() set NO CurvePreferences (grep-
//	verified ZERO references in pkg/transport pre-Day-31). Go 1.24+ advertises
//	X25519MLKEM768 (CurveID 4588) by DEFAULT (crypto/tls/common.go:805: "the
//	default includes X25519MLKEM768 hybrid post-quantum key exchange"). So
//	two Go 1.24+ peers ALREADY negotiate the PQ KEM — ConnectionState().CurveID
//	== tls.X25519MLKEM768 (4588) on a real loopback handshake.
//
//	BUG-INJECT control (the proof the tooth is load-bearing, NOT a tautology):
//	  DEFAULT engine config         → CurveID == 4588 (X25519MLKEM768) ✅
//	  forced CurvePreferences=[X25519] → CurveID == 29  (X25519)         ✅ cut vanishes
//	  GODEBUG=tlsmlkem=0            → CurveID == 29  (X25519)         ✅ stdlib knob
//
// So Day 31 does NOT enable the PQ handshake — the engine ALREADY does it via
// the Go default. Day 31 PROVES it (the tooth that asserts the negotiated
// CurveID) + wires the operator-visible counter (Law V) + the hybrid SIGNATURE
// verify (the CRDT-delta frame, the M3 defense-in-depth). This file is the
// proof + the counter-seam surface; the hybrid signature verify is the sibling
// pkg/identity/hybrid_verify.go.
//
// The fork sets NO CurvePreferences — keeping the default is the load-bearing
// choice: a forced CurvePreferences=[X25519MLKEM768] would BREAK a peer lacking
// MLKEM (the Day-29 "opt-IN zero-value = byte-identical" precedent FORBIDS it).
// A peer that does NOT advertise MLKEM gets the classical X25519 fallback (the
// next default curve) — backward-compat preserved. The headline is PROVEN, NOT
// FORCED (the M2 discipline).
//
// The PQ KEM is ORTHOGONAL to the Day-30 VerifyPeerCertificate callback (the
// cert serial check runs AFTER the KEM completes — the key exchange is
// independent of the cert rejection, M5). The KEM is a transport-layer
// constant, NOT a CRDT/data-layer change — the read-your-writes seam (Day-27)
// + the mesh sweep (Day-29) + the PKI surface (Day-30) stay byte-identical
// post-Day-31.
// ──────────────────────────────────────────────────────────────────────────

// NegotiatedPQKEM reports whether a completed TLS handshake negotiated the
// X25519MLKEM768 hybrid post-quantum key exchange. It is the load-bearing
// probe the T-PQ-KEM-NEGOTIATED tooth + the runtime /verify harness assert
// (the NUMBER, not an adjective — Law V). It reads ConnectionState().CurveID
// AFTER the handshake completes (the negotiated KEM, NOT the configured
// preference list — a peer lacking MLKEM falls back to X25519, which this
// helper reports as false, the honest classical-fallback disclosure).
//
// This helper is PROOF-ONLY: it does NOT set CurvePreferences, does NOT enable
// the KEM, does NOT mutate any config. The engine inherits the Go 1.24+
// default; this helper reads the consequence.
func NegotiatedPQKEM(connState tls.ConnectionState) bool {
	return connState.CurveID == tls.X25519MLKEM768
}

// PQKEMCurveID is the CurveID constant the helper probes. It is exported so a
// test / the runtime harness can name the exact constant (4588) the assertion
// compares against (the Day-29 T-STRUCE-M2-CUT-Proven mold — the constant is
// the load-bearing comparison, NOT a magic number buried in the helper).
const PQKEMCurveID = tls.X25519MLKEM768

// SetPQHandshakeReporter binds the counter-increment seam that fires every time
// a completed TLS handshake negotiates the X25519MLKEM768 KEM. It is the Law V
// disclosure (the PQHandshakeNegotiated counter — the operator-visible PROOF
// the PQ handshake is happening, NOT every handshake — ONLY the ones where
// CurveID==X25519MLKEM768; a classical fallback does NOT increment). nil (the
// test + opt-OUT default) leaves the negotiation silent (the
// SetRevocationReporter precedent — the counter is the DISCLOSURE, not the
// mechanism). Bound ONCE at construction.
//
// The reporter is fired by the handshake-observation seam (RecordHandshake
// below), NOT by the crypto/tls stack directly (the stdlib has no
// post-handshake callback that reports CurveID to the application). The
// production binary's control-port accept loop calls RecordHandshake after each
// accepted *tls.Conn completes its handshake; a test mints two configs +
// drives a loopback handshake + calls RecordHandshake directly.
func (t *TLSConnections) SetPQHandshakeReporter(fn func()) {
	t.mu.Lock()
	t.pqHandshakeReporter = fn
	t.mu.Unlock()
}

// RecordHandshake observes a completed TLS handshake + fires the
// PQHandshakeNegotiated reporter IFF the negotiated CurveID is
// X25519MLKEM768. It is the call site the production accept loop + the test
// teeth invoke after Handshake() returns. A classical-CurveID handshake (the
// fallback for a non-MLKEM peer) does NOT fire the reporter (the counter is
// the PQ-KEM disclosure, NOT the every-handshake disclosure — M6). The helper
// is allocation-free (it reads a ConnectionState value the caller already
// holds; no map, no parse).
func (t *TLSConnections) RecordHandshake(connState tls.ConnectionState) {
	if !NegotiatedPQKEM(connState) {
		return // classical fallback — NOT a PQ handshake; the counter is PQ-only
	}
	t.mu.RLock()
	reporter := t.pqHandshakeReporter
	t.mu.RUnlock()
	if reporter != nil {
		reporter() // the PQHandshakeNegotiated counter — Law V PQ-gate disclosure
	}
}
