// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

import "crypto/tls"

// Go 1.24 and later advertise X25519MLKEM768 by default. ServerConfig and
// ClientConfig leave CurvePreferences unset, so supporting peers negotiate the
// hybrid key exchange while other peers can fall back to X25519 (ADR-0036).
// These helpers inspect the negotiated curve and report it; they do not change
// TLS configuration. Hybrid signature verification lives in pkg/identity.
//
// Key exchange and certificate revocation are independent: the serial check in
// VerifyPeerCertificate runs after the TLS key exchange (ADR-0035).

// NegotiatedPQKEM reports whether connState records X25519MLKEM768 as the
// negotiated key exchange. A handshake that fell back to X25519 returns false.
// The function only inspects ConnectionState; it does not alter TLS config.
func NegotiatedPQKEM(connState tls.ConnectionState) bool {
	return connState.CurveID == tls.X25519MLKEM768
}

// PQKEMCurveID names the X25519MLKEM768 CurveID used by NegotiatedPQKEM.
const PQKEMCurveID = tls.X25519MLKEM768

// SetPQHandshakeReporter installs the callback invoked by RecordHandshake for
// X25519MLKEM768 handshakes. A nil callback disables reporting; classical
// fallbacks never invoke it. Configure the reporter during transport setup.
//
// crypto/tls does not expose a post-handshake CurveID callback, so Dial calls
// RecordHandshake explicitly. The server-side control-port accept path does
// not report through this hook (ADR-0036 §6).
func (t *TLSConnections) SetPQHandshakeReporter(fn func()) {
	t.mu.Lock()
	t.pqHandshakeReporter = fn
	t.mu.Unlock()
}

// RecordHandshake invokes the configured reporter only when connState records
// X25519MLKEM768. Dial calls it after the synchronous handshake; tests may call
// it with any completed ConnectionState. Server-side control-port accepts are
// not instrumented (ADR-0036 §6). A nil reporter leaves negotiation uncounted.
func (t *TLSConnections) RecordHandshake(connState tls.ConnectionState) {
	if !NegotiatedPQKEM(connState) {
		return // classical fallback; do not report a hybrid key exchange
	}
	t.mu.RLock()
	reporter := t.pqHandshakeReporter
	t.mu.RUnlock()
	if reporter != nil {
		reporter() // typically increments PQHandshakeNegotiated
	}
}
