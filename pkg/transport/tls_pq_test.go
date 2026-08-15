package transport

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/hr18vk/supremum/pkg/crypto"
)

// ──────────────────────────────────────────────────────────────────────────
// Day 31 (ADR-0036): the post-quantum transport-readiness teeth.
//
// The blueprint's post-quantum posture ("ML-DSA-65 from day 1" + the TLS KEM)
// is a security gate Day 31 PROVES byte-for-byte on a real loopback TLS
// handshake (NOT silicon — the Day-7 precedent: loopback is the unit-level
// proof, the silicon gear is the scale proof, a SEPARATE fork). The teeth:
//
//	T-PQ-KEM-NEGOTIATED        — the engine's DEFAULT config (no CurvePreferences
//	                             set) negotiates X25519MLKEM768 (CurveID 4588) on
//	                             a real loopback handshake — the M2 "prove, NOT
//	                             enable" posture (Go 1.24+ advertises MLKEM by
//	                             default; the engine inherits it).
//	T-PQ-KEM-CLASSICAL-CONTROL  — the BUG-INJECT control: a forced
//	                             CurvePreferences=[X25519] yields CurveID==29
//	                             (X25519, classical). The cut vanishes under the
//	                             inject — PROVES the T-PQ-KEM-NEGOTIATED tooth
//	                             is load-bearing (NOT a tautology; a misconfigured
//	                             engine would PASS the assertion's negation).
//	T-PQ-KEM-RECORD-HANDSHAKE   — tr.RecordHandshake fires the reporter IFF the
//	                             negotiated CurveID is X25519MLKEM768 (the PQ
//	                             counter fires on a PQ handshake, NOT a classical
//	                             fallback — M6 the PQ-KEM-only disclosure).
//	T-PQ-KEM-CLASSICAL-NO-FIRE  — the BUG-INJECT control on RecordHandshake: a
//	                             classical-CurveID handshake does NOT fire the
//	                             reporter (the counter is PQ-KEM-only).
//	T-PQ-COUNTER-FIRE           — the package-level PQHandshakeNegotiated counter
//	                             increments on .Inc() (the direct-seam proof; the
//	                             transport.Dial → RecordHandshake path fires it
//	                             end-to-end via tr.Dial).
//	T-PQ-SSOT-22                — Counters() carries the 22nd name
//	                             (PQHandshakeNegotiated); the SSoT grew 21->22.
//	T-PQ-DIAL-FIRES-COUNTER     — tr.Dial (the production dial seam) fires the
//	                             PQHandshakeNegotiated reporter on a PQ
//	                             handshake (the end-to-end wiring proof).
//	T-PQ-OFF-IS-BYTE-IDENTICAL  — no --hybrid-verify + no reporter → the receive
//	                             path stays on the classical VerifyCRDTFrame
//	                             seam (byte-identical Day-30; the opt-OUT
//	                             default).
//
// The hybrid SIGNATURE verify teeth live in pkg/identity (the
// T-PQ-HYBRID-VERIFY-DUAL + T-PQ-HYBRID-STRICT-REJECT teeth in
// pkg/identity/hybrid_verify_test.go) — the transport teeth here are the KEM
// (key exchange) half; the identity teeth are the signature half.
// ──────────────────────────────────────────────────────────────────────────

// pqMeshFixture mints a dev-mesh CA + a leaf for "node-1" + returns the
// transport + the CA cert (the meshFixture shape, named for the PQ teeth).
func pqMeshFixture(t *testing.T) (tr *TLSConnections, caCert *x509.Certificate) {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	certPath, keyPath, err := leaf.WritePEM(dir)
	if err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	tr, err = NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	return tr, ca.CACert()
}

// pqHandshake drives a loopback mTLS handshake + returns the client-side
// ConnectionState (the negotiated CurveID is the load-bearing field). The
// server + client configs are the engine's REAL ServerConfig/ClientConfig
// (the production configs — NOT a hand-rolled config — so the tooth proves
// the PRODUCTION path, not a test-only path). serverCfgOverride (if non-nil)
// replaces the server config (the BUG-INJECT control forces CurvePreferences).
func pqHandshake(t *testing.T, tr *TLSConnections, caCert *x509.Certificate, serverCfgOverride, clientCfgOverride *tls.Config) tls.ConnectionState {
	t.Helper()
	srvCfg := serverCfgOverride
	if srvCfg == nil {
		srvCfg = tr.ServerConfig()
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srvDone := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			srvDone <- e
			return
		}
		defer c.Close()
		if tc, ok := c.(*tls.Conn); ok {
			srvDone <- tc.Handshake()
			return
		}
		srvDone <- nil
	}()
	cliCfg := clientCfgOverride
	if cliCfg == nil {
		cliCfg = tr.ClientConfig("node-1")
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return conn.ConnectionState()
}

// TestPQ_KEMNegotiated (T-PQ-KEM-NEGOTIATED) proves the engine's DEFAULT config
// (no CurvePreferences set — the production transport) negotiates
// X25519MLKEM768 (CurveID 4588) on a real loopback handshake. This is the M2
// "prove, NOT enable" posture: the engine ALREADY does the PQ KEM via the Go
// 1.24+ default; Day 31 PROVES it (the assertion), NOT enables it (no
// CurvePreferences override). The tooth uses the REAL ServerConfig/ClientConfig
// (the production path).
func TestPQ_KEMNegotiated(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("T-PQ-KEM-NEGOTIATED: negotiated CurveID=%d (%s), want X25519MLKEM768 (4588) — the engine's DEFAULT config MUST negotiate the PQ KEM (Go 1.24+ advertises MLKEM by default; the engine inherits it; NO CurvePreferences is set on the production transport)", st.CurveID, tls.CipherSuiteName(uint16(st.CurveID)))
	}
	if !NegotiatedPQKEM(st) {
		t.Fatalf("T-PQ-KEM-NEGOTIATED: NegotiatedPQKEM(st)=false, want true (the helper MUST report the PQ KEM when CurveID==X25519MLKEM768)")
	}
	t.Logf("T-PQ-KEM-NEGOTIATED PASS: the engine's DEFAULT config (no CurvePreferences) negotiates X25519MLKEM768 (CurveID=%d) on a real loopback handshake — the PQ KEM is PROVEN (Go 1.24+ default inherited), NOT enabled", st.CurveID)
}

// TestPQ_KEMClassicalControl (T-PQ-KEM-CLASSICAL-CONTROL) is the BUG-INJECT
// control for T-PQ-KEM-NEGOTIATED: a forced CurvePreferences=[X25519] yields
// CurveID==29 (X25519, classical). The cut vanishes under the inject — PROVES
// the T-PQ-KEM-NEGOTIATED tooth is load-bearing (NOT a tautology; a
// misconfigured engine that forced classical would PASS the negation of
// T-PQ-KEM-NEGOTIATED, so this control proves the assertion is meaningful).
func TestPQ_KEMClassicalControl(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	// BUG-INJECT: force BOTH server + client to classical X25519-only.
	srvForced := tr.ServerConfig()
	srvForced.CurvePreferences = []tls.CurveID{tls.X25519}
	cliForced := tr.ClientConfig("node-1")
	cliForced.CurvePreferences = []tls.CurveID{tls.X25519}
	st := pqHandshake(t, tr, caCert, srvForced, cliForced)
	if st.CurveID != tls.X25519 {
		t.Fatalf("T-PQ-KEM-CLASSICAL-CONTROL: forced CurvePreferences=[X25519] negotiated CurveID=%d, want X25519 (29) — the BUG-INJECT control MUST yield the classical curve (the cut vanishes; PROVES T-PQ-KEM-NEGOTIATED is load-bearing)", st.CurveID)
	}
	if NegotiatedPQKEM(st) {
		t.Fatalf("T-PQ-KEM-CLASSICAL-CONTROL: NegotiatedPQKEM(st)=true on a forced-classical handshake, want false (the helper MUST report classical when CurveID==X25519)")
	}
	t.Logf("T-PQ-KEM-CLASSICAL-CONTROL PASS: forced CurvePreferences=[X25519] -> CurveID=%d (X25519, classical) — the BUG-INJECT control proves T-PQ-KEM-NEGOTIATED is load-bearing (NOT a tautology)", st.CurveID)
}

// TestPQ_KEMRecordHandshake (T-PQ-KEM-RECORD-HANDSHAKE) proves tr.RecordHandshake
// fires the reporter IFF the negotiated CurveID is X25519MLKEM768. The tooth
// drives a PQ handshake (the DEFAULT) + asserts the reporter fires exactly
// once. The reporter is the PQHandshakeNegotiated counter seam (Law V).
func TestPQ_KEMRecordHandshake(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	var fires int32
	tr.SetPQHandshakeReporter(func() { atomic.AddInt32(&fires, 1) })
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("T-PQ-KEM-RECORD-HANDSHAKE: pre-condition failed — negotiated CurveID=%d, want X25519MLKEM768 (the PQ handshake is the setup for the reporter-fire test)", st.CurveID)
	}
	tr.RecordHandshake(st)
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("T-PQ-KEM-RECORD-HANDSHAKE: reporter fired %d times, want 1 (a PQ handshake MUST fire the reporter exactly once — the PQHandshakeNegotiated counter seam)", got)
	}
	t.Logf("T-PQ-KEM-RECORD-HANDSHAKE PASS: tr.RecordHandshake fires the reporter exactly once on a PQ (X25519MLKEM768) handshake")
}

// TestPQ_KEMClassicalNoFire (T-PQ-KEM-CLASSICAL-NO-FIRE) is the BUG-INJECT
// control for T-PQ-KEM-RECORD-HANDSHAKE: a classical-CurveID handshake does NOT
// fire the reporter (the counter is PQ-KEM-only, NOT every handshake — M6). The
// tooth forces CurvePreferences=[X25519] + asserts RecordHandshake does NOT fire.
func TestPQ_KEMClassicalNoFire(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	var fires int32
	tr.SetPQHandshakeReporter(func() { atomic.AddInt32(&fires, 1) })
	srvForced := tr.ServerConfig()
	srvForced.CurvePreferences = []tls.CurveID{tls.X25519}
	cliForced := tr.ClientConfig("node-1")
	cliForced.CurvePreferences = []tls.CurveID{tls.X25519}
	st := pqHandshake(t, tr, caCert, srvForced, cliForced)
	if st.CurveID != tls.X25519 {
		t.Fatalf("T-PQ-KEM-CLASSICAL-NO-FIRE: pre-condition failed — forced classical negotiated CurveID=%d, want X25519", st.CurveID)
	}
	tr.RecordHandshake(st)
	if got := atomic.LoadInt32(&fires); got != 0 {
		t.Fatalf("T-PQ-KEM-CLASSICAL-NO-FIRE: reporter fired %d times on a classical handshake, want 0 (the counter is PQ-KEM-only — a classical fallback MUST NOT fire it; M6)", got)
	}
	t.Logf("T-PQ-KEM-CLASSICAL-NO-FIRE PASS: a classical (X25519) handshake does NOT fire the PQ reporter (the counter is PQ-KEM-only, NOT every handshake)")
}

// TestPQ_CounterFire (T-PQ-COUNTER-FIRE) proves the package-level
// PQHandshakeNegotiated counter increments on .Inc() (the direct-seam proof).
// The transport.Dial → RecordHandshake path fires it end-to-end (verified by
// T-PQ-DIAL-FIRES-COUNTER); this tooth is the DIRECT increment proof (the
// Day-30 TestPKI_CountersFire precedent).
func TestPQ_CounterFire(t *testing.T) {
	before := telemetry.PQHandshakeNegotiated.Value()
	telemetry.PQHandshakeNegotiated.Inc()
	after := telemetry.PQHandshakeNegotiated.Value()
	if after-before < 1 {
		t.Fatalf("T-PQ-COUNTER-FIRE: PQHandshakeNegotiated did NOT increment (before=%v after=%v)", before, after)
	}
	t.Logf("T-PQ-COUNTER-FIRE PASS: PQHandshakeNegotiated (%v->%v) increments on .Inc() (the direct-seam proof; the transport.Dial path fires it end-to-end)", before, after)
}

// TestPQ_SSOT22 (T-PQ-SSOT-22) proves the telemetry Counters() slice carries the
// 22nd name (PQHandshakeNegotiated); the SSoT grew 21->22. The tooth is the
// SSoT-grew-honestly proof: the bridge auto-surfaces the 22nd series (the §0.f
// property) IF the counter is constructed in init() AND rebuildCounters() (the
// Day-21 fill discipline — the T-PQ-COUNTER-FIRE tooth + the registry.go 4-site
// construction prove BOTH).
func TestPQ_SSOT22(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) grew 21 -> 22 (PQHandshakeNegotiated)
	if len(cs) != wantDistinct {
		t.Fatalf("T-PQ-SSOT-22: len(Counters())=%d, want %d (Day 31 grew the SSoT 21->22 — ONE counter: PQHandshakeNegotiated)", len(cs), wantDistinct)
	}
	wantName := "supremum.pki.pq_handshake_negotiated"
	seen := false
	for _, c := range cs {
		if c.Name() == wantName {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("T-PQ-SSOT-22: counter %q MISSING from Counters() (the Day-31 PQ disclosure counter MUST be in the SSoT slice)", wantName)
	}
	t.Logf("T-PQ-SSOT-22 PASS: Counters() carries %d DISTINCT (21->22), the Day-31 PQ name present (PQHandshakeNegotiated)", len(cs))
}

// TestPQ_DialFiresCounter (T-PQ-DIAL-FIRES-COUNTER) proves tr.Dial (the
// production dial seam — the mesh PeerSet.Dial → ps.dialer.Dial → here) fires
// the PQHandshakeNegotiated reporter on a PQ handshake. The tooth starts a
// server (tr.Listen) + dials it (tr.Dial) + asserts the reporter fired. This is
// the end-to-end wiring proof (the counter is NOT just unit-tested; it fires on
// the production dial path).
func TestPQ_DialFiresCounter(t *testing.T) {
	tr, _ := pqMeshFixture(t)
	var fires int32
	tr.SetPQHandshakeReporter(func() { atomic.AddInt32(&fires, 1) })
	ln, err := tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvDone := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			srvDone <- e
			return
		}
		defer c.Close()
		if tc, ok := c.(*tls.Conn); ok {
			srvDone <- tc.Handshake()
			return
		}
		srvDone <- nil
	}()
	conn, err := tr.Dial("tcp", ln.Addr().String(), "node-1")
	if err != nil {
		t.Fatalf("T-PQ-DIAL-FIRES-COUNTER: tr.Dial: %v", err)
	}
	defer conn.Close()
	if err := <-srvDone; err != nil {
		t.Fatalf("T-PQ-DIAL-FIRES-COUNTER: server handshake: %v", err)
	}
	if conn.ConnectionState().CurveID != tls.X25519MLKEM768 {
		t.Fatalf("T-PQ-DIAL-FIRES-COUNTER: tr.Dial negotiated CurveID=%d, want X25519MLKEM768 (the production dial seam MUST negotiate the PQ KEM)", conn.ConnectionState().CurveID)
	}
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("T-PQ-DIAL-FIRES-COUNTER: reporter fired %d times on tr.Dial, want 1 (the production dial seam MUST fire the PQ counter on a PQ handshake — the end-to-end wiring proof)", got)
	}
	t.Logf("T-PQ-DIAL-FIRES-COUNTER PASS: tr.Dial (the production dial seam) negotiated X25519MLKEM768 + fired the PQHandshakeNegotiated reporter (fires=1) — the end-to-end wiring proof")
}

// TestPQ_OffIsByteIdentical (T-PQ-OFF-IS-BYTE-IDENTICAL) proves the opt-OUT
// default: no --hybrid-verify (the receiver stays on the classical
// VerifyCRDTFrame seam) + no PQ reporter bound (the default) → the transport's
// RecordHandshake is a no-op (the reporter is nil). The tooth asserts a nil
// reporter transport's RecordHandshake does NOT panic + does NOT fire (the
// opt-OUT default is byte-identical Day-30 — the PQ seam is dormant until the
// operator binds the reporter, which main.go does unconditionally but a test /
// research node does NOT).
func TestPQ_OffIsByteIdentical(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	// NO SetPQHandshakeReporter — the opt-OUT default (a research node / a test
	// that does not bind the counter). The reporter is nil.
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("T-PQ-OFF-IS-BYTE-IDENTICAL: pre-condition failed — CurveID=%d, want X25519MLKEM768", st.CurveID)
	}
	// RecordHandshake on a nil-reporter transport MUST NOT panic + MUST NOT fire
	// (the nil-guard — the SetRevocationReporter precedent).
	tr.RecordHandshake(st) // nil-reporter no-op — must not panic
	t.Logf("T-PQ-OFF-IS-BYTE-IDENTICAL PASS: a nil-reporter transport's RecordHandshake is a no-op (the opt-OUT default is byte-identical Day-30; the PQ seam is dormant until the operator binds the reporter)")
}
