// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/crypto"
)

// Loopback mTLS tests cover X25519MLKEM768 negotiation, the classical X25519
// control, handshake reporting, telemetry, and the outbound Dial integration
// (ADR-0036). The nil-reporter test checks that observation remains optional.
// Hybrid signature verification is tested separately in pkg/identity.

// pqMeshFixture creates a transport with a "node-1" leaf signed by a new CA.
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

// pqHandshake returns the client ConnectionState from a loopback mTLS
// handshake. Nil overrides use ServerConfig and ClientConfig; tests supply
// overrides to force a particular curve preference.
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

// TestPQ_KEMNegotiated checks that an unmodified ServerConfig and ClientConfig
// negotiate X25519MLKEM768 on loopback through Go's default curve list.
func TestPQ_KEMNegotiated(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("pq kem negotiated: CurveID=%d (%s), want X25519MLKEM768 (4588) — default config must negotiate the PQ KEM", st.CurveID, tls.CipherSuiteName(uint16(st.CurveID)))
	}
	if !NegotiatedPQKEM(st) {
		t.Fatalf("pq kem negotiated: NegotiatedPQKEM(st)=false, want true when CurveID==X25519MLKEM768")
	}
	t.Logf("pq kem negotiated: default config negotiates X25519MLKEM768 (CurveID=%d) on loopback", st.CurveID)
}

// TestPQ_KEMClassicalControl forces X25519 on both endpoints. The different
// negotiated CurveID shows that the default-config assertion responds to the
// key-exchange configuration.
func TestPQ_KEMClassicalControl(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	// Fault injection: force both server and client to classical X25519-only.
	srvForced := tr.ServerConfig()
	srvForced.CurvePreferences = []tls.CurveID{tls.X25519}
	cliForced := tr.ClientConfig("node-1")
	cliForced.CurvePreferences = []tls.CurveID{tls.X25519}
	st := pqHandshake(t, tr, caCert, srvForced, cliForced)
	if st.CurveID != tls.X25519 {
		t.Fatalf("pq kem classical control: forced CurvePreferences=[X25519] negotiated CurveID=%d, want X25519 (29)", st.CurveID)
	}
	if NegotiatedPQKEM(st) {
		t.Fatalf("pq kem classical control: NegotiatedPQKEM(st)=true on forced-classical handshake, want false")
	}
	t.Logf("pq kem classical control: forced CurvePreferences=[X25519] -> CurveID=%d (X25519)", st.CurveID)
}

// TestPQ_KEMRecordHandshake checks one reporter call after an X25519MLKEM768
// handshake.
func TestPQ_KEMRecordHandshake(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	var fires int32
	tr.SetPQHandshakeReporter(func() { atomic.AddInt32(&fires, 1) })
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("pq record handshake: precondition failed — negotiated CurveID=%d, want X25519MLKEM768", st.CurveID)
	}
	tr.RecordHandshake(st)
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("pq record handshake: reporter fired %d times, want 1", got)
	}
	t.Logf("pq record handshake: tr.RecordHandshake fired reporter once on X25519MLKEM768")
}

// TestPQ_KEMClassicalNoFire forces X25519 and checks that RecordHandshake does
// not invoke the hybrid-KEM reporter.
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
		t.Fatalf("pq classical no-fire: precondition failed — forced classical negotiated CurveID=%d, want X25519", st.CurveID)
	}
	tr.RecordHandshake(st)
	if got := atomic.LoadInt32(&fires); got != 0 {
		t.Fatalf("pq classical no-fire: reporter fired %d times on classical handshake, want 0", got)
	}
	t.Logf("pq classical no-fire: classical (X25519) handshake did not fire PQ reporter")
}

// TestPQ_CounterFire checks that PQHandshakeNegotiated advances on Inc.
func TestPQ_CounterFire(t *testing.T) {
	before := telemetry.PQHandshakeNegotiated.Value()
	telemetry.PQHandshakeNegotiated.Inc()
	after := telemetry.PQHandshakeNegotiated.Value()
	if after-before < 1 {
		t.Fatalf("pq counter fire: PQHandshakeNegotiated did not increment (before=%v after=%v)", before, after)
	}
	t.Logf("pq counter fire: PQHandshakeNegotiated (%v->%v) incremented on .Inc()", before, after)
}

// TestPQ_Counter22 checks that telemetry.Counters includes
// PQHandshakeNegotiated and retains the complete registered counter set.
func TestPQ_Counter22(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 25 // includes PKI, PQ, hybrid-frame, region, and write-timeout counters
	if len(cs) != wantDistinct {
		t.Fatalf("pq counter set: len(Counters())=%d, want %d", len(cs), wantDistinct)
	}
	wantName := "supremum.pki.pq_handshake_negotiated"
	seen := false
	for _, c := range cs {
		if c.Name() == wantName {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("pq counter set: counter %q missing from Counters()", wantName)
	}
	t.Logf("pq counter set: Counters() carries %d distinct series including supremum.pki.pq_handshake_negotiated", len(cs))
}

// TestPQ_DialFiresCounter checks that Dial records an X25519MLKEM768 handshake
// through the reporter after completing the outbound connection.
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
		t.Fatalf("pq dial fires counter: tr.Dial: %v", err)
	}
	defer conn.Close()
	if err := <-srvDone; err != nil {
		t.Fatalf("pq dial fires counter: server handshake: %v", err)
	}
	if conn.ConnectionState().CurveID != tls.X25519MLKEM768 {
		t.Fatalf("pq dial fires counter: tr.Dial negotiated CurveID=%d, want X25519MLKEM768", conn.ConnectionState().CurveID)
	}
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("pq dial fires counter: reporter fired %d times on tr.Dial, want 1", got)
	}
	t.Logf("pq dial fires counter: tr.Dial negotiated X25519MLKEM768 and fired PQHandshakeNegotiated (fires=1)")
}

// TestPQ_OffIsByteIdentical checks that RecordHandshake is safe when no
// reporter is configured.
func TestPQ_OffIsByteIdentical(t *testing.T) {
	tr, caCert := pqMeshFixture(t)
	st := pqHandshake(t, tr, caCert, nil, nil)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("pq nil reporter: precondition failed — CurveID=%d, want X25519MLKEM768", st.CurveID)
	}
	tr.RecordHandshake(st) // nil-reporter no-op — must not panic
	t.Logf("pq nil reporter: RecordHandshake on a nil-reporter transport is a no-op")
}
