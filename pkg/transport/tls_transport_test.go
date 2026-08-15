package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/supremum/pkg/crypto"
)

// meshFixture mints a dev-mesh CA + a leaf for "node-1", writes the PEMs to
// a temp dir, and returns the on-disk paths + the parsed CA cert (for ad-hoc
// trust pools). It is the shared setup for the three Day-1 TLS gates.
func meshFixture(t *testing.T) (certPath, keyPath, caPath string, caCert *x509.Certificate) {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err = ca.WriteCAPEM(t.TempDir())
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	certPath, keyPath, err = leaf.WritePEM(t.TempDir())
	if err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	return certPath, keyPath, caPath, ca.CACert()
}

// freeAddr returns a host:port on 127.0.0.1 with a kernel-assigned port
// (":0"), resolved by briefly listening on a plain TCP socket. The TLS
// listener rebinds the same port.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestTLSHandshake_13_Only (G01.b) asserts the negotiated protocol is TLS 1.3
// and the cipher suite is in the 1.3 AEAD set. The Config Min==Max==1.3
// makes a 1.2/1.1/1.0 negotiation impossible — this test is the tooth that
// proves the gate holds on a real handshake.
func TestTLSHandshake_13_Only(t *testing.T) {
	certPath, keyPath, caPath, caCert := meshFixture(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}

	// Assert the server config is 1.3-only at the source (the gate).
	scfg := tr.ServerConfig()
	if scfg.MinVersion != tls.VersionTLS13 || scfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("server Min=%x Max=%x, want both VersionTLS13 (%x)",
			scfg.MinVersion, scfg.MaxVersion, tls.VersionTLS13)
	}
	if scfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server ClientAuth=%v, want RequireAndVerifyClientCert", scfg.ClientAuth)
	}

	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer conn.Close()
		// Force the server-side handshake to complete so ConnectionState is
		// populated; a raw Accept does not drive the handshake.
		if tc, ok := conn.(*tls.Conn); ok {
			srvDone <- tc.Handshake()
			return
		}
		srvDone <- nil
	}()

	// Client: present the leaf as a client cert (mTLS), verify the server
	// cert against the CA pool with ServerName "node-1".
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	ccfg := tr.ClientConfig("node-1")
	conn, err := tls.Dial("tcp", addr, ccfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client Handshake: %v", err)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("server Handshake: %v", err)
	}

	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated Version=%x, want VersionTLS13 (%x)", st.Version, tls.VersionTLS13)
	}
	switch st.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		// ok — the 1.3 AEAD set
	default:
		t.Fatalf("negotiated CipherSuite=%x (%s), want a 1.3 AEAD suite (AES_128_GCM_SHA256 or AES_256_GCM_SHA384)",
			st.CipherSuite, tls.CipherSuiteName(st.CipherSuite))
	}
	// No 1.2/1.1/1.0 suite can be negotiated when Min==Max==1.3; the Version
	// assertion above is the proof. Belt-and-braces: the suite name must not
	// carry a TLS 1.2 marker.
	if name := tls.CipherSuiteName(st.CipherSuite); strings.Contains(name, "TLS_RSA") || strings.Contains(name, "ECDHE_RSA") {
		t.Fatalf("negotiated a non-1.3 suite: %s", name)
	}
}

// TestTLSRejectWithoutClientCert (G01.c) asserts a dial with NO client cert
// FAILS the handshake — the RequireAndVerifyClientCert gate rejects an
// unauthenticated peer. The error is the stdlib's mTLS-reject message; we
// match it loosely (do not over-constrain on an exact internal string).
func TestTLSRejectWithoutClientCert(t *testing.T) {
	certPath, keyPath, caPath, caCert := meshFixture(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// The authoritative proof the mTLS gate fired is the SERVER-side
	// Handshake error: under RequireAndVerifyClientCert the server aborts
	// when the client presents no cert. (In TLS 1.3 the client's Handshake
	// returns before the server verifies the client cert, so the client
	// Dial may not surface the reject immediately; the server-side error is
	// deterministic.)
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		if tc, ok := conn.(*tls.Conn); ok {
			srvErr <- tc.Handshake() // expected to fail; the client is rejected
			return
		}
		srvErr <- nil
	}()

	// Client with NO client cert and NO GetClientCertificate hook. It still
	// trusts the CA (so the failure is specifically the missing client cert,
	// not an unknown-server-authority failure).
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	noClientCertCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "node-1",
		// deliberately no client cert
	}
	conn, err := tls.Dial("tcp", addr, noClientCertCfg)
	if err == nil {
		// TLS 1.3 client handshake can complete before the server verifies
		// the client cert; drive a round-trip to surface the server's reject
		// alert, then fall through to the server-side assertion below.
		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 4)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rerr := conn.Read(buf)
		conn.Close()
		if rerr == nil {
			t.Fatal("dial with no client cert succeeded AND a round-trip read returned clean; RequireAndVerifyClientCert gate did not fire")
		}
	} else {
		conn.Close()
	}
	// The server-side Handshake MUST fail with a certificate-related error —
	// this is the deterministic proof the gate fired.
	serr := <-srvErr
	if serr == nil {
		t.Fatal("server Handshake succeeded for a no-client-cert dial; RequireAndVerifyClientCert gate did not fire")
	}
	msg := serr.Error()
	if !strings.Contains(msg, "certificate") && !strings.Contains(msg, "bad certificate") {
		t.Fatalf("server-side reject error does not look like an mTLS reject: %q", msg)
	}
}

// TestTLSCertRotation_SIGHUP (G01.d) asserts that after writing a NEW leaf
// to the same paths and calling Reload(), a re-Dial presents the NEW leaf
// (distinguished by SerialNumber) within 5s. The SIGHUP handler in the
// binary calls Reload(); this test drives Reload() directly to prove the
// live-reload seam works end-to-end.
func TestTLSCertRotation_SIGHUP(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf1, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf #1: %v", err)
	}
	certPath, keyPath, err := leaf1.WritePEM(dir)
	if err != nil {
		t.Fatalf("WritePEM #1: %v", err)
	}
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}

	// Capture the original leaf serial.
	origSerial := leaf1.LeafCert().SerialNumber

	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	_ = srvErr

	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())

	// Dial #1: confirm the original leaf is presented.
	dialAndReadLeaf := func() *x509.Certificate {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, tr.ClientConfig("node-1"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			t.Fatalf("Handshake: %v", err)
		}
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			t.Fatal("no peer certs presented")
		}
		return certs[0]
	}
	first := dialAndReadLeaf()
	if first.SerialNumber.Cmp(origSerial) != 0 {
		t.Fatalf("dial #1 presented serial %s, want original %s", first.SerialNumber, origSerial)
	}

	// Mint a NEW leaf to the SAME paths (new key + new serial).
	leaf2, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf #2: %v", err)
	}
	if _, _, err := leaf2.WritePEM(dir); err != nil {
		t.Fatalf("WritePEM #2: %v", err)
	}
	newSerial := leaf2.LeafCert().SerialNumber
	if newSerial.Cmp(origSerial) == 0 {
		t.Fatal("new leaf serial == original serial; rotation test cannot distinguish them")
	}

	// SIGHUP handler target: Reload() re-reads the on-disk leaf.
	if err := tr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Re-Dial within 5s and assert the NEW leaf is presented.
	deadline := time.Now().Add(5 * time.Second)
	var presented *x509.Certificate
	for time.Now().Before(deadline) {
		presented = dialAndReadLeaf()
		if presented.SerialNumber.Cmp(newSerial) == 0 {
			break // new leaf live
		}
		// The live leaf may not have swapped into the hook yet on the first
		// post-Reload dial; retry within the 5s window.
	}
	if presented == nil || presented.SerialNumber.Cmp(newSerial) != 0 {
		t.Fatalf("post-Reload dial presented serial %s, want NEW %s (SIGHUP live-reload did not surface the new leaf within 5s)",
			presented.SerialNumber, newSerial)
	}
}
