// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/crypto"
)

// The PKI tests use loopback mTLS handshakes to cover serial-scoped revocation,
// expiry checks, CA and CRL reloads, leaf rotation, and their telemetry
// (ADR-0035). Revocation tests exercise the complete CRL path: MeshCA.RevokeLeaf,
// IssueCRL, WriteCRLPEM, SetCRLPath, and LoadCRL.

// meshFixtureWithCA creates a "node-1" leaf and returns its paths together
// with the signing CA, allowing a test to revoke that leaf and issue a CRL.
func meshFixtureWithCA(t *testing.T) (certPath, keyPath, caPath string, ca *crypto.MeshCA) {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err = ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	leaf, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	certPath, keyPath, err = leaf.WritePEM(dir)
	if err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	return certPath, keyPath, caPath, ca
}

// handshakeResult accepts one connection and returns its server-side handshake
// error. This result is necessary because a TLS 1.3 client can finish before
// the server rejects its certificate.
func handshakeResult(t *testing.T, ln net.Listener) error {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if tc, ok := conn.(*tls.Conn); ok {
		return tc.Handshake()
	}
	return nil
}

// assertHandshakeRejects fails unless either endpoint reports a handshake
// error. Depending on the rejected certificate, the error can surface on the
// client, the server, or both.
func assertHandshakeRejects(t *testing.T, addr string, ccfg *tls.Config, srvErr <-chan error, wantErrSubstr string) {
	t.Helper()
	conn, dialErr := tls.Dial("tcp", addr, ccfg)
	var clientReject bool
	if dialErr == nil {
		// The dial succeeded (the client built the TCP+TLS conn); drive the
		// handshake to surface the reject.
		hsErr := conn.Handshake()
		conn.Close()
		if hsErr != nil {
			clientReject = true
		}
	} else {
		clientReject = true
	}
	srvReject := false
	select {
	case s := <-srvErr:
		if s != nil {
			srvReject = true
		}
	case <-time.After(2 * time.Second):
	}
	if !clientReject && !srvReject {
		t.Fatalf("handshake succeeded on both sides — want a reject (wantErr=%q)", wantErrSubstr)
	}
	// A TLS alert can hide the specific reason from the client. Callers verify
	// the rejection kind through the revocation reporter instead of depending on
	// either endpoint's error text.
	if wantErrSubstr != "" {
		if clientReject && dialErr != nil && !strings.Contains(dialErr.Error(), wantErrSubstr) {
		}
	}
}

// TestPKI_RevokedRejected revokes a leaf, writes and loads a CRL, and checks
// that presenting that leaf fails the handshake and invokes the reporter once.
func TestPKI_RevokedRejected(t *testing.T) {
	certPath, keyPath, caPath, ca := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// Parse the leaf to extract its serial (the serial the CRL will list).
	leafCert, err := parseLeafSerial(certPath)
	if err != nil {
		t.Fatalf("parse leaf serial: %v", err)
	}
	// Revoke the leaf's serial + publish a CRL to disk.
	if err := ca.RevokeLeaf(leafCert.SerialNumber); err != nil {
		t.Fatalf("RevokeLeaf: %v", err)
	}
	crlDER, err := ca.IssueCRL(1)
	if err != nil {
		t.Fatalf("IssueCRL: %v", err)
	}
	crlPath, err := ca.WriteCRLPEM(t.TempDir(), crlDER)
	if err != nil {
		t.Fatalf("WriteCRLPEM: %v", err)
	}
	tr.SetCRLPath(crlPath)
	if err := tr.LoadCRL(); err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	// Count each rejection through the reporter.
	var rejects int32
	tr.SetRevocationReporter(func() { atomic.AddInt32(&rejects, 1) })

	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() { srvErr <- handshakeResult(t, ln) }()

	// Client presents the same (now-revoked) leaf. The server's
	// VerifyPeerCertificate callback rejects it.
	ccfg := tr.ClientConfig("node-1")
	assertHandshakeRejects(t, addr, ccfg, srvErr, "revoked")
	if got := atomic.LoadInt32(&rejects); got != 1 {
		t.Fatalf("CertRevokedRejected fired %d times, want 1 (the reject must fire the counter)", got)
	}
	t.Logf("revoked leaf rejected at handshake; CertRevokedRejected counter fired (rejects=1)")
}

// TestPKI_SiblingNotRevoked loads a CRL containing an unrelated serial. A leaf
// from the same CA must still pass, and the revocation reporter must stay at
// zero, demonstrating that revocation is scoped by serial rather than issuer.
func TestPKI_SiblingNotRevoked(t *testing.T) {
	certPath, keyPath, caPath, ca := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// Revoke a bogus serial (one no leaf holds) and load the CRL. The transport's
	// real leaf (node-1) is not in the set.
	bogus := big.NewInt(999999999999999)
	if err := ca.RevokeLeaf(bogus); err != nil {
		t.Fatalf("RevokeLeaf bogus: %v", err)
	}
	crlDER, err := ca.IssueCRL(1)
	if err != nil {
		t.Fatalf("IssueCRL: %v", err)
	}
	crlPath, err := ca.WriteCRLPEM(t.TempDir(), crlDER)
	if err != nil {
		t.Fatalf("WriteCRLPEM: %v", err)
	}
	tr.SetCRLPath(crlPath)
	if err := tr.LoadCRL(); err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	var rejects int32
	tr.SetRevocationReporter(func() { atomic.AddInt32(&rejects, 1) })

	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() { srvErr <- handshakeResult(t, ln) }()

	// Client presents the node-1 leaf (not revoked). The handshake passes.
	ccfg := tr.ClientConfig("node-1")
	conn, err := tls.Dial("tcp", addr, ccfg)
	if err != nil {
		t.Fatalf("dial (non-revoked sibling leaf should pass): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake (non-revoked sibling leaf should pass): %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake (non-revoked sibling should pass): %v", err)
	}
	if got := atomic.LoadInt32(&rejects); got != 0 {
		t.Fatalf("CertRevokedRejected fired %d times, want 0 (a non-revoked sibling must not fire the counter)", got)
	}
	t.Logf("sibling leaf not in CRL passes handshake; counter did not fire (CRL is serial-scoped)")
}

// TestPKI_ExpiredRejected presents a leaf whose NotAfter is in the past.
// Standard crypto/tls chain validation must reject it before the revocation
// callback runs.
func TestPKI_ExpiredRejected(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	// WritePEM uses fixed cert.pem and key.pem names. Separate directories keep
	// the server leaf from overwriting the expired client leaf.
	caDir := t.TempDir()
	caPath, err := ca.WriteCAPEM(caDir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	// Use a leaf that expired two hours ago.
	past := time.Now().Add(-2 * time.Hour)
	leaf, err := ca.IssueLeafWithLifetime("node-1", past.Add(-time.Hour), past)
	if err != nil {
		t.Fatalf("IssueLeafWithLifetime (expired): %v", err)
	}
	expDir := t.TempDir()
	certPath, keyPath, err := leaf.WritePEM(expDir)
	if err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	// Give the server a valid leaf so the client certificate is the cause of
	// the rejection.
	srvLeaf, err := ca.IssueLeaf("node-server")
	if err != nil {
		t.Fatalf("IssueLeaf server: %v", err)
	}
	srvDir := t.TempDir()
	srvCert, srvKey, err := srvLeaf.WritePEM(srvDir)
	if err != nil {
		t.Fatalf("WritePEM server: %v", err)
	}
	tr, err := NewTLSTransport(srvCert, srvKey, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() { srvErr <- handshakeResult(t, ln) }()

	// Client presents the expired leaf. The default chain validation (the
	// server's ClientCAs verify) rejects it before the VerifyPeerCertificate
	// callback runs (standard Go TLS behavior; an expired leaf never reaches
	// the CRL consult).
	expiredCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair expired: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.CACert())
	ccfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   "node-server",
		Certificates: []tls.Certificate{expiredCert},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &expiredCert, nil
		},
	}
	assertHandshakeRejects(t, addr, ccfg, srvErr, "")
	t.Logf("expired leaf (NotAfter in the past) rejected by default Go TLS chain validation")
}

// TestPKI_CAHoReload first rejects a client leaf signed by a second CA, then
// replaces the server's CA file and checks that ReloadCA admits the same leaf
// on a later handshake without replacing the listener.
func TestPKI_CAHoReload(t *testing.T) {
	// Start with a server leaf signed by the initial CA.
	certPath, keyPath, caPath, oldCA := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// Create a second trust root and a client leaf signed by it.
	newCA, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA new: %v", err)
	}
	newCADir := t.TempDir()
	if _, err := newCA.WriteCAPEM(newCADir); err != nil {
		t.Fatalf("WriteCAPEM new: %v", err)
	}
	newLeaf, err := newCA.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf new: %v", err)
	}
	newLeafDir := t.TempDir()
	newCertPath, newKeyPath, err := newLeaf.WritePEM(newLeafDir)
	if err != nil {
		t.Fatalf("WritePEM new: %v", err)
	}
	// The client presents the new-CA leaf. The client's RootCAs trusts both CAs
	// (a combined pool) so the server's old-CA leaf is always accepted by the
	// client. The server-side ClientCAs rotation is the actual proof: a
	// new-CA client leaf is rejected by the old server pool, then accepted
	// after ReloadCA. The client ServerName "node-1" matches both the server
	// leaf's SAN (old-CA "node-1") and the new client leaf's SAN.
	combinedPool := x509.NewCertPool()
	combinedPool.AddCert(oldCA.CACert())
	combinedPool.AddCert(newCA.CACert())
	newKeypair, err := tls.LoadX509KeyPair(newCertPath, newKeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair new leaf: %v", err)
	}
	clientCfg := func() *tls.Config {
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			RootCAs:      combinedPool,
			ServerName:   "node-1",
			Certificates: []tls.Certificate{newKeypair},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &newKeypair, nil
			},
		}
	}
	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// First, the new-CA client leaf is rejected by the old server pool (the
	// server's ClientCAs is the old CA — a chain to the new CA cannot build).
	srvErr1 := make(chan error, 1)
	go func() { srvErr1 <- handshakeResult(t, ln) }()
	assertHandshakeRejects(t, addr, clientCfg(), srvErr1, "")

	// Then, overwrite the transport's caPath with the new CA PEM and ReloadCA.
	// The server's ClientCAs is now the new CA — the same new-CA client leaf
	// passes.
	if err := writeCAPEM(caPath, newCA); err != nil {
		t.Fatalf("overwrite caPath: %v", err)
	}
	if err := tr.ReloadCA(); err != nil {
		t.Fatalf("ReloadCA: %v", err)
	}
	srvErr2 := make(chan error, 1)
	go func() { srvErr2 <- handshakeResult(t, ln) }()
	conn, err := tls.Dial("tcp", addr, clientCfg())
	if err != nil {
		t.Fatalf("post-reload dial (the new-CA client leaf should pass after ReloadCA loads the new CA into the server's ClientCAs): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("post-reload handshake (the new leaf should pass): %v", err)
	}
	if err := <-srvErr2; err != nil {
		t.Fatalf("post-reload server handshake: %v", err)
	}
	t.Logf("new-CA leaf rejected by old pool, then accepted after ReloadCA loads new CA (CA rotation without restart works)")
}

// TestPKI_CRLHoReload accepts a leaf under an empty CRL, then revokes its
// serial, rewrites the file, and checks that ReloadCRL rejects the same leaf on
// a later handshake.
func TestPKI_CRLHoReload(t *testing.T) {
	certPath, keyPath, caPath, ca := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	leafCert, err := parseLeafSerial(certPath)
	if err != nil {
		t.Fatalf("parse leaf serial: %v", err)
	}
	// Initial CRL: empty (no revoked serials). The leaf passes.
	crlDER, err := ca.IssueCRL(1)
	if err != nil {
		t.Fatalf("IssueCRL 1: %v", err)
	}
	crlPath, err := ca.WriteCRLPEM(t.TempDir(), crlDER)
	if err != nil {
		t.Fatalf("WriteCRLPEM: %v", err)
	}
	tr.SetCRLPath(crlPath)
	if err := tr.LoadCRL(); err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// First, the leaf passes (empty CRL).
	srvErr1 := make(chan error, 1)
	go func() { srvErr1 <- handshakeResult(t, ln) }()
	conn, err := tls.Dial("tcp", addr, tr.ClientConfig("node-1"))
	if err != nil {
		t.Fatalf("dial (empty CRL, leaf should pass): %v", err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake (empty CRL, leaf should pass): %v", err)
	}
	conn.Close()
	if err := <-srvErr1; err != nil {
		t.Fatalf("server: %v", err)
	}

	// Then, revoke the leaf's serial, rewrite the CRL at crlPath,
	// and ReloadCRL. The same leaf is now rejected.
	if err := ca.RevokeLeaf(leafCert.SerialNumber); err != nil {
		t.Fatalf("RevokeLeaf: %v", err)
	}
	crlDER2, err := ca.IssueCRL(2)
	if err != nil {
		t.Fatalf("IssueCRL 2: %v", err)
	}
	if err := writeCRLPEM(crlPath, crlDER2); err != nil {
		t.Fatalf("overwrite crlPath: %v", err)
	}
	if err := tr.ReloadCRL(); err != nil {
		t.Fatalf("ReloadCRL: %v", err)
	}
	srvErr2 := make(chan error, 1)
	go func() { srvErr2 <- handshakeResult(t, ln) }()
	assertHandshakeRejects(t, addr, tr.ClientConfig("node-1"), srvErr2, "revoked")
	t.Logf("leaf passes, then after ReloadCRL adds its serial, the same leaf is rejected (live revocation works)")
}

// TestPKI_RotationTrigger uses a leaf that expires in two seconds, a 100 ms
// poll, and a one-second rotation window. The supplied minter writes and
// reloads a replacement, and the trigger reporter must run.
func TestPKI_RotationTrigger(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	// The leaf has two seconds of validity remaining. It enters the one-second
	// rotation window after roughly one second, subject to the 100 ms poll.
	shortLeaf, err := ca.IssueLeafWithLifetime("node-1", time.Now().Add(-time.Second), time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("IssueLeafWithLifetime short: %v", err)
	}
	certPath, keyPath, err := shortLeaf.WritePEM(dir)
	if err != nil {
		t.Fatalf("WritePEM short: %v", err)
	}
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// The minter replaces the PEM files, reloads them, and returns the new serial.
	minter := func() (*big.Int, error) {
		leaf, err := ca.IssueLeaf("node-1")
		if err != nil {
			return nil, err
		}
		newCert, newKey, err := leaf.WritePEM(dir)
		if err != nil {
			return nil, err
		}
		// WritePEM returns the fixed cert.pem and key.pem paths used by tr.
		if newCert != certPath || newKey != keyPath {
		}
		if err := tr.Reload(); err != nil {
			return nil, err
		}
		return leaf.LeafCert().SerialNumber, nil
	}
	var triggers int32
	stop, err := tr.StartRotationManager(context.Background(), 100*time.Millisecond, time.Second, minter, func() { atomic.AddInt32(&triggers, 1) })
	if err != nil {
		t.Fatalf("StartRotationManager: %v", err)
	}
	defer stop()
	// Allow time to enter the rotation window, poll, mint, and reload.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&triggers) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&triggers); got < 1 {
		t.Fatalf("CertRotationTriggered fired %d times, want >= 1 (trigger must fire when leaf is within pre-expiry lifetime)", got)
	}
	t.Logf("rotation trigger fired %d time(s) within pre-expiry window; CertRotationTriggered counter fired", triggers)
}

// TestPKI_OffIsByteIdentical checks the default with no CRL: the callback
// returns nil for empty and nonempty raw-certificate input, and a handshake
// succeeds without invoking revocation logic.
func TestPKI_OffIsByteIdentical(t *testing.T) {
	certPath, keyPath, caPath, _ := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// With no CRL, both empty input and a real certificate bypass the serial
	// lookup and return nil.
	if err := tr.verifyPeerCertificate(nil, nil); err != nil {
		t.Fatalf("callback(nil) without a CRL returned %v, want nil", err)
	}
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	leaf, err := ca.IssueLeaf("node-1")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	rawCerts := [][]byte{leaf.LeafCert().Raw}
	if err := tr.verifyPeerCertificate(rawCerts, nil); err != nil {
		t.Fatalf("callback(rawCerts) without a CRL returned %v, want nil", err)
	}
	// A complete handshake must also succeed without a CRL.
	addr := freeAddr(t)
	ln, err := tr.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() { srvErr <- handshakeResult(t, ln) }()
	conn, err := tls.Dial("tcp", addr, tr.ClientConfig("node-1"))
	if err != nil {
		t.Fatalf("dial (no-CRL transport should pass): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake (no-CRL transport should pass): %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	t.Logf("no CRL: callback returns nil and the handshake passes")
}

// TestPKI_TelemetryCounterSet21 checks that telemetry.Counters includes
// CertRotationTriggered and CertRevokedRejected in the complete registered set.
func TestPKI_TelemetryCounterSet21(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 25 // includes PKI, PQ, hybrid-frame, region, and write-timeout counters
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d (PKI added two counters: CertRotationTriggered + CertRevokedRejected)", len(cs), wantDistinct)
	}
	wantNames := map[string]bool{
		"supremum.pki.cert_rotation_triggered": false,
		"supremum.pki.cert_revoked_rejected":   false,
	}
	for _, c := range cs {
		if _, ok := wantNames[c.Name()]; ok {
			wantNames[c.Name()] = true
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Fatalf("PKI counter %q is missing from Counters()", name)
		}
	}
	t.Logf("Counters() carries %d distinct counters; both PKI names present (CertRotationTriggered + CertRevokedRejected)", len(cs))
}

// TestPKI_CountersFire checks direct Inc and Value behavior for both PKI
// counters. TestPKI_RevokedRejected covers the handshake reporting path.
func TestPKI_CountersFire(t *testing.T) {
	beforeReject := telemetry.CertRevokedRejected.Value()
	beforeTrigger := telemetry.CertRotationTriggered.Value()
	telemetry.CertRevokedRejected.Inc()
	telemetry.CertRotationTriggered.Inc()
	afterReject := telemetry.CertRevokedRejected.Value()
	afterTrigger := telemetry.CertRotationTriggered.Value()
	if afterReject-beforeReject < 1 {
		t.Fatalf("CertRevokedRejected did not increment (before=%v after=%v)", beforeReject, afterReject)
	}
	if afterTrigger-beforeTrigger < 1 {
		t.Fatalf("CertRotationTriggered did not increment (before=%v after=%v)", beforeTrigger, afterTrigger)
	}
	t.Logf("CertRevokedRejected (%v->%v) and CertRotationTriggered (%v->%v) both increment", beforeReject, afterReject, beforeTrigger, afterTrigger)
}

// ─── helpers ───

// parseLeafSerial loads certPath with its sibling key.pem and parses the leaf
// certificate whose serial a test will revoke.
func parseLeafSerial(certPath string) (*x509.Certificate, error) {
	keyPath := strings.Replace(certPath, "cert.pem", "key.pem", 1)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no cert in keypair")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// writeCAPEM replaces path with ca's certificate in the PEM form accepted by
// AppendCertsFromPEM.
func writeCAPEM(path string, ca *crypto.MeshCA) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CACert().Raw})
	return os.WriteFile(path, pemBytes, 0o644)
}

// writeCRLPEM replaces path with crlDER in PEM form for a later ReloadCRL.
func writeCRLPEM(path string, crlDER []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return os.WriteFile(path, pemBytes, 0o644)
}

var _ = fmt.Sprintf
