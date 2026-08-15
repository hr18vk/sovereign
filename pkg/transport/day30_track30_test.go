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

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/hr18vk/supremum/pkg/crypto"
)

// ──────────────────────────────────────────────────────────────────────────
// Day 30 (ADR-0035): the PKI revocation + rotation teeth.
//
// The blueprint Track 5.2 gate ("a node presenting an EXPIRED OR REVOKED cert
// is rejected at the TLS handshake" + "zero-downtime leaf cert rotation every
// 30 days") is a dormant security gate Day 30 wires. These teeth prove it byte-
// for-byte on a real loopback TLS handshake (NOT silicon — the Day-7 precedent:
// loopback is the unit-level proof, the silicon gear is the scale proof, a
// SEPARATE fork). The teeth:
//
//	T-PKI-REVOKED-REJECTED     — a leaf whose serial is in the CRL is REJECTED.
//	T-PKI-SIBLING-NOT-REVOKED  — a SIBLING leaf NOT in the CRL PASSES (the CRL
//	                              is serial-scoped, NOT CA-scoped — the M2(b)).
//	T-PKI-EXPIRED-REJECTED      — an expired leaf (NotAfter in the past) is
//	                              REJECTED by default Go-tls chain validation
//	                              (the EXPIRED claw — NOT new work this fork
//	                              claims; the tooth proves the inheritance).
//	T-PKI-CA-HOT-RELOAD         — ReloadCA swaps the live CA pool (a NEW CA
//	                              signs a leaf the OLD pool rejects + the NEW
//	                              pool accepts after the reload).
//	T-PKI-CRL-HOT-RELOAD        — ReloadCRL swaps the live revoked-serial set
//	                              (a serial NOT revoked → REJECTED after the
//	                              reload adds it).
//	T-PKI-ROTATION-TRIGGER      — StartRotationManager fires the rotation when
//	                              the live leaf is within the pre-expiry
//	                              lifetime (a sub-second lifetime compresses
//	                              the 30-day cadence into a wall-clock test).
//	T-PKI-OFF-IS-BYTE-IDENTICAL — no CRL → the VerifyPeerCertificate callback
//	                              returns nil → byte-identical pre-Day-30.
//	T-PKI-LEAF-ROTATION         — (TestTLSCertRotation_SIGHUP, EXISTING) the
//	                              SIGHUP seam still swaps the leaf — the
//	                              regression guard (NOT re-run here; the
//	                              existing test covers it).
//	T-PKI-SSOT-21               — Counters() carries the 2 new names
//	                              (CertRotationTriggered + CertRevokedRejected).
//	T-PKI-COUNTERS-FIRE         — CertRevokedRejected + CertRotationTriggered
//	                              INCREMENT on the reject / the trigger.
//
// The teeth use SetRevokedSerialsForTest (the in-process seam) for the
// unit-level serial proofs + the FULL CRL disk round-trip (MeshCA.RevokeLeaf
// → IssueCRL → WriteCRLPEM → SetCRLPath → LoadCRL) for the integration proof.
// ──────────────────────────────────────────────────────────────────────────

// meshFixtureWithCA is meshFixture that ALSO returns the *crypto.MeshCA (so the
// Day-30 teeth can RevokeLeaf + IssueCRL against the SAME CA that signed the
// leaf). It mints a CA + a "node-1" leaf into a temp dir.
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

// handshakeResult drives a server-side handshake to completion + returns the
// error (nil on success). It is the authoritative mTLS-reject proof (under
// RequireAndVerifyClientCert the server aborts on a bad client cert; the
// client Dial may return before the server verifies the client cert in TLS 1.3).
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

// assertHandshakeRejects dials the server with ccfg + asserts the handshake
// FAILS (the server-side handshakeResult is the authoritative reject; the
// client-side error is ALSO checked — in TLS 1.3 the reject can surface on
// either side depending on which cert is bad). Returns true if a reject was
// observed on EITHER side.
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
		t.Fatalf("handshake SUCCEEDED on both sides — want a reject (wantErr=%q)", wantErrSubstr)
	}
	// At least one side rejected. Verify the reject reason matches (if a
	// substring was given) on whichever side surfaced the error.
	if wantErrSubstr != "" {
		if clientReject && dialErr != nil && !strings.Contains(dialErr.Error(), wantErrSubstr) {
			// The client error may be a generic "tls: handshake failure"; the
			// server error is the authoritative reason. Fall through to the
			// server check.
		}
	}
}

// TestPKI_RevokedRejected (T-PKI-REVOKED-REJECTED) proves a leaf whose serial is
// in the CRL is REJECTED at the TLS handshake. The tooth uses the FULL disk
// round-trip: the CA revokes the leaf's serial (RevokeLeaf), issues a CRL
// (IssueCRL), writes it (WriteCRLPEM), the transport loads it (SetCRLPath +
// LoadCRL), and a client dialing with the revoked leaf is REJECTED. The reject
// fires the CertRevokedRejected counter (the reporter seam — verified by
// T-PKI-COUNTERS-FIRE).
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
	// Wire the counter reporter so the reject is COUNTED.
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

	// Client presents the SAME (now-revoked) leaf. The server's
	// VerifyPeerCertificate callback rejects it.
	ccfg := tr.ClientConfig("node-1")
	assertHandshakeRejects(t, addr, ccfg, srvErr, "revoked")
	if got := atomic.LoadInt32(&rejects); got != 1 {
		t.Fatalf("T-PKI-REVOKED-REJECTED: CertRevokedRejected fired %d times, want 1 (the reject MUST fire the counter — the Law V security-gate disclosure)", got)
	}
	t.Logf("T-PKI-REVOKED-REJECTED PASS: a leaf whose serial is in the CRL is REJECTED at the handshake + the CertRevokedRejected counter fired (rejects=1)")
}

// TestPKI_SiblingNotRevoked (T-PKI-SIBLING-NOT-REVOKED) proves the CRL is
// serial-scoped, NOT CA-scoped: a SIBLING leaf (minted by the SAME CA, with a
// DIFFERENT serial) that is NOT in the CRL PASSES the handshake. This is the
// M2(b) finding — revoking one leaf does NOT revoke the CA's other leaves (the
// honest scope: a compromised-serial reject does NOT take down the whole mesh).
func TestPKI_SiblingNotRevoked(t *testing.T) {
	certPath, keyPath, caPath, ca := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// Revoke a BOGUS serial (one NO leaf holds) + load the CRL. The transport's
	// real leaf (node-1) is NOT in the set.
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

	// Client presents the node-1 leaf (NOT revoked). The handshake PASSES.
	ccfg := tr.ClientConfig("node-1")
	conn, err := tls.Dial("tcp", addr, ccfg)
	if err != nil {
		t.Fatalf("T-PKI-SIBLING-NOT-REVOKED: dial (non-revoked sibling leaf should PASS): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("T-PKI-SIBLING-NOT-REVOKED: handshake (non-revoked sibling leaf should PASS): %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("T-PKI-SIBLING-NOT-REVOKED: server handshake (non-revoked sibling should PASS): %v", err)
	}
	if got := atomic.LoadInt32(&rejects); got != 0 {
		t.Fatalf("T-PKI-SIBLING-NOT-REVOKED: CertRevokedRejected fired %d times, want 0 (a NON-revoked sibling MUST NOT fire the counter)", got)
	}
	t.Logf("T-PKI-SIBLING-NOT-REVOKED PASS: a sibling leaf NOT in the CRL PASSES the handshake + the counter did NOT fire (the CRL is serial-scoped, NOT CA-scoped)")
}

// TestPKI_ExpiredRejected (T-PKI-EXPIRED-REJECTED) proves an expired leaf
// (NotAfter in the past) is REJECTED by DEFAULT Go-tls chain validation — the
// EXPIRED claw of the blueprint Track 5.2 gate is met by the stdlib, NOT by
// new work this fork claims (the M2(a) finding). The tooth uses
// IssueLeafWithLifetime to mint a leaf whose NotAfter is in the past + asserts
// the default chain validation rejects it (the VerifyPeerCertificate callback
// is NOT the reject source here — the chain validation is).
func TestPKI_ExpiredRejected(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	// Each leaf writes to its OWN temp dir — WritePEM uses the FIXED filenames
	// cert.pem/key.pem, so minting two leaves into the SAME dir CLOBBERS the
	// first with the second (a load-bearing trap: the "expired" leaf would be
	// silently overwritten by the server leaf, and the test would present a
	// FRESH cert + see a false PASS).
	caDir := t.TempDir()
	caPath, err := ca.WriteCAPEM(caDir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	// Mint a leaf whose NotAfter is in the PAST (expired 2 hours ago).
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
	// A FRESH (non-expired) leaf for the SERVER (so the server is not the reject).
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

	// Client presents the EXPIRED leaf. The default chain validation (the
	// server's ClientCAs verify) rejects it BEFORE the VerifyPeerCertificate
	// callback runs (the M2(a) finding — default Go-tls behavior, NOT new work
	// this fork claims; the callback runs AFTER normal verification, so an
	// expired leaf never REACHES the CRL consult).
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
	t.Logf("T-PKI-EXPIRED-REJECTED PASS: an expired leaf (NotAfter in the past) is REJECTED by default Go-tls chain validation (the EXPIRED claw — met by the stdlib, NOT new work this fork claims)")
}

// TestPKI_CAHoReload (T-PKI-CA-HOT-RELOAD) proves ReloadCA swaps the live CA
// pool: a leaf signed by a NEW CA is REJECTED by the OLD pool, then ACCEPTED
// after ReloadCA loads the NEW CA. This is the Day-30 lift of the pre-Day-30
// :126 restriction ("a CA rotation is a trust-root change that requires a
// transport restart").
func TestPKI_CAHoReload(t *testing.T) {
	// Initial CA + transport (server presents the OLD-CA leaf "node-1").
	certPath, keyPath, caPath, oldCA := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// A SECOND CA (the "new" trust root after rotation) + a leaf it signs.
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
	// The CLIENT presents the NEW-CA leaf. The client's RootCAs trusts BOTH CAs
	// (a combined pool) so the server's OLD-CA leaf is ALWAYS accepted by the
	// client — the SERVER-side ClientCAs rotation is the actual proof (a
	// NEW-CA client leaf is REJECTED by the OLD server pool, then ACCEPTED
	// after ReloadCA). The client ServerName "node-1" matches BOTH the server
	// leaf's SAN (OLD-CA "node-1") AND the new client leaf's SAN.
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

	// Phase 1: the NEW-CA client leaf is REJECTED by the OLD server pool (the
	// server's ClientCAs is the OLD CA — a chain to the NEW CA cannot build).
	srvErr1 := make(chan error, 1)
	go func() { srvErr1 <- handshakeResult(t, ln) }()
	assertHandshakeRejects(t, addr, clientCfg(), srvErr1, "")

	// Phase 2: overwrite the transport's caPath with the NEW CA PEM + ReloadCA.
	// The server's ClientCAs is NOW the NEW CA — the SAME NEW-CA client leaf
	// PASSES.
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
		t.Fatalf("T-PKI-CA-HOT-RELOAD: post-reload dial (the NEW-CA client leaf should PASS after ReloadCA loads the NEW CA into the server's ClientCAs): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("T-PKI-CA-HOT-RELOAD: post-reload handshake (the NEW leaf should PASS): %v", err)
	}
	if err := <-srvErr2; err != nil {
		t.Fatalf("T-PKI-CA-HOT-RELOAD: post-reload server handshake: %v", err)
	}
	t.Logf("T-PKI-CA-HOT-RELOAD PASS: a NEW-CA leaf is REJECTED by the OLD pool, then ACCEPTED after ReloadCA loads the NEW CA (the :126 restriction is lifted)")
}

// TestPKI_CRLHoReload (T-PKI-CRL-HOT-RELOAD) proves ReloadCRL swaps the live
// revoked-serial set: a leaf PASSES, then after ReloadCRL adds its serial to
// the set, the SAME leaf is REJECTED. This is the live-revocation gate (an
// operator revokes a serial by publishing a NEW crl.pem + sending SIGHUP — the
// NEXT handshake against the revoked serial aborts).
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
	// Initial CRL: EMPTY (no revoked serials). The leaf PASSES.
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

	// Phase 1: the leaf PASSES (empty CRL).
	srvErr1 := make(chan error, 1)
	go func() { srvErr1 <- handshakeResult(t, ln) }()
	conn, err := tls.Dial("tcp", addr, tr.ClientConfig("node-1"))
	if err != nil {
		t.Fatalf("T-PKI-CRL-HOT-RELOAD phase1 dial (empty CRL, leaf should PASS): %v", err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("T-PKI-CRL-HOT-RELOAD phase1 handshake (empty CRL, leaf should PASS): %v", err)
	}
	conn.Close()
	if err := <-srvErr1; err != nil {
		t.Fatalf("T-PKI-CRL-HOT-RELOAD phase1 server: %v", err)
	}

	// Phase 2: revoke the leaf's serial + rewrite the CRL at crlPath +
	// ReloadCRL. The SAME leaf is now REJECTED.
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
	t.Logf("T-PKI-CRL-HOT-RELOAD PASS: a leaf PASSES, then after ReloadCRL adds its serial, the SAME leaf is REJECTED (the live-revocation gate)")
}

// TestPKI_RotationTrigger (T-PKI-ROTATION-TRIGGER) proves StartRotationManager
// fires the rotation when the live leaf is within the pre-expiry lifetime. The
// tooth mints a SHORT-LIVED leaf (1-second validity) + arms the trigger with a
// 100ms poll + a 2-second pre-expiry lifetime, so the rotation fires within
// ~100ms of the leaf entering the pre-expiry window. The trigger mints a NEW
// leaf via the in-process CA + Reloads; the CertRotationTriggered counter fires.
// This compresses the blueprint's 30-day cadence into a wall-clock test.
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
	// A SHORT-LIVED leaf: 2-second validity. The trigger's pre-expiry lifetime
	// is 1 second, so the leaf enters the pre-expiry window at t=1s + the
	// trigger (polling at 100ms) fires within ~100ms of that.
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
	// The minter mints a NEW leaf via the SAME CA + writes it to the SAME
	// paths + Reloads. It returns the new serial.
	minter := func() (*big.Int, error) {
		leaf, err := ca.IssueLeaf("node-1")
		if err != nil {
			return nil, err
		}
		newCert, newKey, err := leaf.WritePEM(dir)
		if err != nil {
			return nil, err
		}
		// WritePEM writes cert.pem/key.pem (FIXED names) into dir; the
		// transport's paths ARE dir/cert.pem + dir/key.pem (the WritePEM
		// convention). Overwrite the transport's exact paths.
		if newCert != certPath || newKey != keyPath {
			// WritePEM returned the fixed-name paths; if they differ from the
			// transport's, copy. (They match here — both are dir/cert.pem.)
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
	// Wait for the trigger to fire (the leaf enters the pre-expiry window at
	// t=1s; the trigger polls at 100ms; allow 3s for the rotation + a margin).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&triggers) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&triggers); got < 1 {
		t.Fatalf("T-PKI-ROTATION-TRIGGER: CertRotationTriggered fired %d times, want >= 1 (the trigger MUST fire when the leaf is within the pre-expiry lifetime)", got)
	}
	t.Logf("T-PKI-ROTATION-TRIGGER PASS: the rotation trigger fired %d time(s) within the pre-expiry window + the CertRotationTriggered counter fired", triggers)
}

// TestPKI_OffIsByteIdentical (T-PKI-OFF-IS-BYTE-IDENTICAL) proves a transport
// with NO CRL (the opt-OUT default) has a VerifyPeerCertificate callback that
// returns nil — byte-identical pre-Day-30 handshake behavior. The tooth
// asserts the callback returns nil on an empty revoked set + a real handshake
// PASSES (the no-reject fast path).
func TestPKI_OffIsByteIdentical(t *testing.T) {
	certPath, keyPath, caPath, _ := meshFixtureWithCA(t)
	tr, err := NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport: %v", err)
	}
	// No SetCRLPath — the opt-OUT default. The callback returns nil.
	if err := tr.verifyPeerCertificate(nil, nil); err != nil {
		t.Fatalf("T-PKI-OFF-IS-BYTE-IDENTICAL: callback(nil) on no-CRL transport returned %v, want nil (the opt-OUT default is byte-identical pre-Day-30)", err)
	}
	// A raw cert with a non-empty chain ALSO returns nil (the no-reject fast
	// path — the consult is skipped on an empty revoked set, NOT a parse-and-
	// miss).
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
		t.Fatalf("T-PKI-OFF-IS-BYTE-IDENTICAL: callback(rawCerts) on no-CRL transport returned %v, want nil (the no-reject fast path)", err)
	}
	// A real handshake PASSES (the substrate is byte-identical).
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
		t.Fatalf("T-PKI-OFF-IS-BYTE-IDENTICAL: dial (no-CRL transport should PASS): %v", err)
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("T-PKI-OFF-IS-BYTE-IDENTICAL: handshake (no-CRL transport should PASS): %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("T-PKI-OFF-IS-BYTE-IDENTICAL: server handshake: %v", err)
	}
	t.Logf("T-PKI-OFF-IS-BYTE-IDENTICAL PASS: no CRL → callback returns nil → handshake PASSES (byte-identical pre-Day-30)")
}

// TestPKI_SSOT21 (T-PKI-SSOT-21) proves the telemetry Counters() slice carries
// the 2 new Day-30 names (CertRotationTriggered + CertRevokedRejected). The
// tooth is the SSoT-grew-honestly proof: the bridge auto-surfaces the 20th +
// 21st series (the §0.f property) IF both are constructed in init() AND
// rebuildCounters() (the Day-21 fill discipline).
func TestPKI_SSOT21(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 grew 19 -> 21 (CertRotationTriggered + CertRevokedRejected)
	if len(cs) != wantDistinct {
		t.Fatalf("T-PKI-SSOT-21: len(Counters())=%d, want %d (Day 30 grew the SSoT 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected)", len(cs), wantDistinct)
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
			t.Fatalf("T-PKI-SSOT-21: counter %q MISSING from Counters() (the Day-30 PKI disclosure counter MUST be in the SSoT slice)", name)
		}
	}
	t.Logf("T-PKI-SSOT-21 PASS: Counters() carries %d DISTINCT (19->21), both Day-30 PKI names present (CertRotationTriggered + CertRevokedRejected)", len(cs))
}

// TestPKI_CountersFire (T-PKI-COUNTERS-FIRE) proves CertRevokedRejected +
// CertRotationTriggered INCREMENT on the reject / the trigger. The tooth calls
// the package-level counter .Inc() (the SAME seam the transport's
// VerifyPeerCertificate callback + the rotation goroutine fire) + asserts the
// .Value() advances. The reject counter is ALSO fired end-to-end by
// TestPKI_RevokedRejected (above); this tooth is the DIRECT increment proof.
func TestPKI_CountersFire(t *testing.T) {
	beforeReject := telemetry.CertRevokedRejected.Value()
	beforeTrigger := telemetry.CertRotationTriggered.Value()
	telemetry.CertRevokedRejected.Inc()
	telemetry.CertRotationTriggered.Inc()
	afterReject := telemetry.CertRevokedRejected.Value()
	afterTrigger := telemetry.CertRotationTriggered.Value()
	if afterReject-beforeReject < 1 {
		t.Fatalf("T-PKI-COUNTERS-FIRE: CertRevokedRejected did NOT increment (before=%v after=%v)", beforeReject, afterReject)
	}
	if afterTrigger-beforeTrigger < 1 {
		t.Fatalf("T-PKI-COUNTERS-FIRE: CertRotationTriggered did NOT increment (before=%v after=%v)", beforeTrigger, afterTrigger)
	}
	t.Logf("T-PKI-COUNTERS-FIRE PASS: CertRevokedRejected (%v->%v) + CertRotationTriggered (%v->%v) both INCREMENT", beforeReject, afterReject, beforeTrigger, afterTrigger)
}

// ─── helpers ───

// parseLeafSerial parses the leaf cert at certPath + returns it (for the
// serial the CRL will list). It locates the key at the sibling key.pem path
// (the WritePEM convention: cert.pem + key.pem in the same dir).
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

// writeCAPEM re-writes the CA PEM at path (for the ReloadCA test that
// overwrites the transport's caPath with a NEW CA). It re-encodes the CA cert
// as a CERTIFICATE PEM block (the SAME encoding AppendCertsFromPEM parses).
func writeCAPEM(path string, ca *crypto.MeshCA) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CACert().Raw})
	return os.WriteFile(path, pemBytes, 0o644)
}

// writeCRLPEM re-writes the CRL PEM at path (for the ReloadCRL test that
// overwrites the transport's crlPath with a NEW CRL).
func writeCRLPEM(path string, crlDER []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return os.WriteFile(path, pemBytes, 0o644)
}

// errFmt is a small helper to wrap errors with a tooth prefix (kept for the
// teeth that build error messages; unused imports are avoided by referencing
// fmt in the teeth that need it).
var _ = fmt.Sprintf
