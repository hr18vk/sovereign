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
	"sync"
	"time"
)

// TLSConnections configures the node's TLS 1.3 transport. It owns the
// certificate, key, CA, and CRL paths; the current CA pool and leaf; and the
// in-memory revoked-serial set. ServerConfig and ClientConfig require mutual
// TLS and reject a presented leaf whose serial appears in the CRL (ADR-0035).
//
// TLS writes use Go's ordinary TCP path. The record layer copies and encrypts
// plaintext before netFD.Write; this transport does not use MSG_ZEROCOPY or
// runtime.Pinner (ADR-0006).
//
// Reload, ReloadCA, and ReloadCRL independently replace the leaf, trust pool,
// and revoked-serial set. Accessors take consistent snapshots under an RWMutex,
// and completed replacements are visible to subsequent configuration and
// verification calls.
type TLSConnections struct {
	caPool              *x509.CertPool
	leaf                *tls.Certificate
	revokedSerials      map[string]bool // serial.Text(10) -> true; nil/empty = no revocation consult
	revocationReporter  func()          // fires on each CRL reject (CertRevokedRejected counter); nil = silent
	pqHandshakeReporter func()          // fires on each PQ-KEM handshake (PQHandshakeNegotiated counter); nil = silent
	certPath            string
	keyPath             string
	caPath              string
	crlPath             string
	mu                  sync.RWMutex
}

// ErrNoCALoaded is returned when the CA PEM at caPath fails to parse or is
// empty; the transport refuses to start without a trust root.
var ErrNoCALoaded = errors.New("transport: no CA certificates loaded from caPath")

// ErrNoCRLPath is returned when a CRL operation is attempted on a transport
// that has no crlPath set. NewTLSTransport has no CRL path; the CRL is opt-in
// via SetCRLPath. A node that has revoked no serials may leave the CRL unset.
var ErrNoCRLPath = errors.New("transport: no CRL path set (call SetCRLPath before CRL operations)")

// ErrCertRevoked aborts a handshake when the presented leaf's serial appears
// in the loaded CRL. The callback invokes the configured revocation reporter
// once for each such rejection.
var ErrCertRevoked = errors.New("transport: peer certificate serial is revoked (CRL reject)")

// NewTLSTransport loads a leaf keypair and CA pool from disk. The leaf hooks
// use the certificate installed by later Reload calls, so listeners can remain
// open across leaf rotation.
//
// Revocation is disabled until SetCRLPath and LoadCRL install a CRL. Without
// one, the peer-certificate callback adds no rejection of its own. ReloadCA
// replaces the trust pool after construction.
func NewTLSTransport(certPath, keyPath, caPath string) (*TLSConnections, error) {
	leaf, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("transport: load leaf keypair %q+%q: %w", certPath, keyPath, err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("transport: read CA %q: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: %s", ErrNoCALoaded, caPath)
	}
	return &TLSConnections{
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
		caPool:   pool,
		leaf:     &leaf,
	}, nil
}

// liveLeaf returns the current leaf under the read lock.
func (t *TLSConnections) liveLeaf() *tls.Certificate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.leaf
}

// verifyPeerCertificate adds serial revocation to crypto/tls chain validation.
// rawCerts contains the peer's DER chain, leaf first. With no revoked serials
// it returns immediately. Otherwise it parses the leaf and rejects a listed
// serial with ErrCertRevoked after invoking the configured reporter. Expiry
// and chain errors are handled by the standard library before this callback.
func (t *TLSConnections) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil // no peer cert (RequireAndVerifyClientCert handles this)
	}
	t.mu.RLock()
	revoked := t.revokedSerials
	reporter := t.revocationReporter
	t.mu.RUnlock()
	if len(revoked) == 0 {
		return nil // no serial lookup is configured
	}
	leafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("transport: parse peer leaf for CRL consult: %w", err)
	}
	if leafCert.SerialNumber != nil && revoked[leafCert.SerialNumber.Text(10)] {
		if reporter != nil {
			reporter() // typically increments CertRevokedRejected
		}
		return ErrCertRevoked
	}
	return nil
}

// ServerConfig returns a TLS 1.3-only listener configuration with
// RequireAndVerifyClientCert. GetCertificate supplies the current leaf and the
// peer-certificate callback applies CRL revocation. TLS 1.3 suites are left to
// crypto/tls because Config.CipherSuites does not select them.
//
// GetConfigForClient takes the current CA-pool snapshot for each connection,
// allowing later handshakes to observe ReloadCA without restarting the
// listener. Its configuration also retains the current-leaf and CRL hooks.
func (t *TLSConnections) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             t.caPool, // fallback; the live pool is served via GetConfigForClient below
		GetCertificate:        func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return t.liveLeaf(), nil },
		VerifyPeerCertificate: t.verifyPeerCertificate,
		// GetConfigForClient captures the current pool under RLock. The returned
		// configuration retains the leaf and CRL callbacks, so the next handshake
		// observes a completed ReloadCA.
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			t.mu.RLock()
			pool := t.caPool
			t.mu.RUnlock()
			return &tls.Config{
				MinVersion:            tls.VersionTLS13,
				MaxVersion:            tls.VersionTLS13,
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             pool,
				GetCertificate:        func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return t.liveLeaf(), nil },
				VerifyPeerCertificate: t.verifyPeerCertificate,
			}, nil
		},
	}
}

// ClientConfig returns a TLS 1.3-only dial configuration that verifies
// serverName against the current CA pool, presents the current leaf, and rejects
// revoked server certificates. GetClientCertificate observes later Reload
// calls. RootCAs retains the pool captured by this call, so callers need a new
// ClientConfig after ReloadCA.
func (t *TLSConnections) ClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		RootCAs:               t.caPool,
		ServerName:            serverName,
		GetClientCertificate:  func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return t.liveLeaf(), nil },
		VerifyPeerCertificate: t.verifyPeerCertificate,
	}
}

// Reload reads the leaf keypair from its configured paths and replaces the
// current leaf. Later GetCertificate and GetClientCertificate calls use the new
// certificate. The CA pool and revoked-serial set are unchanged.
func (t *TLSConnections) Reload() error {
	leaf, err := tls.LoadX509KeyPair(t.certPath, t.keyPath)
	if err != nil {
		return fmt.Errorf("transport: reload leaf keypair: %w", err)
	}
	t.mu.Lock()
	t.leaf = &leaf
	t.mu.Unlock()
	return nil
}

// ReloadCA rebuilds the trust pool from caPath. Server configurations produced
// by later GetConfigForClient calls use the new pool; configurations already
// returned to a caller retain their previous pool. Empty or invalid PEM leaves
// the current pool unchanged.
func (t *TLSConnections) ReloadCA() error {
	caPEM, err := os.ReadFile(t.caPath)
	if err != nil {
		return fmt.Errorf("transport: reload CA %q: %w", t.caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("%w: %s", ErrNoCALoaded, t.caPath)
	}
	t.mu.Lock()
	t.caPool = pool
	t.mu.Unlock()
	return nil
}

// SetCRLPath records the CRL file used by LoadCRL and ReloadCRL. Revocation
// remains disabled until a load installs at least one revoked serial.
func (t *TLSConnections) SetCRLPath(crlPath string) {
	t.mu.Lock()
	t.crlPath = crlPath
	t.mu.Unlock()
}

// LoadCRL parses the PEM at crlPath and replaces the revoked-serial set.
// Serials are stored as decimal strings for map lookup in
// verifyPeerCertificate. A valid CRL with no entries disables rejection;
// missing files, invalid PEM, and parse failures return errors and preserve the
// previous set.
//
// The CRL signature is not verified here. Access to the configured path is part
// of the trust model, as with the CA file; see ADR-0035 §6.
func (t *TLSConnections) LoadCRL() error {
	return t.reloadCRL()
}

// ReloadCRL repeats LoadCRL after the file changes. Later certificate callbacks
// use the replacement set; errors leave the previous set in place.
func (t *TLSConnections) ReloadCRL() error {
	return t.reloadCRL()
}

func (t *TLSConnections) reloadCRL() error {
	t.mu.RLock()
	path := t.crlPath
	t.mu.RUnlock()
	if path == "" {
		return ErrNoCRLPath
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("transport: read CRL %q: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("transport: CRL %q is not a PEM block", path)
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("transport: parse CRL %q: %w", path, err)
	}
	revoked := make(map[string]bool, len(rl.RevokedCertificateEntries))
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber != nil {
			revoked[e.SerialNumber.Text(10)] = true
		}
	}
	t.mu.Lock()
	t.revokedSerials = revoked
	t.mu.Unlock()
	return nil
}

// SetRevokedSerialsForTest replaces the revoked-serial set without reading a
// CRL. Tests use it to isolate callback behavior; production revocation uses
// SetCRLPath and LoadCRL instead.
func (t *TLSConnections) SetRevokedSerialsForTest(serials []*big.Int) {
	set := make(map[string]bool, len(serials))
	for _, s := range serials {
		if s != nil {
			set[s.Text(10)] = true
		}
	}
	t.mu.Lock()
	t.revokedSerials = set
	t.mu.Unlock()
}

// SetRevocationReporter installs the callback invoked whenever certificate
// verification rejects a revoked serial. The callback typically increments
// CertRevokedRejected for /metrics. A nil callback disables reporting; configure
// it during transport setup rather than while handshakes are active.
func (t *TLSConnections) SetRevocationReporter(fn func()) {
	t.mu.Lock()
	t.revocationReporter = fn
	t.mu.Unlock()
}

// Listen wraps tls.Listen with the server config. The returned net.Listener
// yields *tls.Conn on Accept.
func (t *TLSConnections) Listen(network, addr string) (net.Listener, error) {
	return tls.Listen(network, addr, t.ServerConfig())
}

// Dial opens a mutual-TLS 1.3 connection to addr and verifies serverName. The
// synchronous handshake populates ConnectionState before Dial returns.
// RecordHandshake reports only an X25519MLKEM768 result (ADR-0036). Outbound
// peer dials use this path; server-side control-port accepts do not invoke the
// reporter here.
func (t *TLSConnections) Dial(network, addr, serverName string) (*tls.Conn, error) {
	conn, err := tls.Dial(network, addr, t.ClientConfig(serverName))
	if err != nil {
		return nil, err
	}
	t.RecordHandshake(conn.ConnectionState()) // reports X25519MLKEM768 when configured
	return conn, nil
}

// StartRotationManager provides the polling loop for ADR-0035. The node binary
// enables it with --cert-rotation-enable; --cert-rotation-poll controls the
// interval and --cert-rotation-lifetime sets how far before NotAfter rotation
// begins. The latter is a lead time, not the certificate's validity period.
//
// A caller-supplied certMinter writes and reloads the replacement leaf. This
// keeps pkg/crypto out of transport and permits other certificate issuers. The
// goroutine exits when its context is canceled.

// certMinter writes a replacement leaf to the transport's configured paths,
// calls Reload, and returns the new serial. The rotation manager invokes it
// without holding the transport lock so certificate generation and file I/O do
// not block certificate callbacks.
type certMinter func() (newSerial *big.Int, err error)

// RotationMinter exposes certMinter to other packages. Implementations write
// and reload a replacement leaf, then return its serial. See
// StartRotationManager.
type RotationMinter = certMinter

// StartRotationManager polls NotAfter after each poll interval. When the
// remaining validity is at most lifetime, it invokes minter and then
// triggerReporter after a successful rotation. The minter is responsible for
// writing and reloading the leaf. A minter error leaves the current leaf in use
// and is retried on a later tick.
//
// poll must be positive and minter non-nil. Choosing lifetime shorter than poll
// can miss the intended rotation window. The returned stop function cancels the
// goroutine and is idempotent; canceling ctx also stops it.
func (t *TLSConnections) StartRotationManager(ctx context.Context, poll, lifetime time.Duration, minter certMinter, triggerReporter func()) (stop func(), err error) {
	if poll <= 0 {
		return nil, fmt.Errorf("transport: cert-rotation-poll must be > 0, got %v", poll)
	}
	if minter == nil {
		return nil, errors.New("transport: cert rotation requires a minter")
	}
	innerCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	stop = func() { once.Do(cancel) }
	go func() {
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-innerCtx.Done():
				return
			case <-ticker.C:
				if !t.shouldRotate(lifetime) {
					continue
				}
				if _, rotateErr := minter(); rotateErr != nil {
					// Keep serving the current leaf and retry on a later tick.
					// A minter can add its own error reporting.
					continue
				}
				if triggerReporter != nil {
					triggerReporter()
				}
			}
		}
	}()
	return stop, nil
}

// shouldRotate reports whether the current leaf has at most lifetime of
// validity remaining. A missing or unparsable leaf returns false.
func (t *TLSConnections) shouldRotate(lifetime time.Duration) bool {
	t.mu.RLock()
	leaf := t.leaf
	t.mu.RUnlock()
	if leaf == nil || len(leaf.Certificate) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return false
	}
	return time.Until(cert.NotAfter) <= lifetime
}
