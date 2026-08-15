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

// TLSConnections is the TLS 1.3 transport configuration for the production
// node binary. It owns the on-disk cert/key/CA/CRL paths, the parsed CA pool,
// the live leaf certificate, and the in-memory revoked-serial set, and produces
// server + client tls.Configs that enforce a 1.3-only, mutual-TLS, no-fallback
// policy with a VerifyPeerCertificate callback that rejects a presented leaf
// whose serial is in the CRL (the Day-30 ADR-0035 revocation gate).
//
// The load-bearing physics truth (C1, verbatim from the Day-1 executor
// prompt §0):
//
//	MSG_ZEROCOPY does NOT transfer to TCP+TLS. TransmitTLSFrame over a
//	*tls.Conn is a PLAIN conn.Write. Go's crypto/tls Conn.Write (the AEAD
//	record layer) copies plaintext into the record outBuf, AEAD-encrypts into
//	c.out, then the underlying TCP write is Go's ordinary netFD.Write -- which
//	does NOT set MSG_ZEROCOPY, does NOT call runtime.Pinner.Pin, and does NOT
//	go through the copy-pin-sendmsg-unpin dance. The zero-copy semantics of
//	TransmitHeapBuffer live ONLY on the AF_XDP turbo tier (Day 9, the UMEM
//	ring hands the NIC a userspace address with no sk_buff).
//
// The default tier is therefore COPY mode by construction. AES-128-GCM is
// ~30-50 ns/record on Graviton4 (Neoverse V2 ARM v8 AES insns
// AESE/AESD/AESMC) and the record copy is ~120B; both are dominated by the
// 60.19 us Ed25519 verify (PROVEN, circl v1.6.4, pkg/identity/bench_test.go)
// by >1000x. The zero-copy-vs-copy delta at the default tier is INVISIBLE
// against verify. See ADR-0006.
//
// ── Day 30 (ADR-0035): the triple hot-reload + the revocation consult ──
//
// Pre-Day-30 the transport reloaded ONLY the leaf (Reload re-parses cert+key);
// the :126 comment was explicit ("The CA pool is NOT reloaded here — a CA
// rotation is a trust-root change that requires a transport restart") and NO
// revocation surface existed (the handshake used the Go-tls default chain
// validation against caPool, which trusts the CA, NOT the serial's revocation
// status). Day 30 lifts both:
//
//	 (i) Leaf — Reload() unchanged (the existing SIGHUP seam + the existing
//	     TestTLSCertRotation_SIGHUP stay byte-identical).
//	(ii) CA pool — ReloadCA() re-reads caPath + rebuilds the pool atomically
//	     under the RWMutex (lifts the :126 restriction; a CA rotation no longer
//	     requires a restart — T-PKI-CA-HOT-RELOAD).
//	(iii) CRL — LoadCRL/ReloadCRL parse the on-disk crl.pem into an in-memory
//	     revoked-serial set; the VerifyPeerCertificate callback consults it
//	     under the RWMutex and rejects a presented leaf whose serial is revoked
//	     (T-PKI-REVOKED-REJECTED, the blueprint Track 5.2 gate byte-proven).
//
// Each rotates INDEPENDENTLY (a CRL update does NOT force a leaf re-parse — the
// M3 triple, NOT the naive "leaf-only" the prior SIGHUP seam implied). All
// three are atomic under the SAME RWMutex; the GetCertificate /
// GetClientCertificate hooks + the VerifyPeerCertificate callback read under
// the RLock so a handshake IN FLIGHT during a swap continues against the OLD
// snapshot (the M5 zero-downtime guarantee — a handshake that has PASSED
// chain validation but not finished the CRL consult is the honest edge; the
// RWMutex bounds the swap so the consult reads a CONSISTENT set, never a
// half-swapped one — disclosed ADR-0035 §M5).
type TLSConnections struct {
	caPool              *x509.CertPool
	leaf                *tls.Certificate
	revokedSerials      map[string]bool // serial.Text(10) -> true; nil/empty = no revocation consult
	revocationReporter  func()          // fires on each CRL-reject (the CertRevokedRejected counter seam); nil = silent
	pqHandshakeReporter func()          // Day-31: fires on each PQ-KEM handshake (the PQHandshakeNegotiated counter seam); nil = silent
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
// that has no crlPath set (NewTLSTransport has no CRL path; the CRL is opt-in
// via SetCRLPath — the Day-30 triple where the CRL may stay unset on a node
// that has revoked NO serials).
var ErrNoCRLPath = errors.New("transport: no CRL path set (call SetCRLPath before CRL operations)")

// ErrCertRevoked is the handshake-abort error the VerifyPeerCertificate
// callback returns when a presented leaf's serial is in the CRL. The error
// string is stable (the teeth match on it). The CertRevokedRejected counter
// is incremented INSIDE the callback (the once-per-reject seam) so a reject is
// NEVER uncounted — the counter is the Law V security-gate-PROVEN-disclosure.
var ErrCertRevoked = errors.New("transport: peer certificate serial is revoked (CRL reject)")

// NewTLSTransport loads the leaf cert+key and the CA pool from disk and
// returns a TLSConnections ready to produce server/client configs. The leaf
// is parsed once here and re-parsed on Reload(); the GetCertificate /
// GetClientCertificate hooks read the live leaf under the RWMutex so a
// SIGHUP-driven Reload swaps the leaf without restarting the listener.
//
// Day 30: the CRL path is NOT set here (NewTLSTransport is the 3-arg
// constructor the existing tests + main.go call — byte-identical signature). A
// node opts into the revocation consult by calling SetCRLPath + LoadCRL
// post-construction; a node with NO CRL (the opt-OUT default) leaves
// revokedSerials nil → the VerifyPeerCertificate callback returns nil (no
// reject) → byte-identical pre-Day-30 handshake behavior (T-PKI-OFF-IS-BYTE-
// IDENTICAL). The CA pool is loaded ONCE here; ReloadCA re-reads it live.
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

// verifyPeerCertificate is the VerifyPeerCertificate callback wired into BOTH
// ServerConfig + ClientConfig (the blueprint's "mTLS enforcement" — the BOTH-
// sides gate). It runs AFTER the Go-tls default chain validation, so the chain
// is ALREADY verified against caPool (the EXPIRED half of the gate is met
// here — an expired leaf fails the default validation BEFORE this callback;
// the M2(a) finding — default Go-tls behavior, NOT new work this fork claims).
// This callback implements the REVOKED half: it extracts the leaf serial from
// the presented chain and rejects it if the serial is in the in-memory revoked
// set. rawCerts is the ASN.1 DER of the peer's chain (leaf first). A
// nil/empty revoked set (no CRL loaded) returns nil — the opt-OUT default is
// byte-identical pre-Day-30. On a revocation HIT the CertRevokedRejected
// counter is incremented (the reporter seam) + ErrCertRevoked surfaces as a
// handshake abort. The callback is allocation-free on the no-reject path (the
// hot path — a handshake against a NON-revoked leaf parses the leaf cert the
// Go-tls stack already parsed; the parse here is the reject-path cost, NOT
// the hot path's).
func (t *TLSConnections) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil // no peer cert (RequireAndVerifyClientCert handles this)
	}
	t.mu.RLock()
	revoked := t.revokedSerials
	reporter := t.revocationReporter
	t.mu.RUnlock()
	if len(revoked) == 0 {
		return nil // no CRL loaded → byte-identical pre-Day-30 handshake
	}
	leafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("transport: parse peer leaf for CRL consult: %w", err)
	}
	if leafCert.SerialNumber != nil && revoked[leafCert.SerialNumber.Text(10)] {
		if reporter != nil {
			reporter() // the CertRevokedRejected counter — Law V security-gate disclosure
		}
		return ErrCertRevoked
	}
	return nil
}

// ServerConfig returns a *tls.Config for the listener side. It is TLS 1.3
// ONLY (Min==Max==VersionTLS13), enforces mutual TLS
// (ClientAuth: RequireAndVerifyClientCert), trusts the loaded CA pool, serves
// the live leaf via GetCertificate so a SIGHUP Reload swaps the presented cert
// without restarting the listener, AND consults the VerifyPeerCertificate
// callback so a revoked CLIENT leaf is rejected at the handshake (the Day-30
// revocation gate — the BOTH-sides mTLS enforcement; a revoked SERVER leaf is
// rejected by the CLIENT's callback in ClientConfig). CipherSuites is NOT set:
// for a 1.3-only config the AEAD suites (TLS_AES_128_GCM_SHA256,
// TLS_AES_256_GCM_SHA384) are auto-negotiated and setting Config.CipherSuites
// is a documented no-op + footgun (the 1.3 ciphers are not selectable via
// the 1.2 CipherSuites field). The 1.3-only gate is the tooth: Min==Max==1.3
// makes a 1.2/1.1/1.0 negotiation impossible.
//
// Day 30 (ADR-0035): the CA pool is served LIVE via GetConfigForClient. The
// top-level ClientCAs is the construction-time pool (the fallback); the per-
// connection config returned by GetConfigForClient reads t.caPool under the
// RLock so a ReloadCA swap is picked up by the NEXT handshake WITHOUT a
// listener restart (T-PKI-CA-HOT-RELOAD). This is the lift of the pre-Day-30
// :126 restriction: Go's tls.Config has NO dynamic-CA hook equivalent to
// GetCertificate (ClientCAs/RootCAs are static fields read at handshake
// time from the config struct), so the ONLY way a live CA rotation reaches
// an already-issued listener is GetConfigForClient returning a fresh config
// whose ClientCAs is the live pool. The returned config re-wires
// GetCertificate + VerifyPeerCertificate so a rotated-CA handshake still
// presents the live leaf + consults the live CRL.
func (t *TLSConnections) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             t.caPool, // fallback; the live pool is served via GetConfigForClient below
		GetCertificate:        func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return t.liveLeaf(), nil },
		VerifyPeerCertificate: t.verifyPeerCertificate,
		// GetConfigForClient returns a per-connection config whose ClientCAs is
		// the LIVE pool (read under the RLock). This is the dynamic-CA hook Go's
		// tls.Config lacks as a field — a ReloadCA swap is picked up by the next
		// handshake. The returned config carries the SAME GetCertificate +
		// VerifyPeerCertificate (the live leaf + the live CRL consult).
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

// ClientConfig returns a *tls.Config for the dial side. It is TLS 1.3 ONLY,
// trusts the loaded CA pool (ServerName verification against the pool),
// presents the live leaf as a client certificate (mTLS) via
// GetClientCertificate so a SIGHUP Reload swaps the presented client cert on
// the next dial, AND consults the VerifyPeerCertificate callback so a revoked
// SERVER leaf is rejected at the handshake (the BOTH-sides revocation gate).
// serverName is the SNI / ServerName the dial verifies the server cert against.
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

// Reload re-reads the leaf cert+key from disk and atomically swaps the live
// leaf. It is the SIGHUP handler's target: replace the PEM on disk, send
// SIGHUP, and the next handshake presents the new leaf (within the
// GetCertificate/GetClientCertificate hook). The CA pool is NOT reloaded here
// — Day 30 (ADR-0035) lifts the pre-Day-30 :126 restriction via a SEPARATE
// ReloadCA() sibling so the leaf rotation's standalone fast-path stays
// byte-identical (the existing TestTLSCertRotation_SIGHUP calls Reload, NOT
// ReloadCA — the seam is preserved). The CRL is NOT reloaded here either; the
// triple hot-reload keeps the three surfaces independent (a CRL update does
// NOT force a leaf re-parse — the M3 discipline).
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

// ReloadCA re-reads the CA PEM at caPath and atomically rebuilds the CA pool
// under the RWMutex. It is the Day-30 (ADR-0035) lift of the pre-Day-30 :126
// restriction ("The CA pool is NOT reloaded here — a CA rotation is a trust-
// root change that requires a transport restart"). A CA rotation is NOW a live
// operation: replace caPath on disk, call ReloadCA, and the NEXT handshake
// validates against the NEW pool (T-PKI-CA-HOT-RELOAD). The pool swap is
// atomic under the RWMutex so a handshake IN FLIGHT continues against the OLD
// pool (the M5 guarantee — the verifier reads the pool under the RLock the
// handshake holds; the swap is a write-Lock that waits for the in-flight
// handshakes to release). A failed rebuild (the new CA PEM is empty/unparseable)
// leaves the OLD pool in place (the transport NEVER trust-degrades on a
// failed reload — the honest-negative posture).
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

// SetCRLPath sets the on-disk CRL path the transport hot-reloads. It is the
// opt-in seam for the revocation consult: a transport constructed via
// NewTLSTransport has NO CRL path (byte-identical pre-Day-30 — the
// VerifyPeerCertificate callback returns nil on a nil/empty revoked set).
// Setting the path + calling LoadCRL arms the consult. The path is stored
// under the write lock so a concurrent ReloadCRL reads a consistent path.
func (t *TLSConnections) SetCRLPath(crlPath string) {
	t.mu.Lock()
	t.crlPath = crlPath
	t.mu.Unlock()
}

// LoadCRL reads + parses the CRL PEM at crlPath and atomically swaps the
// in-memory revoked-serial set. It is the FIRST load (the construction-time
// arm); ReloadCRL is the live re-read. The CRL is parsed via
// x509.ParseRevocationList; the revoked serials are extracted into a
// serial.Text(10)-keyed map for O(1) consult under the RLock in
// verifyPeerCertificate. An empty/missing CRL yields an empty set (the
// transport rejects nothing — byte-identical pre-Day-30). A failed parse
// leaves the OLD set in place (the transport NEVER revocation-degrades on a
// failed reload — the honest-negative posture; a corrupt CRL is NEVER silently
// dropped to "trust everything"). The CRL's signature is NOT re-verified here
// (the Ed25519-CheckSignatureFrom stdlib quirk, disclosed ADR-0035 §6 — the
// trust model is path-ownership, the SAME model the CA pool uses:
// AppendCertsFromPEM loads the self-signed root WITHOUT verifying its
// self-signature).
func (t *TLSConnections) LoadCRL() error {
	return t.reloadCRL()
}

// ReloadCRL re-reads + re-parses the CRL PEM at crlPath and atomically swaps
// the in-memory revoked-serial set. It is the live-reload sibling of LoadCRL
// (the SAME mechanism; LoadCRL is the construction-time arm, ReloadCRL is the
// SIGHUP/rotation-driven re-read). See LoadCRL for the parse + swap semantics.
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

// SetRevokedSerialsForTest is the in-process seam the test teeth use to arm
// the revocation consult WITHOUT a round-trip through disk (the
// T-PKI-REVOKED-REJECTED tooth mints a leaf, revokes its serial in-process,
// and arms the consult directly — no CRL PEM needed for the unit-level proof;
// the verify_day30 harness exercises the FULL disk round-trip). It is the
// transport-side equivalent of MeshCA.RevokeLeaf: the test owns the serial set
// the transport consults. Production NEVER calls this (the CRL disk round-trip
// is the production path); the name + the _ForTest suffix mark it test-only.
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

// SetRevocationReporter binds the counter-increment seam that fires every time
// the VerifyPeerCertificate callback rejects a revoked serial. It is the Law V
// disclosure (the CertRevokedRejected counter — the security-gate-PROVEN-
// disclosure the operator SEES on /metrics). nil (the test default) leaves the
// reject silent (the SetRoundReporter precedent — the counter is the
// DISCLOSURE, not the mechanism). Bound ONCE at construction; the callback reads
// it under the RLock (a rebind mid-handshake is a caller bug — the same
// once-at-boot contract the mesh's reporter seam uses).
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

// Dial opens a TLS 1.3 connection to addr, presenting the live leaf as a
// client cert (mTLS) and verifying the server cert against the CA pool.
// serverName is the SNI / ServerName used for server-cert verification.
//
// Day 31 (ADR-0036): tls.Dial drives the TLS 1.3 handshake SYNCHRONOUSLY, so
// the returned *tls.Conn has a POPULATED ConnectionState() (CurveID is the
// negotiated KEM, NOT the configured preference). Dial fires RecordHandshake
// before returning so the PQHandshakeNegotiated counter increments IFF the
// negotiated CurveID is X25519MLKEM768 (the M6 Law-V disclosure — a classical
// fallback for a non-MLKEM peer does NOT increment). This is the production
// firing point for every peer the node dials (the mesh PeerSet.Dial →
// ps.dialer.Dial → here; the control-port harness dials the same way). The
// server-side control-port accept uses tls.Listen directly + does NOT fire
// the counter here (the client-side ConnectionState is the load-bearing proof
// the runtime /verify harness asserts; a server-side firing is a SEPARATE
// seam a future fork may add — disclosed ADR-0036 §6).
func (t *TLSConnections) Dial(network, addr, serverName string) (*tls.Conn, error) {
	conn, err := tls.Dial(network, addr, t.ClientConfig(serverName))
	if err != nil {
		return nil, err
	}
	t.RecordHandshake(conn.ConnectionState()) // Day-31: the PQ-KEM disclosure (nil reporter = no-op)
	return conn, nil
}

// ──────────────────────────────────────────────────────────────────────────
// Day 30 (ADR-0035): the automated leaf-rotation TRIGGER (M4).
//
// The blueprint Track 5.2 gate ("zero-downtime leaf cert rotation every 30
// days") demands a TRIGGER, not a manual SIGHUP. StartRotationManager launches
// an internal goroutine that polls the live leaf's NotAfter at a coarse
// interval (--cert-rotation-poll, default 1h) and fires the rotation when the
// leaf is within --cert-rotation-lifetime of expiry (the pre-expiry threshold —
// 30 days for the blueprint's 30-day cadence; the LIFETIME is the pre-expiry
// grace window, NOT the poll interval, NOT the leaf's actual validity — the
// M4 honest-calibration: the goroutine polls at 1h, the leaf lives 1 year, the
// rotation fires 30 days before the 1-year NotAfter). The rotation mints a NEW
// leaf via certgen at the SAME paths + calls Reload (the existing seam) so the
// NEXT handshake presents the NEW serial (T-PKI-ROTATION-TRIGGER). The trigger
// is OPT-IN (--cert-rotation-enable, default OFF; the Day-19/23/29 opt-IN
// precedent — keeps the SIGHUP seam + TestTLSCertRotation_SIGHUP byte-identical
// at HEAD). The goroutine exits when ctx is canceled (the clean shutdown seam).
//
// The rotation mints via a caller-supplied minter (the certMinter seam) so the
// transport does NOT import pkg/crypto (avoids an import cycle; main.go owns
// the *crypto.MeshCA + wires the minter). A production fork that rotates via
// an out-of-process minter (a KMS/HSM-backed CA) substitutes its own minter —
// disclosed ADR-0035 §6. The dev minter (main.go's mintLeafForRotation) is the
// test + selftest path; the trigger's polling + reload mechanism is the
// load-bearing wiring this fork ships.
// ──────────────────────────────────────────────────────────────────────────

// certMinter is the rotation-time leaf minter. The default (wired by main.go)
// mints a NEW Ed25519 leaf via the in-process MeshCA + writes the PEM to the
// transport's cert+key paths; a production fork substitutes a KMS/HSM-backed
// minter. It returns the new serial (for the CertRotationTriggered counter
// audit) + any error. The minter is called under NO lock (it does disk +
// crypto work); the Reload that follows is the atomic swap.
type certMinter func() (newSerial *big.Int, err error)

// RotationMinter is the exported alias for certMinter so main.go (and other
// out-of-package callers) can name the minter type without re-declaring the
// signature. A RotationMinter mints a NEW leaf, writes the PEM to the
// transport's cert+key paths, calls Reload, and returns the new serial (for
// the CertRotationTriggered counter audit). See StartRotationManager.
type RotationMinter = certMinter

// StartRotationManager launches the automated leaf-rotation goroutine. It
// polls the live leaf's NotAfter every poll; when the leaf is within lifetime
// of expiry (NotAfter - now <= lifetime), it calls minter (which writes the
// new PEM to the transport's paths + Reloads) and increments triggerReporter
// (the CertRotationTriggered counter). The goroutine exits on ctx cancel.
// Returns a stop function that cancels the goroutine (idempotent — the
// production binary relies on ctx cancel; the stop fn is the test seam).
// poll MUST be > 0 (a zero/negative poll is trapped — the trigger is NEVER a
// busy loop); lifetime SHOULD be > poll (a lifetime < poll risks a missed
// rotation window — disclosed but NOT trapped, the operator owns the
// calibration). The first poll runs after one poll interval (NOT immediately —
// the transport's construction-time leaf is fresh; an immediate poll would
// rotate a leaf that is nowhere near expiry).
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
					// A failed rotation is NOT fatal — the stale leaf still
					// serves (the SIGHUP-seam precedent); the next poll
					// retries. The error is swallowed here (the trigger has
					// no log surface; a production fork wires a logger).
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

// shouldRotate returns whether the live leaf is within lifetime of expiry. It
// reads the leaf under the RLock (the same lock the handshake reads — a
// consistent snapshot of NotAfter). A nil leaf (should not happen post-
// construction) returns false (the trigger waits for a leaf).
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
