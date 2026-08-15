// Package crypto provides the dev-mesh certificate authority used by the
// TLS 1.3 transport (pkg/transport/tls_transport.go) and the production node
// binary (cmd/sovereign-node) for the Day-1 dev mesh.
//
// This is a DEV mesh CA, NOT a production PKI. It mints an Ed25519 root key +
// self-signed x509 CA certificate and per-node leaf certificates signed by
// that CA, writing PEM files to disk for the TLS transport to load. A
// production PKI (offline root, intermediate CAs, HSM-backed key custody,
// OCSP/CRL revocation, automated rotation) is explicitly post-10-day and is
// named in ADR-0006's honesty section.
//
// Ed25519 (not RSA/ECDSA) is chosen to match the engine's identity bridge
// (pkg/identity signs CRDT deltas with circl Ed25519): one signature
// algorithm on the wire, 64-byte signatures, ZIP-215-compatible verification.
// The CRDT-delta verification path (pkg/identity/verify.go) uses circl
// ed25519 v1.6.4 and BANS stdlib crypto/ed25519 for that purpose
// (pkg/identity/doc.go:9); that ban does NOT extend here — certgen uses
// stdlib crypto/ed25519 + crypto/x509 for x509 certificate generation, which
// is the documented stdlib path (crypto/x509.CreateCertificate with
// PublicKeyAlgorithm: x509.Ed25519). The two key spaces are distinct:
// transport-layer mTLS keys (this package) vs CRDT-delta signing keys
// (pkg/identity). They share an algorithm for operational simplicity, not a
// key.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// MeshCA is the dev-mesh certificate authority: an Ed25519 root key pair and
// the self-signed x509 CA certificate that signs per-node leaves.
//
// Day 30 (ADR-0035): MeshCA also owns the in-process revoked-serial set the CRL
// issuer signs. revokedSerials is the CA-authoritative revocation ledger — a
// serial appended via RevokeLeaf is published in the next IssueCRL. The set is
// NOT concurrency-guarded: the dev-mesh CA is a single-goroutine construction
// surface (NewMeshCA → IssueLeaf → RevokeLeaf → IssueCRL run in the order the
// operator or the test harness drives them); a concurrent RevokeLeaf is a
// caller bug (the same single-owner contract the existing IssueLeaf has — it
// mutates no shared state today, so the field adds NO new contention).
type MeshCA struct {
	caKey          ed25519.PrivateKey
	caPub          ed25519.PublicKey
	caCert         *x509.Certificate
	caCertDER      []byte
	caNotBefore    time.Time
	revokedSerials []*big.Int
}

// Leaf is a per-node leaf credential: an Ed25519 key pair and the x509 leaf
// certificate signed by the MeshCA, plus the PEM-ready DER bytes.
type Leaf struct {
	nodeID      string
	leafKey     ed25519.PrivateKey
	leafPub     ed25519.PublicKey
	leafCert    *x509.Certificate
	leafCertDER []byte
}

// serialNumber generates a positive, bounded serial number for an x509
// certificate. It uses crypto/rand so serials are unpredictable (avoiding
// the predictable-serial collision / forgery class); the 62-bit bound keeps
// it inside the ASN.1 INTEGER range Go's x509 marshals cleanly.
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 62) // 2^62
	return rand.Int(rand.Reader, limit)
}

// NewMeshCA generates a fresh Ed25519 root key and a self-signed x509 CA
// certificate. The CA is IsCA:true with KeyUsage CertSign|CRLSign; it is the
// trust root the TLS transport's RootCAs pool loads (WriteCAPEM).
func NewMeshCA() (*MeshCA, error) {
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-time.Minute)
	notAfter := notBefore.AddDate(10, 0, 0) // 10-year dev CA
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sovereign Engine Dev Mesh"},
			CommonName:   "sovereign-dev-mesh-ca",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		PublicKeyAlgorithm:    x509.Ed25519,
	}
	// Self-sign: the CA cert is signed by its own private key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caPub, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &MeshCA{
		caKey:       caKey,
		caPub:       caPub,
		caCert:      caCert,
		caCertDER:   der,
		caNotBefore: notBefore,
	}, nil
}

// IssueLeaf mints a per-node leaf certificate signed by the CA. nodeID is
// embedded as the leaf CommonName (and an organization unit) so a presented
// leaf identifies the node on the wire. The leaf is a server+client cert
// (KeyUsage DigitalSignature; ExtKeyUsage ServerAuth+ClientAuth) so the same
// leaf serves both sides of the mTLS handshake. The lifetime is the 1-year dev
// default (notBefore = now-1m, notAfter = notBefore+1y) — byte-identical to
// the pre-Day-30 behavior the existing teeth (TestCertgen_RoundTrip +
// TestTLSCertRotation_SIGHUP) assert.
func (c *MeshCA) IssueLeaf(nodeID string) (*Leaf, error) {
	return c.issueLeaf(nodeID, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute).AddDate(1, 0, 0))
}

// IssueLeafWithLifetime is the Day-30 (ADR-0035) lifetime-parameterized leaf
// minter. It shares the EXACT template + signing path of IssueLeaf (the only
// delta is the caller-supplied NotBefore/NotAfter) so a test tooth can mint a
// leaf whose NotAfter is in the PAST (T-PKI-EXPIRED-REJECTED — default Go-tls
// chain validation rejects it at the handshake) and the rotation manager can
// mint a SHORT-LIVED leaf (T-PKI-ROTATION-TRIGGER compresses the blueprint's
// 30-day cadence into a sub-second lifetime to test the trigger in-wall-clock).
// Production rotation uses IssueLeaf at the SAME paths (the 1-year default is
// the operator-visible lifetime; the trigger's --cert-rotation-lifetime flag is
// the poll threshold, NOT a re-minted lifetime — see ADR-0035 §M4). notAfter
// MUST be after notBefore or x509.CreateCertificate rejects the template (the
// stdlib guard); the caller owns the temporal sanity.
func (c *MeshCA) IssueLeafWithLifetime(nodeID string, notBefore, notAfter time.Time) (*Leaf, error) {
	return c.issueLeaf(nodeID, notBefore, notAfter)
}

// IssueLeafWithIP is the Day-36 (ADR-0041) IP-SAN-parameterized leaf minter for
// the cross-region silicon gate. It shares the EXACT template + signing path of
// IssueLeaf (the only delta is the caller-supplied IPAddresses SAN) so a leaf
// minted for a node with a KNOWN public IP verifies when the peer dial uses that
// IP as the TLS ServerName (main.go:1381 peerSet.Dial(ctx, pa, host, peerID)
// where host = splitHostPort(pa) — the addr's host). The default IssueLeaf sets
// IPAddresses=nil with the comment "populated by the deploy if a fixed IP is
// known" — THIS minter is that deploy path (the cmd/day36-bootstrap helper
// mints each node's leaf WITH its host's public IP). A nil/empty ips keeps the
// DNSNames-only template (byte-identical to IssueLeaf) so a caller that passes
// no IPs does NOT regress. The DNSNames are unchanged ({nodeID, "localhost"}) so
// a localhost-loopback dial still verifies (the smoke-test path).
func (c *MeshCA) IssueLeafWithIP(nodeID string, ips []net.IP) (*Leaf, error) {
	return c.issueLeafIP(nodeID, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute).AddDate(1, 0, 0), ips)
}

// issueLeafIP is the IP-SAN core, mirroring issueLeaf's template field-for-field
// EXCEPT IPAddresses (issueLeaf hardcodes nil; this takes the caller's list). It
// is a SEPARATE path from issueLeaf (NOT a branch inside it) so the existing
// IssueLeaf/IssueLeafWithLifetime single-path discipline + their byte-identical
// tests are untouched — a regression here cannot leak into the rotation path.
func (c *MeshCA) issueLeafIP(nodeID string, notBefore, notAfter time.Time, ips []net.IP) (*Leaf, error) {
	if c == nil || c.caCert == nil {
		return nil, errors.New("certgen: nil or uninitialized MeshCA")
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"Sovereign Engine Dev Mesh"},
			OrganizationalUnit: []string{"node"},
			CommonName:         nodeID,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           ips, // the Day-36 deploy path: the node's public IP (nil = DNSNames-only, byte-identical IssueLeaf)
		DNSNames:              []string{nodeID, "localhost"},
		BasicConstraintsValid: true,
		IsCA:                  false,
		PublicKeyAlgorithm:    x509.Ed25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, leafPub, c.caKey)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		nodeID:      nodeID,
		leafKey:     leafKey,
		leafPub:     leafPub,
		leafCert:    leafCert,
		leafCertDER: der,
	}, nil
}

// issueLeaf is the shared core of IssueLeaf + IssueLeafWithLifetime. It is the
// single signing path so the two public minters CANNOT drift (a divergence
// would let a lifetime-parameterized leaf escape a template field the default
// minter sets — the Day-30 single-path discipline the M2 prompt names: "the
// CRL is a SERIAL check, NOT a trust-root check" generalizes to "the leaf is a
// single template, NOT a per-minter template").
func (c *MeshCA) issueLeaf(nodeID string, notBefore, notAfter time.Time) (*Leaf, error) {
	if c == nil || c.caCert == nil {
		return nil, errors.New("certgen: nil or uninitialized MeshCA")
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"Sovereign Engine Dev Mesh"},
			OrganizationalUnit: []string{"node"},
			CommonName:         nodeID,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           nil, // populated by the deploy if a fixed IP is known
		DNSNames:              []string{nodeID, "localhost"},
		BasicConstraintsValid: true,
		IsCA:                  false,
		PublicKeyAlgorithm:    x509.Ed25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, leafPub, c.caKey)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		nodeID:      nodeID,
		leafKey:     leafKey,
		leafPub:     leafPub,
		leafCert:    leafCert,
		leafCertDER: der,
	}, nil
}

// WriteCAPEM writes the CA certificate (PEM-encoded) to ca.pem in dir and
// returns the path. The CA private key is NOT written — a dev mesh CA key
// stays in-process; only the public trust anchor is persisted for the
// transport's RootCAs pool.
func (c *MeshCA) WriteCAPEM(dir string) (caPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	caPath = filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caCertDER})
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		return "", err
	}
	return caPath, nil
}

// WritePEM writes the leaf certificate (cert.pem) and leaf private key
// (key.pem) to dir and returns their paths. The key is written 0600; it is
// an Ed25519 seed marshaled via x509.MarshalPKCS8PrivateKey.
func (l *Leaf) WritePEM(dir string) (certPath, keyPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.leafCertDER}),
		0o644); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(l.leafKey)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// CACert returns the parsed CA certificate (for in-process trust pools in
// tests that do not want to round-trip through disk).
func (c *MeshCA) CACert() *x509.Certificate { return c.caCert }

// LeafCert returns the parsed leaf certificate.
func (l *Leaf) LeafCert() *x509.Certificate { return l.leafCert }

// LeafKey returns the leaf private key (for in-process tls.Certificate
// construction in tests).
func (l *Leaf) LeafKey() ed25519.PrivateKey { return l.leafKey }

// NodeID returns the node identifier embedded in the leaf CommonName.
func (l *Leaf) NodeID() string { return l.nodeID }

// ──────────────────────────────────────────────────────────────────────────
// Day 30 (ADR-0035): the CRL issuer — the SERIAL-level revocation surface.
//
// The blueprint Track 5.2 gate ("a node presenting an EXPIRED OR REVOKED cert
// is rejected at the TLS handshake") has two claws (the M2 audit):
//   (a) EXPIRED — default Go-tls chain validation ALREADY rejects an expired
//       leaf (the NotAfter check is in x509.Certificate.Verify). The transport
//       inherits (a) for free; the fork does NOT claim it as new work.
//   (b) REVOKED — requires a SERIAL-level reject. A revoked cert passes the
//       chain (the CA still signed it) UNLESS the transport consults a CRL. This
//       is the load-bearing fork: the CA publishes a signed list of revoked
//       serials (IssueCRL → WriteCRLPEM), the transport hot-reloads the PEM
//       (ReloadCRL), parses it into an in-memory serial set, and the
//       VerifyPeerCertificate callback rejects a presented leaf whose serial is
//       in the set. CRL (NOT OCSP) is chosen because the dev/operator-mesh CA is
//       operator-controlled + offline-friendly; an OCSP responder is a NEW
//       network surface + a NEW availability SPOF (disclosed ADR-0035 §6).
//
// The CRL is signed with x509.CreateRevocationList (the MODERN Go 1.23+ API,
// NOT the deprecated x509.CreateCRL — confirmed go.mod go 1.26.1). The CA cert's
// KeyUsageCRLSign bit is set at NewMeshCA (certgen.go:90), and CreateCertificate
// auto-populates the CA's SubjectKeyId (SHA-256(pubkey)[:20], verified by the
// Day-30 CRL probe) — both are preconditions x509.CreateRevocationList names
// ("the crlSign bit must be set in KeyUsage" + "issuer must have SubjectKeyId
// set") and BOTH are already satisfied by the EXISTING CA. No CA-cert change.
//
// Honest residual (disclosed ADR-0035 §6): Go's RevocationList.CheckSignatureFrom
// rejects an Ed25519-signed CRL with "parent certificate cannot sign this kind
// of certificate" (verified by the Day-30 CRL probe — a stdlib quirk, NOT a
// signature defect; the CRL's Ed25519 signature IS valid). The transport
// therefore consults the in-memory revoked-serial SET (parsed from the CRL the
// CA — the SAME operator in-process owner — produced), NOT a per-handshake
// CheckSignatureFrom. The trust model is path-ownership (the SAME model the CA
// pool uses: AppendCertsFromPEM loads the self-signed root WITHOUT verifying
// its self-signature). A production fork that ships a CRL from an OUT-of-process
// CA must add the Ed25519 CRL signature verification (a CheckSignatureFrom
// replacement that accepts Ed25519) — disclosed, NOT closed.
// ──────────────────────────────────────────────────────────────────────────

// ErrSerialAlreadyRevoked is returned by RevokeLeaf when the serial is already
// in the revoked set. Revocation is idempotent from the CA's ledger view (a
// duplicate append would publish a duplicate entry in the CRL — the stdlib
// ParseRevocationList tolerates duplicates, but the ledger is kept clean).
var ErrSerialAlreadyRevoked = errors.New("certgen: serial already revoked")

// RevokeLeaf appends a serial to the CA's in-process revoked-serial ledger.
// The serial is published in the next IssueCRL. Idempotent: a duplicate append
// returns ErrSerialAlreadyRevoked (the ledger stays clean — no duplicate CRL
// entries). The serial is the leaf's x509 SerialNumber (leaf.LeafCert().
// SerialNumber); it is a 62-bit random (serialNumber(), certgen.go:63) so a
// revocation is serial-scoped, NOT CA-scoped (the M2(b) principle: a SIBLING
// leaf2 NOT in the set STILL passes the handshake — T-PKI-REVOKED-REJECTED).
func (c *MeshCA) RevokeLeaf(serial *big.Int) error {
	if c == nil || c.caCert == nil {
		return errors.New("certgen: nil or uninitialized MeshCA")
	}
	if serial == nil {
		return errors.New("certgen: nil serial")
	}
	for _, s := range c.revokedSerials {
		if s.Cmp(serial) == 0 {
			return ErrSerialAlreadyRevoked
		}
	}
	c.revokedSerials = append(c.revokedSerials, new(big.Int).Set(serial))
	return nil
}

// IssueCRL signs an X.509 v2 Certificate Revocation List (RFC 5280) over the
// CA's current revoked-serial ledger. The CRL is the signed list the transport
// hot-reloads (ReloadCRL parses the PEM, extracts the serials into an in-memory
// set the VerifyPeerCertificate callback consults). An empty ledger yields a
// valid empty CRL (the stdlib omits the revokedCertificates sequence — a
// transport with no revoked serials rejects nothing, the byte-identical
// pre-revocation behavior). crlNumber is the CRL's sequence number (the v2
// cRLNumber extension); the caller passes a monotone counter so a hot-reload
// can detect a stale CRL (a regression in cRLNumber is a CA bug, disclosed but
// not enforced here — the transport swaps the set unconditionally on a
// successful parse).
func (c *MeshCA) IssueCRL(crlNumber int64) ([]byte, error) {
	if c == nil || c.caCert == nil {
		return nil, errors.New("certgen: nil or uninitialized MeshCA")
	}
	entries := make([]x509.RevocationListEntry, 0, len(c.revokedSerials))
	now := time.Now()
	for _, s := range c.revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(s),
			RevocationTime: now,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(crlNumber),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(1, 0, 0), // 1-year CRL validity window
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, c.caCert, c.caKey)
}

// WriteCRLPEM writes the CRL (PEM-encoded, type "X509 CRL") to crl.pem in dir
// and returns the path. It is the CRL sibling of WriteCAPEM: the CA publishes
// the revoked-serial list to disk the SAME way it publishes the trust anchor —
// the transport hot-reloads both via the SAME mechanism (the M3 triple
// hot-reload: leaf + CA pool + CRL, each atomic under the RWMutex).
func (c *MeshCA) WriteCRLPEM(dir string, crlDER []byte) (crlPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	crlPath = filepath.Join(dir, "crl.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(crlPath, pemBytes, 0o644); err != nil {
		return "", err
	}
	return crlPath, nil
}
