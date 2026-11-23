// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package crypto provides the development-mesh certificate authority used by
// the TLS 1.3 transport and the sovereign-node binary.
//
// NewMeshCA creates an Ed25519 root key and a self-signed X.509 CA certificate.
// The CA signs per-node leaf certificates and writes PEM files for the TLS
// transport to load. This is not a production PKI: offline roots, intermediate
// CAs, HSM-backed key custody, and OCSP are out of scope (ADR-0006).
//
// Ed25519 matches the engine's identity bridge, which signs CRDT deltas with
// circl Ed25519. Both protocols therefore use 64-byte signatures. The
// CRDT-delta verification path uses circl ed25519 v1.6.4 and ZIP-215
// verification rules; its rejection of the standard library's ed25519 verifier
// does not apply to certificates. This package uses crypto/ed25519 and
// crypto/x509, including x509.CreateCertificate with x509.Ed25519. Transport
// mTLS keys and CRDT-delta signing keys remain separate; they share only the
// signature algorithm.
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

// MeshCA is the development-mesh certificate authority: an Ed25519 root key
// pair and the self-signed X.509 CA certificate that signs per-node leaves.
//
// MeshCA also owns the revoked-serial set included in each CRL (ADR-0035).
// RevokeLeaf adds a serial, and the next IssueCRL call signs the resulting
// list. The set has no synchronization; callers must serialize RevokeLeaf and
// IssueCRL with other CA operations.
type MeshCA struct {
	caKey          ed25519.PrivateKey
	caPub          ed25519.PublicKey
	caCert         *x509.Certificate
	caCertDER      []byte
	caNotBefore    time.Time
	revokedSerials []*big.Int
}

// Leaf is a per-node credential: an Ed25519 key pair and the X.509 leaf
// certificate signed by the MeshCA, plus the PEM-ready DER bytes.
type Leaf struct {
	nodeID      string
	leafKey     ed25519.PrivateKey
	leafPub     ed25519.PublicKey
	leafCert    *x509.Certificate
	leafCertDER []byte
}

// serialNumber returns an unpredictable X.509 serial number of at most 62
// bits. The random draw reduces the chance of collisions across certificates
// issued by this CA, and the bound keeps the ASN.1 INTEGER encoding small.
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 62) // 2^62
	return rand.Int(rand.Reader, limit)
}

// NewMeshCA generates a fresh Ed25519 root key and a self-signed X.509 CA
// certificate. The CA has IsCA set and KeyUsage CertSign|CRLSign; the TLS
// transport loads it into its RootCAs pool from the file written by WriteCAPEM.
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

// IssueLeaf mints a per-node leaf certificate signed by the CA. nodeID is the
// leaf CommonName, and the organizational unit is "node". KeyUsage permits
// digital signatures, and ExtKeyUsage permits both server and client
// authentication, so one leaf serves both sides of the mTLS handshake. The
// default lifetime is one year, starting one minute before issuance.
func (c *MeshCA) IssueLeaf(nodeID string) (*Leaf, error) {
	return c.issueLeaf(nodeID, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute).AddDate(1, 0, 0))
}

// IssueLeafWithLifetime mints a leaf certificate with caller-supplied NotBefore
// and NotAfter timestamps (ADR-0035). It shares the certificate template and
// signing path with IssueLeaf. Tests use it to cover expiry and rotation with
// expired or short-lived certificates. The node's rotation path still calls
// IssueLeaf: --cert-rotation-lifetime controls when renewal starts, not the
// default one-year lifetime of the new certificate. notAfter must be later
// than notBefore or x509.CreateCertificate rejects the template.
func (c *MeshCA) IssueLeafWithLifetime(nodeID string, notBefore, notAfter time.Time) (*Leaf, error) {
	return c.issueLeaf(nodeID, notBefore, notAfter)
}

// IssueLeafWithIP mints a one-year leaf whose IP subject alternative names
// come from ips (ADR-0041). It otherwise uses the same template and signing
// path as IssueLeaf. A peer that dials one of these IP addresses can verify it
// through the IP SAN when the address is used as the TLS server name. The
// bootstrap helper uses this method for nodes with known public addresses.
// A nil or empty ips produces the same DNS-only template as IssueLeaf. The
// DNS names remain nodeID and "localhost", so loopback dials still verify.
func (c *MeshCA) IssueLeafWithIP(nodeID string, ips []net.IP) (*Leaf, error) {
	return c.issueLeafIP(nodeID, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute).AddDate(1, 0, 0), ips)
}

// issueLeafIP implements leaf issuance with caller-supplied IP SANs. It uses
// the same template as issueLeaf except for IPAddresses. The separate path
// keeps IP-SAN handling out of the default and rotation issuance paths.
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
		IPAddresses:           ips, // nil or empty leaves hostname verification to DNSNames
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

// issueLeaf is the shared core of IssueLeaf and IssueLeafWithLifetime. Keeping
// the template and signing operation here prevents the lifetime-specific
// variant from omitting fields set by the default minter.
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
// returns the path. The CA private key is not written — a dev mesh CA key
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

// CRL issuance
//
// Expiry and revocation are separate handshake checks (ADR-0035). Go's TLS
// chain validation checks NotAfter and rejects expired leaves. A revoked
// certificate still chains to its CA, so the transport must also compare its
// serial with a CRL. IssueCRL signs the CA's revoked serials, WriteCRLPEM
// persists the list, and the transport's ReloadCRL method loads it into an
// in-memory set. VerifyPeerCertificate rejects a presented leaf whose serial
// is in that set. CRLs suit this operator-controlled CA because they work
// offline and do not require an OCSP responder or its network availability.
//
// IssueCRL uses x509.CreateRevocationList rather than the deprecated
// x509.CreateCRL. NewMeshCA sets KeyUsageCRLSign, and CreateCertificate
// populates the CA SubjectKeyId using the leftmost 160 bits of the public
// key's SHA-256 hash. These satisfy CreateRevocationList's requirements for
// the crlSign key usage and an issuer SubjectKeyId.
//
// The transport does not call RevocationList.CheckSignatureFrom when it loads
// a CRL. It trusts the local PEM file by path ownership, just as it loads the
// self-signed root through AppendCertsFromPEM without separately checking its
// self-signature. A deployment that accepts CRLs from an external CA must
// verify each CRL's signature and provenance before installing it.

// ErrSerialAlreadyRevoked is returned by RevokeLeaf when the serial is already
// in the revoked set. Although x509.ParseRevocationList tolerates duplicate
// entries, RevokeLeaf rejects them to keep each published CRL unambiguous.
var ErrSerialAlreadyRevoked = errors.New("certgen: serial already revoked")

// RevokeLeaf adds a serial to the CA's in-process revoked set for inclusion in
// the next IssueCRL call. Duplicate additions return ErrSerialAlreadyRevoked.
// Revocation is scoped to the leaf's SerialNumber, so other leaves signed by
// the same CA remain valid.
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

// IssueCRL signs an X.509 v2 Certificate Revocation List (RFC 5280) containing
// the CA's current revoked serials. The transport's ReloadCRL method parses
// the PEM and extracts the serials into the set consulted by
// VerifyPeerCertificate. With no revoked serials, IssueCRL returns a valid
// empty CRL and the transport rejects no certificates on revocation grounds.
// crlNumber becomes the cRLNumber extension. Callers should increase it for
// each new CRL so receivers can identify stale lists; this method does not
// enforce ordering, and the transport replaces its set after any successful
// parse.
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

// WriteCRLPEM writes crlDER as a PEM block of type "X509 CRL" to crl.pem in
// dir and returns the path. The transport can reload the resulting file with
// ReloadCRL; leaf, CA pool, and CRL reloads are independent and each swaps its
// state under the transport's RWMutex.
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
