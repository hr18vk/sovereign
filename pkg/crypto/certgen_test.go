package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestCertgen_RoundTrip proves the dev-mesh CA mints a CA cert + a leaf cert
// whose PEM files round-trip: the CA cert parses, the leaf key+cert load as
// a tls.Certificate, and the leaf chains to the CA under x509 verification.
func TestCertgen_RoundTrip(t *testing.T) {
	ca, err := NewMeshCA()
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

	// CA PEM parses as a CERTIFICATE block.
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read caPath: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("ca.pem: not a CERTIFICATE pem block, got %+v", block)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if !caCert.IsCA {
		t.Fatal("CA cert IsCA=false, want true")
	}
	if caCert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("CA PublicKeyAlgorithm=%v, want Ed25519", caCert.PublicKeyAlgorithm)
	}

	// Leaf cert+key load as a tls.Certificate (the form tls.X509KeyPair /
	// tls.LoadX509KeyPair produce).
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("leaf cert chain len=%d, want 1 (leaf only; CA is the pool root)", len(tlsCert.Certificate))
	}
	leafCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	if leafCert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("leaf PublicKeyAlgorithm=%v, want Ed25519", leafCert.PublicKeyAlgorithm)
	}
	if leafCert.IsCA {
		t.Fatal("leaf cert IsCA=true, want false")
	}

	// The leaf chains to the CA under x509 verification (the trust root the
	// transport's RootCAs pool loads).
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}

	// Files exist at the documented names.
	for _, p := range []string{caPath, certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(p), err)
		}
	}
}
