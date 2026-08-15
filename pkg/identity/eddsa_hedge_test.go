//go:build !aws_lc_hedged

package identity

import (
	"crypto/rand"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// TestSignCRDTFrame_VerifiesUnderVerifyCRDTFrame is the load-bearing
// verifier-compat test (GB12.g). It proves the hedged signature produced by
// SignCRDTFrame verifies under the UNCHANGED VerifyCRDTFrame. If this test
// fails, the construction is WRONG -- do NOT weaken the verifier to make it
// pass; fix the construction per FINDING-C.
func TestSignCRDTFrame_VerifiesUnderVerifyCRDTFrame(t *testing.T) {
	// Generate a seed
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Derive public key for verification
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Test message
	msg := []byte("test CRDT delta frame message")

	// Sign with hedged signing
	sig, err := SignCRDTFrame(seed, msg)
	if err != nil {
		t.Fatalf("SignCRDTFrame failed: %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// Verify with the UNCHANGED VerifyCRDTFrame
	if !VerifyCRDTFrame(pub, msg, sig) {
		t.Fatal("VerifyCRDTFrame rejected valid hedged signature -- construction is BROKEN per FINDING-C")
	}

	// Verify non-determinism: two signatures on the same message should differ
	sig2, err := SignCRDTFrame(seed, msg)
	if err != nil {
		t.Fatalf("SignCRDTFrame second call failed: %v", err)
	}

	if len(sig2) != ed25519.SignatureSize {
		t.Fatalf("second signature length: got %d, want %d", len(sig2), ed25519.SignatureSize)
	}

	// Both should verify
	if !VerifyCRDTFrame(pub, msg, sig2) {
		t.Fatal("VerifyCRDTFrame rejected second valid hedged signature")
	}

	// Signatures should be different (non-deterministic)
	if string(sig) == string(sig2) {
		t.Fatal("hedged signatures are identical -- nonce is NOT randomized")
	}
}

// TestSignCRDTFrame_InvalidSeed tests error handling for invalid seed length.
func TestSignCRDTFrame_InvalidSeed(t *testing.T) {
	msg := []byte("test message")

	// Too short seed
	_, err := SignCRDTFrame([]byte("short"), msg)
	if err == nil {
		t.Error("expected error for short seed, got nil")
	}

	// Too long seed
	_, err = SignCRDTFrame(make([]byte, ed25519.SeedSize+1), msg)
	if err == nil {
		t.Error("expected error for long seed, got nil")
	}
}

// TestSignCRDTFrame_DeterministicControl verifies the deterministic circl.Sign
// produces signatures that also verify (control test).
func TestSignCRDTFrame_DeterministicControl(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	msg := []byte("deterministic control message")

	// Deterministic circl.Sign
	sig := ed25519.Sign(priv, msg)

	if !VerifyCRDTFrame(pub, msg, sig) {
		t.Fatal("VerifyCRDTFrame rejected deterministic circl signature -- verifier is broken")
	}

	// Deterministic signatures should be identical
	sig2 := ed25519.Sign(priv, msg)
	if string(sig) != string(sig2) {
		t.Error("deterministic circl signatures differ -- unexpected")
	}
}
