// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// Directory hybrid provisioning tests (ADR-0037): mPQ, RegisterPQ, LookupBoth.
//
//	TestPQ_DirRegisterPQBoth        — RegisterPQ + LookupBoth resolve both keys.
//	TestPQ_DirLookupBothClassicalOnly — classical-only returns (edPub, nil, true).
//	TestPQ_DirLookupBothMiss        — unregistered origin returns (nil, nil, false).
//	TestPQ_DirRegisterPQNilReject   — RegisterPQ rejects nil pqPub.
//	TestPQ_DirRegisterLookupUnchanged — Register and Lookup behavior unchanged.
// ──────────────────────────────────────────────────────────────────────────

// dirTestSeed is a 32-byte Ed25519 seed for the Directory tests (deterministic;
// the same seed the Directory Register takes). Not a secret.
var dirTestSeed = bytes.Repeat([]byte{0x5a}, ed25519.SeedSize) // 32 bytes of 'Z'

// dirMintKeys derives an Ed25519 seed->pubkey + nodeID + an ML-DSA-65 keypair
// for the Directory tests. Returns nodeID, edPub, pqPub.
func dirMintKeys(t *testing.T) (nodeID [16]byte, edPub ed25519.PublicKey, pqPub *mldsa.PublicKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(dirTestSeed)
	edPub = priv.Public().(ed25519.PublicKey)
	copy(nodeID[:], edPub[:16])
	pqPriv, err := GeneratePreviewKey65(dirTestSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pqPub = pqPriv.Public().(*mldsa.PublicKey)
	return nodeID, edPub, pqPub
}

// TestPQ_DirRegisterPQBoth verifies that RegisterPQ + LookupBoth resolve both
// pubkeys for a hybrid-provisioned origin.
func TestPQ_DirRegisterPQBoth(t *testing.T) {
	nodeID, edPub, pqPub := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := d.RegisterPQ(nodeID, pqPub); err != nil {
		t.Fatalf("RegisterPQ: %v", err)
	}
	gotEd, gotPQ, ok := d.LookupBoth(nodeID)
	if !ok {
		t.Fatalf("LookupBoth ok=false for hybrid-provisioned origin, want true")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != pqPub {
		t.Fatalf("LookupBoth pqPub mismatch — got %p, want %p", gotPQ, pqPub)
	}
	t.Logf("RegisterPQ + LookupBoth resolve both pubkeys for a hybrid-provisioned origin")
}

// TestPQ_DirLookupBothClassicalOnly proves a peer that registered only the
// classical key (the pre-ADR-0037 default) returns (edPub, nil, true) from
// LookupBoth — the hybrid verify then rejects via the nil-pqPub strict mode
// (the ADR-0036 contract carried forward). This is the posture under the
// default (a non-PQ-provisioned peer is not hybrid-verify-ready).
func TestPQ_DirLookupBothClassicalOnly(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// RegisterPQ is not called — the pre-ADR-0037 default (classical-only).
	gotEd, gotPQ, ok := d.LookupBoth(nodeID)
	if !ok {
		t.Fatalf("LookupBoth ok=false for a classical-provisioned origin, want true (the classical key is registered)")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != nil {
		t.Fatalf("LookupBoth pqPub=%p, want nil (the peer registered only the classical key — the pre-ADR-0037 default; the hybrid verify rejects via the nil-pqPub strict mode)", gotPQ)
	}
	t.Logf("a classical-only-provisioned peer returns (edPub, nil, true) — the hybrid verify rejects via the nil-pqPub strict mode")
}

// TestPQ_DirLookupBothMiss verifies that LookupBoth for an unregistered origin
// returns (nil, nil, false).
func TestPQ_DirLookupBothMiss(t *testing.T) {
	d := NewDirectory()
	var unknown [16]byte
	copy(unknown[:], []byte("unknown-origin-id"))
	gotEd, gotPQ, ok := d.LookupBoth(unknown)
	if ok {
		t.Fatalf("LookupBoth ok=true for unregistered origin, want false")
	}
	if gotEd != nil {
		t.Fatalf("LookupBoth edPub=%x, want nil", gotEd)
	}
	if gotPQ != nil {
		t.Fatalf("LookupBoth pqPub=%p, want nil", gotPQ)
	}
	t.Logf("unregistered origin returns (nil, nil, false)")
}

// TestPQ_DirRegisterPQNilReject verifies that RegisterPQ rejects a nil pqPub.
func TestPQ_DirRegisterPQNilReject(t *testing.T) {
	nodeID, _, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.RegisterPQ(nodeID, nil); err != ErrDirectoryBadPQPubKey {
		t.Fatalf("RegisterPQ with nil pqPub returned err=%v, want ErrDirectoryBadPQPubKey", err)
	}
	t.Logf("nil pqPub rejected with ErrDirectoryBadPQPubKey")
}

// TestPQ_DirRegisterLookupUnchanged proves the classical Register/Lookup are
// byte-identical to ADR-0036 — the grown Directory does not touch the classical
// seam (the classical-only verify path is unchanged; backward-compat). The test
// registers a classical key and asserts Lookup returns it (the exact
// pre-ADR-0037 behavior).
func TestPQ_DirRegisterLookupUnchanged(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The classical Lookup (not LookupBoth) — the exact pre-ADR-0037 seam.
	got, ok := d.Lookup(nodeID)
	if !ok {
		t.Fatalf("Lookup ok=false, want true (the classical seam is byte-identical to ADR-0036)")
	}
	if !bytes.Equal(got, edPub) {
		t.Fatalf("Lookup edPub mismatch — got %x, want %x (the classical seam is byte-identical to ADR-0036)", got, edPub)
	}
	t.Logf("the classical Register/Lookup are byte-identical to ADR-0036 (the grown Directory does not touch the classical seam)")
}
