// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package identity

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// ADR-0037: the Directory BOTH-pubkey provisioning guards.
//
// ADR-0036 disclosed that the Directory (directory.go) carries ONLY
// the ed25519.PublicKey — under --hybrid-verify a hybrid frame's receiver cannot
// resolve the origin's ML-DSA-65 pubkey, so EVERY hybrid frame is REJECTED (the
// honest NOT-YET). This change grows the Directory with a parallel mPQ map +
// RegisterPQ (the sibling of Register) + LookupBoth (the sibling of Lookup that
// returns BOTH pubkeys). These guards prove the grown Directory:
//
//	register-pq-both — RegisterPQ + LookupBoth resolve BOTH
// pubkeys for a hybrid-provisioned origin.
//	lookupboth-classical-only — a peer that registered ONLY the
// classical key returns (edPub, nil, true)
// from LookupBoth (the earlier default;
// the hybrid verify rejects via the
// nil-pqPub STRICT mode).
//	lookupboth-miss — a LookupBoth for an UNREGISTERED origin
// returns (nil, nil, false) — a DropVerify
// on the receiver's hot path (the SAME
// verdict a classical Lookup miss produces).
//	register-pq-nil-reject — RegisterPQ rejects a nil pqPub (a nil
// key cannot be a valid ML-DSA-65
// verification key; the zero-alloc guard
// Register applies to a non-32-byte
// classical key, carried to the PQ key).
//	register-lookup-unchanged — the classical Register/Lookup are
// byte-identical (the grown
// Directory does NOT touch the classical
// seam; the classical-only verify path is
// UNCHANGED — backward-compat).
// ──────────────────────────────────────────────────────────────────────────

// dirTestSeed is a 32-byte Ed25519 seed for the Directory guards (deterministic;
// the SAME seed the Directory Register takes). NOT a secret.
var dirTestSeed = bytes.Repeat([]byte{0x5a}, ed25519.SeedSize) // 32 bytes of 'Z'

// dirMintKeys derives an Ed25519 seed->pubkey + nodeID + an ML-DSA-65 keypair
// for the Directory guards. Returns nodeID, edPub, pqPub.
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

// TestPQ_DirRegisterPQBoth proves RegisterPQ +
// LookupBoth resolve BOTH pubkeys for a hybrid-provisioned origin (Register the
// classical key, RegisterPQ the PQ key, then LookupBoth returns BOTH). This is
// the provisioning seam the receiver's HandleHybridFrame calls.
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
		t.Fatalf("register-pq-both: LookupBoth ok=false for a hybrid-provisioned origin, want true")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("register-pq-both: LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != pqPub {
		t.Fatalf("register-pq-both: LookupBoth pqPub mismatch — got %p, want %p (the SAME pointer the Directory stores)", gotPQ, pqPub)
	}
	t.Logf("register-pq-both PASS: RegisterPQ + LookupBoth resolve BOTH pubkeys for a hybrid-provisioned origin (the provisioning seam HandleHybridFrame calls)")
}

// TestPQ_DirLookupBothClassicalOnly proves
// a peer that registered ONLY the classical key (the earlier default) returns
// (edPub, nil, true) from LookupBoth — the hybrid verify then rejects via the
// nil-pqPub STRICT mode (the contract carried forward). This is the
// honest posture under the default (a non-PQ-provisioned peer is NOT
// hybrid-verify-ready).
func TestPQ_DirLookupBothClassicalOnly(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// RegisterPQ is NOT called — the earlier default (classical-only).
	gotEd, gotPQ, ok := d.LookupBoth(nodeID)
	if !ok {
		t.Fatalf("lookupboth-classical-only: LookupBoth ok=false for a classical-provisioned origin, want true (the classical key IS registered)")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("lookupboth-classical-only: LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != nil {
		t.Fatalf("lookupboth-classical-only: LookupBoth pqPub=%p, want nil (the peer registered ONLY the classical key — the pre- default; the hybrid verify rejects via the nil-pqPub STRICT mode)", gotPQ)
	}
	t.Logf("lookupboth-classical-only PASS: a classical-only-provisioned peer returns (edPub, nil, true) — the hybrid verify rejects via the nil-pqPub STRICT mode")
}

// TestPQ_DirLookupBothMiss proves a LookupBoth for an
// UNREGISTERED origin returns (nil, nil, false) — a DropVerify on the
// receiver's hot path (the receiver cannot verify an unknown origin under ANY
// seam — the SAME verdict a classical Lookup miss produces).
func TestPQ_DirLookupBothMiss(t *testing.T) {
	d := NewDirectory()
	var unknown [16]byte
	copy(unknown[:], []byte("unknown-origin-id"))
	gotEd, gotPQ, ok := d.LookupBoth(unknown)
	if ok {
		t.Fatalf("lookupboth-miss: LookupBoth ok=true for an UNREGISTERED origin, want false (a DropVerify on the receiver's hot path)")
	}
	if gotEd != nil {
		t.Fatalf("lookupboth-miss: LookupBoth edPub=%x, want nil", gotEd)
	}
	if gotPQ != nil {
		t.Fatalf("lookupboth-miss: LookupBoth pqPub=%p, want nil", gotPQ)
	}
	t.Logf("lookupboth-miss PASS: an unregistered origin returns (nil, nil, false) — a DropVerify (the SAME verdict a classical Lookup miss produces)")
}

// TestPQ_DirRegisterPQNilReject proves
// RegisterPQ rejects a nil pqPub (a nil key cannot be a valid ML-DSA-65
// verification key — the zero-alloc guard Register applies to a non-32-byte
// classical key, carried to the PQ key). The guard passes a nil pqPub + asserts
// ErrDirectoryBadPQPubKey.
func TestPQ_DirRegisterPQNilReject(t *testing.T) {
	nodeID, _, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.RegisterPQ(nodeID, nil); err != ErrDirectoryBadPQPubKey {
		t.Fatalf("register-pq-nil-reject: RegisterPQ with a nil pqPub returned err=%v, want ErrDirectoryBadPQPubKey (a nil key cannot be a valid ML-DSA-65 verification key)", err)
	}
	t.Logf("register-pq-nil-reject PASS: a nil pqPub is rejected (the zero-alloc guard carried to the PQ key)")
}

// TestPQ_DirRegisterLookupUnchanged proves
// the classical Register/Lookup are byte-identical — the grown Directory
// does NOT touch the classical seam (the classical-only verify path is
// UNCHANGED; backward-compat). The guard Registers a classical key + asserts
// Lookup returns it (the EXACT earlier behavior).
func TestPQ_DirRegisterLookupUnchanged(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The classical Lookup (NOT LookupBoth) — the EXACT earlier seam.
	got, ok := d.Lookup(nodeID)
	if !ok {
		t.Fatalf("register-lookup-unchanged: Lookup ok=false, want true (the classical seam is byte-identical)")
	}
	if !bytes.Equal(got, edPub) {
		t.Fatalf("register-lookup-unchanged: Lookup edPub mismatch — got %x, want %x (the classical seam is byte-identical)", got, edPub)
	}
	t.Logf("register-lookup-unchanged PASS: the classical Register/Lookup are byte-identical (the grown Directory does NOT touch the classical seam)")
}
