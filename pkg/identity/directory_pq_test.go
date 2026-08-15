package identity

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// Day 32 (ADR-0037): the Directory BOTH-pubkey provisioning teeth.
//
// Day 31 (ADR-0036) disclosed that the Directory (directory.go) carries ONLY
// the ed25519.PublicKey — under --hybrid-verify a hybrid frame's receiver cannot
// resolve the origin's ML-DSA-65 pubkey, so EVERY hybrid frame is REJECTED (the
// honest NOT-YET). Day 32 grows the Directory with a parallel mPQ map +
// RegisterPQ (the sibling of Register) + LookupBoth (the sibling of Lookup that
// returns BOTH pubkeys). These teeth prove the grown Directory:
//
//	T-PQ-DIR-REGISTER-PQ-BOTH      — RegisterPQ + LookupBoth resolve BOTH
//	                                 pubkeys for a hybrid-provisioned origin.
//	T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY — a peer that registered ONLY the
//	                                 classical key returns (edPub, nil, true)
//	                                 from LookupBoth (the pre-Day-32 default;
//	                                 the hybrid verify rejects via the
//	                                 nil-pqPub STRICT mode).
//	T-PQ-DIR-LOOKUPBOTH-MISS       — a LookupBoth for an UNREGISTERED origin
//	                                 returns (nil, nil, false) — a DropVerify
//	                                 on the receiver's hot path (the SAME
//	                                 verdict a classical Lookup miss produces).
//	T-PQ-DIR-REGISTER-PQ-NIL-REJECT — RegisterPQ rejects a nil pqPub (a nil
//	                                 key cannot be a valid ML-DSA-65
//	                                 verification key; the zero-alloc guard
//	                                 Register applies to a non-32-byte
//	                                 classical key, carried to the PQ key).
//	T-PQ-DIR-REGISTER-LOOKUP-UNCHANGED — the classical Register/Lookup are
//	                                 byte-identical Day-31 (the grown
//	                                 Directory does NOT touch the classical
//	                                 seam; the classical-only verify path is
//	                                 UNCHANGED — backward-compat).
// ──────────────────────────────────────────────────────────────────────────

// dirTestSeed is a 32-byte Ed25519 seed for the Directory teeth (deterministic;
// the SAME seed the Directory Register takes). NOT a secret.
var dirTestSeed = bytes.Repeat([]byte{0x5a}, ed25519.SeedSize) // 32 bytes of 'Z'

// dirMintKeys derives an Ed25519 seed->pubkey + nodeID + an ML-DSA-65 keypair
// for the Directory teeth. Returns nodeID, edPub, pqPub.
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

// TestPQ_DirRegisterPQBoth (T-PQ-DIR-REGISTER-PQ-BOTH) proves RegisterPQ +
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
		t.Fatalf("T-PQ-DIR-REGISTER-PQ-BOTH: LookupBoth ok=false for a hybrid-provisioned origin, want true")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("T-PQ-DIR-REGISTER-PQ-BOTH: LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != pqPub {
		t.Fatalf("T-PQ-DIR-REGISTER-PQ-BOTH: LookupBoth pqPub mismatch — got %p, want %p (the SAME pointer the Directory stores)", gotPQ, pqPub)
	}
	t.Logf("T-PQ-DIR-REGISTER-PQ-BOTH PASS: RegisterPQ + LookupBoth resolve BOTH pubkeys for a hybrid-provisioned origin (the provisioning seam HandleHybridFrame calls)")
}

// TestPQ_DirLookupBothClassicalOnly (T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY) proves
// a peer that registered ONLY the classical key (the pre-Day-32 default) returns
// (edPub, nil, true) from LookupBoth — the hybrid verify then rejects via the
// nil-pqPub STRICT mode (the Day-31 contract carried forward). This is the
// honest posture under the default (a non-PQ-provisioned peer is NOT
// hybrid-verify-ready).
func TestPQ_DirLookupBothClassicalOnly(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// RegisterPQ is NOT called — the pre-Day-32 default (classical-only).
	gotEd, gotPQ, ok := d.LookupBoth(nodeID)
	if !ok {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY: LookupBoth ok=false for a classical-provisioned origin, want true (the classical key IS registered)")
	}
	if !bytes.Equal(gotEd, edPub) {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY: LookupBoth edPub mismatch — got %x, want %x", gotEd, edPub)
	}
	if gotPQ != nil {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY: LookupBoth pqPub=%p, want nil (the peer registered ONLY the classical key — the pre-Day-32 default; the hybrid verify rejects via the nil-pqPub STRICT mode)", gotPQ)
	}
	t.Logf("T-PQ-DIR-LOOKUPBOTH-CLASSICAL-ONLY PASS: a classical-only-provisioned peer returns (edPub, nil, true) — the hybrid verify rejects via the nil-pqPub STRICT mode")
}

// TestPQ_DirLookupBothMiss (T-PQ-DIR-LOOKUPBOTH-MISS) proves a LookupBoth for an
// UNREGISTERED origin returns (nil, nil, false) — a DropVerify on the
// receiver's hot path (the receiver cannot verify an unknown origin under ANY
// seam — the SAME verdict a classical Lookup miss produces).
func TestPQ_DirLookupBothMiss(t *testing.T) {
	d := NewDirectory()
	var unknown [16]byte
	copy(unknown[:], []byte("unknown-origin-id"))
	gotEd, gotPQ, ok := d.LookupBoth(unknown)
	if ok {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-MISS: LookupBoth ok=true for an UNREGISTERED origin, want false (a DropVerify on the receiver's hot path)")
	}
	if gotEd != nil {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-MISS: LookupBoth edPub=%x, want nil", gotEd)
	}
	if gotPQ != nil {
		t.Fatalf("T-PQ-DIR-LOOKUPBOTH-MISS: LookupBoth pqPub=%p, want nil", gotPQ)
	}
	t.Logf("T-PQ-DIR-LOOKUPBOTH-MISS PASS: an unregistered origin returns (nil, nil, false) — a DropVerify (the SAME verdict a classical Lookup miss produces)")
}

// TestPQ_DirRegisterPQNilReject (T-PQ-DIR-REGISTER-PQ-NIL-REJECT) proves
// RegisterPQ rejects a nil pqPub (a nil key cannot be a valid ML-DSA-65
// verification key — the zero-alloc guard Register applies to a non-32-byte
// classical key, carried to the PQ key). The tooth passes a nil pqPub + asserts
// ErrDirectoryBadPQPubKey.
func TestPQ_DirRegisterPQNilReject(t *testing.T) {
	nodeID, _, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.RegisterPQ(nodeID, nil); err != ErrDirectoryBadPQPubKey {
		t.Fatalf("T-PQ-DIR-REGISTER-PQ-NIL-REJECT: RegisterPQ with a nil pqPub returned err=%v, want ErrDirectoryBadPQPubKey (a nil key cannot be a valid ML-DSA-65 verification key)", err)
	}
	t.Logf("T-PQ-DIR-REGISTER-PQ-NIL-REJECT PASS: a nil pqPub is rejected (the zero-alloc guard carried to the PQ key)")
}

// TestPQ_DirRegisterLookupUnchanged (T-PQ-DIR-REGISTER-LOOKUP-UNCHANGED) proves
// the classical Register/Lookup are byte-identical Day-31 — the grown Directory
// does NOT touch the classical seam (the classical-only verify path is
// UNCHANGED; backward-compat). The tooth Registers a classical key + asserts
// Lookup returns it (the EXACT pre-Day-32 behavior).
func TestPQ_DirRegisterLookupUnchanged(t *testing.T) {
	nodeID, edPub, _ := dirMintKeys(t)
	d := NewDirectory()
	if err := d.Register(nodeID, edPub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The classical Lookup (NOT LookupBoth) — the EXACT pre-Day-32 seam.
	got, ok := d.Lookup(nodeID)
	if !ok {
		t.Fatalf("T-PQ-DIR-REGISTER-LOOKUP-UNCHANGED: Lookup ok=false, want true (the classical seam is byte-identical Day-31)")
	}
	if !bytes.Equal(got, edPub) {
		t.Fatalf("T-PQ-DIR-REGISTER-LOOKUP-UNCHANGED: Lookup edPub mismatch — got %x, want %x (the classical seam is byte-identical Day-31)", got, edPub)
	}
	t.Logf("T-PQ-DIR-REGISTER-LOOKUP-UNCHANGED PASS: the classical Register/Lookup are byte-identical Day-31 (the grown Directory does NOT touch the classical seam)")
}
