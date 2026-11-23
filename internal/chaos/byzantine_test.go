// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// Tests for Byzantine logical-counter ratchet injection and admission checks
// (verified via admission.PeerBucket.Accept rather than physical-clock caps).

import (
	"bytes"
	"crypto/rand"
	"math"
	"sync"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/identity"
	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// honestDelta builds a sync.CRDTDelta carrying a normal DotCounter value.
func honestDelta(t *testing.T, honestCounter uint64) *engsync.CRDTDelta {
	t.Helper()
	entry := engsync.CRDTEntry{
		PayloadDigest:  [32]byte{0x01},
		OriginNodeID:   [16]byte{0xaa},
		DotNodeID:      [16]byte{0xbb},
		DotCounter:     honestCounter,
		SystemTime:     1_000_000,
		ValidTimeStart: 1_000_000,
		ValidTimeEnd:   2_000_000,
		AssertionTime:  1_500_000,
		DecisionTime:   1_600_000,
		H3Index:        0x1234,
	}
	entityID := "entity-honest"
	return &engsync.CRDTDelta{
		Entries: func(yield func(entityID string, entry engsync.CRDTEntry) bool) {
			yield(entityID, entry)
		},
		OriginNodeID: [16]byte{0xaa},
		MerkleRoot:   [32]byte{0x02},
	}
}

// honestMultiEntryDelta builds a delta carrying N entries (for the
// incremental-ratchet acceptance arm).
func honestMultiEntryDelta(t *testing.T, baseCounter uint64, n int) *engsync.CRDTDelta {
	t.Helper()
	entries := make([]engsync.CRDTEntry, n)
	entityIDs := make([]string, n)
	for i := 0; i < n; i++ {
		entries[i] = engsync.CRDTEntry{
			PayloadDigest: [32]byte{byte(i)},
			OriginNodeID:  [16]byte{0xaa},
			DotNodeID:     [16]byte{0xbb},
			DotCounter:    baseCounter + uint64(i),
		}
		entityIDs[i] = "entity-" + string(rune('a'+i))
	}
	return &engsync.CRDTDelta{
		Entries: func(yield func(entityID string, entry engsync.CRDTEntry) bool) {
			for i := range entries {
				if !yield(entityIDs[i], entries[i]) {
					return
				}
			}
		},
		OriginNodeID: [16]byte{0xaa},
		MerkleRoot:   [32]byte{0x02},
	}
}

// drainDotCounters reads a delta's Entries Seq into a []uint64 of DotCounters
// (the partition.go drain idiom) for assertions.
func drainDotCounters(t *testing.T, delta *engsync.CRDTDelta) []uint64 {
	t.Helper()
	var out []uint64
	delta.Entries(func(_ string, entry engsync.CRDTEntry) bool {
		out = append(out, entry.DotCounter)
		return true
	})
	return out
}

// TestByzantine_A2RatchetCaughtByAdmission verifies that an A2 DotCounter
// ratchet is dropped by admission.PeerBucket.Accept in one admission check.
func TestByzantine_A2RatchetCaughtByAdmission(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	// Baseline delta: modest DotCounter (the peer's real causal position).
	const honestCounter = 42
	delta := honestDelta(t, honestCounter)

	mutated, _, err := InjectByzantineFaults(delta, priv, RatchetMax)
	if err != nil {
		t.Fatalf("InjectByzantineFaults: %v", err)
	}

	// Assert the entry's DotCounter was ratcheted toward MaxUint64.
	ratcheted := drainDotCounters(t, mutated)
	if len(ratcheted) != 1 {
		t.Fatalf("mutated delta has %d entries, want 1", len(ratcheted))
	}
	const wantMax uint64 = math.MaxUint64
	if ratcheted[0] != wantMax {
		t.Fatalf("DotCounter not ratcheted to MaxUint64: got %d, want %d",
			ratcheted[0], wantMax)
	}
	if ratcheted[0] == honestCounter {
		t.Fatal("DotCounter unchanged — injector did not ratchet")
	}

	// The catch: feed the attacker's [32]byte pubkey + the ratcheted
	// DotCounter to 3.1's PeerBucket.Accept. A MaxUint64 ratchet on a fresh
	// peer (budget = initialBudget = 1<<20) gives delta = MaxUint64 >> 1<<20
	// => budget drains to 0 => Drop in one admit.
	bucket := admission.NewPeerBucket()
	verdict, _ := bucket.Accept(pub[:], ratcheted[0])
	if verdict != admission.Drop {
		t.Fatalf("3.1 PeerBucket.Accept did not drop the A2 ratchet: got %v, want Drop (the per-peer EWMA drain)", verdict)
	}

	// Control arm: a baseline delta (no ratchet, modest delta) must Keep —
	// proving the bucket is not a no-op false-rejecter. A fresh peer
	// submitting a modest counter advancement stays within budget.
	pubHonest, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	honestVerdict, _ := bucket.Accept(pubHonest[:], 10)
	if honestVerdict != admission.Keep {
		t.Fatalf("baseline control arm was not Keep: got %v, want Keep (bucket must not be a false-rejecter)", honestVerdict)
	}
	// A second modest baseline admit (+1) must still Keep.
	honestVerdict2, _ := bucket.Accept(pubHonest[:], 11)
	if honestVerdict2 != admission.Keep {
		t.Fatalf("second baseline admit was not Keep: got %v, want Keep", honestVerdict2)
	}
}

// TestByzantine_A2RatchetIncrementalCaught demonstrates the realistic A2
// vector (RatchetIncremental): a sequence of admits with geometric+jittered
// deltas exhausts the 1<<20 budget in a bounded number of admits. The test
// asserts the bucket reaches Drop within a small bound.
func TestByzantine_A2RatchetIncrementalCaught(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	bucket := admission.NewPeerBucket()
	// RatchetIncremental advances by at least 1<<18 per admit against a 1<<20
	// initialBudget, draining within at most 4-5 admissions.
	const maxAdmits = 5
	var lastCounter uint64
	dropped := false
	for i := 0; i < maxAdmits; i++ {
		// Each injector call ratchets a fresh baseline delta incrementally.
		delta := honestDelta(t, lastCounter)
		mutated, _, err := InjectByzantineFaults(delta, priv, RatchetIncremental)
		if err != nil {
			t.Fatalf("InjectByzantineFaults (incremental, iter %d): %v", i, err)
		}
		ratcheted := drainDotCounters(t, mutated)
		if len(ratcheted) != 1 {
			t.Fatalf("iter %d: mutated delta has %d entries, want 1", i, len(ratcheted))
		}
		verdict, _ := bucket.Accept(pub[:], ratcheted[0])
		if verdict == admission.Drop {
			dropped = true
			break
		}
		lastCounter = ratcheted[0]
	}
	if !dropped {
		t.Fatalf("incremental A2 ratchet did not drain the bucket within %d admits (want Drop within bound)", maxAdmits)
	}
}

// TestByzantine_RatchetFrameIsCryptoValid verifies that the re-signed tampered
// frame passes VerifyCRDTFrame over the modified material while failing against
// untampered material.
func TestByzantine_RatchetFrameIsCryptoValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	delta := honestDelta(t, 42)
	mutated, sig, err := InjectByzantineFaults(delta, priv, RatchetMax)
	if err != nil {
		t.Fatalf("InjectByzantineFaults: %v", err)
	}

	// Reconstruct the signed material from the mutated delta (the canonical
	// 120-byte-per-entry layout) and Verify with the production bridge.
	ratcheted := drainDotCounters(t, mutated)
	if len(ratcheted) != 1 {
		t.Fatalf("mutated delta has %d entries, want 1", len(ratcheted))
	}
	// Drain the full mutated entry to reconstruct the signed material.
	var mutatedEntry engsync.CRDTEntry
	mutated.Entries(func(_ string, e engsync.CRDTEntry) bool {
		mutatedEntry = e
		return false
	})
	signedMaterial := canonicalDeltaBytes([]engsync.CRDTEntry{mutatedEntry})

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// Arm 1: the tampered-then-re-signed frame is cryptographically valid.
	if !identity.VerifyCRDTFrame(pub, signedMaterial, sig) {
		t.Fatal("VerifyCRDTFrame rejected the re-signed tampered frame (sig must be valid on tampered material)")
	}

	// Arm 2: the same sig over different (untampered) material must fail —
	// the sig binds to the mutated material, not a free pass.
	untampered := honestDelta(t, 42)
	var honestEntry engsync.CRDTEntry
	untampered.Entries(func(_ string, e engsync.CRDTEntry) bool {
		honestEntry = e
		return false
	})
	untamperedMaterial := canonicalDeltaBytes([]engsync.CRDTEntry{honestEntry})
	if bytes.Equal(untamperedMaterial, signedMaterial) {
		t.Fatal("untampered material equals tampered material — test setup is degenerate")
	}
	if identity.VerifyCRDTFrame(pub, untamperedMaterial, sig) {
		t.Fatal("VerifyCRDTFrame accepted the tampered sig over UNTAMPERED material — the sig does not bind to the mutated material (free-pass bug)")
	}
}

// TestByzantine_CanonicalLayoutMatchesCodec asserts the local canonical
// serializer (canonicalEntryBytes) produces byte-identical output to the
// production codec's encodeCRDTEntry for the same entry — proving the signed
// material is the production wire layout, not a fabricated serializer.
func TestByzantine_CanonicalLayoutMatchesCodec(t *testing.T) {
	entry := engsync.CRDTEntry{
		PayloadDigest:  [32]byte{0xde, 0xad, 0xbe, 0xef},
		OriginNodeID:   [16]byte{0xaa, 0xbb, 0xcc},
		DotNodeID:      [16]byte{0x11, 0x22, 0x33},
		DotCounter:     0x0123456789abcdef,
		SystemTime:     -12345,
		ValidTimeStart: 100,
		ValidTimeEnd:   200,
		AssertionTime:  150,
		DecisionTime:   175,
		H3Index:        0xdeadbeefcafebabe,
	}

	var local [entryWireLen]byte
	canonicalEntryBytes(local[:], entry)

	var codec [crdtEntryWireLen]byte
	encodeCRDTEntry(codec[:], entry)

	if entryWireLen != crdtEntryWireLen {
		t.Fatalf("entryWireLen=%d != codec crdtEntryWireLen=%d", entryWireLen, crdtEntryWireLen)
	}
	if !bytes.Equal(local[:], codec[:]) {
		t.Fatalf("canonical layout does not match codec:\n local=%x\n codec=%x", local[:], codec[:])
	}
}

// TestByzantine_NoInPlaceDeltaMutation is the no-in-place-mutation test: the
// injector must not mutate the input *sync.CRDTDelta's fields. It builds an
// input delta, records its OriginNodeID and the original DotCounter, calls
// InjectByzantineFaults, and asserts the input delta's OriginNodeID is
// unchanged and the input delta's Entries still yields the original DotCounter
// values (the injector drained and copied; it did not mutate in place).
func TestByzantine_NoInPlaceDeltaMutation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	const honestCounter = 7
	delta := honestDelta(t, honestCounter)
	originBefore := delta.OriginNodeID
	merkleBefore := delta.MerkleRoot

	_, _, err = InjectByzantineFaults(delta, priv, RatchetMax)
	if err != nil {
		t.Fatalf("InjectByzantineFaults: %v", err)
	}

	// The input delta's exported fields must be byte-identical.
	if delta.OriginNodeID != originBefore {
		t.Fatalf("injector mutated input delta.OriginNodeID: before=%x after=%x", originBefore, delta.OriginNodeID)
	}
	if delta.MerkleRoot != merkleBefore {
		t.Fatalf("injector mutated input delta.MerkleRoot: before=%x after=%x", merkleBefore, delta.MerkleRoot)
	}

	// The input delta's Entries must still yield the original
	// DotCounter — the injector drained and copied; it did not ratchet in place.
	after := drainDotCounters(t, delta)
	if len(after) != 1 {
		t.Fatalf("input delta Entries yields %d entries, want 1", len(after))
	}
	if after[0] != honestCounter {
		t.Fatalf("injector mutated input delta's DotCounter in place: got %d, want original %d (the drain+copy seam must not touch the input)", after[0], honestCounter)
	}
}

// TestByzantine_InjectorConcurrentNoRace verifies concurrent InjectByzantineFaults
// and PeerBucket.Accept calls execute with no data races.
func TestByzantine_InjectorConcurrentNoRace(t *testing.T) {
	bucket := admission.NewPeerBucket()
	const concurrency = 32
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for g := 0; g < concurrency; g++ {
		go func(id int) {
			defer wg.Done()
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Errorf("goroutine %d: GenerateKey: %v", id, err)
				return
			}
			delta := honestDelta(t, uint64(id))
			mutated, _, err := InjectByzantineFaults(delta, priv, RatchetMax)
			if err != nil {
				t.Errorf("goroutine %d: InjectByzantineFaults: %v", id, err)
				return
			}
			ratcheted := drainDotCounters(t, mutated)
			if len(ratcheted) != 1 || ratcheted[0] != math.MaxUint64 {
				t.Errorf("goroutine %d: ratchet wrong: %v", id, ratcheted)
				return
			}
			// Each goroutine's distinct pubkey hashes to its own shard.
			verdict, _ := bucket.Accept(pub[:], ratcheted[0])
			if verdict != admission.Drop {
				t.Errorf("goroutine %d: Accept = %v, want Drop", id, verdict)
			}
		}(g)
	}
	wg.Wait()
}

// TestByzantine_NilDeltaRejected asserts the injector returns a non-nil error
// (never a panic) on nil or empty delta inputs.
func TestByzantine_NilDeltaRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	if _, _, err := InjectByzantineFaults(nil, priv, RatchetMax); err == nil {
		t.Fatal("InjectByzantineFaults(nil) returned nil error — must reject nil delta")
	}
	emptyDelta := &engsync.CRDTDelta{Entries: nil}
	if _, _, err := InjectByzantineFaults(emptyDelta, priv, RatchetMax); err == nil {
		t.Fatal("InjectByzantineFaults(nil Entries) returned nil error — must reject nil Entries")
	}
}
