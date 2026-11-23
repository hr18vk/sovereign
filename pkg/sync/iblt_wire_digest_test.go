// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"
)

// TestIBLT_WireDigestRoundTripConverged marshals and unmarshals a converged
// peer's digest before GenerateDelta. A correct round trip yields no entries;
// a corrupted digest instead causes an unnecessary delta or full-keyset
// fallback. TestIBLT_WireDigestRoundTripDiverged supplies the diverged control.
func TestIBLT_WireDigestRoundTripConverged(t *testing.T) {
	nodeID := [16]byte{0xF0, 0x21}
	for _, total := range []int{1200, 10000} { // 1200 = saturation regime; 10000 = production keyset
		t.Run(fmt.Sprintf("keyset=%d", total), func(t *testing.T) {
			engineA := newTestEngine(t, nodeID, 0)
			engineB := newTestEngine(t, nodeID, 0)
			for i := 0; i < total; i++ {
				entry := CRDTEntry{
					SystemTime:    int64(1_700_000_000 + i),
					H3Index:       uint64(i),
					PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
				}
				eid := fmt.Sprintf("k-%d", i)
				engineA.InsertLocal(eid, entry)
				engineB.InsertLocal(eid, entry) // converged: identical keyset
			}
			// Deterministic seeds (golden-ratio spread) so the test never flakes.
			for s := 0; s < 6; s++ {
				seed := Uint64ToSeed(uint64(s+1) * 0x9E3779B97F4A7C15)
				// Exercise the complete mesh digest path before reconciliation.
				digestB := engineB.GenerateDigestWithSeed(seed)
				wire, err := MarshalIBLT(digestB)
				if err != nil {
					t.Fatalf("MarshalIBLT failed: %v", err)
				}
				digestB.Release()
				remoteIBLT, err := UnmarshalIBLT(wire)
				if err != nil {
					t.Fatalf("UnmarshalIBLT failed: %v", err)
				}
				delta := engineA.GenerateDelta(remoteIBLT)
				n := 0
				delta.Entries(func(string, CRDTEntry) bool { n++; return true })
				delta.Release()
				remoteIBLT.Release()
				if n != 0 {
					t.Errorf("converged keyset=%d seed=%d produced a %d-entry delta after the wire round trip; want 0",
						total, s, n)
				}
			}
		})
	}
}

// TestIBLT_WireDigestRoundTripDiverged supplies the diverged control: with B
// empty and A populated, the wire round trip must return A's full keyset. This
// distinguishes the converged test from a decoder that always returns no delta.
func TestIBLT_WireDigestRoundTripDiverged(t *testing.T) {
	nodeID := [16]byte{0xF0, 0x21}
	const total = 2000
	engineA := newTestEngine(t, nodeID, 0)
	engineB := newTestEngine(t, nodeID, 0) // B stays empty (fully diverged)
	rng := rand.New(rand.NewSource(0xF21))
	for i := 0; i < total; i++ {
		entry := CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
		}
		engineA.InsertLocal(fmt.Sprintf("k-%d", i), entry)
		_ = rng // reserved
	}
	seed := Uint64ToSeed(0x9E3779B97F4A7C15)
	digestB := engineB.GenerateDigestWithSeed(seed) // empty digest
	wire, err := MarshalIBLT(digestB)
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	digestB.Release()
	remoteIBLT, err := UnmarshalIBLT(wire)
	if err != nil {
		t.Fatalf("UnmarshalIBLT: %v", err)
	}
	delta := engineA.GenerateDelta(remoteIBLT)
	n := 0
	delta.Entries(func(string, CRDTEntry) bool { n++; return true })
	delta.Release()
	remoteIBLT.Release()
	if n != total {
		t.Fatalf("diverged wire round trip returned %d entries; want the full %d-entry keyset", n, total)
	}
	t.Logf("diverged control returned the full %d-entry keyset through the wire round trip", n)
}

// TestIBLT_RelayJoinConvergedPrunes checks digest convergence after a peer
// applies the origin's delta through Join with a different node ID.
// MerkleRootFromShards covers only the dot; HashCausalDot also covers
// PayloadDigest. Join must preserve both, or matching Merkle roots would hide
// an IBLT difference for every entry.
func TestIBLT_RelayJoinConvergedPrunes(t *testing.T) {
	engineA := newTestEngine(t, [16]byte{0x0A}, 0) // the origin
	engineB := newTestEngine(t, [16]byte{0x0B}, 0) // the relay peer (different nodeID)
	const total = 1000
	for i := 0; i < total; i++ {
		entry := CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
		}
		engineA.InsertLocal(fmt.Sprintf("k-%d", i), entry)
	}
	// Apply the origin's full delta through the same Join entry point used by
	// the mesh receive path.
	full := engineA.GenerateDelta(NewIBLT(1, 4))
	engineB.Join(*full)
	full.Release()
	// The Merkle roots must match (dots preserved by Join).
	if engineA.MerkleRootFromShards() != engineB.MerkleRootFromShards() {
		t.Fatalf("Join did not converge the Merkle root — the dots diverged")
	}
	// A matching Merkle root is insufficient if Join changed PayloadDigest:
	// HashCausalDot includes that digest, so every IBLT key would differ.
	for s := 0; s < 8; s++ {
		seed := Uint64ToSeed(uint64(s+1) * 0x9E3779B97F4A7C15)
		digestB := engineB.GenerateDigestWithSeed(seed)
		delta := engineA.GenerateDelta(digestB)
		n := 0
		delta.Entries(func(string, CRDTEntry) bool { n++; return true })
		delta.Release()
		digestB.Release()
		if n != 0 {
			t.Errorf("after Join, origin.GenerateDelta(peer digest) returned %d entries on seed %d; want 0 because Join must preserve both dots and payload digests", n, s)
		}
	}
}
