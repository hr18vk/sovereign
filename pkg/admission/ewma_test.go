// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package admission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// makePub returns a deterministic 32-byte identity filled with b. Accept
// treats these bytes as opaque, so tests do not need generated key pairs or
// imports from the identity packages.
func makePub(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// pubBytes returns the []byte view of a [32]byte key for Accept calls.
func pubBytes(k [32]byte) []byte { return k[:] }

// TestPeerBucket_KeyIsArray32Byte checks that PeerBucketKey has [32]byte
// as its underlying type and that copying a public key preserves all 32
// bytes. The peer_key_slice_probe build tag supplies the complementary
// negative test: a circl Ed25519 public key is a slice, so using it as a map
// key fails with "invalid map key type ed25519.PublicKey".
func TestPeerBucket_KeyIsArray32Byte(t *testing.T) {
	// This assignment compiles only when [32]byte is the underlying type.
	var _ PeerBucketKey = [32]byte{}
	var k PeerBucketKey
	if size := len(k); size != 32 {
		t.Fatalf("PeerBucketKey must be exactly 32 bytes, got %d", size)
	}
	// A slice cannot be assigned to PeerBucketKey; changing the key to a
	// slice would also break the comparable map-key requirement.
	src := makePub(1)
	var sliceKey []byte = src[:]
	_ = sliceKey
	// Confirm that the copy path preserves the complete key.
	var pk PeerBucketKey
	seed := makePub(7)
	copy(pk[:], seed[:])
	if pk != seed {
		t.Fatalf("canonical copy of 32-byte pubkey into PeerBucketKey mismatched")
	}
}

// TestPeerBucket_RejectShortPub checks that a 31-byte public key returns Drop
// without creating a peer entry.
func TestPeerBucket_RejectShortPub(t *testing.T) {
	b := NewPeerBucket()
	short := make([]byte, 31) // len != 32
	got, _ := b.Accept(short, 1)
	if got != Drop {
		t.Fatalf("31-byte pubkey must be rejected (Drop), got %v", got)
	}
	// No peer bucket must have been created for the short key.
	if n := totalMapSize(b); n != 0 {
		t.Fatalf("short pubkey must not touch the bucket map, got size %d", n)
	}
}

// TestPeerBucket_RejectLongPub checks the same boundary for a 33-byte key.
func TestPeerBucket_RejectLongPub(t *testing.T) {
	b := NewPeerBucket()
	long := make([]byte, 33) // len != 32
	got, _ := b.Accept(long, 1)
	if got != Drop {
		t.Fatalf("33-byte pubkey must be rejected (Drop), got %v", got)
	}
	if n := totalMapSize(b); n != 0 {
		t.Fatalf("long pubkey must not touch the bucket map, got size %d", n)
	}
}

// totalMapSize counts entries across all shards so malformed-key tests can
// verify that Accept did not grow the map.
func totalMapSize(b *PeerBucket) int {
	n := 0
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// TestPeerBucket_HonestPeerKeepsBudget checks that 1,000 consecutive counters
// remain within a fresh peer's budget without interim watermark commits. Each
// Accept charges the absolute counter, for a cumulative charge of 500,500.
func TestPeerBucket_HonestPeerKeepsBudget(t *testing.T) {
	b := NewPeerBucket()
	pub := makePub(1)

	const admits = 1000
	for i := 0; i < admits; i++ {
		// Submit the next absolute counter while the watermark stays pending.
		got, _ := b.Accept(pubBytes(pub), uint64(i+1))
		if got != Keep {
			t.Fatalf("peer with consecutive counters returned %v at admit %d, want Keep (budget=%d)",
				i, got, b.Budget(pubBytes(pub)))
		}
	}
	// The consecutive counters leave nearly all of the initial budget available.
	if bg := b.Budget(pubBytes(pub)); bg == 0 {
		t.Fatalf("peer budget is zero after %d consecutive counters, want a positive balance", admits)
	}
}

// TestPeerBucket_AttackerDrainsToZero checks that repeated MaxUint64-scale
// ratchets return Drop. Each gap exceeds the remaining budget. Rejected gaps
// leave the budget unchanged rather than zeroing it, and they must not commit
// a watermark that would make later frames free.
func TestPeerBucket_AttackerDrainsToZero(t *testing.T) {
	b := NewPeerBucket()
	pub := makePub(2)

	// The first counter charges one unit and leaves ample budget.
	if got, _ := b.Accept(pubBytes(pub), 1); got != Keep {
		t.Fatalf("attacker first sight must be Keep (delta 1), got %v", got)
	}
	// The jump to MaxUint64 exceeds the budget and is rejected uncharged.
	if got, _ := b.Accept(pubBytes(pub), ^uint64(0)); got != Drop {
		t.Fatalf("MaxUint64 ratchet must Drop (delta exceeds budget), got %v", got)
	}
	// A rejected gap neither drains the budget nor commits its counter. Later
	// large gaps therefore remain over budget instead of becoming free
	// duplicates against a MaxUint64 watermark.
	if got, _ := b.Accept(pubBytes(pub), ^uint64(0)-1); got != Drop {
		t.Fatalf("attacker must remain unable to advance after the ratchet: a second huge gap must Drop, got %v", got)
	}
	// Repeating the same over-budget counter must produce the same decision.
	if got, _ := b.Accept(pubBytes(pub), ^uint64(0)); got != Drop {
		t.Fatalf("repeated over-budget counter returned %v, want Drop", got)
	}
}

// TestPeerBucket_SybilIsolation checks that repeated MaxUint64 ratchets from
// one identity do not change Keep decisions for 31 other identities. Every
// identity has its own budget even when keys share a shard.
func TestPeerBucket_SybilIsolation(t *testing.T) {
	b := NewPeerBucket()

	const honestPeers = 31
	honest := make([][32]byte, honestPeers)
	for i := range honest {
		// Fill every byte with the peer index to create distinct keys whose
		// low four bits distribute them across shards.
		var k [32]byte
		for j := range k {
			k[j] = byte(i + 1)
		}
		honest[i] = k
	}
	attacker := makePub(0xFF)

	// Establish every non-attacking peer with a unit advance.
	for i := range honest {
		if got, _ := b.Accept(pubBytes(honest[i]), 1); got != Keep {
			t.Fatalf("non-attacking peer %d first admit must be Keep, got %v", i, got)
		}
	}

	// Both ratchets exceed the attacker's remaining budget and return Drop.
	// Rejection leaves the budget uncharged rather than setting it to zero.
	if got, _ := b.Accept(pubBytes(attacker), ^uint64(0)); got != Drop {
		t.Fatalf("attacker MaxUint64 ratchet must Drop, got %v", got)
	}
	if got, _ := b.Accept(pubBytes(attacker), ^uint64(0)-1); got != Drop {
		t.Fatalf("attacker must stay unable to advance (second huge gap must Drop), got %v", got)
	}

	// Continue advancing all other peers while the attacker is rejected.
	for round := 0; round < 100; round++ {
		for i := range honest {
			got, _ := b.Accept(pubBytes(honest[i]), uint64(round+2))
			if got != Keep {
				t.Fatalf("non-attacking peer %d returned %v at round %d during attacker rejection, want Keep (budget=%d)",
					i, round, got, b.Budget(pubBytes(honest[i])))
			}
		}
	}

	// The attacker remains rejected after the other peers finish their rounds.
	if got, _ := b.Accept(pubBytes(attacker), ^uint64(0)); got != Drop {
		t.Fatalf("attacker must stay Drop after isolation, got %v", got)
	}
}

// forbiddenEngineSymbols lists engine implementation details that the
// admission package must not reference. Keeping these references out of
// non-test code preserves the package's independence from the CRDT engine.
var forbiddenEngineSymbols = []string{
	"lamportCounter",
	"observedInboundRate",
	"observedInboundRateBits",
	"AdvanceLamportTo",
}

// TestPeerBucket_ForbiddenSymbolsAbsent parses non-test Go files and rejects
// references to private engine symbols. Comment text is excluded, so tests and
// documentation can name the boundary without creating a code dependency.
func TestPeerBucket_ForbiddenSymbolsAbsent(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		// Only production files can introduce a package dependency.
		name := fi.Name()
		return strings.HasSuffix(name, ".go") &&
			!strings.HasSuffix(name, "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/admission: %v", err)
	}
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			// Collect comment text spans to exclude.
			inComment := func(pos token.Pos) bool {
				for _, cg := range file.Comments {
					for _, c := range cg.List {
						if pos >= c.Pos() && pos <= c.End() {
							return true
						}
					}
				}
				return false
			}
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if inComment(ident.Pos()) {
					return true
				}
				for _, sym := range forbiddenEngineSymbols {
					if ident.Name == sym {
						t.Errorf("engine implementation symbol %q appears in non-test code in %s; "+
							"pkg/admission must remain independent", sym, filepath.Base(fname))
					}
				}
				return true
			})
		}
	}
}

// TestPeerBucket_ConcurrentAdmitNoRace exercises 32 identities concurrently:
// one repeatedly submits a MaxUint64 counter and the others advance and commit
// small counters. Run with -race to check PeerBucket's shard locking.
func TestPeerBucket_ConcurrentAdmitNoRace(t *testing.T) {
	b := NewPeerBucket()
	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			pub := makePub(byte(id))
			// Goroutine 0 repeats an over-budget ratchet; the others make
			// small advances.
			if id == 0 {
				for i := 0; i < 1000; i++ {
					_, _ = b.Accept(pubBytes(pub), ^uint64(0))
				}
				return
			}
			for i := 0; i < 1000; i++ {
				// Commit every charge to model authenticated frames and to cover
				// CommitHWM's shard-lock path under the race detector. Without
				// commits, the pending watermark would repeatedly charge absolute
				// counters and exhaust the peer's budget.
				if _, ch := b.Accept(pubBytes(pub), uint64(i+1)); ch > 0 {
					b.CommitHWM(pubBytes(pub), uint64(i+1))
				}
			}
		}(g)
	}
	wg.Wait()
	// The ratcheting identity remains over budget. A large advance for another
	// identity still fits because its earlier charges total only 1,000 tokens.
	if got, _ := b.Accept(pubBytes(makePub(0)), ^uint64(0)-1); got != Drop {
		t.Fatalf("attacker (id 0) must still be unable to advance after the concurrent run, got %v", got)
	}
	if got, _ := b.Accept(pubBytes(makePub(1)), 1_000_000); got != Keep {
		t.Fatalf("non-attacking peer (id 1) must still be Keep after concurrent run, got %v", got)
	}
}
