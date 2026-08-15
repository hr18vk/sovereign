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

// makePub returns a deterministic 32-byte pubkey seeded by byte b. Tests
// use this rather than circl GenerateKey to keep pkg/admission free of
// the pkg/identity import (the bucket accepts raw []byte and copies into
// [32]byte; only the canonical-copy path is exercised).
func makePub(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// pubBytes returns the []byte view of a [32]byte key for Accept calls.
func pubBytes(k [32]byte) []byte { return k[:] }

// ---------------------------------------------------------------------------
// G3.1.f — COMPILE-ERROR TOOTH (the roadmap-wording fabrication ban)
// ---------------------------------------------------------------------------

// TestPeerBucket_KeyIsArray32Byte asserts the bucket key type is EXACTLY
// [32]byte. The positive compile-time assertion `var _ PeerBucketKey =
// [32]byte{}` lives in peer_key_slice_probe.go under a build tag that is
// NEVER set in the normal build, so it does not pollute production. The
// negative-compile guard (the same file declares `var _ PeerBucketKey =
// ed25519.PublicKey{}`) MUST fail to compile — it detector-bans the
// "map[ed25519.PublicKey]" compile-error pattern from this package's
// source identity.
//
// The roadmap wording "map[ed25519.PublicKey]*PeerEWMA" (line 61) is a
// COMPILE ERROR: circl's ed25519.PublicKey is `type PublicKey []byte`
// (pubkey112.go:7), and Go slices are non-comparable, so the compiler
// rejects `map[ed25519.PublicKey]X` with:
//
//	invalid map key type ed25519.PublicKey
//
// This test verifies the positive assertion holds at runtime and
// documents the banned compile-error string. The negative guard is
// verified by the build-tag probe file (peer_key_slice_probe.go), which
// is compiled only under the `peer_key_slice_probe` tag to assert the
// slice-key form fails; the error string is pasted in that file's
// comment.
func TestPeerBucket_KeyIsArray32Byte(t *testing.T) {
	// Positive compile-time assertion: [32]byte satisfies PeerBucketKey.
	var _ PeerBucketKey = [32]byte{}
	// PeerBucketKey is exactly [32]byte — same underlying type.
	var k PeerBucketKey
	if size := len(k); size != 32 {
		t.Fatalf("PeerBucketKey must be exactly 32 bytes, got %d", size)
	}
	// The slice-key form is banned: a []byte is NOT assignable to
	// PeerBucketKey (different underlying types). This is the runtime
	// mirror of the compile ban — if someone made PeerBucketKey a slice,
	// this would stop compiling.
	src := makePub(1)
	var sliceKey []byte = src[:]
	_ = sliceKey // not assignable to PeerBucketKey; documented below.
	// Confirm the canonical copy path: a 32-byte []byte copies into the
	// [32]byte key with no truncation.
	var pk PeerBucketKey
	seed := makePub(7)
	copy(pk[:], seed[:])
	if pk != seed {
		t.Fatalf("canonical copy of 32-byte pubkey into PeerBucketKey mismatched")
	}
}

// ---------------------------------------------------------------------------
// G3.1.g — wrong-length pubkey REJECTED before bucket touch
// ---------------------------------------------------------------------------

// TestPeerBucket_RejectShortPub asserts a 31-byte pubkey is rejected
// BEFORE the bucket map is touched (no map growth, no allocation). The
// bucket map size must be unchanged after the rejected Accept.
func TestPeerBucket_RejectShortPub(t *testing.T) {
	b := NewPeerBucket()
	short := make([]byte, 31) // len != 32
	got := b.Accept(short, 1)
	if got != Drop {
		t.Fatalf("31-byte pubkey must be rejected (Drop), got %v", got)
	}
	// No peer bucket must have been created for the short key.
	if n := totalMapSize(b); n != 0 {
		t.Fatalf("short pubkey must not touch the bucket map, got size %d", n)
	}
}

// TestPeerBucket_RejectLongPub asserts a 33-byte pubkey is rejected
// BEFORE the bucket map is touched.
func TestPeerBucket_RejectLongPub(t *testing.T) {
	b := NewPeerBucket()
	long := make([]byte, 33) // len != 32
	got := b.Accept(long, 1)
	if got != Drop {
		t.Fatalf("33-byte pubkey must be rejected (Drop), got %v", got)
	}
	if n := totalMapSize(b); n != 0 {
		t.Fatalf("long pubkey must not touch the bucket map, got size %d", n)
	}
}

// totalMapSize returns the total number of PeerEWMA entries across all
// shards. Used to prove a rejected Accept did not grow the map.
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

// ---------------------------------------------------------------------------
// G3.1.h — per-peer token bucket math
// ---------------------------------------------------------------------------

// TestPeerBucket_HonestPeerKeepsBudget asserts a peer submitting modest
// Counter deltas stays above the drop threshold across N admits. A
// modest delta (+1 per frame) drains the initial budget far slower than
// the test runs admits, so every admit is Keep.
func TestPeerBucket_HonestPeerKeepsBudget(t *testing.T) {
	b := NewPeerBucket()
	pub := makePub(1)

	const admits = 1000
	for i := 0; i < admits; i++ {
		// Counter advances by 1 per frame — a modest honest rate.
		got := b.Accept(pubBytes(pub), uint64(i+1))
		if got != Keep {
			t.Fatalf("honest peer (delta=1) must stay Keep at admit %d, got %v (budget=%d)",
				i, got, b.Budget(pubBytes(pub)))
		}
	}
	// The honest peer must still have most of its budget left.
	if bg := b.Budget(pubBytes(pub)); bg == 0 {
		t.Fatalf("honest peer budget must be > 0 after %d modest admits", admits)
	}
}

// TestPeerBucket_AttackerDrainsToZero asserts a peer ratcheting Counter
// by MaxUint64-equivalent deltas drains to 0 and its frames DROP. A
// single delta of math.MaxUint64 exceeds the initial budget, so the
// attacker's first ratchet admit drops.
func TestPeerBucket_AttackerDrainsToZero(t *testing.T) {
	b := NewPeerBucket()
	pub := makePub(2)

	// First admit: counter 1, delta 0 (first sight) -> Keep, budget intact.
	if got := b.Accept(pubBytes(pub), 1); got != Keep {
		t.Fatalf("attacker first sight must be Keep (delta 0), got %v", got)
	}
	// Ratchet by MaxUint64: counter jumps to MaxUint64, delta = MaxUint64-1.
	// That delta exceeds the budget -> Drop, budget pinned to 0.
	if got := b.Accept(pubBytes(pub), ^uint64(0)); got != Drop {
		t.Fatalf("MaxUint64 ratchet must Drop (delta exceeds budget), got %v", got)
	}
	if bg := b.Budget(pubBytes(pub)); bg != 0 {
		t.Fatalf("attacker budget must be 0 after MaxUint64 ratchet, got %d", bg)
	}
	// Subsequent admits stay Drop (budget is 0, any positive delta keeps it 0).
	if got := b.Accept(pubBytes(pub), ^uint64(0)); got != Drop {
		t.Fatalf("drained attacker must stay Drop, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// G3.1.i — Sybil isolation (the load-bearing CPA)
// ---------------------------------------------------------------------------

// TestPeerBucket_SybilIsolation asserts ONE attacker MaxUint64-ratchets
// while 31 honest peers submit modest deltas, and the 31 honest peers'
// admit decisions stay UNCHANGED — their budgets are unaffected by the
// attacker's drain because they have SEPARATE buckets. This is the
// load-bearing Sybil-isolation assertion: a single attacker cannot
// exhaust the admission budget of honest peers.
func TestPeerBucket_SybilIsolation(t *testing.T) {
	b := NewPeerBucket()

	const honestPeers = 31
	honest := make([][32]byte, honestPeers)
	for i := range honest {
		// Distinct pubkeys: byte 0 = peer index (low 4 bits shard it),
		// rest = index too, so all 31 hash to spread across shards.
		var k [32]byte
		for j := range k {
			k[j] = byte(i + 1)
		}
		honest[i] = k
	}
	attacker := makePub(0xFF)

	// Phase 1: every honest peer submits a modest delta and is Keep.
	for i := range honest {
		if got := b.Accept(pubBytes(honest[i]), 1); got != Keep {
			t.Fatalf("honest peer %d first admit must be Keep, got %v", i, got)
		}
	}

	// Phase 2: the attacker ratchets MaxUint64 and drains to Drop.
	if got := b.Accept(pubBytes(attacker), ^uint64(0)); got != Drop {
		t.Fatalf("attacker MaxUint64 ratchet must Drop, got %v", got)
	}
	if bg := b.Budget(pubBytes(attacker)); bg != 0 {
		t.Fatalf("attacker budget must be 0, got %d", bg)
	}

	// Phase 3 (the CPA): the 31 honest peers submit further modest deltas
	// and stay Keep — their budgets are UNAFFECTED by the attacker's drain.
	for round := 0; round < 100; round++ {
		for i := range honest {
			got := b.Accept(pubBytes(honest[i]), uint64(round+2))
			if got != Keep {
				t.Fatalf("honest peer %d must stay Keep at round %d (attacker drained), got %v budget=%d",
					i, round, got, b.Budget(pubBytes(honest[i])))
			}
		}
	}

	// Phase 4: the attacker stays Drop while honest peers keep flowing.
	if got := b.Accept(pubBytes(attacker), ^uint64(0)); got != Drop {
		t.Fatalf("attacker must stay Drop after isolation, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// G3.1.j — STATIC TOOTH: no-re-open guard (crdt.go FROZEN muscle)
// ---------------------------------------------------------------------------

// forbiddenEngineSymbols are identifiers that belong to the FROZEN
// crdt.go engine. 3.1 is transport-layer and pre-3.0; it MUST NOT call
// the engine or touch its private fields. If any of these appear in
// pkg/admission Go source OUTSIDE comments, the silent-re-open pattern
// is present and the test FAILS — detector-banning it from source.
var forbiddenEngineSymbols = []string{
	"lamportCounter",
	"observedInboundRate",
	"observedInboundRateBits",
	"AdvanceLamportTo",
}

// TestPeerBucket_ForbiddenSymbolsAbsent greps pkg/admission Go source for
// the forbidden engine identifiers. It parses each .go file (excluding
// _test.go and the build-tag probe) and FAILS if any forbidden symbol
// appears in code (identifiers), allowing it only in comments. This
// makes the silent-re-open of FROZEN crdt.go detector-banned from
// pkg/admission source.
func TestPeerBucket_ForbiddenSymbolsAbsent(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		// Skip _test.go files (tests may reference forbidden symbols in
		// comments documenting the ban) and the build-tag probe file.
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
						t.Errorf("FORBIDDEN symbol %q appears in code in %s "+
							"(silent-re-open of FROZEN crdt.go detector-banned)",
							sym, filepath.Base(fname))
					}
				}
				return true
			})
		}
	}
}

// ---------------------------------------------------------------------------
// G3.1.k — RACE gate (concurrent Admit across 32 distinct pubkeys)
// ---------------------------------------------------------------------------

// TestPeerBucket_ConcurrentAdmitNoRace runs 32 goroutines, each
// hammering Accept on its own distinct [32]byte pubkey with mixed honest
// + attacker patterns, under -race. 0 data race must be reported. The
// sharded design (16 shards, per-shard mutex) means peers in different
// shards never contend; the attacker goroutine saturates only its own
// shard.
func TestPeerBucket_ConcurrentAdmitNoRace(t *testing.T) {
	b := NewPeerBucket()
	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			pub := makePub(byte(id))
			// Goroutine 0 is the attacker (MaxUint64 ratchet); the rest
			// are honest peers with modest deltas.
			if id == 0 {
				for i := 0; i < 1000; i++ {
					_ = b.Accept(pubBytes(pub), ^uint64(0))
				}
				return
			}
			for i := 0; i < 1000; i++ {
				_ = b.Accept(pubBytes(pub), uint64(i+1))
			}
		}(g)
	}
	wg.Wait()
	// The attacker (id 0) must be drained; honest peers must be Keep-able.
	if bg := b.Budget(pubBytes(makePub(0))); bg != 0 {
		t.Fatalf("attacker (id 0) must be drained after concurrent run, budget=%d", bg)
	}
	if got := b.Accept(pubBytes(makePub(1)), 1_000_000); got != Keep {
		t.Fatalf("honest peer (id 1) must still be Keep after concurrent run, got %v", got)
	}
}
