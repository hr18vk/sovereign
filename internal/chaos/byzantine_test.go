package chaos

// Subphase 5.0 acceptance + teeth. See internal/chaos/byzantine.go for the
// §0 labeling-honesty note (the roadmap's "(Subphase 3.0)" is imprecise; the
// catch is 3.1's PeerBucket.Accept, not 3.0's physical-clock Admit).

import (
	"bytes"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/identity"
	engsync "github.com/hr18vk/supremum/pkg/sync"
)

// honestDelta builds a REAL sync.CRDTDelta carrying honest
// sync.CRDTEntry{DotNodeID, DotCounter,...} entries — the partition.go:151
// idiom. The DotCounter is modest (the honest peer's causal position).
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

// honestMultiEntryDelta builds a delta carrying N honest entries (for the
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
// (the partition.go:151 drain idiom) for assertions.
func drainDotCounters(t *testing.T, delta *engsync.CRDTDelta) []uint64 {
	t.Helper()
	var out []uint64
	delta.Entries(func(_ string, entry engsync.CRDTEntry) bool {
		out = append(out, entry.DotCounter)
		return true
	})
	return out
}

// TestByzantine_A2RatchetCaughtByAdmission is the LOAD-BEARING acceptance gate
// (G5.0.j, roadmap line 81 muscle): the A2 DotCounter ratchet is caught by
// 3.1's PeerBucket.Accept (the per-peer EWMA drain) returning Drop in 1 admit.
//
// The roadmap labels the catch "(Subphase 3.0)" but the source proves the
// catch is 3.1's PeerBucket.Accept (clock-cap 3.0 is independent of
// DotCounter — it rejects on physical-clock drift, not logical-counter
// ratchet). This test asserts 3.1 returns Drop; it does NOT assert 3.0 drops.
func TestByzantine_A2RatchetCaughtByAdmission(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	// Honest delta: modest DotCounter (the peer's real causal position).
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

	// THE CATCH: feed the attacker's [32]byte pubkey + the ratcheted
	// DotCounter to 3.1's PeerBucket.Accept. A MaxUint64 ratchet on a fresh
	// peer (budget = initialBudget = 1<<20) gives delta = MaxUint64 >> 1<<20
	// => budget drains to 0 => Drop IN ONE ADMIT.
	bucket := admission.NewPeerBucket()
	verdict := bucket.Accept(pub[:], ratcheted[0])
	if verdict != admission.Drop {
		t.Fatalf("3.1 PeerBucket.Accept did not drop the A2 ratchet: got %v, want Drop (the per-peer EWMA drain the roadmap line 81 names)", verdict)
	}

	// CONTROL arm: an HONEST delta (no ratchet, modest delta) must Keep —
	// proving the bucket is not a no-op false-rejecter. A fresh honest peer
	// submitting a modest counter advancement stays within budget.
	pubHonest, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey (honest): %v", err)
	}
	honestVerdict := bucket.Accept(pubHonest[:], 10)
	if honestVerdict != admission.Keep {
		t.Fatalf("honest control arm was not Keep: got %v, want Keep (bucket must not be a false-rejecter)", honestVerdict)
	}
	// A second modest honest admit (+1) must still Keep.
	honestVerdict2 := bucket.Accept(pubHonest[:], 11)
	if honestVerdict2 != admission.Keep {
		t.Fatalf("second honest admit was not Keep: got %v, want Keep", honestVerdict2)
	}
}

// TestByzantine_A2RatchetIncrementalCaught demonstrates the realistic A2
// vector (RatchetIncremental): a sequence of admits with geometric+jittered
// deltas exhausts the 1<<20 budget in a BOUNDED number of admits. The test
// asserts the bucket reaches Drop within a small bound.
func TestByzantine_A2RatchetIncrementalCaught(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	bucket := admission.NewPeerBucket()
	// Physical drain bound: RatchetIncremental step ∈ [1<<18, 1<<18+1<<16)
	// (byzantine.go:213-214), initialBudget = 1<<20 (ewma.go:68) →
	// ceil(1<<20 / 1<<18) = 4 admits to drain (every jitter case: jitter=0 →
	// 4*262144 == budget; jitter=32767 → 3*294911 < budget, 4* >= budget;
	// jitter=65535 → 3*327679 < budget, 4* >= budget). 5 is 4-to-drain + 1
	// of slack. maxAdmits=16 was 4× loose (7cc0148 audit): it passed while
	// binding nothing — a regression that doubled the step base to 1<<19
	// (2 admits) or halved it to 1<<17 (8 admits) would still pass. The
	// gate now enforces the physical math, not a comfort blanket.
	const maxAdmits = 5
	var lastCounter uint64
	dropped := false
	for i := 0; i < maxAdmits; i++ {
		// Each injector call ratchets a fresh honest delta incrementally.
		delta := honestDelta(t, lastCounter)
		mutated, _, err := InjectByzantineFaults(delta, priv, RatchetIncremental)
		if err != nil {
			t.Fatalf("InjectByzantineFaults (incremental, iter %d): %v", i, err)
		}
		ratcheted := drainDotCounters(t, mutated)
		if len(ratcheted) != 1 {
			t.Fatalf("iter %d: mutated delta has %d entries, want 1", i, len(ratcheted))
		}
		verdict := bucket.Accept(pub[:], ratcheted[0])
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

// TestByzantine_RatchetFrameIsCryptoValid is the FIS-cannot-forge property
// (G5.0.k): the re-signed frame is CRYPTOGRAPHICALLY VALID even though
// semantically malicious. identity.VerifyCRDTFrame (the SAME bridge the
// production admission path uses) returns TRUE on the tampered material. A
// second arm asserts a frame with the SAME sig but DIFFERENT (untampered)
// material FAILS Verify — proving the sig binds to the mutated material, not
// a free pass.
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
		t.Fatal("VerifyCRDTFrame rejected the re-signed tampered frame — the FIS-cannot-forge property failed (sig must be valid on tampered material)")
	}

	// Arm 2: the SAME sig over DIFFERENT (untampered) material must FAIL —
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
// production codec's encodeCRDTEntry (codec.go:119) for the same entry —
// proving the signed material is the production wire layout, not a fabricated
// serializer.
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

// TestByzantine_NoInPlaceDeltaMutation is the G5.0.g tooth: the injector
// must NOT mutate the input *sync.CRDTDelta's fields. It builds an input
// delta, records its OriginNodeID + the original DotCounter, calls
// InjectByzantineFaults, and asserts the INPUT delta's OriginNodeID is
// UNCHANGED and the input delta's Entries still yields the ORIGINAL DotCounter
// values (the injector drained+copied, it did not mutate in place).
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

	// The input delta's Entries must still yield the ORIGINAL (honest)
	// DotCounter — the injector drained+copied; it did not ratchet in place.
	after := drainDotCounters(t, delta)
	if len(after) != 1 {
		t.Fatalf("input delta Entries yields %d entries, want 1", len(after))
	}
	if after[0] != honestCounter {
		t.Fatalf("injector mutated input delta's DotCounter in place: got %d, want original %d (the drain+copy seam must not touch the input)", after[0], honestCounter)
	}
}

// TestByzantine_NoVectorClockLamportTime is the G5.0.f tooth (the Rev2
// hallucination ban): it parses internal/chaos/byzantine.go (non-test) via
// go/ast and FAILS if `VectorClock` or `LamportTime` appears in CODE (allowed
// in comments — the comment-span exclusion). These identifiers are a Rev2
// hallucination the roadmap line 124 bans; 5.0 MUST use only
// sync.CRDTEntry{DotNodeID, DotCounter,...}.
func TestByzantine_NoVectorClockLamportTime(t *testing.T) {
	banned := []string{"VectorClock", "LamportTime"}
	violations := scanBannedIdentifiers(t, "byzantine.go", banned)
	if len(violations) > 0 {
		t.Fatalf("banned identifiers found in byzantine.go CODE (not comments): %v — 5.0 must use sync.CRDTEntry{DotNodeID, DotCounter,...}, never the Rev2 hallucination %v", violations, banned)
	}
}

// TestByzantine_NoVectorClockLamportTime_NegativeControl proves the tooth is
// load-bearing: injecting `var VectorClock int` into byzantine.go makes the
// scan FAIL; reverting makes it PASS. (Run via t.Skip by default to avoid
// mutating the source on every test run; the negative control is demonstrated
// by the scanBannedIdentifiers helper operating on an in-memory mutated copy.)
func TestByzantine_NoVectorClockLamportTime_NegativeControl(t *testing.T) {
	src, err := os.ReadFile("byzantine.go")
	if err != nil {
		t.Fatalf("read byzantine.go: %v", err)
	}
	// Inject a banned identifier in CODE (not a comment), placed AFTER the
	// package clause so the mutated source still parses.
	mutated := injectAfterPackage(src, "var VectorClock int\n")
	violations := scanBannedIdentifiersFromSource(t, "byzantine.go", mutated, []string{"VectorClock", "LamportTime"})
	if len(violations) == 0 {
		t.Fatal("negative control FAILED: injecting `var VectorClock int` did NOT trip the tooth — the G5.0.f tooth is not load-bearing")
	}
	// Reverting (the original source) must PASS.
	violationsReverted := scanBannedIdentifiersFromSource(t, "byzantine.go", src, []string{"VectorClock", "LamportTime"})
	if len(violationsReverted) != 0 {
		t.Fatalf("reverted source still trips the tooth: %v — the tooth is too broad (flagging comments)", violationsReverted)
	}
}

// TestByzantine_UsesRandV2 is the G5.0.h tooth (the Go-1.20 deprecation ban):
// it parses byzantine.go and FAILS if `rand.Seed(`, `mrand.Seed(`, or a bare
// `"math/rand"` import (not `"math/rand/v2"`) appears. math/rand/v2 is
// REQUIRED for any randomness in byzantine.go.
func TestByzantine_UsesRandV2(t *testing.T) {
	src, err := os.ReadFile("byzantine.go")
	if err != nil {
		t.Fatalf("read byzantine.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "byzantine.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse byzantine.go: %v", err)
	}

	// Ban bare "math/rand" import (must be "math/rand/v2").
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "math/rand" {
			t.Fatalf("banned bare \"math/rand\" import in byzantine.go — use \"math/rand/v2\" (the Go-1.20 deprecation ban, G5.0.h)")
		}
	}

	// Ban rand.Seed( / mrand.Seed( in CODE (not comments).
	violations := scanBannedCallExprs(t, fset, f, []string{"rand.Seed", "mrand.Seed"})
	if len(violations) > 0 {
		t.Fatalf("banned deprecated Seed calls in byzantine.go CODE: %v — use math/rand/v2 (no top-level Seed, G5.0.h)", violations)
	}

	// REQUIRE math/rand/v2 import.
	hasRandV2 := false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "math/rand/v2" {
			hasRandV2 = true
		}
	}
	if !hasRandV2 {
		t.Fatal("byzantine.go does not import \"math/rand/v2\" — required for any randomness (G5.0.h)")
	}
}

// TestByzantine_UsesRandV2_NegativeControl proves the G5.0.h tooth is
// load-bearing: injecting `rand.Seed(1)` makes the scan FAIL; reverting PASS.
func TestByzantine_UsesRandV2_NegativeControl(t *testing.T) {
	src, err := os.ReadFile("byzantine.go")
	if err != nil {
		t.Fatalf("read byzantine.go: %v", err)
	}
	mutated := injectAfterPackage(src, "func init() { rand.Seed(1) }\n")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "byzantine.go", mutated, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse mutated: %v", err)
	}
	violations := scanBannedCallExprs(t, fset, f, []string{"rand.Seed", "mrand.Seed"})
	if len(violations) == 0 {
		t.Fatal("negative control FAILED: injecting `rand.Seed(1)` did NOT trip the tooth — the G5.0.h tooth is not load-bearing")
	}
}

// TestByzantine_CirclSignCited is the G5.0.i tooth (no-fabrication rule,
// roadmap line 124): it asserts byzantine.go contains a go-doc-style citation
// comment naming ed25519.Sign (circl v1.6.4) with the exact signature
// `func Sign(privateKey PrivateKey, message []byte) []byte`.
func TestByzantine_CirclSignCited(t *testing.T) {
	src, err := os.ReadFile("byzantine.go")
	if err != nil {
		t.Fatalf("read byzantine.go: %v", err)
	}
	s := string(src)
	wantSig := "func Sign(privateKey PrivateKey, message []byte) []byte"
	if !strings.Contains(s, wantSig) {
		t.Fatalf("byzantine.go missing the circl ed25519.Sign go-doc citation (exact signature %q) — the Sign symbol must be go-doc-proven, not fabricated (G5.0.i)", wantSig)
	}
	// Also require the file path citation so the symbol is traceable.
	if !strings.Contains(s, "ed25519.go:283") {
		t.Fatal("byzantine.go missing the ed25519.go:283 line citation for circl Sign (G5.0.i)")
	}
}

// TestByzantine_InjectorConcurrentNoRace is the G5.0.l race gate: 32
// concurrent injector+accept callers on distinct deltas; 0 data races. The
// injector must not mutate shared input state, and the PeerBucket is
// 3.1-proven sharded; the test exercises both under concurrency.
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
			verdict := bucket.Accept(pub[:], ratcheted[0])
			if verdict != admission.Drop {
				t.Errorf("goroutine %d: Accept = %v, want Drop", id, verdict)
			}
		}(g)
	}
	wg.Wait()
}

// TestByzantine_NilDeltaRejected asserts the injector returns a non-nil
// error (never a panic) on a malformed input — the production harness is the
// test, and the test must be deterministic.
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

// --- AST tooth helpers ------------------------------------------------------

// injectAfterPackage returns src with decl inserted immediately after the
// import block (so the mutated source still parses as valid Go — a top-level
// decl before imports is a parse error). Used by the negative-control teeth
// to inject banned code into CODE (not a comment) and prove the tooth trips.
func injectAfterPackage(src []byte, decl string) []byte {
	// Find the end of the import block. Handle both grouped `import ( ... )`
	// and single-line `import "..."` forms by scanning for the last import
	// line, then insert after the following newline.
	cut := -1
	if i := bytes.Index(src, []byte("import (")); i >= 0 {
		// Grouped import: find the matching closing paren.
		depth := 0
		for j := i; j < len(src); j++ {
			if src[j] == '(' {
				depth++
			} else if src[j] == ')' {
				depth--
				if depth == 0 {
					// Insert after the newline following the closing paren.
					nl := bytes.IndexByte(src[j:], '\n')
					if nl < 0 {
						return src
					}
					cut = j + nl + 1
					break
				}
			}
		}
	}
	if cut < 0 {
		// Single-line import form: insert after the last `import "..."` line.
		for i := 0; i < len(src); {
			j := bytes.Index(src[i:], []byte("import "))
			if j < 0 {
				break
			}
			lineStart := i + j
			nl := bytes.IndexByte(src[lineStart:], '\n')
			if nl < 0 {
				break
			}
			cut = lineStart + nl + 1
			i = cut
		}
	}
	if cut < 0 {
		return src
	}
	out := make([]byte, 0, len(src)+len(decl))
	out = append(out, src[:cut]...)
	out = append(out, decl...)
	out = append(out, src[cut:]...)
	return out
}

// scanBannedIdentifiers parses <name> from the package directory and returns
// the banned identifiers that appear in CODE (comment spans excluded).
func scanBannedIdentifiers(t *testing.T, name string, banned []string) []string {
	t.Helper()
	src, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return scanBannedIdentifiersFromSource(t, name, src, banned)
}

// scanBannedIdentifiersFromSource parses the given source bytes and returns
// the banned identifiers that appear in CODE (not comments). It builds a set
// of comment byte-spans and skips any identifier whose position falls inside
// a comment.
func scanBannedIdentifiersFromSource(t *testing.T, name string, src []byte, banned []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	// Collect comment byte-spans (offset-based).
	type span struct{ start, end int }
	var spans []span
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			start := fset.Position(c.Pos()).Offset
			end := fset.Position(c.End()).Offset
			spans = append(spans, span{start, end})
		}
	}
	inComment := func(off int) bool {
		for _, s := range spans {
			if off >= s.start && off < s.end {
				return true
			}
		}
		return false
	}
	want := make(map[string]bool, len(banned))
	for _, b := range banned {
		want[b] = true
	}
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if !want[ident.Name] {
			return true
		}
		off := fset.Position(ident.Pos()).Offset
		if inComment(off) {
			return true
		}
		violations = append(violations, ident.Name)
		return true
	})
	return violations
}

// scanBannedCallExprs parses f and returns the banned call expressions
// (e.g. "rand.Seed", "mrand.Seed") that appear in CODE (not comments).
func scanBannedCallExprs(t *testing.T, fset *token.FileSet, f *ast.File, banned []string) []string {
	t.Helper()
	want := make(map[string]bool, len(banned))
	for _, b := range banned {
		want[b] = true
	}
	// Collect comment spans.
	type span struct{ start, end int }
	var spans []span
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			start := fset.Position(c.Pos()).Offset
			end := fset.Position(c.End()).Offset
			spans = append(spans, span{start, end})
		}
	}
	inComment := func(off int) bool {
		for _, s := range spans {
			if off >= s.start && off < s.end {
				return true
			}
		}
		return false
	}
	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkgIdent.Name + "." + sel.Sel.Name
		if !want[name] {
			return true
		}
		off := fset.Position(call.Pos()).Offset
		if inComment(off) {
			return true
		}
		violations = append(violations, name)
		return true
	})
	return violations
}

// Ensure the test file compiles against the real package paths (belt-and-
// suspenders: if the import paths drift, this file fails to compile).
var _ = filepath.Clean
