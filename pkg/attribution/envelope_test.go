// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package attribution

import (
	"bytes"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/identity"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// genKey generates a fresh Ed25519 keypair. Relay-chain behavior does not
// depend on particular key material, so tests use crypto/rand and assert the
// verification verdicts. It accepts testing.TB for use by tests and benchmarks.
func genKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// pubArray copies a 32-byte Ed25519 public key into the canonical [32]byte
// form the Hop record carries (matching PeerBucketKey in pkg/admission).
func pubArray(pub ed25519.PublicKey) [32]byte {
	var a [32]byte
	copy(a[:], pub)
	return a
}

// fakeInnerWire returns a deterministic 120-byte stand-in for the inner
// signed CRDTDeltaEvent capnp frame. The envelope carries the inner wire
// verbatim and returns it byte-identical from Open without re-serializing it,
// so a fixed 120-byte buffer (the CRDT delta frame size) exercises the
// envelope without importing pkg/sync.
func fakeInnerWire() []byte {
	w := make([]byte, 120)
	for i := range w {
		w[i] = byte(i)
	}
	return w
}

// buildRelayChain builds an N-hop envelope. Each relay signs the inner wire
// and the preceding signed material in order. Origin signing is separate:
// the caller verifies that signature after Open returns the inner wire.
// The relay public keys let tests independently verify each hop.
func buildRelayChain(t *testing.T, innerWire []byte, nHops int) (*RelayEnvelope, []ed25519.PublicKey) {
	t.Helper()
	relayPubs := make([]ed25519.PublicKey, nHops)
	relayPrivs := make([]ed25519.PrivateKey, nHops)
	for i := 0; i < nHops; i++ {
		relayPubs[i], relayPrivs[i] = genKey(t)
	}
	hops := make([]Hop, nHops)
	var preceding []byte
	for i := 0; i < nHops; i++ {
		wall := int64(1_700_000_000_000_000 + i*1000)
		hops[i] = SignHop(relayPrivs[i], pubArray(relayPubs[i]), innerWire, preceding, uint16(i), wall)
		// Thread the signed-material accumulator exactly as Open does, so
		// the next relay signs over the same prefix Open will verify.
		preceding = SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	return NewRelayEnvelope(innerWire, hops), relayPubs
}

// ---------------------------------------------------------------------------
// Relay-chain mock A->B->C->D end-to-end verification
// ---------------------------------------------------------------------------

// TestEnvelope_RelayChainABCD builds a 3-hop relayed frame (B relays A's
// origin sig; C relays B's; D relays C's), opens it, asserts all 3 outer
// sigs verify plus the inner origin sig verifies, and checks that the inner
// wire equals the original CRDTDeltaEvent bytes across the hop count bound.
func TestEnvelope_RelayChainABCD(t *testing.T) {
	inner := fakeInnerWire()

	// Origin A signs the inner wire (the inner origin sig, verified by the
	// caller after Open returns the inner wire).
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, inner)

	// Build the 3-hop relay chain B->C->D over A's signed inner frame.
	env, relayPubs := buildRelayChain(t, inner, 3)
	if got := env.HopCount(); got != 3 {
		t.Fatalf("HopCount = %d, want 3", got)
	}

	// Open with a bound that admits 3 hops (e.g. MaxHopsForBudget(1ms)=15).
	maxHops := MaxHopsForBudget(1 * time.Millisecond)
	if maxHops < 3 {
		t.Fatalf("MaxHopsForBudget(1ms)=%d must admit a 3-hop chain for this test", maxHops)
	}
	gotInner, hops, err := env.Open(maxHops)
	if err != nil {
		t.Fatalf("Open 3-hop relay chain: %v", err)
	}
	if hops != 3 {
		t.Fatalf("Open returned hops=%d, want 3", hops)
	}
	// The inner wire must be returned byte-identical (Open never re-serializes
	// the inner frame).
	if !bytes.Equal(gotInner, inner) {
		t.Fatalf("Open returned inner wire that differs from the original (len got=%d want=%d)", len(gotInner), len(inner))
	}

	// The inner origin sig must verify on the returned inner wire. This proves
	// the envelope preserves the inner frame's integrity end-to-end.
	if !identity.VerifyCRDTFrame(originPub, gotInner, originSig) {
		t.Fatalf("inner origin sig must verify on the returned inner wire")
	}

	// Each relay's outer sig must independently verify (defense-in-depth:
	// Open already verified them, but this re-asserts the chain-of-custody
	// material is reconstructable from the envelope alone).
	var preceding []byte
	for i, hop := range env.hops {
		material := SignedMaterial(inner, preceding, uint16(i), hop.WallUSec)
		if !identity.VerifyCRDTFrame(relayPubs[i], material, hop.Sig[:]) {
			t.Fatalf("outer relay hop %d sig must verify", i)
		}
		preceding = material
	}
}

// TestEnvelope_HopBoundExceeded checks the failure result when the hop count
// exceeds the bound. Open returns ErrHopBoundExceeded, a nil inner wire, and a
// zero hop count. TestEnvelope_VerifyCallCounter separately checks that this
// branch makes no verification calls.
func TestEnvelope_HopBoundExceeded(t *testing.T) {
	inner := fakeInnerWire()
	// Build a 5-hop chain and set the bound to 3 (exceeds).
	env, _ := buildRelayChain(t, inner, 5)
	if env.HopCount() != 5 {
		t.Fatalf("HopCount = %d, want 5", env.HopCount())
	}

	gotInner, hops, err := env.Open(3)
	if err != ErrHopBoundExceeded {
		t.Fatalf("Open with hops=5 bound=3 must return ErrHopBoundExceeded, got err=%v inner=%v hops=%d", err, gotInner != nil, hops)
	}
	if gotInner != nil {
		t.Fatalf("Open on hop-bound-exceeded must return nil inner wire, got len=%d", len(gotInner))
	}
	if hops != 0 {
		t.Fatalf("Open on hop-bound-exceeded must return hops=0, got %d", hops)
	}
}

// TestEnvelope_HopBoundExceededZeroVerify checks early rejection of a
// 1000-hop envelope with invalid hop records. Open returns ErrHopBoundExceeded
// from the depth check, before it can attempt their signatures, and the test
// requires that path to finish within one microsecond. The counting hook in
// TestEnvelope_VerifyCallCounter separately checks the zero-call property.
func TestEnvelope_HopBoundExceededZeroVerify(t *testing.T) {
	inner := fakeInnerWire()
	// A forged deep envelope: 1000 hops (deep-relay exhaustion shape). The
	// hop records are garbage (not real signatures) — Open must reject on
	// depth before ever attempting to verify them.
	garbageHops := make([]Hop, 1000)
	env := NewRelayEnvelope(inner, garbageHops)
	// Bound sized for a 1ms budget = 15 hops; 1000 >> 15.
	maxHops := MaxHopsForBudget(1 * time.Millisecond)
	start := time.Now()
	_, _, err := env.Open(maxHops)
	elapsed := time.Since(start)
	if err != ErrHopBoundExceeded {
		t.Fatalf("forged 1000-hop envelope must be dropped with ErrHopBoundExceeded, got %v", err)
	}
	// The O(1) depth check must be sub-microsecond (it is a single integer
	// compare). If it took anywhere near one Verify (60 us), the
	// reject-before-Verify invariant is broken.
	if elapsed > time.Microsecond {
		t.Fatalf("O(1) depth check took %v (must be sub-microsecond, zero Verify)", elapsed)
	}
}

// TestEnvelope_VerifyCallCounter installs a hook that counts calls to
// identity.VerifyCRDTFrame. Opening a five-hop envelope with a three-hop bound
// returns before the verification loop, so the observed count must be zero.
func TestEnvelope_VerifyCallCounter(t *testing.T) {
	inner := fakeInnerWire()
	// 5-hop chain, bound 3 -> exceed.
	env, _ := buildRelayChain(t, inner, 5)

	var calls int64
	verifyHookMu.Lock()
	verifyHook = func(pub ed25519.PublicKey, msg, sig []byte) bool {
		atomic.AddInt64(&calls, 1)
		return identity.VerifyCRDTFrame(pub, msg, sig)
	}
	verifyHookMu.Unlock()
	defer func() {
		verifyHookMu.Lock()
		verifyHook = nil
		verifyHookMu.Unlock()
	}()

	_, _, err := env.Open(3)
	if err != ErrHopBoundExceeded {
		t.Fatalf("want ErrHopBoundExceeded, got %v", err)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("hop-bound-exceeded path must issue zero Verify calls, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Budget-bounded derivation
// ---------------------------------------------------------------------------

// TestMaxHopsForBudget_Derivation checks the hop-bound formula against
// caller-supplied budgets. The result is floor(budget/verifyCostPerHop32c)-1,
// clamped to zero for budgets too small to cover an outer relay hop.
func TestMaxHopsForBudget_Derivation(t *testing.T) {
	// Use the measured verification cost to derive each expected bound.
	const cost = int64(verifyCostPerHop32c) // 60211 ns

	cases := []struct {
		name   string
		budget time.Duration
		want   int
	}{
		// 1 ms budget -> floor(1_000_000 / 60_211) - 1 = 16 - 1 = 15 hops.
		{"1ms", 1 * time.Millisecond, int(1_000_000/cost) - 1},
		// 5 ms budget -> floor(5_000_000 / 60_211) - 1 = 83 - 1 = 82 hops.
		{"5ms", 5 * time.Millisecond, int(5_000_000/cost) - 1},
		// 60.211 us (exactly one Verify) -> floor(1) - 1 = 0 hops (the
		// budget covers only the inner origin Verify, no outer hops).
		{"one-verify", time.Duration(cost), 0},
		// 30 us (below one Verify) -> floor(0) - 1 = -1 -> clamped to 0.
		{"below-one-verify", 30 * time.Microsecond, 0},
		// 0 / negative budget -> 0.
		{"zero", 0, 0},
		{"negative", -1 * time.Millisecond, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaxHopsForBudget(c.budget)
			if got != c.want {
				t.Fatalf("MaxHopsForBudget(%v) = %d, want %d (floor(%dns/%dns)-1 clamped >=0)",
					c.budget, got, c.want, int64(c.budget), cost)
			}
			if got < 0 {
				t.Fatalf("MaxHopsForBudget must be clamped to >= 0, got %d", got)
			}
		})
	}

	// 1 ms budget yields 15 hops.
	if got, want := MaxHopsForBudget(1*time.Millisecond), 15; got != want {
		t.Fatalf("MaxHopsForBudget(1ms) = %d, want %d", got, want)
	}
}

// TestMaxHopsForBudget_BudgetInjectedNotBaked derives the expected bound from
// each supplied budget and the measured verification cost. It also checks
// that increasing the budget cannot reduce the number of permitted hops.
func TestMaxHopsForBudget_BudgetInjectedNotBaked(t *testing.T) {
	const cost = int64(verifyCostPerHop32c)
	cases := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		5 * time.Millisecond,
		250 * time.Microsecond,
	}
	for _, budget := range cases {
		got := MaxHopsForBudget(budget)
		want := int64(budget) / cost
		want--
		if want < 0 {
			want = 0
		}
		if got != int(want) {
			t.Fatalf("MaxHopsForBudget(%v) = %d, want re-derived %d (budget injected, not baked)",
				budget, got, want)
		}
	}
	// The bound must scale with the injected budget: a larger budget admits
	// strictly more hops (or equal, at the clamp). This proves no hidden
	// source constant caps the bound independent of the injected budget.
	prev := -1
	for _, budget := range []time.Duration{
		100 * time.Microsecond,
		1 * time.Millisecond,
		10 * time.Millisecond,
		100 * time.Millisecond,
	} {
		got := MaxHopsForBudget(budget)
		if got < prev {
			t.Fatalf("MaxHopsForBudget must be monotonic in the injected budget: %v -> %d < prev %d",
				budget, got, prev)
		}
		prev = got
	}
}

// ---------------------------------------------------------------------------
// Tamper resistance property tests
// ---------------------------------------------------------------------------

// TestEnvelope_TamperedOuterSig proves a bit-flipped outer relay sig is
// rejected: Open fails at the outer Verify and the inner wire is never
// reached.
func TestEnvelope_TamperedOuterSig(t *testing.T) {
	inner := fakeInnerWire()
	env, _ := buildRelayChain(t, inner, 3)
	// Flip a bit in the middle relay's (hop 1) signature.
	env.hops[1].Sig[0] ^= 0x01
	_, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err == nil {
		t.Fatalf("tampered outer relay sig must fail Open, got nil err")
	}
	if err != ErrVerify && !strings.Contains(err.Error(), ErrVerify.Error()) {
		t.Fatalf("tampered outer sig must return ErrVerify, got %v", err)
	}
}

// TestEnvelope_TamperedOriginSig proves the inner origin sig, bit-flipped,
// fails the caller's Verify after all outer hops passed — the
// ordering proves outer-before-inner. Open succeeds (outer hops intact);
// the inner origin Verify on the returned wire fails.
func TestEnvelope_TamperedOriginSig(t *testing.T) {
	inner := fakeInnerWire()
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, inner)
	// Flip a bit in the inner origin sig.
	originSig[0] ^= 0x01

	env, _ := buildRelayChain(t, inner, 3)
	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops are intact; Open must succeed (inner origin is the caller's job), got %v", err)
	}
	// The inner origin sig is verified by the caller after Open returns the
	// inner wire. A tampered origin sig must fail here — proving the outer
	// hops passed first (outer-before-inner ordering).
	if identity.VerifyCRDTFrame(originPub, gotInner, originSig) {
		t.Fatalf("tampered inner origin sig must fail the caller's Verify (outer-before-inner ordering)")
	}
}

// TestEnvelope_TamperedInnerWire proves a bit-flipped inner wire breaks the
// outer relay sigs (the signed material binds the inner wire), so Open
// fails at the first outer hop.
func TestEnvelope_TamperedInnerWire(t *testing.T) {
	inner := fakeInnerWire()
	env, _ := buildRelayChain(t, inner, 3)
	// Flip a bit in the inner wire after the chain was built. Every relay
	// signed the original inner wire, so the first outer Verify must fail.
	env.innerWire[0] ^= 0x01
	_, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err == nil {
		t.Fatalf("tampered inner wire must break the outer relay sigs, got nil err")
	}
}

// TestEnvelope_ReorderHops proves reordering hops breaks the chain of
// custody: the signed material binds each hop's index, so swapping two
// hops makes the index-material binding fail at the first swapped hop.
func TestEnvelope_ReorderHops(t *testing.T) {
	inner := fakeInnerWire()
	env, _ := buildRelayChain(t, inner, 3)
	// Swap hops 0 and 1. Hop 1's sig was computed over index=1's material;
	// verifying it at index=0 (different preceding material + different
	// hopIndex) must fail.
	env.hops[0], env.hops[1] = env.hops[1], env.hops[0]
	_, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err == nil {
		t.Fatalf("reordered hops must break the chain-of-custody Verify, got nil err")
	}
}

// TestEnvelope_ZeroHops proves a 0-hop envelope (origin frame, no relays)
// opens trivially: the depth check passes (0 <= bound), the verify loop is
// empty, and the inner wire is returned verbatim. This is the direct-origin
// case (a peer publishing its own frame without relay).
func TestEnvelope_ZeroHops(t *testing.T) {
	inner := fakeInnerWire()
	env := NewRelayEnvelope(inner, nil)
	gotInner, hops, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("0-hop envelope must open, got %v", err)
	}
	if hops != 0 {
		t.Fatalf("0-hop envelope must report hops=0, got %d", hops)
	}
	if !bytes.Equal(gotInner, inner) {
		t.Fatalf("0-hop envelope must return inner wire verbatim")
	}
}

// TestEnvelope_MarshalRoundTrip proves Marshal/UnmarshalRelayEnvelope are
// inverse: a built envelope serializes to its deterministic wire form and
// parses back to an envelope that opens identically.
func TestEnvelope_MarshalRoundTrip(t *testing.T) {
	inner := fakeInnerWire()
	env, _ := buildRelayChain(t, inner, 3)
	wire := env.Marshal()

	parsed, err := UnmarshalRelayEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalRelayEnvelope: %v", err)
	}
	if parsed.HopCount() != 3 {
		t.Fatalf("parsed HopCount = %d, want 3", parsed.HopCount())
	}
	gotInner, hops, err := parsed.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("parsed envelope Open: %v", err)
	}
	if hops != 3 || !bytes.Equal(gotInner, inner) {
		t.Fatalf("parsed envelope must open to the original inner wire (hops=%d inner-equal=%v)", hops, bytes.Equal(gotInner, inner))
	}
}

// TestEnvelope_MalformedFraming proves a truncated/malformed wire buffer is
// rejected by UnmarshalRelayEnvelope without crypto.
func TestEnvelope_MalformedFraming(t *testing.T) {
	cases := [][]byte{
		nil,                        // empty
		make([]byte, 4),            // short header
		{1, 0, 3, 0, 120, 0, 0, 0}, // header only, no inner/hops
		{2, 0, 0, 0, 0, 0, 0, 0},   // wrong version
	}
	for i, w := range cases {
		if _, err := UnmarshalRelayEnvelope(w); err == nil {
			t.Fatalf("malformed case %d must be rejected, got nil err", i)
		}
	}
}

// Source checks for deployment budgets and package boundaries.

// forbiddenBudgetIdentifiers names declaration patterns associated with a
// deployment budget or hop limit. The source-invariant test rejects numeric
// literals assigned to these names; verifyCostPerHop32c is the documented
// exception because it contains a measured verification cost.
var forbiddenBudgetIdentifiers = []string{
	"budget", "deadline", "admission", "latency", "hop", "hopcount", "maxhop",
}

// permittedBudgetConstants contains the measured verification-cost constant
// excluded from the literal-budget check.
var permittedBudgetConstants = map[string]bool{
	"verifyCostPerHop32c": true,
}

// TestEnvelope_NoFabricatedBudgetMagicNumber parses non-test source and
// rejects hard-coded deployment budgets or hop limits. A const or var whose
// name matches forbiddenBudgetIdentifiers cannot have a bare numeric or
// duration value, except for the documented verifyCostPerHop32c measurement.
// It also rejects time duration selectors in const and var initializers.
//
// Derived sizes such as HopSize = PubSize + SigSize + WallSize and error
// values such as ErrHopBoundExceeded remain valid because they are not numeric
// budget literals. Adding `const maxHops = 8` to envelope.go makes this test
// fail.
func TestEnvelope_NoFabricatedBudgetMagicNumber(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/attribution: %v", err)
	}
	// isLiteralNumber distinguishes a bare numeric or duration value from a
	// derived expression such as PubSize + SigSize + WallSize or a function
	// call such as errors.New.
	isLiteralNumber := func(expr ast.Expr) bool {
		switch v := expr.(type) {
		case *ast.BasicLit:
			return true
		case *ast.SelectorExpr:
			// time.Millisecond / time.Microsecond etc. (handled separately
			// below, but counted as a literal-shaped Duration value).
			if id, ok := v.X.(*ast.Ident); ok && id.Name == "time" {
				return true
			}
		}
		return false
	}
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				// Only const and var declarations carry these values.
				if gd.Tok != token.CONST && gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for ni, name := range vs.Names {
						lname := strings.ToLower(name.Name)
						matchesForbidden := false
						for _, pat := range forbiddenBudgetIdentifiers {
							if strings.Contains(lname, pat) {
								matchesForbidden = true
								break
							}
						}
						if !matchesForbidden || permittedBudgetConstants[name.Name] {
							continue
						}
						// Reject a bare numeric value assigned to a hop-limit or
						// admission-budget name. Derived sizes and error sentinels
						// are not deployment budgets.
						if len(vs.Values) > ni && isLiteralNumber(vs.Values[ni]) {
							t.Errorf("forbidden budget/hop-count magic-number %q = <literal> "+
								"in %s (only "+
								"verifyCostPerHop32c is permitted, with its citation)",
								name.Name, filepath.Base(fname))
						}
					}
					// Deployment durations belong in constructor arguments rather
					// than const or var initializers in production source.
					for _, val := range vs.Values {
						ast.Inspect(val, func(n ast.Node) bool {
							sel, ok := n.(*ast.SelectorExpr)
							if !ok {
								return true
							}
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == "time" && (sel.Sel.Name == "Millisecond" || sel.Sel.Name == "Microsecond" || sel.Sel.Name == "Second" || sel.Sel.Name == "Nanosecond") {
								t.Errorf("forbidden hardcoded time literal time.%s in %s "+
									"(a deploy-time budget must be an injected ctor parameter, "+
									"never a source literal)", sel.Sel.Name, filepath.Base(fname))
							}
							return true
						})
					}
				}
			}
		}
	}
}

// Production attribution code must not reference engine or clock symbols.

// forbiddenEngineSymbols lists engine and clock identifiers that production
// attribution code must not reference. Calling Join or ApplyCRDTDeltaEvent
// would import pkg/sync; AdvanceLamportTo would cross the clock boundary.
var forbiddenEngineSymbols = []string{
	"lamportCounter",
	"observedInboundRate",
	"observedInboundRateBits",
	"AdvanceLamportTo",
	"ApplyCRDTDeltaEvent",
	"Join",
}

// TestEnvelope_ForbiddenSymbolsAbsent parses non-test source and rejects
// references to forbiddenEngineSymbols. Comments may name those symbols when
// explaining the package boundary. Adding an ApplyCRDTDeltaEvent reference to
// envelope.go makes this test fail.
func TestEnvelope_ForbiddenSymbolsAbsent(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/attribution: %v", err)
	}
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
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
						t.Errorf("forbidden symbol %q appears in code in %s "+
							"(engine/clock boundary violation)",
							sym, filepath.Base(fname))
					}
				}
				return true
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrent Open under -race (32 distinct relay chains)
// ---------------------------------------------------------------------------

// TestEnvelope_ConcurrentOpenNoRace opens 32 independently constructed relay
// chains in parallel. Run with -race to check Open's read-only use of each
// envelope and the package-level verifyHook access.
func TestEnvelope_ConcurrentOpenNoRace(t *testing.T) {
	const goroutines = 32
	// Pre-build 32 distinct relay chains (each with its own keys + inner
	// wire) so the goroutines exercise independent envelopes.
	envs := make([]*RelayEnvelope, goroutines)
	for i := range envs {
		inner := make([]byte, 120)
		for j := range inner {
			inner[j] = byte(i) ^ byte(j)
		}
		envs[i], _ = buildRelayChain(t, inner, 3)
	}
	maxHops := MaxHopsForBudget(1 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			env := envs[id]
			for i := 0; i < 1000; i++ {
				inner, hops, err := env.Open(maxHops)
				if err != nil {
					t.Errorf("goroutine %d Open: %v", id, err)
					return
				}
				if hops != 3 || inner == nil {
					t.Errorf("goroutine %d Open: bad result hops=%d inner-nil=%v", id, hops, inner == nil)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
