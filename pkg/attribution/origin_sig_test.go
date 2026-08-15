package attribution

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/supremum/pkg/identity"
)

// originSigArray copies a 64-byte Ed25519 signature into the canonical
// [OriginSigSize]byte form the envelope header carries.
func originSigArray(sig []byte) [OriginSigSize]byte {
	var a [OriginSigSize]byte
	copy(a[:], sig)
	return a
}

// buildSignedRelayChain is the version-2 build path: the origin signs the
// inner wire (originSig rides ON the envelope, not test-computed out-of-band),
// then each relay signs the chain-of-custody material and appends its Hop.
// Returns the signed envelope, the origin's public key (for the receiver's
// Directory), and the relay public keys. This is the production build path
// the live receiver consumes (GAP-1 closed: originSig is on the wire).
func buildSignedRelayChain(t *testing.T, innerWire []byte, nHops int) (*RelayEnvelope, ed25519.PublicKey, []ed25519.PublicKey) {
	t.Helper()
	originPub, originPriv := genKey(t)
	originSig := ed25519.Sign(originPriv, innerWire)

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
		preceding = SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	return NewSignedRelayEnvelope(innerWire, originSigArray(originSig), hops), originPub, relayPubs
}

// ---------------------------------------------------------------------------
// G3.5.a — originSig framing field EXISTS and is surfaced (positive + negative)
// ---------------------------------------------------------------------------

// TestOriginSig_RoundTrip proves the originSig slot rides the wire: a signed
// envelope Marshal's to its deterministic form, UnmarshalRelayEnvelope parses
// it back, and OriginSig() returns the byte-identical origin signature the
// caller feeds to VerifyCRDTFrame. This is the GAP-1 contract: the live
// receiver resolves originSig from the wire, not from a test-computed cheat.
func TestOriginSig_RoundTrip(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 2)

	wire := env.Marshal()
	got, err := UnmarshalRelayEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalRelayEnvelope: %v", err)
	}
	if !bytes.Equal(got.originSig[:], env.originSig[:]) {
		t.Fatalf("originSig must round-trip byte-identical through Marshal/Unmarshal")
	}
	// The surfaced originSig MUST verify against the verified inner wire under
	// the origin's public key — the load-bearing composition seam.
	gotInner, _, err := got.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("Open outer hops: %v", err)
	}
	if !identity.VerifyCRDTFrame(originPub, gotInner, got.originSig[:]) {
		t.Fatalf("surfaced originSig must verify against the verified inner wire")
	}
}

// TestOriginSig_ZeroOnVersion1Envelope proves NewRelayEnvelope (the version-1
// build path) carries an all-zero originSig, surfaced by OriginSig(). The
// production receiver treats a zero originSig as a DropVerify (an unsigned
// origin is never admitted); this test documents that contract.
func TestOriginSig_ZeroOnVersion1Envelope(t *testing.T) {
	inner := fakeInnerWire()
	env := NewRelayEnvelope(inner, nil)
	var zero [OriginSigSize]byte
	if got := env.OriginSig(); got != zero {
		t.Fatalf("NewRelayEnvelope must carry all-zero originSig, got non-zero")
	}
	// A zero originSig MUST fail VerifyCRDTFrame (the production receiver's
	// DropVerify contract).
	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("0-hop Open: %v", err)
	}
	// Resolve a throwaway origin pub so the Verify is over a real key; a
	// zero sig under any key must fail.
	originPub, _ := genKey(t)
	if identity.VerifyCRDTFrame(originPub, gotInner, zero[:]) {
		t.Fatalf("all-zero originSig must fail VerifyCRDTFrame (production receiver DropVerify)")
	}
}

// TestOriginSig_ForgedOriginSig proves a FORGED originSig (signed by a
// DIFFERENT key than the one the receiver resolves via the Directory) fails
// the caller's VerifyCRDTFrame after Open succeeds. This is the forge tooth:
// an attacker cannot substitute their own origin signature for the origin's.
func TestOriginSig_ForgedOriginSig(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 1)

	// Attacker signs the inner wire with a DIFFERENT key.
	_, attackerPriv := genKey(t)
	forgedSig := ed25519.Sign(attackerPriv, inner)
	env.originSig = originSigArray(forgedSig)

	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops intact; Open must succeed (origin sig is the caller's job): %v", err)
	}
	// The receiver resolves originPub (the real origin) via the Directory;
	// the forged sig under the attacker's key MUST fail VerifyCRDTFrame.
	if identity.VerifyCRDTFrame(originPub, gotInner, env.originSig[:]) {
		t.Fatalf("forged originSig (different key) must fail VerifyCRDTFrame")
	}
}

// TestOriginSig_TamperedOriginSig proves a single-bit flip in the on-wire
// originSig fails the caller's VerifyCRDTFrame after Open succeeds. This is
// the tamper tooth: an attacker cannot mutate the origin signature in flight.
func TestOriginSig_TamperedOriginSig(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 1)

	// Flip a bit in the on-wire originSig.
	env.originSig[0] ^= 0x01

	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops intact; Open must succeed: %v", err)
	}
	if identity.VerifyCRDTFrame(originPub, gotInner, env.originSig[:]) {
		t.Fatalf("tampered originSig must fail VerifyCRDTFrame")
	}
}

// TestOriginSig_OmittedFromWire proves an OMITTED originSig (all-zero on the
// wire) fails the caller's VerifyCRDTFrame — the production receiver's
// DropVerify contract. An attacker cannot strip the origin signature and
// have the frame admitted.
func TestOriginSig_OmittedFromWire(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 1)

	// Strip the originSig (set to all-zero, simulating an omitted slot).
	var zero [OriginSigSize]byte
	env.originSig = zero

	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops intact; Open must succeed: %v", err)
	}
	if identity.VerifyCRDTFrame(originPub, gotInner, env.originSig[:]) {
		t.Fatalf("omitted (zero) originSig must fail VerifyCRDTFrame (DropVerify)")
	}
}

// TestOriginSig_TamperedOnWire proves a bit-flip in the originSig slot ON THE
// WIRE (after Marshal, before Unmarshal) is surfaced byte-differently by
// UnmarshalRelayEnvelope and fails the caller's Verify. This proves the
// originSig slot is integrity-checked end-to-end through the wire, not just
// in-memory.
func TestOriginSig_TamperedOnWire(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 1)
	wire := env.Marshal()

	// Flip a bit in the originSig slot on the wire (header offset 8).
	wire[8] ^= 0x01

	got, err := UnmarshalRelayEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalRelayEnvelope: %v", err)
	}
	if bytes.Equal(got.originSig[:], env.originSig[:]) {
		t.Fatalf("tampered on-wire originSig must differ from the original")
	}
	gotInner, _, err := got.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops intact; Open must succeed: %v", err)
	}
	if identity.VerifyCRDTFrame(originPub, gotInner, got.originSig[:]) {
		t.Fatalf("tampered on-wire originSig must fail VerifyCRDTFrame")
	}
}

// ---------------------------------------------------------------------------
// G3.5.a NEGATIVE CONTROL — removing the originSig slot from the framing
// fails the build (the slot is load-bearing; a production receiver cannot
// verify the inner origin without it). This static tooth greps the
// pkg/attribution non-test source for the originSig framing field and FAILS
// if it is absent.
// ---------------------------------------------------------------------------

// TestOriginSig_FramingSlotPresent is the G3.5.a negative-control tooth: it
// parses pkg/attribution non-test Go source and FAILS if the originSig slot
// is absent from the envelope framing. The framing is load-bearing: without
// the [OriginSigSize]byte field on RelayEnvelope AND the wire write/read of
// it in Marshal/UnmarshalRelayEnvelope, the production receiver has no
// on-wire origin signature and the probe cheat (HC1) ships as production.
//
// Negative control: delete the `originSig [OriginSigSize]byte` field from
// RelayEnvelope (or the copy in Marshal/Unmarshal) and this test MUST FAIL;
// re-add -> PASS.
func TestOriginSig_FramingSlotPresent(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/attribution: %v", err)
	}

	// 1. The RelayEnvelope struct MUST carry an originSig field of array
	//    type [OriginSigSize]byte (the framing slot).
	haveField := false
	// 2. The OriginSigSize const MUST be declared (the slot size).
	haveConst := false
	// 3. Marshal MUST write the originSig slot to the wire (a copy call whose
	//    destination is out[8:...] and source references e.originSig).
	haveMarshalWrite := false
	// 4. UnmarshalRelayEnvelope MUST read the originSig slot from the wire
	//    (a copy call whose source is wire[8:...] and dest references originSig).
	haveUnmarshalRead := false

	// sliceLowIsLiteral8 reports whether a slice expression's low bound is
	// the literal integer 8 (the originSig slot's header offset).
	sliceLowIsLiteral8 := func(sl *ast.SliceExpr) bool {
		if sl == nil || sl.Low == nil {
			return false
		}
		if lit, ok := sl.Low.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "8" {
			return true
		}
		return false
	}
	// exprRefsOriginSig reports whether an expression references originSig
	// (e.g. e.originSig, originSig, got.originSig).
	exprRefsOriginSig := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "originSig" {
				found = true
				return false
			}
			return true
		})
		return found
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				// const OriginSigSize = ...
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
					for _, spec := range gd.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							for _, name := range vs.Names {
								if name.Name == "OriginSigSize" {
									haveConst = true
								}
							}
						}
					}
				}
				// RelayEnvelope struct field: originSig [OriginSigSize]byte
				ast.Inspect(decl, func(n ast.Node) bool {
					if v, ok := n.(*ast.Field); ok {
						for _, name := range v.Names {
							if name.Name == "originSig" {
								if at, ok := v.Type.(*ast.ArrayType); ok {
									if id, ok := at.Len.(*ast.Ident); ok && id.Name == "OriginSigSize" {
										haveField = true
									}
								}
							}
						}
					}
					return true
				})
				// Marshal/UnmarshalRelayEnvelope copy calls. Inspect only real
				// statements (not comments): ast.Inspect walks the parsed AST,
				// which excludes comments, so a commented-out copy is invisible.
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				isMarshal := fn.Name.Name == "Marshal"
				isUnmarshal := fn.Name.Name == "UnmarshalRelayEnvelope"
				if !isMarshal && !isUnmarshal {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					id, ok := call.Fun.(*ast.Ident)
					if !ok || id.Name != "copy" || len(call.Args) != 2 {
						return true
					}
					dst, src := call.Args[0], call.Args[1]
					// Marshal: copy(out[8:8+OriginSigSize], e.originSig[:])
					//   dst is a slice with low literal 8; src refs originSig.
					if isMarshal {
						if dsl, ok := dst.(*ast.SliceExpr); ok && sliceLowIsLiteral8(dsl) && exprRefsOriginSig(src) {
							haveMarshalWrite = true
						}
					}
					// Unmarshal: copy(originSig[:], wire[8:8+OriginSigSize])
					//   src is a slice with low literal 8; dst refs originSig.
					if isUnmarshal {
						if ssl, ok := src.(*ast.SliceExpr); ok && sliceLowIsLiteral8(ssl) && exprRefsOriginSig(dst) {
							haveUnmarshalRead = true
						}
					}
					return true
				})
			}
		}
	}

	if !haveConst {
		t.Errorf("G3.5.a: OriginSigSize const MISSING from pkg/attribution framing " +
			"(originSig slot absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveField {
		t.Errorf("G3.5.a: originSig [OriginSigSize]byte field MISSING from RelayEnvelope " +
			"(originSig slot absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveMarshalWrite {
		t.Errorf("G3.5.a: Marshal does NOT write the originSig slot to the wire " +
			"(originSig absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveUnmarshalRead {
		t.Errorf("G3.5.a: UnmarshalRelayEnvelope does NOT read/surface the originSig slot " +
			"(originSig absent from envelope framing; production receiver cannot verify inner origin)")
	}
}
