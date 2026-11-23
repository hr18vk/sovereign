// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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
	"github.com/hr18vk/sovereign/pkg/identity"
)

// originSigArray copies a 64-byte Ed25519 signature into the canonical
// [OriginSigSize]byte form the envelope header carries.
func originSigArray(sig []byte) [OriginSigSize]byte {
	var a [OriginSigSize]byte
	copy(a[:], sig)
	return a
}

// buildSignedRelayChain signs the inner wire with the origin key and builds
// the requested relay hops. It returns the signed envelope, the origin public
// key, and the relay public keys. The origin signature travels in the envelope
// header, as it does on the production wire.
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
// OriginSig framing field exists and is surfaced (positive and negative tests)
// ---------------------------------------------------------------------------

// TestOriginSig_RoundTrip checks that Marshal and UnmarshalRelayEnvelope
// preserve originSig byte for byte. The parsed signature then verifies against
// the inner wire returned by Open and the origin public key.
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
	// Verify the parsed signature with the origin key and returned inner wire.
	gotInner, _, err := got.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("Open outer hops: %v", err)
	}
	if !identity.VerifyCRDTFrame(originPub, gotInner, got.originSig[:]) {
		t.Fatalf("surfaced originSig must verify against the verified inner wire")
	}
}

// TestOriginSig_ZeroOnVersion1Envelope checks that NewRelayEnvelope leaves
// originSig zero. The production receiver treats that value as DropVerify,
// and VerifyCRDTFrame rejects it even for a zero-hop envelope.
func TestOriginSig_ZeroOnVersion1Envelope(t *testing.T) {
	inner := fakeInnerWire()
	env := NewRelayEnvelope(inner, nil)
	var zero [OriginSigSize]byte
	if got := env.OriginSig(); got != zero {
		t.Fatalf("NewRelayEnvelope must carry all-zero originSig, got non-zero")
	}
	// A zero originSig fails VerifyCRDTFrame (the production receiver's
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

// TestOriginSig_ForgedOriginSig signs the inner wire with a different key
// from the one the receiver resolves through the Directory. Open accepts the
// intact relay chain, but VerifyCRDTFrame rejects the substituted signature.
func TestOriginSig_ForgedOriginSig(t *testing.T) {
	inner := fakeInnerWire()
	env, originPub, _ := buildSignedRelayChain(t, inner, 1)

	// Sign the inner wire with a key other than the resolved origin key.
	_, attackerPriv := genKey(t)
	forgedSig := ed25519.Sign(attackerPriv, inner)
	env.originSig = originSigArray(forgedSig)

	gotInner, _, err := env.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("outer hops intact; Open must succeed (origin sig is the caller's job): %v", err)
	}
	// The receiver resolves originPub (the real origin) via the Directory;
	// the forged sig under the attacker's key fails VerifyCRDTFrame.
	if identity.VerifyCRDTFrame(originPub, gotInner, env.originSig[:]) {
		t.Fatalf("forged originSig (different key) must fail VerifyCRDTFrame")
	}
}

// TestOriginSig_TamperedOriginSig flips one bit in originSig. The relay chain
// still opens, but the caller's VerifyCRDTFrame rejects the changed signature.
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

// TestOriginSig_OmittedFromWire replaces originSig with zero bytes. The
// caller's VerifyCRDTFrame rejects the result, so stripping the origin
// signature does not admit the frame.
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

// TestOriginSig_TamperedOnWire changes originSig after Marshal and before
// UnmarshalRelayEnvelope. The parsed signature differs from the original and
// fails the caller's VerifyCRDTFrame after the relay chain opens.
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

// The source check below verifies that the originSig field and its wire copy
// operations remain present. Without them, the receiver cannot verify the
// inner origin from the wire.

// TestOriginSig_FramingSlotPresent checks the non-test source for each part
// of the origin-signature wire path: the size constant, the RelayEnvelope
// field, the Marshal write, and the UnmarshalRelayEnvelope read. Removing any
// of them leaves the receiver without an on-wire origin signature and makes
// this test fail.
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

	// Check the field, its size constant, and the two wire-copy operations.
	haveField := false
	haveConst := false
	haveMarshalWrite := false
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
		t.Errorf("OriginSigSize const missing from pkg/attribution framing " +
			"(originSig slot absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveField {
		t.Errorf("originSig [OriginSigSize]byte field missing from RelayEnvelope " +
			"(originSig slot absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveMarshalWrite {
		t.Errorf("Marshal does not write the originSig slot to the wire " +
			"(originSig absent from envelope framing; production receiver cannot verify inner origin)")
	}
	if !haveUnmarshalRead {
		t.Errorf("UnmarshalRelayEnvelope does not read/surface the originSig slot " +
			"(originSig absent from envelope framing; production receiver cannot verify inner origin)")
	}
}
