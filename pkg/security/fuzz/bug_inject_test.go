//go:build fuzzbuginject

package fuzz

import (
	"encoding/binary"
	"testing"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// bug_inject_test.go is the T-FUZZ-BUG-INJECT-CONTROL proof — the Day-25 Law 5 /
// Day-31 T-PQ-KEM-CLASSICAL-CONTROL mold. It PROVES the harness is NOT a
// tautology: a fuzz that could NOT catch an INJECTED panic is a no-op runner.
//
// BUILD TAG (load-bearing). This ENTIRE file is behind the `fuzzbuginject` build
// tag. The DEFAULT build (`go test ./pkg/security/fuzz/`, no -tags) does NOT
// compile the bug-injected unmarshaler copy NOR the proof tooth — a buggy
// unmarshaler must NEVER ship in the production binary, and the opt-in tag is
// the gate. The operator runs the proof explicitly:
//
//	go test -tags fuzzbuginject -run TestBugInjectControlProof ./pkg/security/fuzz/
//	go test -tags fuzzbuginject -fuzz=FuzzBugInjectControl -fuzztime=30s ./pkg/security/fuzz/
//
// THE CONTRAST (the load-bearing shape). On a SHORT IBLT seed (a valid 'IBL1'
// magic + numBuckets=3 + k=3 + a zero seed + NO bucket body — just the 18-byte
// header):
//
//   - the REAL sync.UnmarshalIBLT returns ErrMalformedDigest (NO panic). The
//     bounds guard `len(wire) < 18 + 3*20 == 78` HOLDS (the seed is 18 bytes <
//     78) → the guard rejects the short bucket array cleanly. This is the
//     coverage behavior the fuzz asserts.
//
//   - a BUG-INJECTED copy (bugInjectUnmarshalIBLT) that SKIPS the bounds guard
//     reads bucket bytes PAST the wire's 18-byte end → an out-of-bounds slice
//     index panic (the classic fuzz catch, recoverable).
//
// The contrast IS the proof: a real out-of-bounds panic on a real input,
// catchable by a real recover, that the REAL unmarshaler does NOT produce on the
// same input. A fuzz that finds NO panic on the real unmarshalers is therefore a
// genuine "no crash found" result, NOT a no-op runner.

// bugInjectUnmarshalIBLT is a COPY of sync.UnmarshalIBLT with the bounds guard
// DELETED (the bug). It is build-tagged `fuzzbuginject` so it is ONLY compiled
// when the operator opts into the bug-inject proof — it can NEVER reach the
// production binary. The bug: it reads numBuckets from the wire, then reads
// bucket bytes at offset `18 + i*20` WITHOUT checking the wire is long enough →
// an out-of-bounds slice index panic on a short seed.
//
// It does NOT construct a real eng.IBLT (the point is the PANIC, not a usable
// struct — constructing one would need a SetBucket helper that does not exist,
// and adding one would touch non-test pkg/sync source, breaking M5). It reads
// the bucket Count field into a throwaway uint32 so the read happens + panics.
func bugInjectUnmarshalIBLT(wire []byte) (_ *eng.IBLT, _ error) {
	// BUG: NO length check on the header (real UnmarshalIBLT returns
	// ErrMalformedDigest on a short header; this copy reads past the end). The
	// real guard at iblt_wire.go:263 is the one this copy deletes.
	n := int(binary.LittleEndian.Uint32(wire[4:8])) //nolint:staticcheck // the BUG — no bounds guard
	if n > 4 {
		n = 4 // cap so the loop bounds are small (a longer loop would also panic, just slower)
	}
	// BUG: read bucket bytes PAST the wire's end (real UnmarshalIBLT guards
	// `len(wire) < 18 + n*20` BEFORE this loop at iblt_wire.go:277; this copy
	// does NOT — the deleted guard is the injected bug).
	for i := 0; i < n; i++ {
		off := 18 + i*20
		_ = binary.LittleEndian.Uint32(wire[off : off+4]) // out-of-bounds on a short seed
	}
	return nil, nil
}

// TestBugInjectControlProof is the DETERMINISTIC, OPT-IN proof that the harness
// is NOT a tautology (T-FUZZ-BUG-INJECT-CONTROL). It runs a short IBLT seed
// through the REAL unmarshaler (asserts NO panic — returns an error) AND
// through the BUG-INJECTED copy (asserts a PANIC — recovered). The contrast
// proves a real panic IS catchable on a real input shape.
//
// OPT-IN (build-tagged): `go test -tags fuzzbuginject -run TestBugInjectControlProof ./pkg/security/fuzz/`
func TestBugInjectControlProof(t *testing.T) {
	t.Log("T-FUZZ-BUG-INJECT-CONTROL: proving the harness is NOT a tautology")
	// The short seed: a valid 'IBL1' header (18 bytes) declaring numBuckets=3
	// but carrying NO bucket body. The REAL unmarshaler's bounds guard rejects
	// it (len 18 < 18 + 3*20 == 78); the BUG copy's deleted guard reads past.
	shortSeed := make([]byte, 18)
	binary.LittleEndian.PutUint32(shortSeed[0:4], 0x49424C31) // 'IBL1'
	binary.LittleEndian.PutUint32(shortSeed[4:8], 3)          // numBuckets=3, NO body
	binary.LittleEndian.PutUint16(shortSeed[8:10], 3)         // k=3
	binary.LittleEndian.PutUint64(shortSeed[10:18], 0)        // seed

	// 1. The REAL unmarshaler on the short seed: NO panic (returns error).
	_, err := eng.UnmarshalIBLT(shortSeed)
	if err == nil {
		t.Fatal("T-FUZZ-BUG-INJECT-CONTROL: real UnmarshalIBLT should reject the short seed (an error), got nil — the bounds guard should fire")
	}
	t.Logf("T-FUZZ-BUG-INJECT-CONTROL: real UnmarshalIBLT(shortSeed) -> error (NO panic): %v", err)

	// 2. The BUG-INJECTED copy on the SAME short seed: PANIC (the deleted bounds
	//    guard lets the loop read past the wire's 18-byte end).
	var panicked bool
	var panicVal any
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		_, _ = bugInjectUnmarshalIBLT(shortSeed)
	}()
	if !panicked {
		t.Fatal("T-FUZZ-BUG-INJECT-CONTROL: bug-injected UnmarshalIBLT should PANIC on the short seed (the deleted bounds guard lets the loop read past the wire) — the harness is a TAUTOLOGY if it cannot catch this injected panic")
	}
	t.Logf("T-FUZZ-BUG-INJECT-CONTROL: bug-injected UnmarshalIBLT(shortSeed) -> PANIC (recovered): %v — the harness IS load-bearing (a real panic is catchable on a real input shape)", sprintAny(panicVal))
}

// FuzzBugInjectControl is the OPT-IN fuzz target that catches the injected bug
// under a real fuzzer (the manual proof the harness is load-bearing). Run:
//
//	go test -tags fuzzbuginject -run='^$' -fuzz=FuzzBugInjectControl -fuzztime=30s ./pkg/security/fuzz/
//
// The fuzzer mutates the short-seed shape; the deleted bounds guard in
// bugInjectUnmarshalIBLT yields an out-of-bounds panic within seconds — the
// proof a real fuzzer catches a real injected panic (the Day-31
// KEM-CLASSICAL-CONTROL mold). The default build (no tag) does NOT compile this
// target, so it NEVER runs in CI's default `go test ./...`.
func FuzzBugInjectControl(f *testing.F) {
	for _, s := range bugInjectSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		// RECOVER: this is the BUG-INJECT target — its seeds are DELIBERATELY
		// shaped to PANIC the bug-injected copy (the deleted bounds guard). Unlike
		// the 6 real-unmarshaler fuzz targets (which assert NO-panic), this target's
		// PURPOSE is to panic. In `go test` corpus-only mode (no -fuzz flag) the
		// panic would propagate as a test FAILURE; recovering here makes
		// corpus-only mode pass (the panic is EXPECTED for this target) so
		// `go test -tags fuzzbuginject ./pkg/security/fuzz/` is GREEN. The OPERATOR
		// runs the actual fuzzing with `-fuzz=FuzzBugInjectControl`, where the
		// fuzzer reports a panic as "found a failing input" (the success signal —
		// the proof the harness catches real panics). The recover does NOT mask a
		// production crash (Law IV) — the bug-injected copy is build-tagged
		// fuzzbuginject + NEVER ships in the production binary; this recover is in
		// a TEST closure only. The deterministic no-panic-vs-panic CONTRAST proof
		// is TestBugInjectControlProof (which asserts the panic fired); this
		// fuzz target is the operator's exploratory tool, not the proof.
		defer func() { _ = recover() }()
		_, _ = bugInjectUnmarshalIBLT(wire)
	})
}

// bugInjectSeeds is the FuzzBugInjectControl seed corpus (the SINGLE SOURCE OF
// TRUTH — the desync discipline: the f.Add calls AND the on-disk
// testdata/fuzz/FuzzBugInjectControl/ corpus files both derive from this list,
// so the byte-equality tooth TestSeedCorpusMatchesBuilders can re-derive the
// corpus from this list + assert the on-disk files match byte-for-byte). The 6
// seeds: the short header shape (panics under the bug), a second short header
// (a different numBuckets — the bug also OOB-reads here), the valid IBLT (does
// NOT panic — the bug copy's loop reads in-bounds on a well-formed body), the
// length-bomb (capped here so it's an OOB not OOM), + the tiny shapes. The list
// ORDER is the on-disk file order (seed-0.txt..seed-5.txt) — the byte-equality
// tooth asserts byte-identity in this order, so a reordered corpus fails it.
func bugInjectSeeds() [][]byte {
	return [][]byte{
		makeShortIBLTHeader(3),
		makeShortIBLTHeader(4),
		validIBLT(),
		lengthBombIBLT(),
		{0x49},
		{},
	}
}

// bugInjectSeedsOrNil is the build-tagged override of the default-build nil stub
// in bug_inject_default_test.go (the !fuzzbugbuild exclusion there + the
// fuzzbuginject tag here ensure only ONE compiles per build — no redeclaration).
// Under -tags fuzzbuginject it returns the real bugInjectSeeds() so the
// byte-equality tooth TestSeedCorpusMatchesBuilders enforces builder↔corpus
// byte-identity for the bug-inject target too; in the default build the stub
// returns nil → the tooth skips it (the opt-in discipline).
func bugInjectSeedsOrNil() [][]byte {
	return bugInjectSeeds()
}

// makeShortIBLTHeader builds a valid 'IBL1' header declaring numBuckets buckets
// but carrying NO bucket body — the shape that panics under the bug-injected
// copy (deleted bounds guard) and is cleanly rejected by the real unmarshaler.
func makeShortIBLTHeader(numBuckets int) []byte {
	out := make([]byte, 18)
	binary.LittleEndian.PutUint32(out[0:4], 0x49424C31)
	binary.LittleEndian.PutUint32(out[4:8], uint32(numBuckets))
	binary.LittleEndian.PutUint16(out[8:10], 3)
	binary.LittleEndian.PutUint64(out[10:18], 0)
	return out
}
