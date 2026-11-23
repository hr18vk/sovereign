// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build fuzzbuginject

package fuzz

import (
	"encoding/binary"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// The fuzzbuginject build tag limits this fault-injection control to explicit
// test runs; default builds exclude both the modified unmarshaler and its test.
// Run the deterministic control with:
//
//	go test -tags fuzzbuginject -run '^TestBugInjectControlProof$' ./pkg/security/fuzz/
//
// The input is an 18-byte IBLT header with numBuckets=3, k=3, and no bucket
// body. sync.UnmarshalIBLT rejects it because three 20-byte buckets require 78
// bytes in total. bugInjectUnmarshalIBLT omits the header and body length checks,
// so its first bucket read passes the end of the slice and panics. The test
// recovers that panic and requires the real unmarshaler to return an error,
// demonstrating that the two paths behave differently on the same input.

// bugInjectUnmarshalIBLT retains sync.UnmarshalIBLT's bucket-read offsets but
// omits its length checks. A short input therefore causes an out-of-bounds slice
// panic. It returns no usable IBLT: the discarded Count read is sufficient to
// trigger the fault without adding a test-only bucket setter to pkg/sync.
func bugInjectUnmarshalIBLT(wire []byte) (_ *eng.IBLT, _ error) {
	// Omit the header-length check and read numBuckets directly.
	n := int(binary.LittleEndian.Uint32(wire[4:8])) //nolint:staticcheck // the BUG — no bounds guard
	if n > 4 {
		n = 4 // cap so the loop bounds are small (a longer loop would also panic, just slower)
	}
	// Omit the corresponding bucket-array length check as well.
	for i := 0; i < n; i++ {
		off := 18 + i*20
		_ = binary.LittleEndian.Uint32(wire[off : off+4]) // out-of-bounds on a short seed
	}
	return nil, nil
}

// TestBugInjectControlProof requires the real unmarshaler to reject shortSeed
// without a panic and the modified copy to panic on the same input.
func TestBugInjectControlProof(t *testing.T) {
	t.Log("fault-injection control: checking the short-seed contrast")
	// The header declares three buckets but carries no bucket body.
	shortSeed := make([]byte, 18)
	binary.LittleEndian.PutUint32(shortSeed[0:4], 0x49424C31) // 'IBL1'
	binary.LittleEndian.PutUint32(shortSeed[4:8], 3)          // numBuckets=3, no body
	binary.LittleEndian.PutUint16(shortSeed[8:10], 3)         // k=3
	binary.LittleEndian.PutUint64(shortSeed[10:18], 0)        // seed

	// The real unmarshaler rejects the 18-byte input before reading buckets.
	_, err := eng.UnmarshalIBLT(shortSeed)
	if err == nil {
		t.Fatal("real UnmarshalIBLT returned nil error for the short seed; want a bounds rejection")
	}
	t.Logf("real UnmarshalIBLT(shortSeed) returned an error without a panic: %v", err)

	// The modified copy reads the first bucket beyond the same 18-byte input.
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
		t.Fatal("fault-injected UnmarshalIBLT did not panic on the short seed; want an out-of-bounds read")
	}
	t.Logf("fault-injected UnmarshalIBLT(shortSeed) panic recovered: %v", sprintAny(panicVal))
}

// FuzzBugInjectControl exercises the modified unmarshaler with mutated inputs.
// Its closure recovers panics so ordinary tagged test runs can execute the seed
// corpus. Consequently, TestBugInjectControlProof is the deterministic control;
// this target is exploratory rather than a pass/fail panic oracle. Run it with:
//
//	go test -tags fuzzbuginject -run='^$' -fuzz=FuzzBugInjectControl -fuzztime=30s ./pkg/security/fuzz/
func FuzzBugInjectControl(f *testing.F) {
	for _, s := range bugInjectSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		// The modified unmarshaler is expected to panic on short inputs. Recover
		// here so corpus-only execution and fuzz exploration can continue. This
		// recovery also means the fuzzer does not report that panic as a finding;
		// TestBugInjectControlProof checks the expected panic explicitly.
		defer func() { _ = recover() }()
		_, _ = bugInjectUnmarshalIBLT(wire)
	})
}

// bugInjectSeeds returns two short headers, a valid IBLT, an excessive bucket
// count, and empty or one-byte inputs. The valid IBLT remains in bounds; the
// short and excessive-count inputs reach out-of-bounds reads in the modified
// copy. TestSeedCorpusMatchesBuilders requires the six corpus files to match
// this list in order.
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

// bugInjectSeedsOrNil is the tagged counterpart of the nil stub in
// bug_inject_default_test.go. Returning the actual list enables corpus byte
// comparison for FuzzBugInjectControl in this build.
func bugInjectSeedsOrNil() [][]byte {
	return bugInjectSeeds()
}

// This function builds a valid 'IBL1' header declaring numBuckets buckets
// but carrying no bucket body — the shape that panics under the fault-injection
// copy (deleted bounds guard) and is cleanly rejected by the real unmarshaler.
func makeShortIBLTHeader(numBuckets int) []byte {
	out := make([]byte, 18)
	binary.LittleEndian.PutUint32(out[0:4], 0x49424C31)
	binary.LittleEndian.PutUint32(out[4:8], uint32(numBuckets))
	binary.LittleEndian.PutUint16(out[8:10], 3)
	binary.LittleEndian.PutUint64(out[10:18], 0)
	return out
}
