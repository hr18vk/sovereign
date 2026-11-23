// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package chaos — in-process Byzantine fault injection.
//
// InjectByzantineFaults takes a sync.CRDTDelta, ratchets DotCounter toward
// MaxUint64, and re-signs the modified material with circl Ed25519 so the
// resulting frame is cryptographically valid while exceeding normal logical
// counter progression.
//
// In the admission pipeline:
//   - IngressHLCScalarCap.Admit (pkg/clock/admission.go) checks physical-clock
//     drift (incomingPhysicalUSec - localPhysicalUSec > maxDriftEpsilon), so
//     a valid physical timestamp with an inflated logical DotCounter passes.
//   - PeerBucket.Accept (pkg/admission/ewma.go) tracks per-peer DotCounter
//     advancement against an EWMA token budget (initial budget 1<<20),
//     dropping frames whose logical counter jump exhausts the peer's budget.
package chaos

import (
	"encoding/binary"
	"errors"
	"math"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	engsync "github.com/hr18vk/sovereign/pkg/sync"
	mrandv2 "math/rand/v2"
)

// circl ed25519.Sign uses pure RFC 8032 Ed25519 with a 64-byte PrivateKey
// ([]byte, distinct from Go stdlib crypto/ed25519).

// RatchetProfile selects the counter-inflation profile InjectByzantineFaults applies.
type RatchetProfile int

const (
	// RatchetMax sets DotCounter = math.MaxUint64 in one step, draining a fresh
	// peer's 1<<20 EWMA token budget on the first admission check.
	RatchetMax RatchetProfile = iota

	// RatchetIncremental advances DotCounter by a jittered geometric step over
	// sequential frames so the cumulative advance drains the 1<<20 budget within
	// a bounded number of admissions.
	RatchetIncremental
)

// entryWireLen is the on-wire size of sync.CRDTEntry (120 bytes, matching
// crdtEntryWireLen in codec.go).
const entryWireLen = 120

// InjectByzantineFaults takes a sync.CRDTDelta, inflates each entry's
// DotCounter according to profile, and signs the serialized entries with priv.
//
// The caller retains ownership of the input delta. InjectByzantineFaults drains
// input.Entries into a fresh heap slice without mutating the input delta and
// returns a new heap-backed *sync.CRDTDelta, its 64-byte Ed25519 signature,
// and an error if the input delta is nil or empty.
func InjectByzantineFaults(delta *engsync.CRDTDelta, priv ed25519.PrivateKey, profile RatchetProfile) (*engsync.CRDTDelta, []byte, error) {
	if delta == nil || delta.Entries == nil {
		return nil, nil, errors.New("chaos/byzantine: nil delta or nil Entries")
	}

	// Copy each 120-byte CRDTEntry value out of the arena-backed iterator onto
	// the heap so the input delta remains unmodified and EBR pinning is not
	// held across mutation.
	var entries []engsync.CRDTEntry
	var entityIDs []string
	delta.Entries(func(entityID string, entry engsync.CRDTEntry) bool {
		entries = append(entries, entry) // copy-by-value (120-byte value type)
		entityIDs = append(entityIDs, entityID)
		return true
	})

	if len(entries) == 0 {
		return nil, nil, errors.New("chaos/byzantine: delta carries no entries")
	}

	// Inflate each copied entry's DotCounter according to the selected profile.
	for i := range entries {
		entries[i].DotCounter = ratchetCounter(entries[i].DotCounter, profile, i)
	}

	// Build a heap-backed *sync.CRDTDelta with zero arena ownership so callers do
	// not need Release().
	mutated := &engsync.CRDTDelta{
		Entries:      makeSeq(entityIDs, entries),
		OriginNodeID: delta.OriginNodeID,
		MerkleRoot:   delta.MerkleRoot,
	}

	// Sign the canonical 120-byte serialization of the modified entries.
	signedMaterial := canonicalDeltaBytes(entries)
	sig := ed25519.Sign(priv, signedMaterial)

	return mutated, sig, nil
}

// makeSeq returns a heap-slice iterator yielding (entityID, entry) pairs in order.
func makeSeq(entityIDs []string, entries []engsync.CRDTEntry) engsync.Seq {
	return func(yield func(entityID string, entry engsync.CRDTEntry) bool) {
		for i := range entries {
			if !yield(entityIDs[i], entries[i]) {
				return
			}
		}
	}
}

// ratchetCounter computes the inflated DotCounter for one entry under profile.
// RatchetMax returns math.MaxUint64; RatchetIncremental adds a jittered step
// of at least 1<<18 per frame (saturating at math.MaxUint64).
func ratchetCounter(honest uint64, profile RatchetProfile, idx int) uint64 {
	switch profile {
	case RatchetMax:
		return math.MaxUint64
	case RatchetIncremental:
		// Step by 256K + [0, 64K) per entry so 4 steps exceed the 1<<20 budget.
		base := uint64(1 << 18)
		jitter := uint64(mrandv2.IntN(1 << 16))
		step := base + jitter
		// Saturate rather than wrapping around MaxUint64.
		if honest > math.MaxUint64-step {
			return math.MaxUint64
		}
		return honest + step
	default:
		return math.MaxUint64
	}
}

// canonicalEntryBytes encodes one sync.CRDTEntry into a 120-byte BigEndian
// buffer matching encodeCRDTEntry field order.
func canonicalEntryBytes(dst []byte, e engsync.CRDTEntry) {
	off := 0
	copy(dst[off:off+32], e.PayloadDigest[:])
	off += 32
	copy(dst[off:off+16], e.OriginNodeID[:])
	off += 16
	copy(dst[off:off+16], e.DotNodeID[:])
	off += 16
	binary.BigEndian.PutUint64(dst[off:off+8], e.DotCounter)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.SystemTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeStart))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeEnd))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.AssertionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.DecisionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], e.H3Index)
}

// canonicalDeltaBytes returns the canonical serialization of a slice of
// mutated entries: the concatenation of each entry's 120-byte layout. This
// is the signed material InjectByzantineFaults hands to circl Sign. The
// layout is documented (fixed 120 bytes per entry, concatenated in entry
// order) so a verifier can reconstruct it from the mutated delta.
func canonicalDeltaBytes(entries []engsync.CRDTEntry) []byte {
	buf := make([]byte, entryWireLen*len(entries))
	for i := range entries {
		canonicalEntryBytes(buf[i*entryWireLen:(i+1)*entryWireLen], entries[i])
	}
	return buf
}
