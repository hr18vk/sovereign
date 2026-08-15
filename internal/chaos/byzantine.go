// Package chaos — Subphase 5.0: in-process Byzantine interceptor.
//
// This file is the SEMANTIC Byzantine-attack generator — the counterpart to
// AWS FIS that FIS structurally CANNOT be. Per blueprint line 139 (CRDT Sync
// Engine Phase 3.md, verbatim):
//
//	"Out-of-process tools like AWS FIS can introduce latency, drop packets,
//	 and sever connections, but they cannot intelligently synthesize a
//	 cryptographically valid Byzantine payload. FIS cannot forge a
//	 DotCounter, manipulate a causal graph, or craft an Ed25519 signature
//	 that passes the initial mathematical verification but violates the
//	 semantic rules of the CRDT. The architect must ensure the
//	 internal/chaos harness is preserved and evolved to generate these
//	 highly specific, semantically malicious payloads..."
//
// InjectByzantineFaults takes a REAL sync.CRDTDelta, ratchets DotCounter
// toward MaxUint64 (the A2 "incremental ratchet" attack vector the blueprint
// names at CRDT Sync line 101), and re-signs the tampered material with circl
// Sign so the resulting frame is CRYPTOGRAPHICALLY VALID but SEMANTICALLY
// MALICIOUS — exactly the class FIS cannot synthesize. The acceptance test
// then proves the Track 3 admission STACK drops it before it reaches Join.
//
// LABELING HONESTY NOTE (the §0 ruthless-honesty call — do NOT evade):
// The roadmap acceptance (line 81) says "the admission controller (Subphase
// 3.0) catches the A2 ratchet via the per-peer EWMA drain." That wording is
// IMPRECISE. Source-traced:
//   - 3.0's IngressHLCScalarCap.Admit (pkg/clock/admission.go:97) operates on
//     the PHYSICAL CLOCK: reject if incomingPhysicalUSec - localPhysicalUSec
//     > maxDriftEpsilon. A2 inflates DotCounter (a LOGICAL counter), NOT the
//     physical clock — so a frame with a MaxUint64 DotCounter but a valid
//     physical timestamp PASSES 3.0's Admit. 3.0 does NOT catch A2.
//   - 3.1's PeerBucket.Accept (pkg/admission/ewma.go:187) IS the catch:
//     delta = counter - lastCounter; if delta >= peer.budget { Drop }.
//     A MaxUint64 ratchet on a fresh peer (budget = 1<<20) drains the budget
//     to 0 in ONE admit => Drop.
//
// So the roadmap's "(Subphase 3.0)" is a LABELING ERROR: the catch is 3.1's
// PeerBucket.Accept, not 3.0's Admit. A2 is a LOGICAL-counter ratchet; 3.0
// is a PHYSICAL-clock cap. The acceptance test asserts 3.1 returns Drop. We
// do NOT edit the roadmap wording (out of scope); we FLAG the labeling
// imprecision here and in the commit message. Saying "3.0 catches it" would
// be a fabrication the §0 mindset bans.
package chaos

import (
	"encoding/binary"
	"errors"
	"math"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	engsync "github.com/hr18vk/supremum/pkg/sync"
	mrandv2 "math/rand/v2"
)

// circl ed25519.Sign go-doc citation (no-fabrication rule, roadmap line 124).
// Verified from circl@v1.6.4/sign/ed25519/ed25519.go:283:
//
//	func Sign(privateKey PrivateKey, message []byte) []byte
//	    Sign signs the message with privateKey and returns a signature.
//	    This function supports the signature variant defined in RFC-8032:
//	    Ed25519, also known as the pure version of EdDSA. It will panic if
//	    len(privateKey) is not PrivateKeySize.
//
// Related symbols (same file, go-doc-cited):
//   - ed25519.go:178  func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)
//   - ed25519.go:396  func Verify(public PublicKey, message, signature []byte) bool
//   - ed25519.go:56   PublicKeySize  = 32
//   - ed25519.go:58   PrivateKeySize = 64
//   - ed25519.go:60   SignatureSize  = 64
//   - ed25519.go:95   type PrivateKey []byte
//
// The bridge Sign 5.0 uses is circl's ed25519.Sign (NOT stdlib crypto/ed25519
// — stdlib is banned for CRDT per Track 1.1). The private key 5.0 passes is
// circl's PrivateKey ([]byte, 64 bytes).

// RatchetProfile selects the A2 attack shape InjectByzantineFaults applies.
type RatchetProfile int

const (
	// RatchetMax sets DotCounter = math.MaxUint64 in one shot — the maximal
	// single-shot A2 demonstration. It drains 3.1's per-peer budget in
	// exactly 1 admit (delta = MaxUint64 >> initialBudget = 1<<20). This is
	// the deterministic happy path the acceptance test (G5.0.j) exercises.
	RatchetMax RatchetProfile = iota

	// RatchetIncremental steps DotCounter by a geometric+rand/v2-jittered
	// delta over N sequential admits, eventually exhausting the 1<<20 budget
	// in a BOUNDED number of admits — the realistic A2 vector the blueprint
	// names ("a single Byzantine peer can artificially inflate the clock"
	// over passing frames). The incremental test asserts the bucket reaches
	// Drop within a small bound.
	RatchetIncremental
)

// entryWireLen is the canonical on-wire size of a sync.CRDTEntry: 120 bytes
// (the struct is exactly 120 bytes with zero internal padding per
// pkg/sync/hamt.go:28). It MUST equal crdtEntryWireLen in codec.go:31 and
// sizeof(sync.CRDTEntry); the canonical-layout test (G5.0) asserts byte-
// equality against the codec's encodeCRDTEntry so the signed material is
// provably the same layout the production wire path uses.
const entryWireLen = 120

// InjectByzantineFaults is the in-process Byzantine interceptor (roadmap
// line 81, signature verbatim):
//
//	func InjectByzantineFaults(delta *sync.CRDTDelta, priv ed25519.PrivateKey)
//	    (*sync.CRDTDelta, []byte, error)
//
// It takes a REAL sync.CRDTDelta carrying honest sync.CRDTEntry{DotNodeID,
// DotCounter,...} entries, ratchets each entry's DotCounter toward
// MaxUint64 (the A2 attack), and re-signs the tampered material with circl
// Sign so the resulting frame is CRYPTOGRAPHICALLY VALID but SEMANTICALLY
// MALICIOUS — the class FIS cannot synthesize.
//
// OWNERSHIP CONTRACT: the caller owns the input delta's lifecycle. The
// injector does NOT call Release() on the input and does NOT assume EBR
// lifecycle ownership — it DRAINS the input's Entries Seq into a heap
// []CRDTEntry COPY (the partition.go:151 drain idiom), mutates the COPY, and
// builds a NEW *sync.CRDTDelta with a FRESH Seq that yields the mutated
// copies. The new delta is a heap CRDTDelta (only the exported Entries /
// OriginNodeID / MerkleRoot fields are set; the unexported EBR fields are
// zero-valued), so it carries no arena backing and needs no Release. The
// input delta is left byte-identical (the G5.0.g no-in-place-mutation tooth
// asserts this behaviorally).
//
// Returns (mutatedDelta, signature, err). signature is the circl.Sign(priv,
// signedMaterial) [64]byte over the canonical serialized mutated entries.
// err is non-nil iff the input delta is malformed (Entries nil) — never a
// panic; the production harness is the test, and the test is deterministic.
func InjectByzantineFaults(delta *engsync.CRDTDelta, priv ed25519.PrivateKey, profile RatchetProfile) (*engsync.CRDTDelta, []byte, error) {
	if delta == nil || delta.Entries == nil {
		return nil, nil, errors.New("chaos/byzantine: nil delta or nil Entries")
	}

	// DRAIN-AND-COPY (the safe seam, mirroring partition.go:151). The append
	// copies each CRDTEntry (a 120-byte value type) into a heap slice; the
	// arena-backed iterator is now drained. We never mutate the input
	// delta's arena-backed fields in place — that would (i) write into
	// mmap'd C-space the GC does not scan, (ii) race the persist worker / a
	// concurrent InsertLocal CAS, (iii) corrupt the EBR amortization the
	// Phase 2.5b Zero-GC closure depends on. The G5.0.g tooth bans it.
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

	// RATCHET each copied entry's DotCounter toward MaxUint64 (the A2
	// attack). The honest DotCounter is recorded for the test's "was
	// ratcheted" assertion; the ratchet magnitude is profile-dependent.
	for i := range entries {
		entries[i].DotCounter = ratchetCounter(entries[i].DotCounter, profile, i)
	}

	// Build a NEW *sync.CRDTDelta with a FRESH Seq that yields the mutated
	// copies. Only the exported fields are set; the unexported EBR fields
	// stay zero-valued (a heap delta, not arena-backed — safe, no Release).
	mutated := &engsync.CRDTDelta{
		Entries:      makeSeq(entityIDs, entries),
		OriginNodeID: delta.OriginNodeID,
		MerkleRoot:   delta.MerkleRoot,
	}

	// SIGN the canonical serialization of the mutated entries with circl
	// Sign. The signed material is the concatenation of each entry's 120-
	// byte canonical layout (encodeCRDTEntry field order, BigEndian). The
	// signature is cryptographically valid over the tampered material —
	// exactly the FIS-cannot-synthesize property (G5.0.k).
	signedMaterial := canonicalDeltaBytes(entries)
	sig := ed25519.Sign(priv, signedMaterial)

	return mutated, sig, nil
}

// makeSeq returns a fresh Seq yielding the (entityID, entry) pairs in order.
// It captures the slices by reference (the mutated delta owns them for its
// lifetime); the iterator is a plain closure over the heap slices, not an
// arena-backed iterator, so it is safe to consume after the generator
// returns without EBR pinning.
func makeSeq(entityIDs []string, entries []engsync.CRDTEntry) engsync.Seq {
	return func(yield func(entityID string, entry engsync.CRDTEntry) bool) {
		for i := range entries {
			if !yield(entityIDs[i], entries[i]) {
				return
			}
		}
	}
}

// ratchetCounter returns the A2-ratcheted DotCounter for one entry under the
// given profile. RatchetMax pins the counter at MaxUint64 (the maximal
// single-shot). RatchetIncremental steps the counter by a geometric+
// rand/v2-jittered delta so a sequence of admits exhausts the 1<<20 budget
// in a bounded number of frames (the realistic A2). The index seeds the
// rand/v2 jitter deterministically per-entry within a single injector call
// (math/rand/v2's top-level source is process-seeded; no deprecated
// rand.Seed is used — G5.0.h).
func ratchetCounter(honest uint64, profile RatchetProfile, idx int) uint64 {
	switch profile {
	case RatchetMax:
		return math.MaxUint64
	case RatchetIncremental:
		// Geometric step: each entry advances by a large, jittered delta so
		// the cumulative drain exceeds the 1<<20 budget within a bounded
		// number of entries. base = 1<<18 (256K) per step; jitter in
		// [0, 1<<16) via rand/v2.IntN. 4 such steps drain > 1<<20.
		base := uint64(1 << 18)
		jitter := uint64(mrandv2.IntN(1 << 16))
		step := base + jitter
		// Saturating add so the incremental path never wraps past MaxUint64
		// (a wrap would un-ban the attacker — the §0 mindset bans it).
		if honest > math.MaxUint64-step {
			return math.MaxUint64
		}
		return honest + step
	default:
		return math.MaxUint64
	}
}

// canonicalEntryBytes writes one sync.CRDTEntry into a 120-byte destination
// using the SAME field order and BigEndian endianness as the production
// codec's encodeCRDTEntry (codec.go:119-141): PayloadDigest, OriginNodeID,
// DotNodeID, DotCounter, SystemTime, ValidTimeStart, ValidTimeEnd,
// AssertionTime, DecisionTime, H3Index. The canonical-layout test asserts
// byte-equality against the codec so the signed material is provably the
// production wire layout (no fabricated serializer).
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
