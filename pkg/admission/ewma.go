// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package admission implements the per-peer Sybil-burst isolation layer
// of the planetary-fanout CRDT mesh. PeerBucket is the SECOND admission
// gate an inbound frame crosses — it runs at the transport seam, BEFORE
// the sub-us IngressHLCScalarCap clock gate
// and long before the ~71.4 us/op Ed25519 VerifyCRDTFrame gate.
// Where 3.0 drops Byzantine-TIME frames and the engine
// skew bound (crdt.go:32 LamportSkewAbsoluteSlackUnbounded) admits any
// inbound DotCounter below MaxUint64, 3.1 drops Byzantine-RATE frames
// (the DotCounter-ratchet Sybil) at the TCP layer, isolated to the ONE
// malicious identity, so a single attacker cannot exhaust the admission
// budget of honest peers.
//
// Architectural ordering invariant (load-bearing, tested):
//
//	[wire] -> PeerBucket.Accept(pub, counter) // sub-us, per-peer rate cap
//
// -> if Keep: IngressHLCScalarCap.Admit // sub-us clock cap (3.0)
// -> if accept: VerifyCRDTFrame // 71.4 us/op, EXPENSIVE
// -> if verify ok: engine.Join // CRDT merge
//
// pkg/admission is CRDT-agnostic: it imports ONLY the standard library.
// It does NOT import pkg/sync (so it never touches the frozen crdt.go),
// does NOT import pkg/identity, and does NOT import circl. The bucket
// keys on [32]byte — the canonical copy of a 32-byte Ed25519 public key
// — because circl's ed25519.PublicKey is `type PublicKey []byte`
// (pubkey112.go:7), a Go slice, and slices are non-comparable and
// CANNOT be map keys ("invalid map key type"). The roadmap wording
// "map[ed25519.PublicKey]*PeerEWMA" is a compile error and is superseded
// by PeerBucketKey = [32]byte here.
package admission

import (
	"math"
	"sync"
)

// PeerBucketKey is the canonical, comparable copy of a 32-byte Ed25519
// public key. circl's ed25519.PublicKey is `type PublicKey []byte`
// (pubkey112.go:7); ed25519.PublicKeySize == 32 (ed25519.go:56). Go
// slices are non-comparable, so `map[ed25519.PublicKey]X` does NOT
// compile — the compiler rejects it with "invalid map key type". The
// bucket therefore keys on the fixed-size [32]byte array, copied once
// from the inbound []byte pubkey. This is the load-bearing key-type
// decision; the compile-time guard (TestPeerBucket_KeyIsArray32Byte)
// and the negative-compile guard (peer_key_slice_probe) detector-ban
// the slice-key pattern from this package's source identity.
type PeerBucketKey [32]byte

// ewmaAlpha is the exponential moving average decay factor for the
// per-peer inbound Counter-delta rate. alpha = 0.1 matches the engine's
// own per-ENGINE EWMA at crdt.go:1674 (observedInboundRateBits update
// inside AdvanceLamportTo: next = alpha*prev + (1-alpha)*sample). 3.1's
// EWMA is a NEW, SEPARATE, PER-PEER structure — it does NOT touch
// observedInboundRateBits and does NOT call AdvanceLamportTo (the
// forbidden-symbol guard, TestPeerBucket_ForbiddenSymbolsAbsent,
// detector-bans both identifiers from this package's source).
const ewmaAlpha = 0.1

// initialBudget is the token budget a fresh PeerEWMA starts with. It is
// the per-peer admission allowance before any rate deduction. A peer
// whose cumulative Counter-delta drain stays under this budget is Keep;
// once the drain reaches it, subsequent Accept calls return Drop until
// the bucket is replenished (out of scope here — the transport
// wires the refill on connection lifecycle).
//
// Sized so the acceptance test drains a MaxUint64-ratchet attacker in a
// bounded small constant of admits: a single delta of math.MaxUint64
// exceeds the budget, so the attacker's FIRST ratchet admit drops.
const initialBudget uint64 = 1 << 20 // ~1M token units

// FrameDecision is the transport-layer drop verdict. 3.1 ships the
// decision; the real EAGAIN-at-TCP-layer wiring (syscall.EAGAIN /
// net.OpError) lands in (epoll + SO_ATTACH_REUSEPORT_EBPF,
// roadmap line 50 — NOT yet shipped). 3.1 does NOT fabricate the kernel
// path: it returns Drop and the transport seam will call
// EAGAIN at the socket once the kernel path exists.
type FrameDecision int

const (
	// Keep means the frame's per-peer rate is within budget; the
	// transport layer forwards it to the next gate (3.0 clock cap).
	Keep FrameDecision = iota
	// Drop means the frame's per-peer rate has exhausted the bucket;
	// the transport layer drops it at the TCP layer (EAGAIN).
	Drop
)

// PeerEWMA is the per-identity token bucket. It tracks an EWMA of the
// inbound Counter-DELTA (the per-frame DotCounter advancement, NOT the
// absolute Counter — the delta is what a Sybil ratchets) and a remaining
// token budget. It is guarded by its shard's mutex; it is never accessed
// outside its owning shard.
//
// The Counter-delta is the per-frame advancement the transport layer
// extracts from the wire frame before calling Accept. 3.1 does NOT
// import pkg/sync for CRDTEntry.Dot() (hamt.go:44); it accepts the raw
// uint64 delta to keep pkg/admission CRDT-agnostic and avoid the
// import-direction entanglement the engagement forbids (3.0 already
// imports pkg/sync; 3.1 must NOT).
type PeerEWMA struct {
	// rate is the EWMA of the inbound Counter-delta, stored as the
	// IEEE-754 bits of a float64 (mirrors crdt.go:207's
	// observedInboundRateBits atomic.Uint64-of-bits pattern, but in a
	// NEW per-peer field — NOT the engine's field). Held under the
	// shard mutex, so it is a plain uint64, not atomic.
	rate uint64

	// budget is the remaining token allowance. Each Accept deducts the
	// observed delta; when budget reaches 0 the next Accept returns Drop.
	// Held under the shard mutex.
	budget uint64

	// lastCounter is the peer's previously observed DotCounter. The
	// per-frame Counter-delta is counter - lastCounter (0 on first sight
	// and on non-monotonic replay). Held under the shard mutex.
	lastCounter uint64
}

// shardCount is the number of PeerBucket shards. 16 shards keyed by the
// low 4 bits of the pubkey gives 4× the realistic GOMAXPROCS (the storm
// peak is 32 cores; 16 shards lets 16 distinct peers proceed with zero
// cross-shard contention). A single sync.Mutex around the whole map would
// serialize all 32 peers and FAIL the Sybil-isolation intent;
// sharding makes isolation structural — the attacker's shard is the only
// one it can saturate.
const shardCount = 16

// shardMask selects the low 4 bits (log2(16) == 4).
const shardMask = shardCount - 1

// shard holds a shard of the per-peer bucket map. Each shard has its own
// sync.Mutex, so two peers hashing to different shards never contend.
type shard struct {
	mu sync.Mutex
	m  map[PeerBucketKey]*PeerEWMA
}

// PeerBucket is the per-peer Sybil-burst isolation token bucket. It is
// a sharded map of PeerEWMA keyed by the canonical [32]byte pubkey. The
// Accept path is: zero-alloc length check (reject len != 32 BEFORE the
// bucket lookup), one [32]byte copy, shard select on the low 4 bits,
// shard-lock, map lookup (lazy-create on first sight), EWMA update +
// budget deduction, verdict. The whole hot path is a single map lookup
// and a handful of arithmetic ops under a per-shard mutex.
type PeerBucket struct {
	shards [shardCount]shard
}

// NewPeerBucket returns a ready PeerBucket with all shard maps
// initialized.
func NewPeerBucket() *PeerBucket {
	b := &PeerBucket{}
	for i := range b.shards {
		b.shards[i].m = make(map[PeerBucketKey]*PeerEWMA)
	}
	return b
}

// shardIndex returns the shard index for a 32-byte pubkey. It uses the
// low 4 bits of the first byte. The low bits of an Ed25519 public key
// are a uniform field (the key is a uniformly random curve point
// encoding), so the low-4-bit shard distribution is uniform across
// honest peers; an attacker cannot target a single shard to amplify
// contention without also randomizing its key (which just spreads it
// across shards, preserving isolation).
func shardIndex(k PeerBucketKey) int {
	return int(k[0]) & shardMask
}

// Accept applies the per-peer rate cap to an inbound frame. pub is the
// 32-byte Ed25519 public key; counter is the frame's DotCounter value.
// It returns Keep if the peer's rate is within budget, Drop if the peer
// has exhausted its bucket.
//
// The verdict is computed from the Counter-DELTA between this Accept
// and the peer's previous observed Counter (per the design contract:
// "exponential moving average... token bucket deduction"). A peer's Counter is
// monotonic; the delta is the per-frame advancement. A Sybil that
// ratchets Counter by MaxUint64-equivalent deltas produces a huge delta
// that drains its own bucket in bounded admits, while honest peers
// submitting modest deltas keep their separate buckets intact.
//
// pub of len != 32 is REJECTED before the bucket lookup (a zero-alloc
// length check): a short/long pubkey cannot be a valid Ed25519 key
// (ed25519.PublicKeySize == 32) and MUST NOT silently truncate into the
// [32]byte key (the copy-length guard, TestPeerBucket_RejectShortPub /
// TestPeerBucket_RejectLongPub).
func (b *PeerBucket) Accept(pub []byte, counter uint64) FrameDecision {
	// Zero-alloc length check BEFORE the bucket lookup. A pub of len !=
	// 32 is not a valid Ed25519 key and is rejected without touching any
	// shard map (no map growth, no allocation, no silent truncation).
	if len(pub) != 32 {
		return Drop
	}

	// Copy the 32-byte pubkey into the canonical [32]byte key ONCE.
	var k PeerBucketKey
	copy(k[:], pub)

	s := &b.shards[shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()

	peer := s.m[k]
	if peer == nil {
		peer = &PeerEWMA{budget: initialBudget}
		s.m[k] = peer
	}

	// Derive the per-frame Counter-delta from the HIGH-WATER MARK. The first
	// observation for a peer has no prior, so its delta is the counter itself;
	// subsequent observations charge only NEW advancement.
	//
	// ── THE HIGH-WATER-MARK DISCIPLINE ───────────────────────────
	// THE BUG THIS REPLACES (found on silicon): the earlier code wrote
	// `peer.lastCounter = counter` UNCONDITIONALLY, so a NON-MONOTONIC arrival
	// REWOUND the high-water mark and the next fresh counter re-drained a gap the
	// origin had ALREADY paid for — sawtooth amplification. That was harmless while
	// every origin's counters arrived monotonically (one sender per origin), and it
	// became fatal once the batch relay was wired: 34 relayers began
	// interleaving ONE origin's old and new OriginSeqs into ONE origin-keyed bucket.
	// Measured consequence — the 1<<20 budget died in ~10 seconds on EVERY node,
	// including the seed's own bucket (fed by reflected relays of its own batches):
	// node-0 (SEED) 77,838 Drop / 5,945 Accept; node-34-eu 72,831 / 4,442.
	// All of node-34's accepts fell inside ONE 10-second window, then ZERO accepts
	// for the remaining 72 seconds — permanent admission death, not throttling. The
	// second defect compounded it: `delta >= peer.budget` at budget==0 is satisfied
	// by delta==0, so even ALREADY-SEEN frames dropped forever.
	//
	// THE INVARIANT THIS DISCIPLINE ESTABLISHES: the high-water mark NEVER rewinds, and ONLY a
	// Keep advances it. Every case is tabulated in ADR-0045's block
	// (fresh origin / monotonic advance / duplicate / replay / MaxUint64 ratchet /
	// gap-over-budget), OLD behavior vs NEW, because this is a Byzantine-defense
	// seam and a silent edit here would falsify the defense.
	//
	// THE SYBIL BOUND IS UNCHANGED: total ACCEPTED advancement per origin stays
	// <= initialBudget. The discipline removes DOUBLE-CHARGING for the same advancement; it
	// does not raise the ceiling.
	prev := peer.lastCounter
	var delta uint64
	if counter > prev {
		delta = counter - prev
	}

	// DUPLICATE / REPLAY (delta == 0, i.e. counter <= the high-water mark) → Keep
	// IMMEDIATELY: no budget touch, no lastCounter write, no EWMA sample. A frame
	// that advances the origin's sequence by NOTHING costs the origin nothing, so
	// dropping it buys ZERO Sybil protection while costing convergence (it was the
	// permanent-death half of the collapse). Join is idempotent, so an
	// admitted duplicate is bounded work: verify + idempotent apply. Frame-rate
	// flooding was NEVER this gate's job — that is transport backpressure
	//untouched by this change.
	if delta == 0 {
		return Keep
	}

	// EWMA of the inbound Counter-delta, alpha = 0.1 (matches crdt.go:1674).
	// next = alpha*prev + (1-alpha)*sample. Stored as IEEE-754 bits. Unchanged
	// form, now fed only by real advancements; its only consumer is the Rate()
	// accessor, and relayed duplicates no longer sample it (disclosed in the ADR,
	// not redesigned).
	prevRate := math.Float64frombits(peer.rate)
	nextRate := ewmaAlpha*prevRate + (1-ewmaAlpha)*float64(delta)
	peer.rate = math.Float64bits(nextRate)

	// GAP LARGER THAN THE REMAINING BUDGET → Drop, and:
	// (a) do NOT advance lastCounter. If a DROPPED frame advanced the high-water
	// mark, one MaxUint64 ratchet would set the HWM to MaxUint64 and every
	// later frame would be delta-0 → Keep — the attacker converting a single
	// dropped frame into a PERMANENT ADMISSION BYPASS, strictly worse than the
	// sawtooth. Guard R4 (TestRatchetDoesNotAdvanceHWM) exists
	// to make that impossible.
	// (b) do NOT zero the budget. A legitimate origin that jumps a gap larger than
	// its remainder (e.g. rejoining after a partition) keeps admitting later
	// small advances; zeroing turned one large gap into a death sentence. The
	// Sybil bound is identical either way — an UNACCEPTED frame was never
	// charged, so refusing to zero cannot widen the accepted-advancement
	// ceiling.
	// The MaxUint64 ratchet still Drops on its first admit (MaxUint64-prev >= 1<<20)
	// and on every subsequent one: the Byzantine acceptance contract is preserved.
	if delta >= peer.budget {
		return Drop
	}

	// KEEP: charge the real advancement and advance the high-water mark. This is
	// the ONLY site that writes peer.lastCounter.
	peer.budget -= delta
	peer.lastCounter = counter
	return Keep
}

// Budget returns the remaining token budget for a peer's bucket. It is
// a test-only accessor (no production caller); it takes the shard lock
// to read consistently. Not on the hot path.
func (b *PeerBucket) Budget(pub []byte) uint64 {
	if len(pub) != 32 {
		return 0
	}
	var k PeerBucketKey
	copy(k[:], pub)
	s := &b.shards[shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if peer := s.m[k]; peer != nil {
		return peer.budget
	}
	return 0
}

// Rate returns the EWMA of the inbound Counter-delta for a peer. Test-
// only accessor; takes the shard lock.
func (b *PeerBucket) Rate(pub []byte) float64 {
	if len(pub) != 32 {
		return 0
	}
	var k PeerBucketKey
	copy(k[:], pub)
	s := &b.shards[shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if peer := s.m[k]; peer != nil {
		return math.Float64frombits(peer.rate)
	}
	return 0
}
