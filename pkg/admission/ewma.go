// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package admission implements per-identity sequence-advance budgets for
// inbound frames. PeerBucket rejects excessive advancement for one identity
// without consuming the budgets of other identities. The receive path calls
// Accept before its clock and signature checks, so rejected frames avoid
// signature verification.
//
// A relayed frame crosses the gates in this order:
//
//	[wire] -> PeerBucket.Accept(pub, counter)
//	       -> if Keep: IngressHLCScalarCap.Admit
//	       -> if admitted: RelayEnvelope.Open
//	       -> if authenticated: PeerBucket.CommitHWM
//	       -> origin verification and CRDT merge
//
// The package depends only on the standard library. Accept receives the
// sequence counter as a uint64 and copies the 32-byte identity into a
// comparable [32]byte map key. This avoids importing the CRDT or identity
// packages; circl's Ed25519 public-key type is a slice and cannot be a map key.
package admission

import (
	"math"
	"sync"
	"sync/atomic"
)

// PeerBucketKey is the comparable form of a 32-byte peer identity. Accept
// copies the supplied bytes into this array before the map lookup. A circl
// Ed25519 public key cannot be used directly because its underlying type is
// a slice, and Go slices are not comparable. TestPeerBucket_KeyIsArray32Byte
// checks the array type; the peer_key_slice_probe build tag retains the
// complementary negative compilation test.
type PeerBucketKey [32]byte

// ewmaAlpha is the decay factor for each peer's inbound counter-delta EWMA.
// Its value and update formula match the engine-wide inbound-rate average,
// but this state is independent and does not call AdvanceLamportTo.
// TestPeerBucket_ForbiddenSymbolsAbsent checks that the admission package
// does not reference the engine's private rate fields.
const ewmaAlpha = 0.1

// initialBudget is a fresh peer's allowance in counter-advancement units.
// Accept rejects a positive delta greater than or equal to the remaining
// budget without charging it. Duplicates remain admissible, and Refund can
// restore an unattributed charge up to this allowance. There is no time-based
// replenishment, so a MaxUint64 delta always exceeds a fresh peer's budget.
const initialBudget uint64 = 1 << 20 // ~1M token units

// FrameDecision tells the receive path whether to continue processing a
// frame or reject it. This package returns the decision; it does not perform
// socket operations.
type FrameDecision int

const (
	// Keep permits the frame to proceed to the next receive gate.
	Keep FrameDecision = iota
	// Drop rejects a frame whose key length is invalid or whose positive
	// sequence advancement does not fit within the remaining budget.
	Drop
)

// PeerEWMA holds one identity's counter-delta average and remaining budget.
// Accept receives an absolute DotCounter or OriginSeq and computes its
// advancement from lastCounter, keeping this package independent of the CRDT
// representation. The owning shard's mutex guards every field.
type PeerEWMA struct {
	// rate stores the EWMA as the IEEE-754 bits of a float64. The shard
	// mutex makes an atomic field unnecessary.
	rate uint64

	// budget is the remaining counter-advancement allowance. A charging
	// Keep deducts delta; Refund can restore an unattributed charge.
	budget uint64

	// lastCounter is the highest counter committed after authentication.
	// A counter at or below it contributes zero new advancement.
	lastCounter uint64
}

// shardCount spreads identities across independently locked maps. Peers in
// different shards can proceed concurrently, while every operation for one
// identity uses the same mutex.
const shardCount = 16

// shardMask selects the low four bits used to choose a shard.
const shardMask = shardCount - 1

// shard protects one partition of the peer map.
type shard struct {
	mu sync.Mutex
	m  map[PeerBucketKey]*PeerEWMA
}

// PeerBucket maintains independent sequence-advance budgets in a sharded map.
// Accept rejects an invalid key length before the lookup, copies the key,
// selects its shard, and lazily creates the peer entry on first sight. After
// creation, a decision requires one locked map lookup and arithmetic.
type PeerBucket struct {
	shards [shardCount]shard

	// disablePendingHWMBugInject is a test-only fault switch. When true,
	// Accept writes lastCounter at charge time, recreating the attribution
	// bypass that CommitHWM prevents. Its zero value is false in production.
	// This cold field stays after the shard array; preserve the explicit
	// field order rather than applying automatic layout changes.
	disablePendingHWMBugInject atomic.Bool
}

// NewPeerBucket returns a PeerBucket with initialized shard maps, ready for
// concurrent use.
func NewPeerBucket() *PeerBucket {
	b := &PeerBucket{}
	for i := range b.shards {
		b.shards[i].m = make(map[PeerBucketKey]*PeerEWMA)
	}
	return b
}

// shardIndex uses the low four bits of the identity's first byte, avoiding a
// hash computation on the Accept path. Shard choice affects lock contention,
// not budget isolation: colliding identities still have separate entries.
func shardIndex(k PeerBucketKey) int {
	return int(k[0]) & shardMask
}

// Accept applies a per-identity sequence-advance budget. pub is a 32-byte
// identity key and counter is the frame's absolute DotCounter or OriginSeq.
// The method is safe for concurrent use.
//
// A malformed key returns (Drop, 0) without touching a shard map. For a valid
// key, Accept computes positive advancement from the committed watermark. A
// duplicate or replay returns (Keep, 0) without changing the budget, EWMA, or
// watermark. A positive delta updates the EWMA; if it is greater than or equal
// to the remaining budget, Accept returns (Drop, 0) without charging or
// committing it. Otherwise Accept deducts delta and returns (Keep, delta).
//
// The charged delta lets the caller Refund a frame rejected before its
// identity is authenticated. Accept normally leaves lastCounter unchanged;
// after authentication the caller commits the counter with CommitHWM.
func (b *PeerBucket) Accept(pub []byte, counter uint64) (FrameDecision, uint64) {
	// Reject malformed keys without allocating, truncating, or growing a map.
	if len(pub) != 32 {
		return Drop, 0
	}

	// Copy the identity into its comparable map-key form.
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

	// The first observation charges its absolute counter because lastCounter
	// starts at zero. Later observations charge only advancement beyond the
	// committed watermark. A replay must never rewrite that watermark: doing so
	// would charge the next fresh counter for a gap that was already paid for.
	// Independent relayers can produce exactly that non-monotonic arrival order.
	prev := peer.lastCounter
	var delta uint64
	if counter > prev {
		delta = counter - prev
	}

	// Duplicates and replays have no new advancement, so they Keep without
	// changing the budget, watermark, or EWMA. Join is idempotent, although the
	// caller still pays any applicable verification cost. Frame-rate
	// backpressure belongs to the transport rather than this sequence budget.
	if delta == 0 {
		return Keep, 0
	}

	// Sample each positive delta, including one subsequently rejected for
	// exceeding the budget. Duplicates return before this update. Rate exposes
	// the resulting EWMA for diagnostics and tests.
	prevRate := math.Float64frombits(peer.rate)
	nextRate := ewmaAlpha*prevRate + (1-ewmaAlpha)*float64(delta)
	peer.rate = math.Float64bits(nextRate)

	// An over-budget gap is uncharged and cannot commit its counter. Otherwise a
	// single rejected MaxUint64 counter would make every later frame a free
	// duplicate. Leaving the remaining budget intact also lets an origin recover
	// from a large gap with later affordable advances; rejecting a frame does not
	// consume the allowance it failed to use.
	//
	// The comparison is inclusive, so a delta exactly equal to the budget drops.
	if delta >= peer.budget {
		return Drop, 0
	}

	// Charge the advancement but leave its watermark pending. The receiver
	// either refunds an unattributed charge or calls CommitHWM after
	// authentication. Committing here would let an unauthenticated frame make
	// its next duplicate free. The test-only fault restores that unsafe write.
	peer.budget -= delta
	if b.disablePendingHWMBugInject.Load() {
		peer.lastCounter = counter // test-only charge-time watermark fault
	}
	return Keep, delta
}

// Refund returns a delta previously charged by Accept to a known identity.
// Relayed frames refund clock, depth, and relay-envelope failures before the
// relay is authenticated. Batch frames refund directory and origin-signature
// failures before the origin is authenticated. Rejections after the relevant
// authentication point keep the charge.
//
// The refund is capped at initialBudget. It never rolls back lastCounter: a
// conditional rollback would be unsafe with interleaved frames, and committed
// watermarks move only forward. A malformed key, zero delta, or unknown
// identity is a no-op. Refund takes the shard lock and does not allocate.
func (b *PeerBucket) Refund(pub []byte, delta uint64) {
	if len(pub) != 32 || delta == 0 {
		return
	}
	var k PeerBucketKey
	copy(k[:], pub)
	s := &b.shards[shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := s.m[k]
	if peer == nil {
		return // unknown identity: nothing was charged
	}
	peer.budget = min(peer.budget+delta, initialBudget)
}

// CommitHWM advances an identity's watermark after authentication. The
// receive path calls it for a positive charge returned by Accept, after the
// relay envelope, batch signature, or hybrid batch signature has verified.
// Free duplicates need no commit.
//
// The update is max(lastCounter, counter) under the shard lock, so concurrent
// commits cannot move the watermark backward. Two duplicates can both charge
// before either commits; authenticated duplicates are not refunded, so this
// conservatively charges the verified work. That excess is bounded by the
// number of in-flight duplicates. CommitHWM does not allocate.
func (b *PeerBucket) CommitHWM(pub []byte, counter uint64) {
	if len(pub) != 32 {
		return
	}
	var k PeerBucketKey
	copy(k[:], pub)
	s := &b.shards[shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := s.m[k]
	if peer == nil {
		return // unreachable behind the caller's charged>0 gate; defensive
	}
	if counter > peer.lastCounter {
		peer.lastCounter = counter
	}
}

// Budget returns an identity's remaining counter-advancement allowance. It
// takes the shard lock for a consistent read. The receiver uses it in
// rate-drop diagnostics; tests also use it to observe charging and refunds.
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

// Rate returns an identity's EWMA of positive counter deltas. It takes the
// shard lock and is used by tests; a missing or malformed key returns zero.
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
