// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"encoding/binary"
	"fmt"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// V2 reconciliation bounds its IBLT digest sizes and reads the requested size
// directly from the request header. DeliverDigest and respondToDigest gate and
// build responses; generateSweepDelta maintains the per-peer sizing state.
//
// The sizing ladder uses observed peel outcomes instead of a difference
// estimate. A fixed 51,789-byte StrataEstimator can exceed the digest it sizes,
// and DynamicIBLTSize's 1.5x margin is below the approximately 2.8x margin used
// in the literature. The ladder starts at 1,024 buckets, doubles after
// delta.PeelErr reports an incomplete peel, and halves after a configurable
// streak of clean peels. ClampIBLTBuckets already accepts every size it can
// choose: the floor is eng.IBLTDigestDefaultBuckets and the ceiling is
// eng.MaxArenaIBLTBuckets (21,845).
//
// With --defer-handler disabled (the default), a failed peel sends the full
// keyset and resynchronizes the peer, erasing the large difference that caused
// escalation. The ladder therefore mainly bounds steady-state digest sizes in
// that configuration. The defer handler retains the large-difference state over
// multiple rounds, allowing the ladder to adapt while limiting oversend.
//
// Only the SweepLoop goroutine accesses the ladder map, including eviction, so
// it needs neither a mutex nor atomics. Responders take their size from each
// request rather than reading this map. The ibltV2 flag is atomic because read
// loops and responder goroutines also read it, and mixed-mode tests change it
// while a harness is running.

// ladderCleanStreak is the decay hysteresis: a peer's bucket count halves only
// after this many consecutive clean peels. Near the peelable-size boundary, the
// resulting clean/decay/fail/escalate cycle costs about one oversend per 2x
// streak exchanges.
const ladderCleanStreak = 4

// digestLadderState holds one peer's adaptive sizing state. Only the sweep
// goroutine accesses it, and its two integer fields contain no pointers.
type digestLadderState struct {
	buckets     int
	cleanStreak int
}

// SetIBLTV2 sets the mesh's mirror of the process-global digest scheme. main.go
// calls it from --iblt-v2 immediately after eng.SetIBLTSchemeV2 and before the
// first sweep. Placement and encoding remain in pkg/sync under eng.IBLTSchemeV2;
// this local atomic controls the request role, responder gate, and sizing ladder
// without a cross-package call on the frame path. The default false value keeps
// the v1 exchange unchanged.
func (g *Gossiper) SetIBLTV2(v2 bool) {
	g.ibltV2.Store(v2)
	if v2 && g.digestLadder == nil {
		// The setter runs before the first sweep, so every later ladder write
		// finds an initialized map.
		g.digestLadder = make(map[[16]byte]digestLadderState)
	}
}

// SetIBLTV2MinBuckets configures the starting and decay floor for the v2 IBLT
// ladder from --iblt-v2-min-buckets. Zero selects the legacy default of 1,024.
// Positive values are clamped to [eng.IBLTDigestDefaultBuckets,
// eng.MaxArenaIBLTBuckets].
func (g *Gossiper) SetIBLTV2MinBuckets(b int) {
	if b <= 0 {
		g.ibltV2MinBuckets.Store(0)
		return
	}
	clamped := eng.ClampIBLTBuckets(b)
	if clamped < eng.IBLTDigestDefaultBuckets {
		clamped = eng.IBLTDigestDefaultBuckets
	}
	g.ibltV2MinBuckets.Store(int32(clamped))
}

// IBLTV2MinBuckets returns the configured v2 minimum bucket floor (0 when unset).
func (g *Gossiper) IBLTV2MinBuckets() int {
	return int(g.ibltV2MinBuckets.Load())
}

// ibltV2Floor returns eng.IBLTDigestDefaultBuckets when the configured minimum
// is at or below 1,024, and otherwise returns the configured floor.
func (g *Gossiper) ibltV2Floor() int {
	b := int(g.ibltV2MinBuckets.Load())
	if b <= eng.IBLTDigestDefaultBuckets {
		return eng.IBLTDigestDefaultBuckets
	}
	return b
}

// digestBucketsFor returns the bucket count for this peer's request digest.
// With v2 disabled it returns the legacy default without touching ladder state,
// leaving request bytes unchanged. With v2 enabled it returns the peer's ladder
// size, or the effective floor before the peer has an entry.
func (g *Gossiper) digestBucketsFor(peerID [16]byte) int {
	if !g.ibltV2.Load() {
		return eng.IBLTDigestDefaultBuckets
	}
	floor := g.ibltV2Floor()
	if st, ok := g.digestLadder[peerID]; ok && st.buckets >= floor {
		return st.buckets
	}
	return floor
}

// ladderEscalate doubles a peer's bucket count after an observed peel failure,
// reaching the arena ceiling from the default floor in at most about 4.4
// doublings. Only the sweep goroutine calls it, from the digestPeelOversends
// branch of generateSweepDelta.
//
// A DiffNil indicates a configuration mismatch in size, hash count, or scheme,
// not a digest that was too small, so it must not trigger escalation. V2 peers
// use matching sizes because the responder adopts the request's count and
// GenerateDelta adopts the response's count. At eng.MaxArenaIBLTBuckets this
// method only records the peer at the ceiling; larger differences require a
// reconciliation mechanism beyond this bounded IBLT ladder.
func (g *Gossiper) ladderEscalate(peerID [16]byte) {
	floor := g.ibltV2Floor()
	st := g.digestLadder[peerID] // zero-value when absent: buckets=0 → coerced below
	if st.buckets < floor {
		st.buckets = floor
	}
	if st.buckets >= eng.MaxArenaIBLTBuckets {
		g.digestLadder[peerID] = st // record the peer at the ceiling
		return
	}
	st.buckets *= 2
	if st.buckets > eng.MaxArenaIBLTBuckets {
		st.buckets = eng.MaxArenaIBLTBuckets
	}
	st.cleanStreak = 0
	g.digestLadder[peerID] = st
	g.digestLadderEscalations.Add(1)
}

// ladderCleanPeel records one consecutive clean peel and halves the peer's
// bucket count at the hysteresis threshold, down to the effective v2 floor.
// This lets the digest shrink as the peers' difference shrinks. Only the sweep
// goroutine calls it. A peer with no ladder entry has nothing to decay.
func (g *Gossiper) ladderCleanPeel(peerID [16]byte) {
	floor := g.ibltV2Floor()
	st, ok := g.digestLadder[peerID]
	if !ok {
		return
	}
	if st.buckets <= floor {
		return
	}
	st.cleanStreak++
	if st.cleanStreak >= ladderCleanStreak {
		st.buckets /= 2
		if st.buckets < floor {
			st.buckets = floor
		}
		st.cleanStreak = 0
		g.digestLadderDecays.Add(1)
	}
	g.digestLadder[peerID] = st
}

// evictStaleLadder bounds the map by the live peer set rather than by every
// peer ever seen. It runs beside evictStaleDigestRecv on the sweep goroutine,
// so unlike peerRoots it needs no mutex.
func (g *Gossiper) evictStaleLadder() {
	if g.digestLadder == nil || len(g.digestLadder) == 0 || g.peers == nil {
		return
	}
	for id := range g.digestLadder {
		if !g.peers.isLive(id) {
			delete(g.digestLadder, id)
		}
	}
}

// digestRequestBuckets reads the v2 IBLT body's eight-byte header: four bytes
// of little-endian scheme magic followed by a little-endian bucket count. This
// is the IBLT wire layout, not the digest frame header's big-endian layout.
// Truncated, absent, and non-v2 bodies return ok=false, so the responder avoids
// an O(S) digest build and the requester eventually uses its oversend fallback.
// GenerateDigestSizedWithSeed clamps the returned count to [128, 21845] before
// allocating arena storage; an excessive count therefore remains bounded.
//
// buildV2DigestRequestBody constructs that header for a digestRoleRequestV2
// (0x11) frame. DeliverDigest reads only these eight bytes and never unmarshals
// request buckets. The requester rebuilds its local IBLT when the response
// arrives. Sending the header instead of the table reduces this request from
// 436,963 bytes to 53 bytes including the length prefix.
func buildV2DigestRequestBody(numBuckets int) []byte {
	clamped := eng.ClampIBLTBuckets(numBuckets)
	var body [8]byte
	binary.LittleEndian.PutUint32(body[0:4], eng.IBLTWireMagicV2)
	binary.LittleEndian.PutUint32(body[4:8], uint32(clamped))
	return body[:]
}

func digestRequestBuckets(frame []byte) (numBuckets uint32, ok bool) {
	_, ibltBody := digestFrameSplit(frame)
	if len(ibltBody) < 8 {
		return 0, false
	}
	if binary.LittleEndian.Uint32(ibltBody[0:4]) != eng.IBLTWireMagicV2 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(ibltBody[4:8]), true
}

// iblt2SweepSuffix appends v2 sizing metrics to the sweep line without adding
// registry counters. iblt2_b reports the current per-peer bucket range,
// iblt2_esc and iblt2_dec report escalations and decays, and iblt2_snap reports
// stable-cut snapshot restarts from eng.DigestSnapshotRestarts. Snapshot
// restarts can occur on the sweep goroutine or any responder goroutine.
//
// The suffix is empty unless both v2 and stratified anti-entropy are enabled,
// leaving other sweep lines unchanged. SweepLoop calls this method on the same
// goroutine that owns the ladder map.
func (g *Gossiper) iblt2SweepSuffix() string {
	if !g.ibltV2.Load() || !g.stratified {
		return ""
	}
	lo, hi := 0, 0
	for _, st := range g.digestLadder {
		if lo == 0 || st.buckets < lo {
			lo = st.buckets
		}
		if st.buckets > hi {
			hi = st.buckets
		}
	}
	if lo == 0 {
		floor := g.ibltV2Floor()
		lo = floor
		hi = floor
	}
	return fmt.Sprintf(" iblt2_b=%d/%d iblt2_esc=%d iblt2_dec=%d iblt2_snap=%d",
		lo, hi, g.digestLadderEscalations.Load(), g.digestLadderDecays.Load(), eng.DigestSnapshotRestarts())
}
