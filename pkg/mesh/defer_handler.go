// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The defer handler bounds recovery from digest-exchange failures
// (ADR-0062/0063). A timeout, peel failure, malformed or nil digest, Publish
// failure, IBLT marshal failure, or test-only legacy-SE marshal failure defers
// the peer instead of shipping the full keyset. After deferEscalationRounds
// consecutive failures, subsequent failing rounds ship bounded rotating slices
// of the local keyset.
//
// Repeated full-keyset fallback has cascade gain A = S/|Δ|. At the 10,000-key
// shape, the measured result was 5,872,751 entries sent over 690 dumps.
//
// ADR-0071 adds one exception behind --defer-crossover. An ErrIncompletePeel
// failure may ship the full keyset once per divergence episode when the keyset
// is within deferCrossoverMaxEntries. A once-marker and cooldown bound repeats;
// every other failure class continues to use the defer path.
//
// Fixed hash buckets are not sufficient for this bound. Choosing buckets by
// FNV(entityID)%nb with nb = ceil(S_bytes/B_defer) puts the mean at the byte
// cap, so a hard cap truncates some bucket tails. At 10,000 keys,
// Binomial(10,000, 1/17) gives P(bucket>608)≈20%; repeating the same walk-order
// prefix then starves the tail. Removing the cap loses the byte bound.
//
// The ring window provides both properties. Consecutive hash-anchored windows
// tile the 2^64 ring, while the walk stops at deferSliceMaxEntries. An entry's
// fnv64Entity position is fixed across iteration orders and inserts. The offset
// advances only when the round ends with a live context and no peer-Publish
// failures, so a breaker-held peer cannot consume rotations. A round with only
// local skips still advances: relay misses, orphans, and pending entries cannot
// ship from this window, and parking on them would starve the remaining ring.
//
// Each escalation round walks O(S) entries and ships about 11× less than the
// full-keyset walk it replaces. Timeout, malformed-digest, and marshal-failure
// rounds build a full GenerateDelta slice source; other rounds avoid that
// failure-path build, and the per-exchange digest build is unchanged. A peel
// failure already has a full-keyset delta from crdt.go's yield-everything path.
//
// The true diff is unavailable on these failure paths, so each slice is a
// superset. Merge-union Join still converges. Coverage is exact for a quiesced
// keyset; coverage during mutation is established only at the tested scale and
// does not support a larger-fleet wall-clock claim.

import (
	"log"
	"math"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// deferEscalationRounds is the number of consecutive non-gated failures before
// bounded slices begin. Keeping it small limits defer starvation; measured
// convergence takes at most three rounds in the target shape. Once armed, every
// subsequent failing round ships the next slice, about 608 entries per round
// and 17 rounds at 10,000 keys.
const deferEscalationRounds = 3

// deferSliceMaxEntries caps each peer's escalation slice at
// B_defer/s_entry = 82,124/135, approximately 608 entries. B_defer is twice
// the 41,062-byte digest round trip, and the 135-byte entry size is a WAL proxy
// with roughly a factor-of-two uncertainty.
const deferSliceMaxEntries = 608

// deferAlarmLogCap bounds diverged-pair alarm lines per sweep so a persistent
// divergence cannot flood the log.
const deferAlarmLogCap = 8

// deferWindowWidthEntries targets two thirds of the hard cap. At 10,000 keys,
// this gives E[K]=405 with sigma≈20, so exceeding 608 requires a greater than
// 10-sigma density anomaly. Normal rounds ship the entire window and advance by
// W, producing exact ceil(S/405) rotation coverage; the hard cap remains a
// guard for unusual hash distributions.
//
// Sizing W at the full cap made truncation routine. Because HAMT walk order is
// independent of hash order, capped entries could wait a full rotation: one run
// still had 100 missing keys at round 50 and advanced only about 0.62×W per
// round. The expected 405 entries use 54.7 KB at the 135-byte WAL proxy, below
// the 82,124-byte budget.
const deferWindowWidthEntries = (deferSliceMaxEntries * 2) / 3

// deferCrossoverMaxEntries is the largest local keyset that an
// ErrIncompletePeel failure may ship once per divergence episode (ADR-0071).
// The 30-node full-mesh measurement gives a per-pair wire cost of about
// 118,266,395/(10,000×29) = 408 bytes per entry, or 4.08 MB for one 10,000-key
// ship. The 20,000-entry bound keeps that one ship within twice the measured
// per-pair budget of the convergent 1,000-node baseline.
//
// The capacity class implies a true diff of at least about 750 entries: the
// ADR-0034 probe peels 750 and oversends at 800. A_max is therefore about
// 20,000/750 = 27. The once-marker and cooldown prevent the repeated fallback
// that previously sent about 8,511 entries per dump across 332 peers each sweep.
const deferCrossoverMaxEntries = 20000

// deferCrossoverCooldown delays another crossover after a failed publish. With
// f=8 of 332 eligible intra-region peers, a pair meets every 41.5 rounds; at
// the measured 3–5 seconds per round, that is 124.5–207.5 seconds. The 180-second
// cooldown skips the next likely meeting and gives the defer ladder time to run.
const deferCrossoverCooldown = 180 * time.Second

// deferClass identifies the failure that deferred a peer. A responder drop is
// observed by the requester as a timeout when its digest wait expires.
type deferClass uint8

const (
	deferClassTimeout     deferClass = iota // digest wait expired
	deferClassNilDigest                     // malformed or nil digest
	deferClassIBLTMarshal                   // IBLT marshal failure
	deferClassSEMarshal                     // test-only legacy-SE marshal fault injection
	deferClassPublish                       // Publish failed; write recovery owns retry
	deferClassPeel                          // completed exchange failed to peel
)

// deferClassCount is the number of classes in the per-class accounting window.
const deferClassCount = int(deferClassPeel) + 1

// peerDeferState holds one live peer's defer state by value, avoiding a
// per-operation allocation. The sweep goroutine reads, updates, and stores each
// value without a mutex; tests inspect it only between sweeps. evictStaleDefers
// removes state only for peers no longer in PeerSet. Evicting a live peer would
// reset ringOffset and repeatedly ship the same slice.
type peerDeferState struct {
	// lastDeferAt records the latest noteDeferTrigger call. Gateway selection
	// treats a recent timeout or publish streak as unhealthy for 15 seconds,
	// then restores the gateway when the window expires or resetDeferPeer runs.
	// The time fields lead the struct so their location pointers share the
	// leading pointer prefix with no alignment waste.
	lastDeferAt time.Time
	// crossoverAt is the failed-ship timestamp anchor (zero = no failed
	// ship): the cooldown gate reads time.Since(crossoverAt) against
	// deferCrossoverCooldown. Cleared with the marker on the clean digest.
	crossoverAt time.Time
	// consecutive counts non-gated failing rounds since the last clean peel.
	// A change-gate skip neither increments nor resets it; only a clean-peel
	// exchange resets it.
	consecutive int
	// sEst is the local keyset count from the last windowed walk and determines
	// window width. Zero means no walk has run: the next escalation round counts
	// without shipping so the first slice is hash-anchored like every later one.
	sEst int
	// ringOffset is the hash-ring window start. finalizeDeferShip advances it
	// only when pubErrs==0 and the context is live. Failed publishes park the
	// window for retry; rounds containing only local skips still advance so
	// unshippable entries cannot starve the rest of the ring.
	ringOffset uint64
	// walkedCount / nextOffset are the per-round walk stash, written by
	// walkDeferWindow and applied by finalizeDeferShip.
	walkedCount int // entries observed on the last windowed walk (the sEst update)
	// nextOffset records the walk outcome for finalizeDeferShip. A capped round
	// stores lastHash, an exhausted window stores offset+W, and the defensive
	// park stores ringOffset. It applies only when pubErrs==0 on a live context,
	// including rounds that published nothing because every offer skipped locally.
	nextOffset uint64
	// lastClass is the most recent trigger, written by noteDeferTrigger on the
	// sweep goroutine. The alarm uses it to distinguish publish failures, which
	// ship no slice, from classes that escalate bounded slices.
	lastClass deferClass
	// shipWindow is armed by generateSweepDelta on an escalation round (a
	// slice ships this round); consumed + cleared by finalizeDeferShip
	// after the bounded ship.
	shipWindow bool
	// crossoverServed marks the full-keyset ship for this divergence episode.
	// resetDeferPeer clears it on the pair's next clean-peel digest, limiting
	// each episode to one crossover ship.
	crossoverServed bool
	// crossoverPend is the ship-in-flight marker: set at the crossover's
	// ship, consumed by finalizeDeferShip once the ship path knows
	// pubErrs. On any Publish failure the once-marker clears and
	// crossoverAt stamps (the cooldown arms); on a clean ship the marker
	// stays set until the next clean digest clears it.
	crossoverPend bool
}

// SetDeferHandler enables the defer handler. Both the sweep goroutine and the
// accept goroutine's malformed-digest branches read the plain bool, so callers
// must set it before Listen, the accept loops, and SweepLoop start. Changing it
// later can race those reads and the unsynchronized deferState map assignment.
// cmd/sovereign-node/main.go follows this initialization order.
//
// Disabled mode leaves deferState nil and every defer operation becomes a
// no-op. Enabling the handler without stratified anti-entropy is invalid:
// generateSweepDelta reaches every trigger only in its stratified branch, and
// the command wiring rejects a configuration that would otherwise continue to
// dump full keysets.
func (g *Gossiper) SetDeferHandler(on bool) {
	g.deferHandler = on
	if on && g.deferState == nil {
		g.deferState = make(map[[16]byte]peerDeferState)
	}
}

// noteDeferTrigger increments consecutive and digestDefers and records the
// failure in per-region diagnostics. It replaces noteStratFallback when the
// handler is enabled: StratifiedAntiEntropyFallback means oversend occurred,
// which is false on a deferred round.
//
// Every digest failure class increments the same counter. A change-gated round
// cannot reach this function. At consecutive >= deferEscalationRounds the next
// state arms shipWindow, except after a Publish failure: that round ships
// nothing while write deadlines and close-on-error handle connection recovery.
func (g *Gossiper) noteDeferTrigger(peerID [16]byte, class deferClass) {
	g.digestDefers.Add(1)
	ds := g.deferState[peerID]
	ds.consecutive++
	ds.lastClass = class
	ds.lastDeferAt = time.Now()
	if class != deferClassPublish && ds.consecutive >= deferEscalationRounds {
		ds.shipWindow = true
		g.digestDeferEscalations.Add(1)
	}
	g.deferState[peerID] = ds
	if d := g.stratDiag; d != nil {
		r := g.peerRegionTag(peerID)
		d.mu.Lock()
		d.fallback[r]++
		// Keep the per-class, per-region window under the existing mutex.
		// The peel-class test fault injection omits one increment to
		// verify that this accounting is observable.
		if !(class == deferClassPeel && l0iClassT2DropBugInject.Load()) {
			if d.fallbackByClass[class] == nil {
				d.fallbackByClass[class] = make(map[RegionTag]int64)
			}
			d.fallbackByClass[class][r]++
		}
		d.mu.Unlock()
	}
}

// deferSliceSource returns nil on a non-escalation defer or publish-failure
// round, releasing any completed-exchange delta first. On an escalation round
// it reuses a peel failure's full-keyset delta or builds one with GenerateDelta
// against an empty IBLT. Non-escalation rounds avoid that O(S) build; the normal
// per-exchange digest build is unchanged.
func (g *Gossiper) deferSliceSource(peerID [16]byte, completed *eng.CRDTDelta) *eng.CRDTDelta {
	ds, ok := g.deferState[peerID]
	if !ok || !ds.shipWindow {
		if completed != nil {
			completed.Release()
		}
		return nil
	}
	if completed != nil {
		return completed
	}
	emptyDigest := eng.NewIBLT(1, 4)
	return g.engine.GenerateDelta(emptyDigest)
}

// resetDeferPeer resets state after a clean peel. A peer that converges through
// another path becomes change-gated and retains its counter until the next clean
// peel. Healthy peers without a prior trigger do not gain map entries.
func (g *Gossiper) resetDeferPeer(peerID [16]byte) {
	ds, ok := g.deferState[peerID]
	if !ok {
		return
	}
	ds.consecutive = 0
	ds.lastDeferAt = time.Time{}
	// A clean peel ends the divergence episode, so the crossover marker and
	// cooldown anchor clear together before the next episode.
	ds.crossoverServed = false
	ds.crossoverAt = time.Time{}
	g.deferState[peerID] = ds
}

// gatewayDeferEvictionWindow bounds how long a timeout/publish deferral streak
// marks a foreign gateway unhealthy for gateway selection (15 seconds).
const gatewayDeferEvictionWindow = 15 * time.Second

// isGatewayPeerHealthy reports whether peerID is eligible for intra-sibling
// pinning and foreign gateway selection. With a non-nil PeerSet, the connection
// must be live and challenge-verified. A recent timeout or publish deferral
// streak makes the gateway unhealthy for 15 seconds.
func (g *Gossiper) isGatewayPeerHealthy(peerID [16]byte) bool {
	if g.peers != nil && (!g.peers.isLive(peerID) || !g.peers.egressVerified(peerID)) {
		return false
	}
	if g.deferHandler && g.deferState != nil {
		if st, ok := g.deferState[peerID]; ok && !st.lastDeferAt.IsZero() && time.Since(st.lastDeferAt) <= gatewayDeferEvictionWindow {
			if st.lastClass == deferClassPublish && st.consecutive >= 1 {
				return false
			}
			minTimeoutStrikes := 2
			if g.singleStrikeGatewayTimeoutBugInject.Load() {
				minTimeoutStrikes = 1
			}
			if st.lastClass == deferClassTimeout && st.consecutive >= minTimeoutStrikes {
				return false
			}
		}
	}
	return true
}

// SetDeferCrossover enables the saturation crossover in ADR-0071. Only
// ErrIncompletePeel with a local keyset within deferCrossoverMaxEntries is
// eligible; DiffNil and all other failure classes continue to the defer ladder.
// An eligible pair returns its existing delta for one full-keyset ship per
// divergence episode rather than adding another ship path.
//
// Crossover is disabled by default. Configure it before sweeps start, as with
// SetDeferHandler. The atomic prevents a torn read if a caller violates that
// order, and its Load runs only on the capacity-failure branch. The command
// wiring rejects --defer-crossover without --defer-handler.
func (g *Gossiper) SetDeferCrossover(on bool) {
	g.deferCrossover.Store(on)
}

// deferCrossoverTry checks eligibility on the sweep goroutine in marker,
// cooldown, then size order. The engine has no O(1) keyset count and
// SendKeyCount is zero after a peel failure, so sEst supplies the size. If it
// is unset, a zero-allocation walk counts the full-keyset delta once per pair
// and episode; even a rejected walk leaves sEst for the defer ladder.
//
// Success sets crossoverServed and crossoverPend and returns the ship size.
// The caller uses the existing oversend path. If publishing fails,
// finalizeDeferShip clears the once-marker and sets crossoverAt; the ladder
// handles retries until deferCrossoverCooldown expires.
func (g *Gossiper) deferCrossoverTry(peerID [16]byte, delta *eng.CRDTDelta) (int, bool) {
	ds, ok := g.deferState[peerID]
	if ok {
		if ds.crossoverServed {
			return 0, false
		}
		if !ds.crossoverAt.IsZero() && time.Since(ds.crossoverAt) < deferCrossoverCooldown {
			return 0, false
		}
	}
	s := 0
	if ok {
		s = ds.sEst
	}
	if s == 0 {
		// The in-round seed walk — paid once per pair per episode (the
		// stash below carries it), zero-alloc, never on the converged path.
		delta.Entries(func(string, eng.CRDTEntry) bool { s++; return true })
	}
	if s == 0 || s > deferCrossoverMaxEntries {
		if ok || s > 0 {
			ds.sEst = s
			g.deferState[peerID] = ds // the seed survives a reject: the ladder's count round is already paid
		}
		return 0, false
	}
	ds.crossoverServed = true
	ds.crossoverPend = true
	ds.sEst = s
	g.deferState[peerID] = ds
	return s, true
}

// deferWindowActive reports whether this round is an escalation round for
// this peer (generateSweepDelta armed the slice). Called by the ship paths
// on the sweep goroutine only.
func (g *Gossiper) deferWindowActive(peerID [16]byte) bool {
	ds, ok := g.deferState[peerID]
	return ok && ds.shipWindow
}

// anyDeferWindowArmed reports whether any peer has an armed escalation window
// (ADR-0069). The hoist must check this state rather than !deferHandler:
// SetDeferHandler(false) does not clear an already armed shipWindow, and the
// hoisted walk must not feed that stale window a constant-cost oracle or ship
// one peer's subset globally. It runs on the sweep goroutine that owns the map.
func (g *Gossiper) anyDeferWindowArmed() bool {
	for _, ds := range g.deferState {
		if ds.shipWindow {
			return true
		}
	}
	return false
}

// forEachShipEntry uses delta.Entries when the peer is not escalating and
// walkDeferWindow when it is. shipDelta and shipBatchedDelta both use this
// helper; otherwise the batched path at --batch-size=100 could bypass the bound
// and dump the full keyset. costOf is not called outside an escalation window.
//
// costOf reports received cost against the round's single budget: 1 for a self
// entry, the retained decoded element count for a foreign batch, and 0 for a
// relay miss or already-published batch. A nil oracle is valid only for the
// per-frame path, where one offered entry produces at most one received entry;
// every batch-shaped path must charge decoded batch elements.
//
// The walk pre-checks every offer against one deferSliceMaxEntries budget, so
// mixed self and foreign entries cannot exceed 608 received entries per peer
// per escalation round. Separate walk and ship-path caps could exceed that
// bound, and an unconditional foreign cap would also alter disabled mode.
func (g *Gossiper) forEachShipEntry(peerID [16]byte, delta *eng.CRDTDelta, costOf func(entityID string, entry eng.CRDTEntry) int, fn func(entityID string, entry eng.CRDTEntry) bool) {
	if !g.deferWindowActive(peerID) {
		delta.Entries(fn)
		return
	}
	g.walkDeferWindow(peerID, delta, costOf, fn)
}

// walkDeferWindow offers only entries in the peer's current hash-ring window
// and pre-checks their received cost against deferSliceMaxEntries. Self entries
// cost 1 and foreign entries cost their retained batch's decoded element count.
// W derives from sEst and targets deferWindowWidthEntries. If sEst is zero, the
// first escalation round counts without shipping so every slice is hash-anchored.
// finalizeDeferShip applies nextOffset only with no publish errors and a live context.
func (g *Gossiper) walkDeferWindow(peerID [16]byte, delta *eng.CRDTDelta, costOf func(entityID string, entry eng.CRDTEntry) int, fn func(entityID string, entry eng.CRDTEntry) bool) {
	ds, ok := g.deferState[peerID]
	if !ok {
		// deferWindowActive checked this entry immediately before on the same
		// goroutine. If that invariant is ever violated, do not fall back to a
		// plain walk, which would dump the full keyset. walkedCount stays zero
		// and the offset parks for the next escalation round.
		_ = delta
		return
	}
	if ds.sEst == 0 {
		// Before the first measured window, count the local keyset without
		// shipping or moving the offset. The next round starts at offset 0.
		walked := 0
		delta.Entries(func(string, eng.CRDTEntry) bool { walked++; return true })
		ds.walkedCount = walked
		ds.nextOffset = ds.ringOffset // unchanged (nothing published)
		g.deferState[peerID] = ds
		return
	}
	W := uint64(math.MaxUint64)
	if ds.sEst > deferSliceMaxEntries {
		W = (math.MaxUint64 / uint64(ds.sEst)) * uint64(deferWindowWidthEntries)
	}
	offset := ds.ringOffset
	cost := 0 // the round's received-cost accumulator (one budget)
	accepted := 0
	walked := 0
	capped := false
	var lastHash uint64
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		walked++
		if capped {
			return true // past the cap, count without hashing or testing membership
			// Skipping that work avoids about 700,000 FNV and splitmix evaluations
			// on a capped 700,000-entry walk. The walk cannot stop globally: HAMT
			// ForEach honors false only within one shard, and the multi-shard loop
			// invokes it again for each remaining shard. One measured walk reached
			// this branch 17 times. Continue counting so sEst remains complete.
		}
		h := fnv64Entity(entityID)
		if h-offset >= W {
			return true // outside [offset, offset+W) — keep walking (the count)
		}
		// The shared budget is pre-checked before the offer. costOf reports
		// this entry's received cost (1 per self entry; bc per not-yet-published
		// foreign batch; 0 for a relay miss or a dedup-skip). An offer that
		// does not fit the remaining budget is refused here — a post-offer
		// charge could exceed the cap (6x100=600 fits, but a 7th publish
		// would put 700 on the wire before any post-hoc accounting noticed:
		// the pre-check makes the bound exact). A zero-cost entry always
		// fits: it offers (the ship path dedups/misses it) without consuming
		// budget.
		c := 1
		if costOf != nil {
			c = costOf(entityID, entry)
		}
		// An entry whose cost alone exceeds the budget can never fit. Skip the
		// offer and keep walking so it cannot park the ring; every other in-window
		// entry still ships, and the oversized batch is reconsidered each rotation.
		// MaxBatchSize limits outbound flushes only. The inbound batchCount header
		// is informational and unvalidated, so a retained batch can exceed 608
		// decoded elements. Nothing is charged for this skipped offer.
		if c > deferSliceMaxEntries {
			return true
		}
		if c > 0 && cost+c > deferSliceMaxEntries {
			capped = true // the budget cannot fit this entry's cost:
			// lastHash stays at the last offered entry
			return true
		}
		if !fn(entityID, entry) {
			capped = true // the ship path refused (ctx): gate further offers;
			// lastHash stays at the last offered entry (coverage-safe)
			return true
		}
		lastHash = h
		accepted++
		cost += c
		// Charge when the ship path reports the entry handled. A failed foreign
		// Publish can return true without marking seenBatch, so its decoded count
		// is charged even though nothing was received. This can only under-ship;
		// pubErrs parks the window and the unmarked batch is offered again. On the
		// failure path the budget therefore bounds offered rather than received cost.
		return true
	})
	ds.walkedCount = walked
	if capped && accepted > 0 {
		// Resume at the last accepted entry's hash. HAMT walk order is independent
		// of fnv64Entity ring order, so the next window can re-offer roughly half
		// the accepted set as well as the refused entry. Merge-union makes these
		// offers idempotent, but they consume budget again. A capped round therefore
		// advances by the accepted set's hash spread, not W; rotation estimates must
		// include that overlap even though full-ring coverage remains exact.
		ds.nextOffset = lastHash
	} else if capped {
		// The oversized-skip branch above makes a cap with zero accepted entries
		// unreachable: positive accumulated cost implies an accepted offer. Keep
		// this defensive park rather than rewinding to zero if that changes.
		ds.nextOffset = ds.ringOffset
	} else {
		// The window exhausted: advance past it (uint64 wrap = the ring; at
		// sEst <= deferSliceMaxEntries the wrap re-ships the whole small
		// keyset minus the measure-zero boundary hash (h == offset-1,
		// excluded by the half-open window — one hash per round, ~2^-64 per
		// key) each escalation round — bounded by the cap, disclosed).
		ds.nextOffset = offset + W // tile with the next half-open window; adding one would skip the boundary hash and wrap to offset at W=MaxUint64
	}
	g.deferState[peerID] = ds
}

// finalizeDeferShip clears an armed slice, adopts walkedCount as sEst, and
// applies nextOffset when advance reports pubErrs==0 with a live context.
// With no publish failures, the window advances even if every offer skipped
// locally; relay misses, orphans, and pending entries must not park the ring.
// Any publish failure parks it so unpublished entries are retried next round.
// Re-offering the published prefix is idempotent and remains within the cap.
//
// AntiEntropySweep calls this on the sweep goroutine. Missing peer state or an
// unarmed window makes it a no-op. deferAlarmIfAged separately owns alarm caps.
func (g *Gossiper) finalizeDeferShip(peerID [16]byte, advance bool) {
	ds, ok := g.deferState[peerID]
	if !ok {
		return
	}
	// Consume the crossover outcome where pubErrs is known. A failed publish
	// clears the once-marker and sets the cooldown anchor, returning subsequent
	// capacity failures to the ladder until the cooldown expires. A clean ship
	// retains the marker until resetDeferPeer observes the next clean peel.
	if ds.crossoverPend {
		ds.crossoverPend = false
		if !advance {
			ds.crossoverServed = false
			ds.crossoverAt = time.Now()
		}
		g.deferState[peerID] = ds
	}
	if !ds.shipWindow {
		return
	}
	ds.shipWindow = false
	if ds.walkedCount > 0 {
		ds.sEst = ds.walkedCount
	}
	if advance {
		ds.ringOffset = ds.nextOffset
	}
	g.deferState[peerID] = ds
}

// deferAlarmIfAged logs at most deferAlarmLogCap diverged-pair alarms per
// sweep. A rising defer age with a mismatched root indicates that the peer's
// write rate may exceed the bounded slice rate; escalation alone is not
// convergence evidence. Root-based health signals can also mark a converged
// but actively writing peer as sick, so operators should correlate both signals.
func (g *Gossiper) deferAlarmIfAged(peerID [16]byte, st *sweepState) {
	if st == nil || st.deferAlarms >= deferAlarmLogCap {
		return
	}
	ds, ok := g.deferState[peerID]
	if !ok || ds.consecutive < deferEscalationRounds {
		return
	}
	st.deferAlarms++
	if ds.lastClass == deferClassPublish {
		log.Printf("mesh: diverged-pair alarm peer=%x defer_age=%d — %d consecutive digest-exchange failures (publish failure: no slice shipped; circuit breaker handles retry)", peerID, ds.consecutive, ds.consecutive)
		return
	}
	log.Printf("mesh: diverged-pair alarm peer=%x defer_age=%d — %d consecutive digest-exchange failures, escalating bounded <=%d-entry slice/round", peerID, ds.consecutive, ds.consecutive, deferSliceMaxEntries)
}

// evictStaleDefers lazily bounds deferState to the live PeerSet, following
// evictStalePeerRoots and evictStaleDigestRecv. A nil map makes disabled mode a
// no-op. Live peers must retain their rotation offsets to avoid repeatedly
// shipping one slice. The /v1/insert control path has no PeerSet and cannot
// determine liveness, so it retains entries. The sweep goroutine owns the map.
func (g *Gossiper) evictStaleDefers() {
	if g.deferState == nil || len(g.deferState) == 0 {
		return
	}
	if g.peers == nil {
		return
	}
	for id := range g.deferState {
		if !g.peers.isLive(id) {
			delete(g.deferState, id)
		}
	}
}

// fnv64Entity is the entity's fixed position on the escalation ring: a
// 64-bit FNV-1a over the entityID (the HashCausalDot constant family —
// offset basis 14695981039346656037, prime 1099511628211; keyed on the
// entity, not the dot, so an updated entry — a new dot, same entity —
// keeps its ring position and coverage is by entity).
// Order-immune: the walk order never matters, only the hash.
func fnv64Entity(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	// Raw FNV-1a has weak high bits for correlated short names: in one
	// negative control, 20 of 2,200 sibling keys fell into a 29%-wide window.
	// The splitmix64 finalizer supplies the avalanche that window sizing needs.
	h ^= h >> 30
	h *= 0xBF58476D1CE4E5B9
	h ^= h >> 27
	h *= 0x94D049BB133111EB
	h ^= h >> 31
	return h
}
