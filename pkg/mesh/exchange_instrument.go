// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Optional exchange diagnostics are enabled by SOVEREIGN_EXCH_DEBUG=1, read
// once during Gossiper construction. With the default disabled setting, both
// rings remain nil, sweep lines omit the diagnostic tokens, and hook sites do
// no record-keeping work.
//
// The instrumentation covers five parts of an exchange:
//   - response send completion, recorded after the synchronous Publish returns
//     and joined to requester arrival records by (peerID, buildStamp);
//   - arrival at DeliverDigest entry, before routing or deposit drops, so late
//     responses have build-to-arrival measurements;
//   - dispatch busy time in both peer.go's readLoop and main.go's accept-side
//     serve loop, exposing head-of-line work on either connection type;
//   - request, wait, and ship phases of each serial sweep; and
//   - per-class, per-region defer counters from noteDeferTrigger.
//
// These records stay local. The digest frame's reserved bytes remain unused,
// and no instrumentation data is added to the wire. Test-only fault injections
// verify that each diagnostic assertion fails when its target behavior breaks.

import (
	"fmt"
	"sync/atomic"
	"time"
)

// l0iRingLen fixes both rings at 64 slots. Arrival records come from both
// dispatch loops, while up to 16 responders write send records. Construction
// allocates the fixed arrays when instrumentation is enabled; recording then
// uses atomics without allocation or a mutex. Tests and the heartbeat route
// read the rings concurrently with the responder and dispatch goroutines.
const l0iRingLen = 64

// l0iRecord is one ring slot. Writers publish stamp last, and readers skip
// stamp==0 slots so an initially incomplete record is invisible. A scan can
// still race with slot reuse after the ring wraps; these are diagnostic samples,
// not a lossless event log.
type l0iRecord struct {
	peerHi atomic.Int64
	peerLo atomic.Int64
	stamp  atomic.Int64 // the frame's wire build stamp (0 = unstamped — the broken class)
	at     atomic.Int64 // send-complete (send ring) or arrival (arrival ring), Unix nanos
}

// l0iRing is the fixed-size atomic record ring.
type l0iRing struct {
	next atomic.Uint64
	rec  [l0iRingLen]l0iRecord
}

// record claims a slot with an atomic increment and then writes its fields.
// Storing stamp last publishes a new record to scanners; all fields use atomic
// accesses because recording and scanning proceed concurrently.
func (r *l0iRing) record(peer [16]byte, stamp, at int64) {
	i := r.next.Add(1) - 1
	slot := &r.rec[i%l0iRingLen]
	slot.peerHi.Store(int64(binaryBigEndianUint64(peer[:8])))
	slot.peerLo.Store(int64(binaryBigEndianUint64(peer[8:])))
	slot.at.Store(at)
	slot.stamp.Store(stamp) // last: the scan's visibility key
}

// l0iAgg aggregates one record class: count, span sum, maximum span, and the
// number of records with missing build stamps. Missing stamps increment broken
// but contribute no span; subtracting one from the current time would otherwise
// produce a meaningless span of roughly 1.7e18 nanoseconds.
type l0iAgg struct {
	count  atomic.Int64
	sum    atomic.Int64
	max    atomic.Int64
	broken atomic.Int64
}

// note records a span. The compare-and-swap maximum loop avoids losing a larger
// value written concurrently.
func (a *l0iAgg) note(stamp, at int64) {
	if stamp <= 0 {
		a.broken.Add(1)
		return
	}
	a.count.Add(1)
	ns := at - stamp
	if ns < 0 {
		ns = 0 // clocks on different hosts can disagree; clamp negative spans to zero
	}
	a.sum.Add(ns)
	for {
		m := a.max.Load()
		if ns <= m || a.max.CompareAndSwap(m, ns) {
			break
		}
	}
}

// Test-only fault injections, all false in production:
//
//	l0iZeroSendDoneBugInject records a zero send-completion time, which must
//	break the positive-span assertion.
//	l0iArrivalAtEntryBugInject skips entry stamping so late responses have no
//	arrival record.
//	l0iServeBusySkipBugInject skips serve-loop accounting and must break the
//	assertion that both loops accumulate busy time.
//	l0iClassT2DropBugInject omits a peel-class increment from its window.
//	l0iByteWindowZeroBugInject suppresses the latest byte-window stores.
var (
	l0iZeroSendDoneBugInject   atomic.Bool
	l0iArrivalAtEntryBugInject atomic.Bool
	l0iServeBusySkipBugInject  atomic.Bool
	l0iClassT2DropBugInject    atomic.Bool
	l0iByteWindowZeroBugInject atomic.Bool
	// l0iPhaseZeroReqShipBugInject zeroes request and ship accounting, leaving
	// only the wait term for the phase-split negative control.
	l0iPhaseZeroReqShipBugInject atomic.Bool
)

// l0iNoteSendDone records a response's build stamp and the time its synchronous
// Publish call returned. Only the responder goroutine calls it when diagnostics
// are enabled. l0iZeroSendDoneBugInject substitutes a zero completion time to
// exercise the broken-span test.
func (g *Gossiper) l0iNoteSendDone(peer [16]byte, stamp int64) {
	at := time.Now().UnixNano()
	if l0iZeroSendDoneBugInject.Load() {
		at = 0
	}
	if r := g.l0iSendRing; r != nil {
		r.record(peer, stamp, at)
	}
	g.l0iSendAgg.note(stamp, at)
}

// l0iNoteArrival records arrival at DeliverDigest entry, before the nil guard,
// gateway anchor-pinning check (ADR-0068), route lookup, and nonblocking channel
// deposit. Late and otherwise dropped responses therefore still receive a
// record. The readLoop or serve goroutine calls it when diagnostics are enabled;
// l0iArrivalAtEntryBugInject omits this call site in the negative control.
func (g *Gossiper) l0iNoteArrival(peer [16]byte, stamp int64) {
	at := time.Now().UnixNano()
	if r := g.l0iArrivalRing; r != nil {
		r.record(peer, stamp, at)
	}
	g.l0iArriveAgg.note(stamp, at)
}

// l0iArm allocates both record rings once and enables PeerSet dispatch
// accounting. NewGossiper calls it only for SOVEREIGN_EXCH_DEBUG=1, so disabled
// construction leaves the rings nil and recording needs no further allocation.
func (g *Gossiper) l0iArm(peers *PeerSet) {
	g.l0iSendRing = &l0iRing{}
	g.l0iArrivalRing = &l0iRing{}
	if peers != nil {
		peers.setL0IExchDebug()
	}
}

// L0ILoop identifies the inline dispatch loops that report busy time. peer.go's
// readLoop and main.go's serveConnWithDigest use separate labels because
// bidirectional connections can perform bulk applies in either loop.
type L0ILoop uint8

const (
	L0ILoopRead L0ILoop = iota
	L0ILoopServe
)

// NoteDispatchBusy adds one dispatch's duration to its loop's cumulative counter
// and compare-and-swap maximum. The sweep emitter derives per-round durations
// from the prev* bases. A disabled PeerSet performs only the initial atomic
// load. l0iServeBusySkipBugInject skips just the serve-loop update for its test.
func (ps *PeerSet) NoteDispatchBusy(loop L0ILoop, ns int64) {
	if !ps.l0iExchDebug.Load() {
		return
	}
	if loop == L0ILoopServe && l0iServeBusySkipBugInject.Load() {
		return
	}
	if loop == L0ILoopRead {
		ps.l0iReadBusyNs.Add(ns)
		for {
			m := ps.l0iReadBusyMaxNs.Load()
			if ns <= m || ps.l0iReadBusyMaxNs.CompareAndSwap(m, ns) {
				break
			}
		}
		return
	}
	ps.l0iServeBusyNs.Add(ns)
	for {
		m := ps.l0iServeBusyMaxNs.Load()
		if ns <= m || ps.l0iServeBusyMaxNs.CompareAndSwap(m, ns) {
			break
		}
	}
}

// setL0IExchDebug enables the PeerSet during construction, before readLoop
// goroutines start. The atomic also permits concurrent diagnostic reads.
func (ps *PeerSet) setL0IExchDebug() {
	ps.l0iExchDebug.Store(true)
}

// stratDiagClassWindow swaps and resets the per-class, per-region fallback maps
// under the same mutex as stratDiagSnapshotReset. The sweep-line emitter calls
// it when diagnostics are enabled. The map dimensions are bounded by
// deferClassCount and the region set.
func (g *Gossiper) stratDiagClassWindow() [deferClassCount]map[RegionTag]int64 {
	var out [deferClassCount]map[RegionTag]int64
	d := g.stratDiag
	if d == nil {
		return out
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out = d.fallbackByClass
	for c := range d.fallbackByClass {
		d.fallbackByClass[c] = make(map[RegionTag]int64)
	}
	return out
}

// L0ISnapshot contains exchange diagnostics for the /debug/heartbeat JSON
// response and instrumentation tests.
type L0ISnapshot struct {
	SendDoneCount      int64
	SendDoneSpanNs     int64
	SendDoneMaxNs      int64
	SendBrokenTotal    int64
	ArriveCount        int64
	ArriveSpanNs       int64
	ArriveMaxNs        int64
	ArriveBrokenTotal  int64
	ReadBusyNs         int64
	ReadBusyMaxNs      int64
	ServeBusyNs        int64
	ServeBusyMaxNs     int64
	LastShipBytes      int64
	LastDigestReqBytes int64
}

// L0IStats reads the diagnostic aggregates with atomics. A nil PeerSet produces
// zero dispatch values, which supports the Gossiper used by /v1/insert.
func (g *Gossiper) L0IStats() L0ISnapshot {
	s := L0ISnapshot{
		SendDoneCount:      g.l0iSendAgg.count.Load(),
		SendDoneSpanNs:     g.l0iSendAgg.sum.Load(),
		SendDoneMaxNs:      g.l0iSendAgg.max.Load(),
		SendBrokenTotal:    g.l0iSendAgg.broken.Load(),
		ArriveCount:        g.l0iArriveAgg.count.Load(),
		ArriveSpanNs:       g.l0iArriveAgg.sum.Load(),
		ArriveMaxNs:        g.l0iArriveAgg.max.Load(),
		ArriveBrokenTotal:  g.l0iArriveAgg.broken.Load(),
		LastShipBytes:      g.lastShipBytes.Load(),
		LastDigestReqBytes: g.lastDigestReqBytes.Load(),
	}
	if g.peers != nil {
		s.ReadBusyNs = g.peers.l0iReadBusyNs.Load()
		s.ReadBusyMaxNs = g.peers.l0iReadBusyMaxNs.Load()
		s.ServeBusyNs = g.peers.l0iServeBusyNs.Load()
		s.ServeBusyMaxNs = g.peers.l0iServeBusyMaxNs.Load()
	}
	return s
}

// l0iSweepSuffix renders per-round exchange tokens and resets their windows for
// the sweep-line emitter. It returns an empty string when diagnostics are
// disabled. The phase accumulators are plain fields accessed only by the sweep
// goroutine, and this method is their only reader and resetter.
func (g *Gossiper) l0iSweepSuffix(st *sweepState) string {
	if !g.l0iExchDebug {
		return ""
	}
	// Publish the round's byte totals for the heartbeat route. The byte-window
	// fault injection suppresses these stores in its negative control.
	if !l0iByteWindowZeroBugInject.Load() {
		g.lastShipBytes.Store(int64(st.shippedBytes))
		g.lastDigestReqBytes.Store(int64(st.digestReqBytes))
	}
	// Derive busy windows from cumulative counters and reset the maxima. A frame
	// spanning this emission contributes to one of the adjacent windows.
	readNow, serveNow := int64(0), int64(0)
	readMax, serveMax := int64(0), int64(0)
	if g.peers != nil {
		readNow = g.peers.l0iReadBusyNs.Load()
		serveNow = g.peers.l0iServeBusyNs.Load()
		readMax = g.peers.l0iReadBusyMaxNs.Load()
		serveMax = g.peers.l0iServeBusyMaxNs.Load()
		g.peers.l0iReadBusyMaxNs.Store(0)
		g.peers.l0iServeBusyMaxNs.Store(0)
	}
	readDelta, serveDelta := readNow-g.prevReadBusyNs, serveNow-g.prevServeBusyNs
	g.prevReadBusyNs, g.prevServeBusyNs = readNow, serveNow
	// Sum each defer class across regions and emit classes in a fixed order so
	// log comparisons are deterministic.
	classes := g.stratDiagClassWindow()
	cls := func(c deferClass) int64 {
		var n int64
		for _, v := range classes[c] {
			n += v
		}
		return n
	}
	s := fmt.Sprintf(" phase_req_ns=%d phase_wait_ns=%d phase_ship_ns=%d holl_read_ns=%d holl_read_max_ns=%d holl_serve_ns=%d holl_serve_max_ns=%d defer_class=T1:%d,T4:%d,T6:%d,T7:%d,T5:%d,T2:%d",
		g.l0iPhaseReqNs, g.l0iPhaseWaitNs, g.l0iPhaseShipNs, readDelta, readMax, serveDelta, serveMax,
		cls(deferClassTimeout), cls(deferClassNilDigest), cls(deferClassIBLTMarshal), cls(deferClassSEMarshal), cls(deferClassPublish), cls(deferClassPeel))
	g.l0iPhaseReqNs, g.l0iPhaseWaitNs, g.l0iPhaseShipNs = 0, 0, 0
	return s
}
