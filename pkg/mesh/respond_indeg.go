// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The responder in-degree tracker records occupancy when each digest request
// arrives. Buckets 0 through digestRespondMaxConcurrent-1 count requests that
// overlapped that many responder builds. The final bucket counts requests
// dropped because every response slot was busy. Keeping the distribution shows
// how concurrency varies between arrivals instead of reporting only a maximum.
//
// The tracker is nil until SetRespondIndegArmed enables it during construction,
// before connection read loops start. cmd enables it with
// SOVEREIGN_RESPOND_INDEG_DEBUG=1. While disabled, recording is a nil-checked
// no-op and no tracker is allocated. Enabled trackers use atomic counters
// without a mutex.

import "sync/atomic"

// respondIndegBuckets = the observed-occupancy domain + the drop bucket.
const respondIndegBuckets = digestRespondMaxConcurrent + 1

type respondIndegTracker struct {
	hist     [respondIndegBuckets]atomic.Uint64
	arrivals atomic.Uint64
	// blind lets a test suppress histogram mass while still counting arrivals.
	// That gives the occupancy assertions a reachable failure mode. Production
	// never writes this field.
	blind atomic.Bool
}

// record observes the number of in-flight responder builds when a request
// arrives. Occupancy at digestRespondMaxConcurrent is the drop bucket. The
// enqueueing goroutine calls record before the acquire/drop select, so the
// observation describes the arrival rather than the post-acquire state.
func (t *respondIndegTracker) record(occupancy int) {
	t.arrivals.Add(1)
	if t.blind.Load() {
		return
	}
	if occupancy < 0 {
		occupancy = 0
	}
	if occupancy > digestRespondMaxConcurrent {
		occupancy = digestRespondMaxConcurrent
	}
	t.hist[occupancy].Add(1)
}

// SetRespondIndegArmed allocates the tracker at most once; it is not disabled
// later in the process. Leaving it disabled allocates nothing and keeps the
// record site a nil-guarded no-op.
func (g *Gossiper) SetRespondIndegArmed(armed bool) {
	if armed && g.respondIndeg == nil {
		g.respondIndeg = &respondIndegTracker{}
	}
}

// RespondIndeg is the /debug/responder-indegree snapshot (the harness's
// per-run read at quiescence).
type RespondIndeg struct {
	Armed    bool     `json:"armed"`
	Arrivals uint64   `json:"arrivals"`
	Hist     []uint64 `json:"occupancy_hist"` // len == Cap+1; index = observed occupancy; [Cap] = the drop bucket
	Cap      int      `json:"cap"`
}

// RespondIndegSnapshot returns an O(17) diagnostic snapshot. Its histogram
// slice is allocated only for this scrape-time read. An unarmed tracker reports
// Armed=false and zero counts, distinguishing absent instrumentation from an
// armed tracker with no recorded mass.
func (g *Gossiper) RespondIndegSnapshot() RespondIndeg {
	snap := RespondIndeg{
		Armed: g.respondIndeg != nil,
		Cap:   digestRespondMaxConcurrent,
		Hist:  make([]uint64, respondIndegBuckets),
	}
	if g.respondIndeg == nil {
		return snap
	}
	snap.Arrivals = g.respondIndeg.arrivals.Load()
	for i := range snap.Hist {
		snap.Hist[i] = g.respondIndeg.hist[i].Load()
	}
	return snap
}
