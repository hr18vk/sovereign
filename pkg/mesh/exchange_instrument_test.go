// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover optional exchange instrumentation and its negative controls
// (ADR-0072): send completion, arrival after a drained wait, dispatch busy time
// in both loops, sweep phases, defer classes, byte windows, and the disabled
// path. SOVEREIGN_TEST_FAULT_DIGEST_WAIT=<name> selects a test-only fault
// injection that must make the corresponding assertion fail.
//
// Measurements come from two in-process nodes on loopback and make no fleet
// claims. Each test quiesces the mesh and synchronizes responders before reading
// their records.

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// l0iArmEnv arms the construction gate (t.Setenv before the mesh build).
func l0iArmEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SOVEREIGN_EXCH_DEBUG", "1")
}

// l0iNegativeControlArm enables the named fault injection when
// SOVEREIGN_TEST_FAULT_DIGEST_WAIT requests it. The ordinary run must pass; the
// injected run must fail the assertion that observes the injected behavior.
func l0iNegativeControlArm(t *testing.T, name string, inj *atomic.Bool) {
	t.Helper()
	if os.Getenv("SOVEREIGN_TEST_FAULT_DIGEST_WAIT") == name {
		inj.Store(true)
		t.Cleanup(func() { inj.Store(false) })
	}
}

// l0iRingStamps scans the ring for non-0 records (stamp==0 slots are
// skipped by construction — the ring's visibility key).
func l0iRingStamps(r *l0iRing) (stamps, ats []int64) {
	if r == nil {
		return nil, nil
	}
	for i := range r.rec {
		if st := r.rec[i].stamp.Load(); st > 0 {
			stamps = append(stamps, st)
			ats = append(ats, r.rec[i].at.Load())
		}
	}
	return stamps, ats
}

// TestL0ISendComplete joins responder send records to requester arrival records
// by buildStamp and requires positive send-completion spans.
func TestL0ISendComplete(t *testing.T) {
	l0iNegativeControlArm(t, "senddone", &l0iZeroSendDoneBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepRound(t, m)
	m.close()
	latencySyncResponders(t, m)
	sstamps, sats := l0iRingStamps(m.gB.l0iSendRing)
	if len(sstamps) == 0 {
		t.Fatalf("the send ring carries no records — the send-complete instrument never fired")
	}
	astamps, aats := l0iRingStamps(m.gA.l0iArrivalRing)
	amap := make(map[int64]int64, len(astamps))
	for i, s := range astamps {
		amap[s] = aats[i]
	}
	joined := 0
	for i, s := range sstamps {
		if _, ok := amap[s]; !ok {
			continue
		}
		joined++
		if span := sats[i] - s; span <= 0 {
			t.Fatalf("the (peerID, buildStamp) join found stamp %d but build->sendComplete = %d ns (want > 0 — the 0-stamp inject shape)", s, span)
		}
	}
	if joined == 0 {
		t.Fatalf("send and arrival rings share no buildStamp, so their spans cannot be joined")
	}
}

// TestL0IArrivalInclLost delays a response beyond the requester's wait and
// verifies that DeliverDigest still records its eventual arrival.
func TestL0IArrivalInclLost(t *testing.T) {
	l0iNegativeControlArm(t, "arrival", &l0iArrivalAtEntryBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 5 * time.Millisecond})
	defer m.cancel()
	m.gB.digestResponderDelayMs.Store(200)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepAOnly(t, m)              // round 1: A's wait expires at 5 ms
	time.Sleep(400 * time.Millisecond) // B's late response arrives (the lost class)
	deferInsert(t, m.gA, "k%04d", 100, 10)
	deferSweepAOnly(t, m) // round 2: fresh divergence re-fires the gate
	m.close()
	latencySyncResponders(t, m)
	if d := m.gA.digestExchDrained.Load(); d < 1 {
		t.Fatalf("drainedDigests=%d, want at least 1; the delayed response did not enter the drained class", d)
	}
	astamps, aats := l0iRingStamps(m.gA.l0iArrivalRing)
	if len(astamps) == 0 {
		t.Fatalf("the arrival ring carries no records — the late (drained-class) response went unstamped at the entry")
	}
	spanned := false
	for i, s := range astamps {
		if aats[i]-s > 0 {
			spanned = true
		}
	}
	if !spanned {
		t.Fatalf("no arrival record carries a >0 span — the arrival stamp measured nothing real")
	}
}

// l0iTokenVal parses the first named int64 token from a captured sweep line.
func l0iTokenVal(t *testing.T, logged, tok string) int64 {
	t.Helper()
	i := strings.Index(logged, tok)
	if i < 0 {
		t.Fatalf("the log carries no %s token (the armed sweep line must carry it)", tok)
	}
	rest := logged[i+len(tok):]
	end := strings.IndexAny(rest, " \n")
	if end < 0 {
		end = len(rest)
	}
	v, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		t.Fatalf("%s unparseable: %q", tok, rest[:end])
	}
	return v
}

// TestL0IBusyBothLoops requires busy time from both the dial-side readLoop and
// the accept-side serve loop. serveTestConn mirrors main.go's
// serveConnWithDigest wiring, so measuring only readLoop would miss one side.
func TestL0IBusyBothLoops(t *testing.T) {
	l0iNegativeControlArm(t, "servebusy", &l0iServeBusySkipBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepRound(t, m)
	m.close()
	latencySyncResponders(t, m)
	var readNs, serveNs int64
	for _, g := range []*Gossiper{m.gA, m.gB} {
		s := g.L0IStats()
		readNs += s.ReadBusyNs
		serveNs += s.ServeBusyNs
	}
	if readNs <= 0 {
		t.Fatalf("the readLoop busy counters stayed 0 across the mesh — the read arm never accrued")
	}
	if serveNs <= 0 {
		t.Fatalf("the serve busy counters stayed 0 across the mesh — the accept side's arm never accrued (the head-of-line term is blind on the serve loop)")
	}
}

// TestL0IPhaseSplit requires positive request, wait, and ship durations in the
// instrumented sweep line for a round that ships entries.
func TestL0IPhaseSplit(t *testing.T) {
	l0iNegativeControlArm(t, "phase", &l0iPhaseZeroReqShipBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	// The emission rides sweepOnce — the production round (the print gate +
	// the sweep line + the instrument suffix); runSweepRound drives the
	// round body alone (no ship accounting, no line), so the phase tokens
	// would never render under it.
	m.gA.sweepOnce(m.ctx)
	m.close()
	latencySyncResponders(t, m)
	logged := buf.String()
	req := l0iTokenVal(t, logged, "phase_req_ns=")
	wait := l0iTokenVal(t, logged, "phase_wait_ns=")
	ship := l0iTokenVal(t, logged, "phase_ship_ns=")
	if req <= 0 || wait <= 0 || ship <= 0 {
		t.Fatalf("the phase split is not populated: req=%d wait=%d ship=%d (want all > 0)", req, wait, ship)
	}
}

// TestL0IDeferClass creates 20,500 fresh differences to force a capacity-class
// peel failure, then requires a nonzero peel count in the defer-class window.
func TestL0IDeferClass(t *testing.T) {
	l0iNegativeControlArm(t, "classt2", &l0iClassT2DropBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 20500)
	deferSweepRound(t, m)
	m.close()
	latencySyncResponders(t, m)
	// Read through the production accessor. With the defer handler enabled, this
	// round ships nothing, so the heartbeat print gate emits no sweep line.
	// TestL0IPhaseSplit covers suffix rendering on a shipping round.
	classes := m.gA.stratDiagClassWindow()
	var t2 int64
	for _, v := range classes[deferClassPeel] {
		t2 += v
	}
	if t2 <= 0 {
		t.Fatalf("defer-class window T2=%d, want at least 1; the capacity-class peel failure was not counted", t2)
	}
	_ = buf
}

// TestL0IByteWindow requires a shipping round to publish positive request and
// ship byte counts for the heartbeat route.
func TestL0IByteWindow(t *testing.T) {
	l0iNegativeControlArm(t, "bytewindow", &l0iByteWindowZeroBugInject)
	l0iArmEnv(t)
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	deferInsert(t, m.gA, "k%04d", 0, 10)
	// sweepOnce — the production round incl. the byte-window store (the
	// emission site); runSweepRound drives the body without the emission.
	m.gA.sweepOnce(m.ctx)
	m.close()
	latencySyncResponders(t, m)
	s := m.gA.L0IStats()
	if s.LastShipBytes <= 0 {
		t.Fatalf("last_ship_bytes=%d, want > 0 — the shipping round did not publish its byte window (the route's read-back passes without exercising the defect)", s.LastShipBytes)
	}
	if s.LastDigestReqBytes <= 0 {
		t.Fatalf("last_digest_req_bytes=%d, want > 0 — the request bytes did not publish", s.LastDigestReqBytes)
	}
}

// TestL0IOff leaves SOVEREIGN_EXCH_DEBUG unset and verifies that construction
// allocates no rings, sweep lines gain no tokens, and aggregates stay zero.
func TestL0IOff(t *testing.T) {
	if os.Getenv("SOVEREIGN_EXCH_DEBUG") != "" {
		t.Skipf("ambient SOVEREIGN_EXCH_DEBUG=%q — the off arm cannot run (unset it to exercise the off control)", os.Getenv("SOVEREIGN_EXCH_DEBUG"))
	}
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepRound(t, m)
	m.close()
	latencySyncResponders(t, m)
	if m.gA.l0iExchDebug || m.gA.l0iSendRing != nil || m.gA.l0iArrivalRing != nil {
		t.Fatalf("disabled construction allocated instrument state")
	}
	logged := buf.String()
	for _, tok := range []string{"phase_req_ns=", "phase_wait_ns=", "phase_ship_ns=", "holl_read_ns=", "holl_serve_ns=", "defer_class="} {
		if strings.Contains(logged, tok) {
			t.Fatalf("disabled sweep line carries instrument token %s", tok)
		}
	}
	s := m.gA.L0IStats()
	if s.SendDoneCount != 0 || s.ArriveCount != 0 || s.ReadBusyNs != 0 || s.ServeBusyNs != 0 || s.LastShipBytes != 0 {
		t.Fatalf("disabled-path aggregates are nonzero: %+v", s)
	}
}

// TestL0IAllocDraw compares generateSweepDelta allocations with diagnostics
// disabled and enabled, allowing a difference of at most two allocations for
// process-wide background noise. The environment is read at construction, so
// the comparison uses two converged meshes measured in sequence rather than
// changing one mesh mid-flight. The first mesh closes before the second is
// built, keeping teardown allocations outside both measured windows.
// testing.AllocsPerRun includes B-side responder work in both measurements;
// fixed-array ring writes and atomics should add no steady-state allocations.
func TestL0IAllocDraw(t *testing.T) {
	t.Setenv("SOVEREIGN_EXCH_DEBUG", "") // disable instrumentation at construction
	m1 := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m1.cancel()
	deferInsert(t, m1.gA, "exchange-off-%04d", 0, 10)
	deferSweepRound(t, m1) // converge: the measured draw is the healthy per-draw path
	draw1 := func() {
		d := m1.gA.generateSweepDelta(m1.ctx, m1.identB.NodeID)
		if d != nil {
			d.Release()
		}
	}
	for i := 0; i < 300; i++ { // warm the first measured mesh, including B-side work
		draw1()
	}
	allocsOff := testing.AllocsPerRun(300, draw1)
	m1.close()
	latencySyncResponders(t, m1)
	t.Setenv("SOVEREIGN_EXCH_DEBUG", "1") // enable instrumentation at construction
	m2 := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m2.cancel()
	if !m2.gA.l0iExchDebug {
		t.Fatalf("enabled mesh has l0iExchDebug=false; the allocation comparison measured the disabled path twice")
	}
	deferInsert(t, m2.gA, "exchange-on-%04d", 0, 10)
	deferSweepRound(t, m2)
	draw2 := func() {
		d := m2.gA.generateSweepDelta(m2.ctx, m2.identB.NodeID)
		if d != nil {
			d.Release()
		}
	}
	for i := 0; i < 50; i++ { // warm the second mesh before measuring it
		draw2()
	}
	allocsOn := testing.AllocsPerRun(300, draw2)
	m2.close()
	latencySyncResponders(t, m2)
	t.Logf("per-draw allocations disabled=%g enabled=%g; enabled additions use fixed-array ring writes and atomics", allocsOff, allocsOn)
	const zeroAllocNoiseFloor = 2 // tolerate B-side allocations common to both measurements
	if d := allocsOn - allocsOff; d < -float64(zeroAllocNoiseFloor) || d > float64(zeroAllocNoiseFloor) {
		t.Fatalf("per-draw allocations enabled=%g disabled=%g (delta %g) exceed the +/-2 noise floor", allocsOn, allocsOff, d)
	}
}
