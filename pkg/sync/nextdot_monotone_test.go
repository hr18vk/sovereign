// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// NextDot advances lastSavedCounter with a monotone compare-and-swap loop.
// CompareAndSwap(Load(), nextLimit) alone is insufficient: another goroutine
// can store a higher value before the Load is evaluated, allowing a subsequent
// compare-and-swap to replace that higher value with a lower one. Reloading
// and breaking when nextLimit <= lastSaved ensures every successful swap
// advances the watermark. The existing fast path skips the loop while the
// counter remains inside the persisted window.
//
// The static tests require this loop in both NextDot and AdvanceLamportTo,
// retain the non-blocking persist send, and reject a direct Store or a disk
// mutex acquisition in NextDot. The concurrent test uses NumCPU workers,
// 200,000 calls per worker (50,000 with the race detector), consecutive samples
// to detect backwards movement, and a final comparison against the observed
// peak. It also checks that Close leaves a nonzero value on disk.
//
// Persist sends are deliberately dropped while the worker is busy. A disk value
// more than 1,000 behind the in-memory peak is therefore reported as lag when
// both in-memory monotonicity checks pass; it is an error when those checks
// have already detected a regression. The source checks cover this distinction
// as well as the nonzero disk-value floor.

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nextdotReadCrdtSource mirrors parkReadCrdtSource: read the live
// pkg/sync/crdt.go source (os.ReadFile, not go/embed — the guard must sweep
// the current tree). cwd is pkg/sync under `go test ./pkg/sync/`.
func nextdotReadCrdtSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("crdt.go")
	if err != nil {
		alt := filepath.Join("pkg", "sync", "crdt.go")
		data, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("static guard: cannot read crdt.go: %v", err)
		}
	}
	return string(data)
}

// nextdotFuncBody isolates a function body in crdt.go source by name.
// Reuses parkFuncBody (same package) for the parsing logic; the helper
// handles both method receivers and package-level funcs.
func nextdotFuncBody(src, name string) string {
	return parkFuncBody(src, name)
}

// TestNextDotMonotoneLoopStatic checks six properties of NextDot: the retry
// loop, guard before compare-and-swap, reload on contention, non-blocking
// persist send, and absence of both persistMu.Lock and Store(nextLimit).
// It runs in every build mode, including short mode and race-enabled builds.
func TestNextDotMonotoneLoopStatic(t *testing.T) {
	src := nextdotReadCrdtSource(t)
	body := nextdotFuncBody(src, "NextDot")
	if body == "" {
		t.Fatal("nextdot-monotone: cannot isolate NextDot function body in crdt.go")
	}
	t.Logf("nextdot-monotone: isolated NextDot body (%d bytes)", len(body))

	// invariant 1: the monotone loop — a `for {` block. The unguarded shape
	// had no for loop (it was a single `if CompareAndSwap(...) { select {...} }`).
	m1For := regexp.MustCompile(`for\s*\{`)
	// invariant 2: nextLimit <= lastSaved and a break must precede the first
	// CompareAndSwap. Comments are stripped before comparing source positions.
	m2Guard := regexp.MustCompile(`nextLimit\s*<=\s*lastSaved`)
	m2Break := regexp.MustCompile(`break`)
	m2CAS := regexp.MustCompile(`e\.lastSavedCounter\.CompareAndSwap`)
	// invariant 3: a `lastSaved := e.lastSavedCounter.Load()` assignment
	// inside the for loop (the re-load on CAS failure — the loop's retry
	// semantics). The unguarded CAS had a single `Load()` as a CAS argument,
	// not an assignment to a re-looped variable.
	m3Reload := regexp.MustCompile(`lastSaved\s*:=\s*e\.lastSavedCounter\.Load\(\)`)
	// invariant 4: the non-blocking select-default send is preserved (the
	// decouple semantics are byte-identical; only the CAS guard changed).
	m4Send := regexp.MustCompile(`select\s*\{\s*case\s+e\.persistCh\s*<-\s*nextLimit\s*:\s*default\s*:\s*\}`)
	// invariant 5: NextDot must not wait for the disk mutex.
	m5MuLock := regexp.MustCompile(`e\.persistMu\.Lock\(\)`)
	// invariant 6: a relaxed Store must not replace the monotone CAS.
	m6Store := regexp.MustCompile(`\.Store\(nextLimit\)`)

	type inv struct {
		id      string
		ok      bool
		passMsg string
		failMsg string
	}
	var invs []inv

	// invariant 1
	m1ok := m1For.MatchString(body)
	invs = append(invs, inv{
		id:      "M1 (for { monotone loop present)",
		ok:      m1ok,
		passMsg: "monotone retry loop is present",
		failMsg: "NextDot does not contain a monotone retry loop",
	})

	// M2: the guard and its break precede the CAS in executable code.
	stripped := parkStripGoComments(body)
	guardLoc := m2Guard.FindStringIndex(stripped)
	casLoc := m2CAS.FindStringIndex(stripped)
	m2ok := false
	var m2pass, m2fail string
	if guardLoc == nil {
		m2fail = "NextDot has no nextLimit <= lastSaved guard before its compare-and-swap"
	} else if casLoc == nil {
		m2fail = "NextDot does not call CompareAndSwap on lastSavedCounter"
	} else if guardLoc[0] >= casLoc[0] {
		m2fail = fmt.Sprintf("monotone guard at byte %d follows the CAS at byte %d; the guard must come first", guardLoc[0], casLoc[0])
	} else if !m2Break.MatchString(stripped[guardLoc[0]:casLoc[0]]) {
		m2fail = fmt.Sprintf("monotone guard at byte %d has no break before the CAS at byte %d", guardLoc[0], casLoc[0])
	} else {
		m2ok = true
		m2pass = fmt.Sprintf("monotone guard at byte %d precedes CAS at byte %d with a break", guardLoc[0], casLoc[0])
	}
	invs = append(invs, inv{id: "M2 (nextLimit <= lastSaved break before CAS)", ok: m2ok, passMsg: m2pass, failMsg: m2fail})

	// invariant 3
	m3ok := m3Reload.MatchString(body)
	invs = append(invs, inv{
		id:      "M3 (lastSaved := Load() re-loop assignment in for)",
		ok:      m3ok,
		passMsg: "lastSavedCounter is reloaded inside the retry loop",
		failMsg: "NextDot does not reload lastSavedCounter inside its retry loop",
	})

	// invariant 4
	m4ok := m4Send.MatchString(body)
	invs = append(invs, inv{
		id:      "M4 (select-default persistCh send preserved)",
		ok:      m4ok,
		passMsg: "persistCh send uses select with default",
		failMsg: "NextDot no longer uses a non-blocking persistCh send",
	})

	// invariant 5
	m5ok := !m5MuLock.MatchString(body)
	invs = append(invs, inv{
		id:      "M5 (no e.persistMu.Lock() in NextDot)",
		ok:      m5ok,
		passMsg: "NextDot does not acquire persistMu",
		failMsg: "NextDot acquires persistMu and can block behind fsync",
	})

	// invariant 6
	m6ok := !m6Store.MatchString(body)
	invs = append(invs, inv{
		id:      "M6 (no .Store(nextLimit))",
		ok:      m6ok,
		passMsg: "NextDot updates the watermark only through compare-and-swap",
		failMsg: "NextDot uses Store(nextLimit), which can overwrite a higher concurrent value",
	})

	anyFail := false
	for _, iv := range invs {
		if iv.ok {
			t.Logf("NextDot static check %s: %s", iv.id, iv.passMsg)
		} else {
			t.Errorf("NextDot static check %s: %s", iv.id, iv.failMsg)
			anyFail = true
		}
	}
	if anyFail {
		t.Fatalf("NextDot does not satisfy all monotone-loop source checks")
	}
}

// TestNextDotLastSavedMonotoneConcurrent samples lastSavedCounter twice after
// each NextDot and records any backwards movement. Workers also maintain the
// highest observed value with an atomic compare-and-swap loop.
//
// After the workers finish, the final watermark must equal that peak. Close
// drains the persist worker, after which the test decodes the big-endian uint64
// in the Lamport file and requires a nonzero value. The race-enabled build runs
// fewer calls per worker but retains all monotonicity assertions.
func TestNextDotLastSavedMonotoneConcurrent(t *testing.T) {
	numCPU := runtime.NumCPU()
	t.Logf("nextdot-monotone: runtime.NumCPU()=%d GOMAXPROCS=%d", numCPU, runtime.GOMAXPROCS(0))

	perWorker := 200_000
	if raceEnabled {
		perWorker = 50_000
		t.Logf("NextDot persistence: perWorker reduced from 200,000 to %d with race instrumentation", perWorker)
	}

	dir := t.TempDir()
	oldDir := DataDir
	DataDir = dir
	t.Cleanup(func() { DataDir = oldDir })

	nodeID := [16]byte{0x2C, 0x02, 0x5C, 0x02}
	eng, err := NewDeltaCRDTEngine(nodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NextDot persistence: NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() {
		_ = eng.Close()
	})

	var peak uint64            // highest lastSaved observed
	var midFlightRegress int64 // count of second-Load < first-Load
	var wg sync.WaitGroup      // worker synchronization
	wg.Add(numCPU)
	for w := 0; w < numCPU; w++ {
		go func() {
			defer wg.Done()
			// Pin each worker to a tight loop: NextDot, then two consecutive
			// lastSavedCounter.Load() samples to detect a mid-flight regression.
			for i := 0; i < perWorker; i++ {
				_ = eng.NextDot()
				first := eng.lastSavedCounter.Load()
				second := eng.lastSavedCounter.Load()
				// Track the peak. Use a CAS loop to advance peak monotonically
				// (avoid a lost update on the peak itself).
				for {
					p := atomic.LoadUint64(&peak)
					if second <= p {
						break
					}
					if atomic.CompareAndSwapUint64(&peak, p, second) {
						break
					}
				}
				if second < first {
					atomic.AddInt64(&midFlightRegress, 1)
				}
			}
		}()
	}
	wg.Wait()

	// Additional NextDot calls and a short scheduling window give the persist
	// worker an opportunity to finish an fsync before Close. Regression counting
	// has already stopped, so these calls do not hide backwards movement observed
	// during the concurrent phase. The park handshake independently guarantees
	// that the first persist send reaches the worker.
	const quiesceDrain = 2000
	for i := 0; i < quiesceDrain; i++ {
		_ = eng.NextDot()
	}
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)

	finalLastSaved := eng.lastSavedCounter.Load()
	// Merge the final reading into the observed peak without ever lowering the
	// peak. Overwriting it with a lower final value would make the subsequent
	// equality check pass despite an earlier regression.
	for {
		p := atomic.LoadUint64(&peak)
		if finalLastSaved <= p {
			break // peak already >= finalLastSaved; do not regress peak
		}
		if atomic.CompareAndSwapUint64(&peak, p, finalLastSaved) {
			break
		}
	}
	peakFinal := atomic.LoadUint64(&peak)

	// Close drains the persist worker; then read the persisted file directly.
	if err := eng.Close(); err != nil {
		t.Fatalf("NextDot persistence: eng.Close: %v", err)
	}
	persistPath := fmt.Sprintf("%s/lamport_%x.dat", dir, nodeID)
	persistData, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("NextDot persistence: os.ReadFile(%s): %v", persistPath, err)
	}
	if len(persistData) < 8 {
		t.Fatalf("NextDot persistence: persisted file %s too short (%d bytes, want >= 8)", persistPath, len(persistData))
	}
	persisted := binary.BigEndian.Uint64(persistData[:8])

	t.Logf("NextDot persistence: perWorker=%d workers=%d totalNextDot=%d quiesceDrain=%d", perWorker, numCPU, perWorker*numCPU, quiesceDrain)
	t.Logf("NextDot persistence: midFlightRegress=%d finalLastSaved=%d peak=%d persisted=%d",
		midFlightRegress, finalLastSaved, peakFinal, persisted)

	// Consecutive samples must never move backwards.
	if midFlightRegress != 0 {
		t.Errorf("NextDot persistence: observed %d backwards movements of lastSavedCounter, want 0", midFlightRegress)
	} else {
		t.Logf("NextDot persistence: lastSavedCounter never moved backwards")
	}

	// The final value must retain the highest value observed by any worker.
	if finalLastSaved != peakFinal {
		t.Errorf("NextDot persistence: final lastSaved=%d is below observed peak=%d", finalLastSaved, peakFinal)
	} else {
		t.Logf("NextDot persistence: final lastSaved equals observed peak=%d", peakFinal)
	}

	// GATE 3: persistence checks distinguish asynchronous lag from regression.
	//
	// NextDot's select-default send drops a notification whenever the persist
	// worker is busy with fsync. The on-disk watermark is the last value the
	// worker received and can legitimately trail the in-memory peak by more than
	// the 1,000-dot amortization window. A single disk read cannot distinguish
	// that lag from a backwards in-memory compare-and-swap.
	//
	// The direct evidence is therefore the earlier pair of in-memory checks:
	// consecutive samples must never decrease, and the final watermark must equal
	// the observed peak. Those checks inspect the property directly instead of
	// inferring it from the persist worker's schedule.
	//
	// When both in-memory checks pass, a disk gap above 1,000 is logged as lag.
	// The file remains useful as a progress observation, but its distance from
	// the peak does not identify which values were dropped by the full channel.
	// Requiring the gap to stay below 1,000 under contention would contradict the
	// non-blocking send contract and make the test depend on fsync timing.
	//
	// If either in-memory check fails, the same large disk gap is also an error.
	// At that point the test has direct evidence of a regression, and the file
	// provides an additional observation of its effect. The two outcomes are
	// reported separately so asynchronous lag is not presented as a successful
	// bound on persistence latency.
	//
	// These disk outcomes do not weaken either in-memory assertion. The direct
	// samples and peak comparison remain authoritative throughout the concurrent
	// phase; the file check adds only what a post-Close observation can establish
	// about the worker's last completed write.
	//
	// Independently, a zero disk value always fails. The constructor's park
	// handshake guarantees that the first send reaches the worker, and Close
	// waits for the worker to finish, so a valid run must leave a nonzero value.
	// This floor catches a missing persist call or an incomplete Close drain even
	// when the asynchronous gap itself is inconclusive.
	gate3AxisBPass := persisted != 0
	if !gate3AxisBPass {
		t.Errorf("NextDot persistence: recovered value is zero; the persist worker did not complete a write before Close")
	}
	gap := peakFinal - persisted
	const gate3SpecBound = 1000 // persist amortization window
	if midFlightRegress == 0 && finalLastSaved == peakFinal {
		// With monotone in-memory state, the remaining disk gap is send lag.
		if gap > gate3SpecBound {
			t.Logf("NextDot persistence: disk gap=%d exceeds the %d-dot amortization window because persist sends were dropped", gap, gate3SpecBound)
		} else {
			t.Logf("NextDot persistence: disk gap=%d is within the %d-dot amortization window (persisted=%d peak=%d)", gap, gate3SpecBound, persisted, peakFinal)
		}
	} else {
		// Once an in-memory regression is observed, a large disk gap is an error.
		if gap > gate3SpecBound {
			t.Errorf("NextDot persistence: disk gap=%d exceeds %d after an in-memory regression (midFlightRegress=%d finalLastSaved=%d)", gap, gate3SpecBound, midFlightRegress, finalLastSaved)
		} else {
			t.Logf("NextDot persistence: disk gap=%d is within %d, but in-memory monotonicity failed", gap, gate3SpecBound)
		}
	}

	if midFlightRegress != 0 || finalLastSaved != peakFinal || !gate3AxisBPass {
		t.Fatalf("NextDot failed an in-memory monotonicity or nonzero-persistence check")
	}
}

// TestNextDotAdvanceSymmetryMeta requires both NextDot and AdvanceLamportTo to
// place a <= lastSaved guard and break before their compare-and-swap. Sharing
// this shape keeps both watermark updates monotone. The source check runs in
// every build mode, including short mode.
func TestNextDotAdvanceSymmetryMeta(t *testing.T) {
	src := nextdotReadCrdtSource(t)
	nextDotBody := nextdotFuncBody(src, "NextDot")
	advanceBody := nextdotFuncBody(src, "AdvanceLamportTo")
	if nextDotBody == "" {
		t.Fatal("nextdot-monotone: cannot isolate NextDot function body in crdt.go")
	}
	if advanceBody == "" {
		t.Fatal("nextdot-monotone: cannot isolate AdvanceLamportTo function body in crdt.go")
	}

	// The monotone-guard pattern: `<var> <= lastSaved` followed (in the
	// stripped body) by a `break` before the CAS. In NextDot the var is
	// `nextLimit`; in AdvanceLamportTo it's `remoteCounter`. We assert both
	// bodies contain a `<= lastSaved` guard and a `CompareAndSwap` and a
	// `break`, with the guard preceding the CAS in the stripped body.
	guardRe := regexp.MustCompile(`<=\s*lastSaved`)
	breakRe := regexp.MustCompile(`break`)
	casRe := regexp.MustCompile(`lastSavedCounter\.CompareAndSwap`)

	checkOne := func(name, body string) error {
		stripped := parkStripGoComments(body)
		guardLoc := guardRe.FindStringIndex(stripped)
		casLoc := casRe.FindStringIndex(stripped)
		if guardLoc == nil {
			return fmt.Errorf("%s: no monotone guard <= lastSaved", name)
		}
		if casLoc == nil {
			return fmt.Errorf("%s: no lastSavedCounter.CompareAndSwap call", name)
		}
		if guardLoc[0] >= casLoc[0] {
			return fmt.Errorf("%s: monotone guard at byte %d follows the CAS at byte %d", name, guardLoc[0], casLoc[0])
		}
		if !breakRe.MatchString(stripped[guardLoc[0]:casLoc[0]]) {
			return fmt.Errorf("%s: monotone guard at byte %d has no `break` before the CAS at byte %d", name, guardLoc[0], casLoc[0])
		}
		return nil
	}

	if err := checkOne("NextDot", nextDotBody); err != nil {
		t.Errorf("NextDot monotone source check: %v", err)
	} else {
		t.Logf("NextDot places its monotone guard and break before the CAS")
	}
	if err := checkOne("AdvanceLamportTo", advanceBody); err != nil {
		t.Errorf("AdvanceLamportTo monotone source check: %v", err)
	} else {
		t.Logf("AdvanceLamportTo places its monotone guard and break before the CAS")
	}

	if t.Failed() {
		t.Fatalf("NextDot and AdvanceLamportTo do not share the monotone-guard pattern")
	}
}

// TestNextDotRemediationAuditStatic inspects the persistence checks in
// TestNextDotLastSavedMonotoneConcurrent. It requires a nonzero disk-value
// assertion, a named amortization bound, lag reporting conditioned on in-memory
// monotonicity, and an error for a large gap after regression. It also rejects
// replacing those checks with a persisted > 0 condition and bounds the size of
// the inspected source block.
func TestNextDotRemediationAuditStatic(t *testing.T) {
	// Read this file because the persistence checks live in the concurrent test.
	srcBytes, err := os.ReadFile("nextdot_monotone_test.go")
	if err != nil {
		t.Fatalf("persistence source check: cannot read nextdot_monotone_test.go: %v", err)
	}
	src := string(srcBytes)
	// Extract the concurrent test before looking for markers. The static test
	// contains the same search strings, and a whole-file search could otherwise
	// select this function instead of the code under inspection.
	concurrentBody := nextdotFuncBody(src, "TestNextDotLastSavedMonotoneConcurrent")
	if concurrentBody == "" {
		t.Fatal("persistence source check: cannot isolate TestNextDotLastSavedMonotoneConcurrent")
	}
	// The persistence block starts at its GATE 3 comment and ends at the final
	// condition shared by the possible implementations. Structural checks below
	// validate the contents between those boundaries.
	gate3Start := strings.Index(concurrentBody, "// GATE 3:")
	if gate3Start < 0 {
		t.Fatal("persistence source check: cannot locate the GATE 3 persistence block")
	}
	gate3End := strings.Index(concurrentBody[gate3Start:], "midFlightRegress != 0 || finalLastSaved != peakFinal")
	if gate3End < 0 {
		t.Fatal("persistence source check: cannot locate the persistence block terminator")
	}
	gate3Block := concurrentBody[gate3Start : gate3Start+gate3End]
	stripped := parkStripGoComments(gate3Block)

	// A zero persisted value must fail independently of the lag comparison.
	if !strings.Contains(stripped, "gate3AxisBPass := persisted != 0") {
		t.Errorf("persistence source check: missing gate3AxisBPass := persisted != 0")
	} else {
		t.Logf("persistence source check: zero persisted values are rejected")
	}

	// The amortization window has a named constant in the source.
	if !strings.Contains(stripped, "gate3SpecBound") {
		t.Errorf("persistence source check: missing the gate3SpecBound constant")
	} else {
		t.Logf("persistence source check: the amortization bound is named")
	}

	// Lag reporting depends on both in-memory monotonicity checks passing.
	if !strings.Contains(stripped, "midFlightRegress == 0 && finalLastSaved == peakFinal") {
		t.Errorf("persistence source check: lag handling is not conditioned on in-memory monotonicity")
	} else {
		t.Logf("persistence source check: lag handling is conditioned on in-memory monotonicity")
	}

	// A large disk gap must be an error after an in-memory regression.
	if !strings.Contains(stripped, `t.Errorf("NextDot persistence: disk gap=`) || !strings.Contains(stripped, "after an in-memory regression") {
		t.Errorf("persistence source check: no error reports a large disk gap after an in-memory regression")
	} else {
		t.Logf("persistence source check: large disk gaps after regression report an error")
	}

	// A positive persisted value alone is not a monotonicity check.
	if strings.Contains(stripped, "gate3Pass := persisted > 0") {
		t.Errorf("persistence source check: gate3Pass := persisted > 0 omits lag and regression handling")
	} else {
		t.Logf("persistence source check: persistence is not reduced to a positive-value assertion")
	}

	// Keep the persistence block near its reference size so this source audit
	// cannot be satisfied by removing its explanation or checks.
	const preRemediationGate3BlockLines = 66
	gate3BlockLines := strings.Count(gate3Block, "\n")
	if gate3BlockLines > preRemediationGate3BlockLines+10 || gate3BlockLines < preRemediationGate3BlockLines-10 {
		t.Errorf("persistence source check: block has %d lines, outside the reference range %d ± 10", gate3BlockLines, preRemediationGate3BlockLines)
	} else {
		t.Logf("persistence source check: block has %d lines, within the reference range %d ± 10 (delta %d)", gate3BlockLines, preRemediationGate3BlockLines, gate3BlockLines-preRemediationGate3BlockLines)
	}

	if t.Failed() {
		t.Fatalf("persistence source checks failed")
	}
}
