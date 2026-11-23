// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover exchange-latency instrumentation (ADR-0072) on two
// in-process nodes over loopback; they make no fleet claims. Counters always
// run, while SOVEREIGN_DIGEST_LATENCY_DEBUG gates the log lines.
//
// The completed case requires a real exchange and latency line. The drained
// case delays a responder beyond the wait, deposits its late response in the
// capacity-one channel, and drains it during the next registration; the
// build_to_drain span must include the responder delay. The silence case checks
// that counters still advance without debug logging. Finally, a fault injection
// zeroes the wire stamp: the deposit must increment digestStampBroken and log
// BROKEN-STAMP without emitting a meaningless build_to_drain span.

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// latencyCaptureLog swaps the global logger for a buffer; restored at cleanup.
func latencyCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// latencySyncResponders establishes a happens-before edge with every responder
// rather than relying on a sleep. A responder holds one sem token from
// enqueueDigestResponse until its deferred release after the build, ship, and
// log write. The bounded poll first waits for held tokens to reach zero. Filling
// all digestRespondMaxConcurrent slots then uses the buffered-channel
// (k+C)-th-send rule to synchronize with every earlier release, making all
// responder log writes visible to subsequent buffer reads. A stuck responder
// keeps its slot and fails the bounded wait.
func latencySyncResponders(t *testing.T, m *DeferMesh) {
	t.Helper()
	// Acquisition sends a token and the deferred release receives it. Do not
	// drain sem while polling: receiving an in-flight responder's token would
	// steal its slot and destroy the synchronization argument. Once len(sem) is
	// zero, sending digestRespondMaxConcurrent tokens fills the empty buffer;
	// the final send happens after every release and therefore after every log
	// write. The tokens remain held to prevent new responder work during reads.
	deadline := time.Now().Add(2 * time.Second)
	for _, g := range []*Gossiper{m.gA, m.gB} {
		sem := g.respondSem
		if sem == nil {
			t.Fatalf("respondSem nil — the mesh's responder sem was never allocated")
		}
		for len(sem) != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: responder slots still held (len=%d) after the 2 s bounded wait; a responder goroutine has not exited", t.Name(), len(sem))
			}
			time.Sleep(25 * time.Millisecond)
		}
		for i := 0; i < digestRespondMaxConcurrent; i++ {
			sem <- struct{}{} // has room by construction (empty + cap 16); the (k+16)-th-send edge
		}
	}
}

// TestLatencyInstrumentCompleted requires the completedDigests counter and,
// with debug logging enabled, a COMPLETED line carrying a real span.
func TestLatencyInstrumentCompleted(t *testing.T) {
	t.Setenv("SOVEREIGN_DIGEST_LATENCY_DEBUG", "1")
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepRound(t, m)
	// Mesh goroutines can write the global logger until teardown. Close the mesh
	// to cancel and join the serve goroutines before reading the captured buffer;
	// latencySyncResponders then synchronizes with the remaining responders.
	m.close()
	latencySyncResponders(t, m)
	if c := m.gA.digestExchCompleted.Load(); c < 1 {
		t.Fatalf("completedDigests=%d, want ≥1 — the exchange completed but the instrument did not count it (the counter passes without exercising the defect)", c)
	}
	if !strings.Contains(buf.String(), "digest-latency COMPLETED") {
		t.Fatalf("debug logging enabled but no COMPLETED latency line was emitted")
	}
}

// TestLatencyInstrumentDrained uses a 200 ms responder delay and a 5 ms wait.
// The late response must deposit, drain on the next round, increment the
// counter, and produce a build_to_drain span that includes the delay.
func TestLatencyInstrumentDrained(t *testing.T) {
	t.Setenv("SOVEREIGN_DIGEST_LATENCY_DEBUG", "1")
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 5 * time.Millisecond})
	defer m.cancel()
	// Hold B's responder slot for 200 ms to force a late response.
	m.gB.digestResponderDelayMs.Store(200)
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepAOnly(t, m)                  // round 1: A's wait expires at 5 ms (the T1 pattern)
	time.Sleep(400 * time.Millisecond)     // B's late response deposits (~200 ms after the request)
	deferInsert(t, m.gA, "k%04d", 100, 10) // fresh divergence: round 2's gate must fire (a converged pair skips)
	deferSweepAOnly(t, m)                  // round 2's registration drains the late deposit
	// Mesh goroutines can write the global logger until teardown. Close the mesh
	// to cancel and join the serve goroutines before reading the captured buffer;
	// latencySyncResponders then synchronizes with the remaining responders.
	m.close()
	latencySyncResponders(t, m)
	if d := m.gA.digestExchDrained.Load(); d < 1 {
		t.Fatalf("drainedDigests=%d, want at least 1; the late deposit was not drained and counted", d)
	}
	if b := m.gA.digestStampBroken.Load(); b != 0 {
		t.Fatalf("stampBroken=%d, want 0; a stamped deposit was misclassified as broken", b)
	}
	logged := buf.String()
	if !strings.Contains(logged, "digest-latency DRAINED") {
		t.Fatalf("debug logging enabled but no DRAINED latency line was emitted")
	}
	// The responder held the slot for 200 ms before building. Require at least
	// 100 ms in build_to_drain, leaving margin for scheduling jitter.
	i := strings.Index(logged, "build_to_drain_ms=")
	if i < 0 {
		t.Fatalf("the DRAINED line carries no build_to_drain_ms= token")
	}
	rest := logged[i+len("build_to_drain_ms="):]
	end := strings.IndexAny(rest, " \n")
	if end < 0 {
		end = len(rest)
	}
	ms, err := strconv.Atoi(rest[:end])
	if err != nil {
		t.Fatalf("build_to_drain_ms unparseable: %q", rest[:end])
	}
	if ms < 100 {
		t.Fatalf("build_to_drain_ms=%d, want ≥100 — the 200 ms responder delay did not reach the wire stamp (the instrument measures channel-sitting, not the response path)", ms)
	}
}

// TestLatencyInstrumentEnvSilence leaves debug logging disabled. Counters must
// still advance so runtime behavior can be observed without enabling logs, but
// no digest-latency lines may appear.
func TestLatencyInstrumentEnvSilence(t *testing.T) {
	// Do not set the variable in this case; skip if the ambient environment has
	// already enabled it.
	if os.Getenv("SOVEREIGN_DIGEST_LATENCY_DEBUG") != "" {
		t.Skipf("ambient SOVEREIGN_DIGEST_LATENCY_DEBUG=%q — the off arm cannot run (unset it to exercise the negative-control arm)", os.Getenv("SOVEREIGN_DIGEST_LATENCY_DEBUG"))
	}
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	defer m.cancel()
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepRound(t, m)
	// Mesh goroutines can write the global logger until teardown. Close the mesh
	// to cancel and join the serve goroutines before reading the captured buffer;
	// latencySyncResponders then synchronizes with the remaining responders.
	m.close()
	latencySyncResponders(t, m)
	if c := m.gA.digestExchCompleted.Load(); c < 1 {
		t.Fatalf("completedDigests=%d, want at least 1; counters must advance with debug logging disabled", c)
	}
	if strings.Contains(buf.String(), "digest-latency") {
		t.Fatalf("debug logging disabled but digest-latency lines were emitted")
	}
}

// TestLatencyInstrumentBrokenStamp zeroes the wire stamp with a fault
// injection. The drained deposit must count as broken and log BROKEN-STAMP, but
// must not produce a build_to_drain span derived from a zero timestamp.
func TestLatencyInstrumentBrokenStamp(t *testing.T) {
	t.Setenv("SOVEREIGN_DIGEST_LATENCY_DEBUG", "1")
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 5 * time.Millisecond})
	defer m.cancel()
	digestStampBugInject.Store(true)
	t.Cleanup(func() { digestStampBugInject.Store(false) })
	m.gB.digestResponderDelayMs.Store(200)
	buf := latencyCaptureLog(t)
	deferInsert(t, m.gA, "k%04d", 0, 10)
	deferSweepAOnly(t, m)
	time.Sleep(400 * time.Millisecond)
	deferInsert(t, m.gA, "k%04d", 100, 10)
	deferSweepAOnly(t, m)
	// Mesh goroutines can write the global logger until teardown. Close the mesh
	// to cancel and join the serve goroutines before reading the captured buffer;
	// latencySyncResponders then synchronizes with the remaining responders.
	m.close()
	latencySyncResponders(t, m)
	if b := m.gA.digestStampBroken.Load(); b < 1 {
		t.Fatalf("stampBroken=%d, want at least 1; the unstamped deposit was not classified as broken", b)
	}
	if d := m.gA.digestExchDrained.Load(); d < 1 {
		t.Fatalf("drainedDigests=%d, want at least 1; broken deposits must also advance the drained counter", d)
	}
	logged := buf.String()
	if !strings.Contains(logged, "BROKEN-STAMP") {
		t.Fatalf("debug logging enabled but no BROKEN-STAMP line was emitted")
	}
	if strings.Contains(logged, "build_to_drain_ms") {
		t.Fatalf("build_to_drain_ms was emitted for a broken stamp; unstamped deposits must not produce a span")
	}
}
