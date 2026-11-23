// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover the commit window in the PutLocals durability path
// (ADR-0045 §7).
//
// InsertLocalEventsBatch mutates visible engine state and fsyncs the WAL inside
// bridge.PutLocals, then records gossip payloads after it returns. Between the
// first InsertLocal and payload recording, a sweep can see entries that have no
// payload on the wire path. One measured run counted these as misses for 73
// rounds. An in-flight commit must instead be counted as pending and must not
// ship before fsync. An entry left behind by a failed WAL append remains a
// payload miss because the origin cannot ship it until the client retries.
//
// chaos.WAL.SetSyncHookForTest replaces w.sync. Blocking that hook holds a real
// batch inside PutLocals with state mutated, WAL fsync incomplete, and payloads
// unrecorded. The test controls the window through the same fsync that gates
// production gossip, without relying on timing or a fake clock.
//
// Run the suite with:
//
//	go test -run 'TestInFlightCommitIsNotAPayloadMiss|TestOrphanedEntryStillCountsAsMiss|TestForeignRelayUnaffectedByCommitWindow|TestCommitWindowMeasure|TestOversendBytes' -race -count=1 -v ./pkg/mesh/

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// newCommitWindowMesh builds a two-node loopback TLS batchMesh with the real
// transport, receiver, and Publish path. It binds A to a real WAL through
// SetBridge, so InsertLocalEventsBatch uses durable PutLocals and the test can
// control fsync with the WAL sync hook.
func newCommitWindowMesh(t *testing.T) (*batchMesh, *chaos.WAL) {
	t.Helper()
	seedA := make([]byte, 32)
	seedB := make([]byte, 32)
	for i := range seedA {
		seedA[i] = byte(i + 3)
		seedB[i] = byte(i + 71)
	}
	identA, err := NewNodeIdentity(seedA)
	if err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}
	m := newBatchMesh(t, 100, identA, identB)
	wal, err := chaos.OpenWAL(filepath.Join(t.TempDir(), "commitwindow-a.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	m.gA.SetBridge(durability.NewBridge(m.engineA, wal, 0))
	return m, wal
}

func commitWindowItems(prefix string, n int) []BatchItem {
	items := make([]BatchItem, n)
	for i := range items {
		items[i] = BatchItem{
			EntityID: fmt.Sprintf("%s-%d", prefix, i),
			Payload:  fmt.Sprintf("payload-%010d", i),
			Entry:    eng.CRDTEntry{SystemTime: int64(1_700_100_000 + i), H3Index: uint64(i)},
		}
	}
	return items
}

// TestInFlightCommitIsNotAPayloadMiss holds a 100-key batch inside PutLocals
// with fsync blocked. A sweep must ship none of those entries, report 100 as
// pending, and count none as misses. After fsync is released, the next sweep
// must ship the entire batch.
func TestInFlightCommitIsNotAPayloadMiss(t *testing.T) {
	m, wal := newCommitWindowMesh(t)
	defer m.close()

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	wal.SetSyncHookForTest(func() error {
		once.Do(func() { close(entered) })
		<-release // every fsync parks until the test opens the gate; open stays open
		return nil
	})

	const N = 100
	batchDone := make(chan error, 1)
	go func() {
		_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commitwindow-inflight", N))
		batchDone <- err
	}()
	<-entered // State has 100 entries; fsync is blocked and their payloads are not cached.

	stWindow := m.gA.AntiEntropySweep(context.Background())
	if stWindow.shippedEnvelopes != 0 {
		t.Fatalf("durability violation: the sweep shipped %d envelope(s) while the batch's WAL fsync was blocked — gossiping state the origin has not committed is forbidden (ADR-0045 §4)", stWindow.shippedEnvelopes)
	}
	if stWindow.payloadMisses != 0 {
		t.Fatalf("in-flight commit counted as %d payload misses; want pending classification with zero misses (ADR-0045 §7): %+v", stWindow.payloadMisses, stWindow)
	}
	if stWindow.payloadPending != N {
		t.Fatalf("classification missing: the sweep must still walk the in-flight entries and count them as pending (%d), got pending=%d — a 'fix' that drops them from the walk (or never classifies) is invisible to this counter and forbidden (st=%+v)", N, stWindow.payloadPending, stWindow)
	}
	t.Logf("window sweep: misses=%d shipped_env=%d entries_shipped=%d (the in-flight batch was invisible to the wire, by construction — entries counts published entries, so 0 here)",
		stWindow.payloadMisses, stWindow.shippedEnvelopes, stWindow.shippedEntries)

	close(release)
	if err := <-batchDone; err != nil {
		t.Fatalf("InsertLocalEventsBatch: %v", err)
	}

	stAfter := m.gA.AntiEntropySweep(context.Background())
	// shippedEntries counts published entries only (ADR-0045 §7), not
	// entries merely visited by the walk. A full ship of N keys therefore
	// reports N. Any visited self entry that is neither shipped, pending, nor
	// counted as an orphan miss breaks the accounting identity.
	if stAfter.shippedEnvelopes != 1 || stAfter.shippedEntries != N || stAfter.payloadMisses != 0 {
		t.Fatalf("post-commit ship broken: after the fsync landed, the next sweep must ship the whole batch — got shipped_env=%d entries=%d (want 1 envelope, entries=%d published) misses=%d. The fix may not trade the false-miss for a lost ship.",
			stAfter.shippedEnvelopes, stAfter.shippedEntries, N, stAfter.payloadMisses)
	}
	t.Logf("post-commit: released batch shipped whole — shipped_env=%d entries=%d misses=%d",
		stAfter.shippedEnvelopes, stAfter.shippedEntries, stAfter.payloadMisses)
}

// TestOrphanedEntryStillCountsAsMiss fails a batch fsync after InsertLocal has
// changed engine state. Those entries have no recorded payload and cannot ship
// until the client retries after its 503 response. Unlike in-flight entries,
// they must remain payload misses.
func TestOrphanedEntryStillCountsAsMiss(t *testing.T) {
	m, wal := newCommitWindowMesh(t)
	defer m.close()

	wal.SetSyncHookForTest(func() error { return errors.New("commitwindow injected fsync failure") })

	const N = 100
	_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commitwindow-orphan", N))
	if err == nil {
		t.Fatalf("premise broken: the batch must FAIL (its fsync was injected-failed) so the caller 503s and nothing is recorded")
	}

	st := m.gA.AntiEntropySweep(context.Background())
	if st.payloadMisses != N {
		t.Fatalf("defect counter regressed: %d orphaned entries (InsertLocal ran, WAL append failed, no record is ever coming) must count as %d payload misses, got %d. misses is the only steady-state desync signal the sweep has — a fix that silences it converts a loud defect into silent divergence.",
			N, N, st.payloadMisses)
	}
	if st.relayMisses != 0 {
		t.Fatalf("split violation: orphaned self entries must count on misses only — relay_misses=%d moved for a shape with zero foreign entries", st.relayMisses)
	}
	if st.shippedEnvelopes != 0 {
		t.Fatalf("durability violation: shipped %d envelopes for entries whose WAL write failed", st.shippedEnvelopes)
	}
	t.Logf("orphan check: %d orphaned entries counted as %d payload misses", N, st.payloadMisses)
}

// TestForeignRelayUnaffectedByCommitWindow blocks fsync for a local batch while
// A holds a retained batch from B. The sweep must classify A's entries as
// pending without suppressing relay of B's entries; pending classification
// applies only to the local branch.
func TestForeignRelayUnaffectedByCommitWindow(t *testing.T) {
	m, wal := newCommitWindowMesh(t)
	defer m.close()
	m.gB.SetBatchSize(100)       // B ships batches, so A retains via the batch path
	m.gA.WireRelayHooks(m.recvA) // the production wiring seam (batch retainer wiring)

	// B originates 5 keys and ships them to A for real (B→A sweep).
	for i := 0; i < 5; i++ {
		m.gB.InsertLocalEvents(fmt.Sprintf("commitwindow-foreign-%d", i), "v",
			eng.CRDTEntry{SystemTime: int64(1_700_300_000 + i), H3Index: uint64(i)})
	}
	m.gB.AntiEntropySweep(context.Background())
	// A's accept loop applies asynchronously — wait until A's state holds all 5
	// (retention happens in the same accept, so lookupBatch is armed by then).
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := 0
		// PointGet avoids rebuilding the merged view on every poll.
		for i := 0; i < 5; i++ {
			if len(m.engineA.PointGet(fmt.Sprintf("commitwindow-foreign-%d", i))) > 0 {
				n++
			}
		}
		if n == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("premise broken: A never received B's 5-key batch (relay-retain unwired?)")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Open A's commit window: 100 self keys inside PutLocals, fsync blocked.
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	wal.SetSyncHookForTest(func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	batchDone := make(chan error, 1)
	go func() {
		_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commitwindow-self-during-relay", 100))
		batchDone <- err
	}()
	<-entered

	st := m.gA.AntiEntropySweep(context.Background())
	if st.payloadMisses != 0 {
		t.Fatalf("orphan misses during a commit window: got %d, want 0 (the window must classify self entries as pending)", st.payloadMisses)
	}
	if st.payloadPending != 100 {
		t.Fatalf("pending classification wrong: got %d, want 100 (the in-flight self batch)", st.payloadPending)
	}
	if st.shippedEnvelopes != 1 {
		t.Fatalf("foreign relay during A's commit window: got shipped_env=%d, want 1 byte-identical envelope; pending local entries must not suppress the foreign branch",
			st.shippedEnvelopes)
	}
	close(release)
	if err := <-batchDone; err != nil {
		t.Fatalf("InsertLocalEventsBatch: %v", err)
	}
	t.Logf("foreign relay: during a 100-key in-flight local commit, the sweep relayed the retained foreign batch (shipped_env=%d) with local pending=%d and misses=%d",
		st.shippedEnvelopes, st.payloadPending, st.payloadMisses)
}

// TestCommitWindowMeasure reports, without asserting performance thresholds,
// the observed pending population, the tail after the last batch acknowledgment,
// a slow-commit straggler, and ingest cost with sweeps enabled and disabled.
// The measurements appear in verbose test output.
func TestCommitWindowMeasure(t *testing.T) {
	// Population tracks the in-flight window.
	// A 25ms injected fsync emulates the loaded-NVMe commit latency so ~all 10
	// workers are mid-batch at any instant; the sweep sampler records the misses
	// population it observes.
	m, wal := newCommitWindowMesh(t)
	defer m.close()
	const commitLat = 25 * time.Millisecond
	wal.SetSyncHookForTest(func() error { time.Sleep(commitLat); return nil })

	const workers, batchesPerWorker, batchSize = 10, 10, 100 // 10 workers each write 10 batches of 100 keys
	type sweepSample struct {
		at      time.Duration
		misses  int
		pending int
		shipped int
	}
	var (
		samplesMu sync.Mutex
		samples   []sweepSample
		wallsMu   sync.Mutex
		walls     []time.Duration
	)
	start := time.Now()
	stop := make(chan struct{})
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			st := m.gA.AntiEntropySweep(context.Background())
			samplesMu.Lock()
			samples = append(samples, sweepSample{time.Since(start), st.payloadMisses, st.payloadPending, st.shippedEnvelopes})
			samplesMu.Unlock()
		}
	}()

	var injectWG sync.WaitGroup
	for w := 0; w < workers; w++ {
		injectWG.Add(1)
		go func(w int) {
			defer injectWG.Done()
			for b := 0; b < batchesPerWorker; b++ {
				t0 := time.Now()
				if _, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems(fmt.Sprintf("commitwindow-measure-w%d-b%d", w, b), batchSize)); err != nil {
					t.Errorf("batch w%d b%d: %v", w, b, err)
					return
				}
				wallsMu.Lock()
				walls = append(walls, time.Since(t0))
				wallsMu.Unlock()
			}
		}(w)
	}
	injectWG.Wait()
	lastACK := time.Since(start)
	// AntiEntropySweep is single-goroutine, and its memo is not synchronized.
	// Stop the sampler before the tail loop so its sweeps cannot overlap the
	// tail's sweeps and race on that state.
	close(stop)
	sweepWG.Wait()

	// The tail: sweep until the first sweep with nothing unshippable (no orphan
	// misses and nothing pending), measuring from the last batch ACK.
	for {
		st := m.gA.AntiEntropySweep(context.Background())
		if st.payloadMisses == 0 && st.payloadPending == 0 {
			break
		}
	}
	tail := time.Since(start) - lastACK

	maxMiss, maxPend, nonzeroSweeps, pendingSweeps := 0, 0, 0, 0
	samplesMu.Lock()
	for _, s := range samples {
		if s.misses > maxMiss {
			maxMiss = s.misses
		}
		if s.pending > maxPend {
			maxPend = s.pending
		}
		if s.misses > 0 {
			nonzeroSweeps++
		}
		if s.pending > 0 {
			pendingSweeps++
		}
	}
	samplesMu.Unlock()
	p50, p99, wmax := commitWindowPercentiles(walls)
	t.Logf("population measurement (commitLat=%s, %d workers x %d x %d keys):", commitLat, workers, batchesPerWorker, batchSize)
	t.Logf("  per-batch wall: p50=%s p99=%s max=%s (n=%d)", p50, p99, wmax, len(walls))
	t.Logf("  sweep sampler: %d sweeps, %d with misses>0, %d with pending>0, max misses=%d, max pending=%d (predicted in-flight population ~= workers x batchSize = %d)", len(samples), nonzeroSweeps, pendingSweeps, maxMiss, maxPend, workers*batchSize)
	t.Logf("  inject wall (last ACK) = %s; tail (last ACK -> first clean sweep) = %s", lastACK, tail)

	// Hold one batch in fsync for two seconds after the other calls return.
	// Sweeps during that interval show what a convergence measurement would
	// observe if its clock stopped while this commit remained outstanding.
	m2, wal2 := newCommitWindowMesh(t)
	defer m2.close()
	slow := make(chan struct{})
	var slowOnce sync.Once
	wal2.SetSyncHookForTest(func() error {
		slowOnce.Do(func() { close(slow); time.Sleep(2 * time.Second) })
		return nil
	})
	stragglerDone := make(chan struct{})
	go func() {
		_, _, _ = m2.gA.InsertLocalEventsBatch(commitWindowItems("commitwindow-straggler", batchSize))
		close(stragglerDone)
	}()
	<-slow
	clockStop := time.Now() // Model a convergence clock started after the other batches returned.
	missesWhileStraggler := 0
	pendingWhileStraggler := 0
	sweepsWhileStraggler := 0
	for {
		select {
		case <-stragglerDone:
			goto stragglerLanded
		default:
		}
		st := m2.gA.AntiEntropySweep(context.Background())
		sweepsWhileStraggler++
		missesWhileStraggler += st.payloadMisses
		pendingWhileStraggler += st.payloadPending
	}
stragglerLanded:
	stragglerTail := time.Since(clockStop)
	stFinal := m2.gA.AntiEntropySweep(context.Background())
	t.Logf("straggler measurement: clock stopped at last return; straggler committed %s later", stragglerTail)
	t.Logf("  sweeps during the window: %d, misses observed: %d, pending observed: %d (these observations fall inside the convergence interval)", sweepsWhileStraggler, missesWhileStraggler, pendingWhileStraggler)
	t.Logf("  first post-commit sweep: misses=%d pending=%d shipped_env=%d entries=%d", stFinal.payloadMisses, stFinal.payloadPending, stFinal.shippedEnvelopes, stFinal.shippedEntries)

	// Ingest with the sweep on vs off.
	for _, on := range []bool{false, true} {
		mX, _ := newCommitWindowMesh(t)
		defer mX.close()
		// Use real fsync with no hook to measure the local-disk commit window.
		var wgX sync.WaitGroup
		stopX := make(chan struct{})
		var ends []time.Duration // per-batch completion times for the ingest-rate curve
		var endsMu sync.Mutex
		var sweepWG2 sync.WaitGroup
		sweepWG2.Add(1)
		go func() {
			defer sweepWG2.Done()
			for {
				select {
				case <-stopX:
					return
				default:
				}
				if on {
					mX.gA.AntiEntropySweep(context.Background())
				} else {
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
		startX := time.Now()
		for w := 0; w < workers; w++ {
			wgX.Add(1)
			go func(w int) {
				defer wgX.Done()
				for b := 0; b < batchesPerWorker; b++ {
					_, _, _ = mX.gA.InsertLocalEventsBatch(commitWindowItems(fmt.Sprintf("commitwindow-onoff-%v-w%d-b%d", on, w, b), batchSize))
					endsMu.Lock()
					ends = append(ends, time.Since(startX))
					endsMu.Unlock()
				}
			}(w)
		}
		wgX.Wait()
		close(stopX)
		sweepWG2.Wait()
		wall := time.Since(startX)
		t.Logf("ingest comparison: 10,000 keys (10x10x100), sweep enabled=%v: wall=%s (%.0f keys/s) [four-core host, tmpfs and ext4; relative measurement]",
			on, wall, float64(workers*batchesPerWorker*batchSize)/wall.Seconds())
		t.Logf("ingest-rate curve, sweep enabled=%v (decile keys/s): %s", on, commitWindowCurve(ends, batchSize))
	}
}

// TestOversendBytes measures the sweep's transmission cost with a real
// 100-entry batch and a signed, length-prefixed envelope. At the measured
// shape of 35 peers and 100 batches per peer, the sweep repeatedly ships every
// key, including after convergence. The test reports the resulting bytes per
// node and per 34-node host for each round.
func TestOversendBytes(t *testing.T) {
	m, _ := newCommitWindowMesh(t)
	defer m.close()

	// 100 real entries on A (the measured batch size).
	const N = 100
	var keys []string
	for i := 0; i < N; i++ {
		k := fmt.Sprintf("commitwindow-oversend-%d", i)
		m.gA.InsertLocalEvents(k, fmt.Sprintf("payload-%010d", i), eng.CRDTEntry{SystemTime: int64(1_700_600_000 + i), H3Index: uint64(i)})
		keys = append(keys, k)
	}
	events := make([]BuiltEvent, 0, N)
	for _, k := range keys {
		ents := m.engineA.PointGet(k) // Avoid rebuilding the merged State view for each key.
		e := ents[0]
		payload, ok := m.gA.cache.lookup(k, eng.CausalDot{NodeID: e.DotNodeID, Counter: e.DotCounter})
		if !ok {
			t.Fatalf("premise: payload missing for %s", k)
		}
		events = append(events, BuiltEvent{EntityID: k, Payload: payload, Entry: e})
	}
	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		t.Fatalf("BuildCRDTDeltaBatch: %v", err)
	}
	// The envelope as ShipBatch mints it: sign + MarshalBatchEnvelope + length prefix.
	sig, err := identity.SignCRDTFrame(m.gA.owner.Seed, batchWire)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)
	env := attribution.MarshalBatchEnvelope(m.gA.owner.NodeID, sigArr, 1, 1, batchWire)
	prefixed := receive.LengthPrefixFrame(env)

	const peers, batchesPerPeer, nodesPerHost = 35, 100, 34 // the measured shape (run 10)
	perEnv := len(prefixed)
	perRoundNode := peers * batchesPerPeer * perEnv
	perRoundHost := perRoundNode * nodesPerHost
	t.Logf("oversend bytes: payload≈%dB/key; batchWire(100 entries)=%dB; envelope(prefixed)=%dB ⇒ %.1f B/entry on the wire",
		len("payload-0000000000"), len(batchWire), perEnv, float64(perEnv)/N)
	t.Logf("oversend bytes: %d peers × %d batches × %dB = %.1f MB/round/node; × %d nodes/host = %.1f MB/round/host of TLS writes — forever, including at converged steady state (the correct steady-state answer is ~0)",
		peers, batchesPerPeer, perEnv, float64(perRoundNode)/1e6, nodesPerHost, float64(perRoundHost)/1e6)
}

// commitWindowCurve sorts per-batch completion times and reports keys per
// second within each decile of completions, exposing changes over time that a
// single average would hide.
func commitWindowCurve(ends []time.Duration, batchSize int) string {
	if len(ends) < 10 {
		return "n/a"
	}
	sorted := make([]time.Duration, len(ends))
	copy(sorted, ends)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var b strings.Builder
	dec := len(sorted) / 10
	prev := time.Duration(0)
	for i := 0; i < 10; i++ {
		hi := sorted[(i+1)*dec-1]
		rate := float64(dec*batchSize) / (hi - prev).Seconds()
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.0fk", rate/1000)
		prev = hi
	}
	return b.String()
}

// commitWindowPercentiles returns p50/p99/max of the batch wall times.
func commitWindowPercentiles(d []time.Duration) (p50, p99, max time.Duration) {
	if len(d) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(d))
	copy(sorted, d)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted[len(sorted)/2], sorted[(len(sorted)*99)/100], sorted[len(sorted)-1]
}
