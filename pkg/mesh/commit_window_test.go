// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// commit_window_test.go — the COMMIT-WINDOW
// guards + the in-process decomposition measurement.
//
// THE DEFECT UNDER TEST (ADR-0045): InsertLocalEventsBatch mutates the
// engine's VISIBLE state and fsyncs the WAL inside bridge.PutLocals, and records
// the gossip payloads ONLY AFTER it returns (gossip.go:1107-1117 — the order:
// NEVER gossip state the origin has not committed). Between the first InsertLocal
// and the record loop, a sweep sees state entries whose payloads are unrecorded
// and counts them as payload MISSES (batch.go:477-485) — on silicon this was the
// seed missing its OWN keys for 73 sweep rounds. An in-flight commit is
// NOT a defect: the sweep must not count it, must not ship it (— nothing may
// ship before the WAL fsync completes, and the payload does not exist on the wire
// path before record), and MUST still count a genuinely ORPHANED entry (a batch
// whose WAL append FAILED after InsertLocal ran — state the origin will never be
// able to ship until the client retries).
//
// THE SEAM THAT MAKES THE WINDOW DETERMINISTIC: chaos.WAL.SetSyncHookForTest
// replaces w.sync (wal.go:142). A hook that BLOCKS holds a real batch inside
// PutLocals — state mutated, WAL unfsynced, payloads unrecorded — for exactly as
// long as the test chooses. No timing luck, no fake clock: the window is held open
// by the same fsync that gates it in production.
//
// RED→GREEN DISCIPLINE: the in-flight leg asserts the POST-FIX semantics and is
// therefore RED on the pre-fix bytes (misses=100); the orphan leg must stay GREEN
// across the fix (it is the anti-tautology: the fix may not "close" the defect by
// silently never counting again). Run:
//
//	go test -run 'Test(InFlightCommit|OrphanedEntry|ForeignRelay|CommitWindow|OversendBytes)' -race -count=1 -v ./pkg/mesh/

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

// newCommitWindowMesh builds the 2-node loopback TLS mesh (the batchMesh fixture:
// real transport, real receiver, real Publish) and binds A to a REAL WAL via the
// production SetBridge seam, so A's InsertLocalEventsBatch takes the durable
// PutLocals path (the silicon path) with the test's sync hook on the fsync.
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
	wal, err := chaos.OpenWAL(filepath.Join(t.TempDir(), "commit-window-a.wal"))
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

// TestInFlightCommitIsNotAPayloadMiss is the LOAD-BEARING guard.
// It holds a 100-key batch inside PutLocals (fsync blocked) and sweeps: the
// sweep must ship NOTHING and count NOTHING (an in-flight commit is not a
// defect). It then releases the fsync: the next sweep must ship all 100 (no loss).
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
		_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commit-window-inflight", N))
		batchDone <- err
	}()
	<-entered // DETERMINISTIC WINDOW: 100 InsertLocal'd in state, WAL mid-fsync, payloadCache empty for these keys

	stWindow := m.gA.AntiEntropySweep(context.Background())
	if stWindow.shippedEnvelopes != 0 {
		t.Fatalf(" VIOLATION: the sweep shipped %d envelope(s) while the batch's WAL fsync was BLOCKED — gossiping state the origin has not committed is the forbidden fix (ADR-0045)", stWindow.shippedEnvelopes)
	}
	if stWindow.payloadMisses != 0 {
		t.Fatalf("STARTING-LINE DEFECT (ADR-0045 step 2): the sweep counted %d payload misses for an IN-FLIGHT COMMIT — on silicon this is the seed missing its OWN keys for 73 rounds (the run: 20,259 capped log lines, 277.5/round ≈ 35 peers × missLogCap 8). An in-flight commit is not a defect: the sweep must classify it as pending, not as a miss. (st=%+v)", stWindow.payloadMisses, stWindow)
	}
	if stWindow.payloadPending != N {
		t.Fatalf("CLASSIFICATION MISSING: the sweep must still WALK the in-flight entries and count them as pending (%d), got pending=%d — a 'fix' that drops them from the walk (or never classifies) is invisible to this counter and forbidden (st=%+v)", N, stWindow.payloadPending, stWindow)
	}
	t.Logf("WINDOW SWEEP: misses=%d shipped_env=%d entries_shipped=%d (the in-flight batch was invisible to the wire, by construction —: entries counts PUBLISHED entries, so 0 here)",
		stWindow.payloadMisses, stWindow.shippedEnvelopes, stWindow.shippedEntries)

	close(release)
	if err := <-batchDone; err != nil {
		t.Fatalf("InsertLocalEventsBatch: %v", err)
	}

	stAfter := m.gA.AntiEntropySweep(context.Background())
	// NOTE on shippedEntries (updated by ADR-0045): the
	// entries counter is PUBLISHED-ONLY now — the walk-top `entries++` that
	// double-counted every shipped entry (N walked + N shipped = 2N) is
	// deleted, because it made the gate identity "entries + pending ==
	// deliverable set" a tautology. A full ship of N keys reads EXACTLY N, and
	// entries + pending == N is the identity with guards: a walked self entry
	// that is neither shipped, pending, nor orphan-missed breaks the sum.
	if stAfter.shippedEnvelopes != 1 || stAfter.shippedEntries != N || stAfter.payloadMisses != 0 {
		t.Fatalf("POST-COMMIT SHIP BROKEN: after the fsync landed, the next sweep must ship the whole batch — got shipped_env=%d entries=%d (want 1 envelope, entries=%d published) misses=%d. The fix may not trade the false-miss for a lost ship.",
			stAfter.shippedEnvelopes, stAfter.shippedEntries, N, stAfter.payloadMisses)
	}
	t.Logf("GREEN (post-commit): released batch shipped whole — shipped_env=%d entries=%d misses=%d",
		stAfter.shippedEnvelopes, stAfter.shippedEntries, stAfter.payloadMisses)
}

// TestOrphanedEntryStillCountsAsMiss is the ANTI-TAUTOLOGY leg: a batch
// whose WAL fsync FAILS leaves InsertLocal'd entries in state that were never
// recorded and never will be (the client got a 503 and must retry). The sweep MUST
// keep counting those as payload misses — the fix classifies IN-FLIGHT as
// non-defect; it may not reclassify ORPHANED the same way.
func TestOrphanedEntryStillCountsAsMiss(t *testing.T) {
	m, wal := newCommitWindowMesh(t)
	defer m.close()

	wal.SetSyncHookForTest(func() error { return errors.New("injected fsync failure") })

	const N = 100
	_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commit-window-orphan", N))
	if err == nil {
		t.Fatalf("premise broken: the batch must FAIL (its fsync was injected-failed) so the caller 503s and nothing is recorded")
	}

	st := m.gA.AntiEntropySweep(context.Background())
	if st.payloadMisses != N {
		t.Fatalf("DEFECT COUNTER REGRESSED: %d orphaned entries (InsertLocal ran, WAL append FAILED, no record is ever coming) must count as %d payload misses, got %d. misses is the only steady-state desync signal the sweep has — a fix that silences it converts a loud defect into silent divergence.",
			N, N, st.payloadMisses)
	}
	if st.relayMisses != 0 {
		t.Fatalf(" split violation: ORPHANED SELF entries must count on misses ONLY — relay_misses=%d moved for a shape with zero foreign entries", st.relayMisses)
	}
	if st.shippedEnvelopes != 0 {
		t.Fatalf(" VIOLATION: shipped %d envelopes for entries whose WAL write FAILED", st.shippedEnvelopes)
	}
	t.Logf("GREEN (anti-tautology): %d orphaned entries still count as %d payload misses — the defect counter survives the fix", N, st.payloadMisses)
}

// TestForeignRelayUnaffectedByCommitWindow is the FOREIGN-branch
// no-regression guard: while a SELF commit is in flight (blocked fsync), a FOREIGN
// entry with a retained batch must STILL relay — the pending classification lives
// in the SELF branch only, and a fix that swallowed foreign relays behind the
// commit window would re-open the one-hop-relay defect (foreign deltas stuck at one hop).
func TestForeignRelayUnaffectedByCommitWindow(t *testing.T) {
	m, wal := newCommitWindowMesh(t)
	defer m.close()
	m.gB.SetBatchSize(100)       // B ships BATCHES, so A retains via the batch path
	m.gA.WireRelayHooks(m.recvA) // the production wiring seam

	// B originates 5 keys and ships them to A for real (B→A sweep).
	for i := 0; i < 5; i++ {
		m.gB.InsertLocalEvents(fmt.Sprintf("commit-window-foreign-%d", i), "v",
			eng.CRDTEntry{SystemTime: int64(1_700_300_000 + i), H3Index: uint64(i)})
	}
	m.gB.AntiEntropySweep(context.Background())
	// A's accept loop applies asynchronously — wait until A's state holds all 5
	// (retention happens in the same accept, so lookupBatch is armed by then).
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := 0
		st := m.engineA.State()
		for i := 0; i < 5; i++ {
			if len(st.Get(fmt.Sprintf("commit-window-foreign-%d", i))) > 0 {
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

	// Open A's commit window: 100 SELF keys inside PutLocals, fsync blocked.
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
		_, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems("commit-window-self-during-relay", 100))
		batchDone <- err
	}()
	<-entered

	st := m.gA.AntiEntropySweep(context.Background())
	if st.payloadMisses != 0 {
		t.Fatalf("orphan misses during a commit window: got %d, want 0 (the window must classify SELF entries as pending)", st.payloadMisses)
	}
	if st.payloadPending != 100 {
		t.Fatalf("pending classification wrong: got %d, want 100 (the in-flight SELF batch)", st.payloadPending)
	}
	if st.shippedEnvelopes != 1 {
		t.Fatalf("FOREIGN RELAY REGRESSION: during A's commit window the retained FOREIGN batch must STILL relay (1 envelope re-published byte-identical) — got shipped_env=%d. The pending classification must not swallow the foreign branch (Root-2 stays closed).",
			st.shippedEnvelopes)
	}
	close(release)
	if err := <-batchDone; err != nil {
		t.Fatalf("InsertLocalEventsBatch: %v", err)
	}
	t.Logf("GREEN (foreign relay): during a 100-key in-flight SELF commit, the sweep relayed the retained FOREIGN batch (shipped_env=%d) while classifying the self entries pending=%d, misses=%d",
		st.shippedEnvelopes, st.payloadPending, st.payloadMisses)
}

// TestCommitWindowMeasure is the (b)/(c)/(d) MEASUREMENT (reports,
// not gates): the in-flight miss population vs concurrency, the tail after the last
// batch ACK, the straggler shape (the silicon starting-line in miniature), and the
// sweep ON/OFF ingest cost. Artifact: the -v output.
func TestCommitWindowMeasure(t *testing.T) {
	// ──: population tracks the in-flight window ──────────────────────
	// A 25ms injected fsync emulates the loaded-NVMe commit latency so ~all 10
	// workers are mid-batch at any instant (the silicon shape); the sweep sampler
	// records the misses population it observes.
	m, wal := newCommitWindowMesh(t)
	defer m.close()
	const commitLat = 25 * time.Millisecond
	wal.SetSyncHookForTest(func() error { time.Sleep(commitLat); return nil })

	const workers, batchesPerWorker, batchSize = 10, 10, 100 // the gate's shape (10 × 100-key batches), 10,000 keys
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
				if _, _, err := m.gA.InsertLocalEventsBatch(commitWindowItems(fmt.Sprintf("commit-window-measure-w%d-b%d", w, b), batchSize)); err != nil {
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
	// Stop the sampler BEFORE the tail loop: AntiEntropySweep is single-goroutine
	// (the SweepLoop discipline — the memo has no synchronization), so
	// the tail's sweeps must not overlap the sampler's. (An early draft of this
	// test overlapped them and ate a "concurrent map read and map write" fatal —
	// a HARNESS race, not a production one.)
	close(stop)
	sweepWG.Wait()

	// The tail: sweep until the first sweep with NOTHING unshippable (no orphan
	// misses AND nothing pending), measuring from the LAST batch ACK (the
	// gate's convStart anchor pre-).
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
	t.Logf("V2-MEASURE step1 (commitLat=%s, %d workers x %d x %d keys):", commitLat, workers, batchesPerWorker, batchSize)
	t.Logf("  per-batch wall: p50=%s p99=%s max=%s (n=%d)", p50, p99, wmax, len(walls))
	t.Logf("  sweep sampler: %d sweeps, %d with misses>0, %d with pending>0, max misses=%d, max pending=%d (predicted in-flight population ~= workers x batchSize = %d)", len(samples), nonzeroSweeps, pendingSweeps, maxMiss, maxPend, workers*batchSize)
	t.Logf("  inject wall (last ACK) = %s; TAIL (last ACK -> first clean sweep) = %s", lastACK, tail)

	// ──: the straggler — the silicon starting line in miniature ──────
	// One batch whose fsync takes 2s while every other call has returned: the
	// driver's clock stops (injectWG.Wait's analog) with the straggler still
	// inside PutLocals. The sweeps in between observe the misses the silicon
	// gate measured as its "convergence SLO".
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
		_, _, _ = m2.gA.InsertLocalEventsBatch(commitWindowItems("commit-window-straggler", batchSize))
		close(stragglerDone)
	}()
	<-slow
	clockStop := time.Now() // the gate would print "injected ..." and start convStart HERE
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
	t.Logf("V2-MEASURE step2 (straggler): clock stopped at last-return; straggler committed %s LATER;", stragglerTail)
	t.Logf("  sweeps during the window: %d, misses observed: %d, pending observed: %d (the SLO-clock defect — those sweeps are the gate's 'convergence' window)", sweepsWhileStraggler, missesWhileStraggler, pendingWhileStraggler)
	t.Logf("  first post-commit sweep: misses=%d pending=%d shipped_env=%d entries=%d", stFinal.payloadMisses, stFinal.payloadPending, stFinal.shippedEnvelopes, stFinal.shippedEntries)

	// ── ingest with the sweep ON vs OFF (the seed node) ───────────────
	for _, on := range []bool{false, true} {
		mX, _ := newCommitWindowMesh(t)
		defer mX.close()
		// real fsync (no hook): the local-disk commit window
		var wgX sync.WaitGroup
		stopX := make(chan struct{})
		var ends []time.Duration // per-batch completion times — the ingest CURVE
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
					_, _, _ = mX.gA.InsertLocalEventsBatch(commitWindowItems(fmt.Sprintf("commit-window-onoff-%v-w%d-b%d", on, w, b), batchSize))
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
		t.Logf("V2-MEASURE step3: ingest 10,000 keys (10x10x100) sweep ON=%v: wall=%s (%.0f keys/s) [4-core box, tmpfs+ext4 mix — RELATIVE number, not the gate]",
			on, wall, float64(workers*batchesPerWorker*batchSize)/wall.Seconds())
		t.Logf("V2-MEASURE step3 curve ON=%v (decile keys/s): %s", on, commitWindowCurve(ends, batchSize))
	}
}

// TestOversendBytes measures the sweep's wire cost in BYTES — the
// post-cost is TRANSMISSION, not compute: at the silicon shape (35
// peers × 100 batches of 100 entries), the sweep ships every key to every peer
// every round, FOREVER, including at converged steady state (B.4). This guard
// measures the per-envelope wire bytes exactly (build a real 100-entry batch,
// marshal the real envelope) and states the multiplication — no "entries"
// hand-waving.
func TestOversendBytes(t *testing.T) {
	m, _ := newCommitWindowMesh(t)
	defer m.close()

	// 100 real entries on A (the silicon batch size).
	const N = 100
	var keys []string
	for i := 0; i < N; i++ {
		k := fmt.Sprintf("commit-window-oversend-%d", i)
		m.gA.InsertLocalEvents(k, fmt.Sprintf("payload-%010d", i), eng.CRDTEntry{SystemTime: int64(1_700_600_000 + i), H3Index: uint64(i)})
		keys = append(keys, k)
	}
	events := make([]BuiltEvent, 0, N)
	for _, k := range keys {
		ents := m.engineA.State().Get(k)
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

	const peers, batchesPerPeer, nodesPerHost = 35, 100, 34 // the silicon shape
	perEnv := len(prefixed)
	perRoundNode := peers * batchesPerPeer * perEnv
	perRoundHost := perRoundNode * nodesPerHost
	t.Logf("V4 OVERSEND BYTES: payload≈%dB/key; batchWire(100 entries)=%dB; envelope(prefixed)=%dB ⇒ %.1f B/entry on the wire",
		len("payload-0000000000"), len(batchWire), perEnv, float64(perEnv)/N)
	t.Logf("V4 OVERSEND BYTES: %d peers × %d batches × %dB = %.1f MB/round/node; × %d nodes/host = %.1f MB/round/host of TLS writes — FOREVER, including at converged steady state (the correct steady-state answer is ~0)",
		peers, batchesPerPeer, perEnv, float64(perRoundNode)/1e6, nodesPerHost, float64(perRoundHost)/1e6)
}

// commitWindowCurve renders the ingest RATE OVER TIME (not an average): sort the
// per-batch completion times, then for each decile of completions report
// keys/s within that decile. A collapse shows up as a falling tail.
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
