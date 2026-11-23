// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

import (
	"path/filepath"
	"testing"

	"github.com/hr18vk/sovereign/pkg/durability"
)

// TestClockAdvanceSeam_RecordsOneOnActualAdvance is the seam test — the
// production receive path (Receiver.HandleFrame → onClockAdvance →
// wal.AppendClockAdvance) exercised end-to-end, not through the Bridge helper
// bypass the durability negative-control use. It drives a real signed relay-chain frame
// through a real Receiver with a real durability WAL recorder, then replays
// the WAL and asserts exactly one WALRecClockAdvance whose value equals the
// post-Join LamportCounter. This is the proof the gated hook (post>pre)
// actually records a foreign advance and records the right high-water.
func TestClockAdvanceSeam_RecordsOneOnActualAdvance(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1s -> MaxHopsForBudget(1s) = 16607; the single-hop relay chain is admitted
	const foreignDot = uint64(100)
	walPath := filepath.Join(t.TempDir(), "seam.wal")

	// setupReceiver builds a fully-wired Receiver (bucket + clock cap +
	// directory + engine). originPub=nil here; the frame's origin pubkey is
	// registered below once relayChain surfaces it (mirrors the existing
	// TestReceiver_CompositionOverSocketpair pattern).
	r, sc, _, _ := setupReceiver(t, wallBase, budgetNS, nil)

	// Build a real signed relay-chain frame at a foreign dotCounter higher
	// than the engine's zero LamportCounter — so Join's AdvanceLamportTo
	// actually jumps the clock (the load-bearing guard: post > pre).
	inner := buildCRDTDeltaWire(t, "seam-entity-cd", foreignDot)
	env, originPub, _ := relayChain(t, inner, 1, wallBase)
	if err := r.dir.Register(rcvOriginNodeID, originPub); err != nil {
		t.Fatalf("dir.Register origin: %v", err)
	}
	// Pin the synthetic clock near the relay's wallBase so the 3.0 clock gate
	// admits the frame's physical timestamps (drift epsilon).
	sc.Set(wallBase)

	// Open the real durability WAL and bind a Recorder the production way:
	// main.go wires recv.SetClockAdvanceRecorder(func(c uint64) error { return
	// bridge.WAL().AppendClockAdvance(c) }). The test runs that exact lambda
	// against a real WAL file, not the Bridge shell — this is the clock-advance
	// WAL recording path previously had no end-to-end test.
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	r.SetClockAdvanceRecorder(func(c uint64) error {
		return wal.AppendClockAdvance(c)
	})

	// Drive the full production receive path. verdict must be Accept.
	v := r.HandleFrame(env.Marshal())
	if v.Verdict != Accept {
		t.Fatalf("HandleFrame verdict = %v (%v) — expected Accept (the seam test requires the frame clear every gate)", v.Verdict, v.Reason)
	}

	rep, err := durability.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if got, want := len(rep.Advances), 1; got != want {
		t.Fatalf("WAL advances: got %d, want exactly 1 (the hook must record exactly the one real advance)", got)
	}
	// The recorded value must equal the post-Join LamportCounter. The engine
	// seeded at 0 and the frame's dotCounter is 100, so the clock gate's
	// AdvanceLamportTo(100) jumps the clock to 100; post > pre (100 > 0) →
	// the guarded recorder fires once with value 100.
	if got, want := rep.Advances[0], foreignDot; got != want {
		t.Fatalf("recorded advance value: got %d, want %d (the post-entry Lamport high-water)", got, want)
	}
}

// TestClockAdvanceSeam_ZeroRecordsOnStaleReReceive is the load-bearing
// negative: a stale/duplicate frame whose dotCounter does not advance the
// clock (it is <= the entry high-water) must produce zero new WAL records.
// The hook fires only when post > pre; a no-op AdvanceLamportTo (current >=
// remote) yields post == pre, so the guard suppresses the record. The first
// receive records exactly one advance; the second receive of the same frame
// records zero (the clock is already 100).
func TestClockAdvanceSeam_ZeroRecordsOnStaleReReceive(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000) // 1s -> MaxHopsForBudget(1s) = 16607; the single-hop relay chain is admitted
	const foreignDot = uint64(100)
	walPath := filepath.Join(t.TempDir(), "seam-stale.wal")

	r, sc, _, _ := setupReceiver(t, wallBase, budgetNS, nil)
	inner := buildCRDTDeltaWire(t, "seam-stale", foreignDot)
	env, originPub, _ := relayChain(t, inner, 1, wallBase)
	if err := r.dir.Register(rcvOriginNodeID, originPub); err != nil {
		t.Fatalf("dir.Register origin: %v", err)
	}
	sc.Set(wallBase)

	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	r.SetClockAdvanceRecorder(func(c uint64) error {
		return wal.AppendClockAdvance(c)
	})

	// First receive: foreign dotCounter 100 advances the clock 0→100 (one
	// record).
	v1 := r.HandleFrame(env.Marshal())
	if v1.Verdict != Accept {
		t.Fatalf("first HandleFrame verdict = %v (%v)", v1.Verdict, v1.Reason)
	}
	// Second receive of the same frame: the clock is already 100, so
	// AdvanceLamportTo(100) is a no-op (current >= remote) →
	// post == pre → the guard fires zero records. This is the
	// no-op-on-stale-receive proof: the post>pre guard suppresses the extra
	// per-Accept fsync.
	v2 := r.HandleFrame(env.Marshal())
	if v2.Verdict != Accept {
		t.Fatalf("stale re-receive verdict = %v (%v) — a dedup'd re-Accept passes the gates (state already merged)", v2.Verdict, v2.Reason)
	}
	rep, err := durability.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if got := len(rep.Advances); got != 1 {
		t.Fatalf("WAL advances after stale re-receive: got %d, want exactly 1 (the second Accept must not append a record — the post>pre guard suppresses the extra per-Accept fsync)", got)
	}
	if got := rep.Advances[0]; got != foreignDot {
		t.Fatalf("recorded advance value: got %d, want %d", got, foreignDot)
	}
}
