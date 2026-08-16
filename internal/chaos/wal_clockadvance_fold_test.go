// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// ADR-0045 — the clock-advance-fold regression test: a 0x03
// clock-advance record MUST fold its value into ReplayWAL's out.LamportHigh
// (monotone max), EXACTLY as the mutation cases (wal.go:882-884,:892-894) and
// the checkpoint cases (:912-914,:927-929) already do. The recovery clock nail
// (recovery.go's final AdvanceLamportTo + the constructor seed) reads ONLY
// rep.LamportHigh, so a 0x03 record that does not fold is a clock the recovery
// never learns — the under-shoot.
//
// RED on the pre-fix tree: rep.LamportHigh == 100 (the checkpoint watermark),
// NOT 7,000,000 (the advance). GREEN post-fix.

import (
	"path/filepath"
	"testing"

	"github.com/hr18vk/sovereign/pkg/sync"
)

func TestReplayWAL_ClockAdvanceFoldsIntoLamportHigh(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "fold.wal")
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	var nodeID [16]byte
	nodeID[0] = 0xA1
	// Two local mutations, counters 2 and 3 — small, so the advance below is
	// unambiguously the maximum.
	for i := uint64(2); i <= 3; i++ {
		var entry sync.CRDTEntry
		entry.SystemTime = int64(i) * 1_000
		m := NewWALMutation("entity-fold", sync.CausalDot{NodeID: nodeID, Counter: i}, entry)
		if err := wal.AppendMutation(m); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
	}
	// The clock advance: far above every mutation counter AND the checkpoint
	// watermark below.
	const advanceTo = uint64(7_000_000)
	if err := wal.AppendClockAdvance(advanceTo); err != nil {
		t.Fatalf("AppendClockAdvance: %v", err)
	}
	// A checkpoint whose own watermark is small — the max() composition proof.
	if err := wal.AppendCheckpoint(WALCheckpoint{LamportHigh: 100}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}

	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}

	// THE FOLD — the assertion the fix must turn green.
	if rep.LamportHigh != advanceTo {
		t.Fatalf("R2 FOLD ABSENT: rep.LamportHigh=%d, want %d. The 0x03 decode never folded the advance — the recovery clock nail reads only rep.LamportHigh, so a below-cut advance is a clock the recovery never learns (Blocker 1).", rep.LamportHigh, advanceTo)
	}
	// The advance must ALSO remain in the ordered stream — the tail replay's
	// advance case still applies it on the full-replay path.
	if len(rep.Advances) != 1 || rep.Advances[0] != advanceTo {
		t.Fatalf("the 0x03 record vanished from the replay stream: Advances=%v (want [7000000])", rep.Advances)
	}
	// CONTROL (GREEN both sides): the mutation + checkpoint folds are untouched.
	if len(rep.Mutations) != 2 {
		t.Fatalf("control: want 2 mutations, got %d", len(rep.Mutations))
	}
	if !rep.HasCheckpoint || rep.FinalCheckpt.LamportHigh != 100 {
		t.Fatalf("control: checkpoint fold broken (HasCheckpoint=%v LamportHigh=%d)", rep.HasCheckpoint, rep.FinalCheckpt.LamportHigh)
	}
}
