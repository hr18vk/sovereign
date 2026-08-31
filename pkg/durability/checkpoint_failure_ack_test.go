// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//checkpoint_failure_ack_test.go — T16, the 503-on-durable-write guard (ADR-0045). It lives in its OWN file because it references-only bridge API
// (CheckpointErrors): the T7/T17 RED capture reverts bridge.go to the
// pre-fix revision, and this file must be movable aside without breaking that
// compilation unit.

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCheckpointFailureNeverFailsTheACK is the 503-on-durable-write guard. The
// byte-traced HEAD defect: AppendMutations returns nil (the mutation is
// fsync'd — DURABLE), then the periodic checkpoint's fsync fails, and
// bridge.go returned THAT error to the caller — gossip.go:1297 → control.go:463
// stamps 503 on a durable write; the client retries and re-inserts, minting a
// SECOND set of dots for the same keys (the 800-extra-dots candidate).
//
// The guard: K=1 so the single Put triggers a checkpoint; the sync hook
// succeeds for the mutation's fsync (call 1) and fails the checkpoint's
// (call 2). Assert: PutLocal returns NIL (the ACK is 200), the failure is
// METERED (CheckpointErrors) and LOGGED, and the mutation survives a
// crash-recovery (it was durable all along).
//
// RED (bug-inject): PutLocal's `b.noteMutations(1)` reverted to the HEAD shape
// (`if K>0 { if err:= b.AppendCheckpoint(); err != nil { return dot, err } }`)
// → the rigged checkpoint failure reaches the caller → the nil-ACK assertion
// fires.
func TestCheckpointFailureNeverFailsTheACK(t *testing.T) {
	var logBuf bytes.Buffer
	defer log.SetOutput(os.Stderr)
	log.SetOutput(&logBuf)

	walPath := filepath.Join(t.TempDir(), "t16.wal")
	live := newLiveBridge(t, walPath, 1) // K=1: every put designates a checkpoint

	var calls int32
	WALAsChaos(live.WAL()).SetSyncHookForTest(func() error {
		if atomic.AddInt32(&calls, 1) == 2 {
			return errors.New("T16 rigged checkpoint fsync failure")
		}
		return nil
	})

	dot, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), temporalEntry(1))
	if err != nil {
		t.Fatalf("PutLocal returned %v — a DURABLE write was 503'd by its (optional, best-effort) checkpoint (R8a violated)", err)
	}
	// T-A3: the decouple runs the checkpoint on a background goroutine,
	// so the absorbed failure (the meter + the log) is recorded ASYNC. Drain
	// before asserting, or the meter reads 0 / the log is empty purely because
	// the runner has not been scheduled yet — not because the failure vanished.
	live.waitCheckpointsIdle()
	if got := live.CheckpointErrors(); got != 1 {
		t.Errorf("METER: CheckpointErrors=%d, want 1 — the absorbed checkpoint failure must be counted", got)
	}
	if !strings.Contains(logBuf.String(), "checkpoint failed") {
		t.Errorf("LOG: the absorbed checkpoint failure was not logged (log tail: %q)", logBuf.String())
	}
	_ = dot

	// The mutation is durable: crash and recover — it must be there, alone.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	rec, _ := recoverFull(t, walPath)
	ents := collectEntries(t, rec)
	if got := ents[utf8EntityID(1)]; len(got) != 1 {
		t.Fatalf("recovered %d dots for the put, want exactly 1 (durable, not duplicated)", len(got))
	}
}
