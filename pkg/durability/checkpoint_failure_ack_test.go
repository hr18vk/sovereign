// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// A periodic checkpoint runs after its mutation is already durable. Its
// failure must therefore be logged and counted without changing the write's
// acknowledgement (ADR-0045 §5).

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

// TestCheckpointFailureNeverFailsTheACK makes the mutation's fsync succeed and
// the following checkpoint's fsync fail. PutLocal must still return nil, the
// checkpoint failure must be counted and logged, and recovery must find exactly
// one dot for the mutation.
//
// Returning the checkpoint error would make the control path send a 503 for a
// durable write. A client retry could then insert the same keys again and mint
// a second set of dots.
func TestCheckpointFailureNeverFailsTheACK(t *testing.T) {
	var logBuf bytes.Buffer
	defer log.SetOutput(os.Stderr)
	log.SetOutput(&logBuf)

	walPath := filepath.Join(t.TempDir(), "checkpoint-failure.wal")
	live := newLiveBridge(t, walPath, 1) // K=1: every put designates a checkpoint

	var calls int32
	WALAsChaos(live.WAL()).SetSyncHookForTest(func() error {
		if atomic.AddInt32(&calls, 1) == 2 {
			return errors.New("injected checkpoint fsync failure")
		}
		return nil
	})

	dot, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), temporalEntry(1))
	if err != nil {
		t.Fatalf("PutLocal returned %v after the mutation was durable; the optional checkpoint must not fail the write", err)
	}
	// The checkpoint runner records its error and log asynchronously. Drain it
	// before reading either observation.
	live.waitCheckpointsIdle()
	if got := live.CheckpointErrors(); got != 1 {
		t.Errorf("CheckpointErrors=%d, want 1 for the absorbed checkpoint failure", got)
	}
	if !strings.Contains(logBuf.String(), "checkpoint failed") {
		t.Errorf("absorbed checkpoint failure was not logged; log tail: %q", logBuf.String())
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
