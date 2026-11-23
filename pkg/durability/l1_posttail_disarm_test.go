// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// This test covers recovery after a checkpoint image is lost (ADR-0045 and
// ADR-0053). Exact-WAL fallback rebuilds local state without the foreign
// entries folded into the checkpoint root, so the post-tail root comparison
// must remain disabled. Otherwise an intact WAL can fail recovery with
// ErrRecoveryRootMismatch.
//
// The fixture deliberately joins foreign entries without recording a clock
// advance. A receiver can merge a delta without advancing its Lamport clock,
// and the WAL stores only local mutations and clock advances, not foreign
// entries. Replay therefore has no reliable way to infer whether the checkpoint
// root includes foreign state. The test removes the image, recovers from the
// complete local WAL, and checks both the fallback witness and restored rows.

import (
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// foreignJoinNoAdvance joins a foreign delta without recording a clock
// advance, leaving foreign state in the engine but no 0x03 record in the WAL.
func foreignJoinNoAdvance(t *testing.T, live *Bridge, foreignStart uint64, n int) {
	t.Helper()
	eng.DataDir = t.TempDir()
	foreign, err := eng.NewDeltaCRDTEngine(foreignNodeID(), foreignStart, testArenaSize)
	if err != nil {
		t.Fatalf("foreign engine ctor: %v", err)
	}
	defer func() { _ = foreign.Close() }()
	for i := 0; i < n; i++ {
		foreign.InsertLocal(utf8EntityID(5000+i), stagedEntry(5000+i))
	}
	delta := foreign.GenerateDelta(live.Engine().GenerateDigest())
	defer delta.Release() // release the EBR participant before foreign.Close quiesces
	live.Engine().Join(*delta)
}

func TestPostTailMustNotBrickAfterDisarm(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "s1.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)

	const localN, foreignN = 6, 4

	for i := 0; i < localN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	// Foreign state arrives with no 0x03 recorded.
	foreignJoinNoAdvance(t, live, 900000, foreignN)

	// With no mutations after this checkpoint, recovery considers it final.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}

	// Check the fixture in the replayed bytes: the retained WAL must contain no
	// clock advances, and it must contain the durable checkpoint.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	t.Logf("replay: HasCheckpoint=%v HasCutSeq=%v HasFingerprint=%v advances=%d mutations=%d",
		rep.HasCheckpoint, rep.FinalCheckpt.HasCutSeq, rep.FinalCheckpt.HasFingerprint,
		len(rep.Advances), len(rep.Mutations))
	if len(rep.Advances) != 0 {
		t.Fatalf("got %d clock advances; fixture requires none", len(rep.Advances))
	}
	if !rep.HasCheckpoint {
		t.Fatalf("durable checkpoint missing from replay")
	}

	// Remove the checkpoint image while retaining its durable WAL anchor.
	dir := filepath.Join(lfs.Root(), "ckpt")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read ckpt dir: %v", err)
	}
	removed := 0
	for _, e := range ents {
		if !e.IsDir() {
			p := filepath.Join(dir, e.Name())
			if err := os.Remove(p); err != nil {
				t.Fatalf("remove image: %v", err)
			}
			removed++
		}
	}
	if removed == 0 {
		t.Fatalf("no checkpoint image found in %s", dir)
	}
	t.Logf("removed %d checkpoint image(s) from %s", removed, dir)

	// Recovery returns a nil witness on error, so check err before using it.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`recovery failed after checkpoint image loss: %v; `+"`the durable WAL contains `"+`%d local mutations and the checkpoint includes %d foreign entries`,
			err, localN, foreignN)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness == nil {
		t.Fatalf("successful recovery returned a nil witness")
	}
	if !witness.ExactWALFallback {
		t.Fatalf("lost image did not select exact-WAL fallback: witness=%+v", witness)
	}
	if witness.Bounded {
		t.Fatalf("recovery reports bounded mode without an image: witness=%+v", witness)
	}

	// Exact-WAL replay restores every local mutation. Foreign entries are absent
	// until anti-entropy supplies them again.
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing after exact-WAL fallback; the WAL recorded it, so recovery must restore it", i)
		}
	}
	t.Logf("exact-WAL fallback (reason=%q) restored %d/%d local entities; %d foreign entries await anti-entropy",
		witness.FallbackReason, localN, localN, foreignN)
}
