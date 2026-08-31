// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// THE RED GUARD for the post-tail-disarm brick, committed FAILING (RED-first).
//
// It reproduces the brick: after the §11.5 binding/degraded-image DISARM falls
// back to exact-WAL, the KEPT post-tail root check at recovery.go:649 re-arms via
// the `len(rep.Advances)==0` disjunct, compares an origin-only rebuild against an
// anchor root that folded FOREIGN entries, and returns ErrRecoveryRootMismatch →
// cmd/sovereign-node/main.go:829 log.Fatalf. A node whose WAL is byte-perfect
// refuses to boot.
//
// THIS GUARD IS WRITTEN IN ITS FINAL FORM. It asserts the POSTCONDITION the fix
// must establish, so it goes from RED to GREEN with ZERO edits. Do not "turn it
// green" by editing it — that is forbidden: an earlier change added assertions
// to a guard inside the commit that fixed what it tested, so those assertions never
// ran at RED. This file's assertions all run at RED today.
//
// FREQUENCY — READ THIS BEFORE YOU SCOPE ANYTHING (ADR-0045).
// I first published this trigger as "ordinary, not exotic" and WITHDREW
// that. `out.Advances` is appended at ONE unconditional site
// (internal/chaos/wal.go:971) across ALL records, and the only Truncate (:362) is
// torn-tail repair, not rotation — so `len(rep.Advances)` spans the ENTIRE
// retained log and any node that ever recorded one 0x03 never arms the assertion
// again. A seed carrying 13 advances would NOT brick. The shape is
// NARROW but REAL: zero 0x03 across the whole log WITH foreign entries applied,
// which receiver.go:640-655 permits because the Join is merged BEFORE the recorder
// is consulted and the recorder is gated on `post > preAdvance`. This guard
// constructs that shape DELIBERATELY. That is what a guard is for, and it is not
// evidence the defect is contrived — the severity is CRITICAL by CLASS (a whole
// node refuses to boot on an intact WAL).

import (
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// foreignJoinNoAdvance Joins a foreign delta WITHOUT calling RecordClockAdvance,
// producing the zero-0x03-with-foreign-state shape described in the header. It is
// deliberately NOT the common case; see the FREQUENCY note above.
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
	defer delta.Release() // MUST Release (crdt.go:1595): Exits the carried EBR participant so foreign.Close's Quiesce doesn't hang on the leak
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
	// Foreign state arrives with NO 0x03 recorded.
	foreignJoinNoAdvance(t, live, 900000, foreignN)

	// FINAL checkpoint: no tail after it ⇒ checkpointFinal == true, which the
	//:649 predicate also requires.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}

	// PREMISE (proven from the replayed bytes, not assumed): the arming disjunct
	// really is satisfied. If a 0x03 ever got recorded here the assertion would
	// be DISARMED and this guard would pass vacuously.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	t.Logf("PREMISE: HasCheckpoint=%v HasCutSeq=%v HasFingerprint=%v advances=%d mutations=%d",
		rep.HasCheckpoint, rep.FinalCheckpt.HasCutSeq, rep.FinalCheckpt.HasFingerprint,
		len(rep.Advances), len(rep.Mutations))
	if len(rep.Advances) != 0 {
		t.Fatalf("PREMISE BROKEN: want ZERO 0x03 advances (the arming disjunct), got %d — this guard would pass vacuously", len(rep.Advances))
	}
	if !rep.HasCheckpoint {
		t.Fatalf("PREMISE BROKEN: want a durable checkpoint anchor on disk")
	}

	// DEGRADE the image — the lost image write (bridge.go:399 fsyncs the anchor
	// BEFORE:446 writes the image; drainCheckpoints:513 swallows the failure).
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
		t.Fatalf("PREMISE BROKEN: no image to degrade in %s — the degraded-image path is not being exercised", dir)
	}
	t.Logf("DEGRADED: removed %d image(s) from %s (the lost image write)", removed, dir)

	// THE ASSERTION. Note the nil-witness discipline: the error return at
	// recovery.go:653-657 is `return nil, nil, nil, nil, err`, so the witness is
	// NIL on the failure path and MUST NOT be dereferenced before the err check.
	// (An earlier draft of this guard did exactly that and SIGSEGV'd,
	// aborting the whole pkg/durability test binary instead of reporting a
	// failure.)
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`REPRODUCED — a node with an INTACT WAL refused to boot:
 err = %v
 The WAL recorded every one of the %d local mutations and the anchor is durable.
 The image was lost, so §11.5 discarded it and set exactWALFallback — which makes
 the:649 `+"`len(rep.Advances)==0`"+` disjunct TRUE and ARMS the post-tail root
 check. That check compares an origin-only WAL rebuild against an anchor root
 that folded %d FOREIGN entries. It can never match (see the comment at
 recovery.go:631), so recovery returns ErrRecoveryRootMismatch and
 cmd/sovereign-node/main.go:829 log.Fatalf refuses the boot.
 A disarm that covers one of two checks is not a disarm; it is a narrower brick.`,
			err, localN, foreignN)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness == nil {
		t.Fatalf("recovery succeeded but returned a NIL witness — the arming answer must be machine-observable")
	}
	if !witness.ExactWALFallback {
		t.Fatalf("witness.ExactWALFallback=false — a lost image must take the exact-WAL fallback, not silently succeed some other way (witness=%+v)", witness)
	}
	if witness.Bounded {
		t.Fatalf("witness.Bounded=true — there is no image on disk, so the bounded path is impossible (witness=%+v)", witness)
	}

	// The WAL is the truth: every LOCAL mutation must be back. The foreign
	// entries are legitimately absent and re-arrive by anti-entropy.
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing after exact-WAL fallback — the WAL recorded it, so recovery must restore it", i)
		}
	}
	t.Logf("L1 GREEN: intact WAL + lost image ⇒ booted via exact-WAL fallback (reason=%q); %d/%d local entities restored; %d foreign entries legitimately absent",
		witness.FallbackReason, localN, localN, foreignN)
}
