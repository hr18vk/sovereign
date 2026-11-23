// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestEBR_HoistedHazardSnapshotAdversarialRace exercises the hazard snapshot
// shared by AdvanceEpoch and freeRetiredListWithHazards. Across 256 rounds with
// concurrent participants, a protected node must stay out of nodeFreelist while
// unprotected siblings from the same retired-list shards are reclaimed.
// Clearing the hazard must make the node reclaimable after later epoch advances.
//
// With SOVEREIGN_TEST_FAULT_EBR_HAZARDS=ignore_hazards, the enabled fault makes
// the test detect premature reclamation of the protected node.
func TestEBR_HoistedHazardSnapshotAdversarialRace(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_EBR_HAZARDS") == "ignore_hazards" {
		ebrIgnoreHazardsFault.Store(true)
		defer ebrIgnoreHazardsFault.Store(false)
	}

	ebr := NewEBRManager()
	arena, err := NewHamtArena(64*1024*1024, ebr)
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	const (
		rounds       = 256
		siblingsEach = 16
		sentinel     = uint64(0x5A5A5A5AA5A5A5A5)
		numChurners  = 4
	)

	stopChurn := make(chan struct{})
	var churnWG sync.WaitGroup
	for g := 0; g < numChurners; g++ {
		churnWG.Add(1)
		go func(gid int) {
			defer churnWG.Done()
			p := ebr.Acquire()
			defer ebr.Release(p)
			slot := gid % HazardSlots
			dummy := arena.AllocNode()
			dummyPtr := unsafe.Pointer(uintptr(dummy))
			for {
				select {
				case <-stopChurn:
					return
				default:
					p.Enter(ebr)
					p.DetachAndProtect(slot, dummyPtr)
					runtime.Gosched()
					p.ClearHazard(slot)
				}
			}
		}(g)
	}
	defer func() {
		close(stopChurn)
		churnWG.Wait()
	}()

	readerP := ebr.Acquire()
	defer ebr.Release(readerP)

	advanceByEpochs := func(delta uint64) {
		target := ebr.globalEpoch.Load() + delta
		for ebr.globalEpoch.Load() < target {
			stepNode := arena.AllocNode()
			ebr.RetireBlock(arena, uint64(uintptr(stepNode)-arena.base), true)
			ebr.AdvanceEpoch()
			runtime.Gosched()
		}
	}

	for r := 0; r < rounds; r++ {
		slot := r % HazardSlots

		// Allocate the target node and stamp the 64-bit sentinel into its
		// intrusive Treiber-stack word (bytes [0:8], which pushFreeNode
		// atomically overwrites with the freelist head offset on reclamation).
		protNode := arena.AllocNode()
		if protNode == 0 {
			t.Fatalf("round %d: AllocNode returned 0 for protected node", r)
		}
		protOff := uint64(uintptr(protNode) - arena.base)
		protPtr := unsafe.Pointer(arena.base + uintptr(protOff))
		protWord := (*uint64)(protPtr)
		atomic.StoreUint64(protWord, sentinel)

		// Allocate unprotected sibling nodes across shards and stamp them too.
		var sibOffsets [siblingsEach]uint64
		var sibWords [siblingsEach]*uint64
		for i := 0; i < siblingsEach; i++ {
			sib := arena.AllocNode()
			if sib == 0 {
				t.Fatalf("round %d sibling %d: AllocNode returned 0", r, i)
			}
			off := uint64(uintptr(sib) - arena.base)
			sibOffsets[i] = off
			w := (*uint64)(unsafe.Pointer(arena.base + uintptr(off)))
			atomic.StoreUint64(w, sentinel)
			sibWords[i] = w
		}

		// Reader enters EBR before retirement and detaches with hazard protection.
		readerP.Enter(ebr)
		if !readerP.DetachAndProtect(slot, protPtr) {
			t.Fatalf("round %d: DetachAndProtect(slot=%d) returned false", r, slot)
		}

		// Writer retires unprotected siblings and the protected node across multiple
		// retired-list shards, then drives epoch advances from a concurrent goroutine.
		var advWG sync.WaitGroup
		advWG.Add(1)
		go func() {
			defer advWG.Done()
			for i := 0; i < siblingsEach/2; i++ {
				ebr.RetireBlock(arena, sibOffsets[i], true)
			}
			ebr.RetireBlock(arena, protOff, true)
			for i := siblingsEach / 2; i < siblingsEach; i++ {
				ebr.RetireBlock(arena, sibOffsets[i], true)
			}
			advanceByEpochs(4)
		}()
		advWG.Wait()

		// 1. Assert the hazard-protected node was not reclaimed while protected.
		if got := atomic.LoadUint64(protWord); got != sentinel {
			t.Fatalf("hazard violation at round %d (slot=%d): protected node at offset %d was reclaimed while hazard held (word=0x%x, want sentinel 0x%x)",
				r, slot, protOff, got, sentinel)
		}
		for s := 0; s < arenaNodeFreelistShardCount; s++ {
			if arena.nodeFreelist[s].head.Load() == protOff {
				t.Fatalf("hazard violation at round %d: protected offset %d found at nodeFreelist[%d] head while hazard held",
					r, protOff, s)
			}
		}

		// 2. Assert unprotected sibling nodes in the same batch were reclaimed.
		for i := 0; i < siblingsEach; i++ {
			if got := atomic.LoadUint64(sibWords[i]); got == sentinel {
				t.Fatalf("round %d sibling %d (offset %d): unprotected sibling was not reclaimed after 4 AdvanceEpoch calls",
					r, i, sibOffsets[i])
			}
		}

		// 3. Clear the hazard and advance epochs -> protected node must now be reclaimed.
		if !readerP.ClearHazard(slot) {
			t.Fatalf("round %d: ClearHazard(slot=%d) returned false", r, slot)
		}
		advanceByEpochs(4)
		if got := atomic.LoadUint64(protWord); got == sentinel {
			t.Fatalf("round %d: formerly protected node at offset %d was not reclaimed after ClearHazard + 4 AdvanceEpoch calls",
				r, protOff)
		}
	}
}
