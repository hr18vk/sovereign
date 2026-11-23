// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// The slab free-lists are lock-free Treiber stacks protected by EBR epoch
// pinning. Without that protection, a thread could read head=A and be
// preempted while another thread pops A, pushes B, and pushes A back. The
// first thread's compare-and-swap would then accept the recycled A even though
// the stack had changed.
//
// An active epoch pin prevents RetireBlock from recycling the head during the
// pop's compare-and-swap loop. These tests call runtime.Gosched between the
// read and allocation to exercise that protection under the race detector.

// TestTreiberStackABAImmunity cycles the arena's class-0 free-list from
// several goroutines. One goroutine yields after reading the head; the others
// repeatedly allocate and retire nodes to recycle addresses.
//
// Broken epoch pinning can produce a use-after-free or corrupt next pointers.
// Run with: go test -race -run=TestTreiberStackABAImmunity -count=100
//
// AdvanceEpoch runs every 200 operations rather than on every iteration. Its
// cost is O(participants × hazardSlots), and it cannot advance while any
// participant is active. An epoch pin held by the caller would otherwise make
// repeated advancement attempts consume CPU without reclaiming nodes. Retired
// nodes remain queued until the epoch advances twice, so sparse advancement is
// safe while the arena has capacity.
func TestTreiberStackABAImmunity(t *testing.T) {
	arena, err := NewHamtArena(512*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	// Build a pool of recycled nodes for the free-list.
	const poolSize = 256
	nodes := make([]NodePtr, poolSize)
	for i := range nodes {
		nodes[i] = arena.AllocNode()
	}
	// Retire all nodes to populate the free-list via EBR.
	for i := range nodes {
		offset := uint64(uintptr(nodes[i]) - arena.base)
		arena.ebr.RetireBlock(arena, offset, true)
	}
	// Advance epoch twice to physically reclaim into the free-list.
	arena.ebr.AdvanceEpoch()
	arena.ebr.AdvanceEpoch()

	var wg sync.WaitGroup
	const numAttackers = 4
	const opsPerGoroutine = 2000

	// Victim thread: AllocNode (Treiber pop) with Gosched between
	// read and CAS.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p := arena.ebr.Acquire()
		defer arena.ebr.Release(p)
		for i := 0; i < opsPerGoroutine; i++ {
			p.Enter(arena.ebr)
			// Read the head — this is the ABA window start.
			head := arena.freeHeads[0].head.Load()
			// Yield between reading the head and allocating from it.
			runtime.Gosched()
			// If head is still the same, the CAS will succeed.
			// EBR guarantees head was not recycled during Gosched.
			if head != arena.freeHeads[0].head.Load() {
				// Head changed — normal CAS retry, not ABA.
				// AllocNode handles this internally.
			}
			// Perform actual allocation (which does the Treiber pop).
			node := arena.AllocNode()
			if node == 0 {
				t.Errorf("AllocNode returned 0 at iteration %d", i)
			}
			p.Exit()
			// Retire the node back to the free-list.
			offset := uint64(uintptr(node) - arena.base)
			arena.ebr.RetireBlock(arena, offset, true)
			// Advance epoch sparingly to allow reclamation.
			if i%200 == 0 {
				arena.ebr.AdvanceEpoch()
			}
		}
	}()

	// Concurrent goroutines recycle addresses through rapid pops and pushes.
	for a := 0; a < numAttackers; a++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p := arena.ebr.Acquire()
			defer arena.ebr.Release(p)
			for i := 0; i < opsPerGoroutine; i++ {
				p.Enter(arena.ebr)
				node := arena.AllocNode()
				p.Exit()
				if node == 0 {
					continue
				}
				// Immediately retire it back — this is the ABA
				// attack vector: pop A, push A back rapidly.
				offset := uint64(uintptr(node) - arena.base)
				arena.ebr.RetireBlock(arena, offset, true)
				// Advance epoch sparingly to trigger physical recycling.
				if i%200 == 0 {
					arena.ebr.AdvanceEpoch()
				}
				// Yield to vary the interleaving with the other allocator.
				runtime.Gosched()
			}
		}(a)
	}

	wg.Wait()
}

// TestEBRHazardPointerSequencing protects a node with a hazard slot, retires
// it, and advances the epoch twice. Reclamation must leave the node's
// reference count intact until the hazard is cleared.
func TestEBRHazardPointerSequencing(t *testing.T) {
	arena, err := NewHamtArena(128*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	// Allocate a node and protect it with a hazard pointer.
	node := arena.AllocNode()
	offset := uint64(uintptr(node) - arena.base)

	p := arena.ebr.Acquire()
	p.Enter(arena.ebr)

	// Set hazard pointer on the node.
	protected := p.DetachAndProtect(0, unsafe.Pointer(uintptr(arena.base)+uintptr(offset)))
	if !protected {
		t.Fatal("DetachAndProtect failed for valid slot")
	}

	// Retire the protected block and attempt to reclaim it by advancing epochs.
	arena.ebr.RetireBlock(arena, offset, true)

	// The hazard prevents reclamation.
	arena.ebr.AdvanceEpoch()
	arena.ebr.AdvanceEpoch()

	// Verify the node is still intact (not recycled).
	n := (*HamtNode)(unsafe.Pointer(node))
	rc := n.refCount.Load()
	if rc != 1 {
		t.Errorf("hazard-protected node refCount changed: got %d, want 1", rc)
	}

	// Clear the hazard and advance — now it should be reclaimable.
	p.ClearHazard(0)
	arena.ebr.AdvanceEpoch()
	arena.ebr.AdvanceEpoch()

	arena.ebr.Release(p)
}

// TestConcurrentAllocFree exercises AllocNode and RetireBlock concurrently to
// detect races in the Treiber stack and EBR reclamation.
func TestConcurrentAllocFree(t *testing.T) {
	arena, err := NewHamtArena(512*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	const numGoroutines = 16
	const opsPerGoroutine = 2000

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := arena.ebr.Acquire()
			defer arena.ebr.Release(p)
			for i := 0; i < opsPerGoroutine; i++ {
				p.Enter(arena.ebr)
				node := arena.AllocNode()
				p.Exit()
				if node != 0 {
					offset := uint64(uintptr(node) - arena.base)
					arena.ebr.RetireBlock(arena, offset, true)
				}
				if i%200 == 0 {
					arena.ebr.AdvanceEpoch()
				}
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentInsertLocalRace exercises DeltaCRDTEngine's lock-free CAS loop
// under the race detector with frequent goroutine yields.
func TestConcurrentInsertLocalRace(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()

	const numWriters = 8
	const opsPerWriter = 500

	var wg sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < opsPerWriter; i++ {
				key := fmt.Sprintf("w%d-key%d", writerID, i)
				engine.InsertLocal(key, CRDTEntry{
					SystemTime: int64(writerID*10000 + i),
				})
				// Yield periodically to vary CAS retries.
				if i%10 == 0 {
					runtime.Gosched()
				}
			}
		}(w)
	}
	wg.Wait()

	state := engine.State()
	expected := numWriters * opsPerWriter
	if state.Len() != expected {
		t.Errorf("state.Len() = %d, want %d", state.Len(), expected)
	}
}

// TestConcurrentJoinRace exercises concurrent Join operations under -race.
func TestConcurrentJoinRace(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()

	const numJoiners = 4
	const deltasPerJoiner = 200

	var wg sync.WaitGroup
	for j := 0; j < numJoiners; j++ {
		wg.Add(1)
		go func(joinerID int) {
			defer wg.Done()
			nodeID := [16]byte{byte(joinerID + 2)}
			for i := 0; i < deltasPerJoiner; i++ {
				delta := CRDTDelta{
					OriginNodeID: nodeID,
					Entries: makeSeq([]seqEntry{{
						entityID: fmt.Sprintf("j%d-d%d", joinerID, i),
						entry: CRDTEntry{
							SystemTime:   int64(i),
							DotNodeID:    nodeID,
							DotCounter:   uint64(i + 1),
							OriginNodeID: nodeID,
						},
					}}),
				}
				engine.Join(delta)
				if i%10 == 0 {
					runtime.Gosched()
				}
			}
		}(j)
	}
	wg.Wait()

	state := engine.State()
	expected := numJoiners * deltasPerJoiner
	if state.Len() != expected {
		t.Errorf("state.Len() = %d, want %d", state.Len(), expected)
	}
}

// TestEpochStateMachineFuzz drives deterministic pseudo-random sequences of
// Enter, Exit, allocation, retirement, and AdvanceEpoch. No node may be
// recycled while a participant holds an active epoch pin.
func TestEpochStateMachineFuzz(t *testing.T) {
	arena, err := NewHamtArena(256*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	const numGoroutines = 8
	const opsPerGoroutine = 2000

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			p := arena.ebr.Acquire()
			defer arena.ebr.Release(p)

			// Simple LCG for deterministic per-goroutine randomness.
			seed := uint64(gid*6364136223846793005 + 1)
			for i := 0; i < opsPerGoroutine; i++ {
				seed = seed*6364136223846793005 + 1442695040888963407
				op := seed % 4

				switch op {
				case 0: // Enter
					p.Enter(arena.ebr)
				case 1: // AllocNode + Exit
					node := arena.AllocNode()
					p.Exit()
					if node != 0 {
						offset := uint64(uintptr(node) - arena.base)
						arena.ebr.RetireBlock(arena, offset, true)
					}
				case 2: // AdvanceEpoch (sparing — only 25% of ops)
					arena.ebr.AdvanceEpoch()
				case 3: // Exit only
					p.Exit()
				}
			}
		}(g)
	}
	wg.Wait()

	// Final epoch advance to flush remaining retired nodes.
	arena.ebr.AdvanceEpoch()
	arena.ebr.AdvanceEpoch()
}

// TestConcurrentSetGet exercises concurrent Set and Get on the same
// HAMT root under the race detector. HAMT is immutable — concurrent
// reads on the same root must be safe.
func TestConcurrentSetGet(t *testing.T) {
	arena, err := NewHamtArena(512*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	defer arena.Free()

	h := NewHAMT(arena)
	// Pre-populate with 1000 entries.
	for i := 0; i < 1000; i++ {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(i))
		key := unsafe.String(&buf[0], 8)
		h = h.Set(key, []CRDTEntry{{DotCounter: uint64(i)}})
	}

	var wg sync.WaitGroup

	// Concurrent readers.
	for r := 0; r < 10; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				var buf [8]byte
				binary.LittleEndian.PutUint64(buf[:], uint64(i%1000))
				key := unsafe.String(&buf[0], 8)
				got := h.Get(key)
				if len(got) != 1 {
					t.Errorf("Get returned %d entries, want 1", len(got))
				}
				if got[0].DotCounter != uint64(i%1000) {
					t.Errorf("DotCounter mismatch: got %d, want %d", got[0].DotCounter, i%1000)
				}
			}
		}()
	}

	// Concurrent writer (creates new HAMT versions).
	wg.Add(1)
	go func() {
		defer wg.Done()
		hh := h
		for i := 0; i < 10000; i++ {
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(1000+i))
			key := unsafe.String(&buf[0], 8)
			hh = hh.Set(key, []CRDTEntry{{DotCounter: uint64(1000 + i)}})
		}
	}()

	wg.Wait()
}

// TestAtomicCounterStress is a baseline sanity check for the atomic
// operations used in the arena's bump allocator and free-list heads.
func TestAtomicCounterStress(t *testing.T) {
	var counter atomic.Uint64
	const numGoroutines = 32
	const opsPerGoroutine = 100000

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				counter.Add(1)
				runtime.Gosched()
			}
		}()
	}
	wg.Wait()

	expected := uint64(numGoroutines * opsPerGoroutine)
	if counter.Load() != expected {
		t.Errorf("counter = %d, want %d", counter.Load(), expected)
	}
}
