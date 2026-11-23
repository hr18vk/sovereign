// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"hash/maphash"
	"os"
	"runtime"
	gosync "sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestVarFreelist_ABARaceDoesNotCorruptBlocks verifies the varFreelist ABA
// fix (ADR-0045): the HamtArena varFreelist uses a 64-bit tagged
// Treiber head (tag32 << 32 | wordOffset32) and an atomic packed header
// (nextWordOffset << 8 | classIdx) at blockPtr.
//
// With SOVEREIGN_TEST_FAULT_FREELIST=untagged_var_freelist, the
// untaggedVarFreelistFault enables the pre-fix untagged byte-offset shard.head
// and non-atomic *blockPtr = classIdx path, deterministically reproducing
// failure mode A (nextOffset == classIdx yielding bogus near-zero offset) and
// failure mode B (Treiber A -> B -> A double allocation on classIdx = 4 /
// classIdx = 16) within seconds on 4 vCPUs.
//
// Without the fault, the test completes with 0 double-allocations, 0 bogus
// offsets, and 0 payload overwrites under GOMAXPROCS=4 and GOMAXPROCS=32
// with -race.
func TestVarFreelist_ABARaceDoesNotCorruptBlocks(t *testing.T) {
	varFreelistABAYieldFault.Store(true)
	defer varFreelistABAYieldFault.Store(false)

	faultMode := os.Getenv("SOVEREIGN_TEST_FAULT_FREELIST") == "untagged_var_freelist"
	if faultMode {
		untaggedVarFreelistFault.Store(true)
		defer untaggedVarFreelistFault.Store(false)
	}

	const (
		arenaBytes = 256 << 20 // 256 MiB
		workers    = 8
		iters      = 3000
	)
	ebr := NewEBRManager()
	arena, err := NewHamtArena(arenaBytes, ebr)
	if err != nil {
		t.Fatalf("NewHamtArena(256 MiB): %v", err)
	}
	defer func() { _ = arena.Free() }()

	// Track live block ownership by 8-byte wordOffset ((payloadPtr - varAllocHeaderSize - arena.base) >> 3).
	const maxWords = arenaBytes >> 3
	liveOwner := make([]atomic.Uint32, maxWords)

	var (
		doubleAlloc    atomic.Int64
		bogusOffset    atomic.Int64
		payloadCorrupt atomic.Int64
		nodeCorrupt    atomic.Int64
		totalOps       atomic.Int64
		stop           atomic.Bool
		wg             gosync.WaitGroup
	)

	checkAndClaim := func(payloadPtr uintptr, blockSize uint64, workerID uint32, stamp uint64, payloadWords int) bool {
		if payloadPtr < arena.base+uintptr(nodeSize)+varAllocHeaderSize || payloadPtr >= arena.base+uintptr(arena.size) {
			bogusOffset.Add(1)
			stop.Store(true)
			return false
		}
		blockOffset := uint64(payloadPtr - varAllocHeaderSize - arena.base)
		if blockOffset < uint64(nodeSize) || (blockOffset&7) != 0 || blockOffset+blockSize > uint64(arena.size) {
			bogusOffset.Add(1)
			stop.Store(true)
			return false
		}
		wordIdx := blockOffset >> 3
		if !liveOwner[wordIdx].CompareAndSwap(0, workerID) {
			doubleAlloc.Add(1)
			stop.Store(true)
			return false
		}
		firstWord := (*uint64)(unsafe.Pointer(payloadPtr))
		lastWord := (*uint64)(unsafe.Pointer(payloadPtr + uintptr(payloadWords-1)*8))
		atomic.StoreUint64(firstWord, stamp)
		atomic.StoreUint64(lastWord, stamp)
		return true
	}

	verifyAndReleaseClaim := func(payloadPtr uintptr, workerID uint32, stamp uint64, payloadWords int) bool {
		blockOffset := uint64(payloadPtr - varAllocHeaderSize - arena.base)
		wordIdx := blockOffset >> 3
		firstWord := (*uint64)(unsafe.Pointer(payloadPtr))
		lastWord := (*uint64)(unsafe.Pointer(payloadPtr + uintptr(payloadWords-1)*8))
		if atomic.LoadUint64(firstWord) != stamp || atomic.LoadUint64(lastWord) != stamp {
			payloadCorrupt.Add(1)
			stop.Store(true)
		}
		if !liveOwner[wordIdx].CompareAndSwap(workerID, 0) {
			doubleAlloc.Add(1)
			stop.Store(true)
			return false
		}
		return true
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			workerID := uint32(id + 1)
			seed := maphash.MakeSeed()
			for i := 0; i < iters && !stop.Load(); i++ {
				stampA := (uint64(workerID) << 40) | uint64(i*2+1)
				stampB := (uint64(workerID) << 40) | uint64(i*2+2)

				// 1. Allocate two classIdx=4 (128 B total, 120 B payload = 15 uint64 words)
				// blocks — the exact size class shared by NewArenaIBLT's 72-byte IBLT struct
				// and 1-entry []CRDTEntry in allocCRDTEntries (failure mode B).
				pA := arena.allocVar(120)
				if !checkAndClaim(pA, 128, workerID, stampA, 15) {
					return
				}
				pB := arena.allocVar(120)
				if !checkAndClaim(pB, 128, workerID, stampB, 15) {
					blockOffA := uint64(pA - varAllocHeaderSize - arena.base)
					liveOwner[blockOffA>>3].Store(0)
					return
				}

				runtime.Gosched()

				// Release pA first, then pB via direct pushFreeVar (modeling ReleaseLocal /
				// GenerateDelta direct frees racing with concurrent allocVar pops).
				okA := verifyAndReleaseClaim(pA, workerID, stampA, 15)
				if okA {
					arena.pushFreeVar(uint64(pA - arena.base))
				}
				runtime.Gosched()
				okB := verifyAndReleaseClaim(pB, workerID, stampB, 15)
				if okB {
					arena.pushFreeVar(uint64(pB - arena.base))
				}

				// 2. Periodically exercise classIdx=16 (512 KiB = 524,288 B total, 524,280 B
				// payload, the 21,845-bucket v2 IBLT slab) + NewArenaIBLT/ReleaseLocal
				// + AllocNode/freeNode (failure mode A).
				if i%8 == 0 && !stop.Load() {
					const slabPayload = 524280
					pLarge := arena.allocVar(slabPayload)
					stampL := (uint64(workerID) << 48) | uint64(i)
					if !checkAndClaim(pLarge, 524288, workerID, stampL, slabPayload/8) {
						return
					}
					runtime.Gosched()
					if verifyAndReleaseClaim(pLarge, workerID, stampL, slabPayload/8) {
						arena.pushFreeVar(uint64(pLarge - arena.base))
					}

					iblt := NewArenaIBLT(128, 4, seed, arena)
					if iblt == nil {
						t.Errorf("NewArenaIBLT returned nil")
						stop.Store(true)
						return
					}
					iblt.ReleaseLocal()

					nodePtr := arena.AllocNode()
					nodeOff := uint64(uintptr(nodePtr) - arena.base)
					if nodeOff < uint64(nodeSize) || (nodeOff&7) != 0 || nodeOff+uint64(nodeSize) > uint64(arena.size) {
						nodeCorrupt.Add(1)
						stop.Store(true)
						return
					}
					arena.pushFreeNode(nodeOff)
				}

				totalOps.Add(1)
			}
		}(w)
	}

	wg.Wait()

	t.Logf("T1 varFreelist stress: redMode=%v ops=%d double_alloc=%d bogus_offset=%d payload_corrupt=%d node_corrupt=%d bump_MiB=%.2f",
		faultMode, totalOps.Load(), doubleAlloc.Load(), bogusOffset.Load(), payloadCorrupt.Load(), nodeCorrupt.Load(),
		float64(arena.bumpOffset.Load())/(1<<20))

	if doubleAlloc.Load() > 0 || bogusOffset.Load() > 0 || payloadCorrupt.Load() > 0 || nodeCorrupt.Load() > 0 {
		t.Fatalf("varFreelist ABA/header-overwrite corruption detected: double_alloc=%d bogus_offset=%d payload_corrupt=%d node_corrupt=%d",
			doubleAlloc.Load(), bogusOffset.Load(), payloadCorrupt.Load(), nodeCorrupt.Load())
	}
}
