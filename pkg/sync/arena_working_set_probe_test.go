// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strconv"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// runArenaWorkingSetExchange models the arena traffic for one exchange with
// --iblt-v2 --iblt-v2-min-buckets=21845. It builds and marshals requester and
// responder digests, then generates and releases a delta against remote.
//
// local selects ReleaseLocal instead of Release for the two mesh digests.
// GenerateDelta already returns its local digest and diff through the
// goroutine-local free-list.
func runArenaWorkingSetExchange(e *DeltaCRDTEngine, remote *IBLT, buckets int, local bool) {
	for side := 0; side < 2; side++ {
		d := e.GenerateDigestSizedWithSeed(remote.Seed(), buckets)
		if _, err := MarshalIBLT(d); err != nil {
			panic(err)
		}
		if local {
			d.ReleaseLocal()
		} else {
			d.Release()
		}
	}
	delta := e.GenerateDelta(remote)
	delta.Release()
}

// measureArenaWorkingSetProbe runs exchanges per goroutine across workers on a
// 10,000-key, 64 MiB engine. It returns the bump high-water after loading and
// after the run, plus the first exchange that panicked with arena exhaustion,
// or -1 if none did.
func measureArenaWorkingSetProbe(t *testing.T, buckets, workers, exchanges int, local bool) (stateMiB, endMiB float64, oomAt int) {
	t.Helper()
	// Do not Close these engines. Recovering an arena-exhaustion panic inside
	// GenerateDelta can leave its EBR participant pinned, which would make
	// Close wait forever in Quiesce. Process exit reclaims the mappings.
	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() { DataDir = oldDir })
	a, err := NewDeltaCRDTEngine([16]byte{0x48, 0xA0, byte(workers), byte(buckets >> 8)}, 0, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDeltaCRDTEngine([16]byte{0x48, 0xB0, byte(workers), byte(buckets >> 8)}, 0, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		a.InsertLocal(fmt.Sprintf("k-%05d", i), CRDTEntry{
			SystemTime:    int64(1_789_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
		})
	}
	mib := func() float64 { return float64(a.arena.bumpOffset.Load()) / (1 << 20) }
	stateMiB = mib()
	remote := b.GenerateDigestSizedWithSeed(Uint64ToSeed(0x48F48F48), buckets)
	defer remote.Release()

	var mu gosync.Mutex
	oomAt = -1
	var wg gosync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < exchanges; i++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							mu.Lock()
							if oomAt < 0 || i < oomAt {
								oomAt = i
							}
							mu.Unlock()
							i = exchanges // stop this worker
						}
					}()
					runArenaWorkingSetExchange(a, remote, buckets, local)
				}()
			}
		}()
	}
	wg.Wait()
	return stateMiB, mib(), oomAt
}

// TestArenaProbe_WorkingSet is an opt-in diagnostic, not a CI gate. Setting
// SOVEREIGN_TEST_ARENA_PROBE prints the bump high-water across bucket counts,
// worker counts, and the Release versus ReleaseLocal return paths.
func TestArenaProbe_WorkingSet(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_ARENA_PROBE") == "" {
		t.Skip("set SOVEREIGN_TEST_ARENA_PROBE=1 to run the arena working-set probe")
	}
	SetIBLTSchemeV2(true)
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	exchanges := 400
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_EXCHANGES")); err == nil {
		exchanges = v
	}
	for _, buckets := range []int{1024, 21845} {
		for _, workers := range []int{1, 8, 18} {
			for _, local := range []bool{false, true} {
				s, e, oom := measureArenaWorkingSetProbe(t, buckets, workers, exchanges, local)
				t.Logf("PROBE buckets=%d workers=%d exchanges/worker=%d mesh_release=%s state_MiB=%.2f end_bump_MiB=%.2f oom_at=%d",
					buckets, workers, exchanges, map[bool]string{false: "EBR-Release", true: "ReleaseLocal"}[local], s, e, oom)
			}
		}
	}
}

// TestArenaProbe_GrowthTrace runs sequential exchanges on a 1 GiB arena so the
// bump high-water can plateau without hitting the arena limit. Continued growth
// despite a small live working set indicates that freed blocks are not being
// reused.
func TestArenaProbe_GrowthTrace(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_ARENA_PROBE") == "" {
		t.Skip("set SOVEREIGN_TEST_ARENA_PROBE=1 to run the arena growth trace")
	}
	SetIBLTSchemeV2(true)
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() { DataDir = oldDir })
	for _, buckets := range []int{1024, 21845} {
		for _, local := range []bool{false, true} {
			a, err := NewDeltaCRDTEngine([16]byte{0x48, 0xC0, byte(buckets >> 8), map[bool]byte{false: 1, true: 2}[local]}, 0, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			b, err := NewDeltaCRDTEngine([16]byte{0x48, 0xD0, byte(buckets >> 8), map[bool]byte{false: 1, true: 2}[local]}, 0, 64<<20)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10000; i++ {
				a.InsertLocal(fmt.Sprintf("k-%05d", i), CRDTEntry{SystemTime: int64(1_789_000_000 + i), H3Index: uint64(i),
					PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i)))})
			}
			remote := b.GenerateDigestSizedWithSeed(Uint64ToSeed(0x48F48F48), buckets)
			mib := func() float64 { return float64(a.arena.bumpOffset.Load()) / (1 << 20) }
			line := fmt.Sprintf("TRACE buckets=%d mesh_release=%s sweep=%d state=%.2f", buckets,
				map[bool]string{false: "EBR-Release", true: "ReleaseLocal"}[local], arenaVarFreelistSweep, mib())
			for i := 1; i <= 1000; i++ {
				runArenaWorkingSetExchange(a, remote, buckets, local)
				if i%100 == 0 {
					line += fmt.Sprintf(" x%d=%.2f", i, mib())
				}
			}
			t.Log(line)
			remote.Release()
			_ = a.Close()
			_ = b.Close()
		}
	}
}

// TestArenaProbe_NodeExchangeModel models a hierarchical regional gateway with
// --iblt-v2 --iblt-v2-min-buckets=21845. One sequential requester holds each
// delta's EBR pin for SOVEREIGN_TEST_ARENA_PROBE_PIN_MS to represent network
// transmission, while two or six responders continuously build, marshal, and
// release digests. Six is the configuration's maximum in-degree. A 4 GiB arena
// allows the high-water to plateau without an exhaustion cutoff.
func TestArenaProbe_NodeExchangeModel(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_ARENA_PROBE") == "" {
		t.Skip("set SOVEREIGN_TEST_ARENA_PROBE=1 to run the node exchange model")
	}
	SetIBLTSchemeV2(true)
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() { DataDir = oldDir })
	pinMS := 50
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_PIN_MS")); err == nil {
		pinMS = v
	}
	// SOVEREIGN_TEST_ARENA_PROBE_RESP_SLEEP_MS paces each responder. Zero models
	// continuous digest construction; the production-shaped rate is approximately
	// 26 inbound digest builds per second per node.
	respSleepMS := 0
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_RESP_SLEEP_MS")); err == nil {
		respSleepMS = v
	}
	reqN := 300
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_EXCHANGES")); err == nil {
		reqN = v
	}
	// SOVEREIGN_TEST_ARENA_PROBE_LOCAL=1 returns both goroutine-local mesh
	// digests through ReleaseLocal instead of EBR Release.
	meshLocal := os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_LOCAL") == "1"
	meshRelease := func(d *IBLT) {
		if meshLocal {
			d.ReleaseLocal()
		} else {
			d.Release()
		}
	}
	const buckets = 21845
	for _, responders := range []int{2, 6} {
		a, err := NewDeltaCRDTEngine([16]byte{0x48, 0xE0, byte(responders)}, 0, 4<<30)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewDeltaCRDTEngine([16]byte{0x48, 0xF0, byte(responders)}, 0, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10000; i++ {
			a.InsertLocal(fmt.Sprintf("k-%05d", i), CRDTEntry{SystemTime: int64(1_789_000_000 + i), H3Index: uint64(i),
				PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i)))})
		}
		remote := b.GenerateDigestSizedWithSeed(Uint64ToSeed(0x48F48F48), buckets)
		mib := func() float64 { return float64(a.arena.bumpOffset.Load()) / (1 << 20) }
		stop := make(chan struct{})
		var wg gosync.WaitGroup
		var respBuilds [8]int
		for r := 0; r < responders; r++ {
			wg.Add(1)
			go func(r int) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					d := a.GenerateDigestSizedWithSeed(remote.Seed(), buckets)
					if _, err := MarshalIBLT(d); err != nil {
						panic(err)
					}
					meshRelease(d)
					respBuilds[r]++
					if respSleepMS > 0 {
						time.Sleep(time.Duration(respSleepMS) * time.Millisecond)
					}
				}
			}(r)
		}
		line := fmt.Sprintf("NODEMODEL buckets=%d responders=%d pin_ms=%d resp_sleep_ms=%d mesh_release=%s state=%.2f", buckets, responders, pinMS, respSleepMS, map[bool]string{false: "EBR-Release", true: "ReleaseLocal"}[meshLocal], mib())
		for i := 1; i <= reqN; i++ {
			d := a.GenerateDigestSizedWithSeed(remote.Seed(), buckets)
			if _, err := MarshalIBLT(d); err != nil {
				t.Fatal(err)
			}
			meshRelease(d)
			delta := a.GenerateDelta(remote)
			time.Sleep(time.Duration(pinMS) * time.Millisecond) // hold the delta's EBR pin during network transmission
			delta.Release()
			if i%(reqN/10) == 0 {
				line += fmt.Sprintf(" x%d=%.2f", i, mib())
			}
		}
		close(stop)
		wg.Wait()
		tot := 0
		for _, n := range respBuilds {
			tot += n
		}
		t.Logf("%s responder_builds=%d", line, tot)
		remote.Release()
		_ = a.Close()
		_ = b.Close()
	}
}

// TestArenaProbe_VarFreelistDirectVsEBR compares direct pushFreeVar returns
// with EBR retirement. Workers allocate a 512 KiB block, write stamps at both
// ends, yield, and check them again; an overwritten stamp indicates a duplicate
// allocation. Misaligned or out-of-range offsets are counted separately. The
// probe exercises the ABA assumptions between allocVar's EBR-pinned pop and
// freeVar's expected reclaimer-driven push.
func TestArenaProbe_VarFreelistDirectVsEBR(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_ARENA_PROBE") == "" {
		t.Skip("set SOVEREIGN_TEST_ARENA_PROBE=1 to compare direct and EBR free-list returns")
	}
	iters := 20000
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_TEST_ARENA_PROBE_ITERS")); err == nil {
		iters = v
	}
	const payload = 524280 // 21,845 x 24 B — the 21,845-bucket digest slab (the 2^19 class)
	for _, mode := range []string{"ebr", "direct"} {
		for _, workers := range []int{4, 16} {
			ebr := NewEBRManager()
			a, err := NewHamtArena(512<<20, ebr)
			if err != nil {
				t.Fatal(err)
			}
			var dup gosync.WaitGroup
			var nDup, nBogus, nOOM, nOps atomic64
			for w := 0; w < workers; w++ {
				dup.Add(1)
				go func(id int) {
					defer dup.Done()
					defer func() {
						if r := recover(); r != nil {
							nOOM.add(1)
						}
					}()
					for i := 0; i < iters; i++ {
						p := a.allocVar(payload)
						off := uint64(p - a.base)
						if p == 0 || off%8 != 0 || off >= uint64(a.size) {
							nBogus.add(1)
							return
						}
						stamp := uint64(id+1)<<40 | uint64(i)
						*(*uint64)(unsafe.Pointer(p)) = stamp
						*(*uint64)(unsafe.Pointer(p + payload - 8)) = stamp
						runtime.Gosched()
						if *(*uint64)(unsafe.Pointer(p)) != stamp || *(*uint64)(unsafe.Pointer(p + payload - 8)) != stamp {
							nDup.add(1)
						}
						if mode == "direct" {
							a.pushFreeVar(off)
						} else {
							ebr.RetireBlock(a, off, false)
							if i%4 == 0 {
								ebr.AdvanceEpoch()
							}
						}
						nOps.add(1)
					}
				}(w)
			}
			dup.Wait()
			t.Logf("ABA mode=%s workers=%d iters/worker=%d ops=%d double_alloc=%d bogus_offset=%d panics=%d bump_MiB=%.1f",
				mode, workers, iters, nOps.load(), nDup.load(), nBogus.load(), nOOM.load(), float64(a.bumpOffset.Load())/(1<<20))
		}
	}
}

type atomic64 struct{ v int64 }

func (x *atomic64) add(d int64) { atomic.AddInt64(&x.v, d) }
func (x *atomic64) load() int64 { return atomic.LoadInt64(&x.v) }
