// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// This harness diagnoses SEC-allocator stalls in which goroutines spin in
// (*ElimNodePool).allocIndexSharded because all 64 sharded free-lists appear
// empty while deepAlloc's available heuristic still requests indices. The
// environment-gated hunt uses bounded attempts; a cheaper conservation test
// runs with the normal suite.
//
// Three test-side instruments locate the indices without adding hooks to
// production code:
//
//   - The watchdog polls runtime.Stack(buf, true) for allocIndexSharded. A
//     frame that persists across consecutive polls spanning the dwell bound
//     indicates a stall. The defaults are a 10-second bound and 250-millisecond
//     cadence. Normal claims and refills complete well within that interval.
//   - The conservation dump accounts for each of the poolCap-1 allocatable
//     indices; index 0 is the permanent NullOffset64 sentinel. An index belongs
//     in a freeShard list, a secDeepCache, a ShardedStack, or an in-flight
//     operation. A shared visited bitmap detects duplicates, and per-shard walk
//     limits detect cycles. The first failure selects conservationCorrupt,
//     conservationDup, conservationCycle, conservationStranded, or
//     conservationUnstable; otherwise the class is conservationClean.
//   - The cache registry records each workload goroutine's *secDeepCache before
//     it starts and snapshots the contents at exit. This is necessary because
//     goroutine exit does not flush these caches, and a spinning owner cannot
//     report its own cache.
//
// Stack heads, free-list heads, and cache counts can change during a dump. The
// walker reads the controlling word before and after each walk. Free-list and
// stack mutations mark the store UNSTABLE; cache counts use up to eight stability
// reads. Once producers are spinning in allocIndexSharded, their caches and the
// empty free-list heads are stable, and consumers only observe empty stacks.
//
// During a run, the accounting permits one uncommitted index per live
// goroutine while a claim moves from allocIndexSharded to dc.indices[i]. It
// also accounts for claims in a live count==0 cache whose refill has populated
// indices[] but has not set dc.count. Entries found in no persistent store are
// fresh claims; older entries have already been handed out and appear in one
// other store. After wg.Wait the tolerance is zero because no refill remains in
// progress.
//
// Three environment-gated negative controls exercise the diagnostics through
// the real entry points. SOVEREIGN_TEST_FAULT_POOL=DUP injects a double free,
// LEAK withholds claims, and WEDGE holds the whole pool before requesting one
// more index. Each control is expected to fail with its corresponding detector
// or watchdog report.
//
// Initialization order matters: flatcomb_test.go and sharded_test.go reassign
// the stack factory, and the SEC adapter in sharded_test.go runs last. This file
// does not reassign it. Each attempt checks both the candidate name and the
// factory product's type so the harness cannot silently exercise ElimStack.
//
// Environment controls (disabled by default except for the conservation test):
//
//	SOVEREIGN_TEST_POOL_TRIPWIRE=1    run the bounded stall hunt
//	SOVEREIGN_TEST_POOL_ATTEMPTS=N    attempt cap (default 20; use -count=1)
//	SOVEREIGN_TEST_POOL_ATTEMPT_MS=N  workload duration per attempt (default 1000)
//	SOVEREIGN_TEST_POOL_WATCHDOG_MS=N watchdog dwell bound (default 10000)
//	SOVEREIGN_TEST_POOL_POLL_MS=N     watchdog poll cadence (default 250)
//	SOVEREIGN_TEST_POOL_MAX_MIN=N     total wall-clock cap in minutes (default 30)
//	SOVEREIGN_TEST_FAULT_POOL=DUP|LEAK|WEDGE
//	                                  run the selected negative control

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tripwireEnvInt reads a positive int env knob with a default.
func tripwireEnvInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// tripwireCacheSnapshot is the quiesced report a workload goroutine's defer
// publishes at exit: the exact cache contents after its last burst.
type tripwireCacheSnapshot struct {
	count   int
	indices [DeepCacheCap]uint64
}

// tripwireRegEntry is one registry slot. The owner goroutine publishes its live
// *secDeepCache pointer before the start gun (atomic for cross-goroutine
// visibility) and its exit snapshot via defer; the dumper reads the snapshot
// once the owner has exited, the live cache while it runs.
type tripwireRegEntry struct {
	cachePtr atomic.Pointer[secDeepCache]
	snapPtr  atomic.Pointer[tripwireCacheSnapshot]
	exited   atomic.Bool
	_pad     [104]byte // pad to 128B stride; registry slots are polled under fire
}

// tripwireRegistry owns one slot per workload goroutine.
type tripwireRegistry struct {
	entries []tripwireRegEntry
}

func newTripwireRegistry(goroutines int) *tripwireRegistry {
	return &tripwireRegistry{entries: make([]tripwireRegEntry, goroutines)}
}

// tripwireFireReport contains the stack snapshot and timing captured when the
// watchdog's dwell bound expires.
type tripwireFireReport struct {
	dwell   time.Duration // how long the signature persisted before firing
	firstAt time.Time     // when the signature was first seen (for the record)
	stacks  string        // the full runtime.Stack(buf, true) snapshot at fire
}

// tripwireWatchdog polls all goroutine stacks for allocIndexSharded. A fire
// sends one buffered report and ends polling; stop ends polling without a
// report.
type tripwireWatchdog struct {
	fireCh chan tripwireFireReport
	stopCh chan struct{}
}

// armTripwireWatchdog starts polling at cadence. The caller logs the cadence,
// frame signature, and dwell bound before starting the workload. The signature
// must remain visible across consecutive polls spanning dwell; an absent frame
// resets the interval. The outer empty-pool Gosched loop in allocIndexSharded is
// the expected long-lived frame.
func armTripwireWatchdog(dwell, cadence time.Duration) *tripwireWatchdog {
	wd := &tripwireWatchdog{
		fireCh: make(chan tripwireFireReport, 1),
		stopCh: make(chan struct{}),
	}
	go func() {
		buf := make([]byte, 1<<20)
		var firstSeen time.Time
		ticker := time.NewTicker(cadence)
		defer ticker.Stop()
		for {
			select {
			case <-wd.stopCh:
				return
			case now := <-ticker.C:
				// Grow once if truncated; 4 MiB covers 32 workload
				// goroutines plus test machinery with room to spare.
				n := runtime.Stack(buf, true)
				if n == len(buf) && len(buf) < 1<<26 {
					buf = make([]byte, len(buf)*4)
					n = runtime.Stack(buf, true)
				}
				if strings.Contains(string(buf[:n]), "allocIndexSharded") {
					if firstSeen.IsZero() {
						firstSeen = now
						continue
					}
					if now.Sub(firstSeen) >= dwell {
						wd.fireCh <- tripwireFireReport{
							dwell:   now.Sub(firstSeen),
							firstAt: firstSeen,
							stacks:  string(buf[:n]),
						}
						return
					}
				} else {
					// Signature absent this poll: reset. Persistence is
					// across consecutive polls only — a transient healthy
					// sighting cannot accumulate toward the bound.
					firstSeen = time.Time{}
				}
			}
		}
	}()
	return wd
}

// stop disarms the watchdog (clean run end).
func (wd *tripwireWatchdog) stop() {
	close(wd.stopCh)
}

// tripwireRunStats aggregates the workload counters. Attempts includes empty
// pops, making it the offered-load denominator.
type tripwireRunStats struct {
	pushed   int64
	popped   int64
	attempts int64
	elapsed  time.Duration
}

// runTripwireAttempt mirrors the scaling workload's timed runner: producer,
// consumer, and mixed modes use the same 25/25/50 distribution, burst-size
// helper, inter-burst jitter, and per-goroutine value stream. gatePoolCap is
// shared with that workload so pool sizing stays consistent.
//
// Each goroutine registers its cache before starting and publishes an exit
// snapshot, allowing the dump to include caches that are not flushed at exit.
// The caller supplies a new stack and pool for every attempt. Reusing a stack
// would release indices from the previous pool into the new one and create
// double frees.
func runTripwireAttempt(sec *secStackAdapter, pool *ElimNodePool, goroutines int, runDuration time.Duration, reg *tripwireRegistry) tripwireRunStats {

	type gorStats struct {
		pushed   atomic.Int64
		popped   atomic.Int64
		attempts atomic.Int64
	}
	stats := make([]gorStats, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(goroutines)

	for gid := 0; gid < goroutines; gid++ {
		gid := gid
		go func() {
			defer wg.Done()
			wprng := &gatePRNG{}
			_ = wprng.next()
			cprng := &ElimPRNG{}
			_ = cprng.next()
			base := uint64(gid) * (1 << 20)
			var seq uint64

			// Registry — publish the live cache pointer before the start
			// gun (atomic for cross-goroutine visibility), and the exact
			// exit snapshot at exit (defer runs before wg.Done releases
			// the dumper, so a snapshot is final the moment it is read).
			reg.entries[gid].cachePtr.Store(&cprng.secCache)
			defer func() {
				snap := &tripwireCacheSnapshot{count: cprng.secCache.count}
				copy(snap.indices[:], cprng.secCache.indices[:])
				reg.entries[gid].snapPtr.Store(snap)
				reg.entries[gid].exited.Store(true)
			}()

			ready.Done()
			<-start

			deadline := time.Now().Add(runDuration)
			for time.Now().Before(deadline) {
				spinFor(wprng.jitterNanos())
				mode := wprng.pickMode()
				k := wprng.burstSizeCapped(gateBurstMax)

				switch mode {
				case gateModeProducer:
					for i := 0; i < k; i++ {
						v := base + (seq % (1 << 20))
						seq++
						sec.push(pool, cprng, v)
						stats[gid].pushed.Add(1)
						stats[gid].attempts.Add(1)
					}
				case gateModeConsumer:
					for i := 0; i < k; i++ {
						if _, pok := sec.pop(pool, cprng); pok {
							stats[gid].popped.Add(1)
						}
						stats[gid].attempts.Add(1)
					}
				case gateModeMixed:
					for i := 0; i < k; i++ {
						v := base + (seq % (1 << 20))
						seq++
						sec.push(pool, cprng, v)
						stats[gid].pushed.Add(1)
						stats[gid].attempts.Add(1)
					}
					for i := 0; i < k; i++ {
						if _, pok := sec.pop(pool, cprng); pok {
							stats[gid].popped.Add(1)
						}
						stats[gid].attempts.Add(1)
					}
				}
			}
		}()
	}

	ready.Wait()
	t0 := time.Now()
	close(start)
	wg.Wait()

	var st tripwireRunStats
	st.elapsed = time.Since(t0)
	for i := range stats {
		st.pushed += stats[i].pushed.Load()
		st.popped += stats[i].popped.Load()
		st.attempts += stats[i].attempts.Load()
	}
	return st
}

// conservationClass records the first detected failure. conservationCorrupt
// indicates an out-of-range link, conservationDup a repeated bitmap entry, and
// conservationCycle a walk beyond poolCap steps. A double free self-links its
// node, so the duplicate detector fires before the walk limit. Later stages can
// select conservationUnstable or conservationStranded; conservationClean means
// every index was accounted for within the stated tolerance.
type conservationClass string

const (
	conservationClean    conservationClass = "CLEAN"
	conservationDup      conservationClass = "DUPLICATE"
	conservationCycle    conservationClass = "CYCLE"
	conservationStranded conservationClass = "STRANDED"
	conservationCorrupt  conservationClass = "CORRUPT-LINK"
	conservationUnstable conservationClass = "UNSTABLE"
)

// conservationDump records the walked totals, detected failure, and formatted
// accounting report.
type conservationDump struct {
	class         conservationClass
	poolCap       int
	count         int64
	freeTotal     int
	stackTotal    int
	cacheTotal    int
	progressExact int // spinner-array entries found in no other store
	inflightTol   int // stated: 1 per live goroutine mid-run; 0 post-run
	shortfall     int
	countDrift    int
	availableLie  int
	dupIdx        uint64
	dupShard      int
	dupStore      string
	cycleShard    int
	unstable      int
	liveCaches    int
	text          []string
}

func (d *conservationDump) line(format string, args ...any) {
	d.text = append(d.text, fmt.Sprintf(format, args...))
}

func tripwireBitHas(b []byte, i uint64) bool { return b[i>>3]&(1<<(i&7)) != 0 }
func tripwireBitSet(b []byte, i uint64)      { b[i>>3] |= 1 << (i & 7) }

// walkPoolFreeLists visits the 64 sharded free-lists and marks their indices in
// the shared bitmap. The legacy p.free chain is not authoritative: it shares
// ElimNode.freeNext and is overwritten when the constructor seeds the shards.
//
// Only elimIndex(head) determines emptiness because an empty head can carry a
// generation tag. Each list is walked once and its head is then re-read. A
// changed head marks the shard UNSTABLE; walking again could set existing bits
// and falsely report a duplicate.
func walkPoolFreeLists(pool *ElimNodePool, poolCap int, bitmap []byte, d *conservationDump) {
	for sh := 0; sh < elimPoolShardCount; sh++ {
		headStart := pool.freeShards[sh].free.Load()
		cur := headStart
		steps := 0
		for elimIndex(cur) != NullOffset64 {
			idx := elimIndex(cur)
			if idx == 0 || int(idx) >= poolCap {
				d.class, d.dupShard = conservationCorrupt, sh
				d.line("CORRUPT-LINK: shard %d free-list links out-of-range index %d (packed head %#x)", sh, idx, cur)
				return
			}
			if tripwireBitHas(bitmap, idx) {
				d.class, d.dupIdx, d.dupShard, d.dupStore = conservationDup, idx, sh, "free-list"
				d.line("DUPLICATE: index %d seen again on free-list shard %d (first detector: shared bitmap)", idx, sh)
				return
			}
			tripwireBitSet(bitmap, idx)
			d.freeTotal++
			steps++
			if steps > poolCap {
				d.class, d.cycleShard = conservationCycle, sh
				d.line("CYCLE: free-list shard %d walk exceeded poolCap steps", sh)
				return
			}
			cur = atomic.LoadUint64(&pool.nodes[idx].freeNext)
		}
		d.line("freeShards[%2d] head=%#016x (gen %d, idx %d) walked=%d", sh, headStart, elimGen(headStart), elimIndex(headStart), steps)
		if pool.freeShards[sh].free.Load() != headStart {
			d.unstable++
			d.line("UNSTABLE: free-list shard %d head mutated during the dump walk", sh)
		}
	}
}

// walkShardedStacks visits every ShardedStack stackTop chain and adds live
// parked pushes to the shared bitmap. As with the free-lists, each chain is
// walked once and a changed head marks the store UNSTABLE.
func walkShardedStacks(sec *secStackAdapter, pool *ElimNodePool, poolCap int, bitmap []byte, d *conservationDump) {
	if sec == nil {
		return
	}
	for sh := 0; sh < secShardCount; sh++ {
		headStart := sec.inner.shards[sh].stackTop.Load()
		cur := headStart
		steps := 0
		for elimIndex(cur) != NullOffset64 {
			idx := elimIndex(cur)
			if idx == 0 || int(idx) >= poolCap {
				d.class, d.dupShard = conservationCorrupt, sh
				d.line("CORRUPT-LINK: stack shard %d chain links out-of-range index %d (packed %#x)", sh, idx, cur)
				return
			}
			if tripwireBitHas(bitmap, idx) {
				d.class, d.dupIdx, d.dupShard, d.dupStore = conservationDup, idx, sh, "stack"
				d.line("DUPLICATE: index %d seen again on stack shard %d (first detector: shared bitmap)", idx, sh)
				return
			}
			tripwireBitSet(bitmap, idx)
			d.stackTotal++
			steps++
			if steps > poolCap {
				d.class, d.cycleShard = conservationCycle, sh
				d.line("CYCLE: stack shard %d walk exceeded poolCap steps", sh)
				return
			}
			cur = atomic.LoadUint64(&pool.nodes[idx].next)
		}
		if sec.inner.shards[sh].stackTop.Load() != headStart {
			d.unstable++
			d.line("UNSTABLE: stack shard %d stackTop mutated during the dump walk", sh)
		}
	}
}

// accountThreadCaches first adds counted entries from exited snapshots and
// live caches to the shared bitmap. Live counts use a stability retry; spinning
// owners no longer mutate their caches.
//
// During a stall, a second pass handles live caches with count==0. Their refill
// may have claimed entries into indices[] before setting count. Array entries
// absent from every other store are the fresh claims; older entries were handed
// out earlier and already appear elsewhere. Running after the persistent stores
// have been walked prevents double accounting.
func accountThreadCaches(reg *tripwireRegistry, bitmap []byte, d *conservationDump, wedged bool) {
	if reg == nil {
		return
	}
	if d.class != conservationClean {
		// Preserve the first detector's details. Continuing could overwrite
		// them or attribute a duplicate to the wrong store; cacheTotal stays 0
		// and the caller records that cache accounting was skipped.
		return
	}
	// Pass 1: counted entries.
	var progressBits []byte
	for i := range reg.entries {
		e := &reg.entries[i]
		if snap := e.snapPtr.Load(); e.exited.Load() && snap != nil {
			for j := 0; j < snap.count; j++ {
				v := snap.indices[j]
				if tripwireBitHas(bitmap, v) {
					d.class, d.dupIdx, d.dupStore = conservationDup, v, "cache-snapshot"
					d.line("DUPLICATE: index %d seen again in exited cache slot %d (first detector: shared bitmap)", v, i)
					return
				}
				tripwireBitSet(bitmap, v)
				d.cacheTotal++
			}
			d.line("cache[%2d] EXITED  count=%d", i, snap.count)
			continue
		}
		c := e.cachePtr.Load()
		if c == nil {
			d.line("cache[%2d] live but not registered (harness bug)", i)
			continue
		}
		d.liveCaches++
		d.inflightTol++ // <= 1 uncommitted index in register transit per live goroutine
		var cnt int
		stable := false
		for attempt := 0; attempt < 8; attempt++ {
			cnt = c.count
			if c.count == cnt {
				stable = true
				break
			}
		}
		if !stable {
			d.unstable++
			d.line("UNSTABLE: live cache slot %d count churned through 8 stability probes", i)
		}
		if cnt > 0 {
			for j := 0; j < cnt; j++ {
				v := c.indices[j]
				if tripwireBitHas(bitmap, v) {
					d.class, d.dupIdx, d.dupStore = conservationDup, v, "cache-live"
					d.line("DUPLICATE: index %d seen again in live cache slot %d (first detector: shared bitmap)", v, i)
					return
				}
				tripwireBitSet(bitmap, v)
				d.cacheTotal++
			}
		}
		d.line("cache[%2d] LIVE    count=%d", i, cnt)
	}
	// Pass 2: fresh claims in live count==0 caches during a stall.
	if wedged && d.class == conservationClean {
		progressBits = make([]byte, (d.poolCap+7)/8)
		for i := range reg.entries {
			e := &reg.entries[i]
			if e.exited.Load() {
				continue
			}
			c := e.cachePtr.Load()
			if c == nil || c.count != 0 {
				continue
			}
			for j := 0; j < DeepCacheCap; j++ {
				v := c.indices[j]
				if v == 0 || tripwireBitHas(bitmap, v) {
					continue
				}
				tripwireBitSet(progressBits, v)
			}
		}
		for k := 0; k < len(progressBits); k++ {
			d.progressExact += int(popcountByte(progressBits[k]))
		}
	}
}

// popcountByte counts set bits without adding a math/bits import.
func popcountByte(b byte) int {
	n := 0
	for b != 0 {
		b &= b - 1
		n++
	}
	return n
}

// assembleConservationLedger finishes the accounting and sets the class when
// no earlier detector fired:
//
//	held         = stackTotal + cacheTotal + progressExact + inflightTol
//	shortfall    = (poolCap-1) - freeTotal - held
//	countDrift   = count - held
//	availableLie = (poolCap-1-count) - freeTotal
//
// A positive shortfall means indices are missing from every store. countDrift
// compares the pool counter with the accounting, and availableLie compares the
// refill heuristic's estimate with the observed free-list total.
func assembleConservationLedger(d *conservationDump, wedged bool) {
	held := d.stackTotal + d.cacheTotal + d.progressExact + d.inflightTol
	d.shortfall = (d.poolCap - 1) - d.freeTotal - held
	d.countDrift = int(d.count) - held
	d.availableLie = (d.poolCap - 1 - int(d.count)) - d.freeTotal

	d.line("──── CONSERVATION LEDGER ────")
	d.line("poolCap-1 (allocatable)   = %d", d.poolCap-1)
	d.line("free-list walk total      = %d", d.freeTotal)
	d.line("stack walk total          = %d", d.stackTotal)
	d.line("cache counted total       = %d (live=%d)", d.cacheTotal, d.liveCaches)
	d.line("mid-refill claims (exact) = %d (live count==0 arrays minus accounted)", d.progressExact)
	d.line("in-flight tolerance       = %d (stated: 1 per live goroutine mid-run, 0 post-run)", d.inflightTol)
	d.line("pool.count                = %d", d.count)
	d.line("shortfall                 = %+d (indices in no store)", d.shortfall)
	d.line("countDrift                = %+d (count minus held; <0 = undercount, overestimates available slots)", d.countDrift)
	d.line("availableLie              = %+d ((poolCap-1-count) - freeWalk; what the refill believes)", d.availableLie)
	d.line("unstable stores           = %d", d.unstable)

	if d.class != conservationClean {
		d.line("CLASS (first detector)    = %s", d.class)
		return
	}
	switch {
	case d.unstable > 0:
		d.class = conservationUnstable
	case d.shortfall > 0:
		d.class = conservationStranded
	case d.shortfall == -d.inflightTol:
		// Every tolerated in-flight claim was actually observed in a store.
		// This occurs when all spinning goroutines are before their next claim,
		// so the persistent stores already balance exactly.
		d.class = conservationClean
	case d.shortfall < 0:
		// The shared bitmap cannot over-account beyond the tolerance unless a
		// store changed during the dump.
		d.class = conservationUnstable
	default:
		d.class = conservationClean
	}
	d.line("CLASS (first detector)    = %s%s", d.class, map[bool]string{true: " — wedged with clean conservation (pool exhaustion or probe defect)", false: ""}[wedged])
}

// dumpPoolConservation captures one pool's complete index accounting.
func dumpPoolConservation(pool *ElimNodePool, poolCap int, sec *secStackAdapter, reg *tripwireRegistry, wedged bool) *conservationDump {
	d := &conservationDump{poolCap: poolCap, count: pool.count.Load(), class: conservationClean}
	bitmap := make([]byte, (poolCap+7)/8)
	walkPoolFreeLists(pool, poolCap, bitmap, d)
	if d.class == conservationClean {
		walkShardedStacks(sec, pool, poolCap, bitmap, d)
	} else {
		d.line("stack walk skipped: a free-list detector fired first (first-detector-wins)")
	}
	if d.class != conservationClean {
		d.line("cache accounting skipped: a walk detector fired first (first-detector-wins)")
	}
	accountThreadCaches(reg, bitmap, d, wedged)
	assembleConservationLedger(d, wedged)
	return d
}

// String renders the dump's diagnostic lines.
func (d *conservationDump) String() string {
	return strings.Join(d.text, "\n")
}

// TestAllocatorTripwire_LivenessHunt runs the workload at GOMAXPROCS with a
// fresh pool, stack, and registry per attempt and one watchdog across all
// attempts. A completed attempt must balance conservation with zero tolerance.
// A watchdog report includes the accounting dump and raw goroutine stacks. If
// no attempt stalls, the test reports the number of clean attempts without
// claiming that the stall cannot occur.
func TestAllocatorTripwire_LivenessHunt(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_POOL_TRIPWIRE") != "1" {
		t.Skip("SEC-allocator tripwire: set SOVEREIGN_TEST_POOL_TRIPWIRE=1 to run the bounded wedge-hunt harness")
	}

	// Verify each fresh stack because allocIndexSharded belongs to the
	// SEC-sharded implementation. Initialization in sharded_test.go selects that
	// implementation; this file only checks the result.

	goroutines := runtime.GOMAXPROCS(0)
	attempts := tripwireEnvInt("SOVEREIGN_TEST_POOL_ATTEMPTS", 20)
	attemptMs := tripwireEnvInt("SOVEREIGN_TEST_POOL_ATTEMPT_MS", 1000)
	dwellMs := tripwireEnvInt("SOVEREIGN_TEST_POOL_WATCHDOG_MS", 10000)
	pollMs := tripwireEnvInt("SOVEREIGN_TEST_POOL_POLL_MS", 250)
	maxMin := tripwireEnvInt("SOVEREIGN_TEST_POOL_MAX_MIN", 30)
	poolCap := gatePoolCap(goroutines)
	if os.Getenv("SOVEREIGN_TEST_FAULT_UNDERSIZED_POOL") == "1" {
		// Restore the smaller pool calculation as a negative control.
		poolCap = goroutines*gateBurstMax*2 + elimTestPoolSize + 1
		t.Logf("SEC-allocator negative control: SOVEREIGN_TEST_FAULT_UNDERSIZED_POOL=1 selects the smaller pool calculation (poolCap=%d)", poolCap)
	}

	// Log the watchdog settings before starting the workload so an unwatched
	// run cannot be mistaken for a clean result.
	t.Logf("SEC-allocator tripwire armed: watchdog cadence=%dms signature=\"allocIndexSharded\" dwell-bound=%dms (%d consecutive polls; ordinary claims and refills complete sooner)", pollMs, dwellMs, dwellMs/pollMs)
	t.Logf("SEC-allocator tripwire: goroutines=%d poolCap=%d attempts=%d attemptMs=%d wallCap=%dmin candidate=%s", goroutines, poolCap, attempts, attemptMs, maxMin, gateCandidateName())

	wd := armTripwireWatchdog(time.Duration(dwellMs)*time.Millisecond, time.Duration(pollMs)*time.Millisecond)
	defer wd.stop()

	wallCap := time.Now().Add(time.Duration(maxMin) * time.Minute)
	completed := 0
	for i := 0; i < attempts; i++ {
		if !time.Now().Before(wallCap) {
			t.Logf("SEC-allocator tripwire: wall cap reached after %d attempts", i)
			break
		}
		completed = i + 1
		// A new stack prevents leftover nodes from an earlier attempt from
		// releasing indices into this attempt's pool.
		stackIface := makeGateStack()
		sec, secOK := stackIface.(*secStackAdapter)
		if !secOK || gateCandidateName() != "SEC-sharded" {
			t.Fatalf("attempt %d requires the SEC-sharded stack: factory produced %T, candidate=%q", i+1, stackIface, gateCandidateName())
		}
		pool := NewElimNodePool(poolCap)
		reg := newTripwireRegistry(goroutines)
		done := make(chan tripwireRunStats, 1)
		go func() {
			done <- runTripwireAttempt(sec, pool, goroutines, time.Duration(attemptMs)*time.Millisecond, reg)
		}()
		select {
		case st := <-done:
			// All owners exited and published their snapshots, so the accounting
			// must balance exactly without an in-flight tolerance.
			d := dumpPoolConservation(pool, poolCap, sec, reg, false)
			t.Logf("attempt %2d/%d: pushed=%d popped=%d attempts=%d elapsed=%s | ledger=%s shortfall=%+d countDrift=%+d availableLie=%+d",
				i+1, attempts, st.pushed, st.popped, st.attempts, st.elapsed, d.class, d.shortfall, d.countDrift, d.availableLie)
			if d.class != conservationClean || d.shortfall != 0 || d.countDrift != 0 {
				t.Fatalf("SEC-allocator conservation failed on attempt %d with zero in-flight tolerance:\n%s", i+1, d)
			}
		case fire := <-wd.fireCh:
			// Producers remain in the empty-pool spin, consumers only observe
			// empty stacks, and the spinning producers' caches remain stable.
			d := dumpPoolConservation(pool, poolCap, sec, reg, true)
			t.Fatalf("SEC-allocator stall: allocIndexSharded persisted for %s (first seen %s); class=%s shortfall=%+d countDrift=%+d availableLie=%+d\nCONSERVATION DUMP:\n%s\nGOROUTINE STACKS:\n%s",
				fire.dwell, fire.firstAt.Format(time.RFC3339), d.class, d.shortfall, d.countDrift, d.availableLie, d, fire.stacks)
		}
	}
	t.Logf("SEC-allocator tripwire: %d clean attempts; no stall was observed", completed)
}

// The following negative controls use the real allocation and return paths and
// are expected to fail with the corresponding diagnostic. They require no
// production test hooks. Run each with -count=1.

// tripwireLeakSink keeps claimed indices live without returning them.
var tripwireLeakSink [4]uint64

// TestAllocatorTripwire_FaultDoubleFree returns the same index twice through
// freeIndexHome. The second return self-links the node, so the shared bitmap
// reports DUPLICATE before the cycle walk reaches its limit. The test then
// fails intentionally to display the detector's report.
func TestAllocatorTripwire_FaultDoubleFree(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_POOL") != "DUP" {
		t.Skip("set SOVEREIGN_TEST_FAULT_POOL=DUP to run the double-free negative control")
	}
	poolCap := 129 // indices 1..128, all home shards reachable from probe 0
	pool := NewElimNodePool(poolCap)
	idx := pool.allocIndexSharded(0) // the real claim path (+1 count)
	if idx == NullOffset64 {
		t.Fatalf("inject-DUP setup failed: allocIndexSharded returned the sentinel")
	}
	pool.freeIndexHome(idx) // first return decrements count
	pool.freeIndexHome(idx) // injected second return self-links the node
	d := dumpPoolConservation(pool, poolCap, nil, nil, false)
	t.Logf("inject-DUP dump: class=%s count=%d freeWalk=%d dupIdx=%d dupShard=%d\n%s", d.class, d.count, d.freeTotal, d.dupIdx, d.dupShard, d)
	if d.class != conservationDup || d.dupIdx != idx {
		t.Fatalf("double-free negative control: class=%s, want DUPLICATE at index %d", d.class, idx)
	}
	t.Fatalf("expected double-free diagnostic: index %d is DUPLICATE on shard %d; count=%d reports available=%d, observed free=%d", idx, d.dupShard, d.count, poolCap-1-int(d.count), d.freeTotal)
}

// TestAllocatorTripwire_FaultLeak claims three indices through
// allocIndexSharded without returning or caching them. The pool has 128
// allocatable indices, so the dump must report STRANDED with a shortfall of
// exactly three and no in-flight tolerance.
func TestAllocatorTripwire_FaultLeak(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_POOL") != "LEAK" {
		t.Skip("set SOVEREIGN_TEST_FAULT_POOL=LEAK to run the leaked-index negative control")
	}
	poolCap := 129
	pool := NewElimNodePool(poolCap)
	for i := 0; i < 3; i++ {
		idx := pool.allocIndexSharded(0)
		if idx == NullOffset64 {
			t.Fatalf("inject-LEAK setup failed: allocIndexSharded returned the sentinel on claim %d", i)
		}
		tripwireLeakSink[i] = idx // retain the claim without returning it
	}
	d := dumpPoolConservation(pool, poolCap, nil, nil, false)
	t.Logf("inject-LEAK dump: class=%s count=%d freeWalk=%d shortfall=%+d\n%s", d.class, d.count, d.freeTotal, d.shortfall, d)
	if d.class != conservationStranded || d.shortfall != 3 {
		t.Fatalf("leaked-index negative control: class=%s shortfall=%+d, want STRANDED with shortfall 3", d.class, d.shortfall)
	}
	t.Fatalf("expected leaked-index diagnostic: STRANDED with shortfall=%+d and count=%d", d.shortfall, d.count)
}

// TestAllocatorTripwire_FaultExhaustionWatchdog claims every index through
// allocIndexSharded and then requests one more. That request remains in the
// empty-pool Gosched loop, so the watchdog must report it within the dwell and
// polling bounds. Unlike the allocator stall, every index is legitimately held;
// this control exercises only the watchdog mechanism.
func TestAllocatorTripwire_FaultExhaustionWatchdog(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_POOL") != "WEDGE" {
		t.Skip("set SOVEREIGN_TEST_FAULT_POOL=WEDGE to run the exhaustion watchdog control")
	}
	poolCap := 9 // indices 1..8
	pool := NewElimNodePool(poolCap)
	for i := 1; i < poolCap; i++ {
		idx := pool.allocIndexSharded(0)
		if idx == NullOffset64 {
			t.Fatalf("inject-WEDGE setup failed: allocIndexSharded returned the sentinel on claim %d", i)
		}
		tripwireLeakSink[0] = idx // retain every claim in a package variable
	}
	dwellMs := tripwireEnvInt("SOVEREIGN_TEST_POOL_WATCHDOG_MS", 10000)
	pollMs := tripwireEnvInt("SOVEREIGN_TEST_POOL_POLL_MS", 250)
	t.Logf("SEC-allocator exhaustion control: watchdog cadence=%dms signature=\"allocIndexSharded\" dwell-bound=%dms; all %d indices are held before the final claim", pollMs, dwellMs, poolCap-1)
	wd := armTripwireWatchdog(time.Duration(dwellMs)*time.Millisecond, time.Duration(pollMs)*time.Millisecond)
	defer wd.stop()
	go func() {
		tripwireLeakSink[1] = pool.allocIndexSharded(0) // remains in the empty-pool spin
	}()
	select {
	case fire := <-wd.fireCh:
		t.Fatalf("expected exhaustion watchdog report: allocIndexSharded persisted for %s across %d consecutive %dms polls\nStacks:\n%s", fire.dwell, dwellMs/pollMs, pollMs, fire.stacks)
	case <-time.After(time.Duration(dwellMs+4*pollMs) * time.Millisecond):
		t.Fatalf("exhaustion watchdog did not fire within %dms", dwellMs+4*pollMs)
	}
}

// TestAllocatorConservation_Always runs four goroutines for 150 milliseconds
// without an environment gate. Once every owner exits and publishes its cache
// snapshot, all poolCap-1 indices must be accounted for with zero in-flight
// tolerance. This detects duplicate, leaked, and stranded indices in the normal
// test suite.
func TestAllocatorConservation_Always(t *testing.T) {
	stackIface := makeGateStack()
	sec, secOK := stackIface.(*secStackAdapter)
	if !secOK || gateCandidateName() != "SEC-sharded" {
		t.Fatalf("conservation test requires the SEC-sharded stack: factory produced %T, candidate=%q", stackIface, gateCandidateName())
	}
	goroutines := 4
	poolCap := gatePoolCap(goroutines)
	pool := NewElimNodePool(poolCap)
	reg := newTripwireRegistry(goroutines)
	st := runTripwireAttempt(sec, pool, goroutines, 150*time.Millisecond, reg)
	d := dumpPoolConservation(pool, poolCap, sec, reg, false)
	t.Logf("conservation-always: pushed=%d popped=%d attempts=%d elapsed=%s | class=%s shortfall=%+d countDrift=%+d availableLie=%+d",
		st.pushed, st.popped, st.attempts, st.elapsed, d.class, d.shortfall, d.countDrift, d.availableLie)
	if d.class != conservationClean || d.shortfall != 0 || d.countDrift != 0 || d.availableLie != 0 {
		t.Fatalf("post-run conservation must balance with zero tolerance: class=%s shortfall=%+d countDrift=%+d availableLie=%+d\n%s",
			d.class, d.shortfall, d.countDrift, d.availableLie, d)
	}
}
