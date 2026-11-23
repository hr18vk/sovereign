// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// NextDot and AdvanceLamportTo notify a dedicated persist worker without
// acquiring persistMu. The worker receives from an unbuffered channel and owns
// the file Sync and Rename while holding that mutex. Persisted values retain
// the temporary-file-plus-rename format: eight bytes in big-endian order.
//
// The static test checks the worker lifecycle, non-blocking sends, and the
// requirement that Close wait for the worker before freeing the arena. The
// latency drive measures the last NextDot call per goroutine with deliberately
// loose thresholds; fast local storage can also satisfy them with synchronous
// persistence, so it is not the primary decoupling check.
//
// The durability test reconstructs engines from the same directory and checks
// the recovered Lamport value. Its one-NextDot case repeats the immediate-Close
// sequence to exercise the worker drain. Short mode skips only the
// scheduling-heavy latency drive; the static and durability checks still run.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// readCrdtSource loads crdt.go from the current tree so the static checks
// examine the source being tested rather than an embedded snapshot.
func readCrdtSource(t *testing.T) string {
	t.Helper()
	// The test file lives in pkg/sync/; crdt.go is its package sibling.
	data, err := os.ReadFile("crdt.go")
	if err != nil {
		// Fall back to a path relative to the calling test working dir.
		// `go test ./pkg/sync/` runs with cwd=pkg/sync, so "crdt.go" is
		// the canonical relative path; the fallback defends against an
		// alternate harness cwd.
		alt := filepath.Join("pkg", "sync", "crdt.go")
		data, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("static guard: cannot read crdt.go: %v", err)
		}
	}
	return string(data)
}

// TestPersistWorkerDecoupledStatic checks the persist channel, worker
// lifecycle, caller lock exclusion, non-blocking sends, and Close drain order.
// It reports each missing source property and runs in every build mode.
func TestPersistWorkerDecoupledStatic(t *testing.T) {
	src := readCrdtSource(t)

	type inv struct {
		id  string
		re  *regexp.Regexp
		got string
	}

	// S1: persistCh field of type chan uint64 declared in the engine
	// struct. The make(chan uint64, ...) call in NewDeltaCRDTEngine must
	// have cap 0 (unbuffered only).
	s1Field := regexp.MustCompile(`persistCh\s+chan\s+uint64`)
	s1Make := regexp.MustCompile(`make\(\s*chan\s+uint64\s*\)`) // cap 0: empty arg list

	// S2: persistWorkerWg field of type sync.WaitGroup.
	s2 := regexp.MustCompile(`persistWorkerWg\s+sync\.WaitGroup`)

	// S3: persistStopOnce field of type sync.Once.
	s3 := regexp.MustCompile(`persistStopOnce\s+sync\.Once`)

	// S4: a goroutine spawned `go e.persistWorkerLoop()`.
	s4 := regexp.MustCompile(`go\s+e\.persistWorkerLoop\(\)`)

	// S5: NextDot body must not contain e.persistMu.Lock() (regex absence).
	// S6: AdvanceLamportTo body must not contain e.persistMu.Lock() (regex
	// absence). We isolate the body of each function by slicing from its
	// signature line to the next top-level `func` declaration so the
	// absence check is scoped to that function body only (persistMu.Lock
	// elsewhere — e.g. the persist worker loop and the setters — is
	// expected and correct).
	nextDotBody := extractFuncBody(src, "NextDot", "CausalDot")
	advLamBody := extractFuncBody(src, "AdvanceLamportTo", "")

	persistMuLock := regexp.MustCompile(`e\.persistMu\.Lock\(\)`)

	// S7: persistWorkerLoop receives values and passes each to persistLamport.
	// These patterns use worker-specific identifiers; S4 separately requires the
	// worker goroutine to be started.
	s7Range := regexp.MustCompile(`for\s+val\s+:=\s+range\s+e\.persistCh`)
	s7Call := regexp.MustCompile(`e\.persistLamport\(\s*val\s*\)`)

	// S8: Close closes the channel once, waits for the worker, and only then
	// frees the arena. The ordering check compares these statements in Close.
	closeBody := extractFuncBody(src, "Close", "error")
	s8OnceClose := regexp.MustCompile(`e\.persistStopOnce\.Do\(\s*func\(\)\s*\{\s*close\(\s*e\.persistCh\s*\)\s*\}\s*\)`)
	s8Wait := regexp.MustCompile(`e\.persistWorkerWg\.Wait\(\)`)
	s8Free := regexp.MustCompile(`e\.arena\.Free\(\)`)

	// S9: NextDot + AdvanceLamportTo must each contain a non-blocking
	// select: `select { case e.persistCh <- nextLimit: default: }` (regex
	// on the select + default).
	s9Select := regexp.MustCompile(`select\s*\{\s*\n\s*case\s+e\.persistCh\s*<-\s*nextLimit\s*:\s*\n\s*default\s*:`)

	invs := []inv{
		{"S1 (persistCh chan uint64 field declared)", s1Field, "persistCh is not declared as chan uint64"},
		{"S1 (make(chan uint64) cap-0 unbuffered in NewDeltaCRDTEngine)", s1Make, "persistCh is not unbuffered; buffering would change worker handoff"},
		{"S2 (persistWorkerWg sync.WaitGroup field declared)", s2, "persistWorkerWg is not declared as sync.WaitGroup"},
		{"S3 (persistStopOnce sync.Once field declared)", s3, "persistStopOnce is not declared as sync.Once"},
		{"S4 (go e.persistWorkerLoop() spawn in NewDeltaCRDTEngine)", s4, "NewDeltaCRDTEngine does not start persistWorkerLoop"},
		{"S7 (persistWorkerLoop: for val := range e.persistCh)", s7Range, "persistWorkerLoop does not range over e.persistCh"},
		{"S7 (persistWorkerLoop: e.persistLamport(val) inside range)", s7Call, "persistWorkerLoop does not call `e.persistLamport(val)` while draining the channel"},
	}
	for _, iv := range invs {
		if !iv.re.MatchString(src) {
			t.Errorf("static guard: %s failed — %s", iv.id, iv.got)
		}
	}

	// S5 / S6 scoped to the function body.
	if persistMuLock.MatchString(nextDotBody) {
		t.Errorf("static guard: S5 failed — NextDot body contains e.persistMu.Lock(); the decouple is reverted (the CAS caller must not block on the disk mutex). NextDot body:\n%s", nextDotBody)
	}
	if persistMuLock.MatchString(advLamBody) {
		t.Errorf("static guard: S6 failed — AdvanceLamportTo body contains e.persistMu.Lock(); the decouple is reverted. AdvanceLamportTo body:\n%s", advLamBody)
	}

	// S8 scoped to Close body.
	if !s8OnceClose.MatchString(closeBody) {
		t.Errorf("static guard: S8 failed — Close() body missing e.persistStopOnce.Do(func(){ close(e.persistCh) }) (idempotent worker stop). Close body:\n%s", closeBody)
	}
	waitIdx := s8Wait.FindStringIndex(closeBody)
	freeIdx := s8Free.FindStringIndex(closeBody)
	if waitIdx == nil {
		t.Errorf("static guard: S8 failed — Close() body missing e.persistWorkerWg.Wait(). Close body:\n%s", closeBody)
	}
	if freeIdx == nil {
		t.Errorf("static guard: S8 failed — Close() body missing e.arena.Free(). Close body:\n%s", closeBody)
	}
	if waitIdx != nil && freeIdx != nil && waitIdx[0] >= freeIdx[0] {
		t.Errorf("static guard: S8 failed — Close() body ordering: e.persistWorkerWg.Wait() must textually precede e.arena.Free() (drain before arena teardown). Close body:\n%s", closeBody)
	}

	// S9 scoped to both NextDot and AdvanceLamportTo bodies.
	if !s9Select.MatchString(nextDotBody) {
		t.Errorf("static guard: S9 failed — NextDot body missing non-blocking select { case e.persistCh <- nextLimit: default: }. NextDot body:\n%s", nextDotBody)
	}
	if !s9Select.MatchString(advLamBody) {
		t.Errorf("static guard: S9 failed — AdvanceLamportTo body missing non-blocking select { case e.persistCh <- nextLimit: default: }. AdvanceLamportTo body:\n%s", advLamBody)
	}
}

// extractFuncBody returns a named method through the next top-level method.
// Limiting each source check to this slice prevents locks and channel sends in
// the persist worker from matching checks for NextDot or AdvanceLamportTo.
// returnsSig is retained by callers for signature context but is not needed by
// the method-name parser.
func extractFuncBody(src, name, returnsSig string) string {
	_ = returnsSig
	// Scan byte-wise for "func (" at column 0 followed by ") Name(".
	needle := []byte(") " + name + "(")
	startIdx := -1
	for i := 0; i < len(src); i++ {
		if src[i] != 'f' {
			continue
		}
		if src[i:i+len("func (")] != src[i:i+6] && !(hasPrefixAt(src, i, "func (")) {
			continue
		}
		if !atLineStart(src, i) {
			continue
		}
		// find ") Name(" after i
		j := indexOfAt(src, needle, i+6)
		if j < 0 {
			continue
		}
		// must be before the next newline (same signature line).
		nl := indexOfAt(src, []byte("\n"), i)
		if nl > 0 && j < nl {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		return ""
	}
	// Find the next "func (" at column 0 strictly after startIdx.
	nextIdx := -1
	for i := startIdx + 1; i < len(src); i++ {
		if src[i] == 'f' && atLineStart(src, i) && hasPrefixAt(src, i, "func (") {
			nextIdx = i
			break
		}
	}
	end := len(src)
	if nextIdx > startIdx {
		end = nextIdx
	}
	return src[startIdx:end]
}

// hasPrefixAt reports whether s at off starts with p.
func hasPrefixAt(s string, off int, p string) bool {
	if off+len(p) > len(s) {
		return false
	}
	return s[off:off+len(p)] == p
}

// atLineStart reports whether off is at column 0 of a line (off==0 or the
// previous byte is '\n').
func atLineStart(s string, off int) bool {
	if off == 0 {
		return true
	}
	return s[off-1] == '\n'
}

// indexOfAt returns the byte index of sub in s[off:], or -1.
func indexOfAt(s string, sub []byte, off int) int {
	if off >= len(s) {
		return -1
	}
	tail := s[off:]
	if len(sub) == 0 {
		return off
	}
	for i := 0; i+len(sub) <= len(tail); i++ {
		if tail[i:i+len(sub)] == string(sub) {
			return off + i
		}
	}
	return -1
}

// TestNoBlockingFsyncDrive runs NumCPU workers and records the slowest final
// NextDot call. The limit is 50 ms below 32 workers and 100 ms at 32 or more.
// These thresholds tolerate scheduler and storage variation; the static and
// durability checks provide the stronger decoupling assertions.
func TestNoBlockingFsyncDrive(t *testing.T) {
	if testing.Short() {
		t.Skip("no-blocking-fsync drive: GOMAXPROCS-heavy; skip in -short (the 1-NextDot durability sub-case in TestDurabilityRoundTrip always runs).")
	}
	numCPU := runtime.NumCPU()
	workers := numCPU
	t.Logf("no-blocking-fsync drive: runtime.NumCPU()=%d; workers=%d", numCPU, workers)

	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() { DataDir = oldDir })

	engine, err := NewDeltaCRDTEngine([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("no-blocking-fsync drive: NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()

	var tMax atomic.Int64 // nanoseconds
	var wg sync.WaitGroup
	// Each worker makes 1,000 NextDot calls. Timing the final call samples a
	// warmed engine after earlier calls have exercised the persist worker.
	const perWorker = 1000
	wg.Add(workers)
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			<-start
			var last time.Duration
			for i := 0; i < perWorker; i++ {
				t0 := time.Now()
				_ = engine.NextDot()
				last = time.Since(t0)
			}
			ns := int64(last)
			for {
				cur := tMax.Load()
				if ns <= cur || tMax.CompareAndSwap(cur, ns) {
					break
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	tMaxDur := time.Duration(tMax.Load())
	threshold := 50 * time.Millisecond
	if workers >= 32 {
		threshold = 100 * time.Millisecond
	}
	t.Logf("no-blocking-fsync drive: t_MAX (last NextDot per worker)=%s; threshold=%s (workers=%d, NumCPU=%d)", tMaxDur, threshold, workers, numCPU)
	if tMaxDur >= threshold {
		t.Errorf("no-blocking-fsync drive: slowest final NextDot=%s, limit=%s; investigate blocking in the persist handoff", tMaxDur, threshold)
	}
}

// TestDurabilityRoundTrip checks that Close waits for persisted Lamport state
// before releasing the arena. The steady case calls NextDot 1,001 times before
// reconstruction. The cold case calls it once and closes immediately, repeated
// 100 times to vary worker scheduling. Both require recovery of 1001.
//
// The one-call case also runs in short mode; only the latency drive is skipped.
func TestDurabilityRoundTrip(t *testing.T) {
	numCPU := runtime.NumCPU()
	t.Logf("durability round-trip: runtime.NumCPU()=%d", numCPU)

	// Steady case: 1,001 NextDot calls still recover the first persisted window.
	t.Run("Steady_1001NextDot", func(t *testing.T) {
		dir := t.TempDir()

		eng1, err := NewDeltaCRDTEngine([16]byte{0xAA, 0xBB, 0xCC}, 0, 64*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine(1): %v", err)
		}
		eng1.SetDataDir(dir)
		for i := 0; i < 1001; i++ {
			_ = eng1.NextDot()
		}
		if err := eng1.Close(); err != nil {
			t.Fatalf("eng1.Close: %v", err)
		}

		// Construction reads the package-level DataDir before SetDataDir can take
		// effect. Close this intermediate engine, set DataDir, and construct the
		// engine whose recovered counter is checked.
		eng2, err := NewDeltaCRDTEngine([16]byte{0xAA, 0xBB, 0xCC}, 0, 64*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine(2): %v", err)
		}
		eng2.SetDataDir(dir)
		_ = eng2.Close()
		oldDir := DataDir
		DataDir = dir
		t.Cleanup(func() { DataDir = oldDir })
		eng3, err := NewDeltaCRDTEngine([16]byte{0xAA, 0xBB, 0xCC}, 0, 64*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine(3): %v", err)
		}
		recovered := eng3.LamportCounter()
		_ = eng3.Close()

		// The first persist NextDot fires at counter=1 -> nextLimit = 1001.
		// The worker persists 1001; Close drains -> file reads 1001.
		const want uint64 = 1001
		if recovered != want {
			t.Errorf("durability round-trip steady: recovered Lamport counter=%d, want %d — Close() did not drain the persist worker before arena.Free (the durability round-trip broke)", recovered, want)
		} else {
			t.Logf("durability round-trip steady: recovered Lamport counter=%d == want %d (Close-drain held)", recovered, want)
		}
	})

	// Cold case: one NextDot followed immediately by Close, repeated to vary the
	// worker schedule. The expected nextLimit is 1 + 1000 = 1001.
	t.Run("OneNextDot_ThenClose_RaceSurface", func(t *testing.T) {
		const iterations = 100
		var sawMiss int64
		var sawOK int64
		for iter := 0; iter < iterations; iter++ {
			dir := t.TempDir()
			oldDir := DataDir
			DataDir = dir
			eng, err := NewDeltaCRDTEngine([16]byte{0x11, 0x22, 0x33}, 0, 64*1024*1024)
			if err != nil {
				t.Fatalf("iter %d: NewDeltaCRDTEngine: %v", iter, err)
			}
			_ = eng.NextDot()
			if err := eng.Close(); err != nil {
				t.Fatalf("iter %d: Close: %v", iter, err)
			}
			eng2, err := NewDeltaCRDTEngine([16]byte{0x11, 0x22, 0x33}, 0, 64*1024*1024)
			if err != nil {
				t.Fatalf("iter %d: NewDeltaCRDTEngine(2): %v", iter, err)
			}
			recovered := eng2.LamportCounter()
			_ = eng2.Close()
			DataDir = oldDir

			// The single NextDot fires at counter=1 -> nextLimit=1001.
			// Under the decouple Close() drains the worker, so the file must
			// read 1001 (no scheduler-luck dependency).
			const want uint64 = 1001
			if recovered != want {
				atomic.AddInt64(&sawMiss, 1)
				t.Logf("durability round-trip 1-NextDot iteration %d: recovered=%d want=%d; Close returned before the value was durable", iter, recovered, want)
			} else {
				atomic.AddInt64(&sawOK, 1)
			}
		}
		t.Logf("durability round-trip 1-NextDot: iterations=%d ok=%d miss=%d; every iteration must recover 1001", iterations, atomic.LoadInt64(&sawOK), atomic.LoadInt64(&sawMiss))
		if sawMiss != 0 {
			t.Errorf("durability round-trip 1-NextDot: %d/%d iterations missed the persisted value; Close did not drain the persist worker before arena.Free", sawMiss, iterations)
		}
	})
}

// _labels retains strconv for use by package-local test helpers.
var _labels = strconv.Itoa
