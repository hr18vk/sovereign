package sync

// PHASE 2.5c — persistMu DISK-MUTEX DECOPLE (the LAST internal-engine sub-
// phase before Phase 3). These teeth pin the Path A architectural posture
// mandated by S0: the CAS callers (NextDot / AdvanceLamportTo) NO LONGER
// block on the fsync inside persistMu; a single dedicated background
// goroutine (persistWorkerLoop) drains an UNBUFFERED chan uint64 and owns
// the f.Sync()+os.Rename UNDER persistMu. The disk-serialization contract
// (tmp file + rename, 8 bytes BigEndian) is byte-identical to pre-2.5c —
// only the CAS caller no longer blocks on the lock-hold.
//
// The teeth are:
//
//   - TestPhase25C_PersistWorkerDecoupledStatic (R3a): a STATIC regex guard
//     over pkg/sync/crdt.go source that bites RED the instant any of S1-S9
//     is missing (the moment someone re-grabs persistMu inside NextDot or
//     AdvanceLamportTo, the moment the worker spawn goes away, the moment
//     the select-default send is replaced by a blocking send, etc.).
//   - TestPhase25C_NoBlockingFsyncDrive (R3b): a runtime sanity drive that
//     mints Lamport advancement in GOMAXPROCS goroutines and measures the
//     max wall-clock of the LAST NextDot() per goroutine. Thresholds are
//     lenient on purpose — on NVMe this tooth does NOT bite RED on pre-2.5c
//     (the gate is satisfied incidentally); it is a sanity check that
//     post-2.5c the t_MAX STAYS low.
//   - TestPhase25C_DurabilityRoundTrip (R3c): the LOAD-BEARING runtime
//     bite. Mints NextDot calls, Close()s the engine (which drains the
//     worker via persistWorkerWg.Wait BEFORE arena.Free), reconstructs a
//     NEW engine in the SAME dataDir, and asserts recoverLamport reads the
//     persisted value. Mutation M4 (remove the Wait from Close) breaks the
//     1-NextDot sub-case with high probability (it runs the sub-case many
//     times to surface the scheduler race).
//
// The teeth do NOT downgrade red. They do NOT t.Skip under any condition
// other than testing.Short() (the static guard has NO race/skip guard; the
// runtime teeth MAY skip the GOMAXPROCS-heavy parts under testing.Short()
// but the 1-NextDot durability sub-case MUST always run). NO fmt.Sprintf
// on any hot loop of these teeth — stack buffers / strconv only (Phase 2l.1
// makeBinaryKey discipline; §1 scope Dijkstra R5 amnesty applies — do NOT
// gate the teeth on allocs/op, but DO NOT hot-allocate either).

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

// phase25cReadCrdtSource is the single load point for the static guard's
// regex sweep. It is intentionally a helper (not inlined into every assert)
// so a failure can report precisely which invariant missed. It reads the
// file via os.ReadFile (NOT go/embed — the tooth must sweep the LIVE
// source on the current tree, not a stale build-time snapshot).
func phase25cReadCrdtSource(t *testing.T) string {
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
			t.Fatalf("phase25c static guard: cannot read crdt.go: %v", err)
		}
	}
	return string(data)
}

// TestPhase25C_PersistWorkerDecoupledStatic is R3a: the STATIC regex guard
// over pkg/sync/crdt.go source. It asserts ALL of S1-S9 and bites RED with
// a precise regex-miss message for EACH missing invariant. The static guard
// has NO race/skip guard (R3e) — it pins the shape under every build mode.
func TestPhase25C_PersistWorkerDecoupledStatic(t *testing.T) {
	src := phase25cReadCrdtSource(t)

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

	// S5: NextDot body MUST NOT contain e.persistMu.Lock() (regex absence).
	// S6: AdvanceLamportTo body MUST NOT contain e.persistMu.Lock() (regex
	// absence). We isolate the body of each function by slicing from its
	// signature line to the next top-level `func` declaration so the
	// absence check is scoped to that function body only (persistMu.Lock
	// elsewhere — e.g. the persist worker loop and the setters — is
	// EXPECTED and correct).
	nextDotBody := phase25cFuncBody(src, "NextDot", "CausalDot")
	advLamBody := phase25cFuncBody(src, "AdvanceLamportTo", "")

	persistMuLock := regexp.MustCompile(`e\.persistMu\.Lock\(\)`)

	// S7: persistWorkerLoop body MUST contain `for val := range e.persistCh`
	// AND `e.persistLamport(val)` inside it (the worker is the ONLY caller
	// of persistLamport now). The S7 regexes are swept over the WHOLE src
	// (locking the worker's body to the channel-range + the persistLamport
	// call is done implicitly by S4 + the unique identifiers).
	s7Range := regexp.MustCompile(`for\s+val\s+:=\s+range\s+e\.persistCh`)
	s7Call := regexp.MustCompile(`e\.persistLamport\(\s*val\s*\)`)

	// S8: Close() body MUST contain
	//   e.persistStopOnce.Do(func() { close(e.persistCh) })
	// and e.persistWorkerWg.Wait() BEFORE e.arena.Free() (regex ordering:
	// the Wait MUST textually precede arena.Free).
	closeBody := phase25cFuncBody(src, "Close", "error")
	s8OnceClose := regexp.MustCompile(`e\.persistStopOnce\.Do\(\s*func\(\)\s*\{\s*close\(\s*e\.persistCh\s*\)\s*\}\s*\)`)
	s8Wait := regexp.MustCompile(`e\.persistWorkerWg\.Wait\(\)`)
	s8Free := regexp.MustCompile(`e\.arena\.Free\(\)`)

	// S9: NextDot + AdvanceLamportTo MUST each contain a non-blocking
	// select: `select { case e.persistCh <- nextLimit: default: }` (regex
	// on the select + default).
	s9Select := regexp.MustCompile(`select\s*\{\s*\n\s*case\s+e\.persistCh\s*<-\s*nextLimit\s*:\s*\n\s*default\s*:`)

	invs := []inv{
		{"S1 (persistCh chan uint64 field declared)", s1Field, "persistCh chan uint64 field declaration MISSING"},
		{"S1 (make(chan uint64) cap-0 unbuffered in NewDeltaCRDTEngine)", s1Make, "make(chan uint64) cap-0 (unbuffered) call MISSING — a buffered chan would re-introduce tmp-file races"},
		{"S2 (persistWorkerWg sync.WaitGroup field declared)", s2, "persistWorkerWg sync.WaitGroup field declaration MISSING"},
		{"S3 (persistStopOnce sync.Once field declared)", s3, "persistStopOnce sync.Once field declaration MISSING"},
		{"S4 (go e.persistWorkerLoop() spawn in NewDeltaCRDTEngine)", s4, "go e.persistWorkerLoop() spawn MISSING — the worker never starts; channel sends hang / persist never happens"},
		{"S7 (persistWorkerLoop: for val := range e.persistCh)", s7Range, "persistWorkerLoop body MISSING `for val := range e.persistCh` — the worker is not draining the channel"},
		{"S7 (persistWorkerLoop: e.persistLamport(val) inside range)", s7Call, "persistWorkerLoop body MISSING `e.persistLamport(val)` — the worker is NOT the caller of persistLamport"},
	}
	for _, iv := range invs {
		if !iv.re.MatchString(src) {
			t.Errorf("PHASE25C STATIC GUARD: %s FAILED — %s", iv.id, iv.got)
		}
	}

	// S5 / S6 scoped to the function body.
	if persistMuLock.MatchString(nextDotBody) {
		t.Errorf("PHASE25C STATIC GUARD: S5 FAILED — NextDot body contains e.persistMu.Lock(); the decouple is undone (the CAS caller must NOT block on the disk mutex). NextDot body:\n%s", nextDotBody)
	}
	if persistMuLock.MatchString(advLamBody) {
		t.Errorf("PHASE25C STATIC GUARD: S6 FAILED — AdvanceLamportTo body contains e.persistMu.Lock(); the decouple is undone. AdvanceLamportTo body:\n%s", advLamBody)
	}

	// S8 scoped to Close body.
	if !s8OnceClose.MatchString(closeBody) {
		t.Errorf("PHASE25C STATIC GUARD: S8 FAILED — Close() body MISSING e.persistStopOnce.Do(func(){ close(e.persistCh) }) (idempotent worker stop). Close body:\n%s", closeBody)
	}
	waitIdx := s8Wait.FindStringIndex(closeBody)
	freeIdx := s8Free.FindStringIndex(closeBody)
	if waitIdx == nil {
		t.Errorf("PHASE25C STATIC GUARD: S8 FAILED — Close() body MISSING e.persistWorkerWg.Wait(). Close body:\n%s", closeBody)
	}
	if freeIdx == nil {
		t.Errorf("PHASE25C STATIC GUARD: S8 FAILED — Close() body MISSING e.arena.Free(). Close body:\n%s", closeBody)
	}
	if waitIdx != nil && freeIdx != nil && waitIdx[0] >= freeIdx[0] {
		t.Errorf("PHASE25C STATIC GUARD: S8 FAILED — Close() body ordering: e.persistWorkerWg.Wait() MUST textually precede e.arena.Free() (drain BEFORE arena teardown). Close body:\n%s", closeBody)
	}

	// S9 scoped to both NextDot and AdvanceLamportTo bodies.
	if !s9Select.MatchString(nextDotBody) {
		t.Errorf("PHASE25C STATIC GUARD: S9 FAILED — NextDot body MISSING non-blocking select { case e.persistCh <- nextLimit: default: }. NextDot body:\n%s", nextDotBody)
	}
	if !s9Select.MatchString(advLamBody) {
		t.Errorf("PHASE25C STATIC GUARD: S9 FAILED — AdvanceLamportTo body MISSING non-blocking select { case e.persistCh <- nextLimit: default: }. AdvanceLamportTo body:\n%s", advLamBody)
	}
}

// phase25cFuncBody slices the source from the signature line of the named
// method to the next top-level `func (` declaration (a line starting with
// `func (`). It is a robust-enough parse for the static guard: it isolates
// the body of the named function so scoped-absence regexes (S5/S6/S8/S9)
// do not match `e.persistMu.Lock()` or `e.persistCh` that legitimately
// appear in OTHER functions (the worker, the setters). returnsSig (e.g.
// "error" or "CausalDot") is currently unused beyond disambiguation; the
// sweep matches the first top-level method line carrying `) Name(`.
func phase25cFuncBody(src, name, returnsSig string) string {
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

// TestPhase25C_NoBlockingFsyncDrive is R3b: the runtime sanity drive. It
// mints Lamport advancement in GOMAXPROCS goroutines (clamped to
// runtime.NumCPU()) and measures the max wall-clock of the LAST NextDot()
// call per goroutine. The gate: t_MAX < 50ms at NumCPU=4 and t_MAX < 100ms
// at NumCPU=32. The thresholds are LENIENT ON PURPOSE — on NVMe this tooth
// does NOT bite RED on pre-2.5c (the gate is satisfied incidentally).
// Documented honestly in §6; it is NOT the load-bearing bite (R3c is).
func TestPhase25C_NoBlockingFsyncDrive(t *testing.T) {
	if testing.Short() {
		t.Skip("PHASE25C R3b no-blocking-fsync drive: GOMAXPROCS-heavy; skip in -short (the 1-NextDot durability sub-case in TestPhase25C_DurabilityRoundTrip always runs).")
	}
	numCPU := runtime.NumCPU()
	workers := numCPU
	t.Logf("PHASE25C R3b: runtime.NumCPU()=%d; workers=%d", numCPU, workers)

	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() { DataDir = oldDir })

	engine, err := NewDeltaCRDTEngine([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("PHASE25C R3b: NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()

	var tMax atomic.Int64 // nanoseconds
	var wg sync.WaitGroup
	// Each worker mints 1000 NextDot() calls — each goroutine trips persistMu
	// once on pre-2.5c code; under 2.5c the persist is non-blocking.
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
	t.Logf("PHASE25C R3b: t_MAX (last NextDot per worker)=%s; threshold=%s (workers=%d, NumCPU=%d)", tMaxDur, threshold, workers, numCPU)
	if tMaxDur >= threshold {
		t.Errorf("PHASE25C R3b: t_MAX=%s >= threshold %s — a CAS caller blocked on the persist path (the decouple may be undone; NextDot must NOT block on fsync)", tMaxDur, threshold)
	}
}

// TestPhase25C_DurabilityRoundTrip is R3c: the LOAD-BEARING runtime bite.
// It exercises the Close()-drains-the-worker contract:
//
//   - Sub-case A ("steady"): mint 1001 NextDot() calls (the first persist
//     fires at counter=1 with lastSaved=0 -> nextLimit=1001; the worker
//     persists 1001; lastSaved advances to 1001). Close() drains the worker;
//     reconstruct a NEW engine in the SAME dataDir; recoverLamport MUST
//     read 1001.
//   - Sub-case B ("1-NextDot then Close"): mint exactly ONE NextDot, then
//     immediately Close(). The worker may not have drained the job yet
//     when Close returns — 2.5c's persistWorkerWg.Wait() BEFORE arena.Free
//     is the contract that FORCES the drain. Mutation M4 (remove the Wait)
//     breaks this sub-case with high probability; to surface the race the
//     sub-case runs 100 iterations.
//
// The sub-case MUST always run (R3e) — only the GOMAXPROCS-heavy parts of
// R3b may skip under testing.Short(); this tooth's 1-NextDot sub-case runs
// even in -short.
func TestPhase25C_DurabilityRoundTrip(t *testing.T) {
	numCPU := runtime.NumCPU()
	t.Logf("PHASE25C R3c: runtime.NumCPU()=%d", numCPU)

	// Sub-case A: steady-state 1001 NextDot -> recovered value == 1001.
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

		// Reconstruct in the SAME dataDir; recoverLamport MUST read 1001.
		eng2, err := NewDeltaCRDTEngine([16]byte{0xAA, 0xBB, 0xCC}, 0, 64*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine(2): %v", err)
		}
		eng2.SetDataDir(dir)
		// recoverLamport ran in NewDeltaCRDTEngine using the DEFAULT DataDir
		// (set via the package global). To force a re-read against `dir`, we
		// close eng2 and rebuild with DataDir=dir set BEFORE construction via
		// the package global (the constructor reads the package global for
		// its initial dataDir; SetDataDir mutates after the fact and does
		// NOT re-run recoverLamport). So set the package global before the
		// SECOND construction directly.
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

		// The FIRST persist NExtDot fires at counter=1 -> nextLimit = 1001.
		// The worker persists 1001; Close drains -> file reads 1001.
		const want uint64 = 1001
		if recovered != want {
			t.Errorf("PHASE25C R3c Steady: recovered Lamport counter=%d, want %d — Close() did not drain the persist worker before arena.Free (the durability round-trip broke)", recovered, want)
		} else {
			t.Logf("PHASE25C R3c Steady: recovered Lamport counter=%d == want %d (Close-drain held)", recovered, want)
		}
	})

	// Sub-case B: 1 NextDot then Close, many iterations to surface the race
	// that M4 (remove Wait from Close) introduces. The persisted value for
	// a single NextDot is nextLimit = 1 + 1000 = 1001.
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
			// Under 2.5c Close() DRAINS the worker, so the file MUST read
			// 1001 (no scheduler-luck dependency).
			const want uint64 = 1001
			if recovered != want {
				atomic.AddInt64(&sawMiss, 1)
				t.Logf("PHASE25C R3c 1-NextDot iter %d: recovered=%d want=%d (Close-drain MISS — the worker was killed mid-fsync before arena.Free)", iter, recovered, want)
			} else {
				atomic.AddInt64(&sawOK, 1)
			}
		}
		t.Logf("PHASE25C R3c 1-NextDot: iterations=%d ok=%d miss=%d (Close-drain must read 1001 every iteration; any miss is a decouple regression)", iterations, atomic.LoadInt64(&sawOK), atomic.LoadInt64(&sawMiss))
		if sawMiss != 0 {
			t.Errorf("PHASE25C R3c 1-NextDot: %d/%d iterations missed the persisted value — Close() did not drain the persist worker before arena.Free (M4-style regression)", sawMiss, iterations)
		}
	})
}

// _labels keeps strconv reachable so two-letter variable usage stays clean.
var _labels = strconv.Itoa
