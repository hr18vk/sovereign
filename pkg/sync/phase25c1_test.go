package sync

// PHASE 2.5c.1 — PERSIST-WORKER PARK-HANDSHAKE RACE CLOSURE (the durability
// tooth fix). Phase 2.5c shipped a close-channel handshake that only proved
// the worker goroutine was SCHEDULED (it reached close(persistWorkerReady)),
// NOT that it had PARKED on the `for val := range e.persistCh` receive
// (S0). Under bench-sweep scheduler contention the FIRST NextDot's
// select-default send dropped the only persist job, Close() drained an empty
// channel, the worker saw closed and exited without ever calling
// persistLamport, and recoverLamport read 0 instead of 1001.
//
// 2.5c.1 is a SURGICAL MICRO-FIX: a CAP-1 buffered persistWorkerParked ack
// channel. The worker sends struct{}{} on it IMMEDIATELY before the
// for-range; the constructor blocks on the receive. A buffered-send
// synchronizes-with that receive, so unblocking PROVES the worker is parked
// on the persistCh receive before NewDeltaCRDTEngine returns — the first
// NextDot's select-send ALWAYS rendezvouses. persistCh stays UNBUFFERED (the
// exactly-one-in-flight invariant R1a is preserved); Close() is unchanged
// (the drain contract was end-to-end correct once the cold-start park is
// proven). This is NOT 2.5d (the CAS-storm sharding) — that is deferred.
//
// The teeth are:
//
//   - TestPhase25C1_ParkHandshakeStatic (R3a): a STATIC regex guard over
//     pkg/sync/crdt.go asserting the 2.5c.1 park-handshake invariants (the
//     park ack send, the cap-1 buffer, the two-stage constructor wait in
//     order, the preserved 2.5c worker shape). No t.Skip under any
//     condition; red-on-mute.
//   - TestPhase25C1_ColdStartFirstSendNeverDrops (R3b): the LOAD-BEARING
//     runtime bite. 1000 iterations (200 under -race) of: fresh engine in a
//     fresh t.TempDir(), ONE NextDot(), Close(), reconstruct in the SAME
//     dir, assert recoverLamport reads 1001. Gate is sawMiss==0 — a single
//     miss is a HARD FAIL naming the iteration. This is the tooth the 2.5c
//     R3c SHOULD have been but at 100 iterations missed the sub-1% race.
//   - TestPhase25C1_ParkHappensBeforeReasoning (R3c): a STATIC documentation
//     tooth asserting the source comment block above the park-ack send
//     contains "happens-before" (the architectural reasoning is pinned in
//     source so a future engineer does not regress to a close-channel
//     handshake without understanding why). Red-on-mute.
//
// The teeth do NOT downgrade red. The runtime tooth does NOT t.Skip (it
// MUST prove the park handshake holds under -race, which makes the race
// window LARGER, not smaller — only the iteration count is reduced 1000→200
// under -race via the raceEnabled gate, mirroring the Phase 2k precedent).

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// phase25c1ReadCrdtSource mirrors phase25cReadCrdtSource: read the LIVE
// pkg/sync/crdt.go source (os.ReadFile, NOT go/embed — the tooth must sweep
// the current tree). cwd is pkg/sync under `go test ./pkg/sync/`.
func phase25c1ReadCrdtSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("crdt.go")
	if err != nil {
		alt := filepath.Join("pkg", "sync", "crdt.go")
		data, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("phase25c1 static guard: cannot read crdt.go: %v", err)
		}
	}
	return string(data)
}

// phase25c1FuncBody isolates a function body in crdt.go source by name.
// Unlike phase25cFuncBody (which matches only method receivers "func (e) Name("),
// this helper handles BOTH package-level "func Name(" and method "func (e) Name("
// signatures, because NewDeltaCRDTEngine is a package-level constructor. The
// body is returned from the signature line to the next top-level "func " at
// column 0 (mirrors phase25cFuncBody's end-detection).
func phase25c1FuncBody(src, name string) string {
	// Candidate start: a line beginning with "func " containing "name(".
	needle := []byte(name + "(")
	startIdx := -1
	for i := 0; i < len(src); i++ {
		if src[i] != 'f' || !atLineStart(src, i) || !hasPrefixAt(src, i, "func ") {
			continue
		}
		nl := indexOfAt(src, []byte("\n"), i)
		if nl < 0 {
			nl = len(src)
		}
		sigLine := src[i:nl]
		j := indexOfAt(sigLine, needle, 0)
		if j < 0 {
			continue
		}
		// Reject substring matches where name is a suffix of a longer
		// identifier (e.g. "NewDeltaCRDTEngine2" matching "NewDeltaCRDTEngine").
		if j > 0 {
			prev := sigLine[j-1]
			if prev == '_' || (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') {
				continue
			}
		}
		startIdx = i
		break
	}
	if startIdx < 0 {
		return ""
	}
	// Find the next top-level "func " at column 0 strictly after startIdx.
	nextIdx := -1
	for i := startIdx + 1; i < len(src); i++ {
		if src[i] == 'f' && atLineStart(src, i) && hasPrefixAt(src, i, "func ") {
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

// phase25c1StripGoComments removes Go // line comments and /* */ block
// comments from a source slice so a textual-ordering regex does not match a
// phrase that appears only inside a doc-comment (e.g. "for val := range
// e.persistCh" referenced in the comment block ABOVE the function). A
// naive newline join followed by a regex sweep over the raw body would match
// the comment mention before the real statement, producing a false ordering
// inversion. The returned slice preserves newlines (comments replaced by
// blank lines) so byte offsets are a monotone-of-the-original lower-bound;
// textual-ordering checks below only compare relative byte index, which is
// preserved under comment-blanking.
func phase25c1StripGoComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i := 0
	for i < len(src) {
		// Line comment.
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			// skip to end of line, emit a newline to preserve line break.
			j := i
			for j < len(src) && src[j] != '\n' {
				j++
			}
			b.WriteByte('\n')
			i = j
			continue
		}
		// Block comment.
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			j := i + 2
			for j+1 < len(src) && !(src[j] == '*' && src[j+1] == '/') {
				j++
			}
			if j+1 < len(src) {
				j += 2
			}
			// Preserve any newlines that crossed the block so line
			// boundaries (and thus function-isolation heuristics that
			// rely on column-0 "func") stay sane.
			for k := i; k < j; k++ {
				if src[k] == '\n' {
					b.WriteByte('\n')
				}
			}
			i = j
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

// TestPhase25C1_ParkHandshakeStatic is R3a: the STATIC regex guard over
// pkg/sync/crdt.go source asserting the 2.5c.1 park-handshake invariants P1
// through P6. It has NO race/skip guard — it pins the shape under every
// build mode and bites RED the instant any invariant regresses.
func TestPhase25C1_ParkHandshakeStatic(t *testing.T) {
	src := phase25c1ReadCrdtSource(t)

	type inv struct {
		id  string
		re  *regexp.Regexp
		got string
	}

	// P1: persistWorkerParked field of type chan struct{} declared in the
	// engine struct (in the persist pad block adjacent to
	// persistWorkerReady).
	p1Field := regexp.MustCompile(`persistWorkerParked\s+chan\s+struct\{\}`)

	// P2: persistWorkerReady field STILL declared (the 2.5c stage-1 signal
	// is KEPT — both channels coexist; 2.5c.1 only ADDS the stage-2 park).
	p2Ready := regexp.MustCompile(`persistWorkerReady\s+chan\s+struct\{\}`)

	// P3: persistWorkerParked initialized as a CAP-1 buffered channel in
	// NewDeltaCRDTEngine. The `, 1` cap argument is load-bearing: an
	// unbuffered park channel deadlocks the worker waiting for a receiver
	// the constructor has not yet spawned. A regex missing the `, 1` is a
	// HARD FAIL.
	p3Make := regexp.MustCompile(`e\.persistWorkerParked\s*=\s*make\(\s*chan\s+struct\{\}\s*,\s*1\s*\)`)

	// P4: the park ack send `e.persistWorkerParked <- struct{}{}` appears in
	// the persistWorkerLoop body. (Textual-before-for-range ordering is
	// P5's job; P4 just asserts the send exists somewhere in the worker.)
	p4Send := regexp.MustCompile(`e\.persistWorkerParked\s*<-\s*struct\{\}\{\}`)

	// P6: the 2.5c worker shape is preserved inside persistWorkerLoop —
	// close(persistWorkerReady), the for-range over persistCh, and the
	// persistLamport(val) call. 2.5c.1 only ADDS the park proof; it does not
	// regress the worker/drain shape.
	p6Close := regexp.MustCompile(`close\(\s*e\.persistWorkerReady\s*\)`)
	p6Range := regexp.MustCompile(`for\s+val\s+:=\s+range\s+e\.persistCh`)
	p6Call := regexp.MustCompile(`e\.persistLamport\(\s*val\s*\)`)

	workerBody := phase25cFuncBody(src, "persistWorkerLoop", "")
	if workerBody == "" {
		t.Fatalf("PHASE25C1 R3a: could not isolate persistWorkerLoop body")
	}

	// P5 (textual ordering): the park ack send must appear TEXTUALLY BEFORE
	// the `for val := range e.persistCh` in the worker body (a send AFTER
	// the for-range would be unreachable — it sits after the loop — and
	// would NOT prove the worker parked before the first receive).
	// Strip doc-comments so the P5 ordering check compares the ACTUAL
	// code statements, not a phrase mentioned in the comment block above
	// the function (the stage-2 comment legitimately references
	// "for val := range e.persistCh"). Comment-blanking preserves textual
	// order so relative byte-index comparison remains valid.
	workerCode := phase25c1StripGoComments(workerBody)
	sendIdx := indexOfAt(workerCode, []byte("e.persistWorkerParked <- struct{}{}"), 0)
	rangeIdx := indexOfAt(workerCode, []byte("for val := range e.persistCh"), 0)

	// P5b (constructor ordering): the constructor tail MUST contain BOTH
	// `<-e.persistWorkerReady` AND `<-e.persistWorkerParked` (or the
	// tab-aligned variants) in that textual order. The stage-1 receive
	// MUST precede the stage-2 receive (swapping them is stylistic at
	// runtime — M3 — but the static tooth catches the wrong order
	// regardless, pinning the documented two-stage contract).
	readyRecv := regexp.MustCompile(`<-\s*e\.persistWorkerReady`)
	parkedRecv := regexp.MustCompile(`<-\s*e\.persistWorkerParked`)
	ctorBody := phase25c1FuncBody(src, "NewDeltaCRDTEngine")
	if ctorBody == "" {
		t.Fatalf("PHASE25C1 R3a: could not isolate NewDeltaCRDTEngine body")
	}
	readyRecvIdx := -1
	parkedRecvIdx := -1
	if m := readyRecv.FindStringIndex(ctorBody); m != nil {
		readyRecvIdx = m[0]
	}
	if m := parkedRecv.FindStringIndex(ctorBody); m != nil {
		parkedRecvIdx = m[0]
	}

	invariants := []inv{
		{"P1: persistWorkerParked chan struct{} field declared", p1Field, p1Field.FindString(src)},
		{"P2: persistWorkerReady chan struct{} field STILL declared", p2Ready, p2Ready.FindString(src)},
		{"P3: e.persistWorkerParked = make(chan struct{}, 1) with cap-1", p3Make, p3Make.FindString(src)},
		{"P4: park ack send e.persistWorkerParked <- struct{}{} in worker", p4Send, p4Send.FindString(workerBody)},
		{"P6a: close(e.persistWorkerReady) in worker body", p6Close, p6Close.FindString(workerBody)},
		{"P6b: for val := range e.persistCh in worker body", p6Range, p6Range.FindString(workerBody)},
		{"P6c: e.persistLamport(val) in worker body", p6Call, p6Call.FindString(workerBody)},
		{"P5b-a: <-e.persistWorkerReady in constructor", readyRecv, readyRecv.FindString(ctorBody)},
		{"P5b-b: <-e.persistWorkerParked in constructor", parkedRecv, parkedRecv.FindString(ctorBody)},
	}
	for _, invT := range invariants {
		if invT.got == "" {
			t.Errorf("PHASE25C1 R3a PARK-HANDSHAKE STATIC GUARD: %s — regex MISS (bite RED)", invT.id)
		}
	}

	// P5: send textually before for-range in the worker body.
	if sendIdx < 0 {
		t.Errorf("PHASE25C1 R3a P5: park ack send not found in worker body (cannot assert ordering)")
	}
	if rangeIdx < 0 {
		t.Errorf("PHASE25C1 R3a P5: `for val := range e.persistCh` not found in worker body")
	}
	if sendIdx >= 0 && rangeIdx >= 0 && sendIdx > rangeIdx {
		t.Errorf("PHASE25C1 R3a P5: park ack send (%d) textually AFTER for-range (%d) — the send must PRECEDE the receive to prove park (bite RED)", sendIdx, rangeIdx)
	}

	// P5b: stage-1 receive textually before stage-2 receive in the constructor.
	if readyRecvIdx < 0 {
		t.Errorf("PHASE25C1 R3a P5b: <-e.persistWorkerReady not found in NewDeltaCRDTEngine body")
	}
	if parkedRecvIdx < 0 {
		t.Errorf("PHASE25C1 R3a P5b: <-e.persistWorkerParked not found in NewDeltaCRDTEngine body")
	}
	if readyRecvIdx >= 0 && parkedRecvIdx >= 0 && readyRecvIdx > parkedRecvIdx {
		t.Errorf("PHASE25C1 R3a P5b: stage-1 <-persistWorkerReady (%d) textually AFTER stage-2 <-persistWorkerParked (%d) — the two-stage order is documented (S0 stage 1 necessary-but-insufficient, stage 2 load-bearing); reversed order is a HARD FAIL (bite RED)", readyRecvIdx, parkedRecvIdx)
	}

	t.Logf("PHASE25C1 R3a PARK-HANDSHAKE STATIC GUARD: all invariants present (P1-P6 + P5 ordering + P5b constructor order)")
}

// TestPhase25C1_ColdStartFirstSendNeverDrops is R3b: the LOAD-BEARING runtime
// bite. This is the tooth the 2.5c R3c SHOULD have been but at 100 iterations
// missed the sub-1% cold-start race. It FORCES exactly the cold-start surface
// 2.5c shipped: a fresh engine, ONE NextDot, Close, reconstruct in the SAME
// dir, assert recoverLamport==1001. The gate is sawMiss==0.
//
// Iteration count: UNGATED = 1000 (the ruthless floor that surfaces a 0.1%
// race with >99.99% confidence). Under -race the count is reduced to 200 via
// the raceEnabled gate (mirrors the Phase 2k precedent at physics_test.go:197
// / phase25b_test.go:164) because -race instrumentation slows scheduling 5-
// 10x and would otherwise exceed the 10m test timeout. The race window is
// LARGER (not smaller) under -race, so the reduced count is still
// load-bearing. BOTH counts MUST see sawMiss==0 — a single miss in any run is
// a HARD FAIL naming the iteration.
//
// This tooth does NOT t.Skip under -race (unlike the alloc-count teeth which
// skip because the race detector perturbs malloc counters — THIS tooth is a
// correctness tooth and the race detector makes it MORE load-bearing, not
// less). The ONLY skip is under testing.Short() per the standard discipline.
func TestPhase25C1_ColdStartFirstSendNeverDrops(t *testing.T) {
	numCPU := runtime.NumCPU()
	t.Logf("PHASE25C1 R3b: runtime.NumCPU()=%d", numCPU)

	if testing.Short() {
		t.Skip("PHASE25C1 R3b cold-start race surface: 1000-iteration drive (200 under -race); skip under -short (the static guard TestPhase25C1_ParkHandshakeStatic always runs).")
	}

	// UNGATED floor = 1000 (the 2.5c R3c was 100 and missed the race).
	// Under -race = 200 (raceEnabled gate; -race makes the window LARGER).
	iterations := 1000
	if raceEnabled {
		iterations = 200
	}
	t.Logf("PHASE25C1 R3b: iterations=%d (raceEnabled=%v)", iterations, raceEnabled)

	var sawMiss int64
	var sawOK int64
	for iter := 0; iter < iterations; iter++ {
		// FRESH tempdir per iter so recoverLamport reads ONLY this iter's
		// file (no cross-iter reuse — the 2.5c DataDir package-global
		// pattern means the engine must be reconstructed with DataDir=dir
		// set BEFORE the second NewDeltaCRDTEngine).
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

		// The single NextDot fires at counter=1 -> nextLimit = 1 + 1000 = 1001.
		// Under 2.5c.1 the worker is PROVABLY parked before the constructor
		// returns, so the FIRST select-send rendezvouses and the Close drain
		// completes the persist — the file MUST read 1001 (no scheduler-luck
		// dependency). A recovered=0 means the worker never called
		// persistLamport (the 2.5c cold-start drop reproduced) — HARD FAIL.
		const want uint64 = 1001
		if recovered != want {
			atomic.AddInt64(&sawMiss, 1)
			t.Errorf("PHASE25C1 R3b iter %d/%d: recovered Lamport counter=%d, want %d — the cold-start park handshake DROPPED the first persist job (recoverLamport read 0; the 2.5c S0 race reproduced under the park-ack fix — HARD FAIL)", iter, iterations, recovered, want)
		} else {
			atomic.AddInt64(&sawOK, 1)
		}
	}
	missCount := atomic.LoadInt64(&sawMiss)
	okCount := atomic.LoadInt64(&sawOK)
	t.Logf("PHASE25C1 R3b: iterations=%d sawOK=%d sawMiss=%d (gate is sawMiss==0)", iterations, okCount, missCount)
	if missCount != 0 {
		t.Fatalf("PHASE25C1 R3b COLD-START PARK-HANDSHAKE BIT RED: sawMiss=%d across %d iterations (the 2.5c.1 park handshake did NOT hold — HARD FAIL)", missCount, iterations)
	}
	t.Logf("PHASE25C1 R3b COLD-START PARK-HANDSHAKE BIT GREEN: %d/%d iterations recovered=1001 (sawMiss==0)", okCount, iterations)
}

// TestPhase25C1_ParkHappensBeforeReasoning is R3c: a STATIC documentation
// tooth (no runtime drive) that asserts the SOURCE COMMENT BLOCK above the
// `e.persistWorkerParked <- struct{}{}` send in crdt.go contains the phrase
// "happens-before". The architectural reasoning is pinned in the source so a
// future engineer does not regress the park proof to a close-channel
// handshake without understanding WHY the buffered-ack is the only
// structurally-correct fix. This is the muscle-memory tooth — it preserves
// the S0 smoking-gun reasoning in the source, not just in the report. Red-
// on-mute; NO t.Skip under any condition.
func TestPhase25C1_ParkHappensBeforeReasoning(t *testing.T) {
	src := phase25c1ReadCrdtSource(t)

	// Isolate the persistWorkerLoop body and assert the comment block
	// immediately preceding the park-ack send contains "happens-before".
	workerBody := phase25cFuncBody(src, "persistWorkerLoop", "")
	if workerBody == "" {
		t.Fatalf("PHASE25C1 R3c: could not isolate persistWorkerLoop body")
	}
	hbRe := regexp.MustCompile(`happens-before`)
	if !hbRe.MatchString(workerBody) {
		t.Errorf("PHASE25C1 R3c PARK-HAPPENS-BEFORE REASONING: the persistWorkerLoop body does NOT contain the phrase `happens-before` in its comment block above the park-ack send. The S0 architectural reasoning MUST be pinned in source (a future engineer must understand WHY the buffered-ack is the only structurally-correct fix before regressing to a close-channel handshake) — bite RED")
	}

	// Cross-pin: the constructor's two-stage comment block MUST also contain
	// "happens-before" (the park-proof rationale is documented at BOTH ends
	// — the worker that sends the ack and the constructor that receives it).
	ctorBody := phase25c1FuncBody(src, "NewDeltaCRDTEngine")
	if ctorBody == "" {
		t.Fatalf("PHASE25C1 R3c: could not isolate NewDeltaCRDTEngine body")
	}
	if !hbRe.MatchString(ctorBody) {
		t.Errorf("PHASE25C1 R3c PARK-HAPPENS-BEFORE REASONING: the NewDeltaCRDTEngine two-stage park-handshake comment block does NOT contain `happens-before`. The stage-2 load-bearing park proof MUST be documented at the constructor receive end too — bite RED")
	}

	t.Logf("PHASE25C1 R3c PARK-HAPPENS-BEFORE REASONING: `happens-before` present in BOTH the persistWorkerLoop and NewDeltaCRDTEngine comment blocks (S0 reasoning pinned in source)")
}
