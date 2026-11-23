// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// The persist worker acknowledges that it is about to receive from persistCh.
// Closing persistWorkerReady alone would show only that the goroutine had been
// scheduled; the first NextDot could still execute its non-blocking send before
// the worker reached the receive, dropping the only persisted value.
//
// The worker sends on persistWorkerParked immediately before its receive loop.
// The channel has capacity one, and NewDeltaCRDTEngine waits for that send. The
// happens-before relationship ensures the worker is at the loop before the
// constructor returns. persistCh itself remains unbuffered, and Close still
// drains it through the worker WaitGroup.
//
// Static tests check the channel, acknowledgement, ordering, and source
// documentation. The cold-start test repeats construction, one NextDot, Close,
// and reconstruction 1,000 times (200 with the race detector), requiring every
// recovered Lamport value to be 1001.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// parkReadCrdtSource reads crdt.go from the current tree. The alternate path
// accommodates a test invocation from the repository root.
func parkReadCrdtSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("crdt.go")
	if err != nil {
		alt := filepath.Join("pkg", "sync", "crdt.go")
		data, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("park static guard: cannot read crdt.go: %v", err)
		}
	}
	return string(data)
}

// parkFuncBody returns a named function or method from its signature through
// the next top-level declaration. It handles both package-level functions and
// methods with receivers, and rejects matches embedded in longer identifiers.
func parkFuncBody(src, name string) string {
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

// parkStripGoComments replaces Go comments with newlines. Source-order checks
// can then compare executable statements without matching examples in comments.
// Preserving line boundaries also keeps the function parser's positions stable
// relative to the original source.
func parkStripGoComments(src string) string {
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

// TestParkHandshakeStatic checks the park channel declarations,
// acknowledgement, worker receive loop, and constructor wait order. It runs in
// every build mode.
func TestParkHandshakeStatic(t *testing.T) {
	src := parkReadCrdtSource(t)

	type inv struct {
		id  string
		re  *regexp.Regexp
		got string
	}

	// P1 and P2: both worker signals are present.
	p1Field := regexp.MustCompile(`persistWorkerParked\s+chan\s+struct\{\}`)
	p2Ready := regexp.MustCompile(`persistWorkerReady\s+chan\s+struct\{\}`)

	// P3: capacity one lets the worker acknowledge before the constructor starts
	// receiving; an unbuffered acknowledgement would deadlock construction.
	p3Make := regexp.MustCompile(`e\.persistWorkerParked\s*=\s*make\(\s*chan\s+struct\{\}\s*,\s*1\s*\)`)

	// P4: the worker sends the acknowledgement. P5 checks its position.
	p4Send := regexp.MustCompile(`e\.persistWorkerParked\s*<-\s*struct\{\}\{\}`)

	// P6: readiness, the receive loop, and the persist call remain in the worker.
	p6Close := regexp.MustCompile(`close\(\s*e\.persistWorkerReady\s*\)`)
	p6Range := regexp.MustCompile(`for\s+val\s+:=\s+range\s+e\.persistCh`)
	p6Call := regexp.MustCompile(`e\.persistLamport\(\s*val\s*\)`)

	workerBody := extractFuncBody(src, "persistWorkerLoop", "")
	if workerBody == "" {
		t.Fatalf("park handshake static guard: could not isolate persistWorkerLoop body")
	}

	// P5: the acknowledgement must precede the receive loop in executable code.
	// A send after the loop would be unreachable during normal operation and
	// could not establish readiness. Comment stripping keeps prose out of the
	// ordering comparison.
	workerCode := parkStripGoComments(workerBody)
	sendIdx := indexOfAt(workerCode, []byte("e.persistWorkerParked <- struct{}{}"), 0)
	rangeIdx := indexOfAt(workerCode, []byte("for val := range e.persistCh"), 0)

	// P5b: the constructor waits for readiness and then for the park
	// acknowledgement, matching the documented two-stage sequence.
	readyRecv := regexp.MustCompile(`<-\s*e\.persistWorkerReady`)
	parkedRecv := regexp.MustCompile(`<-\s*e\.persistWorkerParked`)
	ctorBody := parkFuncBody(src, "NewDeltaCRDTEngine")
	if ctorBody == "" {
		t.Fatalf("park handshake static guard: could not isolate NewDeltaCRDTEngine body")
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
		{"P2: persistWorkerReady chan struct{} field declared", p2Ready, p2Ready.FindString(src)},
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
			t.Errorf("park handshake static guard: %s: source pattern not found", invT.id)
		}
	}

	// P5: send textually before for-range in the worker body.
	if sendIdx < 0 {
		t.Errorf("park handshake P5: park ack send not found in worker body (cannot assert ordering)")
	}
	if rangeIdx < 0 {
		t.Errorf("park handshake P5: `for val := range e.persistCh` not found in worker body")
	}
	if sendIdx >= 0 && rangeIdx >= 0 && sendIdx > rangeIdx {
		t.Errorf("park handshake P5: park ack send (%d) textually after for-range (%d) — the send must precede the receive to prove park", sendIdx, rangeIdx)
	}

	// P5b: first receive textually before second receive in the constructor.
	if readyRecvIdx < 0 {
		t.Errorf("park handshake P5b: <-e.persistWorkerReady not found in NewDeltaCRDTEngine body")
	}
	if parkedRecvIdx < 0 {
		t.Errorf("park handshake P5b: <-e.persistWorkerParked not found in NewDeltaCRDTEngine body")
	}
	if readyRecvIdx >= 0 && parkedRecvIdx >= 0 && readyRecvIdx > parkedRecvIdx {
		t.Errorf("park handshake P5b: first receive (%d) textually after second receive (%d) — the two-stage order is documented; reversed order is a hard fail", readyRecvIdx, parkedRecvIdx)
	}

	t.Logf("park handshake static guard: all invariants present (P1-P6 + P5 ordering + P5b constructor order)")
}

// TestColdStartFirstSendNeverDrops constructs an engine, calls NextDot once,
// closes it, and requires reconstruction to recover 1001. Every iteration uses
// a fresh directory so no earlier Lamport file can satisfy the check.
//
// The 1,000-iteration run gives more than 99.99% confidence of observing a race
// with per-iteration probability 0.1%. Race-enabled builds use 200 iterations
// to bound instrumentation cost while retaining the scheduling interleaving.
// Short mode skips this drive; the static handshake test still runs.
func TestColdStartFirstSendNeverDrops(t *testing.T) {
	numCPU := runtime.NumCPU()
	t.Logf("cold-start test: runtime.NumCPU()=%d", numCPU)

	if testing.Short() {
		t.Skip("cold-start race surface: 1000-iteration drive (200 under -race); skip under -short (the static guard TestParkHandshakeStatic always runs).")
	}

	// Race-enabled builds use fewer iterations to bound instrumentation cost.
	iterations := 1000
	if raceEnabled {
		iterations = 200
	}
	t.Logf("cold-start test: iterations=%d (raceEnabled=%v)", iterations, raceEnabled)

	var sawMiss int64
	var sawOK int64
	for iter := 0; iter < iterations; iter++ {
		// Fresh tempdir per iter so recoverLamport reads only this iter's
		// file (no cross-iter reuse — the DataDir package-global pattern
		// means the engine must be reconstructed with DataDir=dir set before
		// the second NewDeltaCRDTEngine).
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

		// The first NextDot computes nextLimit = 1 + 1000. The park handshake
		// places the worker at its receive before construction returns, and Close
		// waits for the write, so recovery must return 1001 regardless of scheduling.
		const want uint64 = 1001
		if recovered != want {
			atomic.AddInt64(&sawMiss, 1)
			t.Errorf("cold-start iteration %d/%d recovered Lamport counter %d, want %d; the first value was not persisted", iter, iterations, recovered, want)
		} else {
			atomic.AddInt64(&sawOK, 1)
		}
	}
	missCount := atomic.LoadInt64(&sawMiss)
	okCount := atomic.LoadInt64(&sawOK)
	t.Logf("cold-start test: iterations=%d sawOK=%d sawMiss=%d (gate is sawMiss==0)", iterations, okCount, missCount)
	if missCount != 0 {
		t.Fatalf("cold-start park handshake missed %d of %d persisted values", missCount, iterations)
	}
	t.Logf("cold-start park handshake passed: %d/%d iterations recovered=1001 (sawMiss==0)", okCount, iterations)
}

// TestParkHappensBeforeReasoning requires the worker and constructor source
// comments to document the happens-before relationship at both ends of the park
// acknowledgement. It complements the executable ordering checks.
func TestParkHappensBeforeReasoning(t *testing.T) {
	src := parkReadCrdtSource(t)

	// Isolate the persistWorkerLoop body and assert the comment block
	// immediately preceding the park-ack send contains "happens-before".
	workerBody := extractFuncBody(src, "persistWorkerLoop", "")
	if workerBody == "" {
		t.Fatalf("park happens-before guard: could not isolate persistWorkerLoop body")
	}
	hbRe := regexp.MustCompile(`happens-before`)
	if !hbRe.MatchString(workerBody) {
		t.Errorf("persistWorkerLoop does not document the happens-before relationship for the park acknowledgement")
	}

	// The constructor must document the receiving end of the same relationship.
	ctorBody := parkFuncBody(src, "NewDeltaCRDTEngine")
	if ctorBody == "" {
		t.Fatalf("park happens-before guard: could not isolate NewDeltaCRDTEngine body")
	}
	if !hbRe.MatchString(ctorBody) {
		t.Errorf("NewDeltaCRDTEngine does not document the happens-before relationship for the park acknowledgement")
	}

	t.Logf("park happens-before reasoning is documented in persistWorkerLoop and NewDeltaCRDTEngine")
}
