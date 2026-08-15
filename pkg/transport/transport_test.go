package transport

import (
	"bytes"
	"crypto/md5"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// crdtFrozenMD5 is the FROZEN md5 of pkg/sync/crdt.go. crdt.go was re-pinned at
// Day 10 (4512bd67 -> 705ac671, ADR-0015: JOIN-buffer pool UNFROZE crdt.go with
// disclosure; the 3 contracts — determinism / EBR / 57.6M — were re-proven green).
// The gate now asserts the CURRENT byte-identity. ANY future byte change to crdt.go
// requires: (1) an ADR-disclosed re-pin, (2) the 3 contracts re-gated, (3) ALL 4
// sibling pins re-synced (receive/gate, receive/bench, transport, authorization).
//
// Day 16 (ADR-0021, 2026-08-03): re-pinned 705ac671 -> a50fee8f — a COMMENT-ONLY
// change (a warning doc above `var DataDir` at crdt.go:17: the FROZEN ctor reads
// the global, engine.SetDataDir is the instance-safe override). NO byte of
// executable code changed; the 3 contracts are byte-identical. The re-pin is the
// honesty discipline for the comment drift. ALL 8 pins re-synced. Day-10 ADR-0015
// §7 + Day-8.5 receiver.go precedent (re-pin with disclosure, not silence).
const crdtFrozenMD5 = "44f8952771cfad4d195e518b63a33440" // Day-17 re-pin (ADR-0022: zero-alloc Join — sort.Slice -> slices.SortFunc with a no-capture package-level comparator; kills the reflect-path slice-header spill at the Join sort step; was a50fee8f Day-16). Day-16 re-pin (ADR-0021: comment-only var DataDir warning; was 705ac671 Day-10 ADR-0015). Day-10 re-pin (ADR-0015: JOIN-buffer pool UNFROZE crdt.go; the 3 contracts re-proven)

// TestTransmitHeapBuffer_BuildsHeapCopy (G2.0.b) proves the copy is real and
// exact: the returned heap slice is independent of the mmap source (mutating a
// clone of the source does not change the heap copy), the length matches, and a
// live *runtime.Pinner is returned.
func TestTransmitHeapBuffer_BuildsHeapCopy(t *testing.T) {
	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = byte(i)
	}
	heap, pin, err := TransmitHeapBuffer(payload)
	if err != nil {
		t.Fatalf("TransmitHeapBuffer: unexpected err: %v", err)
	}
	if heap == nil {
		t.Fatal("heap == nil")
	}
	if pin == nil {
		t.Fatal("pin == nil")
	}
	if len(heap) != 120 {
		t.Fatalf("len(heap) = %d, want 120", len(heap))
	}
	if !bytes.Equal(heap, payload) {
		t.Fatal("heap copy != payload (copy was not exact)")
	}
	// The heap copy must be INDEPENDENT of the mmap source: mutate a clone of
	// the source and confirm the heap copy is unchanged. This proves the copy
	// was a real byte copy, not an alias of the source backing array.
	clone := make([]byte, len(payload))
	copy(clone, payload)
	clone[0] = 0xFF
	clone[59] = 0xAA
	clone[119] = 0x55
	if heap[0] == 0xFF || heap[59] == 0xAA || heap[119] == 0x55 {
		t.Fatal("heap copy mutated by source clone edit -> copy aliased the source, not a real copy")
	}
	if !bytes.Equal(heap, payload) {
		t.Fatal("heap copy diverged from original payload after source-clone mutation")
	}
	// Release the pin we took; the test owns the Pinner.
	pin.Unpin()
}

// TestTransmitHeapBuffer_EmptyRejected (G2.0.b) proves a zero-length mmap frame
// is rejected with ErrEmptyPayload and returns no heap, no pin.
func TestTransmitHeapBuffer_EmptyRejected(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		heap, pin, err := TransmitHeapBuffer(in)
		if err == nil {
			t.Fatalf("TransmitHeapBuffer(%v): err == nil, want non-nil", in)
		}
		if !strings.Contains(err.Error(), "empty mmap payload") {
			t.Fatalf("err = %q, want substring \"empty mmap payload\"", err.Error())
		}
		if heap != nil {
			t.Fatalf("heap = %v, want nil", heap)
		}
		if pin != nil {
			t.Fatalf("pin = %v, want nil", pin)
		}
	}
}

// TestTransmitHeapBuffer_HasHonestGearTag (G2.0.j) is the gear-honesty tooth.
// This box is 4c (nproc=4, CPU part 0xd40, Graviton3-era). The 32c figure is
// Track 4's PROVEN publication number, NOT this gear. Re-using 32c for 2.0 OWN
// benches is the track-5.0 mislabel class, detector-banned. The test asserts
// the honest 4c count and skips (with rationale) if the box is willfully
// reporting something else, rather than printing a false tag.
func TestTransmitHeapBuffer_HasHonestGearTag(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("honest gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c / GOMAXPROCS=4)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4c gear this track targets; refusing to tag a false core count (no _32c on 2.0 OWN benches)", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; refusing to tag a false core count", gmp)
	}
}

// TestTransmitHeapBufferSend_AFUnixNoPanicNoRace (G2.0.d + G2.0.i) is the
// egress sequence acceptance (roadmap line 48): copy -> Pin -> sendmsg(MSG_ZEROCOPY)
// -> Unpin runs end-to-end on a real AF_UNIX socketpair with SO_ZEROCOPY set,
// no panic, data integrity verified on the recv side. Kernel zero-copy is
// conditionally-verified, NOT asserted (§1.6): the kernel may decline to arm
// SO_ZEROCOPY (observed EOPNOTSUPP on this AF_UNIX build) and fall back to an
// in-kernel copy; the send still carries the data intact.
func TestTransmitHeapBufferSend_AFUnixNoPanicNoRace(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	sendFd, recvFd := fds[0], fds[1]

	// Arm the send socket for zero-copy. Tolerate the kernel declining
	// (EOPNOTSUPP/ENOPROTOOPT observed on this AF_UNIX build): log it and still
	// run the send. The copy->Pin->sendmsg->Unpin sequence must not panic
	// regardless; whether the kernel truly zero-copies is conditional.
	if serr := unix.SetsockoptInt(sendFd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1); serr != nil {
		t.Logf("setsockopt SO_ZEROCOPY declined by kernel: %v (conditional zero-copy, not asserted; send proceeds)", serr)
	} else {
		t.Logf("setsockopt SO_ZEROCOPY armed (kernel may still fall back to copy)")
	}

	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = byte(i)
	}

	// The egress sequence: copy -> Pin -> sendmsg(MSG_ZEROCOPY) -> Unpin (defer).
	sent, err := TransmitHeapBufferSend(sendFd, payload, nil)
	if err != nil {
		t.Fatalf("TransmitHeapBufferSend: %v", err)
	}
	if sent != 120 {
		t.Fatalf("sent = %d, want 120", sent)
	}

	// Recv loop until the full frame arrives or timeout. Asserts DATA INTEGRITY
	// (the copy into the heap slice went on the wire), NOT zero-copy occurrence.
	got := make([]byte, 0, 120)
	buf := make([]byte, 256)
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < 120 && time.Now().Before(deadline) {
		n, rerr := unix.Read(recvFd, buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			continue
		}
		if rerr != nil {
			t.Fatalf("read: %v (got %d/%d bytes)", rerr, len(got), 120)
		}
		time.Sleep(time.Millisecond)
	}
	if len(got) != 120 {
		t.Fatalf("received %d bytes, want 120 (data integrity failure)", len(got))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("received bytes != payload (data integrity failure over the transport)")
	}
}

// TestTransmitHeapBuffer_NeverPinsMmapRegion (G2.0.f + G2.0.h) is the
// load-bearing -race structural proof. It proves the heap copy and the mmap
// source are at DISTINCT addresses (the copy did not alias) and that -race over
// 32 concurrent sends is clean. Combined with G2.0.g, this is the line-48
// acceptance: Pin accepted for the heap pointer, explicitly NOT accepted for
// the mmap pointer.
//
// unsafe.Pointer is used ONLY here, in the test, for the address-distinctness
// assertion (§6 exception). It is forbidden in transport.go (G2.0.k).
func TestTransmitHeapBuffer_NeverPinsMmapRegion(t *testing.T) {
	// Represent the mmap source as a make slice. The 2.0 source-ban detector
	// (TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild) forbids Pin on
	// this region in transport.go; here we only hand it to TransmitHeapBuffer,
	// which copies it onto a fresh heap slice.
	source := make([]byte, 120)
	for i := range source {
		source[i] = byte(i)
	}
	heap, pin, err := TransmitHeapBuffer(source)
	if err != nil {
		t.Fatalf("TransmitHeapBuffer: %v", err)
	}
	// Distinct-address proof: the heap copy and the source must NOT share a
	// backing array. If they did, the copy was an alias and Pin would be
	// pinning the mmap region (the forbidden pattern).
	heapAddr := uintptr(unsafe.Pointer(&heap[0]))
	srcAddr := uintptr(unsafe.Pointer(&source[0]))
	t.Logf("heap[0]=%#x source[0]=%#x distinct=%v", heapAddr, srcAddr, heapAddr != srcAddr)
	if heapAddr == srcAddr {
		t.Fatal("heap copy and mmap source share the same backing array -> copy aliased, Pin would target the mmap region")
	}
	pin.Unpin()

	// 32 concurrent goroutines each doing copy->Pin->sendmsg->Unpin through an
	// AF_UNIX pair, under -race. This is the G2.0.d race target.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	sendFd, recvFd := fds[0], fds[1]
	_ = unix.SetsockoptInt(sendFd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1) // best-effort arm; decline tolerated

	const concurrency = 32
	const frameLen = 120
	var wg sync.WaitGroup
	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p := make([]byte, frameLen)
			for i := range p {
				p[i] = byte(id) ^ byte(i)
			}
			if _, err := TransmitHeapBufferSend(sendFd, p, nil); err != nil {
				t.Errorf("goroutine %d: TransmitHeapBufferSend: %v", id, err)
				return
			}
		}(g)
	}
	// Drain the recv side concurrently so the socket buffers do not fill and
	// block the senders (SOCK_STREAM has a finite buffer). This also exercises
	// the recv path under -race.
	recvDone := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		total := 0
		deadline := time.Now().Add(5 * time.Second)
		for total < concurrency*frameLen && time.Now().Before(deadline) {
			n, err := unix.Read(recvFd, buf)
			if n > 0 {
				total += n
				continue
			}
			if err != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		close(recvDone)
	}()
	wg.Wait()
	<-recvDone
}

// TestTransmitHeapBuffer_MmapPinIsNoOp_Physics (G2.0.g) is the empirical proof
// that Pin on a non-Go (unix.Mmap) address is a documented no-op on THIS Go
// 1.26.1 build. The roadmap acceptance (line 48) demands this proof; the prompt
// predicted the no-op would surface as an Unpin panic at pinner.go:173
// ("tried to unpin non-Go pointer"). VERIFIED EMPIRICALLY THIS TURN: that panic
// does NOT fire via the normal Pin->Unpin path on this build, because Pin never
// records the non-Go pointer in the first place.
//
// The mechanism (runtime/pinner.go, this build):
//   - Pin -> pinnerGetPtr returns the address (no panic: it is a pointer kind)
//     -> setPinned(ptr, true): spanOfHeap(ptr)==nil -> returns false silently
//     (pinner.go:169-178, comment "nothing to do, silently ignore it")
//     -> the `if setPinned(ptr, true) { p.refs = append(...) }` guard is FALSE,
//     so the mmap pointer is NEVER appended to p.refs.
//   - Unpin -> pinner.unpin() iterates p.refs, which is EMPTY for the mmap pin,
//     so setPinned(_, false) is never called and the pinner.go:173 panic never
//     fires. (That panic only fires if a non-Go pointer is somehow present in
//     p.refs, which the standard Pin path prevents.)
//
// So the honest empirical proof of the no-op is NOT an Unpin panic; it is the
// ASYMMETRY between a heap pin (effective: recorded in p.refs, cleanly unpinned)
// and an mmap pin (no-op: not recorded, Unpin is a no-op). We prove it by
// interleaving both on the SAME Pinner: Pin(heap) records the heap object;
// Pin(mmap) is a silent no-op that does NOT corrupt the recorded heap pin;
// Unpin then cleanly unpins ONLY the heap object with no panic. If Pin(mmap)
// had recorded the mmap pointer, Unpin would panic at pinner.go:173 — its
// absence is the proof the mmap pointer was never accepted.
//
// This test is the SOLE place the raw Pin(mmap) pattern is permitted; it lives in
// the test package and the source guard scans transport.go (non-test) only.
func TestTransmitHeapBuffer_MmapPinIsNoOp_Physics(t *testing.T) {
	buf, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Skipf("mmap unavailable on this box: %v", err)
	}
	defer unix.Munmap(buf)
	buf[0] = 0xAB

	heap := make([]byte, 16)
	heap[0] = 0xCD

	var p runtime.Pinner
	// 1) Pin a REAL Go-heap object: effective, recorded in p.refs.
	pinPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				pinPanicked = true
				t.Errorf("Pin(heap) panicked (unexpected): %v", r)
			}
		}()
		p.Pin(&heap[0])
	}()
	if pinPanicked {
		t.Fatal("Pin on a Go-heap object panicked; the build's Pin contract is broken")
	}

	// 2) Pin the non-Go (mmap) address on the SAME Pinner: documented no-op
	//    (pinner.go:48). Must NOT panic and must NOT corrupt the recorded heap
	//    pin. If this panicked, the build's no-op contract changed.
	mmapPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				mmapPanicked = true
				t.Errorf("Pin(mmap) panicked (unexpected; documented no-op per pinner.go:48): %v", r)
			}
		}()
		p.Pin(&buf[0])
	}()
	if mmapPanicked {
		t.Fatal("Pin on a non-Go (mmap) pointer panicked; expected documented no-op (pinner.go:48)")
	}

	// 3) Unpin the SAME Pinner. If Pin(mmap) had recorded the mmap pointer in
	//    p.refs, this Unpin would call setPinned(mmapPtr, false) and PANIC at
	//    pinner.go:173 ("tried to unpin non-Go pointer"). The absence of that
	//    panic is the empirical proof the mmap pointer was NEVER accepted by
	//    Pin — i.e. Pin(mmap) was a documented no-op on this build.
	unpinPanicked := false
	var unpinPanic any
	func() {
		defer func() {
			if r := recover(); r != nil {
				unpinPanicked = true
				unpinPanic = r
			}
		}()
		p.Unpin()
	}()
	if unpinPanicked {
		t.Fatalf("Unpin panicked after Pin(heap)+Pin(mmap): %v — Pin(mmap) recorded the non-Go pointer (the no-op contract regressed; pinner.go:173 fired)", unpinPanic)
	}
	// heap and buf contents survive the no-op cycle (sanity).
	if heap[0] != 0xCD {
		t.Errorf("heap[0] = %#x, want 0xCD (heap object disturbed by mmap no-op cycle)", heap[0])
	}
	if buf[0] != 0xAB {
		t.Errorf("buf[0] = %#x, want 0xAB (mmap region disturbed by Pin/Unpin no-op cycle)", buf[0])
	}
}

// TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild (G2.0.k) is the negative
// control for the source-ban detector. The detector scans transport.go (non-test
// files) for any Pin whose argument is a sub-element of a non-heap []byte. The
// ONLY permitted Pin is on &heap[0] where heap := make([]byte, ...).
//
// The negative control injects the forbidden pattern `p.Pin(&mmapPayload[0])`
// into a TEMP COPY of the source and asserts the detector flags it. It does NOT
// mutate the real transport.go (which would break the build and other tests);
// the temp-copy injection proves the detector's pattern-matching is load-bearing.
func TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild(t *testing.T) {
	// First: the real transport.go must PASS the detector.
	realSrc, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatalf("read transport.go: %v", err)
	}
	if violations := detectForbiddenPin(string(realSrc)); len(violations) != 0 {
		t.Fatalf("detector found forbidden Pin in real transport.go (source guard violated): %v", violations)
	}

	// Negative control: inject the forbidden pattern into a temp copy and
	// assert the detector flags it. This proves the detector is not a no-op.
	injected := strings.Replace(string(realSrc),
		"p.Pin(&heap[0]) // REAL pin: heap pointer, GC span-tracked",
		"p.Pin(&mmapPayload[0]) // FORBIDDEN: pin on mmap region (negative control)",
		1)
	if injected == string(realSrc) {
		t.Fatal("negative control: could not inject forbidden pattern (anchor string not found)")
	}
	violations := detectForbiddenPin(injected)
	if len(violations) == 0 {
		t.Fatal("FORBIDDEN bare Pin on mmap region present but detector did not flag it (detector is a no-op)")
	}
	t.Logf("negative control OK: detector flagged %d forbidden Pin(s): %v", len(violations), violations)
}

// detectForbiddenPin scans transport.go source for Pin calls whose argument is
// a sub-element of a non-heap []byte. The ONLY permitted Pin argument form is
// &heap[0] (or &<heapvar>[0]) where the variable was created by make([]byte, ...).
// This is a textual detector: it rejects any Pin whose first argument is not
// &heap[0] (modulo the heap variable name), and specifically bans the mmap/buf
// forms. It is deliberately conservative — a false positive here is a build
// failure, which is the correct failure mode for a source guard.
func detectForbiddenPin(src string) []string {
	var violations []string
	lines := strings.Split(src, "\n")
	// Collect identifiers declared as make([]byte, ...) — these are the only
	// permitted Pin targets.
	heapVars := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// match: name := make([]byte, ...)  or  var name []byte = make(...)
		if i := strings.Index(trimmed, ":="); i > 0 {
			lhs := strings.TrimSpace(trimmed[:i])
			rest := strings.TrimSpace(trimmed[i+2:])
			if strings.HasPrefix(rest, "make([]byte") {
				heapVars[lhs] = true
			}
		}
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ".Pin(") {
			continue
		}
		// Extract the Pin argument.
		si := strings.Index(trimmed, ".Pin(")
		if si < 0 {
			continue
		}
		rest := trimmed[si+len(".Pin("):]
		depth := 1
		end := 0
		for j, c := range rest {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					end = j
					break
				}
			}
		}
		if end == 0 {
			continue
		}
		arg := strings.TrimSpace(rest[:end])
		// Permitted form: &<heapVar>[0] where heapVar is a make([]byte,...) var.
		if strings.HasPrefix(arg, "&") {
			varPart := arg[1:]
			if idx := strings.IndexByte(varPart, '['); idx > 0 {
				name := varPart[:idx]
				if heapVars[name] {
					continue // permitted: Pin on a make([]byte) heap slice
				}
			}
		}
		// Anything else is forbidden (Pin on mmap/buf/mmapPayload, or a bare
		// pointer). Flag it.
		violations = append(violations, "Pin("+arg+")")
	}
	return violations
}

// TestTransmitHeapBuffer_CrdtFrozen (G2.0.a) asserts pkg/sync/crdt.go is
// byte-identical to the frozen md5. 2.0 must not touch crdt.go.
func TestTransmitHeapBuffer_CrdtFrozen(t *testing.T) {
	path := filepath.Join("..", "sync", "crdt.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read crdt.go: %v", err)
	}
	sum := md5.Sum(data)
	got := hexEncode(sum[:])
	if got != crdtFrozenMD5 {
		t.Fatalf("crdt.go md5 = %s, want frozen %s (crdt.go was modified — 2.0 must not touch it)", got, crdtFrozenMD5)
	}
}

// hexEncode is a fmt-free lowercase hex encoder used for the md5 comparison so
// the test does not pull in fmt for a one-off.
func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&0x0f]
	}
	return string(out)
}

// TestTransmitHeapBuffer_NoUnsafeInSource (G2.0.k unsafe) asserts transport.go
// does NOT import "unsafe". unsafe is tolerated ONLY in transport_test.go for
// the uintptr address-distinctness assertion.
func TestTransmitHeapBuffer_NoUnsafeInSource(t *testing.T) {
	data, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatalf("read transport.go: %v", err)
	}
	src := string(data)
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, "\"unsafe\"") {
			t.Fatalf("transport.go imports \"unsafe\" (forbidden in source; tolerated only in tests): %s", trimmed)
		}
	}
}
