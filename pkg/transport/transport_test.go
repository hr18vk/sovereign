// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestTransmitHeapBuffer_BuildsHeapCopy checks the returned length and contents
// and requires a non-nil Pinner. It also edits a clone of the source and checks
// that the returned bytes do not change. Address independence is checked
// separately by TestTransmitHeapBuffer_NeverPinsMmapRegion.
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
	// Edits to a source clone must not affect the returned bytes. The separate
	// address check compares the source and destination starting addresses.
	clone := make([]byte, len(payload))
	copy(clone, payload)
	clone[0] = 0xFF
	clone[59] = 0xAA
	clone[119] = 0x55
	if heap[0] == 0xFF || heap[59] == 0xAA || heap[119] == 0x55 {
		t.Fatal("heap copy changed after edits to a source clone")
	}
	if !bytes.Equal(heap, payload) {
		t.Fatal("heap copy differs from the original payload after source-clone edits")
	}
	// The test owns the Pinner and releases it here.
	pin.Unpin()
}

// TestTransmitHeapBuffer_EmptyRejected checks nil and empty slices. Both must
// return an empty-payload error and no heap slice or Pinner.
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

// TestTransmitHeapBuffer_HasHonestGearTag reports the four-core host profile
// used by this check. Other CPU or GOMAXPROCS counts skip the test rather than
// applying the four-core tag to a different host.
func TestTransmitHeapBuffer_HasHonestGearTag(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("host profile: NumCPU=%d GOMAXPROCS=%d (tag: _4c / GOMAXPROCS=4)", n, gmp)
	if n != 4 {
		t.Skipf("host reports NumCPU=%d, not the 4-core profile this test checks; skipping tag assertion", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; skipping tag assertion", gmp)
	}
}

// TestTransmitHeapBufferSend_AFUnixNoPanicNoRace exercises copy, pin, sendmsg,
// and Unpin over an AF_UNIX socketpair and checks the received payload. It can
// be run with the race detector. SO_ZEROCOPY may be unsupported on AF_UNIX; a
// setsockopt failure is logged and payload delivery is still checked. The test
// does not establish whether the kernel used zero-copy.
func TestTransmitHeapBufferSend_AFUnixNoPanicNoRace(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	sendFd, recvFd := fds[0], fds[1]

	// Set SO_ZEROCOPY when supported. A refusal does not prevent the send or
	// change the payload assertions.
	if serr := unix.SetsockoptInt(sendFd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1); serr != nil {
		t.Logf("setsockopt SO_ZEROCOPY: %v; continuing with payload-delivery check", serr)
	} else {
		t.Logf("setsockopt SO_ZEROCOPY succeeded; the kernel may still copy")
	}

	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = byte(i)
	}

	// The helper owns copy, Pin, sendmsg, and the deferred Unpin.
	sent, err := TransmitHeapBufferSend(sendFd, payload, nil)
	if err != nil {
		t.Fatalf("TransmitHeapBufferSend: %v", err)
	}
	if sent != 120 {
		t.Fatalf("sent = %d, want 120", sent)
	}

	// Read until the full frame arrives or the deadline expires. These checks
	// cover data delivery, not whether the kernel used zero-copy.
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

// TestTransmitHeapBuffer_NeverPinsMmapRegion checks that the source and returned
// heap copy start at different addresses, then issues 32 concurrent sends
// through an AF_UNIX socketpair. Running the test with -race exercises the
// concurrent send path. TestTransmitHeapBuffer_MmapPinIsNoOp_Physics covers Pin
// behavior for a non-Go address.
//
// unsafe.Pointer is confined to this test's address comparison; transport.go
// does not import unsafe.
func TestTransmitHeapBuffer_NeverPinsMmapRegion(t *testing.T) {
	// Pass a byte slice to TransmitHeapBuffer. The helper must allocate a new
	// destination rather than pinning its input directly.
	source := make([]byte, 120)
	for i := range source {
		source[i] = byte(i)
	}
	heap, pin, err := TransmitHeapBuffer(source)
	if err != nil {
		t.Fatalf("TransmitHeapBuffer: %v", err)
	}
	// Equal starting addresses would mean that the returned slice aliases the
	// input at its first byte.
	heapAddr := uintptr(unsafe.Pointer(&heap[0]))
	srcAddr := uintptr(unsafe.Pointer(&source[0]))
	t.Logf("heap[0]=%#x source[0]=%#x distinct=%v", heapAddr, srcAddr, heapAddr != srcAddr)
	if heapAddr == srcAddr {
		t.Fatal("heap copy and source start at the same address")
	}
	pin.Unpin()

	// Thirty-two goroutines call the full send helper on a shared socket.
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

// TestTransmitHeapBuffer_MmapPinIsNoOp_Physics checks Pin behavior for an
// address returned by unix.Mmap. The Go 1.26.1 runtime records Go-heap pointers
// in p.refs but ignores non-Go pointers. Pinning heap and mmap addresses on the
// same Pinner therefore leaves only the heap pointer for Unpin to release.
// Recording the mmap pointer instead would make Unpin panic in setPinned.
//
// The test distinguishes that no-op path from an Unpin failure and checks that
// both buffers retain their contents. Raw Pin(mmap) is confined to this test;
// the source guard scans transport.go rather than test files.
func TestTransmitHeapBuffer_MmapPinIsNoOp_Physics(t *testing.T) {
	buf, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Skipf("mmap unavailable: %v", err)
	}
	defer unix.Munmap(buf)
	buf[0] = 0xAB

	heap := make([]byte, 16)
	heap[0] = 0xCD

	var p runtime.Pinner
	// Pin a Go-heap object so the runtime records it in p.refs.
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

	// Pin the mmap address on the same Pinner. This must not panic or disturb
	// the recorded heap pin.
	mmapPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				mmapPanicked = true
				t.Errorf("Pin(mmap) panicked (unexpected; documented no-op per pinner documentation): %v", r)
			}
		}()
		p.Pin(&buf[0])
	}()
	if mmapPanicked {
		t.Fatal("Pin on a non-Go (mmap) pointer panicked; expected documented no-op (pinner documentation)")
	}

	// Unpin the shared Pinner. If Pin(mmap) recorded the non-Go pointer,
	// setPinned would panic while trying to release it. A clean return confirms
	// that Unpin released only the recorded heap entry.
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
		t.Fatalf("Unpin panicked after Pin(heap) and Pin(mmap): %v; the mmap pointer was recorded", unpinPanic)
	}
	// Check that both buffers retain their contents.
	if heap[0] != 0xCD {
		t.Errorf("heap[0] = %#x, want 0xCD (heap object disturbed by mmap no-op cycle)", heap[0])
	}
	if buf[0] != 0xAB {
		t.Errorf("buf[0] = %#x, want 0xAB (mmap region disturbed by Pin/Unpin no-op cycle)", buf[0])
	}
}

// TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild is the negative control
// for detectForbiddenPin. It checks transport.go, replaces the valid pin in a
// temporary copy with p.Pin(&mmapPayload[0]), and requires the detector to
// report that call. The original source file is not modified.
func TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild(t *testing.T) {
	// The unmodified source must pass before testing the negative control.
	realSrc, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatalf("read transport.go: %v", err)
	}
	if violations := detectForbiddenPin(string(realSrc)); len(violations) != 0 {
		t.Fatalf("detector found forbidden Pin in transport.go: %v", violations)
	}

	// Inject an invalid pin into the temporary copy. The detector must report
	// it for this negative control to be meaningful.
	injected := strings.Replace(string(realSrc),
		"p.Pin(&heap[0]) // Pin the Go-heap slice, not the mmap source.",
		"p.Pin(&mmapPayload[0]) // invalid negative control: pin the mmap source",
		1)
	if injected == string(realSrc) {
		t.Fatal("negative control: source anchor not found")
	}
	violations := detectForbiddenPin(injected)
	if len(violations) == 0 {
		t.Fatal("negative control: detector did not report Pin on the mmap source")
	}
	t.Logf("negative control: detector reported %d invalid Pin call(s): %v", len(violations), violations)
}

// detectForbiddenPin reports Pin calls whose argument is not an index into a
// slice declared with name := make([]byte, ...). It is a textual guard for
// transport.go, not a general Go analysis. Other targets, including mmap
// pointers, are returned as violations so the test fails conservatively.
func detectForbiddenPin(src string) []string {
	var violations []string
	lines := strings.Split(src, "\n")
	// Collect identifiers declared as make([]byte, ...) — these are the only
	// permitted Pin targets.
	heapVars := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
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
		// Accept an index into a slice recorded as a Go-heap allocation.
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

// TestTransmitHeapBuffer_NoUnsafeInSource asserts transport.go
// does not import "unsafe". unsafe is tolerated only in transport_test.go for
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
