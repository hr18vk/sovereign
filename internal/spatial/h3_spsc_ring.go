//go:build linux

// Package spatial implements the SPSC (Single-Producer Single-Consumer) shared
// memory ring buffer for lock-free H3 spatial index computation. The Go runtime
// acts as the producer, writing latitude/longitude coordinates into the ring.
// A persistent C++ worker thread (pinned to an isolated CPU core) consumes
// slots, computes H3 cell indices via the C h3 library, and writes results back.
//
// ARCHITECTURAL JUSTIFICATION:
// Standard CGO (import "C") exacts a 50ns context switch per invocation due to
// entersyscall/exitsyscall. At 100,000 RPS, this wastes 5ms/sec of pure context
// switching per core. The asmcgocall trampoline reduces this to ~3ns but blocks
// GC Stop-The-World indefinitely during complex H3 gnomonic projections (>10μs).
//
// The SPSC ring buffer eliminates both vectors entirely:
// - Coordination: Hardware MESI cache-line coherency (~10-15ns).
// - Isolation: C++ thread runs outside Go scheduler jurisdiction.
// - Memory: mmap'd shared region — no syscalls, no futexes, no mutexes.
//
// CROSS-PROCESS SHARED MEMORY TOPOLOGY:
// The shared memory region is backed by memfd_create(2), which creates an
// anonymous in-memory file descriptor. Unlike MAP_ANONYMOUS (which produces
// memory invisible across execve boundaries), memfd creates a real fd that
// can be passed to child processes via os/exec.Cmd.ExtraFiles. The child
// process inherits the fd at position 3+index, mmaps it, and both processes
// share the same physical pages via the kernel's page cache.
//
// VULNERABILITY REMEDIATION (Post-Audit):
// The original implementation used syscall.Mmap(-1, MAP_ANON|MAP_SHARED),
// which creates anonymous memory with NO backing file descriptor. When the
// C++ worker is a standalone binary spawned via execve (required after the
// cmd/ relocation override), anonymous mmap regions are irrevocably severed
// at the execve boundary. The C++ worker would receive fd=-1, lseek would
// fail with EBADF, and the Go producer would deadlock permanently in
// Collect() spinning on SlotDone from a dead consumer. memfd_create solves
// this by providing a real fd that survives execve when explicitly inherited.
package spatial

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// procyield emits a hardware PAUSE instruction (x86_64) or YIELD (ARM64).
// This burns CPU cycles briefly without polluting the Go scheduler's run
// queues or evicting the L1 cache — unlike runtime.Gosched() which moves
// the goroutine back to the run queue, causing Epoll priority-inversion.
//
//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

// PhasedWaitStrategy combines bounded hardware spinning with OS-level futex
// parking. Phase 1: procyield(30) x maxSpins keeps L1 cache hot. Phase 2:
// sync.Cond.Wait() parks the goroutine via futex, yielding the M and P
// completely to prevent Epoll starvation.
type PhasedWaitStrategy struct {
	cond     *sync.Cond
	maxSpins int
}

// NewPhasedWaitStrategy creates a new phased wait strategy.
func NewPhasedWaitStrategy(maxSpins int) *PhasedWaitStrategy {
	return &PhasedWaitStrategy{
		cond:     sync.NewCond(&sync.Mutex{}),
		maxSpins: maxSpins,
	}
}

// Wait blocks the caller deterministically using phased back-off.
// Phase 1: Hardware PAUSE spinning (bounded). Phase 2: Futex park.
func (ws *PhasedWaitStrategy) Wait(isFull func() bool) {
	spins := 0
	for isFull() {
		if spins < ws.maxSpins {
			// Phase 1: Hardware PAUSE. Keeps L1 cache hot, avoids Epoll starvation.
			procyield(30)
			spins++
		} else {
			// Phase 2: OS-Level Futex Park.
			// Yields the M (Machine) and P (Processor) completely.
			ws.cond.L.Lock()
			for isFull() {
				ws.cond.Wait()
			}
			ws.cond.L.Unlock()
			return
		}
	}
}

// Signal wakes one parked goroutine from the futex.
//
// FLAW 6 FIX: The mutex MUST be held around Signal() to serialize with
// the Wait() call in the Wait() method. Without the lock, a signal fired
// between the isFull() predicate check and the cond.Wait() call evaporates
// into the void, permanently deadlocking the producer goroutine.
func (ws *PhasedWaitStrategy) Signal() {
	ws.cond.L.Lock()
	ws.cond.Signal()
	ws.cond.L.Unlock()
}

const (
	// CacheLineSize is the L1 cache line size on modern x86_64 and ARM64.
	CacheLineSize = 64

	// DefaultRingCapacity is the number of slots in the SPSC ring buffer.
	// 8192 slots × 64 bytes = 512KB — fits entirely in L2 cache.
	DefaultRingCapacity = 8192

	// Slot state machine values. Monotonic progression per slot:
	// Go:  EMPTY → READY  (producer writes coords, flips to READY)
	// C++: READY → PROCESSING → DONE  (consumer computes H3, flips to DONE)
	// Go:  DONE → EMPTY   (producer reads result, reclaims slot)
	//
	// ABA Prevention: Each actor owns exclusive state transitions.
	// Go never sees PROCESSING. C++ never sees EMPTY or DONE→EMPTY.
	SlotEmpty      uint32 = 0
	SlotReady      uint32 = 1
	SlotProcessing uint32 = 2
	SlotDone       uint32 = 3
)

// RingSlot is the 64-byte cache-line-aligned data structure for a single
// coordinate→H3 computation request/response.
//
// MEMORY LAYOUT (must be identical in C++ h3_worker main.cpp):
//
//	Offset  Size  Field
//	0x00    4B    State        (atomic uint32: EMPTY/READY/PROCESSING/DONE)
//	0x04    4B    Resolution   (H3 resolution level, 0-15)
//	0x08    8B    Latitude     (IEEE-754 Float64, little-endian)
//	0x10    8B    Longitude    (IEEE-754 Float64, little-endian)
//	0x18    8B    H3Index      (uint64 result, written by C++)
//	0x20    8B    RequestID    (uint64, monotonic sequence for correlation)
//	0x28    24B   _padding     (zeroed, forces total slot size to 64B)
//
// TOTAL: 64 bytes = 1 L1 cache line. Zero implicit Go padding.
type RingSlot struct {
	State      uint32   // Atomic state flag
	Resolution uint32   // H3 resolution (0-15)
	Latitude   float64  // IEEE-754
	Longitude  float64  // IEEE-754
	H3Index    uint64   // Computed by C++ worker
	RequestID  uint64   // Monotonic sequence number
	_padding   [24]byte // Explicit padding to 64 bytes
}

// Compile-time size assertion. If RingSlot is not exactly 64 bytes,
// the build fails immediately — preventing silent false sharing.
var _ [CacheLineSize]byte = [unsafe.Sizeof(RingSlot{})]byte{}

// RingHeader is the shared control region preceding the slot array.
// Each control field occupies its own dedicated 64-byte cache line
// to prevent false sharing between producer and consumer cursors.
//
// MEMORY LAYOUT:
//
//	Offset    Size   Field
//	0x000     8B     WriterCursor  (Go increments, C++ reads — dedicated cache line)
//	0x008     56B    _padW         (padding to 64B boundary)
//	0x040     8B     ReaderCursor  (C++ increments, Go reads — dedicated cache line)
//	0x048     56B    _padR         (padding to 64B boundary)
//	0x080     4B     Shutdown      (Go writes 1 to signal termination)
//	0x084     4B     Resolution    (Default H3 resolution for this ring)
//	0x088     4B     Capacity      (Number of slots)
//	0x08C     52B    _padS         (padding to 64B boundary)
//	0x0C0     ...    Slots[0]      (first RingSlot begins here)
type RingHeader struct {
	WriterCursor uint64   // Atomic: next slot Go will write to
	_padW        [56]byte // Pad to dedicated 64B cache line

	ReaderCursor uint64   // Atomic: next slot C++ will read from
	_padR        [56]byte // Pad to dedicated 64B cache line

	Shutdown   uint32   // Atomic: 1 = C++ worker must exit
	Resolution uint32   // Default H3 resolution
	Capacity   uint32   // Ring slot count
	_padS      [52]byte // Pad to dedicated 64B cache line
}

// Compile-time size assertion for header.
var _ [3 * CacheLineSize]byte = [unsafe.Sizeof(RingHeader{})]byte{}

// SPSCRing is the Go-side producer handle for the shared memory ring buffer.
type SPSCRing struct {
	// header points to the mmap'd shared memory region header.
	header *RingHeader

	// slots is the slice of RingSlots starting after the header.
	slots []RingSlot

	// rawMem is the full mmap'd byte slice for cleanup.
	rawMem []byte

	// memfd is the file descriptor from memfd_create(2) backing the shared
	// memory region. This fd is passed to the C++ worker via ExtraFiles.
	// It must be closed after both the mmap and the child process are done.
	memfd int

	// totalSize is the total byte size of the mmap'd region (header + slots).
	totalSize int

	// capacity is the number of slots (cached for hot-path modulo).
	capacity uint32

	// nextSeqID is the monotonic request sequence counter.
	nextSeqID uint64

	// defaultResolution is the H3 resolution level (default: 9).
	defaultResolution uint32

	// workerCmd holds the reference to the running C++ worker process,
	// if started via StartWorker().
	workerCmd *exec.Cmd

	// GOSCHED ERADICATION: Phased wait strategies replace runtime.Gosched().
	// submitWait: blocks producer when ring is full (all slots occupied).
	// collectWait: blocks collector when waiting for C++ to produce SlotDone.
	submitWait  *PhasedWaitStrategy
	collectWait *PhasedWaitStrategy
}

// NewSPSCRing creates and initializes a shared memory ring buffer.
//
// The memory is backed by memfd_create(2), which creates an anonymous
// in-memory file descriptor. This fd can be passed to the C++ worker
// process via os/exec.Cmd.ExtraFiles, surviving the execve boundary.
//
// VULNERABILITY FIX (Post-Audit):
// The original implementation used syscall.Mmap(-1, MAP_ANON), which
// creates anonymous memory invisible across execve. Since the C++ worker
// is a standalone binary (an operator-supplied consumer of this ring, not
// shipped in the open-source core library release), it could never attach
// to a MAP_ANON shared region — the inherited fd would be -1, lseek would
// fail with EBADF, and Go's Collect() would deadlock forever. memfd_create
// provides a real fd backed by tmpfs that survives process inheritance.
//
// capacity MUST be a power of 2 for efficient modulo via bitmask.
func NewSPSCRing(capacity uint32, resolution uint32) (*SPSCRing, error) {
	if capacity == 0 || (capacity&(capacity-1)) != 0 {
		return nil, fmt.Errorf("spsc: capacity must be a power of 2, got %d", capacity)
	}

	headerSize := unsafe.Sizeof(RingHeader{})
	slotSize := unsafe.Sizeof(RingSlot{})
	totalSize := int(headerSize) + int(slotSize)*int(capacity)

	// Step 1: Create an anonymous in-memory file descriptor via memfd_create(2).
	// MFD_CLOEXEC prevents accidental fd leakage to unrelated child processes.
	// When explicitly passed via os/exec.Cmd.ExtraFiles, Go's runtime dup's the
	// fd and clears CLOEXEC for that specific child — so the H3 worker inherits it.
	fd, err := unix.MemfdCreate("h3_spsc_ring", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("spsc: memfd_create failed: %w", err)
	}

	// Step 2: Set the size of the memfd to the total ring buffer size.
	if err := unix.Ftruncate(fd, int64(totalSize)); err != nil {
		_ = unix.Close(fd) // Best-effort cleanup on error path.
		return nil, fmt.Errorf("spsc: ftruncate failed: %w", err)
	}

	// Step 3: mmap the memfd as MAP_SHARED — both Go and the C++ worker
	// will see the same physical pages via the kernel's page cache.
	// MAP_POPULATE pre-faults all pages to avoid TLB misses on the hot path.
	mem, err := unix.Mmap(fd, 0, totalSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		_ = unix.Close(fd) // Best-effort cleanup on error path.
		return nil, fmt.Errorf("spsc: mmap failed: %w", err)
	}

	// Overlay the header struct onto the mmap'd region.
	header := (*RingHeader)(unsafe.Pointer(&mem[0]))
	header.Capacity = capacity
	header.Resolution = resolution

	// Create Go slice over the slot region (after the header).
	slotBase := unsafe.Pointer(uintptr(unsafe.Pointer(&mem[0])) + headerSize)
	slots := unsafe.Slice((*RingSlot)(slotBase), capacity)

	return &SPSCRing{
		header:            header,
		slots:             slots,
		rawMem:            mem,
		memfd:             fd,
		totalSize:         totalSize,
		capacity:          capacity,
		defaultResolution: resolution,
		submitWait:        NewPhasedWaitStrategy(100),
		// FLAW 6 FIX: collectWait MUST use pure-spin mode (never enter Phase 2
		// futex park). The C++ worker transitions slots to SlotDone via shared
		// memory atomic writes — it cannot call Go's sync.Cond.Signal(). If
		// collectWait enters sync.Cond.Wait(), no signal will ever arrive and
		// the goroutine deadlocks. math.MaxInt prevents Phase 2 entry entirely.
		// Production code uses EpochBatcher.collectWithTimeout (bounded procyield)
		// and never reaches this path.
		collectWait: NewPhasedWaitStrategy(math.MaxInt),
	}, nil
}

// SharedMemoryFd returns the memfd file descriptor and total size of the
// shared memory region. The fd can be passed to child processes via
// os/exec.Cmd.ExtraFiles for cross-process shared memory access.
func (r *SPSCRing) SharedMemoryFd() (int, int) {
	return r.memfd, r.totalSize
}

// StartWorker spawns the C++ H3 worker binary as a child process,
// passing the shared memory fd via ExtraFiles inheritance.
//
// The C++ worker receives the fd at position 3 (first ExtraFiles entry)
// and the total shared memory size as argv[2]. It mmaps the fd and
// begins consuming ring buffer slots.
//
// workerPath: absolute path to the compiled h3_worker binary.
// pinCore: CPU core to pin the worker thread to (-1 for no pinning).
func (r *SPSCRing) StartWorker(workerPath string, pinCore int) error {
	// Wrap the memfd integer in an *os.File for ExtraFiles.
	// os.NewFile does NOT take ownership — we still manage the fd lifecycle.
	memFile := os.NewFile(uintptr(r.memfd), "h3_spsc_ring_memfd")

	// The fd will be inherited as fd 3 in the child process (0=stdin, 1=stdout, 2=stderr).
	// Go's os/exec automatically dup's ExtraFiles entries and clears CLOEXEC for them.
	cmd := exec.Command(workerPath,
		"3",                       // argv[1]: inherited fd number (first ExtraFiles entry)
		strconv.Itoa(pinCore),     // argv[2]: CPU core to pin to
		strconv.Itoa(r.totalSize), // argv[3]: total shared memory size in bytes
	)
	cmd.ExtraFiles = []*os.File{memFile}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spsc: failed to start h3_worker: %w", err)
	}

	r.workerCmd = cmd
	return nil
}

// Submit writes a latitude/longitude pair into the next available ring slot
// and transitions the slot to READY state. Returns the request sequence ID
// for result correlation.
//
// BLOCKING BEHAVIOR: If the ring is full (producer has lapped the consumer),
// Submit uses a Phased Back-Off strategy: bounded procyield(30) hardware
// PAUSE spinning (100 iterations), then sync.Cond.Wait() futex parking.
// This prevents the Epoll priority-inversion livelock caused by Gosched().
//
// MEMORY ORDERING:
//   - All data writes (lat, lng, resolution) use normal stores.
//   - The State transition to READY uses atomic.StoreUint32 with release
//     semantics, guaranteeing all preceding data writes are visible to
//     the C++ consumer before it observes READY.
func (r *SPSCRing) Submit(lat, lng float64) (uint64, error) {
	idx := r.nextSeqID % uint64(r.capacity)
	slot := &r.slots[idx]

	// GOSCHED ERADICATION: Phased back-off replaces runtime.Gosched().
	// Phase 1: procyield(30) x 100 — hardware PAUSE, keeps L1 hot.
	// Phase 2: sync.Cond.Wait() — futex park, yields M+P completely.
	r.submitWait.Wait(func() bool {
		return atomic.LoadUint32(&slot.State) != SlotEmpty
	})

	// Write coordinate data. Normal (non-atomic) stores are sufficient —
	// the subsequent atomic store to State with release semantics will
	// flush these writes to the cache line before the consumer sees READY.
	slot.Latitude = lat
	slot.Longitude = lng
	slot.Resolution = r.defaultResolution
	slot.RequestID = r.nextSeqID
	slot.H3Index = 0 // Clear previous result

	// Release barrier: all data writes above are committed to the cache line
	// before C++ observes the READY state.
	atomic.StoreUint32(&slot.State, SlotReady)

	seqID := r.nextSeqID
	r.nextSeqID++
	return seqID, nil
}

// Collect retrieves the H3 index result for a previously submitted request.
// It uses Phased Back-Off until the C++ worker has written the result.
//
// Returns the computed H3 cell index (uint64).
func (r *SPSCRing) Collect(seqID uint64) (uint64, error) {
	idx := seqID % uint64(r.capacity)
	slot := &r.slots[idx]

	// GOSCHED ERADICATION: Phased back-off replaces runtime.Gosched().
	r.collectWait.Wait(func() bool {
		return atomic.LoadUint32(&slot.State) != SlotDone
	})

	h3Index := slot.H3Index

	// Reclaim the slot for reuse.
	atomic.StoreUint32(&slot.State, SlotEmpty)

	// Signal the submitWait strategy — a slot has been freed.
	// This unparks any producer blocked in Submit() waiting for SlotEmpty.
	r.submitWait.Signal()

	return h3Index, nil
}

// SubmitAndCollect is a convenience method that submits coordinates and
// blocks until the H3 result is available. This is the typical hot-path
// call for the ingestion pipeline.
func (r *SPSCRing) SubmitAndCollect(lat, lng float64) (uint64, error) {
	seqID, err := r.Submit(lat, lng)
	if err != nil {
		return 0, err
	}
	return r.Collect(seqID)
}

// Shutdown signals the C++ worker thread to terminate gracefully.
// It sets the shutdown flag and waits for the worker process to exit.
func (r *SPSCRing) Shutdown() {
	atomic.StoreUint32(&r.header.Shutdown, 1)

	if r.workerCmd != nil {
		// Wait for the C++ worker to observe the shutdown flag and exit.
		_ = r.workerCmd.Wait()
		r.workerCmd = nil
	} else {
		// No managed worker — give external consumer time to observe.
		time.Sleep(10 * time.Millisecond)
	}
}

// Close unmaps the shared memory region and closes the memfd.
// MUST be called after Shutdown() and after the C++ worker has exited.
func (r *SPSCRing) Close() error {
	var firstErr error

	if r.rawMem != nil {
		if err := unix.Munmap(r.rawMem); err != nil {
			firstErr = err
		}
		r.rawMem = nil
		r.header = nil
		r.slots = nil
	}

	if r.memfd >= 0 {
		if err := unix.Close(r.memfd); err != nil && firstErr == nil {
			firstErr = err
		}
		r.memfd = -1
	}

	return firstErr
}
