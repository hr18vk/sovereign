# 3. Storage and Durability — Kernel Bypass

## 3.1 The mmap Illusion And The Page-Fault Tax

The `mmap(2)` system call is routinely misused. Database engineers map a file
into the process's virtual address space and let the Linux page cache lazily
move pages between RAM and storage. This is attractive because it appears to
remove a copy — the application reads the file as if it were memory. The trap
is that `mmap`'s laziness is a *latency tax* paid in two hardware events the
application cannot predict or hide:

- **Major page fault.** When the CPU dereferences a virtual address whose
  physical page is not resident, the MMU raises a page-fault exception. The
  kernel handles this by suspending the faulting OS thread in `D` (uninterruptible
  disk wait) state while it schedules the disk I/O to bring the page in. The
  Go runtime scheduler maps thousands of goroutines onto the `GOMAXPROCS`
  thread pool; it is blind to the fact that a pointer dereference just became
  a blocking I/O, so the stall backs onto the entire thread pool and freezes
  the server.
- **TLB shootdown.** A virtual-to-physical translation change (notably on
  `munmap`, or a protection remap) requires every core that may have cached
  the translation to flush it. The kernel signals this with an
  inter-processor interrupt; on a 32-core mesh a single shootdown can take
  tens of microseconds.

Both events violate the sub-millisecond latency mandate deterministically —
not probabilistically. The blueprint's Stage 6 §1 names this as the *Threat
of mmap and the Go Scheduler Collapse*.

## 3.2 A Deeper Defect: Live Control Corruption

Chaos Mesh-style fault injection (`MADV_DONTNEED` on a `MAP_PRIVATE`
anonymous page) reveals a second failure mode that is a corruption, not a
stall. `MADV_DONTNEED` on an anonymous page tells the kernel it may discard
the page's modifications; the next access re-faults the page as **zero**. The
HAMT root wrapper — its `seed`, `root` pointer, and `count` — lives in the
same `mmap`'d region as the leaves. `MADV_DONTNEED` on a page containing the
root wrapper zeroes the `seed`; the next `Get` panics with `maphash: use of
uninitialized Seed`, an off-heap corruption with no `recover()` path. This
is the SIGSEGV-class failure Stage 6 §2 hardens against at the process level.

## 3.3 Defense Layer: Chunked `mlock`

The engine pins its hot index pages into physical RAM, defeating the OS page
replacement algorithm entirely. The defense is `pkg/sync/residency.go`:

- **`LockHotPages`** issues `syscall.Mlock` over the hot-path index page range
  in chunks rounded to the OS page boundary (`os.PageSize`), because partial-page
  `mlock` semantics are undefined. Graceful degradation: when the process
  lacks `CAP_IPC_LOCK` (unprivileged container), `mlock` returns `EPERM`; when
  the `RLIMIT_MEMLOCK` ceiling is hit, it returns `ENOMEM`. The engine records
  both in `ResidencyStatus.PermDenied`/`PagesPinned` and proceeds — the gate
  asserts the *correctness* of the residency control, not the capability's
  availability.
- **`UnlockHotPages` / `UnlockAllPages`** precedes `munmap` on a locked range,
  because some kernels refuse to `munmap` a still-locked region.
- **`EvictPages`** is the chaos hook: `MADV_DONTNEED` on a caller-specified
  window injects the exact major-fault scenario the blueprint mandates.
- **`PrefaultPages` / `PrefaultHot`** walk a window touching each byte to
  fault pages in ahead of the timed read path — the "prefault fence".

### 3.3.1 The Gate And Why It Is Deterministic

`TestStage6ResidencyPageFaultGate` proves the defense. The original gate used
a worst-case-latency threshold (10 µs), which was flaky on the 32-core box — a
non-faulting traversal ranged 1.4 µs ↔ 16 µs under scheduler jitter, so a
passing run could trip the latency threshold on jitter alone. The gate was
reworked to assert a **major-fault-count delta** read from field 10 of
`/proc/self/stat` (`majflt`). A fault is a kernel-counted physical event immune
to scheduler jitter; the gate asserts `majorFaultsDelta == 0` when hot pages
are pinned, and reproduces the `MADV_DONTNEED` seed-corruption panic in the
negative control (Threat B). The 10 µs mandate survives as the *judicial*
`go tool trace` recipe (`ResidencyTraceRecipe`), run by a human on live traffic.

| Strategy                 | Latency bound          | Failure mode if violated                    |
|:-------------------------|:-----------------------|:-------------------------------------------|
| File-backed `mmap` only  | Unbounded (disk I/O)   | Scheduler-collapse on major fault           |
| `MADV_WILLNEED` hint      | No bound (advisory)    | Kernel may ignore; page may still evict   |
| `mlock` hot index pages  | Bounded by page-pin    | `EPERM`/`ENOMEM` → degrade, no crash       |

## 3.4 The Write-Ahead Log

Durability — the property that an acknowledged mutation survives a crash — is
kept out of the off-heap arena and out of the page cache. The engine ships its
**own WAL** (`internal/chaos/wal.go`), explicitly *not* PostgreSQL's WAL (which
the DR3 roadmap sunsets).

### 3.4.1 Framing And The Durability-Before-ACK Contract

The WAL is an append-only file opened with `os.OpenFile(path, O_RDWR|O_CREATE,
0644)` and prefixed with an 8-byte header (`magic = 0x57414C00`, `version = 1`).
Each record is `[seq(8) | type(1) | len(4) | payload]`. Three record types are
defined (`internal/chaos/wal.go:54-71`): `WALRecMutation` (an
`(entityID, CausalDot, CRDTEntry)` tuple), `WALRecCheckpoint` (a
`(MerkleRoot, LamportHigh)` tuple anchoring recovery), and
`WALRecClockAdvance` (the Day-8.5 foreign-advance record — an 8-byte
advanced-to counter). `WALRecClockAdvance` records a peer-driven
`AdvanceLamportTo` (`pkg/sync/crdt.go:1762`, reachable from the live receive
path inside `Join` at `crdt.go:1106`); recovery's replay switches on all
three (`internal/chaos/wal.go:557-591`). This third record is what makes the
`firstMutation.Counter − 1` seed in §3.4.3 necessary — without it a foreign
clock jump leaves an un-recorded counter gap and the two-record formula
silently under-counts the seed.

`AppendMutation` is **synchronous**: it writes the record then calls
`f.Sync()` before returning. The worker ACKs the client only after the fsync
returns. This is the **durability-before-ACK contract**: a crash between the
fsync and the ACK produces a duplicate replay on recovery, which
`InsertLocal`'s dot identity deduplicates — no loss, no divergence. A crash
between the ACK and a hypothetical subsequent fsync would lose an
acknowledged mutation; the synchronous ordering eliminates that window.

### 3.4.2 Tail-Tear Handling And Foreign-File Rejection

A crash mid-record leaves a partial trailing record. `ReplayWAL` reads with
`io.ReadFull`; a short read on the trailing record returns `io.ErrUnexpectedEOF`
and the replayer truncates that tail, returning the valid prefix and leaving
the next sequence number at the last good record. A file with a bad magic is
rejected explicitly by both `OpenWAL` and `ReplayWAL` — the engine never
rebuilds state on a suspect log (`TestStage6WALForeignFileRejected`,
`TestStage6WALTornTailTruncation`).

### 3.4.3 The Recovery Determinism Contract

`HAMT.MerkleRoot()` folds `SHA-256` over the canonical sort of `(DotNodeID,
DotCounter)` pairs only; it does not depend on `maphash.Seed` (which Go marks
as non-serializable across processes). A recovered worker started from a fresh
seed therefore reproduces the identical root for the same mutation sequence —
*provided* it replays with matching `(localNodeID, initialLamport)`. The
subtle invariant: `InsertLocal` re-stamps `DotNodeID`/`DotCounter` from
`NextDot()` (`pkg/sync/crdt.go:854`, the `lamportCounter.Add(1)`; the re-stamp
is `crdt.go:966-968`), so the recovered engine must boot from

    initialLamport = firstMutation.Counter − 1

i.e. `rebuiltInitial = rep.Mutations[0].Counter − 1` (`pkg/durability/recovery.go:229`
for the full-replay path, `:221` for the bounded path). This is the counter the
engine held immediately *before* the first durably-logged `InsertLocal`; the
first recorded mutation minted `firstMutation.Counter = seed + 1` by
construction, so `seed = firstMutation.Counter − 1` reproduces every
subsequent origin dot exactly.

The *rejected* formula is `initialLamport = LamportHigh − len(Mutations)`.
It is the **Day-8 defect** (`recovery.go:196-209` names it "the Day-8 defect,
§0 root cause"): `AdvanceLamportTo` jumps the Lamport clock forward via CAS
consuming *no* counter, and it is reachable from the live receive path inside
`Join` (`crdt.go:1106` calls `crdt.go:1762`). A foreign jump creates a counter
**gap** — the N recorded mutations do NOT occupy the N consecutive counters
ending at `LamportHigh`, so `LamportHigh − len(Mutations)` *under-counts* the
seed; replay re-mints different dots; Merkle diverges (silently, or as a false
`ErrRecoveryRootMismatch`). Day-8 fixed the naive `LamportHigh` boot (which
re-mints counters above all recorded ones and silently loses data) to
`LamportHigh − len(Mutations)`; Day-8.5 generalized the seed to
`firstMutation.Counter − 1` to close the foreign-advance gap that Day-8's
formula still missed — the `WALRecClockAdvance` record (§3.4.1) is the on-disk
half of that fix.

The two formulas **coincide** in the no-foreign-advance case: when no
`AdvanceLamportTo` ever ran, the mutations ARE consecutive, so
`firstMutation.Counter − 1 == LamportHigh − len(Mutations)` (`recovery.go:207-209`).
This is why the determinism gate (`TestStage6WALRecoveryDeterminism`,
`internal/chaos/wal_test.go:42`) stays GREEN despite its scenario still using
the Day-8 formula (`wal_test.go:120-126`) — that scenario appends only
`WALRecMutation` records with no `AppendClockAdvance`, so it has no counter
gap and the two seeds are equal. The gate was the artifact that caught the
original `LamportHigh` boot bug; the Day-8.5 generalization closed the
foreign-advance gap the original gate could not see.

## 3.5 The L0 Flush Path And The `io_uring` Roadmap

The WAL's durability depends on `fsync` driving the dirty page to storage.
`fsync` on a file opened with the default `O_RDWR` writes through the Linux
**page cache**, incurring a kernel copy and a context-switching syscall tax.
The WAL today accepts that tax: `internal/chaos/wal.go:161` opens the file
with `os.OpenFile(path, O_RDWR|O_CREATE, 0644)` and `AppendMutation` /
`AppendMutations` / `AppendCheckpoint` all call the synchronous `sync()`
(`wal.go:149-154`) before returning — correctness-bound, not throughput-bound.
Neither `O_DIRECT` nor `io_uring` is wired into the WAL data path.

The L0 flush — which durable-binds the LSM-Tree memtable to storage — is
likewise **not** io_uring-driven and **not** `O_DIRECT`. `FlushArenaToIPC`
(`internal/database/l0_flusher.go:135`) serializes a frozen `SkipListArena`
into Apache Arrow IPC (schema `ArrowSchema`, `l0_flusher.go:41-54`, the
9-field tri-temporal columnar layout) one per-entity partition at a time, and
hands each serialized `L0Partition.Buf` to the `S3Uploader` interface
(`l0_flusher.go:58-60`, `UploadPartition` at `:307`, the actual
`f.uploader.Upload` call at `:319`). The destination is object storage, not a
local block device, so there is no kernel page-cache copy to bypass and no
`write(2)` to align. The `O_DIRECT` / `io_uring` framing below is therefore
**roadmap, not the current data path**.

`O_DIRECT` and `io_uring` are tracked as P2-not-started gaps — the project's
`CLAUDE.md` lists `io_uring transport` under P2 GAPS and `README.md` flags
`io_uring transport` as "Not started (P2)." A repo-wide search for `io_uring`
in `*.go` returns only comment mentions (e.g. `pkg/transport/fanout.go:6`
contrasts the *deployed* eBPF `SO_ATTACH_REUSEPORT_EBPF` program against
io_uring); there is no io_uring implementation. The mechanisms are described
here as the planned kernel-bypass evolution of the WAL's `fsync`, not as the
live data path:

| Axis                | `O_RDWR` + `fsync` (deployed) | `O_DIRECT` (roadmap)      | `io_uring` (P2 roadmap)  |
|:--------------------|:--------------------------|:--------------------------|:-------------------------|
| Data path           | kernel page cache         | bypass page cache          | bypass + async submission|
| Copy                | user → page cache → disk  | user → disk (DMA)          | user → disk (DMA)         |
| Submission          | blocking syscall          | blocking syscall           | submission queue, polled  |
| Tail latency noise  | page-cache flush storms   | bounded by disk             | bounded by disk           |

- **`O_DIRECT`** (roadmap) would open the file with
  `O_APPEND|O_WRONLY|O_DIRECT`, aligning writes to the device's logical block
  size and `iovec` boundaries. The kernel copy into the page cache is
  eliminated; the user buffer is DMA'd directly. The contract is mechanical:
  the caller must align buffer addresses, lengths, and file offsets to the
  block boundary or `write(2)` returns `EINVAL`.
- **`io_uring`** (P2 roadmap) would submit I/O asynchronously via a shared
  ring between user space and the kernel, removing the syscall context switch
  from the hot path. Submissions post to the Submission Queue; completions
  arrive on the Completion Queue and are polled by an `IORING_SETUP_SQPOLL`
  kernel thread, making the submission-to-completion loop zero-syscall under
  steady load.

The `Merkle-root checkpoint` is WAL-appendant and fsync'd; the L0 flush
durable-binds the memtable to object storage via Arrow IPC + the `S3Uploader`
interface. The WAL is fsync-synchronous (correctness-bound); the L0 flush is
network-serialized (throughput-bound by the S3 upload, not by any kernel
ring).

## 3.6 SIGSEGV Survival

Because `mmap`'d memory is outside Go's safety net, a pointer-arithmetic defect
raises a `SIGSEGV` that `recover()` cannot intercept — the fault violently
terminates the entire process. The Supervisor-Worker topology (see §1.3 of
`1_ARCHITECTURE.md`) is the architectural defense: a worker that dies is
restarted from the WAL, and the listening socket in the Supervisor survives
the death. `TestStage6SIGSEGVSurvival` drives `OpCrashProbe`, which corrupts a
child pointer in the worker's arena via the deliberate fuzzer and
dereferences the poisoned address; the worker dies, the Supervisor observes
the stdout EOF, replays the WAL, spawns a pristine worker, and asserts the
recovered Merkle root equals the pre-crash root — with the held client TCP
connection surviving the entire cycle. The contract proven is crash-consistency,
not merely liveness.
