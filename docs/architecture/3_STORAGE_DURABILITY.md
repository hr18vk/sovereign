# 3. Storage and Durability

## 3.1 The mmap Illusion and the Page-Fault Tax

Mapping a file with `mmap(2)` lets an application read storage as memory, but
the access still depends on kernel paging. Two hardware events matter to the
latency of that design:

- **Major page fault.** If a dereference requires storage I/O, the kernel can
  suspend the faulting OS thread in `D` (uninterruptible disk wait) until the
  page arrives. Go schedules goroutines onto the `GOMAXPROCS` thread pool, but
  a pointer dereference does not tell the scheduler that it is about to block
  on I/O. Enough concurrent faults can therefore occupy the pool and stall
  unrelated goroutines.
- **TLB shootdown.** Changing a virtual-to-physical translation, during
  `munmap` or a protection remap, requires cores that cached the translation
  to flush it. The kernel uses inter-processor interrupts; on a 32-core
  machine a single shootdown can take tens of microseconds.

The engine's HAMT arena uses anonymous `mmap` rather than a file-backed
mapping. Residency still matters: first-touch faults, eviction, and address
range teardown occur outside Go's memory model and are not visible as ordinary
heap allocations.

## 3.2 Live Control Corruption

Fault injection with `MADV_DONTNEED` exposes a second failure mode on a
`MAP_PRIVATE` anonymous page. The kernel may discard the page's modifications,
and the next access re-faults it as zero. The HAMT root wrapper — its `seed`,
`root` pointer, and `count` — lives in the same mapped region as the leaves.
Zeroing the wrapper's page can make the next `Get` panic with `maphash: use of
uninitialized Seed`. Corrupting a raw pointer can instead produce a fatal
`SIGSEGV`, which `recover()` cannot intercept. The process-isolation harness in
§3.6 addresses the second case.

## 3.3 Residency Controls

`pkg/sync/residency.go` implements page-pinning and fault-injection primitives:

- **`LockHotPages`** rounds the requested range to `osPageSize` boundaries and
  calls `syscall.Mlock` one page at a time. `EPERM`, normally from missing
  `CAP_IPC_LOCK`, sets `ResidencyStatus.PermDenied`; `ENOMEM`, normally from
  reaching `RLIMIT_MEMLOCK`, sets `Truncated`. Both leave already-pinned pages
  locked and return a status rather than crashing.
- **`UnlockHotPages` and `UnlockAllPages`** release locked pages. The arena's
  production cleanup calls `UnlockAllPages` before `syscall.Munmap`; unlocking
  an unlocked range is harmless.
- **`EvictPages`** applies `MADV_DONTNEED` to a caller-specified window for
  fault-injection tests.
- **`PrefaultPages` and `PrefaultHot`** touch one 32-bit word per page, up to
  the arena's allocation high-water mark, to move first-touch faults ahead of a
  timed traversal.

These controls are built but are not enabled by node startup. Apart from
`UnlockAllPages` during arena cleanup, their current callers are in
`pkg/sync/residency_test.go`. In particular, the engine does not currently pin
its hot index pages during normal operation.

### 3.3.1 What the Residency Test Checks

`TestResidencyPageFaultGate` builds a multi-page HAMT, evicts the whole arena
as a negative control, then pins the control region and evicts a later data
window. It checks that the pinned traversal does not panic and that the
major-fault delta from field 10 of `/proc/self/stat` (`majflt`) is zero. If
procfs is unavailable, it uses a P99 latency ceiling instead.

The fault count avoids using a tight wall-clock threshold as the normal test
oracle. On the 32-core machine where the earlier threshold was evaluated, a
non-faulting traversal ranged from 1.4 µs to 16 µs under scheduler jitter, so a
10 µs limit could fail without a major fault. `ResidencyTraceRecipe` retains a
manual `go tool trace` procedure for inspecting that 10 µs bound; it is not an
automated latency guarantee.

The test skips when the host cannot perform the required `madvise` or `mlock`
operation. The whole-arena control also logs, rather than requires, seed
corruption because the kernel's response is host-dependent. A passing or
skipping test therefore does not imply that production nodes have page pinning
enabled.

## 3.4 The Write-Ahead Log

The engine's WAL is implemented in `internal/chaos/wal.go` and re-exported by
`pkg/durability/wal.go`. `Bridge.PutLocal` inserts a local mutation, appends
the returned dot and complete entry, and returns only after the WAL append and
fsync finish. This is separate from the off-heap arena and from PostgreSQL's
WAL. WAL writes are buffered through the kernel page cache; fsync supplies the
durability barrier.

### 3.4.1 Framing and Durability Before Acknowledgment

The WAL opens with `os.OpenFile(path, O_RDWR|O_CREATE, 0644)`. A new file
receives an 8-byte header (`magic = 0x57414C00`, `version = 1`), and each
record has the frame `[seq(8) | type(1) | len(4) | payload]`.

The record forms are:

- `WALRecMutation`, the legacy entry subset;
- `WALRecMutationV2`, the full 120-byte `CRDTEntry` used by new appends;
- `WALRecCheckpoint`, the legacy root and local Lamport watermark;
- `WALRecCheckpointV2`, which adds a pre-snapshot `CutSeq`, the live clock
  high-water mark, and an optional state fingerprint;
- `WALRecClockAdvance`, a peer-driven Lamport advance; and
- `WALRecChecksummed`, a Castagnoli CRC32C frame around another record.

New mutation, checkpoint, and clock-advance appends use the checksummed form.
Replay still accepts the unframed legacy forms and marks legacy mutations so
their unpersisted fields are not mistaken for recorded zeros.

`AppendMutation` writes and sequence-stamps under the WAL mutex, captures the
file handle, releases the mutex, and then fsyncs. Checkpoint and clock-advance
appends follow the same order. `AppendMutations` writes a batch under one
critical section and issues one fsync after unlocking. A batch failure rejects
the whole batch for acknowledgment purposes; it does not roll back bytes that
may already have reached the file. The group-commit and split-completion
decisions are recorded in [ADR-0044](adr/0044_wal_group_commit.md) and
[ADR-0048](adr/0048_wal_split_completion.md); checksum framing is in
[ADR-0053](adr/0053_wal_snapshot_crc32c.md).

A successful return establishes that the append's fsync completed. Only then
may the caller acknowledge the write. A crash after fsync but before that
acknowledgment can leave an unacknowledged record in the WAL; recovery applies
that record at its recorded dot, and applying the same dot again is idempotent.
Acknowledging before fsync would instead create a window in which an
acknowledged write could be lost.

### 3.4.2 Tail Tears, Corruption, and Foreign Files

`ReplayWAL` reads record headers and payloads with `io.ReadFull`. A partial
final header or payload is a crash boundary: replay stops and returns the valid
prefix without modifying the file. `OpenWAL` separately scans to the last
complete record, truncates a torn tail, restores the next sequence number, and
seeks to the append boundary before new writes.

Bad magic or an unsupported version is rejected by both readers. Replay also
rejects excessive payload lengths, gaps or duplicates in the contiguous record
sequence, unknown record types, and checksum mismatches. A checksum mismatch in
a complete record returns `ErrWALCorrupt`; recovery refuses to rebuild from
that authoritative log. `TestWALForeignFileRejected` and
`TestWALTornTailTruncation` cover the format boundary cases.

### 3.4.3 The Recovery Determinism Contract

Recovery restores each mutation at its WAL-recorded `(DotNodeID, DotCounter)`
through a synthetic-delta `Join`; it never calls `InsertLocal` to mint a
replacement. The replacement engine starts at the maximum durable Lamport
high-water mark, including the checkpoint's live `ClockHigh`, and recorded
clock advances are applied as monotone maxima. Exact-dot restoration makes
replaying an overlapping image and tail idempotent.

The earlier approach derived an initial counter and replayed through
`InsertLocal`. [ADR-0045 §4](adr/0045_mesh_transport_invariants.md) records
why that cannot reproduce durable state: concurrent mint and WAL append orders
can differ; a Lamport counter is not a WAL position; and re-minting dots already
present in a non-quiescent snapshot creates duplicates. Record sequence, not a
scalar counter, now defines the checkpoint tail. A V2 checkpoint starts the
tail at its pre-walk `CutSeq`; a legacy checkpoint starts after the checkpoint
record.

With a usable snapshot, `RecoverEngineWithSnapshot` joins the image before the
tail in separate operations. Joining the full image first matters when an equal
dot also occurs in a legacy tail record: an equal-dot merge retains the existing
entry, so the image's full fields win. Local image dots must have corresponding
WAL mutations. Missing or unusable images, binding mismatches, and local
phantom dots select full WAL replay; `RecoveryWitness` records which path ran
and which checks were available.

`HAMT.MerkleRoot()` folds SHA-256 over sorted `(DotNodeID, DotCounter)` pairs;
it does not depend on `maphash.Seed`. The same dot set therefore produces the
same root with a fresh seed, but root equality does not establish entry-byte
integrity. The root does not cover the payload digest or temporal fields.

Current mutation records persist the complete entry. Legacy mutation records
retain only the original subset, so their `ValidTimeStart`, `ValidTimeEnd`,
`AssertionTime`, `DecisionTime`, and `H3Index` fields were not persisted;
recovery marks and counts those records rather than treating their synthesized
zero values as historical measurements.

A fingerprint-bearing checkpoint also covers the entity ID and every entry
field through `StateFingerprint`. When a snapshot is bound to such a
checkpoint, recovery compares both the image root and fingerprint before
applying the tail. `ErrRecoveryRootMismatch` and
`ErrRecoveryFingerprintMismatch` refuse startup on their respective mismatches.
After tail replay, root equality is checked only for bounded recovery from a
final, intact checkpoint. Full replay contains local WAL entries but may omit
foreign entries in the checkpoint root, so it relies on WAL sequence
contiguity instead of making an invalid root comparison.

Snapshot images use the same full-entry encoding and carry a whole-image
Castagnoli CRC32C. `ErrSnapshotCorrupt` causes recovery to discard the derived
image and rebuild from the authoritative WAL; a corrupt WAL checksum instead
refuses recovery. `TestWALRecoveryDeterminism` exercises exact-dot restoration.

## 3.5 The L0 Flush Path and Kernel-Bypass Status

The LSM query index is separate from both the WAL and the dot-bearing recovery
image. `L0Flusher.FlushArenaToIPC` serializes a frozen `SkipListArena` into
per-entity Apache Arrow IPC partitions using the 9-field `ArrowSchema`.
`UploadPartition` passes each buffer to the `S3Uploader` interface. The
implementation uploads one partition at a time and frees its buffer before
starting the next. When the query index is enabled, periodic checkpoints select
entities whose latest dot has changed since the previous durable query-tier
flush. `LocalFS` provides a local
implementation of the storage interface, while object-storage implementations
perform network uploads. These Arrow files are a query index, not a payload
store or a replacement for the recovery image.

The WAL uses buffered `O_RDWR` writes and fsync. Neither it nor the Arrow flush
path uses `O_DIRECT` or `io_uring`; both mechanisms remain planned and have no
implementation in this release. The existing eBPF reuse-port fanout is a
separate network mechanism, not kernel-bypass storage I/O.

## 3.6 Process-Crash Recovery

A raw-pointer fault in the mapped arena can raise `SIGSEGV` and terminate the
process; Go's `recover()` cannot intercept it. The process-isolation harness in
`internal/chaos/supervisor.go` addresses this by spawning a worker, detecting
its stdout EOF, and starting a replacement that replays the same WAL. A front
end that owns the listeners and never hands them to the worker can keep client
TCP connections open across the replacement.

`TestSIGSEGVSurvival` is intended to compose that recovery with a listener
owned by the test process. `OpCrashProbe` poisons a child pointer in the
worker's arena; the intended assertions cover both the recovered Merkle root
and a ping on the same client connection. The supervisor itself is
listener-agnostic, so the connection property comes from the external listener
owner as well as worker replacement. In this release, `CHAOS_WORKER_BIN` only
controls whether the test skips. The supplied path is ignored: the test
unconditionally tries to build `./cmd/chaos-worker/`, which is not included,
and fails before starting a worker. It therefore provides no current
end-to-end result for those assertions.

This harness is distinct from normal `sovereign-node` startup recovery. With
`--wal-path` configured, the node calls `RecoverEngineWithSnapshot` in process,
using a snapshot only when `--lsm-root` supplies a store and falling back to
full WAL replay when the image is unusable. The broader topology is discussed
in §1.3 of [Architecture Overview](1_ARCHITECTURE.md).
