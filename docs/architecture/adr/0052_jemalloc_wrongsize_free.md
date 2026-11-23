# ADR-0052: Free resliced jemalloc buffers by usable size

**Status:** Accepted  
**Date:** 2026-09-10

## Context

An intermittent `internal/database` SIGSEGV at `addr=0x30` interrupted MemTable flush tests. The
crash occurred in production flush code, but its source was a test helper that corrupted the
process-global jemalloc heap shared by every test in the process.

`readAllIntoJemalloc` in `internal/database/l1_compaction_test.go` returned `buf[:n]`, reslicing
the allocation to its content length. `collectRowKeys` freed that slice, so `sdallocx(ptr, n)`
received a content length such as 3266 rather than the block's recorded usable size of 32768. This
returned a 32KB large extent through the approximately 3.2KB small size class. A later 64KB
MemTable allocation or free encountered the corrupted metadata and faulted.

The production allocator and flush callers already observed the usable-size contract. The decision
therefore had two parts: harden the production allocator against resliced lengths, and correct the
test helper rather than relying on that defense.

## Decision

`JemallocAllocator.Free` now derives the deallocation size from `malloc_usable_size(ptr)` rather
than `len(b)`. A caller that reslices a buffer to a shorter length can no longer return the block
through the wrong size class. `bytesAllocated` subtracts the same usable size, keeping the 256MB
MemTable accounting ceiling accurate.

The change adds one radix lookup per free. The allocation-and-free microbenchmark increased by
about 6.5%, from 865 to 921 ns/op, with 0 allocs/op. `JemallocAllocator` is not used by `pkg/sync`,
whose CRDT write path uses `HamtArena`, so this lookup is not added to the CRDT hot path. The
lookup applies to the LSM, durability, and transport allocation paths.

The test helper now returns the full buffer and its content length separately. `collectRowKeys`
reads `buf[:n]` but frees the full buffer. This preserves the correct caller pattern even though
`Free` now tolerates a shorter slice.

## Consequences

The original corruption came from test code, not a production flush caller. The production
allocator is nevertheless the enforcement point because it can protect every caller that supplies a
shorter slice. Double frees and invalid pointers remain undefined behavior; deriving the usable
size does not make those calls safe.

The optional heap audit remains available through `SUPREMUM_JEMALLOC_AUDIT`. It is disabled by
default. When disabled, its call sites reduce to a predictable branch with no allocation. When
enabled, it records live blocks and diagnoses length mismatches, invalid frees, and double frees.

## Evidence

### Heap corruption mechanism

`Allocate(32768)` returns a block whose usable size is `32768`, a 32KB large extent. Passing
`Free(buf[:3266])` to the old implementation called `sdallocx(ptr, 3266, 0)`. Jemalloc selected a
small size class from 3266 even though the pointer referred to a large extent, corrupting the
size-class bookkeeping.

The fault appeared only when later allocation activity encountered that metadata.
`TestMemTable_InsertAndFlush` performed 50,000 partitions of 64KB `NewJemallocBuffer` allocation
and free activity, making the flush test the usual victim. The observed fault rate was about 50%.
The anomalous 2048-to-32768 growth in `TestJemallocAllocator_Reallocate` was another symptom of
the corrupted size metadata, not a separate defect.

### Diagnosis

The race detector cannot track cgo and jemalloc memory. The jemalloc 5.3.0 build used for these
tests also rejected `redzone:true`, so that run had not ruled out an out-of-bounds write. Sixteen
of sixteen isolated flush reproductions passed, covering both 64KB buffer churn and an Arrow
`RecordBuilder`, `JemallocBuffer`, and IPC-writer path. This pointed to corruption seeded by a
different test in the same process.

The audit in `memory_allocator_audit.go` registers live blocks and validates frees. On four of four
full-suite runs it identified `free_size=3266` against a recorded usable size of `32768`, allocated
by `readAllIntoJemalloc` and freed by `collectRowKeys`.

A healing mode freed those blocks with their recorded sizes and continued. The suite completed
with zero SIGSEGVs and 13 healed wrong-size frees, all from that helper. Correcting only the free
size removed the observed crashes and isolated the mechanism.

### Alternative explanations

Healing only the free size removed the observed crashes, which an out-of-bounds write would not
explain. The allocator already passed usable sizes for aligned allocations, and sixteen of sixteen
stress runs using `ALIGN(64)` allocation with `flags=0` on free passed. The uploader mocks did not
let buffers escape. A full-suite race run completed in 615 s with no data-race report. These checks
left the length mismatch, rather than alignment, uploader lifetime, or a Go data race, as the
mechanism consistent with the evidence.

### Regression guards

`TestReslicedFreeIsSafeAndBalanced` in `jemalloc_free_audit_test.go` performs 512 resliced frees of
32KB blocks followed by a 64KB sweep. It asserts that `BytesAllocated` returns to its baseline and
that no corruption occurs, making the result deterministic rather than dependent on an intermittent
SIGSEGV. Restoring the old `len(b)` behavior fails with `BytesAllocated=16134400, want 0`.

`TestReallocateAccountingExact` checks allocation, growth, shrinkage, and free, requiring the
accounting to track usable sizes and return to zero.

`TestAuditInstrumentIsLoadBearing` runs a subprocess with the audit enabled. A resliced free emits
a length-mismatch diagnostic; a double free panics with the audit's invalid-free diagnostic. These
cases show that the instrument detects the conditions it reports.

The complete `internal/database` package was added to the standard race-enabled verification run.

### Verification runs

The full `internal/database` suite passed twelve of twelve post-fix runs with zero SIGSEGVs, against
an earlier fault rate of about 50%. If independent runs had retained that rate, twelve consecutive
passes would have probability 0.5¹², approximately 0.02%. The full race-enabled suite completed in
615 s with no data-race report.

Build and vet passed, as did `TestHotPathZeroAllocations` and `BenchmarkHAMTInsertZeroAlloc`. The
fieldalignment report retained the same 11 pre-existing findings and was not used to apply automatic
layout changes. The full verification suite passed on a 32-core machine.

The CRDT merge-law and wire-schema files were unchanged. An out-of-bounds guard-band diagnostic was
not needed after the healing experiment isolated the free-size mismatch.
