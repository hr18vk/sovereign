# Engineering style and constraints

The CRDT core uses explicit arena allocation, memory layout, and synchronization to
avoid garbage-collection work and cache-line contention on its hot paths. These
constraints apply to changes on those paths; they do not mean every package is
allocation-free or lock-free. Measurements belong to the layer that produced them.

## 1. Zero allocation on the hot path

`HAMT.Set`, `DeltaCRDTEngine.InsertLocal`, and `ElimStack` push/pop are designed not
to allocate Go heap objects. `TestHotPathZeroAllocations` checks `HAMT.Set` with
`testing.AllocsPerRun`; `BenchmarkHAMTInsertZeroAlloc` reports `0 B/op 0 allocs/op`
under `-benchmem`. A change to another hot path needs its own measurement.

- **Long-lived core data lives off-heap.** HAMT nodes, leaves, entity strings, and
  CRDT entry arrays are carved from anonymous memory reserved with `syscall.Mmap` and
  recycled through segregated slab allocators with lock-free Treiber free-lists. The
  Go collector does not scan that arena. The residency code names `MADV_WILLNEED` for
  prefetching and uses `MADV_DONTNEED` in eviction tests; it does not use
  `MADV_SEQUENTIAL`.
- **Avoid `make` and `new` on an allocation-free path.** Take storage from an arena
  slab or embed it by value. Preallocate scratch space outside the measured loop.
- **Avoid heap-escaping interfaces.** Passing a concrete value through `interface` or
  `any` can box it on the heap. Check escape analysis and an allocation test rather
  than assuming a particular compiler version will keep a value on the stack.

### Allocation checks

CI runs `TestHotPathZeroAllocations`. It does not grep diffs for allocation syntax or
approve `// arena-bound:` annotations. Review the complete path, including pool misses
and error branches, and measure the change with `-benchmem` where applicable.

## 2. The 128-byte stride

A Graviton core fetches data in 64-byte cache lines, and cache coherence tracks
ownership at line granularity. Independently contended slots therefore use a
128-byte stride where that separation is required. Fields exchanged as one
protocol unit may deliberately share a line; compact, uncontended records need
a different layout. [The struct-alignment notes](docs/internals/STRUCT_ALIGNMENT.md)
give the sizes, offsets, and access patterns for each case.

- **Check the actual assertions.** `TestCRDTEntry_SizeAndAlignment` pins
  `CRDTEntry` at 120 bytes and `TestHamtLeaf_SizeAndAlignment` pins `hamtLeaf`
  at 32 bytes, including their field offsets. `HamtNode` occupies 72 bytes, but
  `TestHamtNodeOffsets` only logs its size and offsets. The tests in
  [pkg/sync/layout_analysis_test.go](pkg/sync/layout_analysis_test.go) are also
  diagnostic: they print layouts rather than asserting them.
- **Separate independent contention, not every field.** Padding isolates
  `EBRManager.globalEpoch`, `EBRManager.head`, each `shardRoot.ptr`, and
  `ElimStack.head`. The engine root is sharded, so `InsertLocal` and `Join`
  compare-and-swap only the selected shard's root pointer. An `ElimSlot` occupies
  128 bytes: a 48-byte lead pad places `state` and `value` together on one
  64-byte line, and a 64-byte tail separates the slot from its neighbour.
- **Preserve the reason for the layout.** The retired single-locus allocator
  measured 1.1M ops/s at 32 cores (1.6% parallel efficiency). Sharding its
  free-list locus across 64 lines brought the in-process CRDT core benchmark
  into the recorded 50.7M–68.3M ops/s range. These are core measurements, not
  receive-path or mesh results; see the [core benchmark
  receipt](docs/evidence/core-crucible.txt).

`fieldalignment` is not part of public CI. Use its report for review, never its
automatic rewrite: tighter packing can remove deliberate cache-line separation.

## 3. Lock freedom on the write path

- Do not add a `sync.Mutex` to the lock-free CRDT write path. It uses
  compare-and-swap on `uint64` arena offsets and epoch-based reclamation.
  Persistence, lazy views, and other subsystems have their own synchronization;
  this constraint does not make them lock-free. `sync.Pool` is used for per-call
  wrappers and preallocated `Join` scratch buffers. A pool miss on an
  allocation-free path still needs to be measured.
- `recover()` does not turn a fatal `SIGSEGV` into an ordinary panic. Crash
  isolation uses separate processes: the supervisor owns the listener, the
  worker owns the engine, and `stdout` EOF signals a worker crash.
- **WAL replay restores the recorded dot.** Each mutation is applied at its
  WAL-recorded `(DotNodeID, DotCounter)` through synthetic-delta `Join`, and the
  post-checkpoint tail is selected by WAL record sequence rather than a scalar
  counter ([ADR-0045](docs/architecture/adr/0045_mesh_transport_invariants.md)).
  Replay must not call `InsertLocal` to mint a replacement dot. Concurrent
  writers can mint dots and append their WAL records in different orders, so a
  counter derived from record order is not the original causality. The recorded
  failure of that approach produced 10,800 live dots from 10,000 keys.

## 4. Report measurements precisely

Identify the workload, hardware, toolchain, command, and source for every result.
Keep the in-process core benchmark, the in-process receive path, and mesh
convergence separate. Give a range when runs vary, do not round a result up, and
do not turn one run's pass margin into a general headroom claim. Link the
matching receipt in `docs/evidence/` rather than relying on an adjective.

Keep failed and retired comparisons available when they explain the current
design. The retired single-locus scaling test remains skipped with its result
and reason recorded; its 1.6% parallel efficiency is evidence for the sharded
allocator, not a current throughput result.

## 5. Checks for a change

Public CI builds the tree, checks formatting, runs `go vet` with only the known
`unsafe.Pointer` arena warnings allowed, and runs `TestHotPathZeroAllocations`
plus the selected struct-layout tests. Match those checks locally and add the
tests that exercise your change:

- Use `TestHotPathZeroAllocations` and `BenchmarkHAMTInsertZeroAlloc` for the
  measured allocation-free path. A different path needs its own measurement.
- Run the relevant size and offset assertions after a layout change. Inspect
  `TestHamtNodeOffsets` and `TestMemoryLayoutAnalysis` output as well; their
  diagnostic logs do not assert that the offsets are correct.
- Run `TestScalingGate` with `RUN_CRUCIBLE=1` after changing stack contention
  or allocator behaviour. It checks linearizability at every eligible
  `GOMAXPROCS` tier and throughput at the highest tier.
- Exercise the CRDT-law and deterministic simulation tests affected by a merge
  or reconciliation change. The resulting Merkle root must depend on causal
  history, not the test's random seed.

## Platform status

Pre-publication platform checks on 2026-11-21 tested native Linux arm64 and emulated
Linux amd64. Both builds passed; neither complete short-test invocation passed. Native
arm64 included a `TestCheckpointWalkPinnedAgainstState` arena-exhaustion panic and a
known SDK test failure. Emulated amd64 had ten packages with observed segmentation
faults and two assertion failures. The emulated result does not establish behavior on
native amd64 hardware or a root cause for the segmentation faults. These results do
not support a claim of a green test suite on either platform. See
[platform-checks-2026-11-21.txt](docs/evidence/platform-checks-2026-11-21.txt) for the
complete receipt.