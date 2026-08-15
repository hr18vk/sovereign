# SUPREMUM_STYLE — The Laws of Physics Imposed on Every Pull Request

This is not a `CONTRIBUTING.md`. It is the constraint set under which the
Supremum Engine holds 57,638,422 ops/s on a 32-core AWS Graviton. Every rule
below traces to a measured gate in `pkg/sync`. A pull request that
violates them is rejected by continuous integration before a human reads it.
That mechanical rejection is not hostility for its own sake; it is the only
honest architect at planetary scale, because a gate that cannot be talked out
of failing is the only architect that survives contact with silicon.

## 1. Zero-GC on the Hot Path

The Go mark-and-sweep garbage collector is a non-deterministic latency tax.
Every heap allocation on the write path is a future stop-the-world pause. The
Supremum Engine's write path — `HAMT.Set`, `DeltaCRDTEngine.InsertLocal`,
`ElimStack` push/pop — must perform **0 allocations, 0 bytes/op**, verified by
`TestHotPathZeroAllocations` asserting `BenchmarkHAMTInsertZeroAlloc` shows
`0 B/op 0 allocs/op`.

- **All long-lived data lives off-heap.** HAMT nodes, leaves, entity strings,
  and CRDT entry arrays are carved from anonymous memory reserved with
  `syscall.Mmap`, advised with `MADV_SEQUENTIAL`/`MADV_WILLNEED`, and freed
  through segregated slab allocators with lock-free Treiber free-lists. The Go
  GC cannot scan it and cannot stop the world over it.
- **No `make` on the hot path.** `make([]T, n)`, `make(map[...]...)`, and
  `make(chan ...)` allocate on the Go heap. Their use in any package reachable
  from the write path is forbidden. Pre-allocate into the arena, or use a
  `sync.Pool` seeded by arena wrappers.
- **No `new` on the hot path.** `new(T)` returns a Go-heap pointer. If you
  need a `T`, take it from an arena slab or embed it by value.
- **No heap-escaping interfaces.** Assigning a concrete `T` to an `interface`
  or `any` boxes it onto the heap when `T` is larger than a word or its address
  is taken. Pass concrete types or `unsafe.Pointer` into arena offsets. The
  compiler's escape analysis is advisory, not a contract — if a hot-path
  function is not provably `nosplit`/no-escape, rewrite it.

### Mechanical Rejection

CI greps the diff for `make(`, `new(`, `interface{`, `any`, and `func() ...`
closures on the hot path, and runs escape analysis with `-gcflags="-m"`. A diff
that matches and is not annotated with a `// arena-bound: <reason>` comment
naming the slab class is rejected without review. There is no appeal to
intent; the gate is the reviewer.

## 2. The 128-Byte Stride

A Graviton core fetches data in 64-byte cache lines; the coherence protocol
 invalidates on the line. The Supremum Engine standardizes on a **128-byte
stride** — two cache lines — for every record that may be touched concurrently
by more than one core. The proof is in [docs/internals/STRUCT_ALIGNMENT.md](docs/internals/STRUCT_ALIGNMENT.md);
the gate is [pkg/sync/layout_analysis_test.go](pkg/sync/layout_analysis_test.go) and the `fieldalignment`
CI job.

- **Wasted intra-struct padding is zero.** Fields are ordered so that the
  struct's size is the sum of its field sizes — no alignment gaps between
  fields. `CRDTEntry` is exactly 120 bytes with zero internal padding;
  `hamtLeaf` is exactly 32 bytes; `HamtNode` is exactly 72 bytes. These are
  asserted by `TestCRDTEntry_SizeAndAlignment`, `TestHamtLeaf_SizeAndAlignment`,
  and `TestHamtNodeOffsets`.
- **Every contended atomic is alone on its line.** `EBRManager.globalEpoch`,
  `EBRManager.head`, the per-shard `shardRoot.ptr` (the HAMT root pointer, CAS'd
  on every `InsertLocal`/`Join` *within one shard*), and `ElimStack.head` are
  each flanked by `CacheLinePad` (`[64]byte`) so that no other field shares
  their line. The engine root is sharded (`shards []shardRoot`), so the single
  global `DeltaCRDTEngine.state` CAS of earlier phases is gone — the hot locus
  is dispersed across N per-shard padded CAS slots (`_padHead | ptr | _padTail`).
  The `ElimSlot` is 128 bytes: a 48-byte lead pad so `state`+`value` share exactly
  one 64-byte line, followed by a 64-byte `CacheLinePad` tail, so adjacent slots
  never false-share.
- **The cost of ignoring this is measured.** The legacy single-locus SEC gate
  collapsed the allocator's free locus to one shared cache line and measured
  **1.1M ops/s at 32 cores (1.6% parallel efficiency)** — a HITM storm. The
  Home-Shard Allocator disperses that locus across 64 lines and restores
  **57.63M ops/s**. Two atomics on one line is not a sub-microsecond rounding
  error; it is the whole budget.

## 3. Lock Freedom on the Write Path

- `sync.Mutex` on the write path is a futex and a scheduler stall. The write
  path uses `atomic.Uint64` CAS against arena offsets, not boxed pointers — a
  `uint64` index stays Zero-GC under the CAS. `sync.Pool` is permitted only for
  non-hot per-call wrappers (e.g. `RetiredNode`), never for the value being
  routed.
- `recover()` is blind to `SIGSEGV`. Crash isolation is a separate address
  space (supervisor owns the listener, worker owns the engine, `stdout` EOF is
  the crash signal), never a panic boundary. WAL replay seeds the rebuilt engine
  at `firstMutation.Counter - 1` (the pre-first-write Lamport), NOT at
  `LamportHigh` and NOT at `LamportHigh - len(Mutations)` — the latter is the
  legacy Day-8 defect formula that under-counts the seed and silently diverges
  the Merkle root; replay re-runs the minting from the true pre-write frontier.

## 4. Absolute Honesty About Headroom

From `AGENTS.md` and the post-mortem, the cardinal reporting rule:

- A gate that passes by 8.5% is a gate that passed. It is not a "shatter." Cite
  the range — the 32-core figure varies 50.7M–57.6M across clean runs; the 25.1%
  parallel efficiency is the silicon wall, not a defect you are asked to "fix."
- No marketing adjectives. "blazing fast," "revolutionary," "high-performance"
  are inversely correlated with competence here and are anti-signals. Use the
  number, the host, and the gate that produced it.
- Preserve the evidence of failure. The retired legacy gate is skipped with a
  recorded reason, not deleted. Its 1.6% efficiency is the justification for the
  Stage 5 rewrite.

## 5. What Breaks the Build

- Any struct with non-zero wasted padding, per `fieldalignment`.
- Any benchmark regression > 0.5% throughput or > 1 µs P99, per `bencher`.
- Any `ALLOC=0` gate that records a non-zero `allocs/op`.
- Any linearizability assertion failing at any `GOMAXPROCS` tier.
- Deterministic simulation that does not converge seed-independently (the Merkle
  root must be a function of the causal history, not the test's RNG).
