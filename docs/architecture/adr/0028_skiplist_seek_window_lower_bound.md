# ADR-0028: SkipListArena.Seek — Window Lower-Bound Iterator

**Status:** Accepted

**Date:** 2026-08-08

## Context

`SkipListArena` could insert through a multi-level search, but its only read
iterator started at the first key and walked level 0. Finding the lower bound of
a window therefore required an O(N) scan even though `Put` already knew how to
skip through upper levels. ADR-0024 identified this missing primitive while
describing Range-read acceleration.

The composite key is 40 bytes: a 16-byte entity hash followed by 8-byte system,
valid, and assertion timestamps. Offset 0 is the head node; `0xFFFFFFFF` marks
the end of a level. `nodeNext` reads links atomically, and `maxHeight` caps the
list at 11 levels.

## Decision

Add `Seek(target)` and the equivalent `NewSeekIterator(target)`. They descend
from the highest level, advance while the next key is less than the target, and
return the first level-0 key greater than or equal to the target. A target past
all keys returns an exhausted iterator whose current offset is `0xFFFFFFFF`.

A read-only descent lacks the compare-and-swap retry that corrects `Put` when a
concurrent insertion moves a predecessor. Before the concurrency guard was
added, a writer inserting 100,000 keys alongside 8 readers making 1,000 seeks
each produced lower-bound violations on about 1–2% of seeks. The failure could
return the last key for a target beyond the end of the list.

`Seek` therefore checks its level-0 result before returning it. If the key is
less than the target, it calls `seekLowerBoundLinear`, which starts at the head
and follows only level 0 until it finds the lower bound. This preserves the
read-time lower-bound contract without taking a lock. In the recorded runs, the
fallback fired 51–219 times per 8,000 concurrent seeks.

The stale key-layout comment was also corrected from 32 bytes with an 8-byte
hash to the actual 40-byte layout with a 16-byte hash. This did not change the
key format.

## Consequences

The descent examines at most 11 levels, although it may take multiple steps on
one level. On a quiescent list it avoids the full level-0 scan and the fallback
does not run. Under concurrent writes, a stale descent can still cost an O(N)
fallback. The contract is a valid lower bound at the read moment, not a
linearizable snapshot of the list.

Each `Seek` returns one heap-allocated iterator. This is a read-path allocation,
separate from the zero-allocation write-path contract.

The primitive has no production caller in v0.2.0. `FlushArenaToIPC` still uses
`NewIterator`, and `scanWindowRecordBatch` consumes an `arrow.Record`, not a
SkipList. The existence of `Seek` must not be read as wired Range acceleration.

## Evidence

`internal/database/skiplist_seek_test.go` contains seven tests and two
benchmarks. The tests cover exact and just-before lower bounds, targets before
the first key and past the last key, empty lists, iterator equivalence,
allocation count, and concurrent inserts. Quiescent equivalence uses 4,096 keys
and 10,000 deterministic targets from seed 23, split between within-entity and
random 128-bit hashes. The concurrent test reports zero violations after the
guard and also checks the final lower bounds after the writer stops.

The recorded quiescent, in-process benchmark used 131,072 keys from one entity
and deterministic targets from seed 42:

| Operation | Time | Allocation |
|---|---:|---:|
| `BenchmarkSeekLogN` | 714–743 ns/op | 16 B/op, 1 alloc/op |
| `BenchmarkLinearScanLogN` | 429,080–429,462 ns/op | 0 B/op, 0 allocs/op |

The measured ratio is about 600× at this key count. It is a microbenchmark
comparison, not a production query-latency result; the source record does not
name the benchmark machine.

The linear benchmark's `NewIterator` result remains on the stack after inlining,
while the iterator returned by `Seek` escapes to the heap. The zero allocation
report for the linear path is therefore not the result of amortizing a heap
allocation across benchmark iterations.
