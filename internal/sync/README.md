# Sharded Elimination and Combining allocator

**Code-locality architecture document**
*Reference: [Architecture](../../docs/architecture/1_ARCHITECTURE.md)*

This directory contains only this note. The implementation is in `pkg/sync/`: [`sharded.go`](../../pkg/sync/sharded.go), [`reclamation.go`](../../pkg/sync/reclamation.go), and [`crdt.go`](../../pkg/sync/crdt.go).

## Multi-locus sharded topology

`ShardedStack` distributes stack heads and pool free-list traffic across shards so contenders do not all update the same cache line.

- **128-byte stride:** Each `secShard` is 128 bytes, checked by `TestShardedShardSize`. Adjacent stack heads therefore sit 128 bytes apart, matching Neoverse-V1's adjacent-cache-line prefetch pair.
- **Per-goroutine deep cache:** A `secDeepCache` holds up to `DeepCacheCap` node indices. Refills and drains move up to `DeepCacheCap/2` indices at a time, with refills limited by available pool slots. This keeps common bursts goroutine-local while retaining a bounded path to the shared pool.
- **Local routing:** `deepAlloc` refills from the caller's local pool shard, and `deepFreeLocal` drains to the same shard. A pop first probes its selected stack shard, then later shards until it finds a value or exhausts the stack.

## `runtime.procPin` and shard selection

`pkg/sync/sharded.go` calls `runtime.procPin` and `runtime.procUnpin` through `//go:linkname`. The P ID selects a shard, and the pin covers only the yield-free stack-head probe and CAS sequence.

Pool operations happen outside the pin because they can call `runtime.Gosched`. While the pin is held, `mp.locks > 0` blocks asynchronous preemption; the goroutine is not pinned for its lifetime.
