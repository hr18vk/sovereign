# Home-Shard SEC Allocator

**Code-Locality Architecture Document**
*Reference: `docs/architecture/1_ARCHITECTURE.md`*

This directory contains the Sharded Elimination & Combining (SEC) Stack implementation for the Supremum Engine (`sharded.go`, `reclamation.go`, `crdt.go`).

## Multi-Locus Sharded Topology

As identified in Stage 5c analysis, standard Treiber stacks or Flat-Combining funnels mathematically collapse at high concurrency (32+ Neoverse-V1 cores) due to cache-line saturation at the Home Node (HN-F). 

Our `ShardedStack` defeats this physics bottleneck by implementing a multi-locus topology:
- **128-Byte Stride:** Each shard (`secShard`) is strictly padded to 128 bytes. This physically isolates shards into separate Cache Line pairs, defeating the Neoverse-V1 L2 adjacent spatial prefetcher.
- **Per-Goroutine Deep Cache:** The global `ElimNodePool` is protected by `secDeepCache`. It draws indices in bulk (128 at a time) ensuring that continuous burst-pushes resolve locally in the goroutine without touching a shared atomic. 
- **Scatter/Gather Home-Shard Routing:** Indices are scattered back to their "home" shards (`idx % 64`) during pops, mathematically balancing consumer/producer skew.

## `runtime.procPin` Go Scheduler Evasion

To guarantee absolute cache-locality, `sharded.go` uses `//go:linkname` to invoke `runtime.procPin()`. 

1. **Deterministic Hashing:** The `P-ID` maps perfectly to a discrete shard index.
2. **Preemption Immunity:** Pushing `mp.locks > 0` blocks the Go `sysmon` thread from injecting `SIGURG` preemption signals midway through our Compare-And-Swap (CAS) sequence.
