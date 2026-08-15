# Network & Epoll Cap'n Proto Boundary

**Code-Locality Architecture Document**
*Reference: `docs/architecture/4_NETWORK_CONSENSUS.md`*

This directory (alongside `internal/transport/` and `internal/chaos/`) defines the raw physical network entry points to the Supremum Engine.

## Supervisor & Worker SIGSEGV Isolation

The engine is mathematically guaranteed to survive a `SIGSEGV` in the off-heap `C-space` because the network listener is physically isolated from the runtime failure domain.

- **Supervisor Pattern:** `internal/chaos/supervisor.go` boots the `chaos-worker` as a child process. The actual TCP socket and OS-level `net.Listener` is held by the Supervisor, **not** the worker.
- **Crash Survival:** If the worker faults, the Supervisor's OS pipe receives an `EOF`. The Supervisor instantly spawns a pristine worker, initiates a WAL replay to the exact Merkle Root checkpoint, and re-submits the in-flight payloads. 
- **The Client Experience:** The TCP connection remains completely intact. The client simply experiences a brief spike in latency, totally unaware that the server suffered a fatal core dump.

## Cap'n Proto Zero-Copy Integration

Defined in `capnp_arena.go`, incoming packets are bound directly from the `jemalloc` block into an immutable `capnp.Arena`.
The engine does NOT deserialize objects. The pointers mapping the `TriTemporalEvent` schema physically point to offsets in the Linux socket buffer, achieving $O(1)$ memory mapping with $0$ Go GC overhead.
