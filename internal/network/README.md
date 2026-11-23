# Network and epoll Cap'n Proto boundary

**Code-locality architecture document**
*Reference: [Network and consensus](../../docs/architecture/4_NETWORK_CONSENSUS.md)*

`internal/network/` contains the read-only Cap'n Proto arena adapter and network clients. The edge-triggered listener is in [`internal/transport/capnp_server.go`](../transport/capnp_server.go); process-isolation helpers are in `internal/chaos/`.

## Supervisor and worker isolation

`internal/chaos/supervisor.go` manages an external `chaos-worker` process for the crash-survival harness. That worker binary is not included in this repository; `TestSIGSEGVSurvival` skips unless `CHAOS_WORKER_BIN` supplies it.

The Supervisor communicates with the worker over stdin/stdout pipes. EOF marks worker death; recovery starts a new worker that replays the WAL. An unacknowledged submit is retried once, and a failed retry is returned to the caller as an error.

The Supervisor does not own a `net.Listener`. The front end retains listeners and client connections outside the worker process, so a worker exit does not itself close those sockets.

## Read-only Cap'n Proto arenas

`EpollServer` reads socket bytes into a jemalloc-backed reassembly buffer. After parsing single-segment framing, it passes exactly the segment bytes to `NewIngestionArena` in `capnp_arena.go`.

`NewIngestionArena` uses `capnp.SingleSegment` to read the message in place; it does not copy the segment into a Go heap allocation or map a kernel socket buffer. Arena allocation is disabled. Schema fields are decoded as views over the received segment rather than deserialized into a separate object graph.

The caller dispatches the decoded `TriTemporalEvent` synchronously and releases the message before reusing the buffer. Releasing the message does not free the jemalloc allocation.
