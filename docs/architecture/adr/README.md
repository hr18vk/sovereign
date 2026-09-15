# Architecture Decision Records

Every consequential design decision in Sovereign Engine is written down here as an ADR: the
problem, the options weighed, the decision, and the measured result. These are the engineering
log, not marketing — several are *rejections* ("we tried X, here's the measured reason it loses"),
which are as valuable as the acceptances because they stop the next person from re-walking a dead end.

Numbers in these records follow the repo's honesty rule: each carries its **layer** (CRDT-core
microbench vs. production ingest vs. convergence), its **range**, and the **machine** it was measured
on. A number without those three is a bug in the record.

Read in order they tell the story of the engine; grouped below by theme for orientation.

## Core data structure & the merge law
- **ADR-0001** — Reject TrueTime commit-wait; HLC + time-sync ε suffices
- **ADR-0004** — Reject per-entry physical-time tuples in the CRDT core (memory-layout regression)
- **ADR-0015** — Unfreeze the Join hot path: pool the incoming buffer + per-block merge scratch
- **ADR-0022** — The zero-alloc Join sort step (`sort.Slice` → `slices.SortFunc`, no-capture comparator)
- **ADR-0028** — SkipListArena.Seek: the logarithmic window lower-bound iterator

## Durability, storage & recovery
- **ADR-0013** — Durability triad: WAL write-through + recovery bootstrap
- **ADR-0016** — The LSM↔durability seam: bounded recovery
- **ADR-0018** — The per-entity L0 split-merge (closing the silent multi-entity read-miss)
- **ADR-0019** — L0→L1 per-entity compaction (eliminating the MaxL0Files silent-data-loss cap)
- **ADR-0020** — Level-2 superseded-row pruning: the tri-temporal dominance lattice + a GC floor
- **ADR-0021** — The L0 reaper: reclaim the superseded-L0 backstop
- **ADR-0025** — The DominancePrune O(N²)→O(N·H) interval sweep
- **ADR-0029** — Filename-bounded download skip (transitively-safe elimination on the file channel)
- **ADR-0030** — Manifest-channel download skip (the second download channel)
- **ADR-0031** — Zero-alloc streaming manifest parse
- **ADR-0033** — Deleting the eager-lossy conflict resolver (a convergence-correctness won't-fix)
- **ADR-0044** — WAL group-commit: cutting the fsync count for the convergence SLO
- **ADR-0048** — Complete the WAL fsync lock-scope split (the reverse-convoy)
- **ADR-0049** — Checkpoint-flush causation at silicon (the synchronous flush, not the WAL convoy)
- **ADR-0050** — Decouple + delta-batch the checkpoint flush (the convergence SLO met)
- **ADR-0053** — WAL + snapshot CRC32C integrity that fails loud

## Transport, security & post-quantum
- **ADR-0002** — epoll + SO_ATTACH_REUSEPORT_EBPF ingress fanout (in-process seam)
- **ADR-0003** — Live BPF sk_reuseport on Graviton (the BPF steering half, silicon-proven)
- **ADR-0006** — TLS 1.3 transport + the production node binary (default tier)
- **ADR-0007** — Real-socket two-node mesh: signed-envelope gossip over TLS 1.3
- **ADR-0035** — PKI leaf rotation + CRL revocation
- **ADR-0036** — Post-quantum transport readiness (X25519MLKEM768 KEM proof)
- **ADR-0037** — Hybrid PQ sign wire (Ed25519 + ML-DSA-65 batch sign + envelope frame)

## Ingest, query & observability
- **ADR-0005** — Close the four ingress gaps (epoll loop + real NIC + perf bench + receiver wiring)
- **ADR-0008** — Prometheus `/metrics` + SLO p99 histograms (making the engine observable)
- **ADR-0010** — Batched delta wire v1: the 1M/sec arithmetic (one Ed25519 over N self-originated deltas)
- **ADR-0011** — SDK + client library + runnable example (the engine becomes usable)
- **ADR-0012** — Silicon 1M/sec sector bench (the headline becomes measured)
- **ADR-0014** — Ingest-path alloc hardening (value-return seam + zero-copy payload read)
- **ADR-0017** — The query resolver: the read half of the durability tier (`/v1/query` over `Resolver.AsOf`)
- **ADR-0023** — The observability egress: bridging internal counters onto the `/metrics` registry
- **ADR-0024** — The durable bitemporal-history range read (`Resolver.Range`, interval-intersection)
- **ADR-0026** — Arm `telemetry.Init` at boot (dedup + counter rebuild)
- **ADR-0027** — GC-floor auto-inference from the observed live-query frontier
- **ADR-0032** — The read-your-writes live δ-CRDT seam (the LiveSource interface)

## Mesh, convergence & hardening
- **ADR-0009** — Chaos partition probe: the convergence-after-heal SLO (the survival gate)
- **ADR-0034** — Stratified anti-entropy mesh wiring (digest exchange before the per-peer delta)
- **ADR-0038** — Wire-protocol + CRDT-apply fuzz harness (native `go test -fuzz` no-panic anchor)
- **ADR-0039** — Region-aware gossip data-plane
- **ADR-0040** — Out-of-band peer-directory pubkey provisioning
- **ADR-0041** — The 100-node 3-region silicon convergence gate
- **ADR-0045** — Mesh transport correctness invariants (the two-release discipline)
- **ADR-0047** — Close quiesce: the teardown use-after-free + the cold-start Lamport flush
- **ADR-0051** — A per-shard PointGet retires the production read-path OOM
- **ADR-0052** — The resliced-buffer wrong-size free that corrupted the jemalloc heap

---

These records are append-only. A decision that turns out wrong is not edited away — a later ADR
supersedes it and says why. That trail of honest reversals is the point.
