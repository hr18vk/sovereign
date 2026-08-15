# Contributing to the Sovereign Engine

The Sovereign Engine is a planetary-scale, zero-GC, off-heap δ-CRDT database
engine. Contributions are welcome and held to the same world-class engineering
standard as the core: every change must preserve the physical invariants the
engine is built on, and must be honest about what it does and does not prove.

## Before you contribute

1. **Read [SUPREMUM_STYLE.md](../SUPREMUM_STYLE.md)** — the laws of physics
   (zero-GC on the hot path, 128-byte cache-line stride, lock freedom on the
   write path, absolute honesty about headroom) imposed on every change. A
   change that violates them is rejected by continuous integration without human
   review — and that is the point: a gate that cannot be talked out of failing
   is the only architect that survives contact with silicon.
2. **Read the relevant [ADR](../docs/architecture/adr/)** before touching the
   subsystem it governs. Every load-bearing change is recorded as an
   Architecture Decision Record with a root cause, a change, and a gate result.
   The on-disk sequence jumps ADR-0041 → ADR-0044 (ADR-0042 and ADR-0043 were
   committed in code but not written as documents — an honest documentation gap,
   not an engine defect) — read the ADRs that bracket any subsystem you change.
3. **Run the gates locally** before opening a pull request (commands below). A
   PR that fails CI on a physical invariant has not wasted only your time; it
   has also wasted the silicon budget, so CI cancels superseded runs.

## License and contribution terms

This repository is **source-available under the [Business Source License 1.1](../LICENSE)**,
owned by **Sovereign Systems (Sovereign Engine Project)**.

- **Change Date:** 2029-08-15. On the Change Date this license converts in
  perpetuity to an unencumbered one.
- **Non-Production Use** (evaluation, testing, benchmarking, internal research,
  development, educational and personal use) is permitted without restriction.
- **Production Use** (any use offered as a commercial product or service, or that
  competes with or substitutes for the Licensor's offerings) requires a separate
  written grant from the Licensor until the Change Date.

This is **source-available, not OSI "open source"** — the BSL-1.1 restricts
Production Use until the Change Date. Contributions are accepted under these
same terms. By submitting a pull request you attest that:

- your contributions are your original work and you have the right to license
  them to Sovereign Systems under the BSL-1.1;
- your contributions are licensed to Sovereign Systems under the BSL-1.1, on the
  same terms as the rest of the repository, and will convert on the Change Date
  alongside the rest of the work;
- you are not, to your knowledge, introducing proprietary code you do not have
  the right to contribute.

A contribution that touches a load-bearing file (the FROZEN-5 below) is almost
never the right change — open an issue first so the design can be discussed
before the bytes move.

## The engineering standard — what CI enforces mechanically

A change that compiles is not a change that ships. Continuous integration
enforces the physical invariants; a red run is a mechanical rejection that does
not require, and does not wait for, human judgement.

- **Zero-GC hot path** — `TestHotPathZeroAllocations` asserts `0 B/op,
  0 allocs/op` for `HAMT.Set`. No `make`/`new`/heap-escaping `interface{}` on a
  path reachable from the write path unless annotated `// arena-bound: <reason>`
  naming the slab class. CI greps the diff and runs escape analysis.
- **128-byte stride** — `fieldalignment` + `TestMemoryLayoutAnalysis` reject
  wasted intra-struct padding and any cache line holding more than one contended
  atomic. Every hot struct is packed with zero internal padding (`CRDTEntry` =
  120 B, `hamtLeaf` = 32 B, `HamtNode` = 72 B, `ElimSlot` = 128 B).
- **Lock freedom on the write path** — no `sync.Mutex` on the write path; CAS +
  EBR only. The mutexes that exist guard off-hot-path concerns (disk fsync in
  the decoupled persist worker, the lazy `State()` view, the WAL append
  serializer) and are disclosed honestly, not hidden.
- **WAL replay seed** — replay starts at `firstMutation.Counter - 1`, NOT
  `LamportHigh`; replay re-runs the minting. Changing this is data corruption.
- **FROZEN-5 byte-identity** — five load-bearing files
  (`pkg/sync/crdt.go`, `pkg/sync/crdt_apply.go`, `pkg/attribution/envelope.go`,
  and the `api/capnp/api/capnp/schema.capnp` + `schema.capnp.go` pair) are
  byte-locked by `TestDay39_T_FrozenMD5` and `TestDay36_T_LOOP_FrozenMD5`. A
  change that alters their bytes fails CI. These encode the CRDT convergence
  law and the wire contract; they move only with an ADR that re-proves the law.
- **Benchmark regression** — throughput may not regress > 0.5% and P99 may not
  rise > 1 µs vs the target branch, per `bencher`.

## Legacy namespaces (read before you are surprised)

Two legacy identifiers are intentional and documented in-code, not defects:

- **Go module path.** `go.mod` declares `module github.com/hr18vk/supremum`. The
  public repository is `github.com/hr18vk/sovereign`. These differ pending a
  module-path migration fork: clone-and-build works (the module path is an
  identifier, not a fetch path — `go build ./...` succeeds from a clone), but
  `go get github.com/hr18vk/sovereign` does not resolve until the module path
  is renamed (a code-wide import edit, tracked as a future fork). The README's
  Quickstart uses `git clone`, not `go get`, for this reason.
- **Prometheus metric namespace.** The engine surfaces metrics under the
  `supremum_*` Prometheus namespace (e.g. `supremum_mesh_inter_region_envelopes`),
  mapped from internal `supremum.*` dotted telemetry counters by
  `pkg/metrics/telemetry_bridge.go`. A `sovereign_*` namespace coexists for
  newer series. The `supremum_*` names are a load-bearing observability API
  asserted by the metric teeth; renaming them is a breaking change tracked as a
  future fork, not a docs edit. The shell scripts keep the `SUPREMUM_*`
  environment-variable prefix for the same reason (operator-set API); their
  defaults already point at `hr18vk/sovereign`.

## Build, vet, test

```bash
# Prerequisites: libjemalloc-dev + capnproto (the engine binds jemalloc via CGO
# and generates the capnp wire schema). See the README "System prerequisites".
go build ./...          # must exit 0
go vet ./...            # the documented pkg/sync FROZEN-test unsafe.Pointer
                        # warnings are the pre-existing baseline — tolerated, not "fixed"
go test ./...           # green across the repository
```

The core microbenchmark gate (the data-structure floor, NOT the ingest rate):

```bash
RUN_CRUCIBLE=1 go test -run TestStage5ScalingGate -v ./pkg/sync/
```

The multi-region silicon teeth (convergence + sharded root + batch insert):

```bash
go test ./pkg/mesh/ ./pkg/sync/ \
  -run "TestDay39|TestDay37|TestDay36|TestShardedRoot|TestBatchInsert" -count=1
```

See the README *Quickstart* and *The measured numbers* sections for what each
gate measures and the layer discipline that separates the CRDT core microbench
from the production ingest rate.

## Honesty is the contribution bar

The moat of the Sovereign Engine is that it is the most truthful planetary
engine ever built. A contribution is held to that bar:

- Cite the measurement, the hardware, and the gate that produced it — never an
  adjective. "Blazing", "world-class", "revolutionary" are anti-signals here.
- Report the layer a number measures. The CRDT core (50.7M–57.6M ops/s @32c,
  in-process `HAMT.Set`, no Ed25519/envelope/network/TLS/persistence) and the
  production ingest rate (1.0M–3.1M deltas/sec @64c, N=256) are different claims
  — never conflate them.
- Preserve the evidence of failure. A gate that passes by a thin margin passes;
  cite the margin, do not round it up. A retired gate is skipped with a recorded
  reason, not deleted.

## Reporting issues

Issues are welcome for **defects and honesty gaps** — a number that does not
reproduce on the documented silicon, a claim that does not match its cited
source, a gate that passes by a thinner margin than stated. File the issue with
the exact command, the hardware, the Go version, and the observed output. The
honest-negative culture is the moat: a reported failure is a contribution, not
an embarrassment.
