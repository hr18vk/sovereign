# Contributing to Sovereign Engine

Thanks for your interest. Read [STYLE.md](STYLE.md) and the decision records relevant
to the subsystem before opening a pull request.

## Build & test

The target and tested platform is Linux/ARM64 on AWS Graviton. You need **Go 1.26.1**,
a C toolchain, and **jemalloc** for the off-heap store's CGO binding:

```bash
sudo apt-get install -y build-essential libjemalloc-dev
go build ./...
go test ./...
```

`scripts/benchmark.sh` installs Go 1.26.1 and runs `TestScalingGate` with
`RUN_CRUCIBLE=1`. The gate needs eight or more cores and asserts 50M ops/s at its top
eligible tier. A different machine can fail on throughput alone. `--no-crucible` skips
that assertion and still runs the allocation and false-sharing benchmarks.

`scripts/reproduce.sh` runs the single-machine allocation, layout, CRDT-law,
post-quantum key-exchange, in-process receive-path, and core scaling checks, and
saves a transcript with machine details. It does not recreate the 100-node multi-region or
crash-recovery receipts in `docs/evidence/`. `scripts/local-mesh.sh` starts a three-node
mesh on one machine and checks Merkle-root convergence; `CRASH=1` also stops the origin
and checks recovery from its WAL. A node-count option is available:
`NODES=30 ./scripts/local-mesh.sh` runs the same flags on one machine with 30 node
processes. This is a single-machine counterpart of the fleet run, never a substitute for it.

Pre-publication platform checks on 2026-11-21 tested native Linux arm64 and emulated Linux
amd64. Both builds passed; neither complete short-test invocation passed. Native arm64
included a `TestCheckpointWalkPinnedAgainstState` arena-exhaustion panic and a known SDK
failure. Emulated amd64 had ten packages with observed segmentation faults and two
assertion failures. These results do not support a claim of a green test suite on either
platform. See [platform-checks-2026-11-21.txt](docs/evidence/platform-checks-2026-11-21.txt).

## Engineering constraints

The core has deliberate constraints on allocation, memory layout, and synchronization.
A change to those paths must preserve them:

- **Zero allocation on the measured write hot path.** `TestHotPathZeroAllocations`
  checks `HAMT.Set`; benchmark other affected paths and report their allocation counts.
- **Padding around contended atomics.** Independently written fields must not share a
  cache line. The hot layouts and their tests are described in [STYLE.md](STYLE.md).
- **No mutex in the lock-free CRDT core.** Compare-and-swap and epoch-based reclamation
  protect that path. Persistence and other subsystems have their own synchronization.
- **WAL replay restores the recorded dot.** It must not mint a new dot for an existing
  mutation.
- **Measurements identify their layer and conditions.** Keep the in-process core
  benchmark, the in-process receive path, and mesh convergence separate. Cite the
  command, machine, range where relevant, and receipt in `docs/evidence/`.

## What "done" means

- `go build ./...`, `gofmt -l .` (empty), and `go test ./...` are clean.
- `go vet ./...` adds no findings beyond the existing `possible misuse of
  unsafe.Pointer` arena warnings; CI allows that known baseline only.
- If you touch the hot path, show the benchmark delta and its allocation count.
- If you change an externally-visible number, update the matching file in
  `docs/evidence/` with the command and the machine.

## Failed results are useful

If something is slower, wrong, or unproven, say so in the PR. A documented
limitation is more useful than an omitted one. The ADRs under
`docs/architecture/adr/`, including the rejections, show the expected candor.

## License

Sovereign Engine is source-available under the **Business Source License 1.1** (see
`LICENSE`). By contributing, you agree to provide your contributions under the same
terms and confirm that you have the right to license them. Production use requires a
written grant from the Licensor until the applicable Change Date. Each version then
converts to Apache-2.0 four years after its publication; v0.1.0 retains its Change
Date of 2029-08-15; v0.2.0 converts four years after its actual publication date.

## A note on scope

This is a solo-maintained project. Review bandwidth is real but finite — small,
focused, well-tested PRs with a clear rationale get the fastest response. Large
refactors should be proposed in an issue first.