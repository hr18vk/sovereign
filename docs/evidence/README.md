# Evidence

Every headline number in this repository is backed by a real `go test` run on named
silicon. This directory holds the raw verdict excerpts — the command, the machine,
and the unedited output lines — so each claim is independently checkable rather than
taken on faith.

The discipline that governs every number here: **report the layer, the range, and the
provenance** — never a bare hero figure. The CRDT *core* microbench and the *production
ingest* path are different layers and are never conflated.

| Claim | Receipt | Command to reproduce |
|:--|:--|:--|
| **CRDT core: 68,278,197 ops/s 32c** (gate floor 50,736,038) | [core-crucible.txt](core-crucible.txt) | `RUN_CRUCIBLE=1 go test -run TestScalingGate -cpu=32 -count=1 ./pkg/sync/` |
| **Convergence: 100 node processes on 3 machines, 8.95s against a 10s target** | [convergence-100-node.txt](convergence-100-node.txt) | 100 node processes (34/33/33) on one `c7gd.8xlarge` in each of `us-east-1` / `eu-west-1` / `ap-southeast-2`, mTLS mesh; convergence timed from origin quiescence |
| **Production ingest: 5.7M–6.0M deltas/sec 32c** | [ingest-ed25519.txt](ingest-ed25519.txt) | `go test -run '^$' -bench=BenchmarkBatchedVerifyParallel -benchmem -cpu=32 ./pkg/receive/` |
| **Zero-GC hot path: 0 B/op, 0 allocs/op** | [zero-alloc.txt](zero-alloc.txt) | `go test -bench=BenchmarkHAMTInsertZeroAlloc -benchmem ./pkg/sync/` |
| **Crash recovery: kill -9 → root re-equals in ~15s** | [crash-recovery.txt](crash-recovery.txt) | inject batch → `kill -9` the seed → restart on the same WAL + snapshot → compare root |
| **All of the above, on your own machine** | your transcript | `./scripts/reproduce.sh` (provenance header + saved transcript); `CRASH=1 ./scripts/local-mesh.sh` for a 3-node mesh, `kill -9`, and WAL recovery on one box |

## How to read these

- **`core-crucible.txt`** is the *data-structure floor*: an in-process `HAMT.Set`
  push/pop crucible with **no** Ed25519 verify, envelope, network, TLS, or
  persistence. It is the largest number the engine can cite, and it is deliberately
  *not* the ingest rate.
- **`ingest-ed25519.txt`** is the *real production receive path*: verified Ed25519 +
  CRDT apply + envelope. It is a different, lower layer — the per-frame Ed25519
  verify (~60µs unbatched) is the dominant per-op cost that batching + 32-way
  parallelism amortize. This is the honest gap between "the core does 68M" and
  "the wire does ~5.7–6M", stated plainly instead of hidden.
- **`convergence-100-node.txt`** is the multi-region run: 100 node processes on three
  machines (one per region) reach an identical Merkle root 8.95 s after the origin went
  quiet, against a 10-second target, with the durable write path (WAL, one fsync per
  batch) on in every node log. It is the one published receipt; the seven consecutive
  runs before it (six passes between 6.6 s and 8.7 s, one miss at 10.15 s) are tabulated
  in [ADR-0050](../architecture/adr/0050_checkpoint_decouple_delta.md).
- **`zero-alloc.txt`** is the zero-GC invariant: the write hot path allocates nothing.

## What is intentionally *not* claimed

The honest boundary matters as much as the numbers. Not yet built: production PKI /
HSM key custody, the io_uring transport, and the gRPC API surface. The convergence
target is met, but the last one or two of 100 nodes occasionally straggle past the
10-second mark on roughly one run in seven — an open robustness item, not a
correctness failure. These are stated on the main
[verification page](https://sovereignengine.space/docs/architecture/verification) and
in the [decision log](../architecture/adr/), not hidden.

If a number here does not reproduce on the documented silicon, that discrepancy is
real and worth an issue — the honest-negative culture treats a reported failure as a
contribution, not an embarrassment.
