# Evidence

These are the published v0.1.0 receipts. Each identifies its workload and
method or command, followed by preserved output. Hardware and run dates appear
where they were recorded. The six receipt files remain unchanged, including
their historical wording, so the output stays attached to the run that produced
it.

The measurements cover different layers: an in-process stack benchmark, an
in-process receive-path benchmark, a multi-region mesh, crash recovery, and a
HAMT allocation test. Their conditions and units are not interchangeable. None
of these files is a v0.2.0 re-run; new results need their own dated receipts.

| Claim | Receipt | Recorded command or method |
|:--|:--|:--|
| Core stack: 68,278,197 ops/s at 32 cores on 2026-09-03 | [core-crucible.txt](core-crucible.txt) | `RUN_CRUCIBLE=1 go test -v -run TestScalingGate -cpu=32 -count=1 ./pkg/sync/` |
| Convergence: 100 node processes on 3 machines reached equal roots 8.950s after origin quiescence on 2026-09-13 | [convergence-100-node.txt](convergence-100-node.txt) | Fleet layout, durability checks, and timing method are in the receipt |
| In-process receive path: 5.7M–6.0M deltas/sec at 32 cores on 2026-09-15 | [ingest-ed25519.txt](ingest-ed25519.txt) | `go test -run '^$' -bench=BenchmarkBatchedVerifyParallel -benchmem -count=3 -cpu=32 ./pkg/receive/` |
| HAMT.Set: 0 B/op and 0 allocs/op | [zero-alloc.txt](zero-alloc.txt) | `go test -bench=BenchmarkHAMTInsertZeroAlloc -benchmem -count=3 ./pkg/sync/` |
| Crash recovery: `kill -9` to equal roots in 14.943s on 2026-09-02 | [crash-recovery.txt](crash-recovery.txt) | Inject, kill the seed, restart on its WAL and snapshot, then compare roots |
| Local test and benchmark transcript at v0.1.0 on 2026-09-22 | [reproduce-c8g-8xlarge-2026-09-22.txt](reproduce-c8g-8xlarge-2026-09-22.txt) | `./scripts/reproduce.sh` |
| Local test and benchmark transcript at v0.2.0 on 2026-11-23 | [reproduce-c4a-standard-32-2026-11-23.txt](reproduce-c4a-standard-32-2026-11-23.txt) | `./scripts/reproduce.sh` |

## v0.2.0 1,000-process fleet evidence

The following receipts document three clean convergence runs and three fault drills
on 1,000 node processes across 30 `c7gd.8xlarge` machines in three AWS regions
on 6 November 2026.

| Receipt | Scope |
|:--|:--|
| [convergence-1000-node.txt](convergence-1000-node.txt) | Full fleet layout, clock definitions, non-default configuration, per-run timestamps, post-quiescence convergence times (2.906 s, 4.038 s, 3.823 s), and verbatim gate output |
| [convergence-1000-node-runs.tsv](convergence-1000-node-runs.tsv) | Six-run measurement table (three clean runs plus kill/restart, packet-drop, and impostor-identity drills) with 28 columns: verdict, converged_at_ms, per-region t100_ms, fingerprint equality, exchange counts, signature failures, digest bytes, and heartbeat bytes |
| [convergence-1000-node-attempts.tsv](convergence-1000-node-attempts.tsv) | Complete history of 49 full-scale attempts (attempt-001 through attempt-049), including earlier target misses, aborted runs, the free-list SIGBUS/corruption run, and the first impostor attempt's RUN_RC=4 |
| [fault-drills-1000-node.txt](fault-drills-1000-node.txt) | Exact drill definitions (which node, which port, duration, impostor behavior), results, and limitations; the first impostor attempt (RUN_RC=4) and the replacement-fleet repetition are disclosed separately |

### Raw evidence directory

The `raw/` subdirectory contains 27 verified files:

- Six per-node final-state tables (`*.fingerprints.tsv`), each with 1,000 data rows and columns `global_idx`, `region`, `box_id`, `ip` (redacted as `[address]`), `port`, `keys`, `state_fp`, and `xor_root`. The `xor_root` column retains its original raw-table meaning and is not a Merkle root.
- Six archive manifests (`*.manifest.sha256`), each with 30 per-machine archive entries plus one self-entry, preserving original SHA-256 digests and entry order.
- Nine gate and hook logs (`*.gate.log`, `*.during-gate-hook.log`, `*.pre-gate-hook.log`), published verbatim with only approved redactions (addresses, instance identifiers, private filesystem tokens, and blocked source-run labels replaced by bracketed placeholders or public aliases).
- Six console extracts (`*.console.txt`), selected verbatim lines sufficient to check injection, quiescence, convergence, per-region t100, fingerprints, verdict, drill hooks, and harvest. They are selections, not complete consoles.

See [raw/README.md](raw/README.md) for the full index, column meanings, redaction conventions, archive coverage (the 180 original per-machine `.tgz` archives were not preserved after 6 November 2026 and cannot be restored; their manifests preserve recorded names and digests but do not establish current archive availability), and console-extract limits.

Earlier 1,000-node runs missed the 10-second target and all 49 full-scale attempts are listed in `convergence-1000-node-attempts.tsv`. The complete raw evidence (manifests, final-state tables, gate/hook logs, and console extracts) for the six final runs is verified and published. The original per-machine `.tgz` tarballs were not preserved and cannot be supplied; their manifests do not establish current availability. Do not request raw tarballs — they do not exist.

The fleet harness is not published. The 1,000-process, 30-machine run cannot be reproduced from this repository, and no harness publication date is promised. The single-machine local mesh (`scripts/local-mesh.sh`) is a counterpart, not a substitute.

## Current configuration evidence

Current node defaults, verified against `parseFlags` and `pprofBindAddr` in
`cmd/sovereign-node/main.go` and the listener tests in
`cmd/sovereign-node/pprof_endpoint_test.go`: the plain-HTTP metrics listener
binds to `127.0.0.1:7431`, and the dedicated profiling listener binds to
`127.0.0.1:8431`. The latter derives from the default metrics port plus 1000;
`--pprof-addr` can change the port but not the loopback host. These are current
configuration facts, not v0.1.0 measurements or new fleet receipts.

## Platform checks

The pre-publication platform check on 2026-11-21 tested native Linux arm64 and
emulated Linux amd64 builds and complete short-test invocations:

| Platform | Build | Short tests | Build duration | Test duration |
|:--|:--|:--|:--|:--|
| Native Linux arm64, Go 1.26.1 | PASS, exit 0 | FAIL, exit 1 | 20 s | 409 s |
| Emulated Linux amd64, Ubuntu 24.04.5, Go 1.26.1 | PASS, exit 0 | FAIL, exit 1 | 357 s | 677 s |

**Native arm64 failures:**
- `pkg/durability`: `TestCheckpointWalkPinnedAgainstState` → `panic: HamtArena: OOM - arena exhausted (variable alloc)`
- `sdk/sovereign`: `TestClientGetOnPeerReturnsDigestNotValue` → `did not converge in 20 rounds` (known SDK failure)

**Emulated amd64 failures:**
- Ten packages failed with `signal: segmentation fault (core dumped)`: `cmd/sovereign-node`, `internal/database`, `internal/index`, `internal/network`, `internal/transport`, `pkg/durability`, `pkg/mesh`, `pkg/receive`, `pkg/security/fuzz`, `sdk/sovereign`
- `pkg/attribution`: `TestEnvelope_HopBoundExceededZeroVerify` → `O(1) depth check took 12.754µs (must be sub-microsecond, zero Verify)`
- `pkg/metrics`: `TestIngestLatencyRecorded` → `the 1e-06 bucket has no early-rejection samples`

The emulated result does not establish behavior on native amd64 hardware or a root cause for the segmentation faults. Neither complete short-test invocation passed. These results do not support a claim of a green test suite on either platform.

Full receipt: [platform-checks-2026-11-21.txt](platform-checks-2026-11-21.txt).

## Reproduce locally

On Linux with Go 1.26.1, a C toolchain, and jemalloc installed:

```bash
./scripts/reproduce.sh
CRASH=1 ./scripts/local-mesh.sh
```

The first command runs local tests and benchmarks and saves a transcript. The
second starts a 3-node mesh on loopback addresses, checks convergence, kills the
origin, restarts it on the same WAL and LSM, and compares the roots again. These
are local counterparts, not recreations of the 100-process multi-region run.

A node-count option is available: `NODES=30 ./scripts/local-mesh.sh` runs the
same flags on one machine with 30 node processes. This is a single-machine
counterpart of the fleet run, never a substitute for it.

The outsider verification guide with prerequisites, exact commands, expected
output, duration, cost, and failure meaning is [docs/VERIFY.md](../VERIFY.md).

## How to read these

- **`core-crucible.txt`** measures `ShardedStack` push/pop attempts, including
  empty pops. It does not call `HAMT.Set`, verify signatures, decode envelopes,
  use the network or TLS, or persist to the WAL. Its ops/s are not ingest rates.
- **`ingest-ed25519.txt`** calls `Receiver.HandleBatchFrame` in parallel. The
  path verifies one Ed25519 signature per frame, decodes its envelope, and
  applies the deltas. Frames are built and signed before timing, and the timed
  loop reapplies the same deltas idempotently. Sockets, TLS, WAL persistence,
  and ingest metrics are outside the measurement, so this is not an end-to-end
  production write rate.
- **`convergence-100-node.txt`** records 100 node processes on three machines,
  one per region, reaching an identical Merkle root 8.950s after origin
  quiescence. WAL durability was on in every node log. The seven earlier runs —
  six passes between 6.6s and 8.7s and one miss at 10.150s — are tabulated in
  [ADR-0050](../architecture/adr/0050_checkpoint_decouple_delta.md).
- **`zero-alloc.txt`** measures heap allocations in `HAMT.Set`. It does not make
  a zero-allocation claim for signature verification, envelope decoding, CRDT
  application, networking, or persistence.
- **`convergence-1000-node.txt`** records 1,000 node processes on 30 machines
  across three regions (333/333/334 split), one writer injecting 10,000 keys
  into node 0, per-region t100 curves, and identical state fingerprints across
  all 1,000 nodes. The post-quiescence convergence times are timestamp
  differences, not sums of rounded components.
- **`convergence-1000-node-runs.tsv`** keeps all 28 columns exactly as in the
  source summary table, with plain column names. The six rows are
  attempt-034, attempt-035, attempt-036 (clean runs), attempt-038 (kill drill),
  attempt-037 (packet-drop drill), and attempt-039 (impostor-identity drill).
- **`convergence-1000-node-attempts.tsv`** has one row for every one of the 49
  full-scale attempts, with public aliases attempt-001 through attempt-049.
  Dates, process counts, key counts, verdicts, and timings are preserved exactly;
  `not recorded` is used for absent values.
- **`fault-drills-1000-node.txt`** defines each drill exactly as its fault log
  shows it: the kill/restart test targeted node 333 (eu-west-1) with a 15-second
  `kill -9` hold; the packet-drop test applied a 30-second iptables DROP on
  TCP port 7373 for node 333; the impostor-identity test isolated node 0 and
  sent a forged 133-byte SGWC challengeRoleResponse using node 333's
  certificate. The first impostor attempt (attempt-040) exited with RUN_RC=4
  and no gate verdict; the passing test ran on a replacement fleet.

## What is not claimed

The multi-region fleet harness is not published in this release. The convergence
and crash receipts document past runs; they are not self-contained reproduction
recipes. The local scripts do not reproduce their fleet layout or timing.

The convergence runs do not establish an upper bound on the tail. In one of the
seven earlier 100-node runs, the last one or two of 100 nodes were still
converging after the 10-second objective, with t100 at 10.150s. Equal final
roots establish convergence for those runs, not a latency guarantee for every
run.

The 1,000-process fault drills do not establish multi-writer behavior, every
possible fault or attack, production readiness, or independent reproduction.

Absolute throughput depends on the processor, core count, host load, and
toolchain. When repeating a local measurement, record those conditions and keep
the complete transcript, including failed steps. A discrepancy on the documented
setup is worth an issue with the exact command and output attached.

Neither native arm64 nor emulated amd64 complete short-test suites pass. The
platform receipt discloses every observed failure; do not describe either suite
as green.