# Verification guide

This guide lets anyone check the claims in this repository on their own machine. Every quoted output line comes from a real run with a durable receipt in `docs/evidence/`. Receipt links use the release tag (`/blob/v0.2.0/...`), not `main`.

## Prerequisites

- Linux (macOS and Windows: use a Linux VM, container, or the Codespace)
- Go 1.26.1
- A C toolchain (`gcc`)
- `libjemalloc-dev` and `curl` (`sudo apt-get install -y libjemalloc-dev curl` on Debian/Ubuntu)
- At least 8 cores for the scaling gate; fewer cores will fail the throughput assertion
- For the 32-core reproduction: a `c8g.8xlarge` (Graviton4, 32 vCPU) in `us-east-1`, about $1.30/hour on-demand

Before running `scripts/reproduce.sh` on EC2, the script queries the instance metadata service at `169.254.169.254` (IMDSv2) to record the instance type and region. This request is made silently and is skipped outside EC2.

---

## Level 1: Five minutes — build and core gates (any Linux machine or Codespace)

### Clone and build

```bash
git clone https://github.com/hr18vk/sovereign
cd sovereign
git checkout v0.2.0
go build ./...
```

Expected: clean build, exit 0.

### Zero-allocation gate (core write path)

```bash
go test -run TestHotPathZeroAllocations -count=1 ./pkg/sync/
go test -run '^$' -bench=BenchmarkHAMTInsertZeroAlloc -benchmem -count=1 ./pkg/sync/
```

Expected (from `docs/evidence/zero-alloc.txt`):

```
PASS
ok      github.com/hr18vk/sovereign/pkg/sync

goos: linux
goarch: arm64
BenchmarkHAMTInsertZeroAlloc-4   	  166969	      9650 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMTInsertZeroAlloc-4   	  163645	      9555 ns/op	       0 B/op	       0 allocs/op
BenchmarkHAMTInsertZeroAlloc-4   	  164134	      9790 ns/op	       0 B/op	       0 allocs/op
```

The zero-allocation claim applies to `HAMT.Set` on the core write path. It does not cover signature verification, envelope decoding, CRDT application, networking, or persistence.

### Struct layout and false-sharing checks

```bash
go test -run 'TestHamtNodeOffsets|TestCRDTEntry_SizeAndAlignment|TestHamtLeaf_SizeAndAlignment' -count=1 -v ./pkg/sync/
go test -run '^$' -bench='BenchmarkFalseSharing' -benchmem -count=1 ./pkg/sync/
```

Expected: all struct-layout tests pass; the false-sharing benchmark runs and prints padded vs. unpadded counter throughput.

### CRDT algebra laws (property-based)

```bash
go test -run 'TestCRDTJoin|TestCRDTConvergenceMultiNode|TestCRDTMonotonicGrowth' -count=1 -v ./pkg/sync/
```

Expected: commutative, associative, idempotent join; multi-node convergence; monotonic growth — all pass.

### Post-quantum key exchange negotiation

```bash
go test -run 'TestPQ_' -count=1 -v ./pkg/transport/
```

Expected: `X25519MLKEM768` negotiates successfully; the test fails if the peer does not offer it.

---

## Level 2: Ten minutes — three-node mesh and crash recovery (one machine)

### Basic mesh

```bash
./scripts/local-mesh.sh
```

This starts 3 `sovereign-node` processes on loopback addresses `127.0.0.1`, `127.0.0.2`, `127.0.0.3` (three regions), injects 1,000 keys into node 0, and waits for all 3 Merkle roots to agree. The gate's verdict is the script's exit status: 0 on PASS.

A recorded example from the default run ends the convergence check with:

```
GATE 1 VERDICT: PASS
convergence-gate: DONE
```

The mesh uses the same public tooling as the fleet: `cmd/mesh-bootstrap` (CA, identities, peer directory), `cmd/sovereign-node`, and `cmd/convergence-gate`. Durability is on (WAL + LSM per node).

### Crash recovery

```bash
CRASH=1 ./scripts/local-mesh.sh
```

After the gate passes, the script sends `kill -9` to node 0, restarts it on the same WAL and LSM directory, waits for `/livecheck`, and then re-runs the gate in `--merkle-only` mode to compare one root per region.

A recorded example from the same run follows. Process IDs, timestamps, and output paths are redacted; restart timings vary.

```
== crash test: kill -9 node 0, then restart it on the same WAL and LSM
   node 0 is dead: /livecheck on 127.0.0.1:9100 gets no answer
   node 0  us-east-1  127.0.0.1:7373  pid [pid]  (WAL [output directory]/node-0/wal)
   node 0 answering again after 114 ms
   [timestamp] sovereign-node: durability enabled; recovered WAL [output directory]/node-0/wal from snapshot ckpt/1001 (replayed 0 post-checkpoint record(s), bridge active)
== roots after recovery (one per region; all 3 must match)
convergence-gate: loaded 3 nodes (control port base 8443, split 1,1,1)
  [us-east-1 node 0] /v1/merkle root = 255eb83e817ca62035444c12eaa5388576ab70570ce16b07a612e656f1919bfe
  [eu-west-1 node 1] /v1/merkle root = 255eb83e817ca62035444c12eaa5388576ab70570ce16b07a612e656f1919bfe
  [ap-southeast-2 node 2] /v1/merkle root = 255eb83e817ca62035444c12eaa5388576ab70570ce16b07a612e656f1919bfe
```

This reproduces the crash-recovery receipt in `docs/evidence/crash-recovery.txt` on a single machine. It is a local counterpart, not a recreation of the 1,000-process multi-region run.

### Optional: 30-node counterpart

```bash
NODES=30 ./scripts/local-mesh.sh
# or with crash recovery:
NODES=30 CRASH=1 ./scripts/local-mesh.sh
```

`NODES` accepts 3 through 100. Nodes are divided across the three regions as evenly as possible (for example, 30 → 10/10/10). Each node maps a 256 MiB arena: `NODES=30` maps several GiB before Go runtimes, WALs, and LSM data. Check memory, file descriptors, and disk. This is a single-machine counterpart of the fleet run, never a substitute for it.

---

## Level 3: Thirty minutes — 32-core reproduction on `c8g.8xlarge`

### Estimated cost and duration

| Item | Initial estimate |
|------|-------------------------------------|
| Instance | `c8g.8xlarge` (Graviton4, 32 vCPU), `us-east-1` |
| On-demand price | ~$1.30/hour |
| Expected wall time | ~30 minutes (build + selected checks and benchmarks) |
| Estimated cost | <$1.00 |

These are estimates; the published reproduction transcript records the measured values.

### Run

```bash
# On a fresh c8g.8xlarge with Ubuntu 24.04 arm64:
sudo apt-get update && sudo apt-get install -y golang-go gcc libjemalloc-dev git
# Or install Go 1.26.1 from go.dev if the distro version differs
git clone https://github.com/hr18vk/sovereign
cd sovereign
git checkout v0.2.0
./scripts/reproduce.sh
```

The script records a provenance header (UTC, kernel, arch, Go version, jemalloc, commit, EC2 instance type via IMDSv2 at `169.254.169.254`), then runs:

1. Zero-allocation gate + benchmark
2. Struct layout (CRDTEntry, hamtLeaf, HamtNode diagnostics)
3. False-sharing benchmark
4. CRDT algebra (commutative, associative, idempotent; property-based)
5. Post-quantum key exchange (X25519MLKEM768)
6. Ingest benchmark: one Ed25519 verify per frame, then envelope + merge per delta (`pkg/receive`, tens of seconds; skip with `SKIP_INGEST=1`)
7. Core scaling gate (`RUN_CRUCIBLE=1`, runs on 8+ cores, asserts 50M ops/s at top tier; skip with `SKIP_GATE=1`)

Every step prints its command and exit status. The script's own exit status is 0 only if every step passed. A transcript `reproduce-<UTC>-<sha>.txt` is saved in the repo root and printed to screen.

### Compare with the published transcript

The receipt `docs/evidence/reproduce-c8g-8xlarge-2026-09-22.txt` was recorded on a `c8g.8xlarge` at v0.1.0. The v0.2.0 transcript will differ in commit hash and absolute benchmark numbers (fewer cores give lower absolute throughput). The zero-allocation, struct-layout, PQ, and CRDT-law gates hold on any Linux box; the scaling gate needs eight or more cores and asserts 50M ops/s at its top tier, so a smaller machine can fail it on throughput alone.

---

## Level 4: The 1,000-node result — what was run, what is published, what is not reproducible

### What the fleet runs did

- 1,000 `sovereign-node` processes on 30 `c7gd.8xlarge` machines (10 per region) in `us-east-1`, `eu-west-1`, `ap-southeast-2`, split 333/333/334.
- One writer injected 10,000 keys into node 0 in ten chunks of ≤1,000 keys (`inject_parallel=1`). This was not a multi-writer test.
- mTLS mesh, per-node WAL + LSM, 256 MiB arenas, digest wait 1,500 ms.
- Three consecutive clean runs converged after origin quiescence in **2.906 s, 4.038 s, 3.823 s**. All 1,000 nodes had the same Merkle root and the same state fingerprint within each run.
- Three fault drills passed:
  - **Kill/restart** (node 333, eu-west-1, 15 s `kill -9` hold): converged in 15.716 s post-quiescence.
  - **Packet drop** (node 333, eu-west-1, TCP port 7373; 30 s iptables DROP): converged in 8.671 s post-quiescence.
  - **Impostor-identity** (node 0 isolated, forged SGWC `challengeRoleResponse` using node 333's certificate): node 0 rejected the forged response (`signature verify FAILED`); after isolation removed, converged in 6.221 s post-quiescence. The first impostor attempt (attempt-040) exited with `RUN_RC=4` and no gate verdict; the passing test ran on a replacement fleet.

Full receipts:
- `docs/evidence/convergence-1000-node.txt` — fleet layout, clock definitions, non-default configuration, per-run timestamps, post-quiescence convergence times, verbatim gate output.
- `docs/evidence/convergence-1000-node-runs.tsv` — six-row measurement table (28 columns).
- `docs/evidence/convergence-1000-node-attempts.tsv` — all 49 full-scale attempts (attempt-001 through attempt-049), including earlier target misses, aborted runs, the free-list SIGBUS/corruption run, and attempt-040's `RUN_RC=4`.
- `docs/evidence/fault-drills-1000-node.txt` — exact drill definitions, results, and limitations.

### Published raw evidence (verified)

The `docs/evidence/raw/` directory contains **27 verified files**:

| Run | Per-node table | Archive manifest | Gate log | Hook log | Console extract |
|-----|----------------|------------------|----------|----------|-----------------|
| Clean run 1 | `clean-run-1.fingerprints.tsv` | `clean-run-1.manifest.sha256` | `clean-run-1.gate.log` | — | `clean-run-1.console.txt` |
| Clean run 2 | `clean-run-2.fingerprints.tsv` | `clean-run-2.manifest.sha256` | `clean-run-2.gate.log` | — | `clean-run-2.console.txt` |
| Clean run 3 | `clean-run-3.fingerprints.tsv` | `clean-run-3.manifest.sha256` | `clean-run-3.gate.log` | — | `clean-run-3.console.txt` |
| Packet-drop drill | `packet-drop-drill.fingerprints.tsv` | `packet-drop-drill.manifest.sha256` | `packet-drop-drill.gate.log` | `packet-drop-drill.during-gate-hook.log` | `packet-drop-drill.console.txt` |
| Kill drill | `kill-drill.fingerprints.tsv` | `kill-drill.manifest.sha256` | `kill-drill.gate.log` | `kill-drill.during-gate-hook.log` | `kill-drill.console.txt` |
| Impostor-identity drill | `impostor-identity-drill.fingerprints.tsv` | `impostor-identity-drill.manifest.sha256` | `impostor-identity-drill.gate.log` | `impostor-identity-drill.pre-gate-hook.log` | `impostor-identity-drill.console.txt` |

**Per-node tables**: 1,000 data rows each; columns `global_idx`, `region`, `box_id`, `ip` (redacted as `[address]`), `port`, `keys`, `state_fp`, `xor_root`. `xor_root` is a separate per-node harvest value, not the Merkle root. The common Merkle roots appear in the gate logs and console extracts.

**Archive manifests**: 30 per-machine archive entries + 1 self-entry each, preserving original SHA-256 digests and entry order.

**Gate and hook logs**: 9 files, published verbatim with only approved redactions (addresses, instance identifiers, private filesystem tokens, blocked source-run labels replaced by bracketed placeholders or public aliases).

**Console extracts**: 6 files, selected verbatim lines sufficient to check injection, quiescence, convergence, per-region t100, fingerprints, verdict, drill hooks, and harvest. They are selections, not complete consoles.

See `docs/evidence/raw/README.md` for the full index, column meanings, redaction conventions, and console-extract limits.

### What is not available

**The original 180 per-machine `.tgz` archives for the six final runs were not preserved after 6 November 2026 and cannot be restored.** Their per-node log members are unavailable, and no archive digest can be rechecked against live tarballs. The manifests preserve the recorded archive names and SHA-256 digests; they do not establish current archive availability, and the manifest entries are not links to downloadable archives.

**The fleet harness is not published.** The 1,000-process, 30-machine run cannot be reproduced from this repository, and no harness publication date is promised. The single-machine local mesh (`scripts/local-mesh.sh`) is a counterpart, not a substitute.

**These runs do not establish** multi-writer behavior, every possible fault or attack, production readiness, or independent reproduction. Earlier attempts missed the target and are included in the complete history rather than omitted.

---

## Level 5: Platform status — native arm64 and emulated amd64

The pre-publication platform check on 2026-11-21 tested native Linux arm64 and emulated Linux amd64 builds and complete short-test invocations on a pre-publication candidate snapshot (not a build from the future v0.2.0 tag). No native-amd64 hardware was tested.

| Platform | Build | Short tests | Build duration | Test duration |
|----------|-------|-------------|----------------|---------------|
| Native Linux arm64, Go 1.26.1 | PASS, exit 0 | FAIL, exit 1 | 20 s | 409 s |
| Emulated Linux amd64, Ubuntu 24.04.5, Go 1.26.1 | PASS, exit 0 | FAIL, exit 1 | 357 s | 677 s |

**Native arm64 failures:**
- `pkg/durability`: `TestCheckpointWalkPinnedAgainstState` → `panic: HamtArena: OOM - arena exhausted (variable alloc)`
- `sdk/sovereign`: `TestClientGetOnPeerReturnsDigestNotValue` → `did not converge in 20 rounds` (known SDK failure)

**Emulated amd64 failures:**
- Ten packages failed with `signal: segmentation fault (core dumped)`: `cmd/sovereign-node`, `internal/database`, `internal/index`, `internal/network`, `internal/transport`, `pkg/durability`, `pkg/mesh`, `pkg/receive`, `pkg/security/fuzz`, `sdk/sovereign`
- `pkg/attribution`: `TestEnvelope_HopBoundExceededZeroVerify` → `O(1) depth check took 12.754µs (must be sub-microsecond, zero Verify)`
- `pkg/metrics`: `TestIngestLatencyRecorded` → `the 1e-06 bucket has no early-rejection samples`

The emulated result does not establish behavior on native amd64 hardware or a root cause for the segmentation faults. The two timing-sensitive assertion failures are likewise not native-amd64 results. **Neither complete short-test invocation passed. These results do not support a claim of a green test suite on either platform.**

Full receipt: `docs/evidence/platform-checks-2026-11-21.txt`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `go build` fails: `jemalloc` not found | Missing `libjemalloc-dev` | `sudo apt-get install -y libjemalloc-dev` |
| Scaling gate fails throughput assertion | Fewer than 8 cores | Use `CPUS=32` (or your core count) or run on an 8+ core machine |
| `local-mesh.sh` runs out of memory / file descriptors | `NODES` too high for the machine | Reduce `NODES`; each node maps 256 MiB arena plus runtime overhead |
| `local-mesh.sh` nodes don't answer `/livecheck` | Port conflict or firewall | Ensure loopback 127/8 is free; Linux routes it to `lo` by default |
| `reproduce.sh` ingest benchmark times out | Low CPU or high load | `SKIP_INGEST=1 ./scripts/reproduce.sh` |
| `reproduce.sh` scaling gate fails | <8 cores or saturated machine | `SKIP_GATE=1 ./scripts/reproduce.sh` or run on appropriate hardware |
| EC2 metadata query hangs | Not on EC2 or IMDSv2 blocked | The script times out after 1 s and continues silently |

---

## Report what you saw

If a step behaves differently from the receipts, open a **Reproduction report** issue:

- Machine (cloud provider, instance type, core count, memory)
- Commit (`git rev-parse HEAD`)
- Complete transcript (the `reproduce-*.txt` or `local-mesh` output)
- Which step failed and how
- Any local modifications

Use the issue template: `.github/ISSUE_TEMPLATE/reproduction_report.yml`.

---

## Links to receipts (all at `/blob/v0.2.0/`)

- `docs/evidence/zero-alloc.txt`
- `docs/evidence/core-crucible.txt`
- `docs/evidence/convergence-100-node.txt`
- `docs/evidence/ingest-ed25519.txt`
- `docs/evidence/crash-recovery.txt`
- `docs/evidence/reproduce-c8g-8xlarge-2026-09-22.txt`
- `docs/evidence/convergence-1000-node.txt`
- `docs/evidence/convergence-1000-node-runs.tsv`
- `docs/evidence/convergence-1000-node-attempts.tsv`
- `docs/evidence/fault-drills-1000-node.txt`
- `docs/evidence/platform-checks-2026-11-21.txt`
- `docs/evidence/raw/README.md`
- `docs/evidence/README.md`