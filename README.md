# Sovereign Engine

> **Source-available under the [Business Source License 1.1](LICENSE).** Owned by
> **Sovereign Systems**. Non-Production Use (evaluation, testing, benchmarking,
> internal research, development, educational and personal use) is permitted
> without restriction; Production Use requires a written grant from the Licensor
> until the **Change Date, 2029-08-15**, on which the license converts in
> perpetuity to an unencumbered one. This is *source-available*, not "open
> source" — read [CONTRIBUTING](.github/CONTRIBUTING.md) and the
> [ADR directory](docs/architecture/adr/) before contributing.

A planetary-scale, **zero-GC, off-heap δ-CRDT database engine** written in Go.
State is modeled as a **tri-temporal** CRDT keyed by
`(system_time × valid_time × assertion_time)` (with `decision_time` on the wire),
folded by a merge-union `Join` so concurrent writers converge without
coordination and without losing history. **H3 spatial indexing** is native to
the CRDT, and the transport is **post-quantum-secure from day one**
(Ed25519 production seam + an ML-DSA-65 preview envelope). The hot path
performs **zero heap allocations** — every node, leaf, and CRDT entry lives in
a `mmap`'d anonymous arena the Go garbage collector cannot see, cannot scan,
and cannot stop the world over.

There are no marketing adjectives below. There is a measured `go test` on a
named piece of silicon, the honest layer that number measures, and the gate
that has **not** passed yet.

---

## Status / Readiness

**Research preview — not production-ready.**

| Gate | Result | What it proves |
|:--|:--|:--|
| **GATE 0** — 100-node mTLS boot, 3 regions | **PASS** (0.62s) | The mesh forms across 100 nodes in 3 regions over real TLS 1.3 |
| **GATE 1** — 100-node convergence < 10s SLO | **NOT-MET (honest)** | The 10K-key delta is *shipped* but does not *land* on peers — a receive-side delta-apply failure (envelopes ship, deltas don't apply). Tracking notes: [ADR-0041](docs/architecture/adr/0041_100_node_silicon_convergence_track36.md) and [ADR-0044](docs/architecture/adr/0044_wal_group_commit_track39.md); the narrative arc is on the [developer portal](https://sovereignengine.space/docs/architecture/multi-region-mesh) |
| **GATE 3** — inter-region partition isolation | **PROVEN** (isolation); heal re-convergence not yet detected | Partition isolates the divergent roots; heal re-convergence is the open carry-forward |

**Not started (P2):** production PKI / HSM key custody, io_uring transport, the
gRPC API surface. The current API surface is a JSON-over-mTLS control port
(`/v1/insert|get|query|range|merkle`).

The honest headline: the CRDT core is silicon-proven and byte-locked; the
multi-region convergence SLO is an open engineering fork, not a shipped claim.
An Azure reviewer, a GitHub visitor, and a future contributor all see the same
unvarnished truth here.

---

## The measured numbers — two layers, never conflated

> **LAYER DISCIPLINE.** The CRDT **core** number is an in-process `HAMT.Set`
> producer-consumer crucible — **no Ed25519 verify, no envelope unmarshal, no
> network, no TLS, no persistence**. It measures the data-structure floor, not
> the production ingest path. The production ingest path (verified Ed25519 +
> CRDT apply, with envelope) is a **different, lower layer**. These are **not
> the same claim.** Quoting the core number as the engine's ingest rate is a
> layer mismatch — it omits the ~60µs Ed25519 verify the real node runs per
> batch. Read both; never conflate them.

| Layer | Number | What it measures | What it omits | Provenance |
|:--|:--|:--|:--|:--|
| **CRDT core** | **50.7M–57.6M ops/s** @32c ARM64 Graviton (gate-passing floor **50,736,038**; residency high **57,638,422**, *not* "sustained") | in-process `HAMT.Set` crucible | Ed25519, envelope, network, TLS, persistence | `TestStage5ScalingGate` (`RUN_CRUCIBLE=1`); **upstream pre-fork** silicon (cache-line post-mortem SHA `f719be4`); this-fork 32c re-run **PENDING** |
| **Production ingest** | **1.0M–3.1M deltas/sec** @64c, N=256 batching (1.39M–3.08M real single-origin) | Ed25519 verify + CRDT apply + envelope | TLS-on-the-wire, AF_XDP zero-copy | `BenchmarkBatchedVerifyParallel`, `phase-03/silicon_bench_20260730T020338Z.log` |
| **Hot-path allocations** | **0 allocs/op, 0 B/op** for `HAMT.Set` | the write path | — | `TestHotPathZeroAllocations` |
| **Cache-line discipline** | 128-byte stride, zero wasted padding | contended atomics | — | `fieldalignment` CI + `TestMemoryLayoutAnalysis` |
| **ML-DSA-65 (post-quantum preview)** | sig 3309 B, pub 1952 B (**51.7×** sig inflation vs Ed25519 64 B) | size economics | — | `filippo.io/mldsa`; `pq_preview` build-tagged, **preview-only**; hedged Ed25519 is the production seam |

The 32c core number was measured **upstream pre-fork** (the cache-line
post-mortem SHA `f719be4` is not in this fork's git history); this fork's 32c
re-run of `RUN_CRUCIBLE=1 go test -run TestStage5ScalingGate ./pkg/sync/` is
**PENDING**. The range across clean runs is 50.7M–57.6M at 32c on AWS Graviton
(c8g / Graviton4); thermal throttling explains the spread, and the 57.6M is a
residency high-end, **not** a "sustained" figure. We show the floor, the high,
and the ingest rate together so no single figure can be misread.

---

## Quickstart — the minimal 3-node loopback

The fastest way to see the engine work is the 3-node loopback mesh. This
mirrors the [portal quickstart](https://sovereignengine.space/docs/guides/quickstart).

### 1. Provision a dev mesh CA

Use `pkg/crypto`'s dev-mesh CA to mint a CA and per-node leaves (or supply your
own PKI and point `--tls-cert --tls-key --tls-ca` at it):

```go
ca, err := crypto.NewMeshCA()
caPath, err := ca.WriteCAPEM(".")             // writes ca.pem into the dir; returns its path
leaf, err := ca.IssueLeaf(nodeID)             // nodeID hex; localhost is added to DNSNames internally
certPath, keyPath, err := leaf.WritePEM(".")  // single dir arg; derives cert/key filenames, returns them
```

> This is a **dev** mesh CA, not production PKI — offline root, intermediate
> CAs, HSM-backed key custody, OCSP/CRL revocation, and automated rotation are
> named as post-launch work (ADR-0006).

### 2. Derive node identity

Pass `--identity-seed` (an Ed25519 seed); the `nodeID` is the first 16 bytes of
the derived pubkey and **must equal** `engine.localNodeID`.

### 3. Start a node

```bash
cmd/sovereign-node \
  --bind :443 \
  --peers peer1:443,peer2:443 \
  --tls-cert leaf.crt --tls-key leaf.key --tls-ca ca.crt \
  --metrics-addr :9100 \
  --control-addr :4433 \
  --arena-mib 4096 \
  --wal-path /var/lib/sovereign/wal \
  --lsm-root /var/lib/sovereign/lsm \
  --gossip-tick 1s \
  --batch-size 100
```

Defaults are conservative: pruning **OFF**, reaper **OFF**. Opt into durability
and compaction once you trust the `T_gc` floor (`--wal-checkpoint-interval N`,
`--compaction-prune-enable`, `--compaction-prune-horizon-ns <T_gc>`); the reaper
never auto-ONs (`--compaction-reap-enable`).

### 4. Write & read via the SDK

```go
client, _ := sovereign.DialWithCerts(":4433", "leaf.crt", "leaf.key", "ca.crt", "node-1")

// Originator path: routes through Gossiper.InsertLocalEvents → bridge.PutLocal (WAL fsync)
// InsertLocal returns (dotHex, error) — the causal dot is the write's receipt
dotHex, err := client.InsertLocal("entity-1", `{"v":42}`)

// Get — Payload only on the originator; peers return the digest, not a value
res, _ := client.Get("entity-1")
// res.PayloadDigest is always set; res.Payload is non-empty only on the originator

root, _ := client.MerkleRoot()
```

> **Honest boundary.** `GetResult.Payload` is non-empty only on the originator
> (cache hit); peers return `Payload==""` + `PayloadDigest!=""` because the
> engine stores only the `PayloadDigest` on a joined `CRDTEntry`
> (`TestClientGetOnPeerReturnsDigestNotValue`). The SDK does **not** claim
> linearizability — `InsertLocal` returns at local-apply; peer convergence is
> eventual (next gossip sweep).

### Reproduce the core benchmark

```bash
git clone https://github.com/hr18vk/sovereign.git
cd sovereign
./scripts/benchmark.sh --core-count=32
```

`benchmark.sh` provisions the exact Go 1.26.1 toolchain used for the recorded
numbers, builds the engine hermetically (CGO_ENABLED=1 for the jemalloc
substrate), runs `TestStage5ScalingGate`, and prints the throughput and the
Zero-GC witness (`BenchmarkHAMTInsertZeroAlloc` must show `0 B/op`). If the 32c
core range does not reproduce on equivalent silicon, the discrepancy is real
and the gate will say so.

---

## System prerequisites

The engine achieves Zero-GC by routing allocations off-heap into a `mmap`'d
arena and a `jemalloc`-backed database store (via CGO). Install the headers
before compiling from source:

**Ubuntu/Debian:** `sudo apt-get update && sudo apt-get install -y libjemalloc-dev capnproto`
**Fedora/RHEL:** `sudo dnf install jemalloc-devel capnproto`
**Arch Linux:** `sudo pacman -S jemalloc capnproto`
**macOS:** `brew install jemalloc capnp`

**Windows:** the engine relies on strict POSIX memory semantics (`mmap`,
`MADV_SEQUENTIAL`) and `jemalloc`; native Windows compilation is not supported.
Windows developers compile and run inside [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install)
using the Ubuntu instructions above.

Two build profiles ship:
- **Optimal-performance build** (`scripts/benchmark.sh`): `CGO_ENABLED=1`,
  binds `jemalloc` via CGO. The build the recorded core numbers were taken on.
- **Portable binary** (`scripts/install.sh`): `CGO_ENABLED=0`, no CGo, no
  jemalloc — a genuinely statically linked binary with zero runtime
  dependencies, but it falls back to the Go runtime allocator for the database
  layer and **cannot reproduce** the c8g Graviton4 core bench.

---

## Read the physics

- [SUPREMUM_STYLE.md](SUPREMUM_STYLE.md) — the laws of physics imposed on every
  pull request (zero-GC, 128-byte stride, lock freedom, absolute honesty about
  headroom). The constraint set under which the engine holds its core numbers.
- [docs/architecture/5_BENCHMARKS_AND_LIMITS.md](docs/architecture/5_BENCHMARKS_AND_LIMITS.md)
  — the silicon wall, per-core decomposition, and the honest headroom record.
- [docs/architecture/6_ENGINEERING_POST_MORTEM.md](docs/architecture/6_ENGINEERING_POST_MORTEM.md)
  — the full failure arc and the gates that caught every manufactured bug.
- [docs/internals/STRUCT_ALIGNMENT.md](docs/internals/STRUCT_ALIGNMENT.md) —
  the byte-level struct packing proof against MESI false sharing.
- [Multi-Region Mesh](https://sovereignengine.space/docs/architecture/multi-region-mesh)
  (developer portal) — the multi-region data-plane arc and the honest GATE-1
  status; the silicon verdicts are recorded in-engine in
  [ADR-0041](docs/architecture/adr/0041_100_node_silicon_convergence_track36.md)
  and [ADR-0044](docs/architecture/adr/0044_wal_group_commit_track39.md).

## Architecture & decisions

- [docs/architecture/adr/](docs/architecture/adr/) — the decision log. Every
  load-bearing change is recorded as an ADR with a root cause, a change, and a
  gate result. Read the relevant ADR before touching the subsystem it governs.
- [Developer portal](https://sovereignengine.space) — the public mirror of this
  repo: the same numbers, the same honest NOT-MET, the same deleted-primitive
  refutations. The portal is the repo's public documentation, not a marketing
  layer.

## Contributing

Read [SUPREMUM_STYLE.md](SUPREMUM_STYLE.md) and
[.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) before opening a pull
request. PRs that allocate on the hot path, introduce wasted struct padding, or
escape an interface to the heap are rejected by CI without human review — and
that is the point: a gate that cannot be talked out of failing is the only
architect that survives contact with silicon.

## License

[Business Source License 1.1](LICENSE) — Licensor **Sovereign Systems**, Change
Date **2029-08-15**. Non-Production Use is permitted without restriction;
Production Use requires a written grant from the Licensor until the Change Date.
