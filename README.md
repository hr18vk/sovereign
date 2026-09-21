<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo-light.svg">
    <img alt="Sovereign Engine" width="130" src="docs/assets/logo-light.svg">
  </picture>

  <h1>Sovereign Engine</h1>

  <p><strong>A fast, globally-consistent, quantum-resistant database engine.<br/>
  Every number below is measured on real hardware. None of it is marketing.</strong></p>

  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL--1.1-blue.svg" alt="License: BSL 1.1"></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Language-Go-00ADD8.svg" alt="Language: Go"></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Toolchain-Go%201.26.1-00ADD8.svg" alt="Go 1.26.1"></a>
    <a href="https://github.com/hr18vk/sovereign/actions/workflows/gatekeeper.yml"><img src="https://github.com/hr18vk/sovereign/actions/workflows/gatekeeper.yml/badge.svg" alt="CI: gatekeeper"></a>
    <a href="https://github.com/codespaces/new?hide_repo_select=true&amp;ref=main&amp;repo=hr18vk%2Fsovereign"><img src="https://img.shields.io/badge/Open%20in-Codespaces-24292f?logo=github" alt="Open in GitHub Codespaces"></a>
  </p>
</div>

---

## What is this, in plain terms?

Sovereign Engine is a new kind of database — the software that sits under almost every app and stores its data.

Right now, databases make you pick. You can have one that's **fast**, or one that stays **correct when a hundred machines write to it at once across the world**, or one that's **safe against the quantum computers people are building**. Getting all three at once is supposed to be nearly impossible, so big companies spend millions of dollars a year duct-taping it together.

This engine does all three at once:

- **Fast** — millions of verified operations a second on one server.
- **Globally consistent** — writes from many places converge to the same answer on their own. No leader, no lost updates. (Checked on a 100-node fleet across 3 cloud regions.)
- **Quantum-resistant** — encrypted against the machines expected to break today's encryption.

And I'm not asking you to take my word for it. Every number here is a real measurement — the exact command, the machine, and the raw output are in the repo so you can check my work. That matters more to me than sounding impressive.

> **Status: research preview.** This is not production-ready software — it's a working, measured research engine I'm sharing early so the design and the numbers can be checked. See [Where it stands](#where-it-stands) for the honest boundary.

## Why I built this

It bothered me that "pick two out of three" was treated as normal for something as basic as a database. So I built one that doesn't make you choose — and I wrote the failures up honestly in the [post-mortem](docs/architecture/6_ENGINEERING_POST_MORTEM.md), because the dead ends are where the real engineering is. The result holds up on a 100-node fleet, and the numbers reproduce.

## Why it's different

Most engines make you choose. This one is built on four things nobody else combines:

| | |
|:--|:--|
| **Tri-temporal CRDT state** | Every fact carries `system × valid × assertion` time, so you can ask "what did we know, and when." Concurrent writers converge without a leader or coordination. No other engine does this. |
| **H3 spatial, built in** | Geospatial indexing lives inside the CRDT, not bolted on top. |
| **Post-quantum from day one** | X25519MLKEM768 key exchange + hybrid Ed25519 + ML-DSA-65 signatures, on by default. |
| **Zero-GC** | The write path does **0 allocations per op** — state lives in an off-heap arena the Go garbage collector never touches. |

<p align="center"><img src="docs/assets/architecture.svg" width="780" alt="Sovereign Engine architecture — write path and convergence"></p>

---

## The measured numbers

> **Two layers, never mixed up.** The CRDT **core** number is an in-process data-structure test — no crypto, no network, no TLS, no disk. The **production ingest** number is the real receive path (signature verify + apply + envelope). They're different things, so I show both — that way no number gets misread.

| Layer | Number | Where it's from |
|:--|:--|:--|
| **CRDT core** | gate floor **50,736,038 ops/s**; this tree re-measured **68,278,197 ops/s** on 32 cores | `TestScalingGate` · c8g.8xlarge (Graviton4) · Go 1.26.1 |
| **Production ingest** | **5.7M–6.0M deltas/sec** on 32 cores (N=100–256; ceiling 12.5M–14.7M) | `BenchmarkBatchedVerifyParallel` · measured 2026-09-15 |
| **Hot-path allocations** | **0 allocs/op, 0 B/op** | `TestHotPathZeroAllocations` |
| **Convergence** | 100 nodes / 3 regions agree in **6.6–10.2s** | real silicon, integrity checks on |

Every one of these is reproducible — the exact command, the machine, and the unedited output are in [docs/evidence/](docs/evidence/). **That's my substitute for an outside audit: you don't have to trust the numbers, you can re-run them.**

### How it compares

Numbers only mean anything at the same layer, so read the **Workload** and **Hardware** columns before the **Throughput** one. And note what only one row is paying for: a post-quantum signature verified on every single operation.

| System | Workload | Hardware | Throughput |
|:--|:--|:--|:--|
| **Sovereign — production ingest** | PQ-verified write path | Graviton4, 32 cores | **5.7M–6.0M deltas/s** |
| **Sovereign — CRDT core** | in-process data structure (no network/crypto/disk) | Graviton4, 32 cores | **50.7M–68.3M ops/s** |
| Dragonfly | in-memory, write / read | 48 cores | 4.2–5.2M write · 4–15.5M read |
| Redis | in-memory SET | single core | ~72K (1.8M pipelined) |
| FoundationDB | 90/10 transactional | 24-machine cluster | 8.2M ops/s |
| TigerBeetle | transfers (batched, durable) | single core, replicated | ~100K–450K/s |
| ScyllaDB | durable write | per node, RF=3 | ~75K ops/s |
| CockroachDB | TPC-C | multi-node, 3× replicated | 128,000+ tpmC |
| PostgreSQL | durable writes (pgbench) | single node | ~5K–12K TPS |

The bottom rows pay for durability and replication on every operation — a cost Sovereign's ingest number does **not** yet carry, because this is a research preview, not a production database. The full methodology and the source for every figure: **[Full benchmark comparison →](https://sovereignengine.space/docs/benchmarks/competitive-comparison)**

---

## Try it

It builds and runs on any Linux box (and the Codespace installs the one dependency for you):

```bash
git clone https://github.com/hr18vk/sovereign.git
cd sovereign
sudo apt-get install -y libjemalloc-dev    # the one dependency
go build ./...                             # builds the engine
go test ./pkg/sync/ -run TestHotPathZeroAllocations   # the zero-GC gate
```

Or open a ready-to-run [GitHub Codespace](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=hr18vk%2Fsovereign) — the dependencies are pre-installed there.

The full 3-node mesh walkthrough (dev CA, node identity, the SDK) is in [docs/sdk-quickstart.md](docs/sdk-quickstart.md). The 32-core benchmark (`scripts/benchmark.sh`) self-skips on smaller machines — on a laptop it still builds and runs, it just won't reproduce the headline number (that needs the named ARM64 box, which is the honest truth of it).

---

## Where it stands

**Research preview — not production-ready.** The hard part (the core) is done and verified on real hardware, but this is a research preview, not a production database: don't trust it with data you can't afford to lose yet. What's left is hardening and the developer-facing surface. By my own count the v1.0 feature set is roughly **57% landed**.

| Capability | Status |
|:--|:--|
| Mesh — 100 nodes, 3 regions, mTLS | ✅ Verified |
| Convergence — 10K keys across the fleet | ✅ Met (6.6–10.2s) |
| Crash recovery | ✅ Proven (root re-equals after a kill) |
| Durability — WAL fsync per batch | ✅ Held on every run |
| Convergence tail (last 1–2 of 100 nodes) | 🟡 Still hardening (~1 run in 7 straggle) |
| Production PKI / HSM · io_uring · gRPC API | ⬜ Planned |

The honest boundary, and the evidence tier behind each row, is on the [verification page](https://sovereignengine.space/docs/architecture/verification).

---

## Read more

- [SUPREMUM_STYLE.md](SUPREMUM_STYLE.md) — the engineering laws every change has to obey.
- [docs/architecture/](docs/architecture/) — architecture, benchmarks, and the honest post-mortem.
- [docs/architecture/adr/](docs/architecture/adr/) — the decision log (50+ ADRs: root cause → change → measured result).
- [docs/evidence/](docs/evidence/) — the raw silicon receipts behind every number.
- [Developer portal](https://sovereignengine.space) — the same docs, rendered.

> **A note on the name.** The engine's original codename was *supremum* — the mathematical least-upper-bound, which is literally what a CRDT merge computes. The product, this repo, and the Go module path (`github.com/hr18vk/sovereign`) are **Sovereign Engine**; the codename survives only in a few internal identifiers (the `supremum_*` metric series, the `SUPREMUM_*` environment knobs, and `SUPREMUM_STYLE.md`).

## About the author

Sovereign Engine is designed and built by Harsh Rawat. I use AI coding tools as part of my engineering process, the way many working engineers now do — but the architecture and every design decision are mine, and every number in this repo is one I ran and read myself. The engine is the point; the process is just how I work.

## License

Source-available under the [Business Source License 1.1](LICENSE) — Licensor **Harsh Rawat** ("Sovereign Engine" is the project name, not a company). Non-Production Use is free; Production Use needs a written grant until the **Change Date 2029-08-15**, when it converts in perpetuity to an unencumbered license.
