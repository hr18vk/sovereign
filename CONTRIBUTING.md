# Contributing to Sovereign Engine

Thanks for your interest. This engine is built to a specific, uncompromising set of
engineering laws, and contributions are held to that bar. Read this before opening a PR.

## Build & test

Requires **Go 1.26.1**, **Linux/ARM64** (the target is AWS Graviton), and **jemalloc**
(the off-heap store binds it via CGO):

```bash
sudo apt-get install -y libjemalloc-dev
go build ./...
go test ./...
```

`scripts/benchmark.sh` runs the gated throughput crucible; it self-skips the absolute
assertion below 32 cores (it still builds and runs — it just won't reproduce the
headline number off the named silicon).

## The non-negotiables (see `SUPREMUM_STYLE.md`)

These are physical constraints of the design, not preferences. A PR that violates one
is rejected on that ground alone:

- **0 allocs/op on the write hot path.** Verified by the zero-alloc gate. Every
  allocation on the hot path is a future GC pause at 50M+ ops/s.
- **128-byte stride on contended atomics.** Two atomics sharing a cache line is a
  HITM storm. Struct-layout tests enforce this.
- **No `sync.Mutex` on the write path.** CAS + EBR only.
- **WAL replay restores the recorded dot — it never re-mints.** Re-minting on replay
  is data corruption.
- **Numbers carry layer + range + provenance.** A throughput claim without its layer
  (core microbench vs. production ingest vs. convergence), its range, and the machine
  it was measured on is a bug. See `docs/evidence/`.

## What "done" means

- `go build ./...`, `go vet ./...`, `gofmt -l .` (empty), and `go test ./...` all clean.
- If you touch the hot path, show the benchmark delta (and that allocs stayed at 0).
- If you change an externally-visible number, update the matching file in
  `docs/evidence/` with the command and the machine.

## Honest negatives are welcome here

If something is slower, wrong, or unproven, say so in the PR — the project would
rather ship a documented limitation than a quiet one. The ADRs under
`docs/architecture/adr/` (including the rejections) show the expected candor.

## License

Sovereign Engine is source-available under the **Business Source License 1.1** (see
`LICENSE`). By contributing you agree your contributions are provided under the same
terms. Production use requires a grant from the Licensor until the Change Date
(2029-08-15), after which it converts to an unencumbered license.

## A note on scope

This is a solo-maintained project. Review bandwidth is real but finite — small,
focused, well-tested PRs with a clear rationale get the fastest response. Large
refactors should be proposed in an issue first.
