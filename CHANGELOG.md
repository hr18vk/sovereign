# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the version scheme, with the exception that the licence Change Date is
expressed in years from publication rather than a fixed calendar date.

## [v0.2.0] - 2026-11-21

### Added

- **1,000-process convergence evidence**: three clean runs on 30 machines across three AWS regions (us-east-1, eu-west-1, ap-southeast-2) with a 333/333/334 process split, reaching identical Merkle roots and identical state fingerprints 2.906 s, 4.038 s, and 3.823 s after the origin node went quiet; three fault tests (single-process kill and restart, 30 s packet drop on the mesh port, impostor-identity test with forged node credentials) all converged
- **Complete 49-run history** (`docs/evidence/convergence-1000-node-attempts.tsv`): every full-scale 1,000-process attempt from the private records, including earlier runs that missed the 10 s target, the free-list ABA exposure run, and the first impostor test that exited with RUN_RC=4 and was repeated on a replacement fleet
- **Six-run measurement table** (`docs/evidence/convergence-1000-node-runs.tsv`): the three clean runs and three fault tests with 28 plain-named columns retaining exact source values
- **Per-process final-state tables and archive manifests** for all six runs: 1,000 rows per run with `state_fp` and `xor_root` values, 30 archive entries plus one self-entry per manifest
- **Complete gate and hook logs** for all six runs (9 files): redacted but otherwise verbatim, with disclosed address/instance-ID substitution classes
- **Selected console extracts** for all six runs (6 files): verbatim lines sufficient to check injection, quiescence, convergence, per-region t100, fingerprints, verdict, fault hooks, and harvest
- **Platform check receipt** (`docs/evidence/platform-checks-2026-11-21.txt`): native Linux arm64 build passes in 20 s, short tests fail in 409 s (2 packages); emulated Linux amd64 build passes in 357 s, short tests fail in 677 s (10 segmentation faults, 2 assertion failures); neither suite is green
- **`NODES` option for `scripts/local-mesh.sh`**: runs the same flags on a single machine with the specified process count (e.g., `NODES=30`); documented as a single-machine counterpart, never a substitute for the fleet run
- **Outsider verification guide** (`docs/VERIFY.md`): five-minute Linux/Codespace build plus zero-allocation, struct-layout, CRDT-law, and post-quantum negotiation tests; ten-minute three-process mesh and `CRASH=1` recovery; optional `NODES=30` counterpart; thirty-minute c8g.8xlarge reproduction with disclosed `sudo apt-get` and EC2 metadata request; troubleshooting; reproduction-report issue template
- **GitHub issue templates**: `reproduction_report.yml`, `bug_report.yml`, and `config.yml` (disables blank issues, directs security reports to private vulnerability reporting)
- **Evidence index** (`docs/evidence/README.md` and `docs/evidence/raw/README.md`): indexes all new evidence, states that the 180 original per-machine `.tgz` archives were not preserved after 6 November 2026 and cannot be restored; their manifests preserve recorded names and digests, not current availability

### Changed

- **Command renames**: `convergence-gate` and `mesh-bootstrap` restore the v0.1.0 public names; `fleet-gate` is new in v0.2.0
- **ADR file renames**: ADR files stripped of development suffixes; v0.1.0 public basenames preserved where they existed
- **Test file renames**: test files stripped of process markers; v0.1.0 public names reused where they existed
- **Test function renames**: test functions stripped of internal markers; v0.1.0 public names reused where they existed
- **Identifier renames**: internal identifiers (variables, helpers, constants) renamed to public names
- **Style guide rename**: the style guide file renamed to `STYLE.md` (codename removed from path)
- **Licence header**: updated to BSL 1.1 with "Four years from the date the Licensed Work is published" Change Date (HashiCorp wording); v0.1.0 Change Date 2029-08-15 unchanged
- **README corrections**:
  - "H3 spatial CRDT — native geospatial indexing" → H3 and system-time secondary index, opt-in (`--secondary-index`), coordinate-to-H3 conversion not wired into write path
  - "Post-quantum from day one — ML-DSA-65 signatures" → hybrid Ed25519+ML-DSA-65 signatures opt-in (`--hybrid-sign`, `--hybrid-verify`), default wire format byte-identical
  - the previous hyperbolic description was replaced with "1,000 node processes on 30 machines across three AWS regions"
  - v0.1.0 release notes overstated the convergence range; the v0.1.0 README contains a one-row measurement and a summary linking to the seven-run table in ADR-0050, which shows six passes between 6.6 s and 8.7 s and one miss at 10.150 s
  - "never loses a write when a hundred machines are writing" → was 100 processes on three machines
  - "The hard part is done and verified" → research preview, not production-ready
  - "Production ingest" → in-process upper bound, not full durability/replication cost
  - "All of the above, on your own machine" → 1,000-process fleet run cannot be reproduced from this repository
  - "Every number, re-run on a fresh machine" → 100-process run was not re-run
  - Supported platforms: tested on Linux arm64 (AWS Graviton); x86-64 builds but is not tested in CI
- **SECURITY.md additions**: operational exposure (metrics/pprof endpoints, loopback defaults), all production fault-injection environment variables with effects, frame-signing nonce construction (randomized-nonce Ed25519 via `crypto/rand`, not hedged), allocator issue disclosure
- **CONTRIBUTING.md**: updated for v0.2.0, licence paragraph includes both Change Dates
- **Evidence README**: discloses .tgz archives not preserved, actual native arm64 and emulated amd64 build/short-test results including every observed failure

### Fixed

- **Process-only test pollution**: removed process-only test files and process-only test functions/helpers (MD5 byte-identity pins of "frozen" files, `git diff HEAD` scope guards, pre-registration checks, AST scan tests banning identifiers); these tests policed the development process, not the engine
- **Internal identifier leakage**: renamed all development markers in public identifiers, test names, file names, and environment variable names
- **Private token leakage**: scanner now blocks private commit SHAs, AWS/GCP identifiers, filesystem paths, account IDs, and internal project names

### Known Issues

- **HAMT node free-list next-link overlap**: `pushFreeNode` stores the fixed-size free-list link in the first 8 bytes of a dead `HamtNode`, overlapping `refCount` (offset 0) and `bitmap` (offset 4), instead of the dedicated `nextFree` field at offset 64. The write overwrites node metadata and creates a reclamation and reuse hazard. This release retains that defect; the correction is planned for the next release. The current layout is documented in `docs/internals/STRUCT_ALIGNMENT.md`. Not observed in the six runs published with v0.2.0.
- **Earlier SIGBUS root-cause uncertainty**: a hardware `SIGBUS BUS_ADRALN` on unaligned `LDAR` on ARM64 was observed in fault-injection testing; the root cause was not definitively established. Not observed in the six runs published with v0.2.0.
- **Redundant fault-injection environment read**: `validateConfig` in `cmd/sovereign-node/main.go` reads the `SOVEREIGN_TEST_FAULT_IBLT_ARENA` environment variable to skip the arena-mib guard; this is a fault-injection control that production code reads.
- **Native arm64 short-test failures**: `pkg/durability` `TestCheckpointWalkPinnedAgainstState` panics with arena exhaustion (variable alloc); `sdk/sovereign` `TestClientGetOnPeerReturnsDigestNotValue` fails to converge in 20 rounds.
- **Emulated amd64 short-test failures**: 10 packages observe segmentation faults (`cmd/sovereign-node`, `internal/database`, `internal/index`, `internal/network`, `internal/transport`, `pkg/durability`, `pkg/mesh`, `pkg/receive`, `pkg/security/fuzz`, `sdk/sovereign`); 2 packages fail assertions (`pkg/attribution` O(1) depth check timing, `pkg/metrics` ingest latency bucket). Root causes not established; results are for this QEMU/container combination only.
- **Convergence tail**: 1 run in 7 straggles on the 100-process convergence target (the published v0.1.0 seven-run table shows one miss at 10.150 s).
- **Cedar authorization**: benchmark code only; no Cedar policy is enforced on any API path.
- **Frame-signing nonce**: default `identity.SignCRDTFrame` uses randomized-nonce Ed25519 deriving the nonce from SHA-512 of 64 bytes from `crypto/rand` and the message, without the secret-key prefix; relies on `crypto/rand` (`getrandom` on Linux), not hedged against RNG failure.
- **Fault-injection environment variables**: whoever controls a node's environment controls the node. Variables enable diagnostics or fault injection; they are not authentication or authorization controls. Do not set them in production or accept them from an untrusted launcher.

## [v0.1.0] - 2026-09-21

### Added

- Initial public release of Sovereign Engine
- Tri-temporal CRDT state (system × valid × assertion time)
- H3 cell axis reserved in the record (opt-in secondary index)
- Post-quantum key exchange (X25519MLKEM768) on by default
- Hybrid Ed25519 + ML-DSA-65 signatures opt-in
- Off-heap arena allocator with zero-GC hot path
- Lock-free CRDT core with compare-and-swap and epoch-based reclamation
- Write-ahead log with group commit, snapshots, and bounded recovery
- Mesh transport with mTLS, gossip anti-entropy, and Merkle convergence
- SDK with dev CA, node identity, mTLS control port, and client example
- Evidence directory with raw silicon receipts for all published numbers
- Reproduction scripts (`scripts/reproduce.sh`, `scripts/local-mesh.sh`)
- Business Source License 1.1 with Change Date 2029-08-15

### Known Issues (v0.1.0)

- Convergence tail: 1 run in 7 straggles on 100-process target
- Cedar authorization: benchmark only
- Production PKI/HSM, io_uring transport, gRPC API: planned

---

## How this release was published

v0.2.0 is a snapshot of private development from the v0.1.0 public tag to 6 November 2026 (the date of the 1,000-process runs). The private development history is not published. The public commit history is a publication record, not the development record.

- Comments and documents were edited for publication; no code behaviour was changed
- Files and tests were renamed for publication (development markers removed, v0.1.0 public names restored)
- The compiled engine is unchanged apart from the declared renames
- Process-only test files and process-only test functions/helpers were removed
- All numbers trace to receipts in `docs/evidence/`; every capability is described with its real status
- The 180 per-machine `.tgz` archives from the 6 November 2026 runs were not retained and cannot be restored; their manifests preserve recorded names and digests, not current availability
- The fleet harness is not published and no publication date is promised