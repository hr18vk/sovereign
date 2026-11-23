# Security Policy

Sovereign Engine is a research preview. Its peer transport uses mTLS and
negotiates post-quantum key exchange by default when both endpoints support it.
Hybrid post-quantum frame signatures are opt-in with `--hybrid-sign` and
`--hybrid-verify`. Cedar authorization is benchmark code only: no Cedar policy
is enforced on an API path.

If you find a vulnerability in the implemented security boundaries, I want to hear
about it directly and will treat it as a priority.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

If *Report a vulnerability* is available on this repository's *Security* tab, use
**GitHub Private Vulnerability Reporting** there. Otherwise, use the contact options
on [my GitHub profile](https://github.com/hr18vk) to ask me to arrange a private
channel. Do not include sensitive details in public issues, discussions, or other
public messages.

Include, if you can:

- A description of the issue and the attack scenario it enables.
- The affected version/commit and the environment (OS, arch, Go version).
- A minimal reproduction or a pointer to the implicated code path.
- Whether you believe it's exploitable in a default configuration.

## What to expect

- **Acknowledgement** of your report as soon as I've read it (this is a
  solo-maintained project; allow a few days).
- **An assessment** of severity and whether it reproduces, including any
  environmental limits on that conclusion.
- **A fix and credit** (with your permission) in the release notes and the
  relevant ADR.

## Scope notes

- **In scope:** the CRDT merge/apply path, the WAL/durability path, the mesh
  transport (TLS/mTLS/PQ handshake), and the signed-envelope attribution path.
- **Constructions and implementation:** reviews of hybrid key exchange and
  signatures, nonce generation, and fallback behaviour are welcome. Hybrid
  signing is opt-in; default frame signing is Ed25519.
- **Out of scope:** vulnerabilities requiring you to already have root on the host,
  and issues in third-party dependencies (report those upstream — though I'm glad
  to hear about them too).

## Operational exposure

The unauthenticated plain-HTTP metrics listener is separate from the TLS peer
listener and the optional mTLS control listener. `--metrics-addr` defaults to
`127.0.0.1:7431`; setting it selects a different address. The listener serves:

- `/livecheck`
- `/metrics`
- `/debug/memstats`

Keep this listener on loopback or otherwise unreachable from untrusted networks.
Binding it to another interface exposes these routes without authentication.

Three more routes share that listener only when their environment switches are
set: `/debug/state-fingerprint` with `SOVEREIGN_STATE_FP_DEBUG=1`,
`/debug/responder-indegree` with `SOVEREIGN_RESPOND_INDEG_DEBUG=1`, and
`/debug/heartbeat` with either `SOVEREIGN_DIGEST_LATENCY_DEBUG=1` or
`SOVEREIGN_EXCH_DEBUG=1`.

Profiling is served beneath `/debug/pprof/` on a dedicated listener, including
goroutine, mutex, and block profiles. It always binds to `127.0.0.1`; the host in
`--pprof-addr` is discarded. By default, `pprofBindAddr` uses
`127.0.0.1:8431`, the default metrics port plus 1000. Mutex and block sampling
require `--diag-profile` or `SOVEREIGN_DIAG_PROFILE=1` because collection adds
runtime overhead. A profile-listener bind failure disables profiling without
stopping the node.

The optional JSON-over-mTLS control listener (`--control-addr`) is separate from
both the peer and metrics listeners and requires a client certificate. It is
disabled by default.

The default endpoint configuration is verified in `docs/evidence/README.md`
(current configuration evidence): the plain-HTTP metrics listener binds to
`127.0.0.1:7431` and the dedicated profiling listener binds to `127.0.0.1:8431`.
The latter derives from the default metrics port plus 1000; `--pprof-addr` can
change the port but not the loopback host.

## Environment-controlled diagnostics and faults

Whoever controls a node's environment controls the node. These variables enable
diagnostics or fault injection; they are not authentication or authorization
controls. Do not set them in a production environment or accept them from an
untrusted launcher.

Production-read fault-injection variables (read by production code):

- `SOVEREIGN_TEST_FAULT_FINGERPRINT=oracleblind` substitutes the dot-only Merkle
  root for the value returned by `/debug/state-fingerprint` when that route is
  enabled. It therefore reports a false state fingerprint and marks the response
  with `neutered=oracleblind`.
- `SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=sync_boot_dial` replaces concurrent initial
  peer dialing with sequential dialing.
- `SOVEREIGN_TEST_FAULT_IBLT_ARENA=skip_arena_mib_guard` skips validation that a
  large IBLT bucket floor has a sufficiently large arena.
- Any non-empty `SUPREMUM_JEMALLOC_AUDIT` enables allocation tracking and free
  checks in the jemalloc binding. It adds overhead, reports caller-size mismatches,
  and panics on an invalid or double free.

Production-read debug and diagnostic variables (read by production code):

- `SOVEREIGN_STATE_FP_DEBUG=1` exposes `/debug/state-fingerprint` (read-only state
  fingerprint and entry count).
- `SOVEREIGN_RESPOND_INDEG_DEBUG=1` exposes `/debug/responder-indegree`
  (per-arrival responder occupancy tracking and its debug route).
- `SOVEREIGN_DIGEST_LATENCY_DEBUG=1` or `SOVEREIGN_EXCH_DEBUG=1` exposes
  `/debug/heartbeat` (exchange and response byte counts, timing and busy-time
  diagnostics).
- `SOVEREIGN_MISS_LOG_CAP` (positive integer, max 10000) overrides the default
  payload-miss log cap in the gossiper.
- `SOVEREIGN_SWEEP_PHASE_JITTER=1` enables deterministic per-node sweep offsets
  (also controlled by `--sweep-phase-jitter`).
- `SOVEREIGN_DIAG_PROFILE=1` enables mutex and block profiling (also controlled
  by `--diag-profile`).

Test-only fault-injection variables (read only by test files, not production code)
are not listed here; they exist only to exercise negative controls in the test
suite and have no effect on a production node.

## Frame-signing nonce

The default `identity.SignCRDTFrame` implementation uses randomized-nonce
Ed25519. It derives the nonce from SHA-512 of 64 bytes from `crypto/rand` and the
message, without the secret-key prefix. Nonce unpredictability therefore relies
on `crypto/rand` (`getrandom` on Linux); the construction is not hedged against
random-number-generator failure. The `aws_lc_hedged` build tag does not provide
an alternative implementation.

## Known allocator issue

`pushFreeNode` stores the fixed-size HAMT node free-list link in the first eight
bytes of a dead `HamtNode`, overlapping `refCount` and `bitmap`, instead of the
dedicated `nextFree` field at offset 64. The write overwrites node metadata and
creates a reclamation and reuse hazard. This release retains that defect; the
correction is planned for the next release. The current layout is documented in
[the struct-alignment notes](docs/internals/STRUCT_ALIGNMENT.md).

## Known test failure

The SDK client test `TestClientGetOnPeerReturnsDigestNotValue` in
`sdk/sovereign` is a known failure (it did not converge in 20 rounds). This is a
test harness issue, not an engine defect, and is disclosed in the platform check
receipt [platform-checks-2026-11-21.txt](docs/evidence/platform-checks-2026-11-21.txt).

## Platform status

Pre-publication platform checks on 2026-11-21 tested native Linux arm64 and emulated
Linux amd64. Both builds passed; neither complete short-test invocation passed. Native
arm64 included a `TestCheckpointWalkPinnedAgainstState` arena-exhaustion panic and the
known SDK failure. Emulated amd64 had ten packages with observed segmentation faults
and two assertion failures. The emulated result does not establish behavior on native
amd64 hardware or a root cause for the segmentation faults. These results do not
support a claim of a green test suite on either platform. See
[platform-checks-2026-11-21.txt](docs/evidence/platform-checks-2026-11-21.txt) for the
complete receipt.