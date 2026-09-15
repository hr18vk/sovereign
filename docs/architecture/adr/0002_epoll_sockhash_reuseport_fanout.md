# ADR-0002: epoll + SO_ATTACH_REUSEPORT_EBPF ingress fanout (in-process seam)
> Status: ACCEPTED     Date: 2026-07-25
> Supersedes: none     Superseded by: none

## 1. Context

The engine's ingress transport boundary must fan out arriving packets across
cores while keeping a stateful flow pinned to ONE core across a peer IP roam.
The underlying architecture decision is already settled in the 
architecture document, which I quote here rather than re-derive:

- The epoll decision: "(a) epoll + SO\_ATTACH\_REUSEPORT\_EBPF vs
  io\_uring: PROVEN. The Go 1.26.1 scheduler is deeply intertwined with its
  internal, highly optimized, non-blocking epoll netpoller infrastructure ...
  Implementing epoll coupled with the Linux kernel's SO\_ATTACH\_REUSEPORT\_EBPF
  custom socket steering provides the necessary packet fanout on Linux 6.18
  without compromising scheduler stability."
- The matrix row: "Edge-triggered epoll dominance over io\_uring for Go mesh
  networking | PROVEN ... Socket ingress must utilize edge-triggered epoll
  combined with native BPF steering programs (bpf\_sk\_select\_reuseport) to
  achieve concurrent scale."
- The SOCKHASH rationale: "... utilizing a BPF SOCKHASH map to pin stateful
  connections to specific processor cores, thereby eradicating cache
  invalidation and thread migration latency during periods of high peer
  mobility and network churn."

This ADR records the IN-PROCESS SEAM the decision gates — the deterministic
decision function a kernel `BPF_PROG_TYPE_SK_REUSEPORT` program loaded via
`SO_ATTACH_REUSEPORT_EBPF` would implement. The kernel eBPF load (binding a
real `SO_REUSEPORT` socket group, loading the program via `bpf(2)`, and
verifying flow stickiness on `c8g` with `CAP_BPF`) is deferred follow-up
work. Here I build and measure the in-process analogue on the 4-core
development box using the `internal/chaos` VirtualNet harness; the plan
explicitly scopes acceptance to the in-process VirtualNet, with the kernel
path conditionally approved pending the kernel-load work.

The eBPF route key is the **Application Connection ID** — the plaintext
cheap-gate header mirror `originNodeID [16]byte`, read BEFORE any crypto. This
is the load-bearing physical fact: the whole point of "strip-from-packet" is
that the selector keys off a field the packet carries IN PLAINTEXT in the
header, so the eBPF program can route without Verifying. Verified at
`pkg/attribution/envelope.go`:

- **:345** `func (e *RelayEnvelope) OriginNodeID() [OriginNodeIDSize]byte` —
  the no-crypto accessor the selector reads.
- **:129** the wire-layout comment: "[16] originNodeID ([16]byte) NEW v3 — the
  cheap-gate mirror of the inner capnp CRDTDeltaEvent.OriginNodeID. The GAP-3
  Directory.Lookup keys on THIS field."
- **:498-503** the Marshal offset doc: "dotCounter at [72:80], originNodeID at
  [80:96]".
- **:143-144** "dotCounter and originNodeID are read from the header BEFORE any
  capnp decode, so the cheap 3.1/3.0 gates run against header fields, not a
  capnp unmarshal" — the SAME read-before-Verify seam the existing 3.1 rate
  gate and 3.0 clock gate already use.

The kernel socket-option constants the live program would use are doc-cited
from the module cache at `$(go env GOMODCACHE)/golang.org/x/sys@v0.46.0/unix`
and are NOT invoked at runtime here:

- `zerrors_linux_arm64.go:336` `SO_ATTACH_REUSEPORT_EBPF = 0x34`
- `zerrors_linux_arm64.go:387` `SO_REUSEPORT = 0xf`
- `ztypes_linux.go:2831` `BPF_PROG_TYPE_SK_REUSEPORT = 0x15`
- `ztypes_linux.go:2739` `BPF_MAP_CREATE = 0x0`

`golang.org/x/sys v0.46.0` is ALREADY pinned (`go.mod:21`); this ADR adds NO
new go.mod dependency.

## 2. Decision Drivers

- **D1: Worker affinity (cache locality).** A flow pinned to one core keeps
  its per-flow state warm in that core's L1/L2; a roam that re-hashes the flow
  to a different core incurs cache invalidation + thread-migration latency.
  The selector MUST be deterministic so a constant CID stays on one core.
- **D2: Peer mobility (IP roam, app CID constant).** A peer's 4-tuple changes
  across a roam (NAT rebinding, DHCP renewal, mobile handoff) but its
  Application Connection ID does NOT. The route MUST key on the CID, NOT the
  4-tuple, so the flow survives the roam on the same core.
- **D3: Cheap-gate seam (route before Verify).** The eBPF program runs in
  kernel context BEFORE the packet reaches userspace crypto; it CANNOT call
  `Open`/`Verify`. The selector reads the plaintext header mirror
  (`OriginNodeID`), the same read-before-crypto seam the 3.1 rate gate and
  3.0 clock gate already use (envelope.go:143-144).
- **D4: Zero new deps.** `golang.org/x/sys v0.46.0` is already pinned
  (`go.mod:21`); the in-process selector uses only stdlib `hash/fnv` + the
  `attribution` package (already a dep). No `go.mod`/`go.sum` change.

## 3. Considered Options

- **Option A: kernel eBPF live load NOW.** Bind a real `SO_REUSEPORT` socket
  group, write + load a `BPF_PROG_TYPE_SK_REUSEPORT` program via
  `setsockopt(SO_ATTACH_REUSEPORT_EBPF)`, and measure stickiness on `c8g` with
  `CAP_BPF`. **REJECTED** — needs `CAP_BPF` + a `c8g` box (the deferred
  kernel work); the 4-core development box lacks the capability, and the plan
  explicitly permits the in-process path FIRST.
- **Option B: in-process selector + VirtualNet stickiness test FIRST, kernel
  load deferred.** Build the deterministic decision function in pure
  Go (`pkg/transport/fanout.go`), prove the determinism + stickiness + no-crypto
  properties on the in-process `internal/chaos` VirtualNet, and defer the live
  eBPF load to the follow-up kernel work. ✅ **ACCEPTED.**

## 4. Decision (the load-bearing claim)

**I accept Option B.** The in-process `ReusePortFanout.SelectRoute`
(`pkg/transport/fanout.go`) is a FAITHFUL analogue of
`bpf_sk_select_reuseport(bpf_sock_addr) -> SOCKHASH` keyed on the plaintext
Application Connection ID (`RelayEnvelope.OriginNodeID`, envelope.go:345). It
hashes the full 16-byte CID via FNV-1a to a `uint32` worker index in
`[0, numSockets)` — deterministic, lock-free, and read-before-Verify. The
kernel eBPF load is deferred work; this ADR does NOT load a real eBPF
program, call `bpf(2)`, or bind `SO_REUSEPORT` group sockets. The
`SO_ATTACH_REUSEPORT_EBPF` / `SO_REUSEPORT` / `BPF_PROG_TYPE_SK_REUSEPORT`
constants are doc-cited (the citation block of the selector + this ADR) but
NOT invoked at runtime.

This decision is enforced structurally, not merely documented:

- `TestSelectRouteDeterminism` (`pkg/transport/fanout_test.go`) asserts
  `SelectRoute(sameCID, n) == sameIndex` for `1<<20` iterations — a future
  change swapping in a randomized rand-based shuffle to "balance" load would
  FAIL this tooth.
- `TestRoamStickiness_32ListIncomplete` asserts the 32-listener stickiness
  property: 1000 frames, peer 4-tuple changes / CID constant -> all land on ONE
  worker (0 failures).
- `TestNoCryptoBeforeRoute` asserts the strip-from-packet eBPF invariant:
  `VerifyHookCount` stays 0 across the routing decision (route-before-Verify).

## 5. Rationale (R1-R4; transcribed, not re-proven)

The epoll-routing decision is settled in the architecture document; this
ADR does NOT re-prove it. It is the canonical citable home for the in-process
seam that decision gates.

- **R1: Determinism (route-by-identity, not route-by-clock).** The kernel eBPF
  program is deterministic BY DEFINITION (a remap keyed on a fixed field hash);
  the in-process analogue is too. A flow MUST always land on the same core
  while the CID is constant — that is the whole point (eradicating cache
  invalidation and thread migration across a roam). The selector keys ONLY on
  the identity field; the clock (dotCounter) is a cheap gate AFTER, not a route
  key.
- **R2: Cheap seam (no crypto — the strip-from-packet eBPF invariant).** The
  selector reads `OriginNodeID()` (envelope.go:345) and never calls
  `Open`/`Verify`. This is the same read-before-crypto property the 3.0/3.1
  gates already use (envelope.go:143-144); the eBPF program CANNOT Verify
  (it runs in kernel context before userspace crypto), so the analogue MUST
  not either.
- **R3: The epoll-routing decision is citable unchanged.** The architecture
  decision lives in the architecture document; this ADR builds +
  measures the SEAM it gates, it does not re-derive the epoll-vs-io_uring
  decision.
- **R4: The in-process carve-out explicitly permits this.** Acceptance uses
  the in-process `internal/chaos` VirtualNet harness, NOT the kernel, until
  real `c8g` hardware is available; the kernel path is conditionally approved pending
  the kernel-load work.

## 6. Consequences (N1-N4)

- **N1:** The seam IS a conditionally approved seam. The kernel eBPF load is the
  deferred work on a `c8g` box with `CAP_BPF`. The measurements behind
  this ADR are an IN-PROCESS deterministic-model correctness property, NOT a
  32-core linux-6.18 silicon number, and must not be labeled as silicon.
- **N2:** The fanout is read-before-Verify (the same property the 3.0/3.1
  gates already use). The selector sits AT the socket boundary; once a frame
  is routed to a worker, the existing `pkg/receive/receiver.go` `HandleFrame`
  path (receiver.go:244) is the consumer ABOVE the selector. This ADR does
  NOT modify `receiver.go`.
- **N3:** Advancing a route-by-verified-identity design (routing by the
  VERIFIED identity, not the plaintext header mirror) would supersede this ADR
  (ADR-0002b). Such a design is not WRONG — it is a DIFFERENT architecture —
  but it is NOT the in-kernel epoll design settled in the architecture document
  and would defeat the cheap-gate layer; the `TestNoCryptoBeforeRoute` tooth
  would FAIL on it.
- **N4:** The cheap-gate mirror `originNodeID` (`[80:96]` wire, envelope.go) is
  load-bearing for BOTH ingress routing (this ADR) AND the existing gate
  path (3.1 rate, 3.0 clock). A future wire-layout change to that field
  propagates through the `OriginNodeID()` accessor, so the route never desyncs
  from the gate path; the selector reads the accessor, NOT hand-rolled offsets.

## 7. Relationships

- **R1:** Cites the architecture document — the epoll-routing decision, the
  epoll-vs-io_uring matrix row, and the SOCKHASH rationale (quoted in §1).
- **R2:** Cites `pkg/attribution/envelope.go:345` (the `OriginNodeID()`
  read-before-crypto seam), `:129` (the wire-layout comment), `:498-503` (the
  Marshal offset doc), `:143-144` (the read-before-capnp comment).
- **R3:** Enforced structurally via the teeth at `pkg/transport/fanout_test.go`
  — `TestNoCryptoBeforeRoute` (the strip-from-packet eBPF invariant) +
  `TestSelectRouteDeterminism` (the determinism tooth) +
  `TestRoamStickiness_32ListIncomplete` (the 32-listener stickiness gate).
