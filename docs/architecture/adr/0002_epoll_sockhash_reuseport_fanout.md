# ADR-0002: Route ingress by the plaintext origin node ID

> **Status:** Accepted
> **Date:** 2026-07-25
> **Supersedes:** none
> **Superseded by:** none

## Context

Ingress routing should keep a flow on the same worker when a peer changes its
network address. A route derived from the network 4-tuple cannot provide that
property across NAT rebinding, DHCP renewal, or a mobile handoff. The relay
envelope already carries an Application Connection ID in its plaintext
`originNodeID [16]byte` header mirror, so that field can select a worker before
Cap'n Proto decoding or signature verification.

In the version 3 wire layout, `RelayEnvelope.Marshal` places `dotCounter` at
bytes `[72:80]` and `originNodeID` at `[80:96]`.
`(*RelayEnvelope).OriginNodeID` exposes the latter without decoding the inner
event. The receive path later checks the mirror against the decoded event and
authenticates the frame.

Routing before verification has a precise limit: the header value is an
unauthenticated routing hint. A sender can influence its worker selection, but
selection alone neither accepts nor applies a frame.

The initial implementation of this decision was a pure-Go selector tested with
the in-process VirtualNet harness. Kernel loading was deferred so that determinism,
roaming behavior, and independence from cryptography could be tested without a
privileged host. [ADR-0003](0003_kernel_sk_reuseport_silicon.md) later added the
kernel implementation, and [ADR-0005](0005_close_four_movea_gaps.md) added the
tagged epoll adapter and its benchmark.

## Decision

Use `ReusePortFanout.SelectRoute` as the in-process model for deterministic
worker selection. It computes FNV-1a over the complete 16-byte origin node ID
and returns the hash modulo `numSockets`. An empty socket group returns the
zero sentinel, which is outside the otherwise valid range and must not be
treated as a worker index.

The selector retains no flow state and performs no cryptographic operation.
Routing by the network 4-tuple is rejected because it loses affinity during a
roam; routing only after verification is rejected because a kernel selector
must act before userspace cryptography.

The Go model tests the selection rule. It is not a byte-for-byte model of the
later eBPF program: `KernelFanout` uses a SOCKHASH map populated by `PinFlow`,
with the kernel's normal reuseport hash as the fallback for misses and short
frames. Both designs use the same plaintext connection-ID field and preserve
the separation between routing and authentication.

## Consequences

- The tests establish deterministic worker selection, not placement on a
  particular physical CPU. They do not demonstrate a cache-locality or
  throughput improvement.
- `ReusePortFanout` has no non-test caller in this tree. The kernel loader is
  available only with the `ebpf_kernel` build tag, and the tagged epoll adapter
  is not constructed by non-test code. Neither mechanism is the default
  production receive path.
- Plaintext routing does not bypass admission or authentication.
  `Receiver.HandleFrame` still applies rate and clock gates, verifies the relay
  and origin signatures, and checks the header mirrors before applying data.
- The origin-ID accessor and wire marshaler own the Go-side layout contract.
  The kernel packet-offset constants must change with that layout, as detailed
  in ADR-0003.

## Evidence

The tests in `pkg/transport/fanout_test.go` exercise the model rather than
kernel delivery:

- `TestSelectRouteDeterminism` repeats one selection for `1<<20` iterations and
  requires the same in-range worker index.
- `TestRoamStickiness_32ListIncomplete` sends 1000 frames through VirtualNet
  with a fixed connection ID and changing source identities. All frames reach
  the same worker among 32 listeners.
- `TestNoCryptoBeforeRoute` instruments `attribution.VerifyHookCount` and
  requires zero verification calls during routing.
- `TestNoPanicOnZeroFrame` covers the empty-group sentinel and deterministic
  selection for a zero-valued connection ID.

These are correctness checks for an in-process model, not hardware performance
measurements. Kernel evidence and the negative single-host performance result
are recorded separately in [ADR-0003](0003_kernel_sk_reuseport_silicon.md) and
[ADR-0005](0005_close_four_movea_gaps.md).
