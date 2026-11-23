# ADR-0005: Close the epoll, real-NIC, benchmark, and receiver-wiring gaps

> **Status:** Accepted with negative single-host performance
> **Date:** 2026-07-26
> **Supersedes:** none
> **Superseded by:** none

## Context

[ADR-0003](0003_kernel_sk_reuseport_silicon.md) established kernel
SO_REUSEPORT steering by the plaintext origin node ID. Its measurements covered
socket selection on loopback, but four parts of the ingress design remained
untested: an epoll receive loop, delivery through a non-loopback interface, a
performance comparison against the kernel's hash fallback, and delivery into
`Receiver.HandleFrame`.

Those distinctions matter. A successful socket-selection test does not show
that an epoll loop can reassemble frames, that a NIC-bound group delivers them,
or that eBPF steering is faster than the kernel default. It also does not turn
the plaintext routing key into an authenticated identity.

## Decision

Extend `KernelFanout` with `LoadGroupOnIP`, so loopback and interface-specific
tests share one socket-creation path, and `DetachProgram`, which selects the
kernel hash fallback for the comparison run.

Add `EpollIngress` behind the `ebpf_kernel` build tag. The caller loads and
attaches the fanout before starting it. The adapter registers the group's UDP
sockets with `EPOLLIN|EPOLLET`, drains each ready socket through `EAGAIN`, and
separates datagrams into frames with the 4-byte big-endian length prefix
produced by `LengthPrefixFrame`. It copies each frame before calling
`Receiver.HandleFrame`, because the receive buffer is reused while accepted
frames may be retained.

This is a delivery adapter above the existing receive pipeline. It does not
change the order of rate, clock, depth, signature, and application checks in
`HandleFrame`.

## Consequences

- The implementation is opt-in. Default builds exclude both the kernel loader
  and `EpollIngress`, and no non-test code constructs the adapter. The normal
  node command therefore does not use this path.
- Kernel tests require `CAP_BPF` or equivalent privilege. An `EPERM` capability
  probe skips them rather than reporting an unavailable kernel test as a pass.
  `TestEBPFEpollIngress_RealNIC` also skips when `REAL_NIC_BIND_IP` is unset.
- The real-NIC benchmark found attached eBPF steering slower than detached
  kernel hash fallback on one host. It supports delivery correctness, not a
  performance advantage or a general cache-locality claim.
- That result comes from one machine and one secondary ENI. It does not predict
  behavior on a multi-NIC, multi-machine mesh, and it must not be generalized
  to other kernels or workloads without another measurement.
- Routing still precedes authentication. A connection ID can influence socket
  selection, but it cannot bypass the receive path's later validation.

## Evidence

The implementation and its tests are guarded by `ebpf_kernel`:

- `TestEBPFEpollIngress_DeliveryWiring` sends a valid length-prefixed envelope
  through a 32-socket group and requires `EpollIngress` to deliver it to
  `HandleFrame`.
- `TestEBPFEpollIngress_AttachVsDetach_AntiCorrelation` repeats delivery with
  the selector attached and detached. Both modes must deliver every frame.
- `TestEBPFEpollIngress_RealNIC` binds the group to `REAL_NIC_BIND_IP` and
  checks delivery through that interface. Per-socket stickiness belongs to the
  transport tests rather than this assertion.
- `BenchmarkEBPFDelivery_vs_HashFallback_32c` runs otherwise identical attached
  and detached workloads over a changing connection-ID set. Both runs use the
  same destination, and the benchmark fails if the attached run takes longer.
  Its intended invocation uses `-cpu=32 -benchtime=3s -count=3`.

No receipt for the recorded run is included in `docs/evidence/`. The specific
elapsed timings are therefore omitted, and the negative result above is historical
context rather than a reproducible performance claim. The tagged benchmark retains
the comparison for future measurement.

The related routing decision is [ADR-0002](0002_epoll_sockhash_reuseport_fanout.md);
the kernel packet layout, map behavior, and fallback contract are in
[ADR-0003](0003_kernel_sk_reuseport_silicon.md).
