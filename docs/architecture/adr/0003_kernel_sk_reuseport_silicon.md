# ADR-0003: Kernel SO_REUSEPORT steering on Linux 6.18

**Status:** Accepted, scoped to BPF socket steering  
**Date:** 2026-07-25 to 2026-07-26  
**Supersedes:** None  
**Superseded by:** None  
**Related:** [ADR-0002](0002_epoll_sockhash_reuseport_fanout.md),
[ADR-0005](0005_close_four_movea_gaps.md)

## Context

[ADR-0002](0002_epoll_sockhash_reuseport_fanout.md) established the in-process
`ReusePortFanout.SelectRoute` selector and deferred a live kernel eBPF load.
Its pure-Go FNV-1a hash modeled the routing rule, but could not test the
`bpf(2)` loader, kernel verifier, socket attachment, or packet offsets.

The routing requirement is flow affinity across peer mobility. A peer's
4-tuple can change while its Application Connection ID stays constant, so the
selector keys on the plaintext `originNodeID [16]byte` rather than the network
4-tuple. The field is available through `(*RelayEnvelope).OriginNodeID` in
`pkg/attribution/envelope.go` before Cap'n Proto decoding or signature
verification. Kernel routing uses the same field; it does not authenticate the
frame, and the userspace receive path still verifies it.

This ADR records the kernel implementation and its correctness tests on one
Spot `c8g.8xlarge` with Graviton4 CPU part `0xd4f`, Linux 6.18.38, and
`unprivileged_bpf_disabled=1`. The tests ran with `CAP_BPF` through `sudo`.
The measured scope is BPF socket steering on loopback, not the complete epoll
ingress design or a performance result.

### Decision drivers

- Exercise the real kernel program rather than inferring its behavior from the
  Go selector.
- Preserve a flow's selected socket when its 4-tuple changes.
- Route before userspace cryptography without treating the plaintext ID as
  authenticated identity.
- Deliver malformed frames and map misses through the kernel's normal hash
  fallback instead of dropping them in the BPF program.
- Keep the implementation and its dependency out of default builds.

## Decision

### Loader and map

Use `cilium/ebpf` v0.22.0 and its `asm.Instructions` DSL to construct and load
the program. The alternative was to define `bpf_attr`, issue `bpf(2)` through
`unix.Syscall`, and encode the instruction stream directly. That duplicates
the syscall and union handling already provided by cilium's typed API.
`golang.org/x/sys` v0.46.0 supplies constants such as `SYS_BPF=280`, but not
the Go wrappers and `bpf_attr` types needed for this path. Although the test
host had `clang` 15 and `llc`, the Go DSL avoids a separate compiler step.

Cilium does not expose `sk_reuseport_md` as a Go type. The program therefore
uses the Linux v6.18 UAPI offsets for its `data` and `data_end` fields and
checks the packet bounds before reading the key.

`KernelFanout` uses a `BPF_MAP_TYPE_SOCKHASH` map (`0x12`, cilium
`ebpf.SockHash`) keyed by the 16-byte OriginNodeID, with a `uint64` socket file
descriptor as the value. `PinFlow` populates an entry through
`ebpf.Map.Update`. The `bpf_sk_select_reuseport` helper (ID 82) accepts
SOCKHASH as well as SOCKMAP and REUSEPORT_SOCKARRAY. SOCKHASH fits this design
because REUSEPORT_SOCKARRAY is indexed by a `u32`, not a 16-byte connection
ID, and a direct map lookup needs no second hash inside the BPF program.

### Socket group and attachment

`pkg/transport/ebpf_reuseport.go`, guarded by `//go:build ebpf_kernel`, is the
kernel counterpart of `ReusePortFanout` in `pkg/transport/fanout.go`.
`KernelFanout` binds a UDP group with `SO_REUSEPORT` (`0xf`), loads a
`BPF_PROG_TYPE_SK_REUSEPORT` program (`0x15`), and attaches it with
`unix.SetsockoptInt` using `SOL_SOCKET` (`0x1`) and
`SO_ATTACH_REUSEPORT_EBPF` (`0x34`). The measured group had 32 sockets; the
implementation accepts a caller-selected group size.

### Packet layout and fallback

`RelayEnvelope.Marshal` places `dotCounter` at envelope bytes `[72:80]` and
`originNodeID` at `[80:96]`. For `sk_reuseport_md`, `data` points to the UDP
header rather than the payload. The 8-byte UDP header therefore puts the
connection ID at `ctx->data[88:104]`. The program checks `data+104` against
`data_end`, copies those 16 bytes into a stack key, and calls
`bpf_sk_select_reuseport` with the SOCKHASH map.

An earlier draft read `ctx->data[80:96]`, which combined bytes from
`dotCounter` and `originNodeID` and made every lookup miss. Adding the UDP
header offset corrected the route key. This offset is part of the wire
contract and must change with `RelayEnvelope.Marshal`, not independently of
it.

The return values follow Linux's `enum sk_action`: `SK_DROP=0` and
`SK_PASS=1`. Every path returns `SK_PASS`. A successful lookup selects the
mapped socket. A miss, or a frame too short for the bounds check, skips
selection and lets the kernel use its normal reuseport hash fallback through
`SELECT_OR_MIGRATE`. The BPF program does not drop malformed input or panic on
a zero-length frame, matching the fallback contract of the Go selector.

## Consequences

- **Availability:** The kernel path requires the `ebpf_kernel` build tag and
  `CAP_BPF` or equivalent privilege; the test process does not grant that
  privilege. Default builds exclude `ebpf_reuseport.go` and use the in-process
  selector instead.

- **Authentication:** OriginNodeID is an unauthenticated routing key at this
  layer. A sender can choose its value and influence socket selection, but
  cannot bypass the subsequent checks in `Receiver.HandleFrame`. The routing
  decision neither accepts nor applies a frame.

- **Wire compatibility:** The BPF offset constants duplicate part of the relay
  envelope layout. `RelayEnvelope.Marshal`, `OriginNodeID`, and the BPF bounds
  check must be changed together if that layout changes. The wire-offset test
  in `makeFrame` checks the Go side of this contract.

- **Dependencies:** The change added `cilium/ebpf` v0.22.0. Its module
  requirements also updated the transitive `davecgh/go-spew` and
  `pmezard/go-difflib` versions used by testify. The kernel loader remains
  excluded from the default build by its tag.

- **Measured scope:** The ADR-0003 run used one single-AZ host and loopback
  (`127.0.0.1`). It did not exercise a NIC queue, RSS, XPS, interrupt
  affinity, an epoll loop, or the receive pipeline, and it recorded no
  latency or throughput benchmark. It supports socket-selection correctness,
  not a claim about cache locality, scheduler stability, or multi-AZ behavior.

- **Later work:** [ADR-0005](0005_close_four_movea_gaps.md) added
  `LoadGroupOnIP`, `DetachProgram`, and the tagged `EpollIngress` adapter to
  `Receiver.HandleFrame`. Its real-NIC benchmark at 32 cores measured slower
  eBPF steering than kernel hash fallback. Both the adapter and loader remain
  opt-in, and no non-test code currently constructs `EpollIngress`.

## Evidence

The measurements used the host and privilege configuration described in
Context. The tests are in `pkg/transport/ebpf_reuseport_test.go` behind the
same build tag as the implementation.

- `TestEBPFRoamStickiness_32Sockets` created 32 real UDP sockets on
  `127.0.0.1` and sent 1000 frames from fresh source sockets after pinning one
  connection ID to socket 0. The 4-tuple changed while the connection ID remained
  constant. The recorded result was 0/1000 mis-routes, with all 1000 frames
  delivered to socket 0.
- `TestEBPFDeterminism` checked that repeated datagrams carrying one
  connection ID arrive at exactly one socket, independently of the Go
  selector's FNV-1a hash.
- `TestNoCryptoBeforeRoute_EBPF` routed a frame with an empty signature and no
  hops using only its plaintext OriginNodeID. This tests routing before
  verification; it is not an authentication test.
- `TestEBPFMalformedFrameNoDrop` sent frames too short to contain
  `data[88:104]`. The bounds check returned `SK_PASS`, and the kernel hash
  fallback delivered the datagrams rather than dropping them.
- `requireCapBPF` probes `BPF_MAP_CREATE` with the same SOCKHASH type used by
  the implementation. `EPERM` skips the kernel tests; other errors fail them,
  so an unavailable capability is not reported as a passing test.

Linux v6.18's `include/uapi/linux/bpf.h` defines `sk_reuseport_md`,
`enum sk_action`, and the helper contract. The verifier's
`check_map_func_compatibility` accepts SOCKHASH for
`bpf_sk_select_reuseport`; `net/core/sock_reuseport.c` provides the hash
fallback, and `net/core/sock_map.c` handles the file-descriptor-valued map
update.

A separate `BenchmarkVerifyCRDTFrame_32c` measured 60.19µs per Ed25519
verification with circl v1.6.4 at 32 cores; see
[ADR-0010](0010_batched_delta_wire_v1.md). That is a signature-verification
microbenchmark, not a measurement of this BPF path.
