// Package transport — INGRESS fanout half.
//
// This file is the in-process analogue of the kernel ingress fanout the
// Phase-3 architecture PROVES in prose at
// phase-03/Final_Sovereign_Architecture_Phase3.md:358 (§2.X1(a): "epoll +
// SO_ATTACH_REUSEPORT_EBPF vs io_uring: PROVEN"), :108 (the matrix row:
// "Socket ingress must utilize edge-triggered epoll combined with native BPF
// steering programs (bpf_sk_select_reuseport)"), and :102 (the SOCKHASH
// rationale: "utilizing a BPF SOCKHASH map to pin stateful connections to
// specific processor cores, thereby eradicating cache invalidation and
// thread migration latency during periods of high peer mobility and network
// churn").
//
// The architecture decision is PROVEN in the prose; THIS file builds the
// in-process SEAM the decision gates — the deterministic decision function a
// kernel BPF_PROG_TYPE_SK_REUSEPORT program loaded via SO_ATTACH_REUSEPORT_EBPF
// would implement. It does NOT load a real eBPF program, call bpf(2), or bind
// SO_REUSEPORT group sockets — the kernel load is Subphase 12.0 (a FUTURE
// track on a c8g box with CAP_BPF). The kernel socket-option constants below
// are doc-cited from the module cache at
// $(go env GOMODCACHE)/golang.org/x/sys@v0.46.0/unix and are NOT invoked at
// runtime:
//
//	zerrors_linux_arm64.go:336  SO_ATTACH_REUSEPORT_EBPF         = 0x34
//	zerrors_linux_arm64.go:387  SO_REUSEPORT                     = 0xf
//	ztypes_linux.go:2831       BPF_PROG_TYPE_SK_REUSEPORT       = 0x15
//	ztypes_linux.go:2739       BPF_MAP_CREATE                   = 0x0
//
// golang.org/x/sys v0.46.0 is ALREADY pinned (go.mod:21); this file adds NO
// new go.mod dependency (stdlib hash/fnv + the attribution package only).
package transport

import (
	"hash/fnv"

	"github.com/hr18vk/supremum/pkg/attribution"
)

// ReusePortFanout is the in-process analogue of a kernel
// BPF_PROG_TYPE_SK_REUSEPORT program loaded via SO_ATTACH_REUSEPORT_EBPF
// (x/sys unix const 0x15, ztypes_linux.go:2831). A kernel program of this
// type is invoked by the kernel on every ingress packet landing on a
// SO_REUSEPORT (zerrors_linux_arm64.go:387, const 0xf) socket group and
// returns the index of the ONE socket in the group that must receive the
// packet. The kernel analogue is loaded onto the group via
// setsockopt(SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, prog) (const 0x34,
// zerrors_linux_arm64.go:336). This struct carries no state — the decision is
// a pure function of (connectionID, numSockets) — mirroring the kernel
// program's stateless-per-call contract (state lives in the SOCKHASH map,
// not the program).
type ReusePortFanout struct{}

// SelectRoute is the analogue of bpf_sk_select_reuseport(bpf_sock_addr) ->
// SOCKHASH index keyed on the plaintext Application Connection ID read from
// the packet header. Returns the uint32 worker index in [0, numSockets).
//
// It is a DETERMINISTIC, LOCK-FREE hash (the kernel eBPF program is also
// deterministic — a flow MUST always land on the same core while the CID is
// constant; determinism is the whole point — eradicating cache invalidation
// and thread migration across a roam). A future track that swaps in a
// randomized rand-based shuffle to "balance" load would DEFEAT the stickiness
// property and is explicitly out of scope (the kernel eBPF program is
// deterministic BY DEFINITION — a remap keyed on a fixed field hash).
//
// It reads RelayEnvelope.OriginNodeID() — the no-crypto cheap-gate header
// mirror (envelope.go:345). It does NOT call Open/Verify. The selector runs
// BEFORE open/verify — the SAME seam the 3.1 rate gate and 3.0 clock gate
// already use (envelope.go:143-144: "dotCounter and originNodeID are read
// from the header BEFORE any capnp decode, so the cheap 3.1/3.0 gates run
// against header fields, not a capnp unmarshal"). The wire offset of the
// field is [80:96] (envelope.go:498-503 Marshal doc: "dotCounter at [72:80],
// originNodeID at [80:96]"); the selector reads it via the exported accessor
// rather than hand-rolling offsets, so a future wire-layout change propagates
// through the accessor and never desyncs the route from the gate path.
//
// Pinning requirement: a FNV-1a over the FULL 16 bytes -> uint32 mod
// numSockets. A fixed hash (NOT rand) — sticky across a 4-tuple roam. Using
// only the first 4 bytes (a u32 cast) is WRONG: it ignores the entropy in
// bytes 4..15 and concentrates flows. The whole id is hashed. (The kernel eBPF
// would hash via bpf_get_hash_relay(); for the pure-Go in-process analogue,
// FNV-1a over the [16]byte is the documented substitute — a kernel track may
// use a different hash, and the determinism tooth is parameterized to
// whatever the live program uses.)
//
// numSockets == 0 is the malformed/empty socket-group case: the kernel eBPF
// program's `return 0` (drop) analogue. SelectRoute returns 0 and the caller
// treats it as DropMalformed (route to no worker); it does NOT panic.
func (f *ReusePortFanout) SelectRoute(originNodeID [attribution.OriginNodeIDSize]byte, numSockets uint32) uint32 {
	if numSockets == 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write(originNodeID[:])
	return h.Sum32() % numSockets
}
