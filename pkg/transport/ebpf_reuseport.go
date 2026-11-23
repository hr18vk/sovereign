// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build ebpf_kernel

package transport

// KernelFanout implements ingress routing with BPF_PROG_TYPE_SK_REUSEPORT and
// SO_ATTACH_REUSEPORT_EBPF. It is available only in ebpf_kernel builds and is
// used by the correspondingly tagged receive code and tests.
//
// The eBPF program reads the plaintext Application Connection ID from the
// relay envelope and selects a socket through a SOCKHASH map. Flows therefore
// retain their selected socket when the network 4-tuple changes. The separate
// ReusePortFanout type models the selection rule in Go.
//
// The cilium/ebpf package provides typed program and map loading. The context
// offsets and helper semantics follow Linux's include/uapi/linux/bpf.h; that
// package does not expose sk_reuseport_md as a Go type.

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/hr18vk/sovereign/pkg/attribution"
)

// ciliumEbpfCachePath identifies the cilium/ebpf version used by this loader.
const ciliumEbpfCachePath = "github.com/cilium/ebpf@v0.22.0"

// originNodeIDWireOffset locates the Application Connection ID in the relay
// envelope. RelayEnvelope.Marshal places dotCounter at [72:80] and originNodeID
// at [80:96], the same field accepted by ReusePortFanout.SelectRoute.
//
// sk_reuseport_md.data points to the transport header, not the UDP payload.
// The 8-byte UDP header therefore puts envelope bytes [80:96] at
// ctx->data[88:104]. Omitting that header offset would read the wrong key and
// make every SOCKHASH lookup miss.
const (
	originNodeIDWireOffset = 80
	// udpHeaderSize accounts for the source port, destination port, length, and
	// checksum fields preceding the envelope in ctx->data.
	udpHeaderSize = 8
)

// originNodeIDBpfOffset includes the UDP header before the envelope, placing
// the 16-byte connection ID at ctx->data[88:104].
const originNodeIDBpfOffset = udpHeaderSize + originNodeIDWireOffset

// skReuseportMdDataOffset and skReuseportMdDataEndOffset locate the packet
// bounds pointers in sk_reuseport_md. Both __bpf_md_ptr fields are 64-bit:
// data is at byte 0 and data_end at byte 8. The program checks every key read
// against this pair as required by the eBPF verifier.
const (
	skReuseportMdDataOffset    = 0
	skReuseportMdDataEndOffset = 8
)

// skPass tells the kernel to deliver through the socket selected by
// bpf_sk_select_reuseport. If the helper was skipped or found no mapping, the
// kernel uses its default reuseport hash. Short frames and map misses therefore
// fall back to ordinary delivery rather than being dropped.
const skPass = 1

// reuseportSockHashMapName identifies the SOCKHASH map queried by helper 82.
// Its 16-byte OriginNodeID keys map to uint64 socket file descriptors. SOCKHASH
// accepts arbitrary byte keys, so the program can look up the connection ID
// directly; PinFlow populates those entries from userspace.
const reuseportSockHashMapName = "reuseport_sockhash"

// KernelFanout routes packets by the plaintext OriginNodeID before signature
// verification. It owns a SO_REUSEPORT group, a SOCKHASH map from connection IDs
// to sockets, and an attached BPF_PROG_TYPE_SK_REUSEPORT program. Pinned flows
// retain their socket when their network 4-tuple changes.
type KernelFanout struct {
	// sockets are the file descriptors of the SO_REUSEPORT UDP socket group,
	// created by LoadGroup. The eBPF program selects among these.
	sockets []int
	// port is the UDP port all sockets in the group are bound to.
	port int
	// prog is the loaded BPF_PROG_TYPE_SK_REUSEPORT program (a cilium
	// *ebpf.Program wrapping the kernel program fd), attached to the group via
	// SO_ATTACH_REUSEPORT_EBPF.
	prog *ebpf.Program
	// sockMap is the BPF_MAP_TYPE_SOCKHASH keyed on the 16-byte OriginNodeID,
	// valued on the socket FD (uint64). The kernel verifier allows SOCKHASH for
	// bpf_sk_select_reuseport, and SOCKHASH keys directly on the 16-byte ID
	// without an in-program hash. Populated by PinFlow before traffic arrives.
	sockMap *ebpf.Map
}

// buildReuseportProgram constructs a BPF_PROG_TYPE_SK_REUSEPORT program.
// It preserves sk_reuseport_md in R9, loads data and data_end, and returns
// SK_PASS without a lookup unless data+104 is within bounds. For a full frame,
// it copies data[88:104] into a stack key and calls
// bpf_sk_select_reuseport(ctx, map, &key, 0). Both helper hits and misses return
// SK_PASS; misses use the kernel's default reuseport hash.
func buildReuseportProgram(mapFD int) *ebpf.ProgramSpec {
	const keyStackOff = -16 // 16-byte key at FP[-16:0]

	insns := asm.Instructions{
		// Preserve ctx in callee-saved R9 before using R1 for the bounds
		// calculation. The helper requires the original context in R1.
		asm.Mov.Reg(asm.R9, asm.R1),

		// R6 holds PTR_TO_PACKET and R7 holds PTR_TO_PACKET_END.
		asm.LoadMem(asm.R6, asm.R1, skReuseportMdDataOffset, asm.DWord),
		asm.LoadMem(asm.R7, asm.R1, skReuseportMdDataEndOffset, asm.DWord),

		// data+104 is one past the connection ID. A larger value than data_end
		// means the frame is short, so skip the lookup and use the kernel hash.
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Add.Imm(asm.R1, originNodeIDBpfOffset+attribution.OriginNodeIDSize),
		// Jump to SK_PASS when data+104 exceeds data_end.
		asm.JGT.Reg(asm.R1, asm.R7, "fallback"),
	}

	// Copy data[88:104] into FP[-16:0] one byte at a time. Initializing the
	// complete stack key is required before passing it to the helper.
	for i := 0; i < attribution.OriginNodeIDSize; i++ {
		insns = append(insns,
			asm.LoadMem(asm.R8, asm.R6, int16(originNodeIDBpfOffset+i), asm.Byte),
			asm.StoreMem(asm.R10, int16(keyStackOff+i), asm.R8, asm.Byte),
		)
	}

	insns = append(insns,
		// Restore ctx in R1 and pass the map, stack-key pointer, and zero flags
		// in R2 through R4.
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.LoadMapPtr(asm.R2, mapFD),
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, keyStackOff),
		asm.Mov.Imm(asm.R4, 0),

		// Helper 82 selects the mapped socket, if any.
		asm.FnSkSelectReuseport.Call(),

		// A hit uses the selected socket. A miss leaves it unset and falls back
		// to the kernel hash; both paths return SK_PASS.
		asm.Mov.Imm(asm.R0, skPass),
		asm.Return(),

		// Short frames reach this label without calling the helper.
		asm.Mov.Imm(asm.R0, skPass).WithSymbol("fallback"),
		asm.Return(),
	)

	return &ebpf.ProgramSpec{
		Type:       ebpf.SkReuseport,
		AttachType: ebpf.AttachSkReuseportSelect,
		Name:       "sk_reuseport_route_by_cid",
		// ebpf.NewProgram marshals these instructions for BPF_PROG_LOAD.
		Instructions: insns,
		// bpf_sk_select_reuseport is not restricted to GPL-only programs; this
		// conventional license string is accepted by the verifier.
		License: "GPL",
	}
}

// newReuseportSockHashMap allocates the connection-ID-to-socket map queried by
// bpf_sk_select_reuseport. Values are uint64 file descriptors.
func newReuseportSockHashMap(maxEntries uint32) (*ebpf.Map, error) {
	return ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.SockHash,
		Name:       reuseportSockHashMapName,
		KeySize:    uint32(attribution.OriginNodeIDSize),
		ValueSize:  8, // uint64 socket file descriptor
		MaxEntries: maxEntries,
	})
}

// LoadGroup binds numSockets UDP sockets to INADDR_ANY and port with
// SO_REUSEADDR and SO_REUSEPORT. It shares LoadGroupOnIP's setup path.
func (k *KernelFanout) LoadGroup(numSockets uint32, port int) error {
	return k.LoadGroupOnIP(numSockets, port, [4]byte{})
}

// LoadGroupOnIP binds numSockets nonblocking UDP sockets to bindIP and port
// with SO_REUSEADDR and SO_REUSEPORT. A zero bindIP selects INADDR_ANY;
// otherwise the group is restricted to that interface address.
func (k *KernelFanout) LoadGroupOnIP(numSockets uint32, port int, bindIP [4]byte) error {
	if numSockets == 0 {
		return fmt.Errorf("ebpf_reuseport: numSockets must be > 0")
	}
	k.port = port
	k.sockets = make([]int, 0, numSockets)
	for i := uint32(0); i < numSockets; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("ebpf_reuseport: socket %d: %w", i, err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("ebpf_reuseport: SO_REUSEADDR socket %d: %w", i, err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("ebpf_reuseport: SO_REUSEPORT socket %d: %w", i, err)
		}
		sa := &unix.SockaddrInet4{Port: port, Addr: bindIP}
		if err := unix.Bind(fd, sa); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("ebpf_reuseport: bind socket %d %d.%d.%d.%d:%d: %w", i, bindIP[0], bindIP[1], bindIP[2], bindIP[3], port, err)
		}
		k.sockets = append(k.sockets, fd)
	}
	return nil
}

// LoadProgram creates a SOCKHASH map with one slot per socket, then loads the
// reuseport program and stores both objects on KernelFanout.
func (k *KernelFanout) LoadProgram() error {
	return k.LoadProgramWithMapSize(uint32(len(k.sockets)))
}

// LoadProgramWithMapSize creates a SOCKHASH map with maxEntries slots before
// loading the program. The capacity is raised to the socket count when needed.
// Workloads that pin more connection IDs than sockets must request enough slots
// to avoid E2BIG from PinFlow.
func (k *KernelFanout) LoadProgramWithMapSize(maxEntries uint32) error {
	if maxEntries < uint32(len(k.sockets)) {
		maxEntries = uint32(len(k.sockets)) // never smaller than the socket group
	}
	m, err := newReuseportSockHashMap(maxEntries)
	if err != nil {
		return fmt.Errorf("ebpf_reuseport: create sockhash map: %w", err)
	}
	k.sockMap = m

	// The map must exist first because LoadMapPtr embeds its file descriptor.
	spec := buildReuseportProgram(m.FD())
	// NewProgram issues BPF_PROG_LOAD for the constructed instruction stream.
	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		_ = m.Close()
		return fmt.Errorf("ebpf_reuseport: BPF_PROG_LOAD: %w", err)
	}
	k.prog = prog
	return nil
}

// PinFlow maps cid to the socket at socketIndex so later packets with that
// OriginNodeID select this socket. The map stores its file descriptor as a
// uint64. An out-of-range index returns an error.
func (k *KernelFanout) PinFlow(cid [attribution.OriginNodeIDSize]byte, socketIndex uint32) error {
	if int(socketIndex) >= len(k.sockets) {
		return fmt.Errorf("ebpf_reuseport: socketIndex %d out of range (have %d sockets)", socketIndex, len(k.sockets))
	}
	fd := uint64(k.sockets[socketIndex])
	// UpdateAny permits both insertion and replacement of a flow mapping.
	return k.sockMap.Update(cid, fd, ebpf.UpdateAny)
}

// AttachProgram attaches the loaded program with
// SO_ATTACH_REUSEPORT_EBPF. Setting the option on one member applies it to the
// whole SO_REUSEPORT group. It requires a loaded program and a nonempty group.
func (k *KernelFanout) AttachProgram() error {
	if k.prog == nil {
		return fmt.Errorf("ebpf_reuseport: program not loaded")
	}
	if len(k.sockets) == 0 {
		return fmt.Errorf("ebpf_reuseport: no sockets in group")
	}
	fd := k.prog.FD()
	if err := unix.SetsockoptInt(k.sockets[0], unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, fd); err != nil {
		return fmt.Errorf("ebpf_reuseport: SO_ATTACH_REUSEPORT_EBPF: %w", err)
	}
	return nil
}

// DetachProgram clears the group's attached program with
// SO_DETACH_REUSEPORT_BPF. Later packets use the kernel's default reuseport
// hash, while the program remains open and can be attached again. The dedicated
// detach option is required; SO_ATTACH_REUSEPORT_EBPF with fd 0 returns EINVAL.
func (k *KernelFanout) DetachProgram() error {
	if len(k.sockets) == 0 {
		return fmt.Errorf("ebpf_reuseport: no sockets in group")
	}
	if err := unix.SetsockoptInt(k.sockets[0], unix.SOL_SOCKET, unix.SO_DETACH_REUSEPORT_BPF, 0); err != nil {
		return fmt.Errorf("ebpf_reuseport: SO_DETACH_REUSEPORT_BPF: %w", err)
	}
	return nil
}

// SocketFD returns the file descriptor of the socket at socketIndex, so a test
// can recvfrom() it and count per-socket receipts (the stickiness table).
func (k *KernelFanout) SocketFD(socketIndex uint32) int {
	if int(socketIndex) >= len(k.sockets) {
		return -1
	}
	return k.sockets[socketIndex]
}

// NumSockets returns the size of the SO_REUSEPORT group.
func (k *KernelFanout) NumSockets() uint32 { return uint32(len(k.sockets)) }

// Close detaches and closes the program, closes the map, and closes every
// socket. Cleanup continues after individual errors and Close is idempotent.
func (k *KernelFanout) Close() error {
	// Detach on a best-effort basis before releasing the program and sockets.
	if len(k.sockets) > 0 {
		_ = unix.SetsockoptInt(k.sockets[0], unix.SOL_SOCKET, unix.SO_DETACH_REUSEPORT_BPF, 0)
	}
	if k.prog != nil {
		_ = k.prog.Close()
		k.prog = nil
	}
	if k.sockMap != nil {
		_ = k.sockMap.Close()
		k.sockMap = nil
	}
	for _, fd := range k.sockets {
		_ = unix.Close(fd)
	}
	k.sockets = nil
	return nil
}
