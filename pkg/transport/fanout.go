// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package transport provides TLS configuration and ingress-routing helpers.
//
// ReusePortFanout is the in-process selection rule corresponding to the
// BPF_PROG_TYPE_SK_REUSEPORT implementation in ebpf_reuseport.go (ADR-0002).
// It hashes an Application Connection ID to a worker index. It does not create
// sockets, load eBPF programs, or perform cryptographic verification.
package transport

import (
	"hash/fnv"

	"github.com/hr18vk/sovereign/pkg/attribution"
)

// ReusePortFanout maps connection IDs to workers without retaining state.
// The kernel implementation keeps its routing state in a SOCKHASH map; this Go
// counterpart computes an index directly from its arguments.
type ReusePortFanout struct{}

// SelectRoute returns FNV-1a(originNodeID) modulo numSockets. Hashing the
// complete 16-byte ID gives a stable worker index while that ID remains fixed,
// even if the peer's network 4-tuple changes. The function does not inspect or
// verify the frame from which the caller obtained the ID.
//
// A zero numSockets returns 0. This sentinel is outside the otherwise valid
// range [0, numSockets); the caller must not treat it as a worker index.
func (f *ReusePortFanout) SelectRoute(originNodeID [attribution.OriginNodeIDSize]byte, numSockets uint32) uint32 {
	if numSockets == 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write(originNodeID[:])
	return h.Sum32() % numSockets
}
