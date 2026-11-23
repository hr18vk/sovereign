// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// CRDTEntry layout checks and arena-exhaustion profiling helpers.

package sync

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// crdtEntrySizeOf reports CRDTEntry's size on the current architecture.
func crdtEntrySizeOf() uintptr {
	return unsafe.Sizeof(CRDTEntry{})
}

// payloadDigestSize reports the width of the [32]byte digest field.
func payloadDigestSize() uintptr {
	var e CRDTEntry
	return unsafe.Sizeof(e.PayloadDigest)
}

// nodeIDSize reports the [16]byte node-ID width, summed across Dot + Origin.
func nodeIDSize() uintptr {
	var e CRDTEntry
	return unsafe.Sizeof(e.DotNodeID) + unsafe.Sizeof(e.OriginNodeID)
}

// TestCRDTEntryWidthStaticAudit pins the entry layout used by the wire and
// arena accounting. It also logs the field-group sizes.
func TestCRDTEntryWidthStaticAudit(t *testing.T) {
	t.Logf("unsafe.Sizeof(CRDTEntry{}) = %d bytes", crdtEntrySizeOf())
	t.Logf("  PayloadDigest[32]      = %d bytes", payloadDigestSize())
	t.Logf("  DotNodeID+OriginNodeID  = %d bytes", nodeIDSize())
	t.Logf("  expected (baseline form) = 120 bytes")
	if got := crdtEntrySizeOf(); got != 120 {
		t.Errorf("CRDTEntry width drifted from baseline: got %d, want 120", got)
	}
}

// entryWidthArenaSizes supplies arena capacities for profiling Join.
var entryWidthArenaSizes = []struct {
	name string
	size uintptr
}{
	{"64MiB", 64 * 1024 * 1024},
	{"256MiB", 256 * 1024 * 1024},
	{"1GiB", 1 * 1024 * 1024 * 1024},
	{"2GiB", 2 * 1024 * 1024 * 1024},
}

// buildEntryWidthDeltas pre-builds the same delta shape used by
// BenchmarkCRDTEngine_Join.
func buildEntryWidthDeltas(n int, arena *HamtArena, nodeB [16]byte) []CRDTDelta {
	out := make([]CRDTDelta, n)
	for i := range out {
		out[i] = CRDTDelta{
			OriginNodeID: nodeB,
			Entries: makeSeq([]seqEntry{{
				entityID: fmt.Sprintf("remote-%d", i),
				entry: CRDTEntry{
					SystemTime:   int64(i),
					DotNodeID:    nodeB,
					DotCounter:   uint64(i + 1),
					OriginNodeID: nodeB,
				},
			}}),
		}
	}
	return out
}

// entryWidthJoinRecover runs Join until arena exhaustion and recovers the panic
// so the test binary can flush memory and CPU profiles. Production Join keeps
// its panic-on-exhaustion behavior.
func entryWidthJoinRecover(b *testing.B, arenaBytes uintptr) (diedAt int, recoveredPanic any) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, arenaBytes)
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	defer engine.Close()
	nodeB := [16]byte{2}
	deltas := buildEntryWidthDeltas(b.N, engine.Arena(), nodeB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					recoveredPanic = r
					diedAt = i
					runtime.Goexit()
				}
			}()
			engine.Join(deltas[i])
		}()
		if recoveredPanic != nil {
			return
		}
	}
	return -1, nil
}

// BenchmarkJoinRecover64M profiles arena exhaustion with a 64 MiB arena.
// Defer and recovery change per-iteration costs, so the unrecovered benchmark
// remains the source for Join timings and the exhaustion iteration.
func BenchmarkJoinRecover64M(b *testing.B) {
	diedAt, p := entryWidthJoinRecover(b, 64*1024*1024)
	if p != nil {
		b.Logf("recovered arena OOM at iter %d of b.N=%d: %v", diedAt, b.N-1, p)
	}
}
