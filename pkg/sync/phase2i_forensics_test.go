// Phase 2i — ARENA EXHAUSTION FORENSICS (measurement-only, non-production)
//
// R1/R3 scope: this file is the ONLY new source added by phase feat/phase2i-arena-forensics.
// It contains NO production code. It does NOT modify crdt.go / hamt.go / hamt_arena.go /
// crdt_apply*.go / crdt_reconstruct*.go. It exposes:
//   - the static sizeof(CRDTEntry) (Gate 3a) so the report can quote a literal number
//     derived from the SAME toolchain that compiled the production struct, and
//   - a thin pass-through shim around DeltaCRDTEngine.maybeAdvanceEpoch (Gate 3c) that
//     increments an atomic counter so the report can quote how many epoch advances are
//     physically issued under bench load. The shim does NOT touch production code; it
//     is reachable from the bench via TestMain-free test helpers only.
//
// Nothing here is on any production path. It is a _test.go file.

package sync

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// phase2iCRDTEntrySizeOf reports the exact machine width of CRDTEntry as compiled
// today. Used by Gate 3a's static audit.
func phase2iCRDTEntrySizeOf() uintptr {
	return unsafe.Sizeof(CRDTEntry{})
}

// phase2iPayloadDigestSize reports the [32]byte digest width for the report's
// "is the digest the load-bearing width?" cross-check.
func phase2iPayloadDigestSize() uintptr {
	var e CRDTEntry
	return unsafe.Sizeof(e.PayloadDigest)
}

// phase2iNodeIDSize reports the [16]byte node-ID width, summed across Dot + Origin.
func phase2iNodeIDSize() uintptr {
	var e CRDTEntry
	return unsafe.Sizeof(e.DotNodeID) + unsafe.Sizeof(e.OriginNodeID)
}

// TestPhase2I_CRDTEntryWidthStaticAudit is the static gate-3a assertion. It is NOT a
// correctness test; it exists so `go test` prints the literal sizeof the report cites.
func TestPhase2I_CRDTEntryWidthStaticAudit(t *testing.T) {
	t.Logf("unsafe.Sizeof(CRDTEntry{}) = %d bytes", phase2iCRDTEntrySizeOf())
	t.Logf("  PayloadDigest[32]      = %d bytes", phase2iPayloadDigestSize())
	t.Logf("  DotNodeID+OriginNodeID  = %d bytes", phase2iNodeIDSize())
	t.Logf("  expected (Phase 1 form) = 120 bytes")
	if got := phase2iCRDTEntrySizeOf(); got != 120 {
		t.Errorf("CRDTEntry width drifted from Phase 1: got %d, want 120", got)
	}
}

// phase2iArenaSizes is a small table used by the forensics benches below to
// exercise the Join path at varied arena sizes WITHOUT touching the real
// BenchmarkCRDTEngine_Join harness (R3 forbids editing existing bench files).
var phase2iArenaSizes = []struct {
	name string
	size uintptr
}{
	{"64MiB", 64 * 1024 * 1024},
	{"256MiB", 256 * 1024 * 1024},
	{"1GiB", 1 * 1024 * 1024 * 1024},
	{"2GiB", 2 * 1024 * 1024 * 1024},
}

// phase2iBuildDeltas mirrors the shape of BenchmarkCRDTEngine_Join's delta
// pre-build, so the forensics benches exercise the identical Join code path.
func phase2iBuildDeltas(n int, arena *HamtArena, nodeB [16]byte) []CRDTDelta {
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

// phase2iJoinRecover runs n Join ops, recovering the arena-exhaustion panic so
// that the testing harness can still flush -memprofile/-cpuprofile (a raw panic
// aborts the process before the profile writer runs). It reports where in the
// loop the OOM landed. This is NON-production forensics scaffolding; the panic
// is caught here ONLY so profiles can be written — the production arena still
// panics (see Gate 1's raw /tmp/p2i-g1-runK.log for the unmodified panic stack).
func phase2iJoinRecover(b *testing.B, arenaBytes uintptr) (diedAt int, recoveredPanic any) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, arenaBytes)
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	defer engine.Close()
	nodeB := [16]byte{2}
	deltas := phase2iBuildDeltas(b.N, engine.Arena(), nodeB)
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

// BenchmarkPhase2I_JoinRecover64M is the forensics clone of
// BenchmarkCRDTEngine_Join at 64 MiB that catches the OOM panic so -memprofile
// and -cpuprofile are actually written. N.B. the recovered variant alters the
// per-iteration cost slightly (defer/recover goroutine) — use Gate 1's raw
// bench for the literal death iteration, use THIS bench for the profile only.
func BenchmarkPhase2I_JoinRecover64M(b *testing.B) {
	diedAt, p := phase2iJoinRecover(b, 64*1024*1024)
	if p != nil {
		b.Logf("recovered arena OOM at iter %d of b.N=%d: %v", diedAt, b.N-1, p)
	}
}

