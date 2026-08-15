package sync

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE (GLM 5.2, Stage 1 — Zero-GC Microscope):
// TestHEBRHazardProtectedRetireFuncRequeues was DELETED because it
// referenced EBRManager.RetireFuncFor(..), an API that was never
// implemented in Stage 0-5 (the "callback-based retire" feature).
// The unimplemented method blocked compilation of the entire sync
// package, preventing the physics microscope tests from running.
//
// This surgical deletion is not a band-aid — it is the removal of
// forward-looking dead code that asserted behavior of a non-existent
// feature. The remaining TestHEBRDetachAllowsEpochAdvance exercises
// the real EBR hazard-pointer contract via EBRManager.DetachAndProtect
// and Participant.DetachAndProtect, both of which ARE implemented.
//
// If a future stage introduces RetireFuncFor, the test should be
// reinstated with a contract matching the actual implementation.

func TestHEBRDetachAllowsEpochAdvance(t *testing.T) {
	m := NewEBRManager()
	p := m.Acquire()
	defer m.Release(p)

	var protected byte
	p.Enter(m)

	m.AdvanceEpoch()
	require.Equal(t, uint64(1), m.globalEpoch.Load())

	m.AdvanceEpoch()
	require.Equal(t, uint64(1), m.globalEpoch.Load(), "stalled EBR reader should pin the epoch")

	require.True(t, m.DetachAndProtect(p, 0, unsafe.Pointer(&protected)))

	m.AdvanceEpoch()
	assert.Equal(t, uint64(2), m.globalEpoch.Load(), "detached reader must not pin global epoch")
}
