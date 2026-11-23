// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
