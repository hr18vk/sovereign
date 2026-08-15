package database

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEpochCompactor_BumpEpoch(t *testing.T) {
	c := NewEpochCompactor(2)
	assert.Equal(t, uint64(0), c.CurrentEpoch())

	c.BumpEpoch()
	assert.Equal(t, uint64(1), c.CurrentEpoch())
	c.BumpEpoch()
	assert.Equal(t, uint64(2), c.CurrentEpoch())
}

func TestEpochCompactor_StableEpoch(t *testing.T) {
	c := NewEpochCompactor(2)

	// No peers -> 0 stable epoch
	assert.Equal(t, uint64(0), c.StableEpoch())

	nodeA := [16]byte{1}
	nodeB := [16]byte{2}

	c.AdvancePeerEpoch(nodeA, 5)
	c.AdvancePeerEpoch(nodeB, 3)

	// Min is 3
	assert.Equal(t, uint64(3), c.StableEpoch())

	// Advance node B
	c.AdvancePeerEpoch(nodeB, 7)
	// Min is now 5
	assert.Equal(t, uint64(5), c.StableEpoch())
}

func TestEpochCompactor_PruneTombstones(t *testing.T) {
	c := NewEpochCompactor(2) // stabilityLag = 2

	nodeA := [16]byte{1}

	// Insert tombstones across epochs
	for e := uint64(0); e <= 10; e++ {
		// Sync the current epoch
		c.currentEpoch.Store(e)

		for i := 0; i < 5; i++ {
			c.InsertTombstone(fmt.Sprintf("entity-%d-%d", e, i), nodeA, uint64(i))
		}
	}

	assert.Equal(t, 55, c.TombstoneCount())

	// Set stable epoch to 5
	c.AdvancePeerEpoch(nodeA, 5)

	// pruneThreshold = stable(5) - lag(2) = 3
	// We keep epochs > 3 (i.e. 4,5,6,7,8,9,10 = 7 epochs)
	// 7 * 5 = 35 remaining, 20 pruned (epochs 0,1,2,3)
	pruned, remaining := c.PruneTombstones()

	assert.Equal(t, 20, len(pruned))
	assert.Equal(t, 35, remaining)
	assert.Equal(t, 35, c.TombstoneCount())

	// Verify the stats
	stats := c.Stats()
	assert.Equal(t, uint64(55), stats["total_inserted"])
	assert.Equal(t, uint64(20), stats["total_pruned"])
	assert.Equal(t, uint64(35), stats["pending_count"])
}

func TestEpochCompactor_PruneTombstones_NotStable(t *testing.T) {
	c := NewEpochCompactor(5) // High lag

	nodeA := [16]byte{1}

	// Epoch 2
	c.currentEpoch.Store(2)
	c.InsertTombstone("entity1", nodeA, 1)

	// Stable is 4
	c.AdvancePeerEpoch(nodeA, 4)

	// Stable(4) < lag(5), so nothing should be pruned
	pruned, remaining := c.PruneTombstones()
	assert.Equal(t, 0, len(pruned))
	assert.Equal(t, 1, remaining)
}

func BenchmarkEpochCompactor_InsertTombstone(b *testing.B) {
	c := NewEpochCompactor(2)
	nodeA := [16]byte{1}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.InsertTombstone("entity", nodeA, uint64(i))
	}
}

func BenchmarkEpochCompactor_PruneTombstones(b *testing.B) {
	c := NewEpochCompactor(2)
	nodeA := [16]byte{1}

	for i := 0; i < 10000; i++ {
		c.InsertTombstone("entity", nodeA, uint64(i))
	}

	c.AdvancePeerEpoch(nodeA, 100)
	c.currentEpoch.Store(100)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.PruneTombstones()
	}
}
