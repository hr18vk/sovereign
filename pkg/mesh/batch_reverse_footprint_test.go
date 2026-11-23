// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The batchReverse index maps each retained dot to its origin sequence.
// Displacement re-points an existing entry; it does not allocate another one.
// RelayBatchReverseBytes therefore increases by batchReverseEntryFootprint only
// for a distinct new dot, while the forward frame is released after its last
// dot moves away (ADR-0071). The displacement case distinguishes this accounting
// from charging once per RetainForeignBatch call.

import (
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
)

func TestP2ReverseBytesInvariant(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("create node identity: %v", err)
	}
	g := NewGossiper(nil, owner, nil, identity.NewDirectory())
	var foreign [16]byte
	for i := range foreign {
		foreign[i] = 0xF2
	}
	f1 := make([]byte, 137)
	g.RetainForeignBatch(foreign, 7, []uint64{101, 102, 103}, f1)
	cs := g.CacheStats()
	if cs.RelayBatchReverse != 3 || cs.RelayBatchReverseBytes != 3*batchReverseEntryFootprint {
		t.Fatalf("after insert: reverse entries=%d bytes=%d, want 3 and %d", cs.RelayBatchReverse, cs.RelayBatchReverseBytes, 3*batchReverseEntryFootprint)
	}
	if cs.RelayBatchForward != 1 || cs.RelayBatchForwardBytes != 137 {
		t.Fatalf("after insert: forward frames=%d bytes=%d, want 1 and 137", cs.RelayBatchForward, cs.RelayBatchForwardBytes)
	}
	// Reusing the dots under a new sequence releases the old frame, retains the
	// new one, and re-points the reverse entries without growing the index.
	f2 := make([]byte, 151)
	g.RetainForeignBatch(foreign, 8, []uint64{101, 102, 103}, f2)
	cs = g.CacheStats()
	if cs.RelayBatchReverse != 3 || cs.RelayBatchReverseBytes != 3*batchReverseEntryFootprint {
		t.Fatalf("after displacement: reverse entries=%d bytes=%d, want 3 and %d; charging per retain call would give %d bytes", cs.RelayBatchReverse, cs.RelayBatchReverseBytes, 3*batchReverseEntryFootprint, 6*batchReverseEntryFootprint)
	}
	if cs.RelayBatchForward != 1 || cs.RelayBatchForwardBytes != 151 {
		t.Fatalf("after displacement: forward frames=%d bytes=%d, want 1 and 151", cs.RelayBatchForward, cs.RelayBatchForwardBytes)
	}
	// Sequence 9 adds dot 104 and moves the other three dots, so only the
	// reverse index grows; the sequence 8 forward frame is released.
	g.RetainForeignBatch(foreign, 9, []uint64{101, 102, 103, 104}, f2)
	cs = g.CacheStats()
	if cs.RelayBatchReverse != 4 || cs.RelayBatchReverseBytes != 4*batchReverseEntryFootprint {
		t.Fatalf("after growth: reverse entries=%d bytes=%d, want 4 and %d after adding dot 104", cs.RelayBatchReverse, cs.RelayBatchReverseBytes, 4*batchReverseEntryFootprint)
	}
	if cs.RelayBatchForward != 1 || cs.RelayBatchForwardBytes != 151 {
		t.Fatalf("after growth: forward frames=%d bytes=%d, want 1 and 151", cs.RelayBatchForward, cs.RelayBatchForwardBytes)
	}
}
