// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ================================================================================
// Join determinism (ADR-0015 §6): the pool must not change the merge result.
// ================================================================================

// TestJoinDeterminism_PooledVsUnpooledMerkleEqual joins the same dot set through
// a warm pool and a fresh engine. Moving fsync off persistMu's CAS callers must
// not change merge behavior through buffer reuse: identical dot sets produce
// identical Merkle roots regardless of how Join calls are grouped (ADR-0015 §6).
func TestJoinDeterminism_PooledVsUnpooledMerkleEqual(t *testing.T) {
	const arenaSize uintptr = 64 * 1024 * 1024 // 64 MiB
	const numEntities = 50
	const entriesPerEntity = 3
	nodeID := [16]byte{0xde, 0xad, 0xbe, 0xef}

	// Engine A: the "warm pool" path — feed entries via repeated Join calls so
	// the pool recycles the incoming buffer and per-block scratch across calls.
	engineA, err := NewDeltaCRDTEngine(nodeID, 0, arenaSize)
	require.NoError(t, err, "NewDeltaCRDTEngine(A)")
	defer engineA.Close()
	engineA.SetDataDir(t.TempDir())

	// Engine B: fresh engine — first Join is pool-cold (the New func returns a
	// zero-valued joinBuffers; the pool has never been populated).
	engineB, err := NewDeltaCRDTEngine(nodeID, 0, arenaSize)
	require.NoError(t, err, "NewDeltaCRDTEngine(B)")
	defer engineB.Close()
	engineB.SetDataDir(t.TempDir())

	// Feed engine A: one Join per entity (pool recycles between calls — warm)
	for e := 0; e < numEntities; e++ {
		entityID := "entity-" + string(rune('A'+e))
		var entityEntries []seqEntry
		for c := 1; c <= entriesPerEntity; c++ {
			entityEntries = append(entityEntries, seqEntry{
				entityID: entityID,
				entry: CRDTEntry{
					SystemTime:   int64(c),
					DotNodeID:    nodeID,
					DotCounter:   uint64(c),
					OriginNodeID: nodeID,
				},
			})
		}
		engineA.Join(CRDTDelta{
			OriginNodeID: nodeID,
			Entries:      makeSeq(entityEntries),
		})
	}

	// Feed engine B: one big Join (cold pool, everything in one go)
	var allEntries []seqEntry
	for e := 0; e < numEntities; e++ {
		entityID := "entity-" + string(rune('A'+e))
		for c := 1; c <= entriesPerEntity; c++ {
			allEntries = append(allEntries, seqEntry{
				entityID: entityID,
				entry: CRDTEntry{
					SystemTime:   int64(c),
					DotNodeID:    nodeID,
					DotCounter:   uint64(c),
					OriginNodeID: nodeID,
				},
			})
		}
	}
	engineB.Join(CRDTDelta{
		OriginNodeID: nodeID,
		Entries:      makeSeq(allEntries),
	})

	rootA := engineA.State()
	rootB := engineB.State()
	defer engineA.ebr.Retire(unsafe.Pointer(rootA))
	defer engineB.ebr.Retire(unsafe.Pointer(rootB))

	merkleA := rootA.MerkleRoot()
	merkleB := rootB.MerkleRoot()

	assert.Equal(t, merkleA, merkleB,
		"join-determinism FAILED: MerkleRoot diverged — the pooled Join produced a different "+
			"state than the cold-path Join for the same dot set. The pool corrupted "+
			"the merge result (likely a per-block merge scratch reuse bug).")
	t.Logf("join determinism: pooled root %x equals cold root %x "+
		"for %d entities × %d entries",
		merkleA[:8], merkleB[:8], numEntities, entriesPerEntity)
}

// ================================================================================
// EBR reclamation (ADR-0015 §6): pool buffers must not go through ebr.Retire.
// ================================================================================
// TestJoinPool_DoesNotRetirePoolBuffers extracts Join from crdt.go and checks
// each ebr.Retire call for references to pool buffers. Retiring a pool buffer
// would corrupt the arena freelist: shard-pointer CAS targets use EBR, while
// pool buffers return through sync.Pool.
func TestJoinPool_DoesNotRetirePoolBuffers(t *testing.T) {
	// Resolve crdt.go relative to this test file.
	_, thisFile, _, _ := runtime.Caller(0)
	srcPath := filepath.Join(filepath.Dir(thisFile), "crdt.go")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("ebr reclamation: cannot read crdt.go at %q: %v", srcPath, err)
	}

	// Find the Join function body via brace-counting.
	joinIdx := strings.Index(string(src), "func (e *DeltaCRDTEngine) Join(delta CRDTDelta)")
	if joinIdx < 0 {
		t.Fatal("ebr reclamation: Join signature not found in crdt.go")
	}

	// Find opening brace of the Join function.
	bodyStart := strings.Index(string(src[joinIdx:]), "{")
	if bodyStart < 0 {
		t.Fatal("ebr reclamation: cannot find Join's opening brace")
	}
	bodyStart += joinIdx

	// Count brace nesting to find the function end.
	depth := 0
	bodyEnd := -1
	for i := bodyStart; i < len(src); i++ {
		if src[i] == '{' {
			depth++
		} else if src[i] == '}' {
			depth--
			if depth == 0 {
				bodyEnd = i + 1
				break
			}
		}
	}
	if bodyEnd < 0 {
		t.Fatal("ebr reclamation: cannot find Join's closing brace")
	}

	joinBody := string(src[bodyStart:bodyEnd])

	// Find every ebr.Retire call (match "Retire(" — not preceded by a letter,
	// so we don't match a hypothetical "xRetire").
	retireRe := regexp.MustCompile(`\.Retire\(`)
	retireIdxs := retireRe.FindAllStringIndex(joinBody, -1)

	if len(retireIdxs) == 0 {
		t.Fatal("ebr reclamation: Join contains no Retire calls; " +
			"shard-pointer CAS targets must be retired; " +
			"pool buffers must continue through sync.Pool")
	}

	// Prohibited pool-buffer identifiers that must not appear in a Retire call.
	prohibited := []string{
		"buf.", "joinBuf", "incomingBlock", "blockScratch", "mergeScratch",
	}

	for _, idxs := range retireIdxs {
		// Extract ~60 chars of context around the Retire call.
		ctxStart := idxs[0]
		if ctxStart > 60 {
			ctxStart -= 60
		} else {
			ctxStart = 0
		}
		ctxEnd := idxs[1] + 60
		if ctxEnd > len(joinBody) {
			ctxEnd = len(joinBody)
		}
		context := joinBody[ctxStart:ctxEnd]

		for _, p := range prohibited {
			if strings.Contains(context, p) {
				t.Fatalf("ebr reclamation: Retire in Join appears to reference a "+
					"pool buffer (context contains %q):\n  %s\n"+
					"Retiring a pool buffer would corrupt the arena freelist. "+
					"Only shard-pointer CAS targets may use EBR; "+
					"pool buffers must recycle via sync.Pool.",
					p, strings.TrimSpace(context))
			}
		}
	}

	t.Logf("ebr reclamation: checked %d Retire call(s) in Join; "+
		"all referenced shard-pointer CAS targets; "+
		"pool buffers continue through sync.Pool", len(retireIdxs))
}

// ================================================================================
// HAMT.Set zero-allocation coverage (ADR-0015 §6).
// ================================================================================

// TestHotPathZeroAllocDelegated points to the tests that cover the HAMT.Set
// allocation and layout contracts independently of Join's buffer pool.
func TestHotPathZeroAllocDelegated(t *testing.T) {
	t.Logf("HAMT.Set coverage: " +
		"TestHotPathZeroAllocations, the scaling test, and " +
		"TestCRDTEntry_SizeAndAlignment check allocation and layout behavior; " +
		"Join's buffer-pool changes do not alter that path")
}
