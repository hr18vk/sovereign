package sync

import (
	"fmt"
	"testing"
	"unsafe"
)

// TestMemoryLayoutAnalysis prints the exact byte-level memory layout of
// all hot-path structs to identify false sharing vulnerabilities.
//
// This is Phase 1 of the AWS Graviton Crucible: we must know the EXACT
// byte offsets of every atomic field to determine which ones share a
// 64-byte L1 cache line.
func TestMemoryLayoutAnalysis(t *testing.T) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║     PHASE 1: MEMORY LAYOUT ANALYSIS — FALSE SHARING DETECT     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// --- HamtNode ---
	fmt.Println("━━━ HamtNode ━━━")
	fmt.Printf("  sizeof(HamtNode) = %d bytes\n", unsafe.Sizeof(HamtNode{}))
	printFields("HamtNode", []fieldInfo{
		{"refCount", unsafe.Offsetof(HamtNode{}.refCount), unsafe.Sizeof(HamtNode{}.refCount)},
		{"bitmap", unsafe.Offsetof(HamtNode{}.bitmap), unsafe.Sizeof(HamtNode{}.bitmap)},
		{"childrenPtr", unsafe.Offsetof(HamtNode{}.childrenPtr), unsafe.Sizeof(HamtNode{}.childrenPtr)},
		{"entriesPtr", unsafe.Offsetof(HamtNode{}.entriesPtr), unsafe.Sizeof(HamtNode{}.entriesPtr)},
		{"merkleHash", unsafe.Offsetof(HamtNode{}.merkleHash), unsafe.Sizeof(HamtNode{}.merkleHash)},
		{"nextFree", unsafe.Offsetof(HamtNode{}.nextFree), unsafe.Sizeof(HamtNode{}.nextFree)},
	})
	fmt.Println()

	// --- EBRManager ---
	fmt.Println("━━━ EBRManager ━━━")
	fmt.Printf("  sizeof(EBRManager) = %d bytes\n", unsafe.Sizeof(EBRManager{}))
	printFields("EBRManager", []fieldInfo{
		{"globalEpoch", unsafe.Offsetof(EBRManager{}.globalEpoch), unsafe.Sizeof(EBRManager{}.globalEpoch)},
		{"head", unsafe.Offsetof(EBRManager{}.head), unsafe.Sizeof(EBRManager{}.head)},
		{"retired[0]", unsafe.Offsetof(EBRManager{}.retired), unsafe.Sizeof(EBRManager{}.retired)},
		{"pool", unsafe.Offsetof(EBRManager{}.pool), unsafe.Sizeof(EBRManager{}.pool)},
		{"retiredPool", unsafe.Offsetof(EBRManager{}.retiredPool), unsafe.Sizeof(EBRManager{}.retiredPool)},
	})
	fmt.Println()

	// --- Participant ---
	fmt.Println("━━━ Participant ━━━")
	fmt.Printf("  sizeof(Participant) = %d bytes\n", unsafe.Sizeof(Participant{}))
	printFields("Participant", []fieldInfo{
		{"active", unsafe.Offsetof(Participant{}.active), unsafe.Sizeof(Participant{}.active)},
		{"epoch", unsafe.Offsetof(Participant{}.epoch), unsafe.Sizeof(Participant{}.epoch)},
		{"hazards", unsafe.Offsetof(Participant{}.hazards), unsafe.Sizeof(Participant{}.hazards)},
		{"next", unsafe.Offsetof(Participant{}.next), unsafe.Sizeof(Participant{}.next)},
	})
	fmt.Println()

	// --- DeltaCRDTEngine ---
	fmt.Println("━━━ DeltaCRDTEngine ━━━")
	fmt.Printf("  sizeof(DeltaCRDTEngine) = %d bytes\n", unsafe.Sizeof(DeltaCRDTEngine{}))
	printFields("DeltaCRDTEngine", []fieldInfo{
		{"shards", unsafe.Offsetof(DeltaCRDTEngine{}.shards), unsafe.Sizeof(DeltaCRDTEngine{}.shards)},
		{"routeSeed", unsafe.Offsetof(DeltaCRDTEngine{}.routeSeed), unsafe.Sizeof(DeltaCRDTEngine{}.routeSeed)},
		{"mergedView", unsafe.Offsetof(DeltaCRDTEngine{}.mergedView), unsafe.Sizeof(DeltaCRDTEngine{}.mergedView)},
		{"localNodeID", unsafe.Offsetof(DeltaCRDTEngine{}.localNodeID), unsafe.Sizeof(DeltaCRDTEngine{}.localNodeID)},
		{"lamportCounter", unsafe.Offsetof(DeltaCRDTEngine{}.lamportCounter), unsafe.Sizeof(DeltaCRDTEngine{}.lamportCounter)},
		{"lastSavedCounter", unsafe.Offsetof(DeltaCRDTEngine{}.lastSavedCounter), unsafe.Sizeof(DeltaCRDTEngine{}.lastSavedCounter)},
		{"persistMu", unsafe.Offsetof(DeltaCRDTEngine{}.persistMu), unsafe.Sizeof(DeltaCRDTEngine{}.persistMu)},
		{"dataDir", unsafe.Offsetof(DeltaCRDTEngine{}.dataDir), unsafe.Sizeof(DeltaCRDTEngine{}.dataDir)},
		{"participantPool", unsafe.Offsetof(DeltaCRDTEngine{}.participantPool), unsafe.Sizeof(DeltaCRDTEngine{}.participantPool)},
		{"arena", unsafe.Offsetof(DeltaCRDTEngine{}.arena), unsafe.Sizeof(DeltaCRDTEngine{}.arena)},
		{"ebr", unsafe.Offsetof(DeltaCRDTEngine{}.ebr), unsafe.Sizeof(DeltaCRDTEngine{}.ebr)},
		{"epochCounter", unsafe.Offsetof(DeltaCRDTEngine{}.epochCounter), unsafe.Sizeof(DeltaCRDTEngine{}.epochCounter)},
		{"epochAdvanceThreshold", unsafe.Offsetof(DeltaCRDTEngine{}.epochAdvanceThreshold), unsafe.Sizeof(DeltaCRDTEngine{}.epochAdvanceThreshold)},
		{"deltasGenerated", unsafe.Offsetof(DeltaCRDTEngine{}.deltasGenerated), unsafe.Sizeof(DeltaCRDTEngine{}.deltasGenerated)},
		{"deltasApplied", unsafe.Offsetof(DeltaCRDTEngine{}.deltasApplied), unsafe.Sizeof(DeltaCRDTEngine{}.deltasApplied)},
		{"entriesInserted", unsafe.Offsetof(DeltaCRDTEngine{}.entriesInserted), unsafe.Sizeof(DeltaCRDTEngine{}.entriesInserted)},
		{"entriesSkipped", unsafe.Offsetof(DeltaCRDTEngine{}.entriesSkipped), unsafe.Sizeof(DeltaCRDTEngine{}.entriesSkipped)},
	})
	fmt.Println()

	// --- Cache line analysis for DeltaCRDTEngine ---
	fmt.Println("━━━ CACHE LINE ANALYSIS (64-byte lines) ━━━")
	analyzeCacheLines("DeltaCRDTEngine", []fieldInfo{
		// Phase 2.5a: the per-shard atomic.Pointer[HAMT]s sit inside e.shards
		// (each shardRoot is its own cache-line-padded slot); the standalone
		// `state` cache line is gone. Here we surface the engine-level
		// lamport/epoch/metrics hot atomics, which remain single-shared across
		// shards (R2 §3 — sharding the HAMT root does NOT shard the LamportClock).
		{"lamportCounter", unsafe.Offsetof(DeltaCRDTEngine{}.lamportCounter), unsafe.Sizeof(DeltaCRDTEngine{}.lamportCounter)},
		{"lastSavedCounter", unsafe.Offsetof(DeltaCRDTEngine{}.lastSavedCounter), unsafe.Sizeof(DeltaCRDTEngine{}.lastSavedCounter)},
		{"epochCounter", unsafe.Offsetof(DeltaCRDTEngine{}.epochCounter), unsafe.Sizeof(DeltaCRDTEngine{}.epochCounter)},
		{"epochAdvanceThreshold", unsafe.Offsetof(DeltaCRDTEngine{}.epochAdvanceThreshold), unsafe.Sizeof(DeltaCRDTEngine{}.epochAdvanceThreshold)},
		{"deltasGenerated", unsafe.Offsetof(DeltaCRDTEngine{}.deltasGenerated), unsafe.Sizeof(DeltaCRDTEngine{}.deltasGenerated)},
		{"deltasApplied", unsafe.Offsetof(DeltaCRDTEngine{}.deltasApplied), unsafe.Sizeof(DeltaCRDTEngine{}.deltasApplied)},
		{"entriesInserted", unsafe.Offsetof(DeltaCRDTEngine{}.entriesInserted), unsafe.Sizeof(DeltaCRDTEngine{}.entriesInserted)},
		{"entriesSkipped", unsafe.Offsetof(DeltaCRDTEngine{}.entriesSkipped), unsafe.Sizeof(DeltaCRDTEngine{}.entriesSkipped)},
	})
	fmt.Println()

	// --- slabFreeHead ---
	fmt.Println("━━━ slabFreeHead ━━━")
	fmt.Printf("  sizeof(slabFreeHead) = %d bytes\n", unsafe.Sizeof(slabFreeHead{}))
	fmt.Printf("  head offset = %d\n", unsafe.Offsetof(slabFreeHead{}.head))
	fmt.Println()

	// --- HamtArena ---
	fmt.Println("━━━ HamtArena ━━━")
	fmt.Printf("  sizeof(HamtArena) = %d bytes\n", unsafe.Sizeof(HamtArena{}))
	fmt.Printf("  freeHeads offset = %d, size = %d\n",
		unsafe.Offsetof(HamtArena{}.freeHeads), unsafe.Sizeof(HamtArena{}.freeHeads))
	fmt.Printf("  bumpOffset offset = %d\n", unsafe.Offsetof(HamtArena{}.bumpOffset))
	fmt.Printf("  base offset = %d\n", unsafe.Offsetof(HamtArena{}.base))
	fmt.Println()
}

type fieldInfo struct {
	name   string
	offset uintptr
	size   uintptr
}

func printFields(structName string, fields []fieldInfo) {
	for _, f := range fields {
		fmt.Printf("  %-30s offset=%-4d size=%-4d cacheLine=%d\n",
			f.name, f.offset, f.size, f.offset/64)
	}
}

func analyzeCacheLines(structName string, fields []fieldInfo) {
	type cacheLine struct {
		lineNum int
		fields  []fieldInfo
	}
	lineMap := make(map[int]*cacheLine)
	for _, f := range fields {
		ln := int(f.offset / 64)
		if lineMap[ln] == nil {
			lineMap[ln] = &cacheLine{lineNum: ln}
		}
		lineMap[ln].fields = append(lineMap[ln].fields, f)
	}

	for ln := 0; ln <= 10; ln++ {
		if lineMap[ln] == nil {
			continue
		}
		names := ""
		for _, f := range lineMap[ln].fields {
			names += fmt.Sprintf("%s(%d-%d) ", f.name, f.offset, f.offset+f.size-1)
		}
		fmt.Printf("  Line %d (bytes %d-%d): %s", ln, ln*64, ln*64+63, names)
		if len(lineMap[ln].fields) > 1 {
			fmt.Printf(" ⚠️ FALSE SHARING RISK!")
		}
		fmt.Println()
	}
}
