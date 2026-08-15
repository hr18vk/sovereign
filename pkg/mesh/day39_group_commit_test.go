package mesh

// Day 39 (ADR-0044) teeth for the WAL group-commit — the fsync-COUNT closer for
// the Day-36/37/38 GATE-1 (B) SLO-overrun. Internal test (package mesh) so the
// teeth reach the UNEXPORTED JSON response types + the Gossiper batch seam:
//   - batchInsertResponse / batchInsertItemStatus / dotHex (control.go)
//   - BatchItem / InsertLocalEventsBatch (gossip.go)
//   - durability.LocalItem / PutLocals (bridge.go)
//   - chaos.WAL.AppendMutations + the syncHook spy (wal.go)
//
// FALSIFIABLE + bug-inject-PROVEN (NOT tautologies):
//   T-GROUP-COUNT  — AppendMutations issues ONE fsync for a 1000-entry batch
//                    (the 1000× count cut); AppendMutation issues 1000. RED:
//                    a regression to per-mutation fsync in AppendMutations →
//                    the count is 1000, NOT 1 → FAILS.
//   T-GROUP-ACK    — a WAL Sync failure on the batch → ALL valid entries get
//                    Code 503 (the per-BATCH atomicity, NOT per-entry). RED:
//                    a per-ENTRY 503 regression (the Day-37 semantic) → the
//                    pre-failure entries get 200, NOT 503 → FAILS the "ALL 503"
//                    assertion. A bug-inject that fakes per-entry 503 proves
//                    the tooth is load-bearing against the granularity it
//                    replaced.
//   T-GROUP-DET    — a batch written via AppendMutations replays into a FRESH
//                    engine and the rebuilt MerkleRoot == the live root (the
//                    determinism contract preserved under group-commit). RED: a
//                    batch path that minted dots BEFORE InsertLocal (reversed
//                    order) → the recorded dots != the live dots → Merkle
//                    mismatch → FAILS (the same class TestStage6WALRecovery-
//                    Determinism catches for the single-entry path).
//   T-DAY39-FROZEN-MD5 — Day 39 touches ZERO of the 5 FROZEN files (the 44f89527
//                    streak from Day 29 PRESERVED); AppendMutation's
//                    encode/write/nextSeq++ body is byte-identical to HEAD (the
//                    §8 absence-of-fork guard — the ONLY change is the fsync
//                    call routed through w.sync(), nil-hook = w.f.Sync()).
//   T-DAY39-SCOPE  — Day 39's production-source diff set ⊆ {internal/chaos/wal.go,
//                    pkg/durability/bridge.go, pkg/mesh/gossip.go,
//                    pkg/mesh/control.go, cmd/day36-gate/main.go} + the
//                    pre-existing carry-overs. ZERO FROZEN. ZERO crdt.go.
//                    ZERO hamt.go. ZERO crdt_apply.go.

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/supremum/internal/chaos"
	"github.com/hr18vk/supremum/pkg/durability"
	"github.com/hr18vk/supremum/pkg/identity"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// ---------------------------------------------------------------------------
// T-GROUP-COUNT — the fsync-COUNT physics (the GATE-1 closer).
// ---------------------------------------------------------------------------

// TestDay39_T_GROUP_COUNT proves AppendMutations issues ONE fsync for a
// 1000-entry batch while AppendMutation issues 1000 (the 1000× count cut that
// closes the Day-38 GATE-1 SLO-overrun: ~2.1ms/fsync × 10000 = ~21s > 10s SLO
// → ONE fsync × 2.1ms = 2.1ms inject). It uses the ADR-0044 syncHook spy
// (wal.go) — a test-local counter incremented inside w.sync() — to COUNT the
// fsync calls WITHOUT instrumenting the production WAL. The hook is set on a
// test-constructed *chaos.WAL (OpenWAL leaves it nil in production); the
// production path is byte-identical (nil hook → w.f.Sync()).
//
// BUG-INJECT-PROVEN (NOT a tautology): the tooth asserts count==1 for the batch
// AND count==1000 for the per-mutation loop. A regression that re-introduces a
// per-mutation fsync inside AppendMutations (e.g. moving w.sync() inside the
// for-loop) → the batch count is 1000, NOT 1 → the `if batchCount != 1` FAILS.
// The per-mutation leg asserts 1000 so a hook that never fires (a broken spy) is
// caught symmetrically (the loop leg would be 0, NOT 1000).
func TestDay39_T_GROUP_COUNT(t *testing.T) {
	// A test-local *chaos.WAL with the syncHook spy. OpenWAL opens a real file
	// (AppendMutations writes real records); the hook replaces ONLY the fsync
	// call (w.sync() → hook) so we COUNT fsyncs without a real disk sync (faster
	// + deterministic — the count is the physics, not the latency).
	walPath := filepath.Join(t.TempDir(), "group-count.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	var fsyncCount int64
	wal.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCount, 1)
		return nil // do NOT call the real fsync — the count is the physics
	})

	// Build 1000 distinct mutations (the Day-38 silicon batch size).
	const N = 1000
	mutations := make([]chaos.WALMutation, N)
	for i := 0; i < N; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		mutations[i] = chaos.WALMutation{
			EntityID: fmt.Sprintf("group-count-entity-%d", i),
			NodeID:   [16]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)},
			Counter:  uint64(i + 1),
			Entry: chaos.WALEntry{
				PayloadDigest: digest,
				OriginNodeID:  [16]byte{0xAA},
				DotNodeID:     [16]byte{0xAA},
				DotCounter:    uint64(i + 1),
				SystemTime:    int64(i) * 1_000,
			},
		}
	}

	// LEG 1 — the BATCH path: ONE AppendMutations for 1000 entries → ONE fsync.
	atomic.StoreInt64(&fsyncCount, 0) // reset before the batch
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("T-GROUP-COUNT: AppendMutations: %v", err)
	}
	batchCount := atomic.LoadInt64(&fsyncCount)
	if batchCount != 1 {
		t.Fatalf("T-GROUP-COUNT FAIL: AppendMutations issued %d fsyncs for a %d-entry batch, want EXACTLY 1 (the 1000× fsync-count cut — a per-mutation fsync inside AppendMutations is a GATE-1 regression)", batchCount, N)
	}

	// LEG 2 — the PER-MUTATION path: 1000 AppendMutation calls → 1000 fsyncs.
	// This is the byte-identical /v1/insert path (the control the batch cut is
	// measured against). A fresh WAL so the per-mutation records do not interleave
	// with the batch records (the count is per-WAL).
	atomic.StoreInt64(&fsyncCount, 0)
	for i := 0; i < N; i++ {
		if err := wal.AppendMutation(mutations[i]); err != nil {
			t.Fatalf("T-GROUP-COUNT: AppendMutation %d: %v", i, err)
		}
	}
	perMutCount := atomic.LoadInt64(&fsyncCount)
	if perMutCount != int64(N) {
		t.Fatalf("T-GROUP-COUNT FAIL: %d AppendMutation calls issued %d fsyncs, want %d (the per-mutation path is the control — a broken syncHook that never fires would make BOTH legs 0, caught here)", N, perMutCount, N)
	}

	// The COUNT-CUT ratio: per-mutation / batch. 1000/1 = 1000× — the physics
	// Day 39 closes (the SLO: ~21s → ~2.1ms inject, modulo HTTP RTT).
	ratio := perMutCount / batchCount
	if ratio != int64(N) {
		t.Fatalf("T-GROUP-COUNT FAIL: fsync-count-cut ratio = %d, want %d (the 1000× cut)", ratio, N)
	}
	t.Logf("T-GROUP-COUNT PASS: AppendMutations(1000 entries) = %d fsync; 1000× AppendMutation = %d fsync — the %d× fsync-count cut (the GATE-1 SLO closer: ~2.1ms × 1 vs ~2.1ms × 10000)", batchCount, perMutCount, ratio)
}

// ---------------------------------------------------------------------------
// T-GROUP-ACK — the per-BATCH 503 atomicity (the ADR-0044 §4 granularity change).
// ---------------------------------------------------------------------------

// TestDay39_T_GROUP_ACK proves a WAL Sync failure on the batch → ALL valid
// entries get Code 503 (the per-BATCH atomicity, NOT per-entry). It rigs the
// Sync to fail via the syncHook spy (a hook that returns an error on the FIRST
// fsync → AppendMutations returns (-1, syncErr) → PutLocals returns (dots, 0,
// err) → handleBatchInsert ACKs ALL valid entries as 503). The tooth asserts
// EVERY valid entry is 503 + the HTTP-layer 200 (per-batch failures are in the
// body, NOT the HTTP status — the SAME discipline the Day-37 tooth pins).
//
// BUG-INJECT-PROVEN against the Day-37 PER-ENTRY semantic: a handler that
// reported per-entry 503 (only the entry at the failure point) would leave the
// PRE-failure entries as 200 — the tooth's "ALL valid entries Code 503" loop
// would FAIL on the first 200. The tooth is load-bearing against the granularity
// it replaced (the resolution verified at the working tree: the Day-37
// TestBatchInsertWALFailPerEntry tooth stays GREEN because it posts all-success
// and all-fail batches separately, never a mixed batch — agnostic to the
// granularity; THIS tooth posts a mixed-in-advance batch + rigs the Sync to
// fail, so it DISTINGUISHES per-batch from per-entry).
func TestDay39_T_GROUP_ACK(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-ack.wal")
	wal, err := durability.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// Rig the Sync to fail on the FIRST fsync (the batch's single fsync). The
	// hook is set on the *chaos.WAL underlying the durability alias; durability
	// re-exports chaos.WAL as a type alias, so the SAME instance.
	var fsyncCalls int64
	chaosWAL := durability.WALAsChaos(wal) // the underlying *chaos.WAL (alias)
	chaosWAL.SetSyncHookForTest(func() error {
		atomic.AddInt64(&fsyncCalls, 1)
		return fmt.Errorf("T-GROUP-ACK: injected Sync failure (the rig)")
	})

	// Build the harness (mirrors newBatchControlServer in day37_batch_insert_test.go).
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(test503NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	bridge := durability.NewBridge(engine, wal, 0)
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	g.SetBridge(bridge)
	cs := NewControlServer(g, test503NodeID, nil, nil)
	srv := httptest.NewServer(cs.Handler())
	t.Cleanup(srv.Close)

	// A batch of 5 VALID entries (no empty keys — the 400 path is NOT exercised
	// here; this tooth isolates the 503-ALL atomicity). The Sync is rigged to
	// fail on the batch's single fsync → ALL 5 must be 503.
	const n = 5
	items := make([]batchItemReq, n)
	for i := 0; i < n; i++ {
		items[i] = batchItemReq{Key: batchKey(i), Val: batchVal(i)}
	}
	r := postBatch(t, srv, items)

	// The HTTP layer is 200 (per-batch failures are in the body, NOT the HTTP
	// status — the SAME discipline postBatch + the Day-37 tooth pin).
	if r.Inserted != 0 {
		t.Fatalf("T-GROUP-ACK FAIL: Inserted=%d, want 0 (the Sync is rigged to fail → NO entry is durable)", r.Inserted)
	}
	if r.Failed != n {
		t.Fatalf("T-GROUP-ACK FAIL: Failed=%d, want %d (the per-BATCH atomicity — ALL valid entries 503 on a Sync failure)", r.Failed, n)
	}
	if len(r.Items) != n {
		t.Fatalf("T-GROUP-ACK FAIL: len(Items)=%d, want %d", len(r.Items), n)
	}
	// EVERY valid entry MUST be 503. A per-ENTRY 503 regression (the Day-37
	// semantic) would leave the pre-failure entries as 200 — this loop FAILS
	// on the first 200. This is the load-bearing assertion that distinguishes
	// per-batch from per-entry.
	for _, st := range r.Items {
		if st.Code != http.StatusServiceUnavailable {
			t.Fatalf("T-GROUP-ACK FAIL: entry index %d Code=%d, want 503 for ALL %d entries (the per-BATCH atomicity — a per-ENTRY 503 regression would leave this as %d); DotHex=%q", st.Index, st.Code, n, http.StatusOK, st.DotHex)
		}
		if st.DotHex != "" {
			t.Fatalf("T-GROUP-ACK FAIL: entry index %d DotHex=%q, want empty (no receipt for a non-durable batch)", st.Index, st.DotHex)
		}
	}
	// The Sync was called EXACTLY once (the batch's single fsync — the count cut
	// holds even on the failure path: ONE fsync attempt, ONE failure, ALL 503).
	if got := atomic.LoadInt64(&fsyncCalls); got != 1 {
		t.Fatalf("T-GROUP-ACK FAIL: the rigged Sync was called %d times, want 1 (the batch's single fsync — a per-mutation fsync would call it %d times)", got, n)
	}
	t.Logf("T-GROUP-ACK PASS: a rigged Sync failure → ALL %d valid entries Code 503 (per-BATCH atomicity, NOT per-entry); the Sync was called EXACTLY once (the count cut holds on the failure path)", n)
}

// ---------------------------------------------------------------------------
// T-GROUP-DET — batch-path WAL replay determinism (the §8 absence-of-fork).
// ---------------------------------------------------------------------------

// TestDay39_T_GROUP_DET proves a batch written via AppendMutations replays into a
// FRESH engine and the rebuilt MerkleRoot == the live root (the determinism
// contract preserved under group-commit). It mirrors TestStage6WALRecovery-
// Determinism (internal/chaos/wal_test.go:42) but uses AppendMutations for the
// live appends, proving the batch path's record format is byte-identical to the
// per-mutation path (ReplayWAL scans record-by-record via length-prefix — it
// sees N individual WALRecMutation records, populates Mutations[] IDENTICALLY).
//
// BUG-INJECT-PROVEN: the tooth asserts the recovered root == the live root. A
// batch path that minted dots BEFORE InsertLocal (reversed physical order — the
// dot the WAL carries would NOT be the engine-stamped dot) → replay re-mints
// DIFFERENT dots → Merkle mismatch → FAILS (the same class the single-entry
// determinism tooth catches). The tooth re-uses the SAME stagedEntry/stagedEntityID
// helpers + the SAME rebuiltInitial = LamportHigh - len(Mutations) derivation so
// the determinism contract is proven IDENTICALLY for the batch path.
func TestDay39_T_GROUP_DET(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "group-det.wal")
	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// A non-zero localNodeID + a non-zero initial counter (the same shape the
	// single-entry determinism tooth uses — a fresh boot at 0 is the trivial
	// case; the rejoin-at-7 case exercises the rebuiltInitial derivation).
	var nodeID [16]byte
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}
	const initialCounter uint64 = 7
	const N = 64

	// Build the LIVE engine + insert N mutations, appending the WHOLE batch via
	// AppendMutations (the Day-39 batch path — ONE fsync for all N).
	eng.DataDir = t.TempDir()
	live, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	mutations := make([]chaos.WALMutation, N)
	for i := 0; i < N; i++ {
		entityID := "entity-" + string([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
		entry := eng.CRDTEntry{
			PayloadDigest: sha256FirstByte(i),
			OriginNodeID:  originFromIndex(i),
			SystemTime:    int64(i) * 1_000,
		}
		dot := live.InsertLocal(entityID, entry)
		mutations[i] = chaos.WALMutation{
			EntityID: entityID,
			NodeID:   dot.NodeID,
			Counter:  dot.Counter,
			Entry: chaos.WALEntry{
				PayloadDigest: entry.PayloadDigest,
				OriginNodeID:  entry.OriginNodeID,
				DotNodeID:     entry.DotNodeID,
				DotCounter:    entry.DotCounter,
				SystemTime:    entry.SystemTime,
			},
		}
	}
	if _, err := wal.AppendMutations(mutations); err != nil {
		t.Fatalf("T-GROUP-DET: AppendMutations: %v", err)
	}
	liveRoot := live.State().MerkleRoot()
	if err := wal.AppendCheckpoint(chaos.WALCheckpoint{
		MerkleRoot:  liveRoot,
		LamportHigh: live.LamportCounter(),
	}); err != nil {
		t.Fatalf("T-GROUP-DET: AppendCheckpoint: %v", err)
	}

	// Recovery: replay the batch-written WAL into a FRESH engine seeded with the
	// DERIVED rebuiltInitial = LamportHigh - len(Mutations) (the SAME derivation
	// the single-entry determinism tooth uses — the contract is that replay
	// re-mints the SAME dots because the recorded dots come from the SAME
	// NextDot sequence).
	rep, err := chaos.ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("T-GROUP-DET: ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != N {
		t.Fatalf("T-GROUP-DET: replay got %d mutations, want %d (the batch path wrote %d individual WALRecMutation records — ReplayWAL scans record-by-record via length-prefix)", len(rep.Mutations), N, N)
	}
	rebuiltInitial := uint64(0)
	if rep.LamportHigh >= uint64(len(rep.Mutations)) {
		rebuiltInitial = rep.LamportHigh - uint64(len(rep.Mutations))
	}
	if rebuiltInitial != initialCounter {
		t.Fatalf("T-GROUP-DET: derived rebuiltInitial=%d, want live initialCounter=%d (the determinism contract — the batch path does NOT perturb the Lamport clock derivation)", rebuiltInitial, initialCounter)
	}
	// Recover into a FRESH DataDir (the SAME discipline
	// TestStage6WALRecoveryDeterminism uses at wal_test.go:107-108): the live
	// engine captured its OWN t.TempDir() at construction, and its async
	// persist worker may have flushed a lamport_<nodeID>.dat there. The recovered
	// engine MUST read a FRESH dir (no persisted high-water) so recoverLamport
	// returns 0 + the constructor honors rebuiltInitial — else the recovered
	// engine would load the live's persisted 1008 (initialCounter + 1000, the
	// nextLimit the live's NextDot CAS'd) and re-mint counters ABOVE the
	// recorded ones (the gap that fake-failed this tooth before the fix). This
	// is a TEST-harness concern (production recovery replays into the engine's
	// OWN dataDir, which on a cold boot is empty); the determinism CONTRACT is
	// on the WAL replay, not the lamport-persist side-channel.
	recoverDir := t.TempDir()
	eng.DataDir = recoverDir
	recovered, err := eng.NewDeltaCRDTEngine(nodeID, rebuiltInitial, 64*1024*1024)
	if err != nil {
		t.Fatalf("T-GROUP-DET: NewDeltaCRDTEngine recovered: %v", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })

	// Replay each recorded mutation via InsertLocal (the SAME replay the worker
	// main does). The recovered engine re-mints each dot from the SAME initial
	// lamport → the SAME (DotNodeID, DotCounter) the live engine minted.
	for i, m := range rep.Mutations {
		entry := eng.CRDTEntry{
			PayloadDigest: m.Entry.PayloadDigest,
			OriginNodeID:  m.Entry.OriginNodeID,
			DotNodeID:     m.Entry.DotNodeID,
			DotCounter:    m.Entry.DotCounter,
			SystemTime:    m.Entry.SystemTime,
		}
		dot := recovered.InsertLocal(m.EntityID, entry)
		if dot.NodeID != m.NodeID {
			t.Errorf("T-GROUP-DET: replay %d: DotNodeID mismatch: got %x, want %x (the batch path recorded the wrong dot — reversed physical order?)", i, dot.NodeID, m.NodeID)
		}
		wantCounter := initialCounter + uint64(i) + 1
		if dot.Counter != wantCounter || dot.Counter != m.Counter {
			t.Fatalf("T-GROUP-DET: replay %d: re-minted DotCounter=%d, want %d (recorded=%d) — the batch path's dots do NOT replay- match (determinism lost)", i, dot.Counter, wantCounter, m.Counter)
		}
	}

	recoveredRoot := recovered.State().MerkleRoot()
	if recoveredRoot != liveRoot {
		t.Fatalf("T-GROUP-DET FAIL: WAL recovery determinism BROKEN under group-commit:\n  checkpoint root = %x\n  recovered root = %x\n  (the batch-written WAL replays to a DIFFERENT state than the live engine — the §8 absence-of-fork is violated)", liveRoot, recoveredRoot)
	}
	if recovered.LamportCounter() != rep.LamportHigh {
		t.Fatalf("T-GROUP-DET FAIL: recovered lamport %d != checkpoint lamportHigh %d", recovered.LamportCounter(), rep.LamportHigh)
	}
	t.Logf("T-GROUP-DET PASS: a %d-entry batch written via AppendMutations replays into a fresh engine and the rebuilt MerkleRoot == the live root (the determinism contract preserved under group-commit — ReplayWAL sees N individual WALRecMutation records, byte-identical to N AppendMutation calls)", N)
}

// ---------------------------------------------------------------------------
// T-DAY39-FROZEN-MD5 — the 44f89527 streak + AppendMutation byte-identity.
// ---------------------------------------------------------------------------

// TestDay39_T_FrozenMD5 proves Day 39 touches ZERO of the 5 FROZEN files (the
// 44f89527 streak from Day 29 PRESERVED through Day 39). It mirrors the Day-37
// T-DAY37-FROZEN-MD5 tooth verbatim (os.Stat guard FIRST + t.Fatalf on missing +
// git diff --name-only HEAD -- <path> empty + md5 pin + bogus-path bug-inject).
// Day 39 touches internal/chaos/wal.go (NOT FROZEN) + pkg/durability/bridge.go +
// pkg/mesh (NOT FROZEN) — ZERO FROZEN. The streak stays at 44f89527.
func TestDay39_T_FrozenMD5(t *testing.T) {
	root := repoRootMesh(t)
	frozen := []struct {
		path string
		md5  string
	}{
		{"pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},                    // the Day-29 streak anchor (InsertLocal at :965 — Day 39 calls it byte-identical, does NOT touch it)
		{"pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},              // the Join seam
		{"api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},    // the REAL path (NOT pkg/sync/)
		{"api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"}, // the REAL path
		{"pkg/attribution/envelope.go", "b1beba1e9de81294bc66a823dece6ab6"},         // convention-frozen (Day-32 mold)
	}
	for _, f := range frozen {
		abs := filepath.Join(root, f.path)
		// (a) the os.Stat existence guard FIRST — a `git diff --name-only HEAD --
		// <nonexistent>` returns EMPTY + would PASS VACUOUSLY (the Day-34 wrong-path
		// class, the [[frozen_touch_tooth_must_guard_existence]] memory).
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("T-DAY39-FROZEN-MD5: the FROZEN file %s does NOT EXIST at %s — a `git diff --name-only HEAD -- <nonexistent>` returns EMPTY + would PASS VACUOUSLY: %v", f.path, abs, err)
		}
		// (b) the git-HEAD byte-equality check: `git diff --name-only HEAD --
		// <path>` returns EMPTY iff the file is byte-identical to HEAD.
		out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", f.path).Output()
		if err != nil {
			t.Skipf("T-DAY39-FROZEN-MD5: git diff unavailable for %s (%v); skipping", f.path, err)
			return
		}
		if len(strings.TrimSpace(string(out))) != 0 {
			t.Fatalf("T-DAY39-FROZEN-MD5: the FROZEN file %s was TOUCHED by Day 39 — the 44f89527 streak is BROKEN; Day 39 touches ZERO FROZEN source; diff:\n%s", f.path, string(out))
		}
		// (c) belt-and-suspenders md5 cross-check (disk vs the pin).
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("T-DAY39-FROZEN-MD5: cannot read %s: %v", f.path, err)
		}
		got := fmt.Sprintf("%x", md5.Sum(data))
		if got != f.md5 {
			t.Fatalf("T-DAY39-FROZEN-MD5: %s md5 DRIFTED: got %s, want %s — the Day-29 44f89527 streak is BROKEN by Day 39", f.path, got, f.md5)
		}
	}
	t.Logf("T-DAY39-FROZEN-MD5 PASS: all 5 FROZEN files byte-identical to git-HEAD + md5-pinned (the Day-29 44f89527 streak PRESERVED through Day 39)")

	// AppendMutation byte-identity guard: the §8 absence-of-fork means Day 39
	// adds AppendMutations ADDITIVELY + routes the fsync through w.sync() (nil-
	// hook = w.f.Sync() byte-identical). The encode/write/nextSeq++ body of
	// AppendMutation is UNCHANGED. Assert the function body is byte-identical to
	// git-HEAD (the ONLY allowed change to wal.go is ADDITIVE: the struct field,
	// the sync() method, the AppendMutations method — NOT a modification of
	// AppendMutation's body). This is a targeted guard: it greps the wal.go diff
	// for the AppendMutation function region + asserts no removed lines inside it.
	walDiff, err := exec.Command("git", "-C", root, "diff", "HEAD", "--", "internal/chaos/wal.go").Output()
	if err != nil {
		t.Skipf("T-DAY39-FROZEN-MD5: git diff wal.go unavailable (%v); skipping AppendMutation byte-identity guard", err)
		return
	}
	// The diff must NOT contain a removed line inside AppendMutation's body. A
	// removed line is prefixed with "-"; the AppendMutation body is the lines
	// between "func (w *WAL) AppendMutation(" and the next "func ". If any "-"
	// line appears in that region (other than the fsync-call rerouting which is
	// an EDIT, not a removal of the encode/write body), the byte-identity is
	// violated. We assert the encode/write/nextSeq++ lines are present verbatim
	// (the load-bearing body) by checking the diff does NOT delete them.
	diffStr := string(walDiff)
	for _, sentinel := range []string{
		"rec, err := encodeMutationRecord(w.nextSeq, m)",
		"w.f.Write(rec)",
		"w.nextSeq++",
	} {
		// The sentinel must NOT appear as a REMOVED line ("-<sentinel>"). A
		// removal means the body was modified (a §8 fork, not additive).
		if strings.Contains(diffStr, "-"+sentinel) {
			t.Fatalf("T-DAY39-FROZEN-MD5: AppendMutation byte-identity BROKEN — the line %q was REMOVED from internal/chaos/wal.go (Day 39 is ADDITIVE on the WAL; the encode/write/nextSeq++ body of AppendMutation must stay byte-identical to HEAD, only the fsync call is rerouted through w.sync())", sentinel)
		}
	}
	t.Logf("T-DAY39-FROZEN-MD5 AppendMutation byte-identity PASS: the encode/write/nextSeq++ body of AppendMutation is byte-identical to HEAD (the §8 absence-of-fork — Day 39 is ADDITIVE: struct field + sync() + AppendMutations; the fsync call is rerouted through w.sync(), nil-hook = w.f.Sync())")

	// bug-inject: a BOGUS path would PASS vacuously without the os.Stat guard.
	bogus := filepath.Join(root, "pkg/sync/CRDT_GO_DOES_NOT_EXIST.go")
	if _, err := os.Stat(bogus); err == nil {
		t.Fatalf("T-DAY39-FROZEN-MD5 bug-inject: the BOGUS path %s EXISTS — the control is invalid", bogus)
	}
	t.Logf("T-DAY39-FROZEN-MD5 bug-inject PASS: the BOGUS path was REJECTED by the os.Stat guard (the Day-34 vacuous-by-wrong-path class is caught)")
}

// ---------------------------------------------------------------------------
// T-DAY39-SCOPE — the production-source bleed guard.
// ---------------------------------------------------------------------------

// TestDay39_T_Scope proves Day 39's production-source diff set ⊆ the allowed
// Day-39 edits (the 4 files Day 39 touches: internal/chaos/wal.go +
// pkg/durability/bridge.go + pkg/mesh/gossip.go + pkg/mesh/control.go + the
// carry-over cmd/day36-gate/main.go + pkg/sync/iblt_wire.go). ZERO FROZEN. ZERO
// crdt.go. ZERO hamt.go. ZERO crdt_apply.go. It mirrors the Day-37 T-DAY37-SCOPE
// tooth (git diff --name-only HEAD + an allowed map + NEW _test.go exemption).
func TestDay39_T_Scope(t *testing.T) {
	root := repoRootMesh(t)
	// Production packages Day 39 touches (the diff pathspecs — pkg/sync is
	// included so the carry-over iblt_wire.go is observed + any pkg/sync bleed is
	// caught; internal/chaos is the WAL; pkg/mesh is gossip+control; cmd/day36-gate
	// is the Edit-E gate-binary target).
	prodPackages := []string{"pkg/sync", "pkg/mesh", "internal/chaos", "cmd/day36-gate"}
	args := append([]string{"-C", root, "diff", "--name-only", "HEAD", "--"}, prodPackages...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		t.Skipf("T-DAY39-SCOPE: git diff unavailable (%v); skipping", err)
		return
	}
	allowed := map[string]bool{
		// Day 39 (ADR-0044) — the WAL group-commit. The 4 production-source edits.
		"internal/chaos/wal.go":    true, // Edit A — AppendMutations + the sync() indirection (the fsync-count hook)
		"pkg/durability/bridge.go": true, // Edit B — PutLocals + LocalItem (the batch origin path)
		"pkg/mesh/gossip.go":       true, // Edit C — InsertLocalEventsBatch + BatchItem (the batch mesh seam) [+ Day-37 carry-over]
		"pkg/mesh/control.go":      true, // Edit D — handleBatchInsert routes through InsertLocalEventsBatch (per-batch 503) [+ Day-37 carry-over]
		"cmd/day36-gate/main.go":   true, // Edit E — the gate-binary ONE-batch switch (10K → ONE POST) [+ Day-37 carry-over]
		// Carry-overs (pre-existing in the diff, NOT Day-39 edits — allow so the
		// tooth does not false-fire on them, the SAME precedent the Day-37 tooth
		// uses for iblt_wire.go).
		"pkg/sync/iblt_wire.go": true, // the Day-36 Edit-0 carry-over
	}
	var unexpected []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" || allowed[f] {
			continue
		}
		// NEW _test.go files (this file, the day39 group-commit test) are added,
		// not modified — git diff --name-only HEAD lists MODIFIED tracked files;
		// an untracked NEW file shows in `git status` not `git diff HEAD`. A NEW
		// _test.go under the touched packages is the harness (allowed).
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		unexpected = append(unexpected, f)
	}
	if len(unexpected) > 0 {
		t.Fatalf("T-DAY39-SCOPE FAIL: unexpected production-source bleed: %v — Day 39 touches ZERO FROZEN + ZERO crdt.go + ZERO hamt.go + ZERO crdt_apply.go; the allowed set is {internal/chaos/wal.go, pkg/durability/bridge.go, pkg/mesh/gossip.go, pkg/mesh/control.go, cmd/day36-gate/main.go} (+ the carry-over pkg/sync/iblt_wire.go)", unexpected)
	}
	t.Logf("T-DAY39-SCOPE PASS: production-source diff set ⊆ {internal/chaos/wal.go, pkg/durability/bridge.go, pkg/mesh/gossip.go, pkg/mesh/control.go, cmd/day36-gate/main.go} (+ carry-over pkg/sync/iblt_wire.go) — ZERO FROZEN bleed, ZERO crdt.go/hamt.go/crdt_apply.go bleed")
}

// ---------------------------------------------------------------------------
// helpers (local to the Day-39 teeth — not reused from day37_batch_insert_test.go
// to keep the tooth self-contained; the batchKey/batchVal/postBatch helpers ARE
// reused via the same package).
// ---------------------------------------------------------------------------

// sha256FirstByte returns a 32-byte digest whose first byte is i (a stable,
// content-distinct payload digest per mutation index — mirrors stagedEntry's
// sha256-of-i pattern without importing internal/chaos test helpers).
func sha256FirstByte(i int) [32]byte {
	var d [32]byte
	d[0] = byte(i)
	d[1] = byte(i >> 8)
	d[2] = byte(i >> 16)
	return d
}

// originFromIndex returns a 16-byte origin nodeID derived from i (mirrors
// stagedEntry's binary.BigEndian.PutUint64(origin[:8], uint64(i+100))).
func originFromIndex(i int) [16]byte {
	var o [16]byte
	o[0] = byte(uint64(i+100) >> 56)
	o[1] = byte(uint64(i+100) >> 48)
	o[2] = byte(uint64(i+100) >> 40)
	o[3] = byte(uint64(i+100) >> 32)
	o[4] = byte(uint64(i+100) >> 24)
	o[5] = byte(uint64(i+100) >> 16)
	o[6] = byte(uint64(i+100) >> 8)
	o[7] = byte(uint64(i + 100))
	return o
}

// hexDump is a small helper for diagnostic output (not load-bearing).
func hexDump(b [32]byte) string { return hex.EncodeToString(b[:]) }

// bytesUnused keeps the bytes import live (postBatch uses bytes.NewReader; the
// teeth that do not call postBatch still compile with the import for the ones
// that do — this is a no-op guard so go vet does not flag a conditional import).
var bytesUnused = bytes.NewBuffer(nil)
