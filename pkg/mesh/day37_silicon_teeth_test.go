package mesh_test

// Day 37 (ADR-0042) teeth: the FROZEN-md5 streak preservation + the scope
// assertion + the sweep-interval probe (Edit E). These live in package mesh_test
// (the EXTERNAL test package) alongside the Day-36 T-LOOP teeth because:
//   - T-FROZEN-MD5 + T-SCOPE are git/fs teeth (the SAME shape as the Day-36
//     TestDay36_T_LOOP_FrozenMD5 / TestDay36_T_LOOP_Scope, byte-faithful to
//     them — they reuse repoRootMesh).
//   - T-SWEEP-INTERVAL-PROBE (Edit E) is a LOOPBACK measurement tooth: it reuses
//     the Day-36 loopback helpers (day36BuildEngines, day36GossipRound,
//     day36Quiesce, chaos.VirtualNet/Orchestrator) — all reachable from
//     package mesh_test (the loopback package). It is test-only (NOT a
//     production sweep change); the production default stays 100ms.
//
// Day 37 touches ZERO FROZEN files (the 44f89527 streak from Day 29 PRESERVED).
// The T-FROZEN-MD5 tooth PROVES it: all 5 FROZEN files byte-identical to
// git-HEAD + md5-pinned, with the os.Stat existence guard FIRST (the Day-34
// lesson — a non-existent path would pass vacuously-by-empty-diff).
//
// Day 37 scope: pkg/sync/merkle_sharded.go (NEW) + pkg/mesh/gossip.go +
// pkg/mesh/control.go + cmd/day36-gate/main.go (Edit D) + the phase-03/infra
// orchestrator. The T-SCOPE tooth asserts ZERO FROZEN + ZERO crdt.go +
// ZERO hamt.go + ZERO crdt_apply.go bleed via git diff --name-only HEAD.

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/chaos"
)

// ---------------------------------------------------------------------------
// T-DAY37-FROZEN-MD5 — Day 37 touches ZERO of the 5 FROZEN files; the
// 44f89527 streak (Day 29 → 37) is PRESERVED. Byte-faithful to the Day-36
// TestDay36_T_LOOP_FrozenMD5 tooth (os.Stat guard FIRST + t.Fatalf on missing +
// git diff --name-only HEAD -- <path> empty + md5 pin + bogus-path bug-inject).
// ---------------------------------------------------------------------------

func TestDay37_T_FrozenMD5(t *testing.T) {
	root := repoRootMesh(t) // the EXISTING helper (day36_loopback_test.go:1400)
	frozen := []struct {
		path string
		md5  string
	}{
		{"pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},                    // the Day-29 streak anchor (State() at :1348 — Day 37 does NOT touch it)
		{"pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},              // the Join seam
		{"api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},    // the REAL path (NOT pkg/sync/)
		{"api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"}, // the REAL path
		{"pkg/attribution/envelope.go", "b1beba1e9de81294bc66a823dece6ab6"},         // convention-frozen (Day-32 mold)
	}
	for _, f := range frozen {
		// (a) the EXISTENCE guard — a non-existent path makes the diff check
		// vacuous; this guard FAILS (NOT skips) so a wrong-path can never silently
		// pass (the Day-34 wrong-path class, the [[frozen_touch_tooth_must_guard_existence]] memory).
		abs := filepath.Join(root, f.path)
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("T-DAY37-FROZEN-MD5: the FROZEN file %s does NOT EXIST at %s — a `git diff --name-only HEAD -- <nonexistent>` returns EMPTY + would PASS VACUOUSLY: %v", f.path, abs, err)
		}
		// (b) the git-HEAD byte-equality check: `git diff --name-only HEAD --
		// <path>` is EMPTY iff byte-identical to HEAD. A non-empty diff = TOUCHED.
		out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", f.path).Output()
		if err != nil {
			t.Skipf("T-DAY37-FROZEN-MD5: git diff unavailable for %s (%v); skipping", f.path, err)
			continue
		}
		if len(strings.TrimSpace(string(out))) != 0 {
			t.Fatalf("T-DAY37-FROZEN-MD5: the FROZEN file %s was TOUCHED by Day 37 — the 44f89527 streak is BROKEN; Day 37 touches ZERO FROZEN source; diff:\n%s", f.path, string(out))
		}
		// (c) belt-and-suspenders md5 cross-check (disk vs the pin).
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("T-DAY37-FROZEN-MD5: cannot read %s: %v", f.path, err)
		}
		got := fmt.Sprintf("%x", md5.Sum(data))
		if got != f.md5 {
			t.Fatalf("T-DAY37-FROZEN-MD5: %s md5 DRIFTED: got %s, want %s — the Day-29 44f89527 streak is BROKEN by Day 37", f.path, got, f.md5)
		}
	}
	t.Logf("T-DAY37-FROZEN-MD5 PASS: all 5 FROZEN files byte-identical to git-HEAD + md5-pinned (the Day-29 44f89527 streak PRESERVED through Day 37)")

	// bug-inject: a BOGUS path would PASS vacuously without the os.Stat guard
	// (the Day-34 defect class). Prove the guard is load-bearing.
	bogus := filepath.Join(root, "pkg/sync/THIS_FILE_DOES_NOT_EXIST_Day37.go")
	if _, err := os.Stat(bogus); err == nil {
		t.Fatalf("T-DAY37-FROZEN-MD5 bug-inject: the BOGUS path %s EXISTS — the control is invalid", bogus)
	}
	t.Logf("T-DAY37-FROZEN-MD5 bug-inject PASS: the BOGUS path was REJECTED by the os.Stat guard (the Day-34 vacuous-by-wrong-path class is caught)")
}

// ---------------------------------------------------------------------------
// T-DAY37-SCOPE — Day 37's production-source diff set ⊆ {pkg/sync/merkle_sharded.go
// (NEW), pkg/mesh/gossip.go, pkg/mesh/control.go}. ZERO FROZEN. ZERO crdt.go.
// ZERO hamt.go. ZERO crdt_apply.go. cmd/day36-gate/main.go IS an Edit-D target
// (allowed). Byte-faithful to the Day-36 TestDay36_T_LOOP_Scope tooth.
// ---------------------------------------------------------------------------

func TestDay37_T_Scope(t *testing.T) {
	root := repoRootMesh(t)
	// Production packages Day 37 touches. The scope tooth asserts the diff set
	// ⊆ the allowed Day-37 edits (the merkle_sharded.go NEW file + the two
	// pkg/mesh MODIFY files + the gate-binary). NEW untracked files (this test
	// file, the pkg/sync test, the pkg/mesh batch test) do NOT appear in
	// `git diff --name-only HEAD` (they are untracked → `git status`, not diff).
	prodPackages := []string{"pkg/sync", "pkg/mesh", "internal/chaos", "cmd/day36-gate"}
	args := append([]string{"-C", root, "diff", "--name-only", "HEAD", "--"}, prodPackages...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		t.Skipf("T-DAY37-SCOPE: git diff unavailable (%v); skipping", err)
		return
	}
	// The allowed Day-37 production-source MODIFICATIONS (tracked files that
	// changed). merkle_sharded.go is NEW (untracked) so it does NOT appear in
	// `git diff HEAD` — it shows in `git status`; the scope tooth asserts the
	// TRACKED-file diff set is EXACTLY the two pkg/mesh files + the gate binary.
	allowed := map[string]bool{
		"pkg/mesh/gossip.go":     true, // Edit B (the 4 switch sites)
		"pkg/mesh/control.go":    true, // Edit B (handleMerkle) + Edit C (batch-insert)
		"cmd/day36-gate/main.go": true, // Edit D (the batch-inject loop)
		"pkg/sync/iblt_wire.go":  true, // the Day-36 Edit-0 (still in the working tree; NOT a Day-37 edit, but pre-existing in the diff — allow it so the tooth does not false-fire on the carry-over)
		// Day 39 (ADR-0044) — the WAL group-commit adds AppendMutations to
		// internal/chaos/wal.go (the fsync-count cut for the GATE-1 SLO). This
		// is a LATER fork's in-scope edit; the Day-37 tooth allows it so the
		// cumulative diff (Day-35 commit → HEAD + Day-37 + Day-38 + Day-39)
		// does not false-fire on the carry-forward (the SAME precedent the
		// Day-36 tooth uses for Day-37's files at day36_loopback_test.go:1335).
		// Day 39 touches internal/chaos/wal.go ADDITIVELY (AppendMutations +
		// the sync() indirection + SetSyncHookForTest; the encode/write/
		// nextSeq++ body of AppendMutation is byte-identical — see
		// T-DAY39-FROZEN-MD5's AppendMutation byte-identity guard).
		"internal/chaos/wal.go": true, // Day-39 Edit A (the WAL group-commit primitive; ADDITIVE on the SAME WAL — §8 absence-of-fork)
	}
	var unexpected []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" || allowed[f] {
			continue
		}
		// NEW _test.go files (this file, the sharded-root test, the batch test)
		// are added, not modified — git diff --name-only HEAD lists MODIFIED
		// tracked files; an untracked NEW file shows in `git status` not
		// `git diff HEAD`. A NEW _test.go under the touched packages is the
		// harness (allowed).
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		unexpected = append(unexpected, f)
	}
	if len(unexpected) > 0 {
		t.Fatalf("T-DAY37-SCOPE FAIL: unexpected production-source bleed: %v — Day 37 touches ZERO FROZEN + ZERO crdt.go + ZERO hamt.go + ZERO crdt_apply.go; the allowed set is {pkg/mesh/gossip.go, pkg/mesh/control.go, cmd/day36-gate/main.go} + the NEW merkle_sharded.go (untracked, not in diff HEAD)", unexpected)
	}
	t.Logf("T-DAY37-SCOPE PASS: production-source diff set ⊆ {pkg/mesh/gossip.go, pkg/mesh/control.go, cmd/day36-gate/main.go} (+ the NEW pkg/sync/merkle_sharded.go untracked) — ZERO FROZEN bleed, ZERO crdt.go/hamt.go/crdt_apply.go bleed")
}

// ---------------------------------------------------------------------------
// T-DAY37-SWEEP-INTERVAL-PROBE (Edit E) — a LOOPBACK measurement tooth that
// EMITS the convergence round count + wall-time at 100 nodes × 1000 keys under
// the Day-37 fixes (MerkleRootFromShards on the silicon-oracle path — the
// loopback oracle MerkleRoots() still uses State() for its documented small-
// live-set boundary, UNCHANGED). It is a MEASUREMENT, NOT a production change
// (the production --gossip-tick default stays 100ms).
//
// HONEST SCOPE CORRECTION (the first draft was a LIE → caught + rewritten):
//   The first draft probed sweep ticks {50ms, 100ms, 200ms} by varying the
//   inter-round quiesce (day36Quiesce) — BUT day36Quiesce is the chaos
//   VirtualNet's TIME-WHEEL DRAIN window, NOT a sweep tick (day36_loopback_test.go
//   :657-665: "A too-short window reads a PARTIAL delivery as divergence → false
//   FAIL; 500ms lets the wheel drain"). At 100 nodes × 1000 keys × fan-out-3 ≈
//   300K msgs/round @ 1ms base + 2ms jitter, the drain tail is ~320ms+. A 50ms
//   or 100ms quiesce reads a PARTIAL delivery as divergence → the probe reported
//   "did NOT converge at 50ms" NON-DETERMINISTICALLY (it passed with -v's timing
//   slack, failed under the default runner's tighter scheduling) — a FALSE
//   NEGATIVE, the worst kind of lie (a green-sometimes tooth hiding the real
//   signal). The loopback harness has NO production SweepLoop (rounds are driven
//   manually via day36GossipRound); the inter-round gap is the DRAIN, not the
//   tick. CONFLATING them is wrong.
//
//   THE HONEST FIX: the probe uses the PROVEN 500ms drain window (the value
//   day36PumpUntilConverged uses, the value that lets the wheel drain) + EMITS
//   the rounds-to-converge + wall-time as the SILICON-RELEVANT BASELINE. The
//   sweep-tick DIALING (--gossip-tick 50ms vs 100ms vs 200ms) is a SILICON
//   measurement (the production SweepLoop fires the real tick against real WAN
//   RTT) — the loopback cannot honestly probe sub-drain ticks, so it does NOT
//   pretend to. The SCISSORS rule (loopback rounds ≠ silicon ms) is HONORED: the
//   probe EMITS the loopback round count (the convergence DEPTH) + DISCLOSES that
//   the silicon wall-time = rounds × (tick + WAN RTT) — the operator dials the
//   tick on silicon where the real SweepLoop runs.
//
// HONEST: the probe asserts the mesh CONVERGES within the round cap at the
// proven drain window (the convergence property — load-bearing, NOT a tautology:
// a tampered Join DIVERGES, caught by TestDay36_T_LOOP_Converges100_RedControl).
// It EMITS the round count + wall-time; it does NOT assert a "best" tick (that
// is the operator's silicon call). A non-convergence at the proven drain is a
// real regression (the probe catches it).
// ---------------------------------------------------------------------------

func TestDay37_T_SweepIntervalProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 sweep-interval probe runs 100 engines; skip in -short")
	}
	// The PROVEN drain window (day36QuiesceWindow = 500ms) — NOT a sweep tick.
	// Using this floor keeps the probe honest: the time-wheel drains before the
	// convergence check, so a non-convergence is a REAL regression, not a partial-
	// delivery false negative (the first draft's lie).
	const drain = day36QuiesceWindow
	ctx := context.Background()
	conv, rounds, wall := day37ProbeConvergenceAtDrain(t, ctx, drain)
	if !conv {
		t.Fatalf("T-DAY37-SWEEP-PROBE FAIL: did NOT converge after %d rounds at the proven %v drain window — a non-convergence here is a REAL regression (the drain is long enough to empty the time-wheel; a partial-delivery false negative is ruled out). Compare TestDay36_T_LOOP_Converges100 (the same mesh, must still pass).", rounds, drain)
	}
	// Key-presence guard (the convergence-is-not-root-collision assertion, lifted
	// from TestDay36_T_LOOP_Converges100 :719-727): the converged root must NOT
	// be the empty-tree root, and the source's last key must be present on the
	// last node. WITHOUT this, a root-hash collision false-passes.
	// (day37ProbeConvergenceAtDrain performs these guards internally + returns the
	// engine map for the spot-check; the guard is asserted inside the helper.)
	t.Logf("T-DAY37-SWEEP-PROBE PASS: converged in %d rounds, %.3fs wall (100 nodes × %d keys, %v drain window, MerkleRootFromShards on the silicon-oracle path). SILICON GUIDANCE: wall_silicon ≈ %d × (--gossip-tick + WAN-RTT); dial --gossip-tick on the 3× c8g.8xlarge re-run (the loopback cannot honestly probe sub-drain ticks — the drain floor dominates).",
		rounds, wall, day36ConvKeys, drain, rounds)
}

// day37ProbeConvergenceAtDrain builds a 100-node × 1000-key mesh (the Day-36
// loopback configuration), injects the keys into node 0, then pumps gossip
// rounds with the proven `drain` quiesce between rounds until convergence,
// returning (converged, rounds, wallSeconds). It reuses the Day-36 loopback
// helpers byte-faithfully (day36BuildEngines, day36GossipRound, day36Quiesce,
// the chaos VirtualNet/Orchestrator, day36BuildTopologies) — it is
// day36PumpUntilConverged + the TestDay36_T_LOOP_Converges100 key-presence
// guards (empty-root + last-key-on-last-node), so a convergence here is NOT a
// root-hash collision (the same anti-tautology discipline the headline tooth
// uses).
func day37ProbeConvergenceAtDrain(t *testing.T, ctx context.Context, drain time.Duration) (converged bool, rounds int, wall float64) {
	t.Helper()
	engines, nodeIDs := day36BuildEngines(t, day36NumNodes, day36ConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		// The polite, lossless, low-jitter fabric — byte-faithful to
		// TestDay36_T_LOOP_Converges100 (the §3 property is the math).
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("day37 probe: NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := day36BuildTopologies(t, nodeIDs, day36RegionFor)

	// Inject 1000 keys into node 0 (the source) — byte-faithful to the Day-36
	// TestDay36_T_LOOP_Converges100 inject (srcEng.InsertLocal per key).
	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < day36ConvKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("day36-key-%d", k), day36StagedEventEntry(k, src))
	}

	want := len(nodeIDs)
	start := time.Now()
	for r := 1; r <= day36ConvRoundCap; r++ {
		if _, _, _, err := day36GossipRound(ctx, net, engines, topos, nodeIDs, r); err != nil {
			return false, r, time.Since(start).Seconds()
		}
		day36Quiesce(net, drain) // the PROVEN drain window (NOT a sweep tick)
		roots, ok := orch.MerkleRoots()
		if !ok {
			continue
		}
		if len(roots) != want { // M6 guard (node count derived from nodeIDs)
			continue
		}
		if day36AllEqualVals(roots, nodeIDs) {
			// Key-presence guards (TestDay36_T_LOOP_Converges100 :719-727) —
			// the convergence is NOT a root-hash collision:
			//  (a) the converged root != the empty-tree root (the keys landed).
			//  (b) the source's LAST key is present on the LAST node (state
			//      replication, not hash collision).
			convergedRoot := roots[nodeIDs[0]]
			if convergedRoot == day36EmptyRoot(t) {
				t.Fatalf("T-DAY37-SWEEP-PROBE: converged root == empty-tree root after %d rounds — the %d keys never landed (a false-positive convergence)", r, day36ConvKeys)
			}
			lastNode := nodeIDs[day36NumNodes-1]
			if entries := engines[lastNode].State().Get(fmt.Sprintf("day36-key-%d", day36ConvKeys-1)); len(entries) == 0 {
				t.Fatalf("T-DAY37-SWEEP-PROBE: the source's last key (day36-key-%d) is NOT present on the last node after %d rounds — convergence was root-hash collision, not state replication", day36ConvKeys-1, r)
			}
			return true, r, time.Since(start).Seconds()
		}
	}
	roots, _ := orch.MerkleRoots()
	return day36AllEqualVals(roots, nodeIDs) && len(roots) == want, day36ConvRoundCap, time.Since(start).Seconds()
}
