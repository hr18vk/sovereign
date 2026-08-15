// Day 16 (ADR-0021) teeth (the REAL *LocalFS teeth) — the L0 reaper fork, driven
// against a REAL *LocalFS (the Day-12.5 tooth-principle "drive the route, not
// the seam" — the same discipline Day-14/15 used).
//
// The reaper CLOSES the monotonic L0 disk leak ADR-0020 §6c deferred: the
// compaction write path (l1_compactor.go) writes a manifest at
// compaction/{hex8}/{sysNs}.manifest listing the L0 files it merged into the L1,
// but the L0 files are KEPT FOREVER as the crash-recovery backstop (no code
// deletes them; every compaction leaves N L0 files PLUS the manifest on disk).
// The reaper deletes the manifest-listed L0 files AFTER verifying the L1 still
// exists (Stage C safety guard), then deletes the manifest.
//
// THE TEETH (mirrors the §1.5 spec):
//
//   - T1 — THE HEADLINE: write N per-entity checkpoints → run compaction (a
//     manifest listing the N L0s is written, the L1 is written, the L0s STAY)
//     → Reap → every superseded L0 is deleted, the manifest is deleted, the L1
//     is untouched, and L0 files NOT in the manifest are untouched.
//     RED-before-reaping (the L0s exist) → GREEN-after (os.Stat → not found).
//
//   - T2 — the safety guard (the load-bearing test): delete the L1 a manifest
//     points at, then Reap → the reaper MUST NOT delete the L0s NOR the
//     manifest; SkippedOrphan increments. This is the critical safety condition
//     the whole reaper exists to enforce: an L0 whose L1 is gone is the SOLE
//     durable copy → preserve it.
//
//   - T3 — idempotent reaper: run Reap TWICE. The second run observes the
//     manifest + L0s already deleted (LocalFS.Delete returns nil for
//     os.IsNotExist) → zero-deletes, zero-error, no manifest (it was deleted
//     round 1; not re-listed). The second run is a clean no-op, NOT an error.
//
//   - T4 — partial reap: a manifest with K L0s; make ONE L0 delete fail (a
//     fault-injecting LocalFS wrapper) so only the first succeeds → the manifest
//     is NOT deleted (Stage D stops on the first delete failure); the already-
//     deleted L0 stays deleted (monotone forward progress); SkippedError
//     increments. The next sweep (against the real LocalFS) reaps the rest.
//
// These teeth live in pkg/durability (the home of LocalFS) because an
// internal/database test cannot import pkg/durability (import cycle: snapshot.go
// imports internal/database) — the Day-14 precedent. The FROZEN-md5 +
// scope-hygiene teeth (T5/T6) live in internal/database/l1_compaction_track16_test.go.
package durability

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// track16LocalFS builds a REAL *LocalFS (reuses the track14 helper — same root,
// same temp-dir cleanup, same compile-checked interface satisfaction). The reaper
// teeth drive the production-on-disk path the Day-12.5 tooth-principle demands.
func track16LocalFS(t *testing.T) *LocalFS {
	t.Helper()
	return track14LocalFS(t)
}

// track16WriteNMerge writes `n` per-entity checkpoints for ONE entity and runs a
// compaction to produce a manifest listing all `n` L0 keys → returns the merged
// set (manifestKey, l1Key, l0Keys, hash8). The L0 files STAY on disk after the
// compaction (Day-14 keeps them as the backstop — the reaper reclaims them).
// RED-before-reaping helper for T1.
func track16WriteNMerge(t *testing.T, lfs *LocalFS, alloc *database.JemallocAllocator, entity string, n int) (manifestKey, l1Key string, l0Keys []string, hash8 [8]byte) {
	t.Helper()
	track14WriteN(t, alloc, lfs, entity, n)
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track16-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(context.Background(), entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (n=%d L0 files exist)", n)
	require.Lenf(t, res.L0Files, n, "the manifest must list all %d merged L0 keys", n)
	require.NotEmpty(t, res.L1Key)
	require.NotEmpty(t, res.ManifestKey)
	return res.ManifestKey, res.L1Key, res.L0Files, h8
}

// track16KeyExists reports whether the object at `key` exists in lfs (a stat
// via Download — the production read interface; LocalFS has no Head/Stat).
func track16KeyExists(t *testing.T, lfs *LocalFS, key string) bool {
	t.Helper()
	rc, err := lfs.Download(context.Background(), "local", key)
	if err != nil {
		return false
	}
	_ = rc.Close()
	return true
}

// track16DeleteKey removes a key directly (bypassing the reaper — used by T2 to
// simulate the filesystem losing the L1 a manifest points at).
func track16DeleteKey(t *testing.T, lfs *LocalFS, key string) {
	t.Helper()
	err := lfs.Delete(context.Background(), "local", key)
	require.NoErrorf(t, err, "direct delete %s (T2 fault setup)", key)
}

// --- T1 — THE HEADLINE: Reap deletes every superseded L0 + the manifest, leaves
// the L1 + non-manifest L0s untouched (RED-then-GREEN over a REAL *LocalFS). ---
//
// Setup a SECOND entity (entity "bravo") with its own L0 file that is NOT in the
// reaped manifest, to prove the reaper deletes ONLY the manifest-listed L0s.
// The bravo L0 is NOT superseded (no compaction ran for it) → it MUST survive.
func TestTrack16_T1_ReapDeletesSupersededL0AndManifest_RedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := track16LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 8
	manifestKey, l1Key, l0Keys, _ := track16WriteNMerge(t, lfs, alloc, entity, N)

	// A SECOND entity with an UNSUPERSEDED L0 (no compaction → no manifest → the
	// reaper MUST NOT touch it). Proves the reaper deletes ONLY manifest-listed
	// L0s, not every L0 on disk.
	const bystander = "bravo"
	track14WriteN(t, alloc, lfs, bystander, 1)
	bystanderH8 := database.EntityHash8(bystander)
	bystanderL0s, lerr := lfs.ListObjects(ctx, "local", "l0/"+fmt.Sprintf("%x", bystanderH8[:])+"/", 0)
	require.NoError(t, lerr)
	require.Lenf(t, bystanderL0s, 1, "bystander entity bravo must have exactly 1 L0 file")
	bystanderL0 := bystanderL0s[0]

	// --- RED stage: before reaping, every superseded L0 exists + the manifest
	// exists; the L1 exists (the reaper's Stage C will verify it). ---
	for _, k := range l0Keys {
		require.Truef(t, track16KeyExists(t, lfs, k), "RED: superseded L0 %s must exist BEFORE reaping", k)
	}
	require.Truef(t, track16KeyExists(t, lfs, manifestKey), "RED: manifest %s must exist BEFORE reaping", manifestKey)
	require.Truef(t, track16KeyExists(t, lfs, l1Key), "RED: L1 %s must exist (the reaper verifies it at Stage C)", l1Key)
	require.Truef(t, track16KeyExists(t, lfs, bystanderL0), "RED: bystander L0 %s must exist (will prove the reaper leaves non-manifest L0s alone)", bystanderL0)

	// --- GREEN stage: run the reaper. ---
	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res := reaper.Reap(ctx)

	// Stage F tally assertions: exactly 1 manifest fully reaped, N L0s deleted,
	// 0 orphan, 0 error.
	assert.Equalf(t, 1, res.ReapedManifests, "T1: exactly 1 manifest fully reaped (got %d)", res.ReapedManifests)
	assert.Equalf(t, N, res.ReapedL0, "T1: all %d manifest-listed L0s deleted (got %d)", N, res.ReapedL0)
	assert.Equalf(t, 0, res.SkippedOrphan, "T1: 0 orphan (the L1 IS present — Stage C admits); got %d", res.SkippedOrphan)
	assert.Equalf(t, 0, res.SkippedError, "T1: 0 delete-error; got %d", res.SkippedError)

	// Every superseded L0 is GONE (os.Stat → not found).
	for _, k := range l0Keys {
		assert.Falsef(t, track16KeyExists(t, lfs, k), "GREEN: superseded L0 %s must be DELETED after reaping", k)
	}
	// The manifest is GONE.
	assert.Falsef(t, track16KeyExists(t, lfs, manifestKey), "GREEN: manifest %s must be DELETED after reaping (Stage E)", manifestKey)
	// The L1 is UNTOUCHED (the reaper deletes superseded L0s, NOT the L1 they were merged into).
	assert.Truef(t, track16KeyExists(t, lfs, l1Key), "GREEN: L1 %s must be UNTOUCHED (the reaper preserves the L1 it verified)", l1Key)
	// The NON-manifest bystander L0 is UNTOUCHED (the reaper deletes ONLY manifest-listed L0s).
	assert.Truef(t, track16KeyExists(t, lfs, bystanderL0), "GREEN: non-manifest L0 %s (entity bravo) must be UNTOUCHED (the reaper deletes ONLY manifest-listed L0s)", bystanderL0)

	// And AsOf still resolves the entity's data via the L1 alone (the superseded
	// L0s are gone but their rows live in the L1 — the backstop-reaped, truth-
	// preserved invariant). Query at the oldest validTime the L1 covers.
	resolver := database.NewResolver(lfs, lfs, alloc, "track16-bucket", database.ResolverConfig{MaxL0Files: 100})
	oldestSysNs := l0KeysFirstSysNs(t, l0Keys)
	got, gerr := resolver.AsOf(ctx, entity, time.Unix(0, oldestSysNs), time.Unix(0, oldestSysNs+1))
	require.NoErrorf(t, gerr, "T1: AsOf must still resolve the entity via the L1 after the L0s are reaped (truth preserved)")
	require.NotNil(t, got)
	assert.Equalf(t, entity, got.EntityID, "T1: AsOf returns the right entity (no keying collision)")

	t.Logf("T1 RED: %d superseded L0s + manifest existed; GREEN: reaper deleted all %d L0s + the manifest, left the L1 + the non-manifest bravo L0 untouched; AsOf still 200 via the L1 (truth preserved)",
		N, N)
}

// l0KeysFirstSysNs extracts the {sysNs} segment from the lex-smallest L0 key in
// the set (l0/{hex16}/{sysNs}.arrow). The manifest lists the L0 keys sorted; the
// smallest key carries the OLDEST sysNs (the L1's firstSysT, the query target).
func l0KeysFirstSysNs(t *testing.T, l0Keys []string) int64 {
	t.Helper()
	require.NotEmpty(t, l0Keys)
	// key form: l0/{16hex}/{sysNs}.arrow — the sysNs is key[20:len-6].
	k := l0Keys[0]
	require.Truef(t, strings.HasPrefix(k, "l0/"), "l0 key %q", k)
	// l0/ (3) + 16 hex + / (1) = offset 20.
	const prefix = len("l0/") + 16 + 1
	require.Truef(t, len(k) > prefix && strings.HasSuffix(k, ".arrow"), "l0 key %q shape", k)
	sysStr := k[prefix : len(k)-len(".arrow")]
	var sys int64
	_, err := fmt.Sscanf(sysStr, "%d", &sys)
	require.NoError(t, err)
	return sys
}

// --- T2 — the SAFETY GUARD: an L1 that is GONE → the reaper PRESERVES the
// manifest's L0s + the manifest (the L0s are the sole durable copy). The whole
// reaper exists to enforce this. SkippedOrphan MUST increment; the L0s MUST
// stay on disk; the manifest MUST stay on disk (not deleted). ---
func TestTrack16_T2_OrphanL1_SafetyGuard_PreservesL0AndManifest(t *testing.T) {
	ctx := context.Background()
	lfs := track16LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 6
	manifestKey, l1Key, l0Keys, _ := track16WriteNMerge(t, lfs, alloc, entity, N)

	// Simulate the filesystem LOSING the L1 (a disk error, a manual wipe, an S3
	// lifecycle rule). The manifest still points at it; the L0s are the backstop.
	track16DeleteKey(t, lfs, l1Key)
	require.Falsef(t, track16KeyExists(t, lfs, l1Key), "T2 setup: the L1 must be GONE (simulated loss)")

	// Every L0 + the manifest exist BEFORE reaping (the backstop is intact).
	for _, k := range l0Keys {
		require.Truef(t, track16KeyExists(t, lfs, k), "T2 setup: superseded L0 %s must exist (it is the backstop)", k)
	}
	require.True(t, track16KeyExists(t, lfs, manifestKey))

	// Reap. The reaper's Stage C download of the L1 FAILS (the L1 is gone) → the
	// reaper treats it as orphan → PRESERVES the L0s + the manifest.
	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res := reaper.Reap(ctx)

	// The SAFETY assertions: ZERO manifests reaped, ZERO L0s deleted, ONE orphan.
	assert.Equalf(t, 0, res.ReapedManifests, "T2 SAFETY: 0 manifests reaped (the L1 is GONE — the reaper refuses); got %d", res.ReapedManifests)
	assert.Equalf(t, 0, res.ReapedL0, "T2 SAFETY: 0 L0s deleted (the L0s are the sole durable copy — PRESERVED); got %d", res.ReapedL0)
	assert.Equalf(t, 1, res.SkippedOrphan, "T2: exactly 1 manifest skipped as ORPHAN (the L1 is gone); got %d", res.SkippedOrphan)
	assert.Equalf(t, 0, res.SkippedError, "T2: 0 delete-error (nothing was attempted — Stage C refused before Stage D); got %d", res.SkippedError)

	// The L0s are PRESERVED on disk (the backstop). Every one still exists.
	for _, k := range l0Keys {
		assert.Truef(t, track16KeyExists(t, lfs, k), "T2 SAFETY: superseded L0 %s must be PRESERVED (it is the sole durable copy — the L1 is gone)", k)
	}
	// The manifest is PRESERVED (the reaper did NOT delete it — it skipped it).
	assert.Truef(t, track16KeyExists(t, lfs, manifestKey), "T2 SAFETY: the manifest %s must be PRESERVED (the reaper retains it for the next sweep; the L1 may be restored)", manifestKey)

	t.Logf("T2 SAFETY: L1 gone → reaper skipped the manifest as orphan (SkippedOrphan=1), PRESERVED all %d L0s + the manifest (the backstop intact, the sole durable copy)", N)
}

// --- T3 — IDEMPOTENT reaper: Reap TWICE. The first run reaps fully (deletes the
// L0s + the manifest); the second run is a CLEAN NO-OP (the manifest is already
// gone → it is not even listed; zero deletes, zero error, zero manifest). ---
func TestTrack16_T3_Idempotent_SecondSweepIsCleanNoOp(t *testing.T) {
	ctx := context.Background()
	lfs := track16LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 5
	manifestKey, l1Key, l0Keys, _ := track16WriteNMerge(t, lfs, alloc, entity, N)
	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")

	// First sweep: reaps fully.
	res1 := reaper.Reap(ctx)
	require.Equalf(t, 1, res1.ReapedManifests, "T3 sweep 1: 1 manifest reaped")
	require.Equalf(t, N, res1.ReapedL0, "T3 sweep 1: all %d L0s deleted", N)
	require.Falsef(t, track16KeyExists(t, lfs, manifestKey), "T3 sweep 1: manifest gone")
	require.Truef(t, track16KeyExists(t, lfs, l1Key), "T3 sweep 1: L1 untouched")
	for _, k := range l0Keys {
		require.Falsef(t, track16KeyExists(t, lfs, k), "T3 sweep 1: L0 %s gone", k)
	}

	// Second sweep: the manifest is GONE (deleted sweep 1) → ListObjects under
	// compaction/ returns the OTHER entities' manifests (none — only alpha was
	// compacted) → the second run observes ZERO manifests. It is a clean no-op:
	// zero manifests reaped, zero L0s deleted, zero orphan, zero error. NOT an
	// error (LocalFS.Delete's os.IsNotExist nil path is exercised if any stale
	// reference remained, but here the manifest isn't even re-listed).
	res2 := reaper.Reap(ctx)
	assert.Equalf(t, 0, res2.ReapedManifests, "T3 sweep 2: 0 manifests reaped (the manifest was deleted sweep 1 → not re-listed); got %d", res2.ReapedManifests)
	assert.Equalf(t, 0, res2.ReapedL0, "T3 sweep 2: 0 L0s deleted (nothing to reap); got %d", res2.ReapedL0)
	assert.Equalf(t, 0, res2.SkippedOrphan, "T3 sweep 2: 0 orphan; got %d", res2.SkippedOrphan)
	assert.Equalf(t, 0, res2.SkippedError, "T3 sweep 2: 0 error (a clean no-op, NOT an error on the missing manifest); got %d", res2.SkippedError)

	// Re-state the steady-state: the L1 is STILL untouched (the second sweep did
	// not delete it either), the L0s + manifest are still gone.
	assert.Truef(t, track16KeyExists(t, lfs, l1Key), "T3 sweep 2: L1 still untouched")
	assert.Falsef(t, track16KeyExists(t, lfs, manifestKey), "T3 sweep 2: manifest still gone")

	// Now exercise the os.IsNotExist nil path directly: re-creating the manifest
	// by hand and reaping AGAIN proves Delete-on-missing-L0 is nil (idempotent
	// delete). Write a manifest pointing at L0 keys that are ALREADY gone; Reap
	// verifies the L1 (still present) → Stage D deletes each L0 (already gone →
	// LocalFS.Delete returns nil for os.IsNotExist) → Stage E deletes the
	// manifest. Forward progress on an already-reaped keyspace.
	track16WriteManifest(t, lfs, manifestKey, l1Key, l0Keys)
	require.True(t, track16KeyExists(t, lfs, manifestKey))
	res3 := reaper.Reap(ctx)
	assert.Equalf(t, 1, res3.ReapedManifests, "T3 sweep 3: the re-created manifest reaps (the L1 still verifies at Stage C; Stage D's Deletes return nil for the already-gone L0s — idempotent — then Stage E deletes the manifest); got %d", res3.ReapedManifests)
	// HONEST counting: the reaper counts EVERY successful Delete call as a
	// reaped L0 (a Delete that returns nil — whether it physically removed a file
	// OR the file was already-absent, the idempotent os.IsNotExist-nil path). The
	// re-created manifest still lists ALL N L0 keys, so the reaper re-issues
	// Delete on each — all return nil (idempotent, already gone) → all N count.
	// This is the documented per-sweep tally: "successful Delete calls", not
	// "files physically removed this sweep" (which would need a pre-Stat per L0 —
	// an IO the reaper's safety contract does not require).
	assert.Equalf(t, N, res3.ReapedL0, "T3 sweep 3: N=%d L0 Deletes succeeded (idempotent nil on already-gone files; the reaper counts a successful Delete call, incl. the idempotent already-absent path, as a reaped L0 — see l0_reaper.go Stage D + the L0ReapL0Deleted metric description); got %d", N, res3.ReapedL0)
	assert.Falsef(t, track16KeyExists(t, lfs, manifestKey), "T3 sweep 3: the re-created manifest is deleted (Stage E)")

	t.Logf("T3: sweep 1 reaped (1 manifest, %d L0s); sweep 2 clean no-op (0/0/0/0); sweep 3 reaped the re-created manifest (idempotent Delete-on-missing re-counted N successful nil Deletes)", N)
}

// track16WriteManifest writes a manifest body (l1Key + l0Keys) at manifestKey via
// the LocalFS Upload path — used by T3 sweep 3 to re-create an already-deleted
// manifest and exercise the idempotent-Delete-on-missing-L0 path.
func track16WriteManifest(t *testing.T, lfs *LocalFS, manifestKey, l1Key string, l0Keys []string) {
	t.Helper()
	var body strings.Builder
	body.WriteString(l1Key)
	body.WriteByte('\n')
	for _, k := range l0Keys {
		body.WriteString(k)
		body.WriteByte('\n')
	}
	err := lfs.Upload(context.Background(), manifestKey, strings.NewReader(body.String()), int64(body.Len()))
	require.NoErrorf(t, err, "write manifest %s (T3 sweep-3 setup)", manifestKey)
}

// --- T4 — PARTIAL reap: a fault-injecting LocalFS wrapper makes the SECOND L0
// delete fail → Stage D stops → the manifest is RETAINED; the first L0 IS
// deleted (monotone forward progress); SkippedError increments. The next sweep
// (against the real LocalFS) reaps the rest. ---
//
// The wrapper delegates List/Download/Upload to the real LocalFS but Delete
// fails once the Nth delete succeeds (failAfter). This proves Stage D's "stop on
// the first delete failure + retain the manifest" contract.
func TestTrack16_T4_PartialReap_DeleteFailureRetainsManifest(t *testing.T) {
	ctx := context.Background()
	lfs := track16LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 5
	manifestKey, l1Key, l0Keys, _ := track16WriteNMerge(t, lfs, alloc, entity, N)

	// Fault injector: let exactly `failAfter` L0 deletes succeed, then FAIL the
	// next L0 delete (return a real error — NOT a missing-file, which is
	// idempotent nil). The manifest delete (Stage E) is NEVER reached (Stage D
	// stops first). failAfter=1 → the FIRST L0 is deleted, the SECOND fails.
	const failAfter = 1
	faulty := &track16FaultyDeleter{real: lfs, failAfter: failAfter}

	// The reaper takes the faulted deleter but the REAL lister/downloader (the
	// fault must surface ONLY at delete time, so Stage A/B/C run against the
	// real store; the L1 verifies fine).
	reaper := database.NewL0Reaper(lfs, lfs, faulty, "local")
	res := reaper.Reap(ctx)

	// Stage D stopped after failAfter deletes → manifest NOT reaped (Stage E
	// never ran) → SkippedError increments; exactly failAfter L0s were deleted
	// (counted before the fault).
	assert.Equalf(t, 0, res.ReapedManifests, "T4: 0 manifests reaped (Stage D stopped on the delete failure → Stage E did NOT run); got %d", res.ReapedManifests)
	assert.Equalf(t, failAfter, res.ReapedL0, "T4: exactly %d L0 deleted before the fault (forward progress); got %d", failAfter, res.ReapedL0)
	assert.Equalf(t, 0, res.SkippedOrphan, "T4: 0 orphan (the L1 verifies fine — the fault is at delete time only); got %d", res.SkippedOrphan)
	assert.Equalf(t, 1, res.SkippedError, "T4: exactly 1 SkippedError (the manifest with the failed delete); got %d", res.SkippedError)

	// The manifest is RETAINED (Stage D stopped → Stage E did NOT delete it).
	assert.Truef(t, track16KeyExists(t, lfs, manifestKey), "T4: manifest RETAINED (the reaper retries the failed delete next sweep)")
	// The L1 is untouched (the reaper never deletes the L1).
	assert.Truef(t, track16KeyExists(t, lfs, l1Key), "T4: L1 untouched")
	// The FIRST failAfter L0s ARE deleted (forward progress is monotone); the
	// REMAINING L0s (incl. the one whose delete failed + the ones after it) are
	// PRESERVED (Stage D stopped).
	deleted := l0Keys[:failAfter]
	remaining := l0Keys[failAfter:]
	for _, k := range deleted {
		assert.Falsef(t, track16KeyExists(t, lfs, k), "T4: the first %d L0(s) ARE deleted (forward progress): %s", failAfter, k)
	}
	for _, k := range remaining {
		assert.Truef(t, track16KeyExists(t, lfs, k), "T4: L0 %s PRESERVED (Stage D stopped on the failed delete — the manifest + remaining L0s retry next sweep)", k)
	}

	// The RESUME: run a SECOND sweep against the REAL LocalFS (fault cleared).
	// The remaining L0s are now reaped + the manifest is reaped (Stage D
	// succeeds for all remaining → Stage E deletes the manifest). The already-
	// deleted first L0 returns nil (idempotent) — but it is NOT re-listed in the
	// manifest's body as a NEW delete; the manifest still lists ALL N, so the
	// reaper re-issues Delete on the already-gone first L0 (nil) + the remaining
	// N-failAfter (succeed). The sweep reaps the manifest.
	reaper2 := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res2 := reaper2.Reap(ctx)
	// The retained manifest still lists ALL N L0s (it was not modified by the
	// partial sweep). On resume, the reaper re-issues Delete on each: the first
	// failAfter are already-gone (idempotent nil, counted) + the remaining
	// N-failAfter succeed (counted) → res2.ReapedL0 == N; the manifest reaps
	// (Stage E runs now that Stage D cleared); zero error this time.
	assert.Equalf(t, 1, res2.ReapedManifests, "T4 resume: 1 manifest reaped (Stage D cleared → Stage E); got %d", res2.ReapedManifests)
	assert.Equalf(t, N, res2.ReapedL0, "T4 resume: N=%d L0 Deletes succeeded (the first %d idempotent-nil on already-gone + the remaining %d real); got %d", N, failAfter, N-failAfter, res2.ReapedL0)
	assert.Equalf(t, 0, res2.SkippedError, "T4 resume: 0 error (the fault cleared); got %d", res2.SkippedError)
	assert.Truef(t, !track16KeyExists(t, lfs, manifestKey), "T4 resume: the manifest is now reaped (Stage D+E succeed against the fault-free store); manifest gone")
	// Every L0 is now gone (the remaining + the already-deleted stay deleted).
	for _, k := range l0Keys {
		assert.Falsef(t, track16KeyExists(t, lfs, k), "T4 resume: L0 %s gone (the partial reap resumed + completed)", k)
	}
	assert.Truef(t, track16KeyExists(t, lfs, l1Key), "T4 resume: L1 still untouched")

	t.Logf("T4 PARTIAL: fault after %d delete(s) → manifest RETAINED, %d L0 deleted (forward progress), SkippedError=1; resume sweep reaped the manifest + the remaining %d L0s",
		failAfter, failAfter, N-failAfter)
}

// track16FaultyDeleter wraps a *LocalFS and makes the (failAfter+1)th Delete
// call FAIL with a real error. It delegates List/Download/Upload to the real
// store so Stage A/B/C run against the truth; only Stage D's delete is faulted.
type track16FaultyDeleter struct {
	real      *LocalFS
	failAfter int // how many Delete calls succeed before the fault
	calls     int // Delete calls so far
}

func (f *track16FaultyDeleter) Delete(ctx context.Context, bucket, key string) error {
	f.calls++
	// Stage D deletes the L0s one by one. Let the first `failAfter` succeed,
	// then FAIL the next (a real IO error, NOT a missing-file → so it is NOT
	// the idempotent-nil path). The manifest delete (Stage E) is guarded by
	// Stage D stopping first → never reached under this fault.
	if f.calls > f.failAfter && !strings.HasPrefix(key, "compaction/") {
		// Fault: the reaper sees a real delete error, stops Stage D for this
		// manifest, retains it. The already-deleted first L0s stay deleted.
		return fmt.Errorf("track16 fault: simulated delete failure on %s (call #%d)", key, f.calls)
	}
	return f.real.Delete(ctx, bucket, key)
}

// The faulty deleter still needs to satisfy the S3Deleter interface — but the
// reaper takes it positionally as database.S3Deleter, so it MUST ALSO satisfy the
// List/Download/Upload seams IF it were injected for those. It is NOT (T4
// injects the REAL lfs for those), so this only needs Delete. Compile-time check:
var _ database.S3Deleter = (*track16FaultyDeleter)(nil)

// keep the os import alive (track16LocalFS uses t.TempDir via track14; this file
// directly uses os via... none — guard removed if gofmt complains).
var _ = os.IsNotExist
