// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// L0 reaper tests over real LocalFS storage (ADR-0021). Compaction leaves the
// merged L0 files and a manifest on disk as a recovery backstop. The reaper
// deletes the manifest-listed L0 files only after verifying that their L1 still
// exists, then deletes the manifest.
//
// The fixtures cover a complete reap, a missing L1, repeated sweeps, and a delete
// failure partway through a manifest. They also check that unrelated L0 files
// survive and that a completed L1 still serves queries after its L0 inputs are
// reclaimed. These tests live beside LocalFS to avoid an import cycle with
// internal/database.
package durability

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReaperLocalFS uses the shared LocalFS fixture so reaper tests exercise the
// same on-disk interfaces and cleanup as the compaction tests.
func newReaperLocalFS(t *testing.T) *LocalFS {
	t.Helper()
	return newLocalFS(t)
}

// writeNMerge writes n checkpoints and compacts them into an L1. It returns the
// manifest, L1, merged L0 keys, and entity hash. Compaction intentionally leaves
// the L0 files in place for the reaper to reclaim.
func writeNMerge(t *testing.T, lfs *LocalFS, alloc *database.JemallocAllocator, entity string, n int) (manifestKey, l1Key string, l0Keys []string, hash8 [8]byte) {
	t.Helper()
	writeNCheckpoints(t, alloc, lfs, entity, n)
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "reaper-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(context.Background(), entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (n=%d L0 files exist)", n)
	require.Lenf(t, res.L0Files, n, "the manifest must list all %d merged L0 keys", n)
	require.NotEmpty(t, res.L1Key)
	require.NotEmpty(t, res.ManifestKey)
	return res.ManifestKey, res.L1Key, res.L0Files, h8
}

// keyExists reports whether the object at `key` exists in lfs (a stat
// via Download — the production read interface; LocalFS has no Head/Stat).
func keyExists(t *testing.T, lfs *LocalFS, key string) bool {
	t.Helper()
	rc, err := lfs.Download(context.Background(), "local", key)
	if err != nil {
		return false
	}
	_ = rc.Close()
	return true
}

// deleteKey removes an object directly to simulate loss of the L1 named by a
// manifest.
func deleteKey(t *testing.T, lfs *LocalFS, key string) {
	t.Helper()
	err := lfs.Delete(context.Background(), "local", key)
	require.NoErrorf(t, err, "delete L1 %s to simulate loss", key)
}

// TestReapDeletesSupersededL0AndManifestRedThenGreen verifies a complete reap.
// A second entity supplies an unmerged L0 file that must survive because it is
// absent from the manifest. The merged L1 and its query results must survive as
// well.
func TestReapDeletesSupersededL0AndManifestRedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := newReaperLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 8
	manifestKey, l1Key, l0Keys, _ := writeNMerge(t, lfs, alloc, entity, N)

	// A second entity with an un-superseded L0 (no compaction → no manifest → the
	// reaper must not touch it). Proves the reaper deletes only manifest-listed
	// L0s, not every L0 on disk.
	const bystander = "bravo"
	writeNCheckpoints(t, alloc, lfs, bystander, 1)
	bystanderH8 := database.EntityHash8(bystander)
	bystanderL0s, lerr := lfs.ListObjects(ctx, "local", "l0/"+fmt.Sprintf("%x", bystanderH8[:])+"/", 0)
	require.NoError(t, lerr)
	require.Lenf(t, bystanderL0s, 1, "bystander entity bravo must have exactly 1 L0 file")
	bystanderL0 := bystanderL0s[0]

	// Establish every input before reaping, including the L1 that the safety
	// check must verify and the unrelated bystander file.
	for _, k := range l0Keys {
		require.Truef(t, keyExists(t, lfs, k), "superseded L0 %s must exist before reaping", k)
	}
	require.Truef(t, keyExists(t, lfs, manifestKey), "manifest %s must exist before reaping", manifestKey)
	require.Truef(t, keyExists(t, lfs, l1Key), "L1 %s must exist for the reaper safety check", l1Key)
	require.Truef(t, keyExists(t, lfs, bystanderL0), "unrelated L0 %s must exist before reaping", bystanderL0)

	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res := reaper.Reap(ctx)

	assert.Equalf(t, 1, res.ReapedManifests, "got %d fully reaped manifests, want 1", res.ReapedManifests)
	assert.Equalf(t, N, res.ReapedL0, "all %d manifest-listed L0 files must be deleted; got %d", N, res.ReapedL0)
	assert.Equalf(t, 0, res.SkippedOrphan, "got %d orphan skips with the L1 present", res.SkippedOrphan)
	assert.Equalf(t, 0, res.SkippedError, "got %d delete errors", res.SkippedError)

	for _, k := range l0Keys {
		assert.Falsef(t, keyExists(t, lfs, k), "superseded L0 %s still exists after reaping", k)
	}
	assert.Falsef(t, keyExists(t, lfs, manifestKey), "manifest %s still exists after reaping", manifestKey)
	assert.Truef(t, keyExists(t, lfs, l1Key), "merged L1 %s was deleted during reaping", l1Key)
	assert.Truef(t, keyExists(t, lfs, bystanderL0), "non-manifest L0 %s was deleted during reaping", bystanderL0)

	// The L1 alone must still serve the oldest row after its L0 inputs are gone.
	resolver := database.NewResolver(lfs, lfs, alloc, "reaper-bucket", database.ResolverConfig{MaxL0Files: 100})
	oldestSysNs := l0KeysFirstSysNs(t, l0Keys)
	got, gerr := resolver.AsOf(ctx, entity, time.Unix(0, oldestSysNs), time.Unix(0, oldestSysNs+1))
	require.NoErrorf(t, gerr, "AsOf failed through the L1 after reaping its L0 inputs")
	require.NotNil(t, got)
	assert.Equalf(t, entity, got.EntityID, "AsOf returned a different entity after reaping")

	t.Logf("before reaping, %d superseded L0 files existed; reaping deleted %d and their manifest; the L1 and unrelated L0 survived and served the query", N, N)
}

// l0KeysFirstSysNs extracts sysNs from the first sorted L0 key. That key holds
// the oldest system time in the merged L1 and supplies the query timestamp.
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

// TestOrphanL1SafetyGuardPreservesL0AndManifest removes the L1 named by a
// manifest. Because the L0 inputs are then the only durable copy, the reaper
// must preserve them and the manifest and increment SkippedOrphan.
func TestOrphanL1SafetyGuardPreservesL0AndManifest(t *testing.T) {
	ctx := context.Background()
	lfs := newReaperLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 6
	manifestKey, l1Key, l0Keys, _ := writeNMerge(t, lfs, alloc, entity, N)

	// Simulate the filesystem losing the L1 (a disk error, a manual wipe, an S3
	// lifecycle rule). The manifest still points at it; the L0s are the backstop.
	deleteKey(t, lfs, l1Key)
	require.Falsef(t, keyExists(t, lfs, l1Key), "L1 still exists after simulated loss")

	// Every L0 and the manifest remain in place as the only durable copy.
	for _, k := range l0Keys {
		require.Truef(t, keyExists(t, lfs, k), "backstop L0 %s is missing before reaping", k)
	}
	require.True(t, keyExists(t, lfs, manifestKey))

	// The failed L1 download must classify the manifest as orphaned before any
	// L0 delete is attempted.
	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res := reaper.Reap(ctx)

	assert.Equalf(t, 0, res.ReapedManifests, "reaped %d manifests with the L1 missing", res.ReapedManifests)
	assert.Equalf(t, 0, res.ReapedL0, "deleted %d sole-copy L0 files with the L1 missing", res.ReapedL0)
	assert.Equalf(t, 1, res.SkippedOrphan, "got %d orphan skips with the L1 missing, want 1", res.SkippedOrphan)
	assert.Equalf(t, 0, res.SkippedError, "got %d delete errors although no L0 delete should run", res.SkippedError)

	for _, k := range l0Keys {
		assert.Truef(t, keyExists(t, lfs, k), "sole-copy L0 %s was deleted with the L1 missing", k)
	}
	assert.Truef(t, keyExists(t, lfs, manifestKey), "manifest %s was deleted instead of retained for the next sweep", manifestKey)

	t.Logf("missing L1 produced one orphan skip; all %d L0 files and the manifest were preserved", N)
}

// TestIdempotentSecondSweepIsCleanNoOp runs a complete reap and then verifies
// that a second sweep has no manifests to process. A recreated manifest also
// checks that deleting already-absent L0 keys remains successful and counted.
func TestIdempotentSecondSweepIsCleanNoOp(t *testing.T) {
	ctx := context.Background()
	lfs := newReaperLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 5
	manifestKey, l1Key, l0Keys, _ := writeNMerge(t, lfs, alloc, entity, N)
	reaper := database.NewL0Reaper(lfs, lfs, lfs, "local")

	res1 := reaper.Reap(ctx)
	require.Equalf(t, 1, res1.ReapedManifests, "first sweep did not reap exactly one manifest")
	require.Equalf(t, N, res1.ReapedL0, "first sweep must delete all %d L0 files", N)
	require.Falsef(t, keyExists(t, lfs, manifestKey), "manifest remains after first sweep")
	require.Truef(t, keyExists(t, lfs, l1Key), "L1 was deleted during first sweep")
	for _, k := range l0Keys {
		require.Falsef(t, keyExists(t, lfs, k), "L0 %s remains after first sweep", k)
	}

	// The first sweep removed the only manifest, so the second has no work and
	// must report no deletes, orphan skips, or errors.
	res2 := reaper.Reap(ctx)
	assert.Equalf(t, 0, res2.ReapedManifests, "second sweep reaped %d manifests, want 0", res2.ReapedManifests)
	assert.Equalf(t, 0, res2.ReapedL0, "second sweep deleted %d L0 files, want 0", res2.ReapedL0)
	assert.Equalf(t, 0, res2.SkippedOrphan, "second sweep reported %d orphan skips", res2.SkippedOrphan)
	assert.Equalf(t, 0, res2.SkippedError, "second sweep reported %d errors", res2.SkippedError)

	assert.Truef(t, keyExists(t, lfs, l1Key), "second sweep deleted the L1")
	assert.Falsef(t, keyExists(t, lfs, manifestKey), "manifest reappeared after second sweep")

	// Recreate the manifest with the L1 still present and all L0 files already
	// absent. LocalFS.Delete treats os.IsNotExist as success, so the sweep can
	// finish and remove the manifest again.
	writeManifest(t, lfs, manifestKey, l1Key, l0Keys)
	require.True(t, keyExists(t, lfs, manifestKey))
	res3 := reaper.Reap(ctx)
	assert.Equalf(t, 1, res3.ReapedManifests, "recreated manifest produced %d completed reaps, want 1", res3.ReapedManifests)
	// ReapedL0 counts successful Delete calls, including idempotent success for
	// an already-absent key, rather than physical removals in this sweep.
	assert.Equalf(t, N, res3.ReapedL0, "recreated manifest must count all %d successful L0 deletes; got %d", N, res3.ReapedL0)
	assert.Falsef(t, keyExists(t, lfs, manifestKey), "recreated manifest remains after its sweep")

	t.Logf("second sweep was a no-op; recreated manifest recorded %d successful deletes of already-absent L0 keys", N)
}

// writeManifest uploads an L1 key and its original L0 key list. Recreating a
// deleted manifest lets the repeated-sweep test exercise idempotent deletion of
// L0 keys that are already absent.
func writeManifest(t *testing.T, lfs *LocalFS, manifestKey, l1Key string, l0Keys []string) {
	t.Helper()
	var body strings.Builder
	body.WriteString(l1Key)
	body.WriteByte('\n')
	for _, k := range l0Keys {
		body.WriteString(k)
		body.WriteByte('\n')
	}
	err := lfs.Upload(context.Background(), manifestKey, strings.NewReader(body.String()), int64(body.Len()))
	require.NoErrorf(t, err, "recreate manifest %s for idempotent deletion", manifestKey)
}

// TestPartialReapDeleteFailureRetainsManifest fails the second L0 delete after
// one success. The reaper must stop, retain the manifest for retry, report one
// SkippedError, and leave the remaining L0 files intact. A fault-free sweep must
// then finish the manifest, accepting idempotent deletes for the earlier key.
func TestPartialReapDeleteFailureRetainsManifest(t *testing.T) {
	ctx := context.Background()
	lfs := newReaperLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 5
	manifestKey, l1Key, l0Keys, _ := writeNMerge(t, lfs, alloc, entity, N)

	// Allow one L0 delete, then return a non-NotExist error for the next. The
	// manifest delete must remain unreachable after this failure.
	const failAfter = 1
	faulty := &faultyDeleter{real: lfs, failAfter: failAfter}

	// Only the deleter carries the fault; listing and downloading still use the
	// real store so the L1 existence check succeeds.
	reaper := database.NewL0Reaper(lfs, lfs, faulty, "local")
	res := reaper.Reap(ctx)

	assert.Equalf(t, 0, res.ReapedManifests, "completed %d manifests after the delete failure, want 0", res.ReapedManifests)
	assert.Equalf(t, failAfter, res.ReapedL0, "the first %d L0 deletes must succeed before the fault; got %d", failAfter, res.ReapedL0)
	assert.Equalf(t, 0, res.SkippedOrphan, "reported %d orphan skips with a valid L1", res.SkippedOrphan)
	assert.Equalf(t, 1, res.SkippedError, "reported %d delete errors, want 1", res.SkippedError)

	assert.Truef(t, keyExists(t, lfs, manifestKey), "manifest was deleted despite the failed L0 delete")
	assert.Truef(t, keyExists(t, lfs, l1Key), "L1 was deleted during the partial reap")
	deleted := l0Keys[:failAfter]
	remaining := l0Keys[failAfter:]
	for _, k := range deleted {
		assert.Falsef(t, keyExists(t, lfs, k), "after %d successful delete, L0 %s still exists", failAfter, k)
	}
	for _, k := range remaining {
		assert.Truef(t, keyExists(t, lfs, k), "L0 %s was deleted after the failure stopped the reap", k)
	}

	// Retry against the unfaulted store. The retained manifest still lists every
	// original key: deleting the earlier key succeeds idempotently, and the rest
	// are physically removed before the manifest is deleted.
	reaper2 := database.NewL0Reaper(lfs, lfs, lfs, "local")
	res2 := reaper2.Reap(ctx)
	assert.Equalf(t, 1, res2.ReapedManifests, "resume completed %d manifests, want 1", res2.ReapedManifests)
	assert.Equalf(t, N, res2.ReapedL0, "resume must report %d successful deletes: %d idempotent and %d remaining; got %d", N, failAfter, N-failAfter, res2.ReapedL0)
	assert.Equalf(t, 0, res2.SkippedError, "resume reported %d errors after the fault cleared", res2.SkippedError)
	assert.Truef(t, !keyExists(t, lfs, manifestKey), "manifest remains after the successful resume")
	for _, k := range l0Keys {
		assert.Falsef(t, keyExists(t, lfs, k), "L0 %s remains after the successful resume", k)
	}
	assert.Truef(t, keyExists(t, lfs, l1Key), "resume deleted the L1")

	t.Logf("delete failure after %d success left %d L0 file deleted and retained the manifest; resume completed the remaining %d deletes and removed it", failAfter, failAfter, N-failAfter)
}

// faultyDeleter fails the first L0 delete after failAfter successful calls.
// The reaper receives it only as an S3Deleter; listing and downloading continue
// to use the real LocalFS.
type faultyDeleter struct {
	real      *LocalFS
	failAfter int // how many Delete calls succeed before the fault
	calls     int // Delete calls so far
}

func (f *faultyDeleter) Delete(ctx context.Context, bucket, key string) error {
	f.calls++
	// Let the first failAfter L0 deletes succeed, then return a non-NotExist
	// error. The failed delete stops the loop before manifest deletion.
	if f.calls > f.failAfter && !strings.HasPrefix(key, "compaction/") {
		// Stop this manifest's reap and retain its unprocessed keys for retry.
		return fmt.Errorf("reaper fault: simulated delete failure on %s (call #%d)", key, f.calls)
	}
	return f.real.Delete(ctx, bucket, key)
}

// The partial-reap test injects faultyDeleter only for deletion, so Delete is
// sufficient to satisfy the interface used at that call site.
var _ database.S3Deleter = (*faultyDeleter)(nil)

// os.IsNotExist is part of the idempotent deletion contract exercised above.
var _ = os.IsNotExist
