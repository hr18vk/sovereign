// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package database implements L0 file reclamation after L1 compaction (ADR-0021).
//
// Compaction writes a manifest under compaction/{hex8}/{sysNs}.manifest listing
// the L0 files merged into an L1 object, leaving those source L0 files in place
// as a crash-recovery backstop. L0Reaper periodically lists manifests, verifies
// each referenced L1 object can be opened, deletes the listed L0 files, and then
// deletes the manifest.
//
// If opening an L1 fails for any reason (missing object, store outage, or I/O
// error), its listed L0 files and manifest are retained untouched so no history
// is lost. Because S3Deleter.Delete is idempotent for missing objects, partial
// reap sweeps recover cleanly on the next pass. L0 reaping is disabled unless
// --compaction-reap-enable is set.
package database

import (
	"context"
	"log"
	"strings"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// L0Reaper periodically reclaims L0 files already merged into verified L1 files
// (ADR-0021). It runs independently of per-entity compaction at a slower cadence
// (default 5m) and requires only read/delete storage interfaces.
type L0Reaper struct {
	lister     S3Lister     // lists compaction/{hex8}/{sysNs}.manifest
	downloader S3Downloader // reads manifests and verifies referenced L1 objects
	deleter    S3Deleter    // deletes reclaimed L0 files and manifests
	bucket     string       // bucket name passed through to storage interfaces
}

// NewL0Reaper constructs an L0Reaper over the given storage interfaces. Callers
// gate execution behind --compaction-reap-enable (default false).
func NewL0Reaper(lister S3Lister, downloader S3Downloader, deleter S3Deleter, bucket string) *L0Reaper {
	return &L0Reaper{
		lister:     lister,
		downloader: downloader,
		deleter:    deleter,
		bucket:     bucket,
	}
}

// ReapResult summarizes the object counts from a single Reap sweep, mirroring
// the cumulative counters registered in internal/telemetry.
type ReapResult struct {
	// ReapedManifests is the count of manifests whose listed L0 files and
	// manifest object were all deleted during this sweep.
	ReapedManifests int
	// ReapedL0 is the count of L0 files deleted during this sweep, including
	// partial progress before a manifest or L0 delete error.
	ReapedL0 int
	// SkippedOrphan is the count of manifests skipped because the manifest or its
	// target L1 object could not be opened, preserving listed L0s as a backstop.
	SkippedOrphan int
	// SkippedError is the count of manifests retained because an L0 or manifest
	// delete returned an error; subsequent sweeps retry remaining deletions.
	SkippedError int
}

// Reap executes one cross-entity reclamation sweep across compaction/, verifying
// each manifest's target L1 object before deleting listed L0 files and the
// manifest itself. Individual manifest failures are logged and skipped without
// halting the sweep, and missing objects are ignored idempotently on retry.
func (r *L0Reaper) Reap(ctx context.Context) ReapResult {
	var result ReapResult
	if telemetry.L0ReapSweeps != nil {
		telemetry.L0ReapSweeps.Add(1)
	}

	// List all manifests across entities under compaction/, ignoring stray keys
	// that do not end in .manifest.
	const manifestsPrefix = "compaction/"
	manifestKeys, err := r.lister.ListObjects(ctx, r.bucket, manifestsPrefix, 0)
	if err != nil {
		log.Printf("l0_reaper: list %s: %v — sweep skipped (store sick?); retry next interval", manifestsPrefix, err)
		return result
	}

	for _, manifestKey := range manifestKeys {
		if err := ctx.Err(); err != nil {
			log.Printf("l0_reaper: cancelled mid-sweep after %d manifest(s): %v", len(manifestKeys), err)
			return result
		}
		if !strings.HasSuffix(manifestKey, ".manifest") {
			continue
		}

		// Read and parse the manifest using ParseManifest so query and reaper share
		// identical manifest parsing semantics.
		rc, derr := r.downloader.Download(ctx, r.bucket, manifestKey)
		if derr != nil {
			log.Printf("l0_reaper: read manifest %s: %v — skipped (preserve; cannot verify L1 without the manifest)", manifestKey, derr)
			result.SkippedOrphan++
			if telemetry.L0ReapSkippedOrphan != nil {
				telemetry.L0ReapSkippedOrphan.Add(1)
			}
			continue
		}
		body, _ := readManifestBody(rc)
		_ = rc.Close()
		l1Key, l0Keys := ParseManifest(body)

		// Verify the target L1 object opens before deleting any L0 file; any
		// download failure treats the manifest as an orphan and retains L0s.
		if l1Key == "" {
			log.Printf("l0_reaper: manifest %s has no L1 key — skipped (preserve; cannot verify a missing L1)", manifestKey)
			result.SkippedOrphan++
			if telemetry.L0ReapSkippedOrphan != nil {
				telemetry.L0ReapSkippedOrphan.Add(1)
			}
			continue
		}
		l1rc, l1err := r.downloader.Download(ctx, r.bucket, l1Key)
		if l1err != nil {
			log.Printf("l0_reaper: WARN manifest %s → L1 %s not verifiable: %v — L0s PRESERVED (backstop; the L1 is either gone or the store is reporting it gone)", manifestKey, l1Key, l1err)
			result.SkippedOrphan++
			if telemetry.L0ReapSkippedOrphan != nil {
				telemetry.L0ReapSkippedOrphan.Add(1)
			}
			continue
		}
		_ = l1rc.Close()

		// Delete each manifest-listed L0 file; if any delete fails, keep the
		// manifest on disk so the next sweep retries the remainder idempotently.
		deletesOK := true
		for _, l0Key := range l0Keys {
			if err := r.deleter.Delete(ctx, r.bucket, l0Key); err != nil {
				log.Printf("l0_reaper: delete L0 %s (manifest %s): %v — manifest RETAINED (partial reap; already-deleted L0s stay deleted; this + remaining L0s retry next sweep)", l0Key, manifestKey, err)
				deletesOK = false
				break
			}
			result.ReapedL0++
		}
		if !deletesOK {
			result.SkippedError++
			continue
		}

		// Delete the manifest only after all listed L0 deletions succeed.
		if err := r.deleter.Delete(ctx, r.bucket, manifestKey); err != nil {
			log.Printf("l0_reaper: delete manifest %s: %v — L0s already reaped; manifest retained, retries next sweep", manifestKey, err)
			result.SkippedError++
			continue
		}

		result.ReapedManifests++
		if telemetry.L0ReapManifestsReaped != nil {
			telemetry.L0ReapManifestsReaped.Add(1)
		}
	}

	if telemetry.L0ReapL0Deleted != nil {
		telemetry.L0ReapL0Deleted.Add(float64(result.ReapedL0))
	}
	log.Printf("l0_reaper: sweep complete — manifests reaped=%d, L0s deleted=%d, skipped orphan(L1 gone/sick)=%d, skipped error(delete failed)=%d",
		result.ReapedManifests, result.ReapedL0, result.SkippedOrphan, result.SkippedError)
	return result
}

// Compile-time interface satisfaction check for L0Reaper.
var _ interface {
	Reap(ctx context.Context) ReapResult
} = (*L0Reaper)(nil)
