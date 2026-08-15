// Package database — Day 16 (ADR-0021): the L0 reaper + the land-mine closure.
//
// This fork closes the THREE OPEN-P1 residuals ADR-0020 §6 deferred:
//
//	(c) The L0 REAPER — the compaction write path (l1_compactor.go) creates a
//	    manifest at compaction/{hex8}/{sysNs}.manifest listing the L0 files it
//	    merged into the L1, but the L0 files are KEPT FOREVER as the crash-
//	    recovery backstop (delete-after-read-safety was deferred "a future
//	    fork"; ADR-0019 §6, ADR-0020 §6c). The l0/ directory grows monotonically
//	    — every 64-checkpoint compaction leaves N L0 files PLUS the manifest.
//	    The reaper deletes the manifest-listed L0 files AFTER verifying the L1
//	    still exists, then deletes the manifest. The backstop is reclaimed, not
//	    leaked.
//
// This file is the reaper. The two land-mines (§0.b MaxValidTime, §0.c DataDir)
// live in l0_flusher.go + pkg/durability/recovery.go respectively.
//
// SAFETY CONTRACT — the reaper NEVER auto-deletes an L0 whose L1 is not first
// VERIFIED PRESENT. The whole reaper exists to enforce this invariant:
//
//	Stage C: a manifest's L1 is downloaded (existence probe). If the download
//	FAILS for ANY reason — a genuine 404 (the L1 was lost), an S3 outage, a
//	permission error — the L0 files are PRESERVED and the manifest is SKIPPED.
//	Treating any download failure as "preserve" is the SAFEST reading: the only
//	cost of a transient false-skip is the L0s stay around ONE more 5-minute
//	interval, while the cost of deleting an L0 whose L1 is actually-gone is
//	LOSING THE SOLE DURABLE COPY of that entity's merged history. A chronic
//	store outage degrades the reaper to a no-op — the correct safety posture
//	(the backstop is never wrongly reclaimed). This is why the reaper is
//	opt-in (--compaction-reap-enable, default false): a filesystem layer that
//	EVER reports a present L1 as missing would ALSO be a layer that the
//	COMPACTOR trusted to write the L1 in the first place; the operator turns
//	the reaper on ONLY once they trust their storage.
//
// IDEMPOTENCY — LocalFS.Delete returns nil for os.IsNotExist (a prior sweep or
// a manual operator may have already reclaimed a file). So a partial reap
// (some L0s deleted, one delete failed) leaves the manifest on disk; the next
// sweep re-tries the failed delete and the already-deleted ones return nil —
// forward progress is monotone and re-runs are safe.
package database

import (
	"context"
	"log"
	"strings"

	"github.com/hr18vk/supremum/internal/telemetry"
)

// L0Reaper is the cross-entity superseded-L0 disk-reclaim sweep (Day 16,
// ADR-0021). It is COMPLEMENTARY to the per-entity compaction scheduler
// (cmd/sovereign-node.compactionSchedulerLoop): the compactor DRIVES new L1s +
// manifests; the reaper RECLAIMS the L0s the compactor superseded. It runs LESS
// often (default 5m vs the compactor's 30s) — the superseded L0s are a SAFETY
// net, there is ZERO urgency to delete them, and a slower cadence amortizes
// the manifest-list + L1-probe cost over more compactions.
//
// The reaper holds the THREE read/delete S3 seams (S3Lister to scan manifests,
// S3Downloader to read a manifest + probe its L1, S3Deleter to remove an L0 +
// the manifest). It does NOT hold an S3Uploader — it never writes. The same
// concrete *LocalFS the compactor + resolver use is injected for all three
// (one FS root, one keyspace — mirrors the Day-12/14 wiring discipline).
type L0Reaper struct {
	lister     S3Lister     // to scan compaction/{hex8}/{sysNs}.manifest
	downloader S3Downloader // to read a manifest + probe its L1 (existence)
	deleter    S3Deleter    // to remove an L0 + the manifest
	bucket     string       // the S3 bucket (ignored by LocalFS; one root IS the bucket)
}

// NewL0Reaper constructs an L0Reaper over the three S3 seams. The concrete
// production injection is a single *LocalFS for all three (the compactor +
// resolver already share it). The reaper NEVER auto-runs: the caller
// (cmd/sovereign-node) gates the reaper goroutine on --compaction-reap-enable
// (default false — byte-identical Day-15 behavior, the backstop kept forever).
func NewL0Reaper(lister S3Lister, downloader S3Downloader, deleter S3Deleter, bucket string) *L0Reaper {
	return &L0Reaper{
		lister:     lister,
		downloader: downloader,
		deleter:    deleter,
		bucket:     bucket,
	}
}

// ReapResult reports the outcome of one Reap sweep (Law V — disclose the
// counts, not adjectives). All four fields are per-sweep tallies; the telemetry
// counters (registry.go) accumulate them across sweeps.
type ReapResult struct {
	// ReapedManifests is the count of manifests FULLY reaped — every listed L0
	// was deleted AND the manifest itself was deleted. Forward progress.
	ReapedManifests int
	// ReapedL0 is the count of L0 files deleted this sweep (across all fully +
	// partially reaped manifests). A partial reap (some L0s deleted, one
	// failed) still counts the deleted L0s here; the manifest is NOT counted
	// in ReapedManifests (it is retained for the next sweep).
	ReapedL0 int
	// SkippedOrphan is the count of manifests SKIPPED because the L1 they point
	// at could not be verified present (download failed for ANY reason — a
	// genuine 404, an S3 outage, a permission error). The manifest's L0s are
	// PRESERVED as the crash-recovery backstop. This is the load-bearing safety
	// counter: a non-zero SkippedOrphan is the OPERATOR SIGNAL that an L1 was
	// lost (or the store is sick) — the reaper is correctly refusing to delete
	// the backstop.
	SkippedOrphan int
	// SkippedError is the count of manifests where an L0 (or manifest) delete
	// FAILED (a real IO/permission error — NOT a missing file, which is
	// idempotent nil). The manifest is RETAINED; the already-deleted L0s stay
	// deleted; the next sweep retries the failed delete. A non-zero
	// SkippedError is the operator signal that the store is rejecting deletes.
	SkippedError int
}

// Reap runs ONE cross-entity sweep of the reaper. It lists every manifest under
// compaction/, verifies each manifest's L1 still exists, then deletes the
// manifest-listed L0 files + the manifest. The procedure is stages A–F (the
// Stage C L1-exists guard is the safety-critical step — see the file doc).
//
// The sweep is BEST-EFFORT + IDEMPOTENT: a per-manifest error is logged and the
// sweep continues to the next manifest (one sick manifest does NOT stall reaping
// for the rest); re-running Reap on an already-reaped keyspace is a no-op
// (Delete returns nil for missing files; a missing manifest is simply not
// listed). ctx is honored at every list / download / delete.
func (r *L0Reaper) Reap(ctx context.Context) ReapResult {
	var result ReapResult
	if telemetry.L0ReapSweeps != nil {
		telemetry.L0ReapSweeps.Add(1)
	}

	// STAGE A — find completed compactions. List ALL keys under compaction/
	// (uncapped — the reaper reaps EVERY entity, not one at a time). Each
	// manifest is compaction/{hex(hash8)}/{firstSysTimeNs}.manifest. Skip any
	// listed key without the .manifest suffix (defense in depth — the only
	// objects Live under compaction/ are manifests, but a stray non-manifest
	// object is ignored rather than mis-parsed).
	const manifestsPrefix = "compaction/"
	manifestKeys, err := r.lister.ListObjects(ctx, r.bucket, manifestsPrefix, 0)
	if err != nil {
		// A list failure is a sick store — do NOT abort the whole sweep's
		// accounting; there is nothing to reap this round. Log + return the
		// (empty) result. The next sweep retries.
		log.Printf("l0_reaper: list %s: %v — sweep skipped (store sick?); retry next interval", manifestsPrefix, err)
		return result
	}

	for _, manifestKey := range manifestKeys {
		if err := ctx.Err(); err != nil {
			// Cancellation mid-sweep: return what we have so far (honest partial
			// result). The next sweep resumes — Delete is idempotent, so
			// already-deleted L0s/manifests are no-ops and the sweep continues
			// forward from the manifests still listed.
			log.Printf("l0_reaper: cancelled mid-sweep after %d manifest(s): %v", len(manifestKeys), err)
			return result
		}
		// STAGE A filter: only .manifest objects are manifests.
		if !strings.HasSuffix(manifestKey, ".manifest") {
			continue
		}

		// STAGE B — read + parse the manifest via the EXISTING ParseManifest
		// (the same function AsOf + SupersededL0Keys use; one parser, one
		// truth).
		rc, derr := r.downloader.Download(ctx, r.bucket, manifestKey)
		if derr != nil {
			// The manifest itself is unreadable — corrupt, or a store hiccup.
			// CANNOT safely decide: an unreadable manifest may list L0s whose
			// L1 IS present (deletable) OR may be stale (L1 gone). Preserve is
			// the safe default — treat as orphan (cannot verify → preserve).
			log.Printf("l0_reaper: read manifest %s: %v — skipped (preserve; cannot verify L1 without the manifest)", manifestKey, derr)
			result.SkippedOrphan++
			if telemetry.L0ReapSkippedOrphan != nil {
				telemetry.L0ReapSkippedOrphan.Add(1)
			}
			continue
		}
		body, _ := readManifestBody(rc) // Day 26 (ADR-0031): single-grow read, NOT io.ReadAll's doublings
		_ = rc.Close()
		l1Key, l0Keys := ParseManifest(body)

		// STAGE C — verify the L1 STILL EXISTS (the safety guard). The reaper
		// deletes an L0 ONLY if the L1 that superseded it is verified present;
		// otherwise the L0 is the SOLE durable copy and MUST be preserved. The
		// probe is a Download — the S3 interface surface has no Head/Stat, and
		// the reaper is OFF the hot path (one probe per manifest per 5-min
		// sweep), so the open+close-without-reading-the-body cost is bounded
		// by the manifest count and disclosed in ADR-0021 §3. A manifest with
		// NO l1Key (malformed / empty) CANNOT be verified → preserve (orphan).
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
			// The L1 is GONE (or the store is sick and REPORTS it gone). Either
			// way, the L0 files are the backstop — DO NOT delete them. This is
			// the critical safety condition the whole reaper exists to enforce.
			// Treating ANY download failure as "preserve" is the SAFEST reading:
			// a transient outage degrades the reaper to no-op for one interval
			// (harmless), while deleting an L0 whose L1 is actually-gone loses
			// the sole durable copy (catastrophic). SkippedOrphan is the operator
			// signal an L1 was lost / the store is sick.
			log.Printf("l0_reaper: WARN manifest %s → L1 %s not verifiable: %v — L0s PRESERVED (backstop; the L1 is either gone or the store is reporting it gone)", manifestKey, l1Key, l1err)
			result.SkippedOrphan++
			if telemetry.L0ReapSkippedOrphan != nil {
				telemetry.L0ReapSkippedOrphan.Add(1)
			}
			continue
		}
		// L1 verified present. Close without reading the body (existence was
		// the only question).
		_ = l1rc.Close()

		// STAGE D — delete each L0 key listed in the manifest. If a SINGLE
		// delete fails (a real IO/permission error — NOT a missing file, which
		// is idempotent nil), STOP, do NOT delete the manifest. The remaining
		// superseded L0s + the manifest are RETAINED — the next sweep retries
		// (the already-deleted L0s return nil; the failed one is retried). The
		// manifest retention means the sweep resumes EXACTLY where it stopped.
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

		// STAGE E — delete the manifest. Only AFTER every listed L0 delete
		// succeeded. If the manifest delete itself fails, the L0s are already
		// gone — the next sweep re-lists the manifest, re-verifies the L1
		// (still present), and re-tries the L0 deletes (all idempotent nil
		// now), then retries the manifest delete. So a manifest-delete failure
		// is ALSO forward-progress-safe: count it as SkippedError (the manifest
		// couldn't be removed this round) but the L0s are already counted as
		// reaped.
		if err := r.deleter.Delete(ctx, r.bucket, manifestKey); err != nil {
			log.Printf("l0_reaper: delete manifest %s: %v — L0s already reaped; manifest retained, retries next sweep", manifestKey, err)
			result.SkippedError++
			continue
		}

		// STAGE F — tally. This manifest was fully reaped (every L0 + the
		// manifest). The L0 count was accumulated in Stage D; ReapedManifests
		// counts the manifest-to-removal completion.
		result.ReapedManifests++
		if telemetry.L0ReapManifestsReaped != nil {
			telemetry.L0ReapManifestsReaped.Add(1)
		}
	}

	// Accumulate the per-sweep L0-delete count into the cross-sweep counter
	// once (rather than per-delete, which would be an Add per L0 on the reaper
	// path — still off-hot, but a single Add is tidier + matches the
	// per-sweep semantics of the other three counters).
	if telemetry.L0ReapL0Deleted != nil {
		telemetry.L0ReapL0Deleted.Add(float64(result.ReapedL0))
	}
	log.Printf("l0_reaper: sweep complete — manifests reaped=%d, L0s deleted=%d, skipped orphan(L1 gone/sick)=%d, skipped error(delete failed)=%d",
		result.ReapedManifests, result.ReapedL0, result.SkippedOrphan, result.SkippedError)
	return result
}

// Compile-time interface satisfaction (catches a signature drift the moment
// l0_reaper.go is edited — the reaper depends on the three S3 seams by
// interface, so a rename in query.go breaks here at compile time, not at the
// main.go wiring site).
var _ interface {
	Reap(ctx context.Context) ReapResult
} = (*L0Reaper)(nil)
