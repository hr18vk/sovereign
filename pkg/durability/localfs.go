// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// — M2: LocalFS, the local-filesystem S3 shim.
//
// internal/database speaks to S3 through three narrow interfaces — S3Uploader
// (l0_flusher.go), S3Lister + S3Downloader (query.go). M8 (ADR-0016 §5) wires
// the LSM tier into the production path for the FIRST time; to prove the seam
// on named WITHOUT an S3 account, this file implements all three interfaces
// over a plain OS directory. The flusher uploads Arrow IPC under "l0/<...>";
// the recovery snapshot (snapshot.go) writes the dot-bearing image under
// "ckpt/<LamportHigh>". LocalFS treats both as files under `root`.
//
// HONEST SCOPE: this is a CI/local substitute for S3. It is correct (the byte
// stream round-trips) but it is not S3 — no eventual-consistency listing
// lag, no multipart, no cross-region GET. Production deployments inject a
// real S3 client that satisfies the same three interfaces.
//
// Key hygiene: keys are S3-style (forward-slash). A key is rejected if it is
// absolute, empty, or escapes `root` via ".." — a snapshot path that left the
// root would be a silent durability lie.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// LocalFS is a local-filesystem implementation of the three S3 interfaces
// consumed by internal/database (S3Uploader, S3Lister, S3Downloader) and by
// the recovery path (the dot-bearing snapshot read/write).
//
// The `bucket` argument carried by S3Lister/S3Downloader is IGNORED — the
// flusher's S3Uploader.Upload already omits bucket (the bucket lives in the
// S3 client config out-of-band, not in the interface), so for LocalFS a single
// `root` directory IS the bucket. Callers that pass a bucket get the same
// root; this keeps the flusher ("l0/...") and the resolver ("l0/...") on the
// same keyspace, and the recovery snapshot ("ckpt/...") alongside them.
type LocalFS struct {
	root string
	// uploadHook is a TEST-ONLY park/spy point on Upload (T-A1 — the
	// SetSyncHookForTest precedent, internal/chaos/wal.go:325). It is nil in
	// production (NewLocalFS leaves it nil; only SetUploadHookForTest sets it).
	// It fires at the TOP of Upload, BEFORE any write/fsync, so a test can park
	// the checkpoint's image/index upload and prove the committing PutLocals
	// does NOT wait for it (the decouple). Set it BEFORE triggering any
	// checkpoint; the goroutine spawn establishes the happens-before edge, so no
	// concurrent write races the read.
	uploadHook func()
}

// uploadTmpPrefix is the CreateTemp pattern for the atomic publish. The files
// are UNCOMMITTED by definition — only the rename(2) publishes — so any
// `.upload-*` a listing can see is an orphan from an interrupted process.
const uploadTmpPrefix = ".upload-"

// uploadDirSyncs counts the parent-directory fsyncs Upload has issued (
// ). It exists so the guard can PROVE the fsync is in the publish path
// (a counter incremented only after a successful fsync); the physical
// durability itself is POSIX-delegated and disclosed as such in the fork
// report. Off the hot path (one per checkpoint/flush), so one atomic add is
// noise against the fsync itself.
var uploadDirSyncs atomic.Int64

// uploadL0Uploads counts the query-tier (l0/) per-entity Arrow uploads (
// T-B1). It is the O(N)-vs-O(Δ) WORK metric the delta-flush cuts: each l0/ upload
// is one file carrying BOTH fsyncs (tmp.Sync:150 + fsyncParentDir:172). A full
// re-flush OVERWRITES the same per-entity keys, so the distinct-file COUNT cannot
// distinguish full from delta — but the upload WORK can (O(N) vs O(Δ) per
// checkpoint). The ckpt/ recovery image is excluded (always 1 per checkpoint).
// Off the hot path (one increment per upload).
var uploadL0Uploads atomic.Int64

// uploadL0UploadsCount is the test accessor for uploadL0Uploads (T-B1).
func uploadL0UploadsCount() int64 { return uploadL0Uploads.Load() }

// NewLocalFS constructs a LocalFS rooted at root, creating the directory if
// missing. It is safe to construct even when the snapshot feature is unused;
// the cost is one MkdirAll + one orphan sweep.
//
// construction REAPS interrupted-upload orphans (`.upload-*`).
// LocalFS is a single-process root (the local S3 shim; production S3 has no
// local files), so at construction no upload of ours can be in flight and every
// `.upload-*` present is by definition an orphan from a previous, dead life.
// Reaping at boot is what bounds the l0/<hash8>/.upload-* wedge
// (l1_compactor.go CompactionByHash8 hard-errors on the orphan sorting first)
// to ONE process lifetime. A reap failure is logged, never fatal: the
// ListObjects filter is the independent second layer.
func NewLocalFS(root string) (*LocalFS, error) {
	if root == "" {
		return nil, errors.New("durability/localfs: empty root")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("durability/localfs: mkdir %s: %w", root, err)
	}
	l := &LocalFS{root: root}
	if _, err := l.ReapUploadOrphans(context.Background()); err != nil {
		log.Printf("durability/localfs: orphan reap at boot failed (the ListObjects filter still excludes them): %v", err)
	}
	return l, nil
}

// Root returns the on-disk root (exposed for snapshot.go + tests).
func (l *LocalFS) Root() string { return l.root }

// SetUploadHookForTest installs a TEST-ONLY hook that fires at the top of every
// Upload, before any write/fsync. It is the T-A1 park point: a test
// parks the checkpoint's image/index upload here to prove the committing
// PutLocals returns without waiting for it (the decouple), with the inline
// (reverted) shape as the blocking negative control. Production NEVER sets it
// (NewLocalFS leaves it nil). Set before any upload; not safe to swap mid-flight.
func (l *LocalFS) SetUploadHookForTest(hook func()) { l.uploadHook = hook }

// resolve joins key under root and verifies the result stays inside root.
func (l *LocalFS) resolve(key string) (string, error) {
	if key == "" {
		return "", errors.New("durability/localfs: empty key")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("durability/localfs: absolute key rejected: %q", key)
	}
	joined := filepath.Join(l.root, filepath.FromSlash(key))
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(l.root)
	if err != nil {
		return "", err
	}
	if rootAbs != abs && !strings.HasPrefix(abs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("durability/localfs: key escapes root: %q", key)
	}
	return abs, nil
}

// Upload implements database.S3Uploader. `size` is advisory (S3 uses it for
// ContentLength); LocalFS copies until EOF and ignores size, matching the
// io.Reader contract the flusher relies on.
//
// ATOMIC PUBLISH (ADR-0045): the write goes to a
// temp file in the SAME directory, is fsync'd, and is then rename(2)'d over the
// target. The pre-form opened the target O_CREATE|O_WRONLY|O_TRUNC —
// an in-place truncating overwrite — so a crash or a failed write (ENOSPC/EIO,
// or kill -9 in the window after the WAL anchor fsynced) left a TORN file at a
// key a durable checkpoint anchor points at. With the ckpt/<watermark> key
// collision (the watermark repeats across back-to-back checkpoints), that made
// a survivable disk-full indistinguishable from corruption. rename(2) is
// atomic: a reader sees the OLD bytes or the NEW bytes, never a torn mix, and a
// failed write leaves the old file intact. (S3's PUT is likewise atomic per
// object, so this is the honest local substitute, not a divergence.)
func (l *LocalFS) Upload(ctx context.Context, key string, data io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.uploadHook != nil {
		l.uploadHook() // TEST-ONLY (T-A1): park/spy before any fsync.
	}
	abs, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("durability/localfs: mkdir for %s: %w", key, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), uploadTmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("durability/localfs: create temp for %s: %w", key, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename below lands
	if _, err := io.Copy(tmp, data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("durability/localfs: write %s: %w", key, err)
	}
	if err := tmp.Sync(); err != nil { // fsync BEFORE the rename (the local substitute for S3's durability guarantee)
		_ = tmp.Close()
		return fmt.Errorf("durability/localfs: sync %s: %w", key, err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("durability/localfs: chmod %s: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("durability/localfs: close %s: %w", key, err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return fmt.Errorf("durability/localfs: rename %s: %w", key, err)
	}
	//rename(2) is ATOMIC but not DURABLE — the directory entry
	// lives in the parent dir's page cache until that DIRECTORY is fsync'd. On a
	// power loss the rename can revert to the OLD bytes while the WAL's 0x05
	// anchor (already fsync'd, bridge.go:399 before:446) describes the NEW
	// ones — exactly the stale-image input the binding check exists to catch.
	// fsync the parent directory after every publish. The cost is one extra
	// fsync per upload (measured in the fork report); an error here means the
	// object exists but is not durable — surfaced, never swallowed.
	if err := fsyncParentDir(filepath.Dir(abs)); err != nil {
		return fmt.Errorf("durability/localfs: dir fsync for %s: %w", key, err)
	}
	if strings.HasPrefix(key, "l0/") {
		uploadL0Uploads.Add(1) // T-B1: the query-tier per-entity upload count
	}
	return nil
}

// fsyncParentDir fsyncs a directory so a rename(2) into it is durable, not
// merely atomic. The observability counter increments ONLY after a
// successful fsync — the guard asserts the count, so a regression that drops
// the fsync (or the whole call) is caught by injection.
func fsyncParentDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	uploadDirSyncs.Add(1)
	return nil
}

// ReapUploadOrphans deletes every `.upload-*` file under root — the temp files
// an interrupted Upload leaves behind (the defer os.Remove only runs in a LIVE
// process; kill -9 between CreateTemp and Rename orphans them). Without a
// reaper an orphan under l0/<hash8>/ sorts BEFORE the real Arrow files
// ('.'=0x2E < '0'=0x30) and CompactionByHash8 hard-errors on it EVERY sweep,
// permanently (register availability wedge); orphans under ckpt/, l1/,
// and compaction/ had no deleter at all. Returns the count; every removal is
// LOGGED (a delete is never silent here).
//
// SAFETY: only call when no upload can be in flight (boot, or an operator
// sweep with the writer stopped). NewLocalFS calls it at construction, which
// is exactly that condition for this single-process root.
func (l *LocalFS) ReapUploadOrphans(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	reaped := 0
	err := filepath.WalkDir(l.root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), uploadTmpPrefix) {
			return nil
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reap orphan %s: %w", path, err)
		}
		reaped++
		log.Printf("durability/localfs: reaped interrupted-upload orphan %s", path)
		return nil
	})
	if err != nil {
		return reaped, fmt.Errorf("durability/localfs: orphan reap: %w", err)
	}
	return reaped, nil
}

// ListObjects implements database.S3Lister. It walks `root` recursively and
// returns the keys (S3-style, forward-slash, root-relative) whose path has the
// given prefix, sorted ascending, capped at maxKeys (maxKeys<=0 ⇒ all). This
// mirrors S3's prefix semantics for the resolver ("l0/") and for recovery
// ("ckpt/").
func (l *LocalFS) ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error) {
	_ = bucket
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var keys []string
	err := filepath.WalkDir(l.root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(l.root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}
		//`.upload-*` temp files are UNCOMMITTED uploads, never
		// objects — S3 has no such keys (a PUT is atomic per object), so
		// returning them here was the shim lying about S3 semantics, and it is
		// what wedged CompactionByHash8. Exclude them at the source so
		// ListObjects("ckpt/") really does enumerate exactly the available
		// checkpoints (snapshot.go's claim, falsified by the orphans).
		if strings.HasPrefix(d.Name(), uploadTmpPrefix) {
			return nil
		}
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("durability/localfs: list %s: %w", prefix, err)
	}
	sort.Strings(keys)
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	return keys, nil
}

// Download implements database.S3Downloader. The caller MUST close the returned
// ReadCloser.
func (l *LocalFS) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	_ = bucket
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := l.resolve(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("durability/localfs: open %s: %w", key, err)
	}
	return f, nil
}

// Delete implements database.S3Deleter (ADR-0021). It removes the file
// at `key` under `root`. It is IDEMPOTENT: a missing file (os.IsNotExist) is
// NOT an error — it returns nil, so the L0 reaper's partial-reap retry loop
// makes forward progress across sweeps (a prior sweep may have already
// reclaimed the backstop file, or a manual operator may have cleaned it). The
// `bucket` argument is ignored (LocalFS's single `root` IS the bucket — the
// same convention Upload/Download/ListObjects use).
//
// SAFETY NOTE: this is a PLAIN object delete. The L0 reaper (l0_reaper.go) is
// the ONLY production caller, and it calls Delete on an L0 key ONLY after
// verifying the manifest's L1 still exists (Stage C). A standalone delete of
// an L0 that has no verified L1 would remove the sole durable copy — the
// reaper's Stage C guard exists to prevent exactly that. LocalFS.Delete itself
// is unopinionated; the safety contract lives in the reaper.
func (l *LocalFS) Delete(ctx context.Context, bucket, key string) error {
	_ = bucket
	if err := ctx.Err(); err != nil {
		return err
	}
	abs, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil {
		if os.IsNotExist(err) {
			// File already gone — this is fine. The backstop was already
			// reclaimed (a prior reaper sweep, or a manual operator). The
			// reaper's idempotency contract relies on this returning nil so a
			// partial reap can resume without re-erroring. Log-free on purpose:
			// NotFound is the EXPECTED steady state once the reaper has caught
			// up (every superseded L0 it tries again is already gone).
			return nil
		}
		return fmt.Errorf("durability/localfs: delete %s: %w", key, err)
	}
	return nil
}

// Compile-time interface satisfaction (catches a signature drift in
// internal/database the moment it is edited, rather than at the Bridge wiring
// site).
var (
	_ interface {
		Upload(ctx context.Context, key string, data io.Reader, size int64) error
	} = (*LocalFS)(nil)
	_ interface {
		ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error)
	} = (*LocalFS)(nil)
	_ interface {
		Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	} = (*LocalFS)(nil)
	_ interface {
		Delete(ctx context.Context, bucket, key string) error
	} = (*LocalFS)(nil)
)
