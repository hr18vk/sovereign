// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// LocalFS implements the storage interfaces used by internal/database and the
// recovery path over a local directory. The flusher writes Arrow IPC objects
// under "l0/<...>", and snapshots use "ckpt/<LamportHigh>".
//
// LocalFS is intended for tests and local development. It does not reproduce
// S3 listing consistency, multipart uploads, or cross-region requests.
// Production deployments supply an S3 client with the same interfaces.
//
// Keys use forward slashes. Empty and absolute keys, and keys that escape the
// root through "..", are rejected.

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
// the recovery path that reads and writes the dot-bearing snapshot.
//
// The bucket argument to S3Lister and S3Downloader is ignored. S3 clients
// carry their bucket in configuration, and Upload has no bucket parameter, so
// the LocalFS root represents one bucket shared by uploads and reads.
type LocalFS struct {
	root string
	// uploadHook pauses tests before an upload writes or syncs data. Production
	// leaves it nil. Tests install it before starting the checkpoint goroutine,
	// which orders the write before Upload reads it.
	uploadHook func()
}

// uploadTmpPrefix identifies temporary uploads. Rename publishes an object;
// any matching file left behind belongs to an interrupted upload.
const uploadTmpPrefix = ".upload-"

// uploadDirSyncs counts successful parent-directory syncs so tests can verify
// that Upload includes that step. The filesystem provides the actual durability.
var uploadDirSyncs atomic.Int64

// uploadL0Uploads counts per-entity Arrow uploads. Unlike distinct filenames,
// this distinguishes full flushes from delta flushes even when both overwrite
// the same keys. Each upload includes a file sync and a parent-directory sync;
// checkpoint images under ckpt/ are excluded.
var uploadL0Uploads atomic.Int64

// uploadL0UploadsCount returns the upload counter to tests.
func uploadL0UploadsCount() int64 { return uploadL0Uploads.Load() }

// NewLocalFS constructs a LocalFS rooted at root, creating the directory if
// missing. It is safe to construct even when the snapshot feature is unused;
// the cost is one MkdirAll plus one orphan sweep.
//
// Construction removes temporary files left by an earlier process. A LocalFS
// root belongs to one process, so no upload can be active at this point.
// Reaping prevents CompactionByHash8 from encountering a temporary filename
// before the Arrow files. Failure to reap is logged; ListObjects independently
// excludes these files.
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

// Root returns the filesystem directory used for all objects.
func (l *LocalFS) Root() string { return l.root }

// SetUploadHookForTest installs a hook at the start of Upload, before any
// write or sync. Tests use it to pause a checkpoint image or index upload and
// verify that PutLocals does not wait for that upload (ADR-0050). Install the
// hook before starting an upload; changing it concurrently is not supported.
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
// Upload writes and syncs a temporary file in the destination directory before
// renaming it over the target. Readers therefore see either the old object or
// the complete new object, never a truncated mixture. A failed write leaves the
// old object intact, matching S3's atomic PUT semantics (ADR-0045).
func (l *LocalFS) Upload(ctx context.Context, key string, data io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.uploadHook != nil {
		l.uploadHook() // pause tests before any write or sync
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
	if err := tmp.Sync(); err != nil { // sync file contents before publishing the name
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
	// Rename is atomic but the new directory entry is durable only after the
	// parent directory is synced. Without this sync, power loss could restore the
	// old image while the synced WAL anchor describes the new one. An error here
	// means the object exists but its publication is not durable.
	if err := fsyncParentDir(filepath.Dir(abs)); err != nil {
		return fmt.Errorf("durability/localfs: dir fsync for %s: %w", key, err)
	}
	if strings.HasPrefix(key, "l0/") {
		uploadL0Uploads.Add(1) // query-tier per-entity upload count
	}
	return nil
}

// fsyncParentDir makes a rename in dir durable. The counter advances only
// after a successful sync, allowing tests to detect a removed call.
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

// ReapUploadOrphans removes temporary files left when a process stops between
// CreateTemp and Rename. Such a file under l0/<hash8>/ sorts before Arrow files
// and causes CompactionByHash8 to fail. It returns the removal count and logs
// each deleted path.
//
// Call it only while no upload is active, such as during construction or with
// the writer stopped.
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
		// Temporary uploads are not published objects. Excluding them preserves
		// S3 PUT semantics and prevents CompactionByHash8 from reading partial
		// data; checkpoint listings likewise contain only complete images.
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

// Download implements database.S3Downloader. The caller must close the returned
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

// Delete implements database.S3Deleter (ADR-0021). It removes key beneath the
// root and ignores bucket. A missing object is not an error, allowing the L0
// reaper to resume a partially completed sweep.
//
// Delete does not check whether another durable copy exists. The L0 reaper is
// responsible for verifying the manifest's L1 before deleting any input L0.
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
			// Another sweep or an operator may already have removed the object.
			// Returning nil lets a partial reap resume, and repeated cleanup does
			// not produce log noise after the reaper has caught up.
			return nil
		}
		return fmt.Errorf("durability/localfs: delete %s: %w", key, err)
	}
	return nil
}

// Check the internal/database storage interface signatures at compile time.
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
