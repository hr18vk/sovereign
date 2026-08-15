package durability

// Day 11 — M2: LocalFS, the local-filesystem S3 shim.
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
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LocalFS is a local-filesystem implementation of the three S3 interfaces
// consumed by internal/database (S3Uploader, S3Lister, S3Downloader) and by
// the Day-11 recovery path (the dot-bearing snapshot read/write).
//
// The `bucket` argument carried by S3Lister/S3Downloader is IGNORED — the
// flusher's S3Uploader.Upload already omits bucket (the bucket lives in the
// S3 client config out-of-band, not in the interface), so for LocalFS a single
// `root` directory IS the bucket. Callers that pass a bucket get the same
// root; this keeps the flusher ("l0/...") and the resolver ("l0/...") on the
// same keyspace, and the recovery snapshot ("ckpt/...") alongside them.
type LocalFS struct {
	root string
}

// NewLocalFS constructs a LocalFS rooted at root, creating the directory if
// missing. It is safe to construct even when the snapshot feature is unused;
// the cost is one MkdirAll.
func NewLocalFS(root string) (*LocalFS, error) {
	if root == "" {
		return nil, errors.New("durability/localfs: empty root")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("durability/localfs: mkdir %s: %w", root, err)
	}
	return &LocalFS{root: root}, nil
}

// Root returns the on-disk root (exposed for snapshot.go + tests).
func (l *LocalFS) Root() string { return l.root }

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
func (l *LocalFS) Upload(ctx context.Context, key string, data io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	abs, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("durability/localfs: mkdir for %s: %w", key, err)
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("durability/localfs: create %s: %w", key, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, data); err != nil {
		return fmt.Errorf("durability/localfs: write %s: %w", key, err)
	}
	if err := f.Sync(); err != nil { // durability: fsync the snapshot/Arrow file before return (local substitute for S3's durability guarantee)
		return fmt.Errorf("durability/localfs: sync %s: %w", key, err)
	}
	return nil
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

// Delete implements database.S3Deleter (Day 16, ADR-0021). It removes the file
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
