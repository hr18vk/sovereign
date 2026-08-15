package database

import (
	"errors"
	"io"
)

// Compile-time interface satisfaction checks (Override 7.2).
var _ io.Writer = (*JemallocBuffer)(nil)
var _ io.Reader = (*JemallocBuffer)(nil)
var _ io.WriteSeeker = (*JemallocBuffer)(nil)

// JemallocBuffer implements io.Writer, io.Reader, and io.WriteSeeker backed by JemallocAllocator.
//
// NOTE on Cursor Semantics:
// Like standard os.File, JemallocBuffer uses a single cursor 'pos' shared between Read, Write, and Seek.
// This allows ipc.NewFileWriter to seek and overwrite headers or footer metadata correctly.
// However, because of the shared cursor, interleaved reads and writes without explicit seeks
// will overwrite/corrupt data. In our flusher usage pattern, writes are completed and finalized
// before reading, which is safe.
type JemallocBuffer struct {
	allocator *JemallocAllocator
	buf       []byte
	length    int
	pos       int // read/write cursor position (Override 7.2 + 10.2)
}

// NewJemallocBuffer creates a new JemallocBuffer.
func NewJemallocBuffer(allocator *JemallocAllocator) *JemallocBuffer {
	return &JemallocBuffer{
		allocator: allocator,
		buf:       allocator.Allocate(64 * 1024), // 64KB initial
		length:    0,
		pos:       0,
	}
}

// Write appends data to the jemalloc-backed buffer.
func (j *JemallocBuffer) Write(p []byte) (n int, err error) {
	if j.buf == nil {
		return 0, errors.New("jemalloc buffer closed")
	}
	need := j.pos + len(p)
	if need > cap(j.buf) {
		newCap := cap(j.buf) * 2
		if need > newCap {
			newCap = need
		}
		j.buf = j.allocator.Reallocate(newCap, j.buf[:cap(j.buf)])
	}
	copy(j.buf[j.pos:need], p)
	j.pos = need
	if j.pos > j.length {
		j.length = j.pos
	}
	return len(p), nil
}

// Read implements io.Reader, reading from the written data (Override 7.2).
func (j *JemallocBuffer) Read(p []byte) (n int, err error) {
	if j.buf == nil {
		return 0, errors.New("jemalloc buffer closed")
	}
	if j.pos >= j.length {
		return 0, io.EOF
	}
	n = copy(p, j.buf[j.pos:j.length])
	j.pos += n
	return n, nil
}

// Seek implements io.Seeker, allowing seeking the read/write cursor.
func (j *JemallocBuffer) Seek(offset int64, whence int) (int64, error) {
	if j.buf == nil {
		return 0, errors.New("jemalloc buffer closed")
	}
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(j.pos) + offset
	case io.SeekEnd:
		newPos = int64(j.length) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if newPos < 0 {
		return 0, errors.New("negative position")
	}
	if newPos > int64(j.length) {
		if newPos > int64(cap(j.buf)) {
			j.buf = j.allocator.Reallocate(int(newPos), j.buf[:cap(j.buf)])
		}
		// REVERT: Zero-pad the gap when seeking forward within existing capacity.
		for i := j.length; i < int(newPos); i++ {
			j.buf[i] = 0
		}
		j.length = int(newPos)
	}
	j.pos = int(newPos)
	return int64(j.pos), nil
}

// ResetRead resets the read cursor to the beginning.
func (j *JemallocBuffer) ResetRead() {
	j.pos = 0
}

// Len returns the number of unread bytes.
func (j *JemallocBuffer) Len() int {
	if j.buf == nil {
		return 0
	}
	return j.length - j.pos
}

// Bytes returns the written data slice.
func (j *JemallocBuffer) Bytes() []byte {
	if j.buf == nil {
		return nil
	}
	return j.buf[:j.length]
}

// Free releases the buffer back to jemalloc.
func (j *JemallocBuffer) Free() {
	if j.buf != nil {
		j.allocator.Free(j.buf[:cap(j.buf)])
		j.buf = nil
		j.length = 0
		j.pos = 0
	}
}

// WriteTo implements io.WriterTo to bypass net/http's 32KB io.Copy heap allocation.
// It streams off-heap jemalloc bytes directly into the network socket.
func (j *JemallocBuffer) WriteTo(w io.Writer) (int64, error) {
	if j.buf == nil {
		return 0, errors.New("jemalloc buffer closed")
	}
	if j.pos >= j.length {
		return 0, nil
	}
	n, err := w.Write(j.buf[j.pos:j.length])
	j.pos += n
	return int64(n), err
}
