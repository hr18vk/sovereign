// Package chaos implements the Stage 6 Chaos Layer for the Supremum Ledger
// engine. See wal.go for the recovery substrate and supervisor.go for the
// decoupled Supervisor-Worker process architecture.
//
// PHYSICS (Blueprint Stage 6 §2):
//
//	Native Go recovers panics with recover(), but a SIGSEGV occurring in
//	off-heap C-space (mmap'd memory the GC does not scan) cannot be caught by
//	recover() — it violently terminates the ENTIRE parent process. The civic
//	engine therefore CANNOT execute in the same failure domain as the HTTP
//	API layer. This package puts the engine in a child process and the
//	listening socket in the supervisor; a worker SIGSEGV is recovered from
//	the WAL without dropping a single active connection.
package chaos

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ---------------------------------------------------------------------------
// Supervisor ↔ Worker IPC protocol (a length-prefixed binary frame stream)
// ---------------------------------------------------------------------------
//
// The Supervisor and Worker are separate OS processes communicating over the
// Worker's stdin (Supervisor→Worker) and stdout (Worker→Supervisor). A pipe
// is used deliberately: it survives a child SIGSEGV in exactly the way a shared
// goroutine address space does not — the supervisor observes EOF on the
// child's stdout read side as the crash signal.
//
// Frame wire layout (big-endian, total header = 9 bytes):
//
//	[0]       op            (1 byte)
//	[1:5]     payloadLen    (4 bytes, uint32; cap 4 GiB)
//	[5:9]     frameSeq      (4 bytes, uint32)
//	[9..]     payload       (payloadLen bytes)

// frameHeaderLen is the fixed size of each frame's header, in bytes.
const frameHeaderLen = 9

// FrameOp is the operation byte that prefixes every protocol frame.
type FrameOp byte

const (
	OpSubmitOK   FrameOp = 0x02 // Worker→Supervisor: mutation durable+WAL-fsynced
	OpQuery      FrameOp = 0x03 // Worker→Supervisor: reports a query Merkle root
	OpHello      FrameOp = 0x04 // Worker→Supervisor: startup (nodeID, lamport, root)
	OpBye        FrameOp = 0x05 // Worker→Supervisor: graceful shutdown
	OpPoke       FrameOp = 0x06 // Supervisor→Worker: keepalive (echoed via OpHello)
	OpCrashProbe FrameOp = 0x07 // Supervisor→Worker: run the chaos fuzzer (SIGSEGV)
	OpSubmit     FrameOp = 0x08 // Supervisor→Worker: apply+WAL-log a mutation
)

// Frame is a decoded protocol frame.
type Frame struct {
	Op       FrameOp
	FrameSeq uint32
	Payload  []byte
}

// writeFrame encodes and writes one frame to w.
func writeFrame(w io.Writer, op FrameOp, seq uint32, payload []byte) error {
	var hdr [frameHeaderLen]byte
	hdr[0] = byte(op)
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[5:9], seq)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads and decodes one frame from r. Returns io.EOF (not wrapped)
// on a clean end-of-stream — which the supervisor interprets as a child
// crash (or graceful shutdown if the last frame was OpBye). A truncated
// header or payload is returned as an error: a half-closed pipe mid-frame is
// the exact SIGSEGV-crash-mid-write signature the supervisor must recognize.
func readFrame(r io.Reader) (Frame, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Frame{}, io.EOF
		}
		return Frame{}, err
	}
	op := FrameOp(hdr[0])
	payloadLen := binary.BigEndian.Uint32(hdr[1:5])
	seq := binary.BigEndian.Uint32(hdr[5:9])
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, fmt.Errorf("chaos/proto: truncated payload for op 0x%x: %w", op, err)
		}
	}
	return Frame{Op: op, FrameSeq: seq, Payload: payload}, nil
}
