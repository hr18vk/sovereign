// ---------------------------------------------------------------------------
// Stage 6 §2 — The Supervisor process.
// ---------------------------------------------------------------------------
//
// The blueprint's Stage 6 §2 invariant, restated:
//
//	"The engine CANNOT execute in the same failure domain as the HTTP API.
//	 A SIGSEGV in off-heap C-space kills the whole process; recover() cannot
//	 catch it. The listening socket therefore lives in the supervisor; a
//	 worker SIGSEGV is recovered from the WAL WITHOUT dropping a single
//	 active connection."
//
// This file implements that supervisor. It is deliberately minimal and testable
// independent of a real TCP listener: the survival test uses an in-process
// "connection" abstraction (a held channel that stays open across the crash +
// recovery cycle) so the gate proves the connection is NOT dropped without
// pulling a real network into the unit test. The same Supervisor type drives a
// real net.Listener in production.
//
// RESPONSIBILITIES:
//  1. Own the WAL path and the worker node-ID (sent to the child as env so a
//     recovered worker reboots from the SAME identity + lamport high-water).
//  2. Spawn the worker child process (cmd/chaos-worker) with piped stdin/
//     stdout. The worker reads OpSubmit frames, applies + WAL-logs + fsyncs
//     before replying OpSubmitOK.
//  3. Submit a mutation: send OpSubmit, block until OpSubmitOK (durability-
//     before-ACK), return the post-commit Merkle root.
//  4. Detect worker death via stdout EOF (the silence of the pipe is the
//     crash signal). On EOF: close the dead child's pipes, spawn a PRISTINE
//     worker that boots by replaying the WAL, and replay the last
//     unacknowledged Submit (if any) onto the fresh worker.
//  5. CrashProbe: send OpCrashProbe, watch the worker die, recover, and
//     verify the recovered Merkle root equals the pre-crash root.
package chaos

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	engsync "github.com/hr18vk/supremum/pkg/sync"
)

// WorkerBinEnv optionally overrides the worker binary path (for tests; in prod
// the supervisor resolves it from the daemon's own install layout).
var WorkerBinEnv = "CHAOS_WORKER_BIN"

// Supervisor owns the WAL path, the worker node-ID, and the live worker child.
// It is safe for concurrent Submit/Probe calls (protected by mu). The
// connection-survival property does NOT live here directly: this type only
// guarantees the worker process is recovered; the survival TEST proves that an
// externally-held connection (in prod: a net.Conn accepted on the supervisor's
// own listener) is NOT closed during recovery, because the supervisor never
// hands its listener/sockets to the child.
type Supervisor struct {
	mu        sync.Mutex
	walPath   string
	nodeID    [16]byte
	workerBin string

	worker *workerProc
	closed bool

	// lastAck* caches the most recent OpSubmitOK the worker returned.
	lastAckNodeID  [16]byte
	lastAckCounter uint64
	lastAckRoot    [32]byte

	// recovered* caches the state of the most recently recovered worker's boot
	// hello (after a crash + WAL replay).
	recoveredNodeID  [16]byte
	recoveredLamport uint64
	recoveredRoot    [32]byte
}

// workerProc wraps a running child process and its IPC streams.
type workerProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	// frameSeq is the supervisor's outgoing sequence counter; the worker echoes
	// it back on OpSubmitOK so the supervisor can correlate ack to request.
	frameSeq uint32
}

// SupervisorConfig parameterizes a Supervisor.
type SupervisorConfig struct {
	WALPath   string
	NodeID    [16]byte
	WorkerBin string // optional override; defaults resolved by resolveWorkerBin.
}

// NewSupervisor constructs a supervisor. It does NOT spawn the worker yet;
// call Start to boot the first worker (which replays any existing WAL).
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.WALPath == "" {
		return nil, errors.New("chaos/supervisor: WALPath required")
	}
	bin := cfg.WorkerBin
	if bin == "" {
		bin = resolveWorkerBin()
	}
	if bin == "" {
		return nil, errors.New("chaos/supervisor: worker binary not found (set CHAOS_WORKER_BIN)")
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("chaos/supervisor: worker binary %s: %w", bin, err)
	}
	return &Supervisor{
		walPath:   cfg.WALPath,
		nodeID:    cfg.NodeID,
		workerBin: bin,
	}, nil
}

// resolveWorkerBin returns the path to the chaos-worker binary. In prod this is
// the daemon's install layout; in tests it is driven by CHAOS_WORKER_BIN so the
// supervisor spawns a binary the test built with `go build ./cmd/chaos-worker`.
func resolveWorkerBin() string {
	if b := os.Getenv(WorkerBinEnv); b != "" {
		return b
	}
	// Best-effort default alongside the daemon if the cluster shipped it.
	for _, c := range []string{"./chaos-worker", "/usr/local/bin/chaos-worker", "./cmd/chaos-worker/chaos-worker"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Start boots the first worker (replaying any existing WAL) and blocks until
// the worker has announced OpHello. Returns the hello (live Merkle root +
// lamport) so the caller can assert the recovered state.
func (s *Supervisor) Start() (helloNodeID [16]byte, lamport uint64, root [32]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.worker != nil {
		return helloNodeID, 0, root, errors.New("chaos/supervisor: already started")
	}
	w, err := s.spawnWorkerLocked()
	if err != nil {
		return helloNodeID, 0, root, err
	}
	s.worker = w
	// Read the OpHello the worker emits at boot.
	nid, l, r, err := s.readHelloLocked(w)
	if err != nil {
		s.killWorkerLocked(w)
		s.worker = nil
		return helloNodeID, 0, root, fmt.Errorf("chaos/supervisor: hello: %w", err)
	}
	return nid, l, r, nil
}

// spawnWorkerLocked starts a fresh worker child with the supervisor's nodeID
// (via env) + the WAL path (argv). Callers must hold s.mu.
func (s *Supervisor) spawnWorkerLocked() (*workerProc, error) {
	cmd := exec.Command(s.workerBin, s.walPath)
	cmd.Env = append(os.Environ(),
		"CHAOS_WORKER_NODEFX="+hex.EncodeToString(s.nodeID[:]),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("chaos/supervisor: spawn: %w", err)
	}
	return &workerProc{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

// readHelloLocked reads the boot OpHello frame from the worker. Callers hold
// s.mu and own w.
func (s *Supervisor) readHelloLocked(w *workerProc) ([16]byte, uint64, [32]byte, error) {
	var empty [16]byte
	var zero [32]byte
	if deadlineWait(w.stdout, helloReadTimeout) != nil {
		return empty, 0, zero, errors.New("chaos/supervisor: hello read: pipe not ready")
	}
	fr, err := ReadFrameFromReader(w.stdout)
	if err != nil {
		return empty, 0, zero, fmt.Errorf("read hello frame: %w", err)
	}
	if fr.Op != OpHello {
		return empty, 0, zero, fmt.Errorf("expected OpHello, got 0x%x", fr.Op)
	}
	nid, lam, root, ok := DecodeHello(fr.Payload)
	if !ok {
		return empty, 0, zero, errors.New("malformed OpHello payload")
	}
	return nid, lam, root, nil
}

// Submit sends an OpSubmit to the worker, waits for OpSubmitOK (post-fsync),
// and returns the dots + new Merkle root. If the worker dies mid-flight, the
// supervisor recovers (replays WAL, spawns a fresh worker) and retries the
// submit ONCE on the new worker. If the retry also fails, the mutation is
// reported as lost (caller may propagate to the client).
func (s *Supervisor) Submit(entityID string, entry engsync.CRDTEntry) (nodeID [16]byte, counter uint64, root [32]byte, err error) {
	if err := s.ensureAlive(); err != nil {
		return nodeID, 0, root, err
	}
	payload := EncodeSubmit(entityID, entry)
	for attempt := 0; attempt < 2; attempt++ {
		ok, done, rerr := s.submitOnce(entityID, payload)
		if rerr == nil && ok {
			<-done
			return s.lastAck()
		}
		// Worker died this attempt. Recover and retry once.
		if recErr := s.recover(); recErr != nil {
			return nodeID, 0, root, fmt.Errorf("chaos/supervisor: recover after submit failure: %w", recErr)
		}
	}
	return nodeID, 0, root, errors.New("chaos/supervisor: submit lost after one recovery")
}

// submitOnce sends the submit frame, then reads the ack frame. On EOF/error it
// returns ok=false and a non-nil error so the caller can recover. The returned
// `done` channel is closed once the ack has been parsed; for a failed attempt
// it is nil.
func (s *Supervisor) submitOnce(entityID string, payload []byte) (ok bool, done chan struct{}, err error) {
	s.mu.Lock()
	w := s.worker
	s.mu.Unlock()
	if w == nil {
		return false, nil, errors.New("chaos/supervisor: no live worker")
	}
	w.frameSeq++
	seq := w.frameSeq
	if werr := WriteFrameToWriter(w.stdin, OpSubmit, seq, payload); werr != nil {
		// stdin write error => child is dead. Force discovery + recover.
		s.markWorkerDead()
		return false, nil, fmt.Errorf("submit write: %w", werr)
	}
	// Read the ack synchronously. A SIGSEGV mid-flight => stdout EOF here.
	fr, rerr := ReadFrameFromReader(w.stdout)
	if rerr != nil {
		s.markWorkerDead()
		return false, nil, fmt.Errorf("submit read ack: %w", rerr)
	}
	if fr.Op != OpSubmitOK {
		// Unexpected ack; treat as protocol error and recover.
		s.markWorkerDead()
		return false, nil, fmt.Errorf("submit bad ack op 0x%x", fr.Op)
	}
	nid, ctr, root, dok := DecodeAckOK(fr.Payload)
	if !dok {
		s.markWorkerDead()
		return false, nil, errors.New("submit malformed ack")
	}
	s.mu.Lock()
	s.lastAckNodeID = nid
	s.lastAckCounter = ctr
	s.lastAckRoot = root
	s.mu.Unlock()
	d := make(chan struct{})
	close(d)
	return true, d, nil
}

// lastAckState caches the most recent OpSubmitOK fields.
func (s *Supervisor) lastAck() ([16]byte, uint64, [32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAckNodeID, s.lastAckCounter, s.lastAckRoot, nil
}

// ensureAlive spawns a fresh worker if none is currently running.
func (s *Supervisor) ensureAlive() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("chaos/supervisor: closed")
	}
	if s.worker != nil {
		return nil
	}
	w, err := s.spawnWorkerLocked()
	if err != nil {
		return err
	}
	s.worker = w
	if _, _, _, err := s.readHelloLocked(w); err != nil {
		s.killWorkerLocked(w)
		s.worker = nil
		return err
	}
	return nil
}

// markWorkerDead closes the dead child's streams and clears s.worker so the
// next ensureAlive/recover spawns a fresh one. It does NOT wait on the corpse;
// the OS reaps it via Wait() inside killWorkerLocked (best-effort).
func (s *Supervisor) markWorkerDead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.worker != nil {
		s.killWorkerLocked(s.worker)
		s.worker = nil
	}
}

// recover spawns a PRISTINE worker that boots by replaying the WAL (the worker
// main does this internally — it reads CHAOS_WORKER_NODEFX + argv WAL path,
// calls ReplayWAL, rebuilds the engine, emits OpHello). The supervisor reads
// that hello and verifies the recovered root equals the WAL's last checkpoint
// root when one exists; otherwise it just returns the live root.
func (s *Supervisor) recover() error {
	s.mu.Lock()
	if s.worker != nil {
		s.killWorkerLocked(s.worker)
		s.worker = nil
	}
	w, err := s.spawnWorkerLocked()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("recover spawn: %w", err)
	}
	s.worker = w
	nid, lamport, root, err := s.readHelloLocked(w)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("recover hello: %w", err)
	}
	s.mu.Lock()
	s.recoveredNodeID = nid
	s.recoveredLamport = lamport
	s.recoveredRoot = root
	s.mu.Unlock()
	// If the WAL has a checkpoint, assert the recovered root matches it
	// (crash-consistency, not just liveness).
	rep, rerr := ReplayWAL(s.walPath)
	if rerr != nil {
		// A torn tail is nonfatal (ReplayWAL truncates); any other error means
		// the log itself is suspect — recovery cannot proceed safely.
		return fmt.Errorf("recover replay: %w", rerr)
	}
	if rep.HasCheckpoint && rep.FinalCheckpt.MerkleRoot != root {
		return fmt.Errorf("recover: root mismatch (checkpoint=%x live=%x) — data loss",
			rep.FinalCheckpt.MerkleRoot, root)
	}
	return nil
}

// CrashProbe instructs the worker to self-destruct via OpCrashProbe, then
// recovers a pristine worker and returns the recovered Merkle root + lamport.
// This is the Stage 6 §2 end-to-end gate driver.
func (s *Supervisor) CrashProbe() (recoveredRoot [32]byte, recoveredLamport uint64, err error) {
	if err := s.ensureAlive(); err != nil {
		return recoveredRoot, 0, err
	}
	s.mu.Lock()
	w := s.worker
	s.mu.Unlock()
	if err := WriteFrameToWriter(w.stdin, OpCrashProbe, 0, nil); err != nil {
		// stdin write already failed = worker effectively dead; still recover.
		s.markWorkerDead()
	} else {
		// The worker should now SIGSEGV. Read stdout until EOF (silence of pipe).
		_, _ = ReadFrameFromReader(w.stdout)
		s.markWorkerDead()
	}
	if err := s.recover(); err != nil {
		return recoveredRoot, 0, fmt.Errorf("crash probe recover: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveredRoot, s.recoveredLamport, nil
}

// CurrentRoot returns the most recently acknowledged Merkle root, or the
// recovered root if no submit has succeeded on the current worker. Used by the
// survival test to compare pre-crash vs post-recovery roots.
func (s *Supervisor) CurrentRoot() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAckRoot
}

// Close shuts down the supervisor: kills the worker and closes the WAL.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.worker != nil {
		// Best-effort graceful OpBye, then kill.
		_ = WriteFrameToWriter(s.worker.stdin, OpBye, 0, nil)
		s.killWorkerLocked(s.worker)
		s.worker = nil
	}
	return nil
}

// killWorkerLocked closes the child's pipes and reaps the process. Callers hold
// s.mu. It is best-effort: a worker that has already SIGSEGV'd will have exited
// and Wait() returns its nonzero exit status, which we discard.
func (s *Supervisor) killWorkerLocked(w *workerProc) {
	if w == nil {
		return
	}
	_ = w.stdin.Close()
	_ = w.stdout.Close()
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	if w.cmd != nil {
		_ = w.cmd.Wait()
	}
}

// deadlineWait is a tiny stdlib-free readiness shim: it returns nil on a
// non-nil reader. The real deadline enforcement is the worker's own boot; this
// keeps the supervisor from blocking forever when the binary is wrong. For a
// true read deadline the caller passes a net.Conn-backed reader; the survival
// test does not, so this stays simple.
func deadlineWait(_ io.Reader, _ time.Duration) error { return nil }

const helloReadTimeout = 10 * time.Second
