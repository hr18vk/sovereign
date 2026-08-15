// Phase 2b — Version-Gate & Wire-Integrity Teeth.
//
// This file closes the two honest limitations Phase 2a self-flagged in its
// §8 report:
//
//	(a) The version tag's mismatch branch in decodeCRDTDeltaEvent (the
//	    refusal to silently fall through to zero-received fields — the
//	    audit's C5 guard) was structurally present but exercised only on
//	    the happy path. Test 1 fires that branch and asserts it fatals.
//
//	(b) CRDTDeltaEvent's payload and payloadDigest are carried independently
//	    on the wire; nothing on the decode path cross-validates
//	    payloadDigest == SHA-256(payload). Phase 2a named this gap (a buggy
//	    peer could send a mismatched pair and Join would accept it) but did
//	    not address it. Test 2 proves the integrity-check technique works on
//	    a mismatched pair via a TEST-LOCAL helper. It does NOT add a
//	    production-side check: the location of production enforcement
//	    (decode-time vs Join-time) is a contract decision the brief reserved
//	    for the verifier — see the report's Test 2 section for the escalation.
//
// Scope discipline: this file ADDS tests only. It touches no production wire
// code (crdt.go / hamt_arena.go / decodeCRDTDeltaEvent are untouched). The
// existing Phase 2/2a assertion battery in crdt_capnp_roundtrip_test.go is
// not modified — the verifier's diff of that file will be empty.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// phase2bVersionMismatchFiresEnv is the sentinel env var the parent test sets
// when it re-execs go test to run the inner "expectFatal" subtest. The inner
// subtest is the one that is EXPECTED to call t.Fatalf via the decoder's
// version-mismatch branch; the parent asserts the child exited non-zero with
// the exact fatal message. This is the repo's existing os/exec subprocess
// idiom — see internal/chaos/survival_test.go — applied to asserting a
// Go testing t.Fatalf actually fires (Goexit, which recover() cannot catch on
// go1.26.1, so a bare defer-recover pattern would not work).
const phase2bVersionMismatchFiresEnv = "PHASE2B_VERSION_MISMATCH_FIRES"

// buildCRDTDeltaEventFrame is the Phase 2b frame builder. It is a SMALL,
// self-contained builder (it does not route through
// encodeEntryToCRDTDeltaEvent) so Test 2 can inject a deliberately
// INCONSISTENT payloadDigest without disturbing the roundtrip-test's canonical
// builder, and so Test 1 can inject a deliberately wrong version tag. The
// payload string is carried verbatim so the integrity check (Test 2) can
// recompute SHA-256 and compare.
//
// version: the value stamped as the frame's version tag (Test 1 uses a value
//
//	!= CRDTDeltaEventWireVersion to drive the mismatch).
//
// digest:  the value stamped into the PayloadDigest field. For Test 2 this is
//
//	deliberately NOT SHA-256(payload) to surface the wire-integrity
//	gap; the test-local helper re-hashes and catches it.
//
// payload: the value stamped into the Payload Text field.
func buildCRDTDeltaEventFrame(t *testing.T, version uint16, digest [32]byte, payload string) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(version)
	if err := ev.SetPayloadDigest(digest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(1)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// ----------------------------------------------------------------------------
// TEST 1 — Version-Mismatch Refusal (mandated, no escalation possible).
// ----------------------------------------------------------------------------

// TestPhase2b_VersionMismatchRefusal is the parent: it re-execs go test with
// the sentinel env var set and asserts the inner subtest called t.Fatalf
// (child failed with the exact version-mismatch message). The mechanism is
// the repo's existing os/exec subprocess idiom — see
// internal/chaos/survival_test.go. Go's testing.T.Fatalf invokes
// runtime.Goexit, which recover() cannot catch (confirmed on go1.26.1), so a
// recover()-in-the-parent pattern would not work; the subprocess pattern is
// the smallest repo-conventional way to assert a t.Fatalf actually fires.
//
// TEETH: if a future engineer removes the version check from
// decodeCRDTDeltaEvent, the inner subtest stops calling t.Fatalf, the child
// exits 0, and this parent's "child exit code != 0" assertion fails → the test
// FAILS, proving the silent-fall-through path is not merely structurally dead
// but provably dead.
func TestPhase2b_VersionMismatchRefusal(t *testing.T) {
	if os.Getenv(phase2bVersionMismatchFiresEnv) == "1" {
		// --- INNER SESSION: this invocation is the re-exec'd child. ---
		t.Run("expectFatal", func(t *testing.T) {
			wrongVersion := CRDTDeltaEventWireVersion + 1
			frame := buildCRDTDeltaEventFrame(t, wrongVersion, rtPayloadDigest, rtPayload)
			// decodeCRDTDeltaEvent MUST t.Fatalf here: the on-wire version
			// (wrongVersion) != the compiled-in CRDTDeltaEventWireVersion.
			// If this returns at all, the refusal branch was removed.
			_ = decodeCRDTDeltaEvent(t, frame)
			t.Fatalf("PHASE2b INVARIANT BROKEN: decodeCRDTDeltaEvent returned on a version mismatch (got %d, want %d) instead of calling t.Fatalf — the silent-fall-through path the C5 audit demanded dead is ALIVE",
				wrongVersion, CRDTDeltaEventWireVersion)
		})
		return
	}

	// --- OUTER (parent) session: spawn the child and assert it fatal'd. ---
	if testing.Short() {
		t.Skip("Phase 2b version-mismatch refusal spawns a child `go test`; skip in -short")
	}
	moduleRoot := phase2bModuleRoot(t)
	args := []string{
		"test",
		"-run", "^TestPhase2b_VersionMismatchRefusal/expectFatal$",
		"-count=1",
		"-v",
		"./pkg/sync/",
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot
	// Propagate the host env so the child `go test` resolves the module + GOTOOLCHAIN
	// identically to the parent. The sentinel flips the child into the inner session.
	cmd.Env = append(os.Environ(), phase2bVersionMismatchFiresEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// The child is EXPECTED to FAIL (non-zero exit) because the inner subtest
	// called t.Fatalf via the decoder's mismatch branch — that is exactly the
	// assertion.
	if err := cmd.Run(); err == nil {
		t.Fatalf("PHASE2b INVARIANT BROKEN: child go test exited 0 — decodeCRDTDeltaEvent did NOT refuse the mismatched version. Expected non-zero (fatal). Child output:\n%s", out.String())
	}
	combined := out.String()
	exitCode := cmd.ProcessState.ExitCode()
	if exitCode == 0 {
		t.Fatalf("PHASE2b INVARIANT BROKEN: child exit code 0; the version-mismatch fatal did not fire.\nchild output:\n%s", combined)
	}
	// The child MUST have printed the exact version-mismatch fatal string from
	// decodeCRDTDeltaEvent. The literal pin is the TEETH: if a future engineer
	// swaps the t.Fatalf for a t.Logf (instead of removing it), the child would
	// exit 0 and the exit-code assertion above catches that; if they replace
	// it with a DIFFERENT t.Fatalf message, this string assertion catches the
	// semantic drift.
	const want = "CRDTDeltaEvent wire version mismatch"
	if !strings.Contains(combined, want) {
		t.Fatalf("PHASE2b INVARIANT BROKEN: child failed (exit code %d) but did NOT emit the version-mismatch fatal message containing %q. Child output:\n%s",
			exitCode, want, combined)
	}
	// Similarly, the child must NOT have hit the inner return-guard message —
	// the fatal must come from decodeCRDTDeltaEvent, not the guard. (If the
	// refusal branch is removed, the guard message would appear and the
	// exit-code check above would already have failed; this is a belt-and-
	// braces pin that the fatal source is the decoder.)
	const guardStr = "PHASE2b INVARIANT BROKEN: decodeCRDTDeltaEvent returned"
	if strings.Contains(combined, guardStr) {
		t.Fatalf("PHASE2b INVARIANT BROKEN: child printed the return-guard message, meaning decodeCRDTDeltaEvent returned instead of fataling. Child output:\n%s", combined)
	}
	t.Logf("Phase 2b Test 1 GREEN: child exited %d and emitted the version-mismatch fatal (refusal-to-silently-fallthrough is provably dead).", exitCode)
}

// phase2bModuleRoot walks up from cwd to find go.mod. pkg/sync is two levels
// under the module root (pkg/sync -> pkg -> root), so a small bounded walk is
// sufficient and avoids hard-coding a path. Mirrors internal/chaos.moduleRoot.
func phase2bModuleRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod above %q", cwd)
	return ""
}

// ----------------------------------------------------------------------------
// TEST 2 — Wire-Integrity Cross-Validation (Form B: Green, test-local check).
// ----------------------------------------------------------------------------

// decodeCRDTDeltaEventWithIntegrity is a TEST-LOCAL helper: it delegates the
// version-gated decode to the existing decodeCRDTDeltaEvent (preserving the
// refusal-to-silently-fall-through guard) and then adds the wire-integrity
// check Phase 2a flagged — it recomputes SHA-256(payload) off the wire and
// compares to the on-wire PayloadDigest. On mismatch it returns a typed
// *wireIntegrityError (NOT a t.Fatalf) so a caller can assert the rejection.
//
// IMPORTANT — SCOPE DISCIPLINE: this is a TEST-LOCAL helper, NOT a production
// change. The real production enforcement (where in the engine the integrity
// check should live) is an architectural decision the brief reserved for the
// verifier; see the Phase 2b report's Test 2 section for the escalation. The
// options are decode-time (cheap, rejects before Join sees the entity ID —
// loses diagnostic context) vs Join-time (couples integrity to merge
// semantics) vs a new ReconstructEntry stage (cleanest seam, new code path).
// Form B proves the technique works without picking any of them.
func decodeCRDTDeltaEventWithIntegrity(t *testing.T, data []byte) (capnp_schema.CRDTDeltaEvent, error) {
	t.Helper()
	ev := decodeCRDTDeltaEvent(t, data) // preserves version gate + teeth
	gotPayload, err := ev.Payload()
	if err != nil {
		return ev, err
	}
	gotDigest, err := ev.PayloadDigest()
	if err != nil {
		return ev, err
	}
	recomputed := sha256.Sum256([]byte(gotPayload))
	if !bytes.Equal(recomputed[:], gotDigest) {
		return ev, &wireIntegrityError{
			recomputed: recomputed,
			onWire:     append([]byte(nil), gotDigest...),
		}
	}
	return ev, nil
}

// wireIntegrityError is the typed error Test 2 asserts on; a typed error
// (rather than a sentinel string) keeps the teeth specific to the integrity
// failure and avoids depending on an error string match for the pass/fail
// signal — the string is reported only for diagnostics.
type wireIntegrityError struct {
	recomputed [32]byte
	onWire     []byte
}

func (e *wireIntegrityError) Error() string {
	return "wire-integrity violation: SHA-256(payload) does not equal PayloadDigest"
}

// TestPhase2b_WireIntegrityCrossValidation proves the SHA-256 cross-validation
// technique works on both a consistent and a mismatched pair. It does NOT add a
// production-side check; production enforcement is a future phase (see the
// report's Test 2 escalation).
//
// TEETH: if a future engineer regresses the test-local integrity check (e.g.,
// removes the sha256 recompute, drops the bytes.Equal, or makes the helper
// always return nil), the mismatched-pair case returns no error and the
// "expected wireIntegrityError" assertion fails → the test FAILS.
func TestPhase2b_WireIntegrityCrossValidation(t *testing.T) {
	// --- Case 1: consistent pair. Helper MUST accept (no error). ---
	consistent := buildCRDTDeltaEventFrame(
		t, CRDTDeltaEventWireVersion, rtPayloadDigest, rtPayload)
	if _, err := decodeCRDTDeltaEventWithIntegrity(t, consistent); err != nil {
		t.Fatalf("consistent pair: helper rejected a valid (payload, digest) pair: %v — the integrity check must pass when SHA-256(payload)==PayloadDigest", err)
	}

	// --- Case 2: mismatched pair. Helper MUST reject (wireIntegrityError). ---
	// A buggy peer could stamp PayloadDigest with SHA-256 of SOME OTHER bytes.
	// Here the digest is SHA-256(rtPayload + suffix) while the payload is
	// still rtPayload — exactly the wire-integrity gap Phase 2a §8(b) named:
	// payloadDigest != SHA-256(payload), a mismatched pair Join would accept.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "tampered-by-a-buggy-peer"))
	if wrongDigest == rtPayloadDigest {
		// Astronomically improbable for SHA-256, but a test must be
		// deterministic; force inequality so Case 2 is a real mismatch.
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("could not construct a deterministic mismatched digest; give up rather than risk a false green")
		}
	}
	mismatched := buildCRDTDeltaEventFrame(
		t, CRDTDeltaEventWireVersion, wrongDigest, rtPayload)
	_, err := decodeCRDTDeltaEventWithIntegrity(t, mismatched)
	if err == nil {
		t.Fatalf("PHASE2b INVARIANT BROKEN: helper accepted a mismatched (payload, payloadDigest) pair — wire-integrity gap is LIVE: SHA-256(payload) != PayloadDigest but the helper returned nil")
	}
	var wie *wireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2b INVARIANT BROKEN: helper rejected the mismatched pair with the wrong error type %T; expected *wireIntegrityError so the teeth are specific to the integrity failure", err)
	}
	// Diagnostic-only string check: the rejection must be the integrity
	// message, not the version-mismatch fatal (which would mean the frame was
	// malformed in an unrelated way and Case 2 tested the wrong property).
	if !strings.Contains(err.Error(), "wire-integrity violation") {
		t.Fatalf("rejection error message is not the wire-integrity violation: %q", err.Error())
	}
	t.Logf("Phase 2b Test 2 GREEN: helper rejects a mismatched (payload, payloadDigest) pair with %q (technique proven; production enforcement is a future phase).", err.Error())
}
