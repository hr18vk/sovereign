// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// CRDTDeltaEvent version and payload-integrity tests.
//
// The version test runs the decoder in a child process to check that a version
// mismatch reaches t.Fatalf rather than continuing with zero-valued fields.
// The integrity test exercises a local helper that compares PayloadDigest with
// SHA-256(payload); production validation is implemented by ReconstructEntry.
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
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// versionMismatchFiresEnv selects the child-process subtest that is expected
// to call t.Fatalf. A subprocess is required because testing.T.Fatalf invokes
// runtime.Goexit, which recover cannot intercept.
const versionMismatchFiresEnv = "CRDT_WIRE_VERSION_MISMATCH_FIRES"

// buildCRDTDeltaEventFrame builds a CRDTDeltaEvent frame. It is a self-contained
// builder (it does not route through encodeEntryToCRDTDeltaEvent) so the
// version-mismatch test can inject a wrong version tag, and the integrity
// test can inject a deliberately inconsistent payloadDigest without disturbing
// the roundtrip test's canonical builder. The payload string is carried
// verbatim so the integrity check can recompute SHA-256 and compare.
//
// version: the value stamped as the frame's version tag (the version-mismatch
// test uses a value != CRDTDeltaEventWireVersion to drive the mismatch).
//
// digest:  the value stamped into the PayloadDigest field. For the integrity
// test this is deliberately not SHA-256(payload) to surface the wire-integrity
// gap; the test-local helper re-hashes and catches it.
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

// Version-mismatch refusal.

// TestVersionMismatchRefusal runs the decoder in a child test process and
// checks both its nonzero exit and version-mismatch diagnostic. If the decoder
// stops rejecting mismatched versions, the child reaches its return guard or
// exits successfully and the parent fails.
func TestVersionMismatchRefusal(t *testing.T) {
	if os.Getenv(versionMismatchFiresEnv) == "1" {
		// The decoder must terminate this subtest on a version mismatch.
		t.Run("expectFatal", func(t *testing.T) {
			wrongVersion := CRDTDeltaEventWireVersion + 1
			frame := buildCRDTDeltaEventFrame(t, wrongVersion, rtPayloadDigest, rtPayload)
			// decodeCRDTDeltaEvent must t.Fatalf here: the on-wire version
			// (wrongVersion) != the compiled-in CRDTDeltaEventWireVersion.
			// If this returns at all, the refusal branch was removed.
			_ = decodeCRDTDeltaEvent(t, frame)
			t.Fatalf("decodeCRDTDeltaEvent returned on a version mismatch (got %d, want %d) instead of calling t.Fatalf",
				wrongVersion, CRDTDeltaEventWireVersion)
		})
		return
	}

	// Run only the child subtest in a fresh process.
	if testing.Short() {
		t.Skip("version-mismatch refusal spawns a child `go test`; skip in -short")
	}
	moduleRoot := crdtCapnpModuleRoot(t)
	args := []string{
		"test",
		"-run", "^TestVersionMismatchRefusal/expectFatal$",
		"-count=1",
		"-v",
		"./pkg/sync/",
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot
	// Preserve module and toolchain settings and select the child subtest.
	cmd.Env = append(os.Environ(), versionMismatchFiresEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// A nonzero exit is expected from the decoder's version-mismatch fatal.
	if err := cmd.Run(); err == nil {
		t.Fatalf("invariant broken: child go test exited 0 — decodeCRDTDeltaEvent did not refuse the mismatched version. Expected non-zero (fatal). Child output:\n%s", out.String())
	}
	combined := out.String()
	exitCode := cmd.ProcessState.ExitCode()
	if exitCode == 0 {
		t.Fatalf("invariant broken: child exit code 0; the version-mismatch fatal did not fire.\nchild output:\n%s", combined)
	}
	// Match the decoder's diagnostic as well as the exit status so an unrelated
	// child failure cannot satisfy the test.
	const want = "CRDTDeltaEvent wire version mismatch"
	if !strings.Contains(combined, want) {
		t.Fatalf("invariant broken: child failed (exit code %d) but did not emit the version-mismatch fatal message containing %q. Child output:\n%s",
			exitCode, want, combined)
	}
	// Also reject the legacy return-guard wording as the source of failure.
	const guardStr = "wire-integrity guard failed: decodeCRDTDeltaEvent returned"
	if strings.Contains(combined, guardStr) {
		t.Fatalf("invariant broken: child printed the return-guard message, meaning decodeCRDTDeltaEvent returned instead of fataling. Child output:\n%s", combined)
	}
	t.Logf("child exited %d with the expected version-mismatch diagnostic", exitCode)
}

// crdtCapnpModuleRoot finds go.mod with a bounded upward walk so the child
// process runs from the module root without a hard-coded path.
func crdtCapnpModuleRoot(t *testing.T) string {
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

// Payload-digest cross-validation.

// decodeCRDTDeltaEventWithIntegrity decodes a version-checked event and
// compares its payload with SHA-256(payload). It returns *wireIntegrityError
// on mismatch so the test can inspect the rejection.
func decodeCRDTDeltaEventWithIntegrity(t *testing.T, data []byte) (capnp_schema.CRDTDeltaEvent, error) {
	t.Helper()
	ev := decodeCRDTDeltaEvent(t, data) // preserves version gate
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

// wireIntegrityError identifies payload-digest mismatches independently of
// unrelated decode failures. Its text is used only for diagnostics.
type wireIntegrityError struct {
	recomputed [32]byte
	onWire     []byte
}

func (e *wireIntegrityError) Error() string {
	return "wire-integrity violation: SHA-256(payload) does not equal PayloadDigest"
}

// TestWireIntegrityCrossValidation checks acceptance of a consistent pair and
// rejection of a mismatched pair with the specific integrity error type.
func TestWireIntegrityCrossValidation(t *testing.T) {
	// Case 1: consistent pair. Helper must accept (no error).
	consistent := buildCRDTDeltaEventFrame(
		t, CRDTDeltaEventWireVersion, rtPayloadDigest, rtPayload)
	if _, err := decodeCRDTDeltaEventWithIntegrity(t, consistent); err != nil {
		t.Fatalf("consistent pair: helper rejected a valid (payload, digest) pair: %v — the integrity check must pass when SHA-256(payload)==PayloadDigest", err)
	}

	// Case 2: the digest hashes different bytes from the payload, so the helper
	// must return wireIntegrityError.
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
		t.Fatalf("invariant broken: helper accepted a mismatched (payload, payloadDigest) pair — wire-integrity gap is live: SHA-256(payload) != PayloadDigest but the helper returned nil")
	}
	var wie *wireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("invariant broken: helper rejected the mismatched pair with the wrong error type %T; expected *wireIntegrityError so the error is specific to the integrity failure", err)
	}
	// Confirm that the rejection is the integrity error rather than an
	// unrelated version failure.
	if !strings.Contains(err.Error(), "wire-integrity violation") {
		t.Fatalf("rejection error message is not the wire-integrity violation: %q", err.Error())
	}
	t.Logf("mismatched payload and digest rejected with %q", err.Error())
}
