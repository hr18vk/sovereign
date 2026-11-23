// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// Tests for the fingerprint sweep crosscheck: when roots are divergent, the
// sweep must not claim the equal-roots-divergent-fingerprints condition; when
// roots are equal but fingerprints diverge, it must report the measured pair
// count per ADR-0045 §5.1.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func runFingerprintSweepCaptureStderr(t *testing.T, fpByNode []string, cr convergeResult) (fpResult, string) {
	t.Helper()
	nodes := make([]node, len(fpByNode))
	for i, fp := range fpByNode {
		fpCopy := fp
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/debug/state-fingerprint" {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprintf(w, `{"state_fingerprint":%q}`, fpCopy)
		}))
		t.Cleanup(srv.Close)
		nodes[i] = node{
			idx:         i,
			region:      "us-east-1",
			metricsAddr: strings.TrimPrefix(srv.URL, "http://"),
		}
	}
	origStderr := os.Stderr
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = wPipe
	defer func() { os.Stderr = origStderr }()

	res := fingerprintSweep(runCfg{fpArmed: true}, nodes, cr)
	_ = wPipe.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, rPipe)
	_ = rPipe.Close()
	return res, buf.String()
}

// TestFingerprintSweep_DivergentRootsDoNotClaimVoid — when roots are
// divergent (cr.converged=false and no two distinct-FP nodes share a root),
// fingerprintSweep must not claim the equal-roots-divergent-fingerprints
// condition. Negative control: SOVEREIGN_TEST_FAULT_GATE_SWEEP=1 enables the
// forced overclaim to verify the crosscheck catches it.
func TestFingerprintSweep_DivergentRootsDoNotClaimVoid(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_GATE_SWEEP") == "1" {
		fingerprintSweepVoidOverclaimBugInject.Store(true)
		t.Cleanup(func() { fingerprintSweepVoidOverclaimBugInject.Store(false) })
	}
	cr := convergeResult{
		converged: false,
		nodeRoots: map[int]string{
			0: "aaaa0000",
			1: "bbbb1111",
		},
	}
	res, stderr := runFingerprintSweepCaptureStderr(t, []string{"fp-node-0", "fp-node-1"}, cr)
	if res.allEqual || res.swept != 2 {
		t.Fatalf("expected swept=2 allEqual=false, got %+v", res)
	}
	if strings.Contains(stderr, "equal roots with divergent bytes (ADR-0045 §5.1;") {
		t.Fatalf("distinct fingerprints under distinct roots falsely claimed equal-root divergence: %s", strings.TrimSpace(stderr))
	}
	if !strings.Contains(stderr, "roots also divergent") || !strings.Contains(stderr, "equal_root_divergent_fp_pairs=0; ADR-0045 §5.1 condition not observed") {
		t.Fatalf("expected roots-also-divergent diagnostic with equal_root_divergent_fp_pairs=0, got: %s", strings.TrimSpace(stderr))
	}
}

// TestFingerprintSweep_EqualRootsDivergentFPClaimsVoid — when two nodes share
// the same measured Merkle root yet report different state fingerprints, the
// ADR-0045 §5.1 condition is observed and the diagnostic must report it with
// the measured pair count.
func TestFingerprintSweep_EqualRootsDivergentFPClaimsVoid(t *testing.T) {
	cr := convergeResult{
		converged: false,
		nodeRoots: map[int]string{
			0: "same_root_deadbeef",
			1: "same_root_deadbeef",
			2: "other_root_cafebabe",
		},
	}
	res, stderr := runFingerprintSweepCaptureStderr(t, []string{"fp-A", "fp-B", "fp-B"}, cr)
	if res.allEqual || res.swept != 3 {
		t.Fatalf("expected swept=3 allEqual=false, got %+v", res)
	}
	if !strings.Contains(stderr, "equal roots with divergent bytes (ADR-0045 §5.1; equal_root_divergent_fp_pairs=1)") {
		t.Fatalf("expected measured ADR-0045 §5.1 claim with equal_root_divergent_fp_pairs=1, got: %s", strings.TrimSpace(stderr))
	}
}
