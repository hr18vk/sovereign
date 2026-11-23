// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// /debug/state-fingerprint exposes StateFingerprint, which incorporates payload
// digests. MerkleRootFromShards incorporates dots only (ADR-0045), so two states
// can have equal roots and different fingerprints. The enabled route returns 200
// with a recomputed fingerprint and returns 404 by default. Setting
// SOVEREIGN_TEST_FAULT_FINGERPRINT=oracleblind substitutes the dot-only root as
// a negative control.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/durability"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

const fpRouteArena uintptr = 16 * 1024 * 1024

func fpRouteNodeID(tag byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = tag
	}
	return id
}

func fpRouteDigest(fill byte) [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = fill
	}
	return d
}

func fpRouteFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free-port probe failed: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// fpRouteSettle waits for the livecheck surface to accept connections.
// startLivecheck binds inside its serve goroutine, so a probe that fires
// before the bind reads connection-refused, not the route's verdict.
func fpRouteSettle(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/livecheck", port))
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the livecheck surface never settled on port %d: %v", port, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fpRouteBuildPair creates two engines with the same nodeID and initial
// counter. Each inserts one entry under the same entityID but with a different
// payload digest, producing identical dots and different state fingerprints.
func fpRouteBuildPair(t *testing.T) (*eng.DeltaCRDTEngine, *eng.DeltaCRDTEngine) {
	t.Helper()
	nid := fpRouteNodeID(0xA1)
	e1, err := eng.NewDeltaCRDTEngine(nid, 1, fpRouteArena)
	if err != nil {
		t.Fatalf("engine 1 construction failed: %v", err)
	}
	e2, err := eng.NewDeltaCRDTEngine(nid, 1, fpRouteArena)
	if err != nil {
		t.Fatalf("engine 2 construction failed: %v", err)
	}
	base := eng.CRDTEntry{
		SystemTime:     1789000000000000000,
		ValidTimeStart: 1,
		ValidTimeEnd:   2,
		AssertionTime:  3,
		DecisionTime:   4,
		H3Index:        0x8f2800000000001,
	}
	a := base
	a.PayloadDigest = fpRouteDigest(0xAA)
	b := base
	b.PayloadDigest = fpRouteDigest(0xBB)
	d1 := e1.InsertLocal("state-fingerprint-key", a)
	d2 := e2.InsertLocal("state-fingerprint-key", b)
	if d1 != d2 {
		t.Fatalf("entries with the same nodeID and initial counter minted different dots: %v vs %v", d1, d2)
	}
	return e1, e2
}

func TestStateFingerprintRoute_ArmedOracleSurface(t *testing.T) {
	e1, e2 := fpRouteBuildPair(t)
	defer func() { _ = e1.Close() }()
	defer func() { _ = e2.Close() }()

	r1, r2 := e1.MerkleRootFromShards(), e2.MerkleRootFromShards()
	fp1, fp2 := durability.StateFingerprint(e1), durability.StateFingerprint(e2)
	t.Logf("payload divergence: root1=%x root2=%x equal=%v | fp1=%x fp2=%x differ=%v", r1[:4], r2[:4], r1 == r2, fp1[:4], fp2[:4], fp1 != fp2)
	if r1 != r2 {
		t.Fatalf("states with identical dots have different roots: %x vs %x", r1, r2)
	}
	if fp1 == fp2 {
		t.Fatalf("StateFingerprint returned equal values for different payload digests")
	}

	t.Setenv("SOVEREIGN_STATE_FP_DEBUG", "1")
	port := fpRouteFreePort(t)
	srv := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port), fpRouteNodeID(0xA1), nil, nil, nil, nil, nil, e1)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	fpRouteSettle(t, port)
	a1 := fpRouteProbe(t, port)
	if a1.neutered {
		t.Fatalf("route returned the fault marker with fault injection disabled")
	}
	wantNode := fpRouteNodeID(0xA1)
	if a1.nodeID != hex.EncodeToString(wantNode[:]) {
		t.Fatalf("route returned unexpected node_id %s", a1.nodeID)
	}
	if a1.fpHex != hex.EncodeToString(fp1[:]) {
		t.Fatalf("route returned fingerprint %s, recomputed value is %s", a1.fpHex, hex.EncodeToString(fp1[:]))
	}
	port2 := fpRouteFreePort(t)
	srv2 := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port2), fpRouteNodeID(0xA1), nil, nil, nil, nil, nil, e2)
	defer func() { _ = srv2.Shutdown(context.Background()) }()
	fpRouteSettle(t, port2)
	a2 := fpRouteProbe(t, port2)
	if a2.fpHex == a1.fpHex {
		t.Fatalf("route returned equal fingerprint %s for different payload digests", a1.fpHex)
	}
}

// fpRouteProbe GETs the armed route and decodes the JSON body.
type fpRouteResult struct {
	nodeID   string
	fpHex    string
	neutered bool
}

func fpRouteProbe(t *testing.T, port int) fpRouteResult {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/state-fingerprint", port))
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/debug/state-fingerprint returned %d (want 200 on the armed route)", resp.StatusCode)
	}
	var body struct {
		NodeID           string `json:"node_id"`
		StateFingerprint string `json:"state_fingerprint"`
		Neutered         string `json:"neutered"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	return fpRouteResult{nodeID: body.NodeID, fpHex: body.StateFingerprint, neutered: body.Neutered == "oracleblind"}
}

func TestStateFingerprintRoute_UnarmedControl(t *testing.T) {
	os.Unsetenv("SOVEREIGN_STATE_FP_DEBUG")
	os.Unsetenv("SOVEREIGN_TEST_FAULT_FINGERPRINT")
	e1, e2 := fpRouteBuildPair(t)
	defer func() { _ = e1.Close() }()
	defer func() { _ = e2.Close() }()
	port := fpRouteFreePort(t)
	srv := startLivecheck(fmt.Sprintf("127.0.0.1:%d", port), fpRouteNodeID(0xA1), nil, nil, nil, nil, nil, e1)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	fpRouteSettle(t, port)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/debug/state-fingerprint", port))
	if err != nil {
		t.Fatalf("probe with debugging disabled failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("route returned %d with debugging disabled, want 404", resp.StatusCode)
	}
}

func TestStateFingerprintRoute_OracleBlindNeuter(t *testing.T) {
	t.Setenv("SOVEREIGN_STATE_FP_DEBUG", "1")
	t.Setenv("SOVEREIGN_TEST_FAULT_FINGERPRINT", "oracleblind")
	e1, e2 := fpRouteBuildPair(t)
	defer func() { _ = e1.Close() }()
	defer func() { _ = e2.Close() }()
	p1 := fpRouteFreePort(t)
	s1 := startLivecheck(fmt.Sprintf("127.0.0.1:%d", p1), fpRouteNodeID(0xA1), nil, nil, nil, nil, nil, e1)
	defer func() { _ = s1.Shutdown(context.Background()) }()
	fpRouteSettle(t, p1)
	p2 := fpRouteFreePort(t)
	s2 := startLivecheck(fmt.Sprintf("127.0.0.1:%d", p2), fpRouteNodeID(0xA1), nil, nil, nil, nil, nil, e2)
	defer func() { _ = s2.Shutdown(context.Background()) }()
	fpRouteSettle(t, p2)
	n1 := fpRouteProbe(t, p1)
	n2 := fpRouteProbe(t, p2)
	if !n1.neutered || !n2.neutered {
		t.Fatalf("routes did not return the oracleblind fault marker")
	}
	if n1.fpHex != n2.fpHex {
		t.Fatalf("fault-injected routes returned %s vs %s, want equal dot-only roots", n1.fpHex, n2.fpHex)
	}
}
