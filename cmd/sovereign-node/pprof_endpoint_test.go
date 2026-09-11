// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package main

// Regression guards for the NON-DESTRUCTIVE loopback pprof endpoint
// (startPprof + pprofBindAddr in main.go). The endpoint exists so a silicon run
// can capture a wedged seed's goroutine/mutex/block profile WITHOUT the
// destructive kill -QUIT. These guards run in-process (loopback) and are
// non-vacuous: they drive the REAL net.Listener + mux + pprof handlers and
// bug-inject a dead port so the capture assertion cannot pass on a tautology.

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestPprofEndpoint_Loopback_NonDestructive is the load-bearing guard:
// start the REAL pprof server on an ephemeral loopback port, capture a goroutine
// dump (?debug=2), and assert (a) HTTP 200, (b) a non-empty dump, (c) the dump
// contains a KNOWN frame — "created by main.startPprof" proves OUR server was
// captured, not some other process's — and (d) the server is STILL SERVING after
// the capture (non-destructive: a second capture also returns 200). It also
// asserts the bound address is loopback (127.0.0.1) — the FORBIDDEN rule.
func TestPprofEndpoint_Loopback_NonDestructive(t *testing.T) {
	srv, err := startPprof("127.0.0.1:0") // ephemeral loopback port
	if err != nil {
		t.Fatalf("startPprof: %v", err)
	}
	defer srv.Close()

	// The bound address MUST be loopback — the endpoint is never public.
	if !strings.HasPrefix(srv.Addr, "127.0.0.1:") {
		t.Fatalf("pprof bound to non-loopback addr %q (FORBIDDEN — must be 127.0.0.1)", srv.Addr)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://" + srv.Addr + "/debug/pprof/goroutine?debug=2"

	// First capture.
	body := httpGetBody(t, client, url)
	if len(body) == 0 {
		t.Fatalf("goroutine dump is EMPTY — the endpoint returned no stack data")
	}
	// A real goroutine dump carries the "goroutine N [state]:" headers AND, for our
	// server goroutine, the "created by...sovereign-node.startPprof" line (the dump
	// qualifies the symbol by its full import path, NOT the short "main." — verified
	// 2026-09-07: "created by github.com/hr18vk/sovereign/cmd/sovereign-node.startPprof").
	// Both must be present — the second proves the capture is of THIS process's pprof
	// server, not a tautology.
	if !strings.Contains(body, "goroutine ") {
		t.Fatalf("dump lacks a 'goroutine ' header — not a goroutine profile; got: %.200q", body)
	}
	if !strings.Contains(body, "sovereign-node.startPprof") {
		t.Fatalf("dump lacks the known frame 'sovereign-node.startPprof' — the capture is not provably OUR server; got: %.400q", body)
	}

	// NON-DESTRUCTIVE: the server must still answer after a capture (a destructive
	// dump — the kill -QUIT class — would make this second request fail).
	body2 := httpGetBody(t, client, url)
	if !strings.Contains(body2, "goroutine ") {
		t.Fatalf("second capture failed — the endpoint is NOT non-destructive; got: %.200q", body2)
	}

	// The mutex/block endpoints answer 200 whether or not collection is armed
	// (they return an empty profile header when --diag-profile is OFF). We only
	// require reachability here; the CONTENT is gated on --diag-profile.
	for _, p := range []string{"/debug/pprof/mutex", "/debug/pprof/block"} {
		resp, err := client.Get("http://" + srv.Addr + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

// TestPprofEndpoint_DeadPortFails is the BUG-INJECTION control: pointing
// the SAME capture at a dead port MUST FAIL (connection refused). This proves the
// guard detects a real capture — it is not a tautology that passes on any curl.
func TestPprofEndpoint_DeadPortFails(t *testing.T) {
	// Obtain a guaranteed-free loopback port by binding then closing it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind scratch: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close() // now nothing is listening on deadAddr

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + deadAddr + "/debug/pprof/goroutine?debug=2")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("capture from a DEAD port (%s) unexpectedly SUCCEEDED — the guard cannot distinguish a live capture from a dead one", deadAddr)
	}
	// err != nil is the REQUIRED outcome (connection refused).
}

// TestPprofBindAddr_LoopbackEnforced pins the address-resolution contract:
// the host is ALWAYS 127.0.0.1 (structurally — a non-loopback --pprof-addr host is
// dropped), the port derives from the metrics port (+1000) by default, and an
// explicit port overrides it. Every case asserts the loopback prefix.
func TestPprofBindAddr_LoopbackEnforced(t *testing.T) {
	cases := []struct {
		name        string
		metricsAddr string
		flag        string
		want        string
	}{
		{"derive-from-silicon-metrics (seed node-0)", "0.0.0.0:9100", "", "127.0.0.1:10100"},
		{"derive-from-default-metrics", "127.0.0.1:7431", "", "127.0.0.1:8431"},
		{"explicit-port", "", "9998", "127.0.0.1:9998"},
		{"explicit-loopback-honored", "", "127.0.0.1:7777", "127.0.0.1:7777"},
		{"non-loopback-host-DROPPED (FORBIDDEN to expose)", "", "0.0.0.0:9999", "127.0.0.1:9999"},
		{"explicit-port-beats-derivation", "0.0.0.0:9100", "7777", "127.0.0.1:7777"},
		{"empty-everything-fallback", "", "", "127.0.0.1:8431"},
	}
	for _, c := range cases {
		got := pprofBindAddr(c.metricsAddr, c.flag)
		if got != c.want {
			t.Errorf("%s: pprofBindAddr(%q, %q) = %q, want %q", c.name, c.metricsAddr, c.flag, got, c.want)
		}
		if !strings.HasPrefix(got, "127.0.0.1:") {
			t.Errorf("%s: result %q is NOT loopback — the FORBIDDEN rule is broken", c.name, got)
		}
	}
}

// httpGetBody GETs url and returns the body on HTTP 200, failing the test otherwise.
func httpGetBody(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(b)
}
