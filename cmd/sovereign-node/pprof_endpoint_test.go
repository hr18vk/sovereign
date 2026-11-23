// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// These tests exercise the loopback pprof listener and its address rules.
// They use real HTTP handlers, verify that profile capture leaves the server
// running, and check that a connection to an unused port fails.

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestPprofEndpoint_Loopback_NonDestructive captures a goroutine profile from
// an ephemeral loopback listener. The startPprof frame identifies this process,
// and a second successful capture shows that profiling did not stop the server.
func TestPprofEndpoint_Loopback_NonDestructive(t *testing.T) {
	srv, err := startPprof("127.0.0.1:0") // ephemeral loopback port
	if err != nil {
		t.Fatalf("startPprof: %v", err)
	}
	defer srv.Close()

	if !strings.HasPrefix(srv.Addr, "127.0.0.1:") {
		t.Fatalf("pprof bound to non-loopback address %q", srv.Addr)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://" + srv.Addr + "/debug/pprof/goroutine?debug=2"

	// First capture.
	body := httpGetBody(t, client, url)
	if len(body) == 0 {
		t.Fatalf("goroutine profile is empty")
	}
	// A goroutine profile has "goroutine N [state]:" headers. The startPprof
	// frame ties this capture to the server goroutine in the current process.
	if !strings.Contains(body, "goroutine ") {
		t.Fatalf("response is not a goroutine profile: %.200q", body)
	}
	if !strings.Contains(body, "sovereign-node.startPprof") {
		t.Fatalf("profile lacks the startPprof frame: %.400q", body)
	}

	// A second capture verifies that the first did not stop the server.
	body2 := httpGetBody(t, client, url)
	if !strings.Contains(body2, "goroutine ") {
		t.Fatalf("second capture returned an invalid profile: %.200q", body2)
	}

	// Mutex and block profiles remain reachable when collection is disabled;
	// --diag-profile controls whether they contain samples.
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

// TestPprofEndpoint_DeadPortFails is the negative control. A profile request
// to an unused loopback port must fail rather than produce an empty success.
func TestPprofEndpoint_DeadPortFails(t *testing.T) {
	// Bind and close an ephemeral port so the request has no listener to reach.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind scratch: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close() // deadAddr now has no listener

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + deadAddr + "/debug/pprof/goroutine?debug=2")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("profile request to unused address %s unexpectedly succeeded", deadAddr)
	}
	// A connection error is the expected result.
}

// TestPprofBindAddr_LoopbackEnforced checks port precedence and confirms that
// every result uses 127.0.0.1. An explicit --pprof-addr port wins; otherwise the
// metrics port plus 1000 is used. Any supplied host is discarded.
func TestPprofBindAddr_LoopbackEnforced(t *testing.T) {
	cases := []struct {
		name        string
		metricsAddr string
		flag        string
		want        string
	}{
		{"derive-from-metrics", "0.0.0.0:9100", "", "127.0.0.1:10100"},
		{"derive-from-default-metrics", "127.0.0.1:7431", "", "127.0.0.1:8431"},
		{"explicit-port", "", "9998", "127.0.0.1:9998"},
		{"explicit-loopback-honored", "", "127.0.0.1:7777", "127.0.0.1:7777"},
		{"non-loopback-host-discarded", "", "0.0.0.0:9999", "127.0.0.1:9999"},
		{"explicit-port-beats-derivation", "0.0.0.0:9100", "7777", "127.0.0.1:7777"},
		{"empty-everything-fallback", "", "", "127.0.0.1:8431"},
	}
	for _, c := range cases {
		got := pprofBindAddr(c.metricsAddr, c.flag)
		if got != c.want {
			t.Errorf("%s: pprofBindAddr(%q, %q) = %q, want %q", c.name, c.metricsAddr, c.flag, got, c.want)
		}
		if !strings.HasPrefix(got, "127.0.0.1:") {
			t.Errorf("%s: result %q is not a loopback address", c.name, got)
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
