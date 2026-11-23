// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The tc-netem sweep measures digest exchange latency and timeout behavior over
// real TLS connections on kernel loopback TCP. It compares 500 ms and 1500 ms
// digest waits under controlled RTTs; it does not emulate WAN loss, jitter, AQM,
// or bandwidth limits.
//
// A prio qdisc and u32 port filters shape only the two test listeners. Other
// loopback traffic uses the unshaped band. With the defer handler enabled, an
// expired digest wait increments digestDefers and must not trigger a fallback
// keyset dump. Each measurement cell requires completed exchanges. A short wait
// without netem provides the unclamped control, and the same wait at 400 ms RTT
// must defer. After the qdisc is removed, the mesh must converge.
//
// RUN_NETEM_SWEEP=1 enables the approximately two-minute sweep on a host with tc
// and CAP_NET_ADMIN. TestNetemMicroSmoke always runs and uses a test-only digest
// responder switch to exercise timeout, recovery, and fallback accounting without
// changing the host qdisc.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// netemTC is the resolved tc invocation prefix (["tc"] or ["sudo","-n","tc"]);
// resolved once, nil when unavailable.
var netemTC []string

// netemTCResolve tries an actual qdisc replacement directly and then through
// passwordless sudo. A read-only tc probe is insufficient: qdisc replacement can
// still fail without CAP_NET_ADMIN. The probe installs a filterless root prio
// qdisc, removes it immediately, and returns nil if neither invocation can write.
func netemTCResolve() []string {
	for _, prefix := range [][]string{{"tc"}, {"sudo", "-n", "tc"}} {
		cmd := append(append([]string{}, prefix...), "qdisc", "replace", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3")
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err == nil {
			clean := append(append([]string{}, prefix...), "qdisc", "del", "dev", "lo", "root")
			_ = exec.Command(clean[0], clean[1:]...).Run()
			return prefix
		}
	}
	return nil
}

// netemTCRun runs a tc command through the resolved prefix.
func netemTCRun(args ...string) error {
	cmd := append(append([]string{}, netemTC...), args...)
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %v: %v: %s", args, err, string(out))
	}
	return nil
}

// netemPortOf extracts the port from a "127.0.0.1:PORT" listener address.
func netemPortOf(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portStr)
}

// netemArm sets the two listeners' loopback RTT to rttMs. It applies half the
// delay in each direction through source- and destination-port filters and
// returns a function that deletes the qdisc. Non-matching traffic remains in the
// unshaped band of the root prio qdisc.
func netemArm(portA, portB, rttMs int) (arm func() error, err error) {
	delay := fmt.Sprintf("%dms", rttMs/2)
	steps := [][]string{
		{"qdisc", "replace", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3"},
		{"qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", delay},
	}
	for _, port := range []int{portA, portB} {
		for _, field := range []string{"dport", "sport"} {
			steps = append(steps, []string{
				"filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:0", "prio", "3", "u32",
				"match", "ip", field, fmt.Sprintf("%d", port), "0xffff", "flowid", "1:3",
			})
		}
	}
	for _, st := range steps {
		if err := netemTCRun(st...); err != nil {
			_ = netemTCRun("qdisc", "del", "dev", "lo", "root")
			return nil, err
		}
	}
	return func() error { return netemTCRun("qdisc", "del", "dev", "lo", "root") }, nil
}

// netemCell runs rounds of A-only sweeps with keys fresh entities inserted before
// each round and the same digest wait configured on both gossipers. It returns
// changes in timeout defers, fallback dumps, completed exchanges, and the
// requester-side exchange duration from stratDiag.digestNs.
func netemCell(t *testing.T, m *DeferMesh, wait time.Duration, keys, rounds int) (defers, fallbacks, exchanges int64, digestNs int64) {
	t.Helper()
	m.gA.SetDigestWaitTimeout(wait)
	m.gB.SetDigestWaitTimeout(wait)
	beforeDefers := m.gA.digestDefers.Load()
	beforeFb := int64(m.fallbackA.Load())
	beforeEx := int64(0)
	beforeNs := int64(0)
	if d := m.gA.stratDiag; d != nil {
		d.mu.Lock()
		for _, v := range d.exchange {
			beforeEx += int64(v)
		}
		beforeNs = d.digestNs
		d.mu.Unlock()
	}
	first := 100 + int(beforeDefers)*keys // deterministic distinct tags per cell
	for r := 0; r < rounds; r++ {
		deferInsert(t, m.gA, "netem-%d", first, keys)
		first += keys
		deferSweepAOnly(t, m)
	}
	afterDefers := m.gA.digestDefers.Load()
	afterFb := int64(m.fallbackA.Load())
	afterEx := int64(0)
	afterNs := int64(0)
	if d := m.gA.stratDiag; d != nil {
		d.mu.Lock()
		for _, v := range d.exchange {
			afterEx += int64(v)
		}
		afterNs = d.digestNs
		d.mu.Unlock()
	}
	return afterDefers - beforeDefers, afterFb - beforeFb, afterEx - beforeEx, afterNs - beforeNs
}

// TestNetemSweep measures RTTs of 50, 100, 200, and 400 ms with digest waits of
// 500 and 1500 ms. RUN_NETEM_SWEEP=1 enables the approximately two-minute test.
// It also checks a 50 ms wait without shaping and under a 400 ms RTT; only the
// shaped case may defer.
func TestNetemSweep(t *testing.T) {
	if os.Getenv("RUN_NETEM_SWEEP") != "1" {
		t.Skip("set RUN_NETEM_SWEEP=1 to arm the netem RTT x digestWait sweep (~2 min; needs tc + CAP_NET_ADMIN — plain or passwordless sudo)")
	}
	netemTC = netemTCResolve()
	if netemTC == nil {
		t.Skip("tc netem is unavailable: install tc and grant CAP_NET_ADMIN directly or through passwordless sudo to run this sweep")
	}
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 100, digestWait: 500 * time.Millisecond})
	portA, err := netemPortOf(m.addrA)
	if err != nil {
		t.Fatalf("port A: %v", err)
	}
	portB, err := netemPortOf(m.addrB)
	if err != nil {
		t.Fatalf("port B: %v", err)
	}

	// Run the unshaped control first. A 50 ms wait on plain loopback must not
	// expire, so the later timeout can be attributed to the netem delay.
	dCtl, fbCtl, exCtl, _ := netemCell(t, m, 50*time.Millisecond, 20, 2)
	t.Logf("unclamped control (wait=50ms, no netem): defers=%d fallbacks=%d exchanges=%d, want defers=0 and exchanges>0", dCtl, fbCtl, exCtl)
	if dCtl != 0 {
		t.Fatalf("unclamped control: defers=%d at wait=50ms on plain loopback — the timer fires without any clamp; the negative control below would measure the harness, not the netem clamp", dCtl)
	}
	if exCtl == 0 {
		t.Fatalf("unclamped control: zero exchanges; the measurement cell did not run")
	}

	for _, rtt := range []int{50, 100, 200, 400} {
		arm, err := netemArm(portA, portB, rtt)
		if err != nil {
			t.Fatalf("netem arm rtt=%d: %v", rtt, err)
		}
		// Cleanup removes the loopback qdisc even if the test aborts.
		var disarmed bool
		disarm := func() {
			if disarmed {
				return
			}
			disarmed = true
			_ = arm()
		}
		t.Cleanup(disarm)
		for _, waitMs := range []int{500, 1500} {
			d, fb, ex, ns := netemCell(t, m, time.Duration(waitMs)*time.Millisecond, 20, 3)
			meanWall := 0.0
			if ex > 0 {
				meanWall = float64(ns) / float64(ex) / 1e6
			}
			t.Logf("rtt=%dms wait=%dms: defers=%d fallbacks=%d exchanges=%d meanExchangeWall=%.1fms", rtt, waitMs, d, fb, ex, meanWall)
			if ex == 0 {
				t.Errorf("rtt=%dms wait=%dms: zero exchanges — the cell never exchanged; the wall/defer numbers prove nothing", rtt, waitMs)
			}
			if fb != 0 {
				t.Errorf("rtt=%dms wait=%dms: defer handler triggered %d fallback keyset dumps, want 0", rtt, waitMs, fb)
			}
			if waitMs == 1500 && d != 0 {
				t.Errorf("rtt=%dms wait=1500ms: %d digest timeouts at %.0fms clamped RTT, want 0", rtt, d, float64(rtt))
			}
			if waitMs == 500 && rtt == 400 && d != 0 {
				t.Logf("rtt=400ms wait=500ms: %d digest timeouts; the exchange duration can approach this margin", d)
			}
			// Below 400 ms RTT, a 500 ms wait has at least a tenfold margin and
			// must not expire. At 400 ms the exchange can approach the timeout,
			// so that cell is logged without making the timing a hard failure.
			if waitMs == 500 && rtt < 400 && d != 0 {
				t.Errorf("rtt=%dms wait=500ms: %d digest timeouts at %.0fms RTT, want 0 within the tenfold timing margin", rtt, d, float64(rtt))
			}
		}
		disarm()
		time.Sleep(100 * time.Millisecond) // let the disarm settle before the next clamp
	}

	// A wait below the shaped RTT floor must expire.
	armNegativeControl, err := netemArm(portA, portB, 400)
	if err != nil {
		t.Fatalf("netem negative control arm: %v", err)
	}
	var redDisarmed bool
	disarmNegativeControl := func() {
		if redDisarmed {
			return
		}
		redDisarmed = true
		_ = armNegativeControl()
	}
	t.Cleanup(disarmNegativeControl)
	dNegativeControl, fbNegativeControl, exNegativeControl, _ := netemCell(t, m, 50*time.Millisecond, 20, 2)
	disarmNegativeControl()
	t.Logf("negative control (rtt=400ms, wait=50ms): defers=%d fallbacks=%d exchanges=%d — the timer below the clamped floor", dNegativeControl, fbNegativeControl, exNegativeControl)
	if dNegativeControl == 0 {
		t.Fatalf("negative control: zero defers at wait=50ms under 400ms RTT; check the port filters and digest timer path")
	}
	if fbNegativeControl != 0 {
		t.Errorf("negative control: defer handler triggered %d fallback keyset dumps, want 0", fbNegativeControl)
	}

	// Removing the qdisc can discard packets queued by netem, so drive fresh
	// sweep rounds until the mesh converges. Restore the production digest wait
	// after the negative control's deliberately short timeout.
	m.gA.SetDigestWaitTimeout(500 * time.Millisecond)
	m.gB.SetDigestWaitTimeout(500 * time.Millisecond)
	converged := false
	quit := time.Now().Add(10 * time.Second)
	for time.Now().Before(quit) {
		if deferConverged(m) {
			converged = true
			break
		}
		deferSweepRound(t, m)
		time.Sleep(50 * time.Millisecond)
	}
	if !converged {
		t.Errorf("mesh did not converge after removing netem and driving fresh sweep rounds")
	}
}

// TestNetemMicroSmoke exercises the measurement path without netem. Disabling
// digest responses must expire the wait and increment digestDefers without a
// fallback dump; re-enabling responses must let the pair converge. The gated
// sweep separately proves that its port filters produce the timeout.
func TestNetemMicroSmoke(t *testing.T) {
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 100, digestWait: 50 * time.Millisecond})
	deferInsert(t, m.gA, "netem-l4micro-%d", 0, 30)
	m.gB.disableDigestRespond.Store(true) // the deterministic no-answer shape
	before := m.gA.digestDefers.Load()
	deferSweepAOnly(t, m)
	fired := m.gA.digestDefers.Load() - before
	if fired == 0 {
		t.Fatalf("micro: digest timer did not fire with responses disabled at digestWait=50ms")
	}
	if m.fallbackA.Load() != 0 {
		t.Fatalf("micro: defer handler dumped the keyset (fallback=%d), want 0", m.fallbackA.Load())
	}
	t.Logf("micro: responder disabled -> %d timer-defer(s), 0 dumps", fired)
	// Re-enable responses and verify that the deferred pair converges.
	m.gB.disableDigestRespond.Store(false)
	deferSweepAOnly(t, m)
	if !deferDrain(t, m, 5*time.Second) {
		t.Fatalf("micro: mesh did not converge after re-enabling digest responses")
	}
	t.Logf("micro: responder re-enabled -> converged (the defer path recovers)")
}
