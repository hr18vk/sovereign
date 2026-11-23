// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// fleet-gate — the 1,000-node fleet convergence harness.
//
// The binary loads a sovereign-bootstrap manifest, establishes mTLS
// connections to each node's control endpoint, and drives the convergence
// measurement:
//
//   - Boot liveness: probes /livecheck over mTLS on the control address
//     (retries slow-booting nodes within a configurable window).
//   - Workload inject: posts keys to node 0 via /v1/batch-insert in
//     configurable chunks, using a single constant valid_from_ns across
//     all chunks when the flag is set.
//   - Origin quiescence: polls the seed node's /v1/merkle until the root
//     is stable and commit_in_flight==0 for 12 consecutive polls.
//   - Convergence poll: scrapes /v1/merkle on all nodes from quiescence
//     until all roots match or the SLO expires, recording per-node and
//     per-region convergence times (t50/t90/t100).
//   - Fingerprint sweep: reads /debug/state-fingerprint on the plain-HTTP
//     metrics port of every node; requires all fingerprints equal.
//   - Schema harvest: pulls /debug/memstats and /debug/responder-indegree
//     from every node's metrics port, plus optional /debug/heartbeat.
//
// Flags control the bootstrap directory, config file, split, SLO, port bases,
// inject chunking and parallelism, valid_from_ns constant, fingerprint
// sweep enable, quiescence cap, and liveness retry window.
//
// PASS requires a quiescent origin, convergence within the SLO, zero
// hard-timeout inject batches, and an all-equal fingerprint sweep. The
// machine-readable verdict line and RUN-LEDGER row record the result.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	bootstrapDir := flagStr("bootstrap", "", "the mesh-bootstrap -out-dir (holds client/, ca.pem, manifest)")
	flag.IntVar(&meshPortWindowMax, "mesh-port-window", 40, "the per-instance mesh-port window's max local index (the fleet's 33/box limit + slack = 41 ports, default; a 111-nodes-per-region-IP loopback run passes 111)")
	keys := flagInt("keys", 10000, "keys to inject into node 0")
	sloSecs := flagInt("slo-secs", 600, "convergence SLO cap in seconds")
	controlPortBase := flagInt("control-port-base", 8443, "control port base; each node binds base + per-instance local index")
	splitCSV := flagStr("split", "333,333,334", "per-region node counts (must match the bootstrap mint)")
	requireN := flagInt("require-n", 1000, "expected node count (1000 for full fleet; 6 for small smoke test)")
	injectParallel := flagInt("inject-parallel", 1, "concurrent inject workers (1 = serial, default)")
	injectChunk := flagInt("inject-chunk", 1000, "keys per batch-insert POST (0 = single batch per ADR-0044)")
	metricsPortBase := flagInt("metrics-port-base", 9100, "plain-HTTP metrics port base (/livecheck, /debug/*)")
	validFromConst := flagInt64("valid-from-ns", 0, "constant valid_from_ns across all chunks (0 = write-time per batch)")
	deckPath := flagStr("deck", "", "arm config file path recorded in the run summary")
	fpArmed := flagBool("expect-fingerprint", true, "run fingerprint sweep by default; false only when driving a stub without the route")
	sloQuiesceCapSecs := flagInt("quiesce-cap-secs", 300, "origin-quiescence probe timeout in seconds")
	liveRetrySecs := flagInt("live-retry-secs", 180, "boot-liveness retry window in seconds for slow-starting nodes")
	parseFlags()
	if *bootstrapDir == "" {
		fmt.Fprintln(os.Stderr, "fleet-gate: -bootstrap is required")
		os.Exit(2)
	}
	if *deckPath == "" {
		fmt.Fprintln(os.Stderr, "fleet-gate: -deck is required")
		os.Exit(2)
	}
	runGate(runCfg{
		bootstrapDir: *bootstrapDir, keys: *keys, sloSecs: *sloSecs,
		controlPortBase: *controlPortBase, splitCSV: *splitCSV, requireN: *requireN,
		injectParallel: *injectParallel, injectChunk: *injectChunk,
		metricsPortBase: *metricsPortBase, validFromConst: *validFromConst,
		deckPath: *deckPath, fpArmed: *fpArmed, quiesceCap: time.Duration(*sloQuiesceCapSecs) * time.Second,
		liveRetry: time.Duration(*liveRetrySecs) * time.Second,
	})
}

// ── the flag helpers (thin wrappers over the stdlib — chunk 1's callers) ──
// meshPortWindowMax is set at flag-parse time (the package var bridges the
// flag to the manifest loader below; see its declaration site for the law).
var meshPortWindowMax int

func flagStr(n string, def string, use string) *string { return flag.String(n, def, use) }
func flagInt(n string, def int, use string) *int       { return flag.Int(n, def, use) }
func flagInt64(n string, def int64, use string) *int64 { return flag.Int64(n, def, use) }
func flagBool(n string, def bool, use string) *bool    { return flag.Bool(n, def, use) }
func parseFlags()                                      { flag.Parse() }

type runCfg struct {
	bootstrapDir    string
	keys            int
	sloSecs         int
	controlPortBase int
	splitCSV        string
	requireN        int
	injectParallel  int
	injectChunk     int
	metricsPortBase int
	validFromConst  int64
	deckPath        string
	fpArmed         bool
	quiesceCap      time.Duration
	liveRetry       time.Duration
}

// node is one manifest row: the mTLS control client and the plain-HTTP metrics
// address. The mTLS control port serves /livecheck and /v1/* endpoints.
// The plain-HTTP metrics port serves /debug/* instrument routes
// (/debug/state-fingerprint, /debug/memstats, /debug/responder-indegree,
// /debug/heartbeat). Both ports key off the node's per-instance local index
// in the 30-instance shape (the bootstrap -region-ips mint), so both stay
// inside the security group's 34-wide windows on every instance.
type node struct {
	idx         int
	region      string
	ip          string
	ctrlPort    int
	nodeIDHex   string
	controlAddr string
	metricsAddr string
	client      *http.Client
}

// loadFleet mints the per-node mTLS clients from the bootstrap dir (the
// convergence gate mold: one http.Client per node so every dial carries
// the correct ServerName = the node's nodeID hex, a DNSName in its leaf).
func loadFleet(cfg runCfg) ([]node, error) {
	caPEM, err := os.ReadFile(cfg.bootstrapDir + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("read ca.pem: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA PEM did not append to the pool")
	}
	clientCert, err := tls.LoadX509KeyPair(cfg.bootstrapDir+"/client/cert.pem", cfg.bootstrapDir+"/client/key.pem")
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	baseTLS := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: caPool, MinVersion: tls.VersionTLS13}
	manifestBytes, err := os.ReadFile(cfg.bootstrapDir + "/manifest")
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var split []int
	for _, s := range strings.Split(cfg.splitCSV, ",") {
		n, _ := strconv.Atoi(s)
		split = append(split, n)
	}
	var nodes []node
	for _, line := range strings.Split(strings.TrimSpace(string(manifestBytes)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		idx, _ := strconv.Atoi(fields[0])
		// meshPortWindowMax is set once at flag-parse time (the -mesh-port-window
		// flag, default 40 = the fleet's per-instance law). An early patch
		// draft initialized it inside the per-node loop, so every iteration
		// reset the flag's probe override back to 40 — node 41 died with the
		// default window while the flag said 111. A loop-local
		// re-initialization of flag state defeats the override; the loop
		// only reads it. See the var's declaration site.)

		// The manifest port is the authority (measured in run 1: 102 of
		// 1,000 nodes plateaued, 2026-10-14). Boxes bind ports from the
		// per-instance local index (0..33, the launcher's k) — the
		// manifest's own mesh-port field (fields[3] = 7373+k) is the
		// mint's authority. The old derivation subtracted the region split
		// (the per-region index, 0..333): the two coincide at <=10
		// nodes/box (the 30-node pre-measurement and micro-smoke both
		// passed) and diverge at 34/box — the plateau sat at exactly 102 =
		// 3 regions × the first box's 34 nodes, whose dial addresses
		// happened to overlap. Derive k from the manifest port, never
		// re-derive it arithmetically.
		meshPort, _ := strconv.Atoi(fields[3])
		localIdx := meshPort - 7373
		if localIdx < 0 || localIdx > meshPortWindowMax {
			return nil, fmt.Errorf("manifest node %d: mesh port %d outside the per-instance port law (7373..%d)", idx, meshPort, 7373+meshPortWindowMax)
		}
		nodeIDHex := fields[5]
		nodeTLS := baseTLS.Clone()
		nodeTLS.ServerName = nodeIDHex
		nc := &http.Client{
			Timeout:   30 * time.Second, // bounds the mTLS dial; does not equal the SLO
			Transport: &http.Transport{TLSClientConfig: nodeTLS},
		}
		nodes = append(nodes, node{
			idx:         idx,
			region:      fields[1],
			ip:          fields[2],
			ctrlPort:    cfg.controlPortBase + localIdx,
			nodeIDHex:   nodeIDHex,
			controlAddr: fields[2] + ":" + strconv.Itoa(cfg.controlPortBase+localIdx),
			metricsAddr: fields[2] + ":" + strconv.Itoa(cfg.metricsPortBase+localIdx),
			client:      nc,
		})
	}
	if len(nodes) != cfg.requireN {
		return nil, fmt.Errorf("manifest has %d nodes, want %d (-require-n)", len(nodes), cfg.requireN)
	}
	return nodes, nil
}

// runGate is the phase dispatcher — each phase is a function with its own
// verdict line; the phases land in the following chunks.
func runGate(cfg runCfg) {
	nodes, err := loadFleet(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fleet-gate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fleet-gate: loaded %d nodes (control base %d, metrics base %d, split %s)\n",
		len(nodes), cfg.controlPortBase, cfg.metricsPortBase, cfg.splitCSV)
	res := gateLiveness(nodes, cfg.liveRetry)
	if !res {
		os.Exit(1)
	}
	ir := injectWorkload(cfg, nodes)
	qr := probeSeedQuiescence(cfg, nodes[0])
	cr := pollConvergence(cfg, nodes, qr)
	fr := fingerprintSweep(cfg, nodes, cr)
	hr := harvestSchema(cfg, nodes)
	printVerdict(cfg, ir, qr, cr, fr, hr)
}

// ── boot-liveness phase ────────────────────────────────────────────────────
func gateLiveness(nodes []node, retryWindow time.Duration) bool {
	fmt.Printf("GATE 0: boot-liveness (GET /livecheck on all %d nodes; slow-boot retry window %s)\n", len(nodes), retryWindow)
	start := time.Now()
	// the 1k boot wave: a node mid-handshake-wave is slow, not dead —
	// re-probe the failing subset until the cap, then fail (bounded).
	pending := append([]node(nil), nodes...)
	pass := 0
	for {
		pass++
		var wg sync.WaitGroup
		var fail int32
		var mu sync.Mutex
		var stillDown []node
		for _, n := range pending {
			wg.Add(1)
			go func(n node) {
				defer wg.Done()
				if _, err := tlsGet(n, "/livecheck"); err != nil {
					if pass == 1 {
						fmt.Fprintf(os.Stderr, "  [node %d %s %s] /livecheck not yet: %v\n", n.idx, n.region, n.controlAddr, err)
					}
					atomic.AddInt32(&fail, 1)
					mu.Lock()
					stillDown = append(stillDown, n)
					mu.Unlock()
				}
			}(n)
		}
		wg.Wait()
		if fail == 0 {
			fmt.Printf("  all %d nodes /livecheck OK in %.2fs (pass %d)\n", len(nodes), time.Since(start).Seconds(), pass)
			return true
		}
		if time.Since(start) >= retryWindow {
			fmt.Fprintf(os.Stderr, "fleet-gate: GATE 0 FAIL — %d/%d nodes not live after %s (%d pass(es))\n", fail, len(nodes), retryWindow, pass)
			return false
		}
		fmt.Printf("  boot wave: %d/%d live (pass %d, %.1fs) — re-probing the failing subset\n", len(nodes)-int(fail), len(nodes), pass, time.Since(start).Seconds())
		time.Sleep(2 * time.Second)
		pending = stillDown
	}
}

// injectResult carries the inject's verdict inputs: failure count, timeout
// count, wall time, number of chunks, and chunk size.
type injectResult struct {
	fail      int
	timeouts  int
	wall      time.Duration
	chunks    int
	chunkSize int
}

// injectWorkload — injects keys into node 0 via /v1/batch-insert in
// configurable chunks. A client timeout is a hard failure (an unACKed batch
// is never treated as "entries may have landed"); a transport error is a
// failure; per-entry status codes are summed. When validFromConst is set,
// a single constant valid_from_ns is applied across all chunks so the
// workload's valid-time is uniform.
func injectWorkload(cfg runCfg, nodes []node) injectResult {
	seed := nodes[0]
	batchSize := cfg.keys
	if cfg.injectChunk > 0 && cfg.injectChunk < batchSize {
		batchSize = cfg.injectChunk
	}
	if batchSize < 1 {
		batchSize = 1
	}
	nBatches := 0
	if cfg.keys > 0 {
		nBatches = (cfg.keys + batchSize - 1) / batchSize
	}
	shape := fmt.Sprintf("%d chunk(s) of <=%d keys", nBatches, batchSize)
	fmt.Printf("INJECT [%s]: %d keys into node 0 (%s %s) via /v1/batch-insert (%s; constant valid_from_ns=%d)\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		cfg.keys, seed.region, seed.controlAddr, shape, cfg.validFromConst)
	ir := injectResult{chunks: nBatches, chunkSize: batchSize}
	start := time.Now()
	workers := cfg.injectParallel
	if workers < 1 {
		workers = 1
	}
	starts := make(chan int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	chunkBody := func(st int) {
		end := st + batchSize
		if end > cfg.keys {
			end = cfg.keys
		}
		items := make([]insertItem, 0, end-st)
		for k := st; k < end; k++ {
			it := insertItem{Key: fmt.Sprintf("fleet-key-%d", k), Val: fmt.Sprintf("%010d", k)}
			if cfg.validFromConst != 0 {
				vfc := cfg.validFromConst
				it.ValidFromNs = &vfc
			}
			items = append(items, it)
		}
		body, _ := json.Marshal(struct {
			Items []insertItem `json:"items"`
		}{Items: items})
		respBody, err := tlsPost(seed, "/v1/batch-insert", body)
		if err != nil {
			if isTimeoutErr(err) {
				mu.Lock()
				ir.timeouts++
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "  [inject %d-%d] HTTP timeout: %v — hard inject failure (an unacknowledged batch invalidates the SLO verdict)\n", st, end-1, err)
			} else {
				mu.Lock()
				ir.fail += end - st
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "  [inject %d-%d] fail (transport/HTTP, entries did not land): %v\n", st, end-1, err)
			}
			return
		}
		var br batchResp
		if err := json.Unmarshal(respBody, &br); err != nil {
			mu.Lock()
			ir.fail += end - st
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "  [inject %d-%d] decode FAIL: %v\n", st, end-1, err)
			return
		}
		mu.Lock()
		for _, ist := range br.Items {
			if ist.Code != 200 {
				ir.fail++
			}
		}
		mu.Unlock()
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for st := range starts {
				chunkBody(st)
			}
		}()
	}
	for st := 0; st < cfg.keys; st += batchSize {
		starts <- st
	}
	close(starts)
	wg.Wait()
	ir.wall = time.Since(start)
	fmt.Printf("  injected %d keys in %.2fs (%d failures, %d hard-timeout chunks)\n", cfg.keys, ir.wall.Seconds(), ir.fail, ir.timeouts)
	return ir
}

// ── origin-quiescence probe ────────────────────────────────────────────────
// The SLO clock starts only after the seed's root is stable and
// commit_in_flight==0 across 12 consecutive 250 ms polls. A seed that
// never quiesces returns quiesced=false and the run is invalid, not late.
type quiesceResult struct {
	root         string
	quiesced     bool
	wall         time.Duration
	lastInFlight int64
}

func probeSeedQuiescence(cfg runCfg, seed node) quiesceResult {
	fmt.Printf("GATE 1 PRE: seed quiescence probe (root-stable AND commit_in_flight==0, 12x250ms, cap %s)\n", cfg.quiesceCap)
	start := time.Now()
	last := ""
	stable := 0
	var lastInFlight int64
	for time.Since(start) < cfg.quiesceCap {
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			stable, last = 0, ""
			time.Sleep(250 * time.Millisecond)
			continue
		}
		lastInFlight = sr.CommitInFlight
		if sr.CommitInFlight > 0 {
			stable, last = 0, sr.RootHex
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if sr.RootHex == last {
			stable++
		} else {
			stable, last = 0, sr.RootHex
		}
		if stable >= 12 {
			fmt.Printf("  origin quiesced [%s]: root=%s (quiesce wall %.2fs)\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), last, time.Since(start).Seconds())
			return quiesceResult{root: last, quiesced: true, wall: time.Since(start)}
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "  origin quiesced=false (last poll: root=%s commit_in_flight=%d) — origin did not quiesce; SLO invalid\n", last, lastInFlight)
	return quiesceResult{root: last, quiesced: false, wall: time.Since(start), lastInFlight: lastInFlight}
}

// regionCurve — the per-region t50/t90/t100 percentiles over non-seed nodes.
type regionCurve struct {
	t50, t90, t100 time.Duration
}

// convergeResult — the SLO verdict inputs + the per-region curves.
type convergeResult struct {
	converged     bool
	convergedAtMs int64
	seedRoot      string
	t50, t90      time.Duration
	regionT       map[string]regionCurve
	nodeRoots     map[int]string // latest scraped RootHex per node idx; used to cross-check equal roots with divergent fingerprints per ADR-0045 §5.1
}

// pollConvergence — convergence poll phase: polls every node's /v1/merkle
// until all roots equal, tracking per-node first-converged times and
// deriving per-region t50/t90/t100. convStart anchors at origin quiescence
// (quiesced==true); an unquiesced seed yields an invalid run without polling.
func pollConvergence(cfg runCfg, nodes []node, qr quiesceResult) convergeResult {
	seed := nodes[0]
	if !qr.quiesced {
		return convergeResult{converged: false, convergedAtMs: -1, seedRoot: qr.root, regionT: map[string]regionCurve{}}
	}
	convStart := time.Now()
	deadline := convStart.Add(time.Duration(cfg.sloSecs) * time.Second)
	fmt.Printf("GATE 1: poll /v1/merkle on all %d (SLO %ds from quiescence)\n", len(nodes), cfg.sloSecs)
	firstAt := make(map[int]int64, len(nodes))
	pollOnce := func() (string, []int, int, map[int]string) {
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			return "", nil, 0, nil
		}
		root := sr.RootHex
		var mu sync.Mutex
		var mismatch []int
		latestRoots := make(map[int]string, len(nodes))
		latestRoots[seed.idx] = root
		scraped := 0
		var wg sync.WaitGroup
		for i := 1; i < len(nodes); i++ {
			wg.Add(1)
			go func(n node) {
				defer wg.Done()
				r, err := tlsGetJSON[merkleResp](n, "/v1/merkle")
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					mismatch = append(mismatch, n.idx)
					return
				}
				scraped++
				latestRoots[n.idx] = r.RootHex
				if r.RootHex != root {
					mismatch = append(mismatch, n.idx)
				}
			}(nodes[i])
		}
		wg.Wait()
		return root, mismatch, scraped, latestRoots
	}
	nonSeed := len(nodes) - 1
	t50Mark, t90Mark := nonSeed/2, (nonSeed*10)/100
	var cr convergeResult
	rounds := 0
	for time.Now().Before(deadline) {
		rounds++
		root, mismatch, scraped, latestRoots := pollOnce()
		if root == "" {
			fmt.Fprintf(os.Stderr, "  [poll %d] seed /v1/merkle FAIL\n", rounds)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		cr.seedRoot = root
		cr.nodeRoots = latestRoots
		nowMs := time.Since(convStart).Milliseconds()
		div := make(map[int]bool, len(mismatch))
		for _, mi := range mismatch {
			div[mi] = true
		}
		for i := 1; i < len(nodes); i++ {
			if !div[nodes[i].idx] {
				if _, seen := firstAt[nodes[i].idx]; !seen {
					firstAt[nodes[i].idx] = nowMs
				}
			}
		}
		if cr.t50 == 0 && len(mismatch) <= t50Mark {
			cr.t50 = time.Since(convStart)
		}
		if cr.t90 == 0 && len(mismatch) <= t90Mark {
			cr.t90 = time.Since(convStart)
		}
		if len(mismatch) == 0 {
			cr.converged = true
			cr.convergedAtMs = nowMs
			fmt.Printf("  CONVERGED [%s] in %.3fs post-quiescence (all %d roots equal = %s); converged_at_ms=%d\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), float64(nowMs)/1000, len(nodes), root, nowMs)
			break
		}
		if rounds%5 == 0 {
			fmt.Printf("  poll %d [%s]: %d divergent (scraped %d/%d; seed root %s)\n", rounds, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), len(mismatch), scraped, nonSeed, root[:8])
		}
		time.Sleep(200 * time.Millisecond)
	}
	cr.regionT = regionCurves(nodes, firstAt, convStart)
	return cr
}

// regionCurves derives the per-region t50/t90/t100 from the per-node
// first-converged map (the seed excluded from its region's set).
func regionCurves(nodes []node, firstAt map[int]int64, convStart time.Time) map[string]regionCurve {
	byRegion := map[string][]int64{}
	for i := 1; i < len(nodes); i++ {
		n := nodes[i]
		if ms, ok := firstAt[n.idx]; ok {
			byRegion[n.region] = append(byRegion[n.region], ms)
		}
	}
	out := map[string]regionCurve{}
	for r, ms := range byRegion {
		sort.Slice(ms, func(a, b int) bool { return ms[a] < ms[b] })
		pct := func(p int) time.Duration {
			k := (len(ms)*p + 99) / 100
			if k < 1 {
				k = 1
			}
			if k > len(ms) {
				k = len(ms)
			}
			return time.Duration(ms[k-1]) * time.Millisecond
		}
		out[r] = regionCurve{t50: pct(50), t90: pct(90), t100: time.Duration(ms[len(ms)-1]) * time.Millisecond}
	}
	return out
}

// fpResult — the integrity-oracle sweep's verdict.
type fpResult struct {
	swept    int
	allEqual bool
	failed   []int
}

// Test-only flag: when true, restores the unconditional
// equal-root-divergent-fingerprints claim at distinct>1 regardless of
// root pairing, so the root-pairing crosscheck can be tested as a negative
// control.
var fingerprintSweepVoidOverclaimBugInject atomic.Bool

// countEqualRootDivergentFPPairs counts unordered node pairs (i < j) that
// landed in different state-fingerprint buckets (fp_i != fp_j) while holding
// the same non-empty measured Merkle root (nodeRoots[i] == nodeRoots[j]).
// A positive count indicates equal roots with divergent state bytes per
// ADR-0045 §5.1; zero means distinct fingerprints track distinct roots.
func countEqualRootDivergentFPPairs(nodeRoots map[int]string, fps map[string][]int) int {
	if len(nodeRoots) == 0 || len(fps) <= 1 {
		return 0
	}
	keys := make([]string, 0, len(fps))
	for k := range fps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := 0
	for a := 0; a < len(keys); a++ {
		for b := a + 1; b < len(keys); b++ {
			for _, na := range fps[keys[a]] {
				ra := nodeRoots[na]
				if ra == "" {
					continue
				}
				for _, nb := range fps[keys[b]] {
					if ra == nodeRoots[nb] {
						pairs++
					}
				}
			}
		}
	}
	return pairs
}

// fingerprintSweep — reads /debug/state-fingerprint on every node's
// plain-HTTP metrics port (the fleet sets SOVEREIGN_STATE_FP_DEBUG=1) and
// requires all fingerprints equal. Root equality is not a state-integrity
// oracle per ADR-0045 §5.1; a node whose bytes diverge under equal roots
// fails the sweep.
func fingerprintSweep(cfg runCfg, nodes []node, cr convergeResult) fpResult {
	if !cfg.fpArmed {
		fmt.Println("fingerprint sweep: skipped (-expect-fingerprint=false)")
		return fpResult{}
	}
	fmt.Printf("fingerprint sweep: GET /debug/state-fingerprint on all %d nodes\n", len(nodes))
	var mu sync.Mutex
	fps := make(map[string][]int, len(nodes))
	var failed []int
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n node) {
			defer wg.Done()
			body, err := httpGetPlain(n.metricsAddr, "/debug/state-fingerprint")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, n.idx)
				return
			}
			var fr struct {
				StateFingerprint string `json:"state_fingerprint"`
			}
			if json.Unmarshal(body, &fr) != nil || fr.StateFingerprint == "" {
				failed = append(failed, n.idx)
				return
			}
			fps[fr.StateFingerprint] = append(fps[fr.StateFingerprint], n.idx)
		}(n)
	}
	wg.Wait()
	if len(failed) > 0 {
		sort.Ints(failed)
		fmt.Fprintf(os.Stderr, "  fingerprint sweep fail: %d node(s) unreachable or unarmed (first: %v)\n", len(failed), failed[:min(4, len(failed))])
		return fpResult{swept: len(nodes) - len(failed), allEqual: false, failed: failed}
	}
	if len(fps) != 1 {
		voidPairs := countEqualRootDivergentFPPairs(cr.nodeRoots, fps)
		if voidPairs > 0 || cr.converged || fingerprintSweepVoidOverclaimBugInject.Load() {
			fmt.Fprintf(os.Stderr, "  fingerprint sweep fail: %d distinct state fingerprints across %d nodes — equal roots with divergent bytes (ADR-0045 §5.1; equal_root_divergent_fp_pairs=%d)\n", len(fps), len(nodes), voidPairs)
		} else {
			fmt.Fprintf(os.Stderr, "  fingerprint sweep fail: %d distinct state fingerprints across %d nodes — roots also divergent (converged=%v, equal_root_divergent_fp_pairs=0; ADR-0045 §5.1 condition not observed)\n", len(fps), len(nodes), cr.converged)
		}
		return fpResult{swept: len(nodes), allEqual: false}
	}
	var only string
	for fp := range fps {
		only = fp
	}
	fmt.Printf("  all %d state fingerprints equal (%s…) — bytes match\n", len(nodes), only[:min(16, len(only))])
	return fpResult{swept: len(nodes), allEqual: true}
}

// harvestResult — the per-sweep schema harvest.
type harvestResult struct {
	memstatsOK  int
	indegreeOK  int
	heartbeatOK int // nodes that served /debug/heartbeat (the env-gated route; absent on an env-unset fleet is not a fetch failure)
	fetchFailed int
}

// harvestSchema pulls /debug/memstats and /debug/responder-indegree on every
// node, printing per-region aggregates. A fetch failure is reported but does
// not by itself void the run — the fingerprint sweep owns the unreachability
// verdict.
func harvestSchema(cfg runCfg, nodes []node) harvestResult {
	fmt.Printf("SCHEMA HARVEST: /debug/memstats + /debug/responder-indegree on all %d nodes (+ optional /debug/heartbeat)\n", len(nodes))
	var mu sync.Mutex
	var hr harvestResult
	regionBytes := map[string]float64{}
	regionArrivals := map[string]int64{}
	// The round-scoped exchange columns (the adaptive digest wait, ADR-0072) —
	// per-round exchange completion observed on the metrics plane, not
	// inferred from a post-run bundle.
	regionDone := map[string]int64{}
	regionDrained := map[string]int64{}
	regionExchCompleted := map[string]int64{}
	regionExchDrained := map[string]int64{}
	regionRespBytes := map[string]int64{}
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n node) {
			defer wg.Done()
			msBody, err1 := httpGetPlain(n.metricsAddr, "/debug/memstats")
			riBody, err2 := httpGetPlain(n.metricsAddr, "/debug/responder-indegree")
			hbBody, err3 := httpGetPlain(n.metricsAddr, "/debug/heartbeat")
			mu.Lock()
			defer mu.Unlock()
			if err1 != nil || err2 != nil {
				hr.fetchFailed++
				return
			}
			var ms struct {
				MeshCacheBytes         float64 `json:"mesh_cache_bytes"`
				RelayBatchReverseBytes float64 `json:"relay_batch_reverse_bytes"`
			}
			var ri struct {
				Armed    bool     `json:"armed"`
				Arrivals uint64   `json:"arrivals"`
				Hist     []uint64 `json:"occupancy_hist"`
			}
			if json.Unmarshal(msBody, &ms) == nil && json.Unmarshal(riBody, &ri) == nil {
				hr.memstatsOK++
				hr.indegreeOK++
				regionBytes[n.region] += ms.MeshCacheBytes
				regionArrivals[n.region] += int64(ri.Arrivals)
			} else {
				hr.fetchFailed++
			}
			// The optional heartbeat pull (the adaptive digest wait, ADR-0072) — the
			// route is env-gated (absent = 404 on a
			// SOVEREIGN_DIGEST_LATENCY_DEBUG-unset fleet), so a miss never
			// counts as a fetch failure; a served heartbeat feeds the per-region
			// round-scoped exchange columns.
			if err3 == nil {
				var hb struct {
					LastExchDone       int64 `json:"last_exch_done"`
					LastExchDrained    int64 `json:"last_exch_drained"`
					ExchCompletedTotal int64 `json:"exch_completed_total"`
					ExchDrainedTotal   int64 `json:"exch_drained_total"`
					RespBytesTotal     int64 `json:"resp_bytes_total"`
				}
				if json.Unmarshal(hbBody, &hb) == nil {
					hr.heartbeatOK++
					regionDone[n.region] += hb.LastExchDone
					regionDrained[n.region] += hb.LastExchDrained
					regionExchCompleted[n.region] += hb.ExchCompletedTotal
					regionExchDrained[n.region] += hb.ExchDrainedTotal
					regionRespBytes[n.region] += hb.RespBytesTotal
				}
			}
		}(n)
	}
	wg.Wait()
	regions := make([]string, 0, len(regionBytes))
	for r := range regionBytes {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	for _, r := range regions {
		fmt.Printf("  %s: sum(mesh_cache_bytes)=%.0f sum(responder_arrivals)=%d\n", r, regionBytes[r], regionArrivals[r])
	}
	// The per-region exchange columns — per-round exch_done vs exch_drained
	if hr.heartbeatOK > 0 {
		for _, r := range regions {
			fmt.Printf("  %s: exch_done(last)=%d exch_drained(last)=%d exch_completed_total=%d exch_drained_total=%d resp_bytes_total=%d\n",
				r, regionDone[r], regionDrained[r], regionExchCompleted[r], regionExchDrained[r], regionRespBytes[r])
		}
	} else {
		fmt.Printf("  heartbeat: 0/%d nodes served (SOVEREIGN_DIGEST_LATENCY_DEBUG unset — optional latency columns omitted)\n", len(nodes))
	}
	if hr.fetchFailed > 0 {
		fmt.Fprintf(os.Stderr, "  schema harvest: %d node(s) failed route pulls (fingerprint sweep owns reachability verdict)\n", hr.fetchFailed)
	} else {
		fmt.Printf("  schema harvest: %d/%d nodes pulled clean (memstats + responder-indegree; heartbeat %d/%d)\n", hr.memstatsOK, len(nodes), hr.heartbeatOK, len(nodes))
	}
	return hr
}

// ── verdict and run-ledger row ───────────────────────────────────────────────
// printVerdict: PASS requires a quiescent origin, convergence within the SLO,
// a clean inject (zero hard-timeout chunks), and an all-equal fingerprint
// sweep (per ADR-0045 §5.1). Every other combination names its failure.
// The machine-readable VERDICT line and RUN-LEDGER row are printed for the
// run ledger.
func printVerdict(cfg runCfg, ir injectResult, qr quiesceResult, cr convergeResult, fr fpResult, hr harvestResult) {
	verdict := "PASS"
	switch {
	case !qr.quiesced:
		verdict = "NOT-QUIESCED"
	case !cr.converged:
		verdict = "NOT-CONVERGED"
	case cr.convergedAtMs >= int64(cfg.sloSecs)*1000:
		verdict = "SLO-MISS-LATE-CONVERGED"
	case ir.timeouts > 0:
		verdict = "INJECT-HARD-FAIL"
	case !fr.allEqual:
		verdict = "FINGERPRINT-DIVERGED"
	}
	fmt.Printf("RUN-LEDGER deck=%s keys=%d slo_secs=%d verdict=%s quiesced=%v converged_at_ms=%d fleet_t50_ms=%d fleet_t90_ms=%d inject_wall_ms=%d quiesce_wall_ms=%d inject_fail=%d inject_timeouts=%d fp_swept=%d fp_all_equal=%v harvest_failed=%d\n",
		filepath.Base(cfg.deckPath), cfg.keys, cfg.sloSecs, verdict, qr.quiesced, cr.convergedAtMs,
		cr.t50.Milliseconds(), cr.t90.Milliseconds(), ir.wall.Milliseconds(), qr.wall.Milliseconds(),
		ir.fail, ir.timeouts, fr.swept, fr.allEqual, hr.fetchFailed)
	regions := make([]string, 0, len(cr.regionT))
	for r := range cr.regionT {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	for _, r := range regions {
		c := cr.regionT[r]
		fmt.Printf("REGION-CURVE region=%s t50_ms=%d t90_ms=%d t100_ms=%d\n", r, c.t50.Milliseconds(), c.t90.Milliseconds(), c.t100.Milliseconds())
	}
	fmt.Printf("FLEET-GATE VERDICT: %s\n", verdict)
	if verdict != "PASS" {
		os.Exit(1)
	}
}

// ── wire types (re-declared lean) ────────────────────────────────────────────
// insertItem mirrors insertRequest (key, val, valid_from_ns); the server
// stamps SystemTime per batch and honors valid_from_ns.
type insertItem struct {
	Key         string `json:"key"`
	Val         string `json:"val"`
	ValidFromNs *int64 `json:"valid_from_ns,omitempty"`
}

// batchResp mirrors batchInsertResponse and batchInsertItemStatus; the inject
// counts failures off the per-item code.
type batchResp struct {
	Inserted int `json:"inserted"`
	Failed   int `json:"failed"`
	Items    []struct {
		Index int    `json:"index"`
		Key   string `json:"key"`
		Code  int    `json:"code"`
	} `json:"items"`
}

// merkleResp mirrors merkleResponse (root_hex + the amended
// commit_in_flight) — the quiescence probe's premise is served on the same
// scrape the probe already makes.
type merkleResp struct {
	RootHex        string `json:"root_hex"`
	CommitInFlight int64  `json:"commit_in_flight"`
}

// ── the plumbing helpers ─────────────────────────────
// tlsGet — one mTLS GET over the node's control client (ServerName = the
// node's nodeID hex, a DNSName in its leaf).
func tlsGet(n node, path string) ([]byte, error) {
	resp, err := n.client.Get("https://" + n.controlAddr + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s on node %d: status %d", path, n.idx, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// tlsGetJSON — the mTLS GET + decode (the /v1/merkle scrape shape).
func tlsGetJSON[T any](n node, path string) (T, error) {
	var out T
	body, err := tlsGet(n, path)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("GET %s on node %d: decode: %w", path, n.idx, err)
	}
	return out, nil
}

// tlsPost — the mTLS POST (the /v1/batch-insert shape): a non-200 carries
// the body's head so the inject's error split names the cause.
func tlsPost(n node, path string, body []byte) ([]byte, error) {
	resp, err := n.client.Post("https://"+n.controlAddr+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s on node %d: status %d: %s", path, n.idx, resp.StatusCode, string(out[:min(120, len(out))]))
	}
	return out, nil
}

var plainClient = &http.Client{Timeout: 10 * time.Second}

// httpGetPlain — the plain-HTTP metrics port: /debug/* instrument routes
// live here, not on the mTLS control port.
func httpGetPlain(metricsAddr, path string) ([]byte, error) {
	resp, err := plainClient.Get("http://" + metricsAddr + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET http://%s%s: status %d", metricsAddr, path, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// isTimeoutErr — the hard-inject-failure timeout arm: a client timeout is a
// hard inject failure (an unACKed batch is never "entries may have landed"),
// so the recognition must catch every wrapper shape.
func isTimeoutErr(err error) bool {
	if ue, ok := err.(*url.Error); ok && ue.Timeout() {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return os.IsTimeout(err)
}
