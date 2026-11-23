// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Command convergence-gate checks convergence across a multi-region mesh through
// the sovereign-node JSON-over-mTLS control port. By default it expects 100 nodes
// in three regions.
//
// The command loads the shared CA and client certificate produced by
// cmd/mesh-bootstrap, then reads the node control addresses from the manifest.
// It checks /livecheck on every node and inserts 10,000 keys into the seed with
// /v1/batch-insert. The convergence clock starts only after the seed's Merkle
// root is stable and no WAL commit is in flight. The command then polls
// /v1/merkle until every root matches the seed and queries an inserted key on a
// node in each remote region. Ingest, quiescence, and convergence durations are
// reported separately.
//
// An external partition harness can use -merkle-only to compare roots while the
// mesh is partitioned and again after the partition heals. The control port uses
// RequireAndVerifyClientCert, so every request requires the client certificate.
//
// Run the command on a host that can reach the control ports:
//
//	convergence-gate -bootstrap <dir> -keys 10000 -slo-secs 120
//
// <dir> is the cmd/mesh-bootstrap -out-dir and contains client/, ca.pem, and
// manifest.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// contextDeadlineExceeded aliases the sentinel matched by isTimeoutErr. A client
// timeout may surface either as this sentinel or as a *url.Error wrapping a
// *net.OpError whose Timeout method reports true.
var contextDeadlineExceeded = context.DeadlineExceeded

// node describes one control-port target. IssueLeaf puts nodeIDHex in the leaf's
// CommonName and DNS names. Setting ServerName to nodeIDHex therefore makes the
// standard TLS verification check both the shared-CA chain and the node identity;
// no custom certificate callback or disabled verification is needed.
type node struct {
	idx         int
	region      string
	ip          string
	ctrlPort    int
	nodeIDHex   string
	controlAddr string       // ip:ctrlPort (the https dial target)
	client      *http.Client // per-node mTLS client (ServerName = nodeIDHex)
}

type insertReq struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

// batchInsertItem mirrors batchInsertItemStatus in pkg/mesh/control.go. Code is
// an HTTP-equivalent per-entry status: 200 means inserted and durable, 400 means
// an invalid entry, and 503 means the WAL fsync failed for that entry. The gate
// counts every non-200 status in injectFail so falsePassReason can reject an
// empty mesh after a systematic injection failure.
type batchInsertItem struct {
	Index  int    `json:"index"`
	Key    string `json:"key"`
	Code   int    `json:"code"`
	DotHex string `json:"dot_hex,omitempty"`
}

type batchInsertResp struct {
	Items    []batchInsertItem `json:"items"`
	Inserted int               `json:"inserted"`
	Failed   int               `json:"failed"`
}

type merkleResp struct {
	RootHex string `json:"root_hex"`
	// The quiescence probe reads CommitInFlight alongside the root
	// (ADR-0045 §5). Older node binaries omit commit_in_flight, which Go
	// decodes as zero; the command therefore assumes matching node binaries
	// rather than treating a missing field as proof that no commit is running.
	CommitInFlight      int64  `json:"commit_in_flight"`
	CommitCount         uint64 `json:"commit_count"`
	CommitTotalAppendNs int64  `json:"commit_total_append_ns"`
	CommitMaxAppendNs   int64  `json:"commit_max_append_ns"`
}

func main() {
	bootstrapDir := flag.String("bootstrap", "", "the cmd/mesh-bootstrap -out-dir (holds client/, ca.pem, manifest)")
	numKeys := flag.Int("keys", 10000, "number of keys to inject into node 0")
	sloSecs := flag.Int("slo-secs", 120, "the convergence SLO cap (seconds)")
	controlPortBase := flag.Int("control-port-base", 8443, "the control port base; node i binds base + (per-region local index)")
	splitCSV := flag.String("split", "34,33,33", "per-region node counts (must match the bootstrap)")
	requireN := flag.Int("require-n", 100, "the expected node count (100 for the multi-region gate; 3 for a local smoke test)")
	injectParallel := flag.Int("inject-parallel", 1, "number of concurrent workers issuing the -inject-chunk POSTs. 1 (default) = the serial loop, byte-identical. N>1 spreads chunks across N workers to cut client wall time without changing server-side per-key cost. Per-chunk error accounting is mutex-guarded and identical to the serial path.")
	injectChunk := flag.Int("inject-chunk", 0, "keys per /v1/batch-insert POST. 0 (default) = one batch of -keys (ADR-0044 one-fsync path). A positive value chunks the inject so each POST completes inside the client timeout and progress is observable; safe because AppendMutations releases the WAL mutex before fsync.")
	metricsPortBase := flag.Int("metrics-port-base", 9100, "the metrics port base (the plain-HTTP /metrics ops surface); node i binds metrics-port-base + localIdx")
	merkleOnly := flag.Bool("merkle-only", false, "print one /v1/merkle root per region and exit; useful for checking root divergence during a partition; skips injection and convergence polling")
	flag.Parse()
	if *bootstrapDir == "" {
		fmt.Fprintln(os.Stderr, "convergence-gate: -bootstrap is required")
		os.Exit(2)
	}

	// ── 1. Load the CA + the client leaf. ──
	caPEM, err := os.ReadFile(*bootstrapDir + "/ca.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "convergence-gate: read ca.pem: %v\n", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "convergence-gate: CA PEM did not append to the pool")
		os.Exit(1)
	}
	clientCert, err := tls.LoadX509KeyPair(*bootstrapDir+"/client/cert.pem", *bootstrapDir+"/client/key.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "convergence-gate: load client keypair: %v\n", err)
		os.Exit(1)
	}
	// The client leaf authenticates this command to the control port, and the
	// shared CA authenticates each node. Per-node clients below set ServerName
	// to the nodeID DNS name, leaving both chain and hostname verification to the
	// standard TLS implementation. TLS 1.3 is the minimum version.
	baseTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}
	_ = caPEM

	// ── 2. Parse the manifest and build each node's control client. ──
	manifestBytes, err := os.ReadFile(*bootstrapDir + "/manifest")
	if err != nil {
		fmt.Fprintf(os.Stderr, "convergence-gate: read manifest: %v\n", err)
		os.Exit(1)
	}
	var split []int
	for _, s := range strings.Split(*splitCSV, ",") {
		n, _ := strconv.Atoi(s)
		split = append(split, n)
	}
	var nodes []node
	for _, line := range strings.Split(strings.TrimSpace(string(manifestBytes)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// manifest: idx region ip mesh_port seed nodeid cert key
		idx, _ := strconv.Atoi(fields[0])
		// Derive the per-region index from the manifest's node index, not the
		// manifest line number. Skipping a blank or malformed line must not shift
		// the control port assigned to every later node.
		localIdx := idx
		cum := 0
		for _, s := range split {
			if idx < cum+s {
				localIdx = idx - cum
				break
			}
			cum += s
		}
		nodeIDHex := fields[5]
		// Each node needs a client with its own ServerName. A shared transport
		// would verify every connection against just one node identity.
		nodeTLS := baseTLS.Clone()
		nodeTLS.ServerName = nodeIDHex
		nc := &http.Client{
			// This timeout bounds each control request, including batch inserts;
			// it is independent of the convergence SLO measured from convStart.
			// Thirty seconds accommodates a slow batch fsync without letting a
			// stuck request wait indefinitely (ADR-0043).
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: nodeTLS},
		}
		nodes = append(nodes, node{
			idx:         idx,
			region:      fields[1],
			ip:          fields[2],
			ctrlPort:    *controlPortBase + localIdx,
			nodeIDHex:   nodeIDHex,
			controlAddr: fields[2] + ":" + strconv.Itoa(*controlPortBase+localIdx),
			client:      nc,
		})
	}
	if len(nodes) != *requireN {
		fmt.Fprintf(os.Stderr, "convergence-gate: manifest has %d nodes, want %d (-require-n)\n", len(nodes), *requireN)
		os.Exit(1)
	}
	fmt.Printf("convergence-gate: loaded %d nodes (control port base %d, split %s)\n", len(nodes), *controlPortBase, *splitCSV)

	// The -merkle-only probe prints one root per region and skips injection and
	// convergence polling. During a partition, different roots across regions
	// demonstrate isolation; equal roots indicate that traffic still crosses it.
	if *merkleOnly {
		seenRegion := map[string]bool{}
		for _, n := range nodes {
			if seenRegion[n.region] {
				continue
			}
			seenRegion[n.region] = true
			r, err := tlsGetJSON[merkleResp](n, "/v1/merkle")
			if err != nil {
				fmt.Printf("  [%s node %d] /v1/merkle FAIL: %v\n", n.region, n.idx, err)
				continue
			}
			fmt.Printf("  [%s node %d] /v1/merkle root = %s\n", n.region, n.idx, r.RootHex)
		}
		return
	}

	// ── 3. GATE 0: boot-liveness — GET /livecheck on every node (concurrent). ──
	section(fmt.Sprintf("GATE 0: boot-liveness (GET /livecheck on all %d nodes)", len(nodes)))
	liveStart := time.Now()
	var wg sync.WaitGroup
	liveFail := int32(0)
	for _, n := range nodes {
		wg.Add(1)
		go func(n node) {
			defer wg.Done()
			if _, err := tlsGet(n, "/livecheck"); err != nil {
				fmt.Fprintf(os.Stderr, "  [node %d %s %s] /livecheck FAIL: %v\n", n.idx, n.region, n.controlAddr, err)
				atomic.AddInt32(&liveFail, 1)
			}
		}(n)
	}
	wg.Wait()
	if liveFail > 0 {
		fmt.Fprintf(os.Stderr, "convergence-gate: GATE 0 FAIL — %d/%d nodes not live (boot-liveness gate not met)\n", liveFail, len(nodes))
		os.Exit(1)
	}
	fmt.Printf("  all %d nodes /livecheck OK in %.2fs\n", len(nodes), time.Since(liveStart).Seconds())

	// Insert through /v1/batch-insert rather than paying one request round trip
	// per key (ADR-0042). The seed and the gate host are normally in us-east-1;
	// gossip then carries the inserted deltas across regions, which is the path
	// this command measures. A one-key partition probe sends a one-item batch,
	// and the cross-region query below uses convergence-key-0.
	//
	// With the default -inject-chunk=0, batchSize equals numKeys. The server
	// handles that request through InsertLocalEventsBatch, Bridge.PutLocals, and
	// WAL.AppendMutations, using one write loop and one fsync for the batch
	// (ADR-0044). Batching avoids one fsync per key: at about 2.1 ms per fsync on
	// the measured NVMe host, 10,000 keys would spend about 21 s in fsyncs alone,
	// exceeding a 10 s SLO.
	//
	// A positive -inject-chunk splits the request to bound request latency and
	// expose progress. One measured 10,000-item request reached the 30 s client
	// timeout because the server had to receive, decode, and join the entire
	// batch before responding. Chunking no longer serializes the seed's receive
	// path behind each fsync: the WAL releases its write mutex before fsync, while
	// clock advances use the same mutex.
	//
	// Every response still carries per-entry statuses. A batch sync failure marks
	// every entry 503 (ADR-0044 §4), and the accounting below counts each one in
	// injectFail so an empty mesh cannot pass as converged.
	batchSize := *numKeys
	if *injectChunk > 0 && *injectChunk < batchSize {
		batchSize = *injectChunk
	}
	if batchSize < 1 {
		// A zero-key post-heal probe sends no batches; keep the loop increment
		// positive for that invocation.
		batchSize = 1
	}
	nBatches := 0
	if *numKeys > 0 {
		nBatches = (*numKeys + batchSize - 1) / batchSize
	}
	// Derive the banner from the selected chunking so it reports the actual
	// number of requests and fsyncs.
	injectShape := fmt.Sprintf("%d batch(es) of <=%d keys", nBatches, batchSize)
	if nBatches == 1 {
		injectShape += " — ONE batch, ONE fsync (ADR-0044)"
	} else {
		injectShape += fmt.Sprintf(" — CHUNKED (-inject-chunk=%d); %d fsyncs, each OUTSIDE the WAL mutex", *injectChunk, nBatches)
	}
	section(fmt.Sprintf("INJECT: %d keys into node 0 (%s %s) via /v1/batch-insert (%s)", *numKeys, nodes[0].region, nodes[0].controlAddr, injectShape))
	injectStart := time.Now()
	seed := nodes[0]
	injectFail := 0
	// A timed-out batch has an unknown final state on the server. It invalidates
	// the SLO because the origin may still be committing when injectWG.Wait
	// returns; measuring from that point could include WAL work rather than just
	// propagation (ADR-0045 §5).
	injectTimeouts := 0
	// One -inject-parallel worker retains serial request order. Multiple workers
	// issue chunks concurrently; injectMu protects the shared failure counters,
	// and every worker uses the same per-entry accounting.
	workers := *injectParallel
	if workers < 1 {
		workers = 1
	}
	starts := make(chan int)
	var injectMu sync.Mutex
	var injectWG sync.WaitGroup
	chunkBody := func(start int) {
		end := start + batchSize
		if end > *numKeys {
			end = *numKeys
		}
		items := make([]insertReq, 0, end-start)
		for k := start; k < end; k++ {
			items = append(items, insertReq{
				Key: fmt.Sprintf("convergence-key-%d", k),
				Val: fmt.Sprintf("%010d", k),
			})
		}
		body, _ := json.Marshal(struct {
			Items []insertReq `json:"items"`
		}{Items: items})
		batchBody, err := tlsPost(seed, "/v1/batch-insert", body)
		if err != nil {
			// A client timeout does not reveal whether the server committed the
			// batch. Record it separately and invalidate the SLO rather than
			// claiming either success or a known number of failed inserts.
			// Other transport and HTTP failures have no per-entry acknowledgment,
			// so every entry in the request contributes to injectFail.
			if isTimeoutErr(err) {
				injectMu.Lock()
				injectTimeouts++
				injectMu.Unlock()
				fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] HTTP timeout: %v — hard inject failure (an unacknowledged batch invalidates the SLO measurement)\n", start, end-1, err)
				return
			}
			injectMu.Lock()
			injectFail += end - start
			injectMu.Unlock()
			fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] fail (transport/HTTP, entries did not land): %v\n", start, end-1, err)
			return
		}
		// A 200 response still reports failures in individual item statuses.
		// Count every non-200 item so partial WAL or validation failures remain
		// visible to the empty-mesh guard.
		var br batchInsertResp
		if err := json.Unmarshal(batchBody, &br); err != nil {
			// Without a decodable response, no entry can be counted as
			// acknowledged; treat the whole batch as failed.
			injectMu.Lock()
			injectFail += end - start
			injectMu.Unlock()
			fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] decode FAIL: %v\n", start, end-1, err)
			return
		}
		injectMu.Lock()
		for _, st := range br.Items {
			if st.Code != 200 {
				injectFail++
			}
		}
		failSnapshot := injectFail
		injectMu.Unlock()
		fmt.Printf("  injected %d/%d keys (%.1fs, %d failures)\n", end, *numKeys, time.Since(injectStart).Seconds(), failSnapshot)
	}
	for w := 0; w < workers; w++ {
		injectWG.Add(1)
		go func() {
			defer injectWG.Done()
			for st := range starts {
				chunkBody(st)
			}
		}()
	}
	for start := 0; start < *numKeys; start += batchSize {
		starts <- start
	}
	close(starts)
	injectWG.Wait()
	injectWall := time.Since(injectStart)
	fmt.Printf("  injected %d keys in %.2fs (%d failures, %d hard-timeout batches)\n", *numKeys, injectWall.Seconds(), injectFail, injectTimeouts)
	if injectTimeouts > 0 {
		fmt.Printf("%d batch(es) never acknowledged — hard inject failure(s); SLO verdict is invalid (ADR-0045)\n", injectTimeouts)
	}

	// Start the convergence clock only after positive origin quiescence
	// (ADR-0045 §5). injectWG.Wait can finish after a client timeout while
	// the server is still committing. Since the write-behind WAL updates the root
	// before fsync, root stability alone is insufficient: every poll in the
	// stability streak must also report commit_in_flight == 0. A fetch error
	// resets the streak, and reaching the cap without a clean streak is a failure.
	section(fmt.Sprintf("GATE 1 PRE: seed quiescence probe (root-stable and commit_in_flight==0), then poll /v1/merkle on all %d (SLO %ds)", len(nodes), *sloSecs))
	quiescedRoot, quiesced, quiesceWall, lastInFlight := probeQuiescence(func() (string, int64, error) {
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			return "", 0, err
		}
		return sr.RootHex, sr.CommitInFlight, nil
	}, quiescenceProbeEvery, quiescenceStablePolls, quiescenceCap)
	if !quiesced {
		fmt.Fprintf(os.Stderr, "convergence-gate: seed did not quiesce within cap (last poll: root=%s commit_in_flight=%d — SLO not measured, run invalid)\n", quiescedRoot, lastInFlight)
	}
	fmt.Printf("  origin quiesced=%v: seed root stable and commit_in_flight==0 across %d consecutive polls (quiesce wall %.2fs); root=%s\n", quiesced, quiescenceStablePolls, quiesceWall.Seconds(), quiescedRoot)
	fmt.Printf("  ingest wall %.2fs (%d hard-timeout batches) and quiesce wall %.2fs (reported separately from convergence SLO)\n", injectWall.Seconds(), injectTimeouts, quiesceWall.Seconds())

	// Measure gossip convergence from origin quiescence. Ingest and quiescence
	// have separate durations above and are not included in convStart.
	convStart := time.Now()
	deadline := convStart.Add(time.Duration(*sloSecs) * time.Second)

	// pollOnce reads the seed root, then polls every other node concurrently.
	// A scrape error marks that node divergent but omits it from the root census.
	// The successful-scrape count is therefore required to interpret both the
	// mismatch count and the distinct-root count (ADR-0045 §5).
	pollOnce := func() (string, []int, map[string]int, int) {
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			return "", nil, nil, 0
		}
		root := sr.RootHex
		var mu sync.Mutex
		var mismatch []int
		roots := map[string]int{}
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
				roots[r.RootHex]++
				if r.RootHex != root {
					mismatch = append(mismatch, n.idx)
				}
			}(nodes[i])
		}
		wg.Wait()
		return root, mismatch, roots, scraped
	}

	// censusLine renders up to four non-seed roots as "root×count", sorted by
	// descending count, and summarizes any remaining distinct roots.
	censusLine := func(roots map[string]int) string {
		type rc struct {
			root string
			n    int
		}
		pairs := make([]rc, 0, len(roots))
		for root, n := range roots {
			pairs = append(pairs, rc{root, n})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })
		var sb strings.Builder
		for i, p := range pairs {
			if i >= 4 {
				fmt.Fprintf(&sb, ", +%d more distinct", len(pairs)-4)
				break
			}
			if i > 0 {
				sb.WriteString(", ")
			}
			short := p.root
			if len(short) > 8 {
				short = short[:8]
			}
			fmt.Fprintf(&sb, "%s×%d", short, p.n)
		}
		return sb.String()
	}

	var seedRoot string
	converged := false
	var convergedAtMs int64 = -1
	// Once the empty-mesh guard fires, further polling cannot establish valid
	// convergence. Skip both the extended poll and its final census; the guard
	// already reports the result.
	falsePassTripped := false
	rounds := 0
	nonSeed := len(nodes) - 1
	t50Mark := nonSeed / 2          // divergent ≤ this ⇒ ≥50% converged
	t90Mark := (nonSeed * 10) / 100 // divergent ≤ this ⇒ ≥90% converged
	var t50, t90 time.Duration
	// Record when each node first leaves the divergent set. The tail report uses
	// these timestamps to identify slow nodes and regions; they do not affect the
	// gate verdict.
	firstConvergedAtMs := make(map[int]int64, len(nodes))
	markConverged := func(mismatch []int) {
		now := time.Since(convStart).Milliseconds()
		div := make(map[int]bool, len(mismatch))
		for _, mi := range mismatch {
			div[mi] = true
		}
		for i := 1; i < len(nodes); i++ {
			n := nodes[i]
			if !div[n.idx] {
				if _, seen := firstConvergedAtMs[n.idx]; !seen {
					firstConvergedAtMs[n.idx] = now
				}
			}
		}
	}
	for time.Now().Before(deadline) {
		rounds++
		root, mismatch, _, scraped := pollOnce()
		if root == "" {
			fmt.Fprintf(os.Stderr, "  [poll %d] seed /v1/merkle FAIL\n", rounds)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		seedRoot = root
		markConverged(mismatch)
		if t50 == 0 && len(mismatch) <= t50Mark {
			t50 = time.Since(convStart)
		}
		if t90 == 0 && len(mismatch) <= t90Mark {
			t90 = time.Since(convStart)
		}
		if len(mismatch) == 0 {
			// Equal roots alone do not prove convergence after a failed or empty
			// injection. falsePassReason rejects an all-failed inject and the
			// 64-zero-character empty HAMT root used by CRDT state.
			if reason := falsePassReason(*numKeys, injectFail, seedRoot); reason != "" {
				fmt.Fprintf(os.Stderr, "convergence-gate: false-pass guard triggered: %s\n", reason)
				falsePassTripped = true
				break
			}
			convMs := time.Since(convStart).Milliseconds()
			// The equality check covers the configured roster, so report len(nodes)
			// rather than assuming the 100-node default.
			fmt.Printf("  CONVERGED in %.3fs post-quiescence (all %d roots equal = %s); converged_at_ms=%d\n", float64(convMs)/1000, len(nodes), seedRoot, convMs)
			converged = true
			convergedAtMs = convMs
			break
		}
		if rounds%5 == 0 {
			fmt.Printf("  poll %d: %d nodes divergent (scraped %d/%d; seed root %s...)\n", rounds, len(mismatch), scraped, nonSeed, seedRoot[:8])
		}
		time.Sleep(100 * time.Millisecond)
	}

	// After an SLO miss, poll every 5 s until 240 s after convStart
	// (ADR-0045 §5). Record the actual timestamp if convergence arrives late;
	// otherwise retain the final divergence census. The external crash-recovery
	// harness runs only after convergence and is skipped when none is observed.
	if !converged && !falsePassTripped {
		fmt.Printf("  SLO %ds expired un-converged — extended poll: 5s cadence to a 240s cap\n", *sloSecs)
		extDeadline := convStart.Add(240 * time.Second)
		for time.Now().Before(extDeadline) {
			time.Sleep(5 * time.Second)
			root, mismatch, roots, scraped := pollOnce()
			if root == "" {
				continue
			}
			seedRoot = root
			conv, guardReason := r1PollVerdict(*numKeys, injectFail, seedRoot, len(mismatch))
			if guardReason != "" {
				fmt.Fprintf(os.Stderr, "convergence-gate: false-pass guard triggered (extended poll): %s\n", guardReason)
				falsePassTripped = true
				break
			}
			if conv {
				converged = true
				convergedAtMs = time.Since(convStart).Milliseconds()
				fmt.Printf("  slo=FAIL converged_at_ms=%d (all %d roots equal = %s) — late convergence; crash leg runs\n", convergedAtMs, len(nodes), seedRoot)
				break
			}
			fmt.Printf("  [ext poll t=%ds] divergent=%d distinct_nonseed_roots=%d scraped=%d/%d census=[%s]\n", int(time.Since(convStart).Seconds()), len(mismatch), len(roots), scraped, nonSeed, censusLine(roots))
		}
		if !converged && !falsePassTripped {
			root, mismatch, roots, scraped := pollOnce()
			if root != "" {
				seedRoot = root
			}
			fmt.Fprintf(os.Stderr, "convergence-gate: not converged by 240s (seed root %s); census: %d divergent, %d distinct non-seed roots scraped=%d/%d census=[%s]; crash leg skipped\n", seedRoot, len(mismatch), len(roots), scraped, nonSeed, censusLine(roots))
		}
	}

	// t50 and t90 are recorded only in the pre-deadline loop. After a late
	// convergence they print "-", meaning that the threshold was not reached
	// before the SLO expired; it says nothing about the later curve
	// (ADR-0045 §5).
	fmt.Printf("  convergence curve from quiescence: t50=%s t90=%s t100=%s (t50/t90 arm pre-deadline only; '-' post-SLO reflects ADR-0045 §7)\n", durMs(t50), durMs(t90), msToDur(convergedAtMs))
	convergenceReportTail(nodes, firstConvergedAtMs, convergedAtMs)

	if converged {
		// Keep convergence from quiescence distinct from end-to-end time, which
		// also includes injection and the quiescence probe.
		e2eWall := time.Since(injectStart).Seconds()
		sloMet := convergedAtMs >= 0 && convergedAtMs < int64(*sloSecs)*1000
		sloStr := "met"
		if !sloMet {
			sloStr = "not-met"
		}
		injectStr := "clean"
		if injectTimeouts > 0 {
			injectStr = fmt.Sprintf("hard-fail(%d timeouts — SLO invalid)", injectTimeouts)
		}
		fmt.Printf("GATE 1: convergence-from-quiescence %.3fs (SLO %ds: %s); inject integrity %s; quiesced=%v; end-to-end %.3fs (incl. inject)\n",
			float64(convergedAtMs)/1000, *sloSecs, sloStr, injectStr, quiesced, e2eWall)
	}

	// Query an inserted key on one node in each region other than the seed's.
	section("cross-region check: /v1/query a seed key on a node in each remote region")
	probeKey := "convergence-key-0"
	// /v1/query parses valid_time and tx_time as RFC3339 timestamps. AsOf's second
	// filter admits an entry only when its SystemTime, assigned
	// from the seed's clock at insertion, is no later than tx_time. If the gate
	// host's clock is behind the seed's, using its current time could filter out
	// the new key and falsely report a failed read. Using now+1h for both time
	// parameters avoids that clock-skew dependency and selects the latest
	// assertion.
	futureRFC := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	probed := map[string]bool{}
	seedRegion := nodes[0].region
	for _, n := range nodes[1:] {
		if n.region == seedRegion {
			continue
		}
		if probed[n.region] {
			continue
		}
		url := fmt.Sprintf("/v1/query?key=%s&valid_time=%s&tx_time=%s", probeKey, futureRFC, futureRFC)
		body, err := tlsGetRaw(n, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%s node %d] /v1/query fail: %v\n", n.region, n.idx, err)
			continue
		}
		probed[n.region] = true
		fmt.Printf("  [%s node %d, cross-region] /v1/query?key=%s → %s\n", n.region, n.idx, probeKey, truncate(string(body), 80))
	}
	if len(probed) == 0 {
		fmt.Fprintf(os.Stderr, "  no cross-region probe succeeded (delta did not reach a remote region)\n")
	}

	// Report the inter-region envelope counter from one node per region.
	section("telemetry counter: supremum_mesh_inter_region_envelopes per region (plain-HTTP /metrics)")
	seenRegion := map[string]bool{}
	for _, n := range nodes {
		if seenRegion[n.region] {
			continue
		}
		seenRegion[n.region] = true
		// The metrics listener uses plain HTTP rather than mTLS. Its port is the
		// metrics base plus the same per-region index used for the control port.
		metricsPort := *metricsPortBase + (n.ctrlPort - *controlPortBase)
		metricsURL := fmt.Sprintf("http://%s:%d/metrics", n.ip, metricsPort)
		val := scrapeCounter(metricsURL, "supremum_mesh_inter_region_envelopes")
		fmt.Printf("  %s (node %d, %s:%d): inter_region_envelopes = %s\n", n.region, n.idx, n.ip, metricsPort, val)
	}

	// A passing exit status requires convergence within the SLO, no timed-out
	// injection batches, and a positive quiescence probe. Late convergence or a
	// timed-out batch exits nonzero even when all roots eventually match. The
	// external crash harness reads converged_at_ms rather than the exit code;
	// GATE 1 VERDICT is the machine-readable verdict line.
	gatePass := converged && convergedAtMs >= 0 && convergedAtMs < int64(*sloSecs)*1000 && injectTimeouts == 0 && quiesced
	verdict := "PASS"
	switch {
	case !quiesced:
		verdict = "NOT-QUIESCED"
	case !converged:
		verdict = "NOT-CONVERGED"
	case convergedAtMs >= int64(*sloSecs)*1000:
		verdict = "SLO-MISS-LATE-CONVERGED"
	case injectTimeouts > 0:
		verdict = "INJECT-HARD-FAIL"
	}
	fmt.Printf("GATE 1 VERDICT: %s\n", verdict)
	if !gatePass {
		os.Exit(1)
	}
	fmt.Println("convergence-gate: DONE")
}

// ── helpers ─────────────────────────────────────────────────────────────────

// The quiescence probe requires 12 matching root polls at 250 ms intervals,
// with no commit in flight throughout. The five-minute cap bounds the wait
// before the gate reports that the origin did not quiesce.
const (
	quiescenceProbeEvery  = 250 * time.Millisecond
	quiescenceStablePolls = 12
	quiescenceCap         = 5 * time.Minute
)

// probeQuiescence polls fetchSignal until the root remains unchanged for need
// consecutive polls and every poll in the streak reports no commit in flight.
// A fetch error clears the streak and remembered root; commitInFlight > 0
// clears only the streak, retaining the root as the baseline for the first
// commit-free poll.
//
// Both signals are necessary with a write-behind WAL: the root can stop changing
// before the commit's fsync returns. ADR-0045 §5 records a run that appeared
// quiescent after 3.12 s while a commit remained outstanding for about 213 s;
// measuring from that point included the commit tail rather than propagation.
// The returned lastInFlight is the final poll's count for the failure report.
func probeQuiescence(fetchSignal func() (root string, commitInFlight int64, err error), every time.Duration, need int, capDur time.Duration) (root string, quiesced bool, wall time.Duration, lastInFlight int64) {
	start := time.Now()
	last := ""
	stable := 0
	for time.Since(start) < capDur {
		r, inFlight, err := fetchSignal()
		if err != nil {
			stable = 0
			last = ""
			lastInFlight = 0
			time.Sleep(every)
			continue
		}
		lastInFlight = inFlight
		if inFlight > 0 {
			// Restart the commit-free streak but retain the root baseline. If
			// the root stays unchanged, the first clean poll can match it.
			stable = 0
			last = r
			time.Sleep(every)
			continue
		}
		if r == last {
			stable++
		} else {
			stable = 0
			last = r
		}
		if stable >= need {
			return last, true, time.Since(start), 0
		}
		time.Sleep(every)
	}
	return last, false, time.Since(start), lastInFlight
}

// convergenceNeverMs marks a node that never left the divergent set during the
// polling window. The sentinel exceeds any real timestamp delta, so the
// descending sort places these nodes ahead of the slowest converged nodes. A -1
// sentinel would incorrectly place them at the end of the report.
const convergenceNeverMs = int64(1) << 60

// convergenceTailRow records one node's first convergence time or sentinel.
type convergenceTailRow struct {
	idx    int
	region string
	atMs   int64 // convergenceNeverMs ⇒ never converged within the window
}

// convergenceComputeTailRows returns non-seed rows in descending atMs order.
// The seed is the injection source and is already converged at t=0, so it is
// excluded. Nodes without a timestamp receive convergenceNeverMs. The function
// performs no I/O, allowing tests to check the ordering and seed exclusion.
func convergenceComputeTailRows(nodes []node, firstConvergedAtMs map[int]int64) []convergenceTailRow {
	seedIdx := nodes[0].idx
	rows := make([]convergenceTailRow, 0, len(nodes)-1)
	for _, n := range nodes {
		if n.idx == seedIdx {
			continue // the source — never a straggler
		}
		at, ok := firstConvergedAtMs[n.idx]
		if !ok {
			at = convergenceNeverMs
		}
		rows = append(rows, convergenceTailRow{n.idx, n.region, at})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].atMs > rows[j].atMs })
	return rows
}

// convergenceReportTail prints per-region timing summaries and up to 12 of the
// slowest nodes. Regions with no converged nodes report only the missing count;
// their min, median, and max are undefined.
func convergenceReportTail(nodes []node, firstConvergedAtMs map[int]int64, convergedAtMs int64) {
	rows := convergenceComputeTailRows(nodes, firstConvergedAtMs)
	byRegion := map[string][]int64{}
	neverByRegion := map[string]int{}
	allRegions := map[string]bool{}
	for _, r := range rows {
		allRegions[r.region] = true
		if r.atMs == convergenceNeverMs {
			neverByRegion[r.region]++
			continue
		}
		byRegion[r.region] = append(byRegion[r.region], r.atMs)
	}
	fmt.Printf("  [convergence-tail] per-region convergence-time (ms since quiescence; t100=%dms):\n", convergedAtMs)
	regions := make([]string, 0, len(allRegions))
	for reg := range allRegions {
		regions = append(regions, reg)
	}
	sort.Strings(regions)
	for _, reg := range regions {
		ts := byRegion[reg]
		if len(ts) == 0 {
			fmt.Printf("    %-16s n=0 converged (all %d did not converge in window)\n", reg, neverByRegion[reg])
			continue
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		fmt.Printf("    %-16s n=%d min=%dms p50=%dms max=%dms never=%d\n", reg, len(ts), ts[0], ts[len(ts)/2], ts[len(ts)-1], neverByRegion[reg])
	}
	// Worst-first ordering names the nodes responsible for the tail rather than
	// reporting only their count.
	fmt.Printf("  [convergence-tail] tail (last-to-converge nodes, ms since quiescence):\n")
	limit := 12
	if len(rows) < limit {
		limit = len(rows)
	}
	for i := 0; i < limit; i++ {
		r := rows[i]
		if r.atMs == convergenceNeverMs {
			fmt.Printf("    node %-4d %-16s did not converge in window\n", r.idx, r.region)
		} else {
			fmt.Printf("    node %-4d %-16s converged_at=%dms\n", r.idx, r.region, r.atMs)
		}
	}
}

// durMs renders a duration as seconds, or "-" when its t50/t90 mark was not set.
func durMs(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.3fs", d.Seconds())
}

// falsePassReason rejects equal roots that result from a failed injection.
// With numKeys > 0, either an all-failed inject or the empty HAMT root (64 zero
// hexadecimal characters) makes equal roots inconclusive. It returns an empty
// string when neither condition holds. Both convergence polling loops use it.
func falsePassReason(numKeys, injectFail int, seedRoot string) string {
	if numKeys > 0 && injectFail >= numKeys {
		return fmt.Sprintf("all %d inserts failed; roots equal on an empty mesh (not valid convergence)", injectFail)
	}
	if numKeys > 0 && seedRoot == strings.Repeat("0", 64) {
		return fmt.Sprintf("seed root is the empty HAMT root %s; roots equal on an empty mesh (not valid convergence)", seedRoot)
	}
	return ""
}

// r1PollVerdict decides one extended-poll result. A nonzero mismatchLen means
// that a node diverged or could not be scraped. With no mismatches, applying
// falsePassReason here as well as in the main loop prevents an all-503 inject
// from passing on equal empty roots. TestR1PollVerdict_FalsePassGuard covers
// that case.
func r1PollVerdict(numKeys, injectFail int, seedRoot string, mismatchLen int) (converged bool, guardReason string) {
	if mismatchLen != 0 {
		return false, ""
	}
	if reason := falsePassReason(numKeys, injectFail, seedRoot); reason != "" {
		return false, reason
	}
	return true, ""
}

// msToDur renders a millisecond timestamp delta as seconds, or "-" when the
// event never happened (convergedAtMs = -1).
func msToDur(ms int64) string {
	if ms < 0 {
		return "-"
	}
	return fmt.Sprintf("%.3fs", float64(ms)/1000)
}

func section(title string) {
	fmt.Printf("\n======== %s ========\n", title)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func tlsGet(n node, path string) ([]byte, error) {
	return tlsGetRaw(n, path)
}

func tlsGetRaw(n node, path string) ([]byte, error) {
	url := "https://" + n.controlAddr + path
	resp, err := n.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(b), 120))
	}
	return b, nil
}

func tlsGetJSON[T any](n node, path string) (T, error) {
	var zero T
	b, err := tlsGetRaw(n, path)
	if err != nil {
		return zero, err
	}
	var r T
	if err := json.Unmarshal(b, &r); err != nil {
		return zero, err
	}
	return r, nil
}

func tlsPost(n node, path string, body []byte) ([]byte, error) {
	url := "https://" + n.controlAddr + path
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(b), 120))
	}
	return b, nil
}

// isTimeoutErr reports whether err is a request deadline expiry. The injection
// path records this separately because the server's final state is unknown;
// other transport and HTTP errors contribute to injectFail.
//
// http.Client.Timeout can surface as a *url.Error wrapping a *net.OpError whose
// Timeout method reports true, or as context.DeadlineExceeded. Match both forms
// and walk wrapping chains so errors added by fmt.Errorf retain their
// classification.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, contextDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

func scrapeCounter(metricsURL, name string) string {
	// Bound the scrape instead of using http.DefaultClient, which has no
	// timeout. Thirty seconds matches the control clients and allows for a
	// briefly busy host without letting a stuck endpoint block the gate
	// indefinitely (ADR-0043).
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(metricsURL)
	if err != nil {
		return "<not scraped: " + err.Error() + ">"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			return fields[1]
		}
	}
	return "<counter not present in /metrics>"
}
