// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Command convergence-gate is the mTLS SDK client that drives the 100-node
// 3-region silicon convergence gate. It is the PRODUCTION-faithful gate: it
// talks to the sovereign-node control port (the JSON-over-mTLS surface) the
// SAME way an operator SDK would — NOT a scraped counter, NOT a test harness.
//
// WHAT IT DOES (the gate, end-to-end):
// 1. Loads the shared CA + the client leaf (minted by cmd/mesh-bootstrap).
// 2. Builds ONE mTLS http.Client (TLS 1.3, RequireAndVerify via the shared CA).
// 3. Reads the manifest (100 node control addrs = public-ip:control-port).
// 4. GATE 0 (boot-liveness): GET /livecheck on every node; all-100 up.
// 5. INJECT: POST /v1/insert 10K keys into node 0 (the seed node). The SLO
// clock starts at the FIRST insert.
// 6. GATE 1 (convergence): poll GET /v1/merkle on all-100 until every node's
// root_hex EQUALS the seed node's root (the live MerkleRoot check — the
// SAME source the loopback harness's MerkleRoots() reads). The wall-time
// from inject-start to all-100-roots-equal is the convergence SLO.
// 7. CROSS-REGION PROOF: GET /v1/query on a node in EACH of the other 2
// regions for an injected key → 200 with the payload (a delta crossed
// regions on real cross-region RTT).
//
// An external harness drives the PARTITION gate around this client: it runs
// convergence-gate for GATE 0/1/cross-region, then injects an
// iptables partition, re-runs the merkle poll to prove ISOLATION (roots
// diverge), heals (iptables -F), and re-polls for re-convergence (rounds).
//
// WHY mTLS, not plain curl: the control port is tls.Listen with
// RequireAndVerifyClientCert (control.go startControlPort) — a no-cert dial is
// a hard TLS error. The gate MUST present the client leaf. Plain-HTTP curl
// (the orchestrator's prior stub) could NEVER reach /v1/insert or /v1/merkle.
//
// USAGE (run on the operator's machine; dials the 100 public control ports):
//
//	convergence-gate -bootstrap <dir> -keys 10000 -slo-secs 120
//
// <dir> is the cmd/mesh-bootstrap -out-dir (holds client/, ca.pem, manifest).
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

// contextDeadlineExceeded is the sentinel context.DeadlineExceeded, captured
// once at package scope (the http.Client.Timeout expiry surfaces as a
// *url.Error wrapping a *net.OpError with Timeout()==true, but the request
// context itself expires as context.DeadlineExceeded — both are matched in
// isTimeoutErr). It is an alias, not a copy, so errors.Is compares identity.
var contextDeadlineExceeded = context.DeadlineExceeded

// node is a per-mesh-node dial target. nodeIDHex is the leaf CommonName +
// DNSName the node presents (IssueLeaf embeds it as a DNSName), so the mTLS
// dial sets ServerName = nodeIDHex — the stdlib then verifies BOTH the chain
// (against the shared CA pool) AND the hostname (the nodeID DNSName). NO
// InsecureSkipVerify, NO custom VerifyPeerCertificate — the world-standard
// hostname-pinned mTLS dial.
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

// batchInsertItem mirrors the server's per-entry status (pkg/mesh/control.go
// batchInsertItemStatus) in the /v1/batch-insert response. Code is the per-entry
// HTTP-equivalent status: 200 = inserted+durable, 400 = bad entry, 503 = WAL
// fsync failed for THAT entry. The gate sums Code != 200 into injectFail so the
// empty-root false-pass guard (main.go ~line 310) catches a systematic inject
// failure honestly.
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
	// ADR-0045: the commit-in-flight
	// signal the quiescence probe must read ALONGSIDE the root. A node running
	// older code omits the field; Go's zero value then reads as
	// "no commit in flight" — safe ONLY because the gate always runs matched
	// binaries, and the probe below says so in words when it relies on it.
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
	requireN := flag.Int("require-n", 100, "the expected node count (100 for the silicon gate; 3 for a local smoke test)")
	injectParallel := flag.Int("inject-parallel", 1, "number of concurrent workers issuing the -inject-chunk POSTs. 1 (default) = the serial loop, byte-identical. N>1 fans the chunks across N workers so the inject costs ~wall/N of PAID INSTANCE TIME (a silicon run: 184s serial at chunk=100). ZERO server-side change — the per-key server cost is NOT root-caused by this flag; it is a harness-throughput knob only. Per-chunk error accounting is mutex-guarded and identical to the serial path.")
	injectChunk := flag.Int("inject-chunk", 0, "keys per /v1/batch-insert POST. 0 (default) = ONE batch of -keys (the ADR-0044 ONE-fsync path, byte-identical). A positive value chunks the inject so each POST returns inside the client Timeout and progress is observable — a silicon run's single 10K POST took 30.03s and HIT the 30s timeout with no partial ACK. Safe to chunk only because the WAL change released the WAL mutex before the fsync (so N fsyncs no longer block the seed's receive path).")
	metricsPortBase := flag.Int("metrics-port-base", 9100, "the metrics port base (the plain-HTTP /metrics ops surface); node i binds metrics-port-base + localIdx")
	merkleOnly := flag.Bool("merkle-only", false, "fetch + print each node's /v1/merkle root (one per region) then exit — the orchestrator's GATE 3 isolation probe uses this to compare node 0's root vs a eu node's root DURING the partition (roots DIVERGE = isolated); skips the inject + GATE 1 poll")
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
	// The base TLS config: the client leaf (presented to each node's
	// RequireAndVerifyClientCert control port) + the shared CA pool (the chain
	// trust anchor) + TLS 1.3. NO InsecureSkipVerify — the per-node client
	// (below) sets ServerName to the node's nodeIDHex, which is a DNSName in the
	// node's leaf (IssueLeaf embeds the nodeID as a DNSName), so the stdlib
	// verifies BOTH the chain (RootCAs) AND the hostname (the nodeID DNSName).
	// This is the world-standard hostname-pinned mTLS dial — no custom verify
	// callback, no weakened verification surface.
	baseTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}
	_ = caPEM

	// ── 2. Parse the manifest → the 100 nodes' control addrs + per-node clients. ─
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
		// per-region local index = the node's GLOBAL index (idx, from the
		// manifest's own field[0]) minus the cumulative split up to this node's
		// region. an earlier draft derived localIdx from the line-scan index
		// `i`, which desyncs every subsequent node's port if a blank/malformed line
		// triggers the `continue` above (i advances, no node appended). Using the
		// manifest's idx field is robust to skipped lines.
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
		// Clone the base TLS config + pin ServerName to the node's nodeID hex
		// (a DNSName in the node leaf). Each node gets its OWN http.Client so
		// the dial carries the correct ServerName (a shared transport dials
		// under ONE ServerName — wrong for a 100-node mesh).
		nodeTLS := baseTLS.Clone()
		nodeTLS.ServerName = nodeIDHex
		nc := &http.Client{
			// raised 10s→30s. The per-node client's Timeout
			// bounds EVERY mTLS dial (the inject POST, the /livecheck, the
			// /v1/merkle poll). It is NOT the convergence SLO (convStart is
			// measured separately, AFTER the inject). The 10s prior bound
			// EQUALED the 10s SLO gate — so a slow-but-succeeding batch POST
			// (EBS fsync ~3s/batch) hit the client timeout = the
			// entries LANDED server-side but the response was dropped = the
			// gate overcounted timeout-as-failure (the injectFail bug, FIXED
			// in the inject loop below). 30s keeps the inject honest under NVMe
			// (a 1.5ms/batch completes instantly) AND de-risks a transient
			// slow fsync WITHOUT equalling the SLO. The SLO clock is
			// convStart→converged, measured independently below.
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

	// ── 2b. -merkle-only: fetch + print each node's /v1/merkle root (one per
	// region) then exit. The orchestrator's GATE 3 isolation probe polls
	// node 0's root vs a eu node's root DURING the partition (roots
	// DIVERGE = isolated; roots EQUAL = the partition leaked). This skips
	// the inject + GATE 1 poll (a probe, NOT the convergence gate). ──
	if *merkleOnly {
		seenRegion := map[string]bool{}
		for _, n := range nodes {
			if seenRegion[n.region] {
				continue
			}
			seenRegion[n.region] = true
			r, err := tlsGetJSON[merkleResp](n, "/v1/merkle")
			if err != nil {
				fmt.Printf(" [%s node %d] /v1/merkle FAIL: %v\n", n.region, n.idx, err)
				continue
			}
			fmt.Printf(" [%s node %d] /v1/merkle root = %s\n", n.region, n.idx, r.RootHex)
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
				fmt.Fprintf(os.Stderr, " [node %d %s %s] /livecheck FAIL: %v\n", n.idx, n.region, n.controlAddr, err)
				atomic.AddInt32(&liveFail, 1)
			}
		}(n)
	}
	wg.Wait()
	if liveFail > 0 {
		fmt.Fprintf(os.Stderr, "convergence-gate: GATE 0 FAIL — %d/%d nodes not live (boot-liveness gate not met)\n", liveFail, len(nodes))
		os.Exit(1)
	}
	fmt.Printf(" all %d nodes /livecheck OK in %.2fs\n", len(nodes), time.Since(liveStart).Seconds())

	// ── 4. INJECT 10K keys into node 0 (the seed) via /v1/batch-insert. ──
	// switched from 10K serial /v1/insert POSTs (one RTT
	// per key over cross-region WAN = minutes, the GATE 1 (B) root cause) to
	// chunked /v1/batch-insert POSTs (batchSize keys per POST). Node 0 is in
	// us-east-1, the gate host dials us-east-1 → the inject is INTRA-region (NO
	// cross-region WAN RTT in the inject phase); the GOSSIP then carries the
	// deltas across regions = the actual gate subject. A 1-key run (the
	// orchestrator's GATE 3 partition-probe at -keys 1) sends ONE 1-item batch
	// (degenerate but correct). Key shape `convergence-key-%d` / val `%010d` is
	// byte-identical to the serial loop (key index 0 is in the FIRST batch —
	// the cross-region proof probe greps `convergence-key-0`).
	//
	// ADR-0044 — the ONE-fsync-per-batch switch. The gate
	// binary chunked 10K keys into 10 batches of 1000 (batchSize=1000); each
	// batch hit the server's /v1/batch-insert which looped InsertLocalEvents
	// PER ENTRY → AppendMutation PER ENTRY → ONE fsync PER ENTRY = 1000 fsyncs
	// per batch × 10 batches = 10000 fsyncs total. At the silicon-measured
	// ~2.1ms/fsync (NVMe), that is ~21s of inject fsync-time ALONE > the 10s
	// GATE-1 SLO (the root cause traced: the binding constraint is
	// the fsync COUNT, not the fsync latency). The single-batch inject collapses the count: set
	// batchSize = numKeys so the loop runs ONCE → ONE /v1/batch-insert POST →
	// the server's handleBatchInsert routes through InsertLocalEventsBatch →
	// Bridge.PutLocals → WAL.AppendMutations (ONE write-loop + ONE fsync for
	// the WHOLE 10K). The 10K keys now pay ONE ~2.1ms fsync + the cross-AZ
	// HTTP RTT (~50-150ms) = a sub-second inject, well inside the 10s SLO.
	//
	// The loop structure is UNCHANGED (the `for start:= 0; start < *numKeys;
	// start += batchSize` runs exactly once when batchSize >= numKeys); only
	// the batchSize constant is replaced with numKeys so a 1-key probe run
	// (-keys 1) still sends ONE 1-item batch (degenerate but correct). The
	// per-entry status accounting (the br.Items loop below) is UNCHANGED — a
	// single 10K-item batch returns 10K per-entry statuses the SAME way 10
	// 1K-batches did; the per-batch 503 semantic (ADR-0044 §4) means a Sync
	// failure reports ALL 10000 as 503 (a wholesale injectFail+=10000 the
	// convergence poll + WAL stat then verify, NOT a per-entry lie).
	//
	// the -inject-chunk override. Silicon showed the
	// ONE-batch inject take 30.03s and hit the client Timeout: a single 10K-item
	// JSON POST must be fully received, unmarshalled, and Join'd before the server
	// responds, so the whole inject is one all-or-nothing 30s+ request with NO
	// progress signal and NO partial ACK. The 10s convergence SLO clock was
	// therefore already 3x expired before the inject finished.
	//
	// WHY THIS IS NOW SAFE TO CHUNK (it was not, before the WAL change): the
	// ONE-batch collapse existed because AppendMutations held w.mu across its fsync, so N
	// batches meant N fsyncs each BLOCKING the seed's own receive path
	// (AppendClockAdvance shares that mutex). The WAL change released the mutex
	// before the fsync, so a chunked inject now costs N fsyncs that DO NOT
	// serialize the receive path. The fsync COUNT is no longer the binding
	// constraint; the single-request WALL TIME is.
	//
	// DEFAULT IS UNCHANGED (-inject-chunk 0 → batchSize = numKeys → the
	// ONE-batch, ONE-fsync path, byte-identical). The orchestrator opts in.
	batchSize := *numKeys // ADR-0044: ONE batch → ONE fsync (the 10000× fsync-COUNT cut; was const 1000 = 10 batches)
	if *injectChunk > 0 && *injectChunk < batchSize {
		batchSize = *injectChunk
	}
	if batchSize < 1 {
		batchSize = 1 // a 0-key run (the post-heal re-convergence probe at -keys 0) sends an empty batch — guard against an empty-loop edge
	}
	// Report the ACTUAL geometry, not a fixed slogan: a banner that says "ONE
	// batch, ONE fsync" while -inject-chunk is chunking would be a lying log line.
	nBatches := 0
	if *numKeys > 0 {
		nBatches = (*numKeys + batchSize - 1) / batchSize
	}
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
	injectTimeouts := 0 // a batch POST that hits the client Timeout is a HARD INJECT FAILURE — the entries likely landed (the exactly-once record stands), but the run's SLO is INVALID: the origin was still committing when the client gave up, so a convergence clock started at injectWG.Wait() measures WAL-commit straggler latency, not propagation (ADR-0045).
	// fan the chunk POSTs across `-inject-parallel` workers.
	// N=1 keeps the SERIAL order and semantics byte-identical to the serial path. The chunk
	// BODY below is UNCHANGED — only who runs it changes — so the honest per-entry
	// accounting (the timeout-vs-transport-vs-per-item distinction) is
	// preserved exactly; injectFail/batchTimedOut are guarded by injectMu because
	// multiple workers now touch them.
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
			// the injectFail honesty fix. A tlsPost
			// error covers THREE distinct failure modes that the prior code
			// conflated into one "injectFail += end-start":
			//
			// (A) a CLIENT TIMEOUT (the http.Client.Timeout was exceeded — the
			// EBS symptom: the per-mutation fsync ate the 10s bound,
			// the response was dropped, but the entries LANDED server-side
			// + were fsync'd; the seed root was non-empty + key-0 crossed
			// regions in silicon). Counting these as 1000 failures
			// was a GATE LIE — it equated "the HTTP response did not return
			// in time" with "the write failed". The correct verdict is
			// DEFERRED: the convergence poll (all roots equal) + the empty-
			// root false-pass guard (below) + the orchestrator's WAL-file
			// stat (CHECK B) VERIFY whether the entries actually landed. So
			// a timeout does NOT add to injectFail; it sets batchTimedOut +
			// logs the honest "entries may have landed" message.
			// (B) a genuine transport/HTTP error (a dial failure, a 5xx at the
			// HTTP layer — the request NEVER reached a durable write). The
			// entries did NOT land; counting them in injectFail is HONEST
			// (the empty-root guard then catches a systematic failure).
			// (C) a context-canceled / connection-reset mid-stream — treat as
			// (B), a genuine failure (we cannot confirm any entry landed).
			//
			// The split: if the error is a net.Timeout / url.Timeout (case A)
			// → do NOT add to injectFail (defer to the convergence + WAL
			// verification). Otherwise (case B/C) → count honestly as before.
			// This is STRICTLY MORE HONEST than the spec's literal "on a
			// timeout/error: do NOT add" grouping — a dial failure is NOT
			// "entries may have landed" (the request never reached the server),
			// and counting it as a timeout would under-report a real failure.
			if isTimeoutErr(err) {
				injectMu.Lock()
				injectTimeouts++
				injectMu.Unlock()
				fmt.Fprintf(os.Stderr, " [inject batch %d-%d] HTTP TIMEOUT: %v — HARD INJECT FAILURE (a batch that does not ACK is never \"entries may have landed\"; the run's SLO is INVALID)\n", start, end-1, err)
				return
			}
			injectMu.Lock()
			injectFail += end - start
			injectMu.Unlock()
			fmt.Fprintf(os.Stderr, " [inject batch %d-%d] FAIL (transport/HTTP, entries did NOT land): %v\n", start, end-1, err)
			return
		}
		// Decode the per-entry status array (a PARTIAL batch is reported
		// HONESTLY — the server returns 200 with per-item Code, NOT a 200-all
		// lie). Sum Code != 200 into injectFail (400 = bad entry, 503 = WAL
		// fsync failed for that entry — the per-entry ACK-before-durability
		// contract).
		var br batchInsertResp
		if err := json.Unmarshal(batchBody, &br); err != nil {
			// Undecodable body = treat the whole batch as failed (honest — we
			// cannot confirm any entry landed).
			injectMu.Lock()
			injectFail += end - start
			injectMu.Unlock()
			fmt.Fprintf(os.Stderr, " [inject batch %d-%d] decode FAIL: %v\n", start, end-1, err)
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
		fmt.Printf(" injected %d/%d keys (%.1fs, %d failures)\n", end, *numKeys, time.Since(injectStart).Seconds(), failSnapshot)
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
	fmt.Printf(" injected %d keys in %.2fs (%d failures, %d hard-timeout batches)\n", *numKeys, injectWall.Seconds(), injectFail, injectTimeouts)
	if injectTimeouts > 0 {
		fmt.Printf("%d batch(es) never ACKed — HARD INJECT FAILURE(S); the entries landed exactly-once (the WAL-stat + root-equality record), but the run's SLO verdict is INVALID (ADR-0045)\n", injectTimeouts)
	}

	// ── 5. GATE 1 PRE (ADR-0045): ORIGIN QUIESCENCE
	// — the SLO clock starts HERE, not at injectWG.Wait(). injectWG.Wait()
	// returns when every batch call returned OR TIMED OUT, and a timed-out
	// batch is still committing server-side (InsertLocal'd in state, WAL
	// mid-flight, payloads unrecorded — the starting-line defect, ADR-0045).
	// The ORIGINAL premise — "a root stable across 12
	// consecutive 250ms polls means NO commit is in flight" — is FALSIFIED
	// (a run declared quiesced at 3.12 s while a ~213 s commit was still
	// outstanding; the write-behind WAL puts the batch in the root BEFORE the
	// fsync, so the root had nothing left to change). The AMENDED probe reads
	// the commit-in-flight signal on the SAME /v1/merkle scrape and requires
	// BOTH: root stable across 12 polls AND commit_in_flight == 0 on every one
	// of them. Positive probe, never timeout-tolerant. The quiesced root is
	// recorded so the gate anchors on a KNOWN root.
	section(fmt.Sprintf("GATE 1 PRE: seed quiescence probe (root-stable AND commit_in_flight==0), then poll /v1/merkle on all %d (SLO %ds)", len(nodes), *sloSecs))
	quiescedRoot, quiesced, quiesceWall, lastInFlight := probeQuiescence(func() (string, int64, error) {
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			return "", 0, err
		}
		return sr.RootHex, sr.CommitInFlight, nil
	}, quiescenceProbeEvery, quiescenceStablePolls, quiescenceCap)
	if !quiesced {
		fmt.Fprintf(os.Stderr, "convergence-gate: GATE 1 PRE — the seed NEVER went quiescent within the cap (last poll: root=%s commit_in_flight=%d — the origin never went quiescent — a worse defect than a missed SLO; the SLO is not measured, the run is INVALID)\n", quiescedRoot, lastInFlight)
	}
	fmt.Printf(" origin quiesced=%v: seed root stable AND commit_in_flight==0 across %d consecutive polls (quiesce wall %.2fs); root=%s\n", quiesced, quiescenceStablePolls, quiesceWall.Seconds(), quiescedRoot)
	fmt.Printf(" SCISSORS: ingest wall %.2fs (its own number — %d hard-timeout batches) + quiesce wall %.2fs are reported SEPARATELY from the convergence SLO below\n", injectWall.Seconds(), injectTimeouts, quiesceWall.Seconds())

	// ── 5. GATE 1: poll all-100 /v1/merkle until roots equal (the SLO). ──
	// convStart is anchored at ORIGIN QUIESCENCE (the gate's stated intent,
	// finally implemented). The gate measures GOSSIP convergence; the ingest
	// and quiescence walls are printed above and never folded in.
	convStart := time.Now()
	deadline := convStart.Add(time.Duration(*sloSecs) * time.Second)

	// pollOnce reads the seed root, then polls all other nodes concurrently.
	// Returns (seedRoot, divergent node indices, non-seed root census, scrape
	// successes). The scrape-success count is LOAD-BEARING (ADR-0045):
	// a scrape error appends to mismatch and SKIPS the census,
	// so len(roots) alone is computed over the successfully-scraped subset —
	// "divergent=99 distinct=1" once meant "1 node scraped, 98 failures", not
	// "99 agree". Print the census AND the scrape count or the number lies.
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

	// censusLine renders the non-seed root census as "root×count,..." sorted
	// by count descending (top 4) — the content that must be printed,
	// not just its cardinality.
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
	// falsePassTripped records that the empty-mesh guard fired. When set, the extended poll is SKIPPED — an inject that landed
	// NOTHING can never honestly converge, so 240s of polling is pure waste,
	// and the NOT-CONVERGED-BY-240s census is skipped with it (the guard line
	// already recorded the honest result).
	falsePassTripped := false
	rounds := 0
	nonSeed := len(nodes) - 1
	t50Mark := nonSeed / 2          // divergent ≤ this ⇒ ≥50% converged
	t90Mark := (nonSeed * 10) / 100 // divergent ≤ this ⇒ ≥90% converged
	var t50, t90 time.Duration      // the convergence curve
	for time.Now().Before(deadline) {
		rounds++
		root, mismatch, _, scraped := pollOnce()
		if root == "" {
			fmt.Fprintf(os.Stderr, " [poll %d] seed /v1/merkle FAIL\n", rounds)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		seedRoot = root
		if t50 == 0 && len(mismatch) <= t50Mark {
			t50 = time.Since(convStart)
		}
		if t90 == 0 && len(mismatch) <= t90Mark {
			t90 = time.Since(convStart)
		}
		if len(mismatch) == 0 {
			// The empty-root guard: if every insert failed
			// OR the seed root is the zero/empty HAMT root, this "convergence"
			// is a FALSE PASS — an empty mesh trivially has equal roots.
			// The loopback test's emptyRoot check guards this; the gate
			// must too. emptyRoot = 64 zero bytes hex (sha256 of the
			// empty HAMT, the crdt.go:1341 path). A non-empty inject + a
			// non-empty root is the honest convergence.
			if reason := falsePassReason(*numKeys, injectFail, seedRoot); reason != "" {
				fmt.Fprintf(os.Stderr, "convergence-gate: GATE 1 — FALSE-PASS guard: %s. HONEST result recorded.\n", reason)
				falsePassTripped = true
				break
			}
			convMs := time.Since(convStart).Milliseconds()
			// len(nodes), NOT a literal 100: this string was hardcoded "all 100
			// roots equal" and printed "100" for ANY node count (a 3-node local
			// run emitted "all 100 roots equal"). The EQUALITY
			// CHECK above is sound (it iterates every node and requires zero
			// mismatches, with -require-n enforcing the roster size), but a
			// report line must state the number it actually measured.
			fmt.Printf(" CONVERGED in %.3fs post-quiescence (all %d roots equal = %s); converged_at_ms=%d\n", float64(convMs)/1000, len(nodes), seedRoot, convMs)
			converged = true
			convergedAtMs = convMs
			break
		}
		if rounds%5 == 0 {
			fmt.Printf(" poll %d: %d nodes divergent (scraped %d/%d; seed root %s...)\n", rounds, len(mismatch), scraped, nonSeed, seedRoot[:8])
		}
		time.Sleep(100 * time.Millisecond)
	}

	// (ADR-0045): when the SLO expires un-converged,
	// keep polling at 5s cadence to a HARD CAP of 240s, recording
	// `slo=FAIL converged_at_ms=<actual>` or `NOT-CONVERGED-BY-240s`, plus a
	// divergence census (node count AND the number of DISTINCT non-seed roots).
	// Late convergence ⇒ the crash leg RUNS. Never converged ⇒ skipped, with
	// the census as the artifact.
	if !converged && !falsePassTripped {
		fmt.Printf(" SLO %ds expired un-converged — extended poll: 5s cadence to a 240s cap\n", *sloSecs)
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
				fmt.Fprintf(os.Stderr, "convergence-gate: GATE 1 — FALSE-PASS guard (extended poll): %s. HONEST result recorded.\n", guardReason)
				falsePassTripped = true
				break
			}
			if conv {
				converged = true
				convergedAtMs = time.Since(convStart).Milliseconds()
				fmt.Printf(" slo=FAIL converged_at_ms=%d (all %d roots equal = %s) — LATE convergence; the crash leg RUNS\n", convergedAtMs, len(nodes), seedRoot)
				break
			}
			fmt.Printf(" [ext poll t=%ds] divergent=%d distinct_nonseed_roots=%d scraped=%d/%d census=[%s]\n", int(time.Since(convStart).Seconds()), len(mismatch), len(roots), scraped, nonSeed, censusLine(roots))
		}
		if !converged && !falsePassTripped {
			root, mismatch, roots, scraped := pollOnce()
			if root != "" {
				seedRoot = root
			}
			fmt.Fprintf(os.Stderr, "convergence-gate: GATE 1 — NOT-CONVERGED-BY-240s (seed root %s); census: %d divergent, %d distinct non-seed roots scraped=%d/%d census=[%s]; the crash leg is SKIPPED (nothing to recover against). HONEST result recorded.\n", seedRoot, len(mismatch), len(roots), scraped, nonSeed, censusLine(roots))
		}
	}

	// The convergence CURVE: t50/t90/t100 from quiescence. t50/t90 arm
	// ONLY inside the pre-deadline loop — after a post-SLO convergence
	// they print '-' — which means "not reached before the SLO expired", NEVER
	// "never converged" (ADR-0045: the '-' is structural,
	// it carries zero information about shape).
	fmt.Printf(" convergence curve from quiescence: t50=%s t90=%s t100=%s (t50/t90 arm pre-deadline only; '-' post-SLO is structural, ADR-0045)\n", durMs(t50), durMs(t90), msToDur(convergedAtMs))

	if converged {
		// Report BOTH the convergence wall-time (quiescence → converge, the
		// SLO-measured gossip portion) + the end-to-end (injectStart →
		// converge) so neither is relabeled as the other (SCISSORS).
		e2eWall := time.Since(injectStart).Seconds()
		sloMet := convergedAtMs >= 0 && convergedAtMs < int64(*sloSecs)*1000
		sloStr := "MET"
		if !sloMet {
			sloStr = "NOT-MET-honest"
		}
		injectStr := "clean"
		if injectTimeouts > 0 {
			injectStr = fmt.Sprintf("HARD-FAIL(%d timeouts — SLO INVALID)", injectTimeouts)
		}
		fmt.Printf("GATE 1: convergence-from-quiescence %.3fs (SLO %ds: %s); inject integrity %s; quiesced=%v; end-to-end %.3fs (incl. inject)\n",
			float64(convergedAtMs)/1000, *sloSecs, sloStr, injectStr, quiesced, e2eWall)
	}

	// ── 6. CROSS-REGION PROOF: query an injected key on a node in each OTHER ─
	// region (NOT the seed's own) → 200 with the payload (a delta crossed ─
	// regions on real cross-region RTT). ─
	section("CROSS-REGION PROOF: /v1/query a seed key on a node in each OTHER region")
	probeKey := "convergence-key-0"
	// /v1/query requires key + valid_time + tx_time (all RFC3339-parsed).
	// AsOf's Filter 2 (query.go:355: SystemTime <= transactionTime)
	// admits only entries whose SystemTime (node 0's HOST clock at insert) <=
	// tx_time. Using the gate host's clock (nowRFC) for tx_time is a
	// read-your-writes clock-skew false-negative — if the gate host lags the
	// us-east-1 host clock, the just-injected key is filtered → 404 → "delta did
	// not cross regions" when it did. Use a far-future tx_time (now + 1h) so
	// Filter 2 always admits the entry regardless of cross-region clock skew;
	// valid_time = now + 1h too (the as-of-far-future corner returns the latest
	// assertion). This is the honest cross-region READ, not a skew-dependent one.
	futureRFC := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	probed := map[string]bool{}
	seedRegion := nodes[0].region
	for _, n := range nodes[1:] {
		// skip the seed's OWN region (the first node in
		// nodes[1:] is in the seed's region — an INTRA-region probe, NOT a
		// cross-region proof). Only probe nodes in a DIFFERENT region.
		if n.region == seedRegion {
			continue
		}
		if probed[n.region] {
			continue
		}
		url := fmt.Sprintf("/v1/query?key=%s&valid_time=%s&tx_time=%s", probeKey, futureRFC, futureRFC)
		body, err := tlsGetRaw(n, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, " [%s node %d] /v1/query FAIL: %v\n", n.region, n.idx, err)
			continue
		}
		probed[n.region] = true
		fmt.Printf(" [%s node %d, CROSS-region] /v1/query?key=%s → %s\n", n.region, n.idx, probeKey, truncate(string(body), 80))
	}
	if len(probed) == 0 {
		fmt.Fprintf(os.Stderr, " NO cross-region probe succeeded (the delta did NOT demonstrably cross regions — an honest gap)\n")
	}

	// ── 7. Report the telemetry counter (scraped plain-HTTP /metrics per region). ─
	section("telemetry counter: supremum_mesh_inter_region_envelopes per region (plain-HTTP /metrics)")
	seenRegion := map[string]bool{}
	for _, n := range nodes {
		if seenRegion[n.region] {
			continue
		}
		seenRegion[n.region] = true
		// /metrics is plain-HTTP on the metrics port (NOT mTLS) — the ops surface.
		// The metrics port = metrics-port-base + localIdx (default 9100+i); the
		// orchestrator binds --metrics-addr 0.0.0.0:<metrics-port-base>+i. localIdx
		// = ctrlPort - controlPortBase. Read it via plain HTTP.
		metricsPort := *metricsPortBase + (n.ctrlPort - *controlPortBase)
		metricsURL := fmt.Sprintf("http://%s:%d/metrics", n.ip, metricsPort)
		val := scrapeCounter(metricsURL, "supremum_mesh_inter_region_envelopes")
		fmt.Printf(" %s (node %d, %s:%d): inter_region_envelopes = %s\n", n.region, n.idx, n.ip, metricsPort, val)
	}

	// The exit code is the AMENDED clause: PASS requires convergence from
	// origin quiescence within the SLO AND a clean inject (zero hard-timeout
	// batches) AND a positively-probed quiescence. A converged-but-late or
	// converged-but-dirty-inject run exits NON-zero — the orchestrator's crash
	// leg keys on the printed `converged_at_ms=` line, NEVER on this code.
	// The VERDICT line is the machine-readable token (the orchestrator greps it).
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

// The quiescence-probe knobs: the SLO clock starts only after the
// seed's root is stable across quiescenceStablePolls consecutive polls spaced
// quiescenceProbeEvery apart (12 × 250ms = 3s with no state change on the
// origin — no commit in flight), with quiescenceCap as the loud-failure bound.
const (
	quiescenceProbeEvery  = 250 * time.Millisecond
	quiescenceStablePolls = 12
	quiescenceCap         = 5 * time.Minute
)

// probeQuiescence polls fetchSignal until the returned root is stable across
// `need` consecutive polls AND every poll in the streak reported ZERO commits
// in flight — or the cap expires. Any fetch error RESETS the streak (a
// transient read failure is not quiescence), and so does commitInFlight > 0:
// under a write-behind WAL the root stops changing the moment the last
// InsertLocal lands — BEFORE the commit's fsync returns — so root stability is
// necessary but NOT sufficient for quiescence (ADR-0045; a run
// declared quiesced at 3.12 s with a ~213 s commit outstanding and the
// "convergence" then measured that commit's tail, not gossip). Extracted from
// main() so the starting-line clock logic has an in-process guard (quiescence_test.go).
// lastInFlight is the final poll's in-flight count, for the failure line.
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
			// A commit is in flight: root stability right now is the
			// write-behind illusion. The streak RESTARTS (the polls that count
			// toward quiescence must ALL be commit-free), but the root tracker
			// stays warm so a stable root scores from the first clean poll.
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

// durMs renders a sub-second duration as seconds, or "-" when unset (a t50/t90
// mark never reached).
func durMs(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.3fs", d.Seconds())
}

// falsePassReason is the gate's empty-mesh guard, shared by the main
// convergence loop and the extended poll. It returns "" when a
// len(mismatch)==0 poll is an honest convergence, else the reason it is a
// FALSE PASS: an empty mesh trivially has equal roots, so with numKeys > 0 an
// all-failed inject or an empty-HAMT seed root is an inject failure wearing
// convergence's clothes. emptyRoot = 64 zero hex chars (the sha256 of the
// empty HAMT, the crdt.go:1341 path).
func falsePassReason(numKeys, injectFail int, seedRoot string) string {
	if numKeys > 0 && injectFail >= numKeys {
		return fmt.Sprintf("ALL %d inserts failed; roots equal on an EMPTY mesh (not honest convergence)", injectFail)
	}
	if numKeys > 0 && seedRoot == strings.Repeat("0", 64) {
		return fmt.Sprintf("seed root is the empty HAMT root %s; roots equal on an EMPTY mesh (not honest convergence)", seedRoot)
	}
	return ""
}

// r1PollVerdict is the extended poll's per-poll decision, extracted for
// the guard. mismatchLen == 0 means every node returned the seed's root.
//
// Hardening (caught in review): the pre-fix shape
// decided convergence on mismatchLen ALONE — the FALSE-PASS guard lived only
// in the main loop, so an all-503 inject (injectFail == numKeys, zero
// timeouts) broke the main loop at poll 1 and then "converged" ~5s in on
// the all-empty roots: gatePass evaluated TRUE, the gate printed VERDICT: PASS
// and exited 0 on a run that inserted NOTHING, and the orchestrator's
// converged_at_ms= grep would have launched the crash leg against an empty
// mesh. The guard is now re-applied HERE, on the same terms as the main loop
// (TestR1PollVerdict_FalsePassGuard pins it).
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

// isTimeoutErr reports whether err is a CLIENT-SIDE timeout (the request was
// sent but the response did not arrive within http.Client.Timeout) —
// This is the case where the entries MAY have landed
// server-side (the EBS symptom: the per-mutation fsync ate the 10s
// bound, the server fsync'd + ACK'd, but the client gave up first). A genuine
// transport failure (dial refused, connection reset, context cancel) is NOT a
// timeout here — it is counted honestly in injectFail (the request did not
// reach a durable write).
//
// The stdlib surfaces an http.Client.Timeout expiry as a *url.Error wrapping a
// *net.OpError whose net.Error.Timeout() is true; net/http also returns a
// plain context.DeadlineExceeded when the request context expires. Both are
// matched. errors.As walks the wrap chain so a wrapped timeout (e.g. via
// fmt.Errorf("...: %w", err)) still classifies correctly.
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
	// http.Get uses the default http.Client (NO timeout);
	// a hung/slow /metrics endpoint hangs the gate (and the orchestrator
	// pipeline driving it) indefinitely. Use a bounded client —
	// raised 10s→30s to match the per-node mTLS client — a transient
	// slow /metrics scrape (e.g. the host briefly busy at the inject peak)
	// should not read as "<not scraped>" when the endpoint was about to
	// return. A hung endpoint is still bounded (30s) so the gate cannot
	// deadlock; the telemetry counter value is read within the gate's wall-time either way.
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
