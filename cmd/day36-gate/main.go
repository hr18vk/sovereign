// Command day36-gate is the mTLS SDK client that drives the Day-36 100-node
// 3-region silicon convergence gate. It is the PRODUCTION-faithful gate: it
// talks to the sovereign-node control port (the JSON-over-mTLS surface) the
// SAME way an operator SDK would — NOT a scraped counter, NOT a test harness.
//
// WHAT IT DOES (the gate, end-to-end):
//  1. Loads the shared CA + the client leaf (minted by cmd/day36-bootstrap).
//  2. Builds ONE mTLS http.Client (TLS 1.3, RequireAndVerify via the shared CA).
//  3. Reads the manifest (100 node control addrs = public-ip:control-port).
//  4. GATE 0 (boot-liveness): GET /livecheck on every node; all-100 up.
//  5. INJECT: POST /v1/insert 10K keys into node 0 (the seed node). The SLO
//     clock starts at the FIRST insert.
//  6. GATE 1 (convergence): poll GET /v1/merkle on all-100 until every node's
//     root_hex EQUALS the seed node's root (the live MerkleRoot oracle — the
//     SAME source the loopback harness's MerkleRoots() reads). The wall-time
//     from inject-start to all-100-roots-equal is the convergence SLO.
//  7. CROSS-REGION PROOF: GET /v1/query on a node in EACH of the other 2
//     regions for an injected key → 200 with the payload (a delta crossed
//     regions on real cross-region RTT).
//
// The orchestrator (day36_orchestrator.sh) drives the PARTITION gate around
// this client: it runs day36-gate for GATE 0/1/cross-region, then injects an
// iptables partition, re-runs the merkle poll to prove ISOLATION (roots
// diverge), heals (iptables -F), and re-polls for re-convergence (rounds).
//
// WHY mTLS, not plain curl: the control port is tls.Listen with
// RequireAndVerifyClientCert (control.go startControlPort) — a no-cert dial is
// a hard TLS error. The gate MUST present the client leaf. Plain-HTTP curl
// (the orchestrator's prior stub) could NEVER reach /v1/insert or /v1/merkle.
//
// USAGE (run on the executor; dials the 100 public control ports):
//
//	day36-gate -bootstrap <dir> -keys 10000 -slo-secs 120
//
// <dir> is the cmd/day36-bootstrap -out-dir (holds client/, ca.pem, manifest).
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
// empty-root false-pass guard (main.go ~ :310) catches a systematic inject
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
}

func main() {
	bootstrapDir := flag.String("bootstrap", "", "the cmd/day36-bootstrap -out-dir (holds client/, ca.pem, manifest)")
	numKeys := flag.Int("keys", 10000, "number of keys to inject into node 0")
	sloSecs := flag.Int("slo-secs", 120, "the convergence SLO cap (seconds)")
	controlPortBase := flag.Int("control-port-base", 8443, "the control port base; node i binds base + (per-region local index)")
	splitCSV := flag.String("split", "34,33,33", "per-region node counts (must match the bootstrap)")
	requireN := flag.Int("require-n", 100, "the expected node count (100 for the silicon gate; 3 for a local smoke test)")
	metricsPortBase := flag.Int("metrics-port-base", 9100, "the metrics port base (the plain-HTTP /metrics ops surface); node i binds metrics-port-base + localIdx")
	merkleOnly := flag.Bool("merkle-only", false, "fetch + print each node's /v1/merkle root (one per region) then exit — the orchestrator's GATE 3 isolation probe uses this to compare node 0's root vs a eu node's root DURING the partition (roots DIVERGE = isolated); skips the inject + GATE 1 poll")
	flag.Parse()
	if *bootstrapDir == "" {
		fmt.Fprintln(os.Stderr, "day36-gate: -bootstrap is required")
		os.Exit(2)
	}

	// ── 1. Load the CA + the client leaf. ──
	caPEM, err := os.ReadFile(*bootstrapDir + "/ca.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "day36-gate: read ca.pem: %v\n", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "day36-gate: CA PEM did not append to the pool")
		os.Exit(1)
	}
	clientCert, err := tls.LoadX509KeyPair(*bootstrapDir+"/client/cert.pem", *bootstrapDir+"/client/key.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "day36-gate: load client keypair: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "day36-gate: read manifest: %v\n", err)
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
		// region. The reviewer's #13: deriving localIdx from the line-scan index
		// `i` desyncs every subsequent node's port if a blank/malformed line
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
			// Day 38 ADR-0043: raised 10s→30s. The per-node client's Timeout
			// bounds EVERY mTLS dial (the inject POST, the /livecheck, the
			// /v1/merkle poll). It is NOT the convergence SLO (convStart is
			// measured separately, AFTER the inject). The 10s prior bound
			// EQUALED the 10s SLO gate — so a slow-but-succeeding batch POST
			// (EBS fsync ~3s/batch on Day 37) hit the client timeout = the
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
		fmt.Fprintf(os.Stderr, "day36-gate: manifest has %d nodes, want %d (-require-n)\n", len(nodes), *requireN)
		os.Exit(1)
	}
	fmt.Printf("day36-gate: loaded %d nodes (control port base %d, split %s)\n", len(nodes), *controlPortBase, *splitCSV)

	// ── 2b. -merkle-only: fetch + print each node's /v1/merkle root (one per
	//       region) then exit. The orchestrator's GATE 3 isolation probe polls
	//       node 0's root vs a eu node's root DURING the partition (roots
	//       DIVERGE = isolated; roots EQUAL = the partition leaked). This skips
	//       the inject + GATE 1 poll (a probe, NOT the convergence gate). ──
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
		fmt.Fprintf(os.Stderr, "day36-gate: GATE 0 FAIL — %d/%d nodes not live (boot-liveness gate not met)\n", liveFail, len(nodes))
		os.Exit(1)
	}
	fmt.Printf("  all %d nodes /livecheck OK in %.2fs\n", len(nodes), time.Since(liveStart).Seconds())

	// ── 4. INJECT 10K keys into node 0 (the seed) via /v1/batch-insert. ──
	// Day 37 (ADR-0042): switched from 10K serial /v1/insert POSTs (one RTT
	// per key over cross-region WAN = minutes, the GATE 1 (B) root cause) to
	// chunked /v1/batch-insert POSTs (batchSize keys per POST). Node 0 is in
	// us-east-1, the executor dials us-east-1 → the inject is INTRA-region (NO
	// cross-region WAN RTT in the inject phase); the GOSSIP then carries the
	// deltas across regions = the actual gate subject. A 1-key run (the
	// orchestrator's GATE 3 partition-probe at -keys 1) sends ONE 1-item batch
	// (degenerate but correct). Key shape `day36-key-%d` / val `%010d` is
	// byte-identical to the serial loop (key index 0 is in the FIRST batch —
	// the cross-region proof probe greps `day36-key-0`).
	//
	// Day 39 (ADR-0044) — the ONE-fsync-per-batch switch. The Day-37/38 gate
	// binary chunked 10K keys into 10 batches of 1000 (batchSize=1000); each
	// batch hit the server's /v1/batch-insert which looped InsertLocalEvents
	// PER ENTRY → AppendMutation PER ENTRY → ONE fsync PER ENTRY = 1000 fsyncs
	// per batch × 10 batches = 10000 fsyncs total. At the Day-38 silicon-measured
	// ~2.1ms/fsync (NVMe), that is ~21s of inject fsync-time ALONE > the 10s
	// GATE-1 SLO (the root cause Day 36/37/38 traced: the binding constraint is
	// the fsync COUNT, not the fsync latency). Day 39 collapses the count: set
	// batchSize = numKeys so the loop runs ONCE → ONE /v1/batch-insert POST →
	// the server's handleBatchInsert routes through InsertLocalEventsBatch →
	// Bridge.PutLocals → WAL.AppendMutations (ONE write-loop + ONE fsync for
	// the WHOLE 10K). The 10K keys now pay ONE ~2.1ms fsync + the cross-AZ
	// HTTP RTT (~50-150ms) = a sub-second inject, well inside the 10s SLO.
	//
	// The loop structure is UNCHANGED (the `for start := 0; start < *numKeys;
	// start += batchSize` runs exactly once when batchSize >= numKeys); only
	// the batchSize constant is replaced with numKeys so a 1-key probe run
	// (-keys 1) still sends ONE 1-item batch (degenerate but correct). The
	// per-entry status accounting (the br.Items loop below) is UNCHANGED — a
	// single 10K-item batch returns 10K per-entry statuses the SAME way 10
	// 1K-batches did; the per-batch 503 semantic (ADR-0044 §4) means a Sync
	// failure reports ALL 10000 as 503 (a wholesale injectFail+=10000 the
	// convergence poll + WAL stat then verify, NOT a per-entry lie).
	batchSize := *numKeys // Day 39 ADR-0044: ONE batch → ONE fsync (the 10000× fsync-COUNT cut; was const 1000 = 10 batches)
	if batchSize < 1 {
		batchSize = 1 // a 0-key run (the post-heal re-convergence probe at -keys 0) sends an empty batch — guard against an empty-loop edge
	}
	section(fmt.Sprintf("INJECT: %d keys into node 0 (%s %s) via /v1/batch-insert (ONE batch, ONE fsync — Day 39 ADR-0044)", *numKeys, nodes[0].region, nodes[0].controlAddr))
	injectStart := time.Now()
	seed := nodes[0]
	injectFail := 0
	batchTimedOut := false // Day 38 ADR-0043 (FIX 5): a batch POST hit the client Timeout — the entries may have landed (deferred to the convergence poll + WAL stat); NOT counted in injectFail.
	for start := 0; start < *numKeys; start += batchSize {
		end := start + batchSize
		if end > *numKeys {
			end = *numKeys
		}
		items := make([]insertReq, 0, end-start)
		for k := start; k < end; k++ {
			items = append(items, insertReq{
				Key: fmt.Sprintf("day36-key-%d", k),
				Val: fmt.Sprintf("%010d", k),
			})
		}
		body, _ := json.Marshal(struct {
			Items []insertReq `json:"items"`
		}{Items: items})
		batchBody, err := tlsPost(seed, "/v1/batch-insert", body)
		if err != nil {
			// Day 38 ADR-0043 (FIX 5): the injectFail honesty fix. A tlsPost
			// error covers THREE distinct failure modes that the prior code
			// conflated into one "injectFail += end-start":
			//
			//  (A) a CLIENT TIMEOUT (the http.Client.Timeout was exceeded — the
			//      Day-37 EBS symptom: the per-mutation fsync ate the 10s bound,
			//      the response was dropped, but the entries LANDED server-side
			//      + were fsync'd; the seed root was non-empty + key-0 crossed
			//      regions in Day-37 silicon). Counting these as 1000 failures
			//      was a GATE LIE — it equated "the HTTP response did not return
			//      in time" with "the write failed". The correct verdict is
			//      DEFERRED: the convergence poll (all roots equal) + the empty-
			//      root false-pass guard (below) + the orchestrator's WAL-file
			//      stat (CHECK B) VERIFY whether the entries actually landed. So
			//      a timeout does NOT add to injectFail; it sets batchTimedOut +
			//      logs the honest "entries may have landed" message.
			//  (B) a genuine transport/HTTP error (a dial failure, a 5xx at the
			//      HTTP layer — the request NEVER reached a durable write). The
			//      entries did NOT land; counting them in injectFail is HONEST
			//      (the empty-root guard then catches a systematic failure).
			//  (C) a context-canceled / connection-reset mid-stream — treat as
			//      (B), a genuine failure (we cannot confirm any entry landed).
			//
			// The split: if the error is a net.Timeout / url.Timeout (case A)
			// → do NOT add to injectFail (defer to the convergence + WAL
			// verification). Otherwise (case B/C) → count honestly as before.
			// This is STRICTLY MORE HONEST than the prompt's literal "on a
			// timeout/error: do NOT add" grouping — a dial failure is NOT
			// "entries may have landed" (the request never reached the server),
			// and counting it as a timeout would under-report a real failure.
			if isTimeoutErr(err) {
				batchTimedOut = true
				fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] HTTP TIMEOUT: %v (entries may have landed — the convergence poll + WAL stat will verify; NOT counted in injectFail)\n", start, end-1, err)
				continue
			}
			injectFail += end - start
			fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] FAIL (transport/HTTP, entries did NOT land): %v\n", start, end-1, err)
			continue
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
			injectFail += end - start
			fmt.Fprintf(os.Stderr, "  [inject batch %d-%d] decode FAIL: %v\n", start, end-1, err)
			continue
		}
		for _, st := range br.Items {
			if st.Code != 200 {
				injectFail++
			}
		}
		fmt.Printf("  injected %d/%d keys (%.1fs, %d failures)\n", end, *numKeys, time.Since(injectStart).Seconds(), injectFail)
	}
	fmt.Printf("  injected %d keys in %.2fs (%d failures", *numKeys, time.Since(injectStart).Seconds(), injectFail)
	if batchTimedOut {
		fmt.Printf("; ≥1 batch HTTP TIMEOUT — entries may have landed, verified by the convergence poll + the WAL-file stat")
	}
	fmt.Println(")")

	// ── 5. GATE 1: poll all-100 /v1/merkle until roots equal (the SLO). ──
	// The SLO clock starts AFTER the inject (the reviewer's #5): the gate
	// measures GOSSIP convergence (the actual subject), NOT the serial WAN
	// inject duration (a harness-config artifact — 10K × ~50-150ms RTT). The
	// inject wall-time is reported separately above so neither number is
	// relabeled as the other (the SCISSORS discipline). The end-to-end time
	// (injectStart → converge) is ALSO reported so the operator sees both.
	section(fmt.Sprintf("GATE 1: poll /v1/merkle on all %d until roots equal (SLO %ds)", len(nodes), *sloSecs))
	convStart := time.Now()
	deadline := convStart.Add(time.Duration(*sloSecs) * time.Second)
	var seedRoot string
	converged := false
	rounds := 0
	for time.Now().Before(deadline) {
		rounds++
		// Read the seed node's root first (the target).
		sr, err := tlsGetJSON[merkleResp](seed, "/v1/merkle")
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [poll %d] seed /v1/merkle FAIL: %v\n", rounds, err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		seedRoot = sr.RootHex
		// Concurrent poll of the other 99.
		var mu sync.Mutex
		var mismatch []int
		var wg sync.WaitGroup
		for i := 1; i < len(nodes); i++ {
			wg.Add(1)
			go func(n node) {
				defer wg.Done()
				r, err := tlsGetJSON[merkleResp](n, "/v1/merkle")
				if err != nil {
					mu.Lock()
					mismatch = append(mismatch, n.idx)
					mu.Unlock()
					return
				}
				if r.RootHex != seedRoot {
					mu.Lock()
					mismatch = append(mismatch, n.idx)
					mu.Unlock()
				}
			}(nodes[i])
		}
		wg.Wait()
		if len(mismatch) == 0 {
			// The empty-root guard (the reviewer's #6): if every insert failed
			// OR the seed root is the zero/empty HAMT root, this "convergence"
			// is a FALSE PASS — an empty mesh trivially has equal roots.
			// The loopback test's day36EmptyRoot check guards this; the gate
			// must too. day36EmptyRoot = 64 zero bytes hex (sha256 of the
			// empty HAMT, the crdt.go:1341 path). A non-empty inject + a
			// non-empty root is the honest convergence.
			emptyRoot := strings.Repeat("0", 64)
			if *numKeys > 0 && injectFail >= *numKeys {
				fmt.Fprintf(os.Stderr, "day36-gate: GATE 1 — FALSE-PASS guard: ALL %d inserts failed; roots equal on an EMPTY mesh (not honest convergence). HONEST result recorded.\n", injectFail)
				break
			}
			if *numKeys > 0 && seedRoot == emptyRoot {
				fmt.Fprintf(os.Stderr, "day36-gate: GATE 1 — FALSE-PASS guard: seed root is the empty HAMT root %s; roots equal on an EMPTY mesh (not honest convergence). HONEST result recorded.\n", seedRoot)
				break
			}
			convMs := time.Since(convStart).Milliseconds()
			fmt.Printf("  CONVERGED in %.3fs post-inject (all 100 roots equal = %s)\n", float64(convMs)/1000, seedRoot)
			converged = true
			break
		}
		if rounds%5 == 0 {
			fmt.Printf("  poll %d: %d nodes divergent (seed root %s...)\n", rounds, len(mismatch), seedRoot[:8])
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !converged {
		fmt.Fprintf(os.Stderr, "day36-gate: GATE 1 — NOT converged within %ds (seed root %s); HONEST result recorded.\n", *sloSecs, seedRoot)
	} else {
		// Report BOTH the convergence wall-time (convStart → converge, the
		// SLO-measured gossip portion) + the end-to-end (injectStart →
		// converge) so neither is relabeled as the other (SCISSORS). The SLO
		// is enforced on the convergence portion.
		convWall := time.Since(convStart).Seconds()
		e2eWall := time.Since(injectStart).Seconds()
		sloMet := convWall < float64(*sloSecs)
		sloStr := "MET"
		if !sloMet {
			sloStr = "NOT-MET-honest"
		}
		fmt.Printf("GATE 1: PASS — convergence wall-time %.3fs (SLO %ds: %s); end-to-end %.3fs (incl. inject)\n", convWall, *sloSecs, sloStr, e2eWall)
	}

	// ── 6. CROSS-REGION PROOF: query an injected key on a node in each OTHER ─
	//        region (NOT the seed's own) → 200 with the payload (a delta crossed ─
	//        regions on real cross-region RTT). ─
	section("CROSS-REGION PROOF: /v1/query a seed key on a node in each OTHER region")
	probeKey := "day36-key-0"
	// /v1/query requires key + valid_time + tx_time (all RFC3339-parsed). The
	// reviewer's #12: AsOf's Filter 2 (query.go:355: SystemTime <= transactionTime)
	// admits only entries whose SystemTime (node 0's HOST clock at insert) <=
	// tx_time. Using the EXECUTOR's clock (nowRFC) for tx_time is a
	// read-your-writes clock-skew false-negative — if the executor lags the
	// us-east-1 host clock, the just-injected key is filtered → 404 → "delta did
	// not cross regions" when it did. Use a far-future tx_time (now + 1h) so
	// Filter 2 always admits the entry regardless of cross-region clock skew;
	// valid_time = now + 1h too (the as-of-far-future corner returns the latest
	// assertion). This is the honest cross-region READ, not a skew-dependent one.
	futureRFC := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	probed := map[string]bool{}
	seedRegion := nodes[0].region
	for _, n := range nodes[1:] {
		// The reviewer's #11: skip the seed's OWN region (the first node in
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
			fmt.Fprintf(os.Stderr, "  [%s node %d] /v1/query FAIL: %v\n", n.region, n.idx, err)
			continue
		}
		probed[n.region] = true
		fmt.Printf("  [%s node %d, CROSS-region] /v1/query?key=%s → %s\n", n.region, n.idx, probeKey, truncate(string(body), 80))
	}
	if len(probed) == 0 {
		fmt.Fprintf(os.Stderr, "  NO cross-region probe succeeded (the delta did NOT demonstrably cross regions — an honest gap)\n")
	}

	// ── 7. Report the SSoT counter (scraped plain-HTTP /metrics per region). ─
	section("24th SSoT: supremum_mesh_inter_region_envelopes per region (plain-HTTP /metrics)")
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
		fmt.Printf("  %s (node %d, %s:%d): inter_region_envelopes = %s\n", n.region, n.idx, n.ip, metricsPort, val)
	}

	if !converged {
		os.Exit(1)
	}
	fmt.Println("day36-gate: DONE")
}

// ── helpers ─────────────────────────────────────────────────────────────────

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
// sent but the response did not arrive within http.Client.Timeout) — Day 38
// ADR-0043 (FIX 5). This is the case where the entries MAY have landed
// server-side (the Day-37 EBS symptom: the per-mutation fsync ate the 10s
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
	// The reviewer's #10: http.Get uses the default http.Client (NO timeout);
	// a hung/slow /metrics endpoint hangs the gate (and the orchestrator
	// pipeline driving it) indefinitely. Use a bounded client. Day 38 ADR-0043
	// (FIX 5): raised 10s→30s to match the per-node mTLS client — a transient
	// slow /metrics scrape (e.g. the host briefly busy at the inject peak)
	// should not read as "<not scraped>" when the endpoint was about to
	// return. A hung endpoint is still bounded (30s) so the gate cannot
	// deadlock; the SSoT value is read within the gate's wall-time either way.
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
