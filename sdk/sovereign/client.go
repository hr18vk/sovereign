// Package sovereign is the client library for the Sovereign Engine control
// port. A developer who has NEVER read the engine internals connects to a
// running mesh over mutual TLS and performs a state operation in under 50
// lines of Go (see examples/sdk/main.go).
//
// THE HONEST READ-PATH BOUNDARY (ADR-0011 §1.1, §5 — encode it, do NOT hide it):
//
//	The engine stores ONLY the PayloadDigest on a joined CRDTEntry (Ruling 3 —
//	the payload is discarded after the integrity cross-check to keep the
//	on-disk footprint at the digest, not 10x the value). The original value
//	survives ONLY on the originator node's payload cache (the node that
//	InsertLocalEvents-ed it). A peer that received the delta via gossip has
//	the digest, NOT the value.
//
//	Get returns a GetResult that makes the boundary VISIBLE:
//	  - On the ORIGINATOR node, Payload is the cached string (a cache hit).
//	  - On a PEER node, Payload is "" and PayloadDigest carries the digest the
//	    value was hashed to before Ruling-3 discard.
//	A Get that reports the digest hex as if it were the value is a
//	FABRICATION; this library reports both paths honestly.
//
// The control port is a LOW-RATE manageability surface (1 op/sec to ~1K
// ops/sec). InsertLocal returns at LOCAL-apply; peer convergence is EVENTUAL
// (the next gossip sweep ships the delta). This library does NOT claim
// linearizability — the doc says so (ADR-0011 §6).
package sovereign

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client is a connection to a Sovereign Engine control port. It holds an
// *http.Client whose transport enforces TLS 1.3 ONLY (Min==Max==1.3) and
// presents the caller's client certificate (mTLS — the SAME trust root as the
// peer path, ADR-0006). Use Dial to construct one; Close releases it.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// GetResult is the typed result of Get. The Payload field is NON-EMPTY only on
// the originator node (the cache hit); on a peer it is "" and PayloadDigest
// carries the digest the value was hashed to before Ruling-3 discard. Both are
// honest results this struct reports WITHOUT faking a value.
type GetResult struct {
	EntityID      string
	Present       bool
	Payload       string // NON-EMPTY only on the originator node (Ruling-3)
	PayloadDigest string // hex; ALWAYS present when Present=true
	DotNodeID     string // hex
	DotCounter    uint64
	OriginNodeID  string // hex
}

// NodeStatus is the typed result of Status (the /livecheck body).
type NodeStatus struct {
	NodeID     string
	Peers      []string
	TLSVersion string
}

// MetricSample is ONE scraped Prometheus series: a metric name, its label set,
// and its scalar value. Metrics() returns the FULL set so a CounterVec (e.g.
// sovereign_ingest_verdicts_total{verdict=...}) does not collapse to one
// last-wins scalar. The old MetricsSnapshot map[string]float64 keyed by name
// only and DROPPED the labels, so a six-value CounterVec collapsed to one value
// (silent data loss in the SDK's own metrics reader); MetricSample preserves
// the label dimension so every series survives.
type MetricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// MetricSamples is the typed result of Metrics — the full set of scraped
// sovereign_* series, one MetricSample per "name{labels} value" line. The
// Value and Samples accessors give a caller the old scalar behavior EXPLICITLY
// (Value returns the sole sample for a name, or 0/false when there are zero or
// multiple — it never silently last-wins; a caller reading a CounterVec MUST
// use Samples).
type MetricSamples []MetricSample

// Value returns the scalar value of the SOLE sample matching name, or (0,
// false) when there are zero or multiple samples. A caller who wants the old
// per-name scalar gets it explicitly here; a CounterVec (multiple samples per
// name) returns false so the caller is forced to Samples — the silent
// last-wins collapse the old map performed is gone.
func (s MetricSamples) Value(name string) (float64, bool) {
	var v float64
	n := 0
	for _, m := range s {
		if m.Name == name {
			v = m.Value
			n++
		}
	}
	if n != 1 {
		return 0, false
	}
	return v, true
}

// Samples returns all samples whose Name matches. Use it to read a CounterVec
// (e.g. sovereign_ingest_verdicts_total) label-by-label; every series survives.
func (s MetricSamples) Samples(name string) MetricSamples {
	var out MetricSamples
	for _, m := range s {
		if m.Name == name {
			out = append(out, m)
		}
	}
	return out
}

// Dial opens a TLS 1.3 connection to the control port at addr (host:port). The
// caller's tlsCfg carries a client certificate signed by the mesh CA (the SAME
// trust root as the peer path, ADR-0006). Dial forces Min==Max==VersionTLS13 so
// a <1.3 negotiation is a hard failure — a 1.2 path is impossible. A tlsCfg
// with no client cert fails the server's RequireAndVerifyClientCert gate at the
// first request (the mTLS tooth, G06.b).
func Dial(addr string, tlsCfg *tls.Config) (*Client, error) {
	// Clone so the caller's config is not mutated, then force 1.3-only.
	cfg := tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	tr := &http.Transport{
		ForceAttemptHTTP2:     false, // the control port is HTTP/1.1 over TLS 1.3
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		baseURL:    "https://" + addr,
	}, nil
}

// DialWithCerts is the convenience constructor for the common case: the caller
// has on-disk PEM paths for a client cert (signed by the mesh CA), the client
// key, and the CA (the trust root), plus the serverName to verify the node's
// leaf against (the leaf CommonName is the node's hex nodeID, or "localhost"
// for a dev mesh). It loads the keypair + CA pool, builds the mTLS client
// config, and calls Dial. It is the one-liner a <50-line example uses so the
// cert-loading boilerplate lives in the SDK, not the caller (ADR-0011 §8 — the
// <50-line knob is the SDK's job, not the example's).
func DialWithCerts(addr, certPath, keyPath, caPath, serverName string) (*Client, error) {
	leaf, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("sovereign: load client keypair: %w", err)
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("sovereign: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("sovereign: no CA certs parsed from %s", caPath)
	}
	return Dial(addr, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		RootCAs:      pool,
		ServerName:   serverName,
	})
}

// InsertLocal stages a key/value pair on the node. It POSTs /v1/insert, which
// routes through Gossiper.InsertLocalEvents (gossip.go:202) — NEVER
// engine.InsertLocal — so the payload is cached for a future gossip sweep. It
// returns the hex of the CausalDot (NodeID||Counter) the engine assigned: the
// receipt the caller uses to prove the insert landed locally.
//
// HONEST: the insert is LOCAL-ONLY at return. Peer convergence is EVENTUAL —
// the next gossip sweep ships the delta. This method does NOT wait for peers.
func (c *Client) InsertLocal(key, val string) (dotHex string, err error) {
	body := struct {
		Key string `json:"key"`
		Val string `json:"val"`
	}{Key: key, Val: val}
	resp, err := c.post("/v1/insert", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		DotHex string `json:"dot_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("sovereign: decode insert response: %w", err)
	}
	return out.DotHex, nil
}

// Get reads the latest entry for key. The returned GetResult reports the
// originator-vs-peer payload boundary HONESTLY (ADR-0011 §1.1): on the
// originator Payload is the cached string; on a peer Payload is "" and
// PayloadDigest carries the digest. A Get that returns the digest as if it
// were the value is a fabrication this method does not commit.
func (c *Client) Get(key string) (GetResult, error) {
	resp, err := c.get("/v1/get?key=" + key)
	if err != nil {
		return GetResult{}, err
	}
	defer resp.Body.Close()
	var raw struct {
		EntityID      string `json:"entity_id"`
		Present       bool   `json:"present"`
		Payload       string `json:"payload"`
		PayloadDigest string `json:"payload_digest"`
		DotNodeID     string `json:"dot_node_id"`
		DotCounter    uint64 `json:"dot_counter"`
		OriginNodeID  string `json:"origin_node_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return GetResult{}, fmt.Errorf("sovereign: decode get response: %w", err)
	}
	return GetResult{
		EntityID:      raw.EntityID,
		Present:       raw.Present,
		Payload:       raw.Payload,
		PayloadDigest: raw.PayloadDigest,
		DotNodeID:     raw.DotNodeID,
		DotCounter:    raw.DotCounter,
		OriginNodeID:  raw.OriginNodeID,
	}, nil
}

// MerkleRoot returns the node's current MerkleRoot as hex. Stable across
// re-reads when the state is unchanged (CRDT idempotency).
func (c *Client) MerkleRoot() (rootHex string, err error) {
	resp, err := c.get("/v1/merkle")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		RootHex string `json:"root_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("sovereign: decode merkle response: %w", err)
	}
	return out.RootHex, nil
}

// Status returns the node's /livecheck body (nodeID, peers, TLSVersion).
func (c *Client) Status() (NodeStatus, error) {
	resp, err := c.get("/livecheck")
	if err != nil {
		return NodeStatus{}, err
	}
	defer resp.Body.Close()
	var raw struct {
		NodeID     string   `json:"node_id"`
		Peers      []string `json:"peers"`
		TLSVersion string   `json:"tls_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return NodeStatus{}, fmt.Errorf("sovereign: decode status response: %w", err)
	}
	return NodeStatus{NodeID: raw.NodeID, Peers: raw.Peers, TLSVersion: raw.TLSVersion}, nil
}

// Metrics scrapes the node's /metrics Prometheus text format and parses the
// sovereign_* series into a label-preserving MetricSamples slice (one
// MetricSample per "name{labels} value" line). The parse is a small scanner
// over the exposition lines; lines without a sovereign_ prefix, with a
// non-numeric value, or with malformed braces are skipped (HELP/TYPE/comment
// lines and bad scrapes never panic — a panic in Metrics() on a bad scrape is a
// NEW bug).
func (c *Client) Metrics() (MetricSamples, error) {
	resp, err := c.get("/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parsePrometheusText(resp.Body)
}

// Close releases the client's idle connections.
func (c *Client) Close() error {
	if c.httpClient == nil {
		return nil
	}
	c.httpClient.CloseIdleConnections()
	return nil
}

// RunDemo is the canonical demo workload the examples/sdk binary drives: insert
// 100 key/val pairs, read the MerkleRoot, then Get the first key back on the
// originator (the cache hit — Ruling 3 keeps the value on the originator). It
// lives in the SDK (not the example) so the <50-line example stays a readable
// connection shell (flag parse + dial + defer Close) while the workload logic
// is the SDK's job (ADR-0011 §8 MEDIOCRITY 1). It returns the first error so the
// example's run() can surface it through its defers (FIX D — no log.Fatal leak).
func (c *Client) RunDemo() error {
	for i := 0; i < 100; i++ {
		if _, err := c.InsertLocal(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i)); err != nil {
			return fmt.Errorf("insert %d: %w", i, err)
		}
	}
	root, err := c.MerkleRoot()
	if err != nil {
		return fmt.Errorf("merkle: %w", err)
	}
	got, err := c.Get("key-0")
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	fmt.Printf("inserted 100 keys; merkle=%s; key-0 payload=%q digest=%s\n", root, got.Payload, got.PayloadDigest)
	return nil
}

func (c *Client) get(path string) (*http.Response, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("sovereign: get %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("sovereign: get %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

func (c *Client) post(path string, body any) (*http.Response, error) {
	r, w := io.Pipe()
	go func() {
		_ = json.NewEncoder(w).Encode(body)
		w.Close()
	}()
	resp, err := c.httpClient.Post(c.baseURL+path, "application/json", r)
	if err != nil {
		return nil, fmt.Errorf("sovereign: post %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("sovereign: post %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

// parsePrometheusText parses the Prometheus text exposition format into a
// label-preserving MetricSamples slice (one MetricSample per "name{labels}
// value" line). It PRESERVES the label set so a CounterVec's N label series
// each survive as their own sample (the old map[string]float64 keyed by name
// only and kept the LAST per name — a six-value CounterVec collapsed to one
// scalar, silent data loss). Lines starting with '#' (HELP/TYPE) and
// non-sovereign lines are skipped. A line with a malformed brace group (a '{'
// with no matching '}', or a label with no '=') is skipped, never panicked on
// — a panic in Metrics() on a bad scrape is a NEW bug.
func parsePrometheusText(r io.Reader) (MetricSamples, error) {
	var out MetricSamples
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		// A sample line is "name{labels} value" or "name value". Split on the
		// LAST whitespace to separate the value from the name{labels} prefix.
		idx := strings.LastIndex(line, " ")
		if idx < 0 {
			continue
		}
		namePart := line[:idx]
		valStr := strings.TrimSpace(line[idx+1:])
		// Split the metric name from the optional {labels} group. A '{' with no
		// matching '}' is a malformed scrape line — skip it, never panic.
		name := namePart
		var labels map[string]string
		if brace := strings.IndexByte(namePart, '{'); brace >= 0 {
			close := strings.IndexByte(namePart, '}')
			if close < 0 || close < brace {
				continue // open brace with no close — malformed, skip
			}
			name = namePart[:brace]
			labelsStr := namePart[brace+1 : close]
			parsed, ok := parseMetricLabels(labelsStr)
			if !ok {
				continue // a label with no '=' — malformed, skip
			}
			labels = parsed
		}
		if !strings.HasPrefix(name, "sovereign_") {
			continue
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}
		out = append(out, MetricSample{Name: name, Labels: labels, Value: v})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("sovereign: parse metrics: %w", err)
	}
	return out, nil
}

// parseMetricLabels parses the inside of a Prometheus label group —
// `key="val",key2="val2"` — into a map. It returns ok=false (so the caller
// skips the line) when a comma-separated token has no '=' or no closing quote;
// it never panics. An empty labelsStr returns a nil map (the no-label case).
func parseMetricLabels(labelsStr string) (map[string]string, bool) {
	labelsStr = strings.TrimSpace(labelsStr)
	if labelsStr == "" {
		return nil, true
	}
	labels := make(map[string]string)
	for _, tok := range strings.Split(labelsStr, ",") {
		eq := strings.IndexByte(tok, '=')
		if eq < 0 {
			return nil, false
		}
		key := strings.TrimSpace(tok[:eq])
		valPart := strings.TrimSpace(tok[eq+1:])
		// The value is a quoted string: "val". Strip the surrounding quotes; a
		// token with no closing quote is malformed.
		if len(valPart) < 2 || valPart[0] != '"' || valPart[len(valPart)-1] != '"' {
			return nil, false
		}
		labels[key] = valPart[1 : len(valPart)-1]
	}
	return labels, true
}
