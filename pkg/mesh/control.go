// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ControlServer serves the SDK's JSON routes over mTLS, together with
// /livecheck and an optional /metrics handler. It uses a listener separate
// from the peer data plane and the plain-HTTP operations endpoint; all three
// surfaces share one trust root (ADR-0011 §3).
//
// This is a low-rate management API, intended for roughly 1 to 1,000
// operations per second. Local inserts pay for JSON decoding, the engine's
// compare-and-swap (about 36 ns on the measured 32-core apply path), and an
// AES-GCM TLS record write (about 30–50 ns). The measured 60.19 µs Ed25519
// verification belongs to gossip fan-out, not to this path. The batched binary
// data plane remains the high-throughput write path (ADR-0011 §2).
//
// Insert handlers go through the Gossiper rather than calling InsertLocal on
// the engine directly. The Gossiper records each payload for a later sweep;
// bypassing that cache would produce deltas whose payloads peers cannot
// reconstruct, and their verification would fail (ADR-0011 §4).
type ControlServer struct {
	gossiper *Gossiper
	nodeID   [16]byte
	peers    []string
	metrics  http.Handler // nil disables /metrics
	// resolver reads the persisted Arrow index. A nil resolver disables the
	// query routes with HTTP 503 so clients can distinguish an unavailable
	// query tier from a missing entity. cmd/sovereign-node sets it when
	// --lsm-root is configured (ADR-0017).
	resolver *database.Resolver
	// secondaryIndexEnabled controls registration of /v1/querybyh3 and
	// /v1/querybysystime and acceptance of nonzero h3_index fields. When
	// false, the routes are absent and h3_index is ignored. cmd/sovereign-node
	// passes the --secondary-index flag to SetSecondaryIndex.
	secondaryIndexEnabled bool
}

// NewControlServer binds a control port to a Gossiper. nodeID and peers are
// reported by /livecheck. The optional metrics handler is accepted as an
// http.Handler so this package does not import pkg/metrics.
func NewControlServer(g *Gossiper, nodeID [16]byte, peers []string, metrics http.Handler) *ControlServer {
	return &ControlServer{gossiper: g, nodeID: nodeID, peers: peers, metrics: metrics}
}

// SetResolver enables bitemporal queries over the persisted Arrow index.
// Keeping this separate from NewControlServer preserves the constructor's
// four-argument API. A nil resolver, including no call to SetResolver, makes
// the query routes return HTTP 503 (ADR-0017 §3).
func (s *ControlServer) SetResolver(r *database.Resolver) { s.resolver = r }

// SetSecondaryIndex enables the cross-entity query routes and nonzero
// h3_index request fields. Its default is false: the routes are not
// registered and h3_index is ignored.
func (s *ControlServer) SetSecondaryIndex(enabled bool) { s.secondaryIndexEnabled = enabled }

// insertRequest is the JSON body accepted by POST /v1/insert.
//
// ValidFromNs and ValidForNs let a client assert a bitemporal window. An
// all-zero CRDTEntry would have the empty interval [0, 0), which Resolver.AsOf
// rejects at every query time. Omitting the fields instead means valid from
// the write time with no asserted end (ADR-0017 §6). A supplied start and
// duration are preserved; a zero or omitted duration uses the open-end
// sentinel below. That sentinel fits int64, unlike UnixNano for year 9999.
type insertRequest struct {
	Key string `json:"key"`
	Val string `json:"val"`

	// ValidFromNs is the optional valid-time start in Unix nanoseconds. Nil
	// uses the write time.
	ValidFromNs *int64 `json:"valid_from_ns,omitempty"`
	// ValidForNs is the optional valid-time duration in nanoseconds. Nil or
	// zero selects OpenEndedValidEndNs.
	ValidForNs *int64 `json:"valid_for_ns,omitempty"`
	// H3Index is an optional H3 cell index. The pointer distinguishes an
	// omitted field from explicit zero, although both store zero, the engine's
	// no-cell value. A nonzero value is used only with the secondary index
	// enabled and must have the H3 cell mode bits. This is a syntactic check,
	// not geographic validation; the engine treats the cell as opaque.
	H3Index *uint64 `json:"h3_index,omitempty"`
}

// OpenEndedValidEndNs ends a valid-time interval for which the client
// asserted no bound. At 9e18 nanoseconds after the Unix epoch, approximately
// year 2253, it remains below math.MaxInt64. By contrast, calling UnixNano on
// database.MaxValidTime (year 9999) overflows int64 to a negative value,
// producing an interval that Resolver.AsOf cannot match. Production code
// therefore uses this sentinel rather than MaxValidTime.UnixNano.
const OpenEndedValidEndNs int64 = 9_000_000_000_000_000_000

// plausibleH3Cell checks that the mode nibble in bits [59,63) is 1, as
// required for an H3 cell. The four-bit resolution field cannot fall outside
// [0,15], so a range check on it would add no validation. Geographic validity
// is not checked: no H3 library is imported and the cell remains opaque to
// the engine.
func plausibleH3Cell(h uint64) bool { return (h>>59)&0xF == 1 }

// insertResponse is the JSON body POST /v1/insert returns. DotHex is the hex
// of the CausalDot (NodeID||Counter) the engine assigned — the receipt the
// caller uses to prove the insert landed locally.
type insertResponse struct {
	DotHex string `json:"dot_hex"`
}

// batchInsertRequest is the JSON body accepted by POST /v1/batch-insert.
// One request carries multiple insertRequest values, avoiding a separate HTTP
// round trip for each key. Entries use the same temporal stamping and empty-key
// validation as /v1/insert. The single-insert endpoint remains available.
type batchInsertRequest struct {
	Items []insertRequest `json:"items"`
}

// batchInsertItemStatus reports one entry's outcome. Code uses HTTP status
// semantics: 200 means inserted and durable with a non-empty DotHex, 400 means
// invalid input, and 503 means the batch was not durable. DotHex is empty on
// failure. Input errors are per entry; a WAL failure marks every otherwise
// valid entry 503 because the WAL batch is atomic (ADR-0044 §4).
type batchInsertItemStatus struct {
	Index  int    `json:"index"`
	Key    string `json:"key"`
	Code   int    `json:"code"`
	DotHex string `json:"dot_hex,omitempty"`
}

// batchInsertResponse is returned by POST /v1/batch-insert. Inserted counts
// durable entries and Failed combines 400 and 503 outcomes. Full success
// requires Inserted == len(Items); Failed > 0 reports a partial failure.
type batchInsertResponse struct {
	Inserted int                     `json:"inserted"`
	Failed   int                     `json:"failed"`
	Items    []batchInsertItemStatus `json:"items"`
}

// getResponse is returned by GET /v1/get and mirrors the SDK's GetResult
// (ADR-0011 §1.1). Payload is populated only when the local payload cache has
// the value, normally on its originator. Peers return an empty Payload and the
// stored PayloadDigest; the digest is never substituted for the value.
type getResponse struct {
	EntityID      string `json:"entity_id"`
	Present       bool   `json:"present"`
	Payload       string `json:"payload"`        // NON-EMPTY only on the originator
	PayloadDigest string `json:"payload_digest"` // hex; populated whenever Present=true
	DotNodeID     string `json:"dot_node_id"`    // hex
	DotCounter    uint64 `json:"dot_counter"`
	OriginNodeID  string `json:"origin_node_id"` // hex
}

// queryResponse is returned by GET /v1/query. Resolver.AsOf selects the
// dominant persisted tri-temporal event from the Arrow index, rather than
// reading current state from the live HAMT (ADR-0011 §1.1). PayloadDigestHex
// is copied from the index, whose rows carry the write path's digest and an
// empty sentinel body. There is no payload field because the index does not
// contain the value (ADR-0017 §3). Present mirrors /v1/get for the SDK.
type queryResponse struct {
	EntityID         string `json:"entity_id"`
	SystemTimeNs     int64  `json:"system_time_ns"`
	ValidTimeStartNs int64  `json:"valid_time_start_ns"`
	ValidTimeEndNs   int64  `json:"valid_time_end_ns"`
	AssertionTimeNs  int64  `json:"assertion_time_ns"`
	H3Index          uint64 `json:"h3_index"`
	PayloadDigestHex string `json:"payload_digest_hex"`
	Present          bool   `json:"present"`
}

// queryDisabledBody is the HTTP 503 response when no resolver is configured.
type queryDisabledBody struct {
	Error string `json:"error"`
}

// queryNotFoundBody is the HTTP 404 response when AsOf finds no matching event.
type queryNotFoundBody struct {
	Error  string `json:"error"`
	Entity string `json:"entity"`
}

// windowRow is one durable tri-temporal event in a /v1/range response
// (ADR-0024). Its fields mirror queryResponse, including the verbatim index
// digest and the absence of a payload body (ADR-0017 §3). Present is omitted
// because Range returns only intersecting rows; an empty result is a 404.
type windowRow struct {
	// Scalars precede strings to reduce padding. This JSON data-transfer
	// object is not a hot-path structure containing contended atomics, so the
	// 128-byte cache-line stride rule does not apply. Explicit JSON tags keep
	// the wire representation independent of field order.
	SystemTimeNs     int64  `json:"system_time_ns"`
	ValidTimeStartNs int64  `json:"valid_time_start_ns"`
	ValidTimeEndNs   int64  `json:"valid_time_end_ns"`
	AssertionTimeNs  int64  `json:"assertion_time_ns"`
	H3Index          uint64 `json:"h3_index"`
	EntityID         string `json:"entity_id"`
	PayloadDigestHex string `json:"payload_digest_hex"`
}

// rangeResponse is returned by GET /v1/range (ADR-0024). Rows are sorted by
// validTimeStart and include durable events whose valid-time intervals overlap
// [vLo, vHi) and whose SystemTime is at most tx_time. Truncated reports that
// MaxRangeRows was reached; the resolver enforces that limit before JSON
// marshaling. Range reads the same index as /v1/query and covers every AsOf
// point in the requested window.
type rangeResponse struct {
	Entity    string      `json:"entity"`
	Rows      []windowRow `json:"rows"`
	Truncated bool        `json:"truncated"`
}

// merkleResponse is returned by GET /v1/merkle.
type merkleResponse struct {
	RootHex string `json:"root_hex"`
	// Commit fields let a quiescence probe check durability on the same
	// request as the root (ADR-0045 §7). With a write-behind WAL, the root
	// can stop changing as soon as the last InsertLocal lands, long before the
	// commit's fsync returns. One measured run had a stable root at 3.12 s
	// while a commit remained outstanding for about 213 s. A stable root
	// therefore requires commit_in_flight == 0 before the node can be
	// considered quiescent. The remaining fields report commit count, total
	// append time, and worst append time from the group-commit bridge.
	CommitInFlight      int64  `json:"commit_in_flight"`
	CommitCount         uint64 `json:"commit_count"`
	CommitTotalAppendNs int64  `json:"commit_total_append_ns"`
	CommitMaxAppendNs   int64  `json:"commit_max_append_ns"`
}

// livecheckResponse is the JSON body GET /livecheck returns (mirrors the
// plain-HTTP ops surface's livecheckBody so the SDK's Status() is consistent).
type livecheckResponse struct {
	NodeID     string   `json:"node_id"`
	Peers      []string `json:"peers"`
	TLSVersion string   `json:"tls_version"`
}

// Handler returns the control-port HTTP handler. cmd/sovereign-node mounts it
// on the --control-addr TLS listener with client certificates required and
// TLS 1.3 as both the minimum and maximum version (ADR-0006). A connection
// without a valid client certificate fails during the TLS handshake.
func (s *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/insert", s.handleInsert)
	mux.HandleFunc("/v1/batch-insert", s.handleBatchInsert)
	mux.HandleFunc("/v1/get", s.handleGet)
	mux.HandleFunc("/v1/query", s.handleQuery)
	mux.HandleFunc("/v1/range", s.handleRange)
	// Register cross-entity queries only when SetSecondaryIndex enables them.
	// Otherwise these paths return 404 rather than an empty successful result.
	// Their handlers use handleQuery's status conventions; a nil resolver
	// returns 503 just as it does for /v1/query.
	if s.secondaryIndexEnabled {
		mux.HandleFunc("/v1/querybyh3", s.handleQueryByH3)
		mux.HandleFunc("/v1/querybysystime", s.handleQueryBySystemTime)
	}
	mux.HandleFunc("/v1/merkle", s.handleMerkle)
	mux.HandleFunc("/livecheck", s.handleLivecheck)
	if s.metrics != nil {
		mux.Handle("/metrics", s.metrics)
	}
	return mux
}

// handleInsert serves POST /v1/insert through Gossiper.InsertLocalEvents so
// the payload is cached for a later sweep (ADR-0011 §4). A successful response
// acknowledges only the local durable write; peers converge asynchronously.
func (s *ControlServer) handleInsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req insertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		http.Error(w, "bad request: empty key", http.StatusBadRequest)
		return
	}
	// InsertLocalEvents derives PayloadDigest from the same payload it caches,
	// keeping the two consistent for receive-side verification.
	//
	// An empty CRDTEntry would produce the empty valid-time interval [0, 0),
	// which AsOf excludes from every query. InsertLocal and bridge.PutLocal
	// preserve these caller fields, so the HTTP boundary supplies the default:
	// absent temporal fields mean valid from write time with no asserted end
	// (ADR-0017 §6).
	now := time.Now().UnixNano()
	validFrom := now
	if req.ValidFromNs != nil {
		validFrom = *req.ValidFromNs
	}
	// SystemTime and AssertionTime default to the write time. AsOf admits the
	// row when SystemTime <= transactionTime, making it visible once written.
	// A positive ValidForNs replaces the open end with the claimed duration.
	validEnd := OpenEndedValidEndNs
	if req.ValidForNs != nil && *req.ValidForNs > 0 {
		// Saturate against int64 to avoid overflow on a pathologically large
		// client-claimed duration; a claim beyond OpenEndedValidEndNs is
		// equivalent to open-ended (and saturating preserves "valid forever").
		claimed := validFrom + *req.ValidForNs
		if claimed > OpenEndedValidEndNs || claimed < validFrom {
			validEnd = OpenEndedValidEndNs
		} else {
			validEnd = claimed
		}
	}
	// Ignore h3_index unless the secondary index is enabled. Nil and explicit
	// zero both retain the engine's no-cell value in either mode. An enabled
	// server validates the mode bits of nonzero values; this checks syntax,
	// not geographic validity.
	h3Index := uint64(0)
	if s.secondaryIndexEnabled && req.H3Index != nil && *req.H3Index != 0 {
		if !plausibleH3Cell(*req.H3Index) {
			http.Error(w, "bad request: h3_index is not an H3 cell index (mode bits [59,63) must be 1; syntax only, not geographic validation)", http.StatusBadRequest)
			return
		}
		h3Index = *req.H3Index
	}
	entry := eng.CRDTEntry{
		SystemTime:     now,
		ValidTimeStart: validFrom,
		ValidTimeEnd:   validEnd,
		AssertionTime:  now,
		H3Index:        h3Index,
	}
	dot := s.gossiper.InsertLocalEvents(req.Key, req.Val, entry) // gossip.go:202

	// A zero CausalDot signals that the bridge's origin PutLocal failed after
	// the in-memory write, so the WAL did not make the write durable. Healthy
	// dots carry the nonzero localNodeID and cannot collide with this sentinel.
	// Return 503 with no receipt so the client can retry instead of treating a
	// non-durable write as successful.
	if dot == (eng.CausalDot{}) && s.gossiper.BridgeActive() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(insertResponse{DotHex: ""})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(insertResponse{DotHex: dotHex(dot)})
}

// handleBatchInsert serves POST /v1/batch-insert through
// Gossiper.InsertLocalEventsBatch, Bridge.PutLocals, and WAL.AppendMutations.
// Group commit pays one fsync for the batch rather than one per mutation
// (ADR-0044). At a measured 2.1 ms per fsync, 10,000 separate commits would
// cost about 21 seconds instead of one 2.1 ms commit. The single-insert route
// retains its per-mutation path.
//
// WAL batches are atomic. A Sync failure means no subset can be reported
// durable, so every otherwise valid item receives 503 and the client retries
// the whole batch (ADR-0044 §4). Empty keys and invalid H3 cells receive
// per-entry 400 statuses before the batch call and do not prevent valid
// entries from being attempted.
//
// Temporal stamping matches handleInsert. Omitted valid_from_ns means valid
// from write time with no asserted end (ADR-0017 §6). All entries share one
// write timestamp for consistent SystemTime and AssertionTime values.
func (s *ControlServer) handleBatchInsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req batchInsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Items) == 0 {
		http.Error(w, "bad request: empty batch", http.StatusBadRequest)
		return
	}
	// One write-time for the whole batch (consistent SystemTime/AssertionTime
	// across the entries — the same stamping a serial /v1/insert loop would
	// produce, modulo microsecond drift).
	now := time.Now().UnixNano()
	statuses := make([]batchInsertItemStatus, len(req.Items))
	inserted, failed := 0, 0

	// Validate entries before the batch call. Invalid entries receive 400
	// without aborting the others, and retain their original request indices
	// so clients can map statuses back to the request.
	batch := make([]BatchItem, 0, len(req.Items))
	for i := range req.Items {
		item := req.Items[i]
		if item.Key == "" {
			statuses[i] = batchInsertItemStatus{Index: i, Key: item.Key, Code: http.StatusBadRequest}
			failed++
			continue
		}
		// Apply the same temporal defaults as handleInsert.
		validFrom := now
		if item.ValidFromNs != nil {
			validFrom = *item.ValidFromNs
		}
		validEnd := OpenEndedValidEndNs
		if item.ValidForNs != nil && *item.ValidForNs > 0 {
			claimed := validFrom + *item.ValidForNs
			if claimed > OpenEndedValidEndNs || claimed < validFrom {
				validEnd = OpenEndedValidEndNs
			} else {
				validEnd = claimed
			}
		}
		// Apply the single-insert H3 rules to each item. An invalid nonzero
		// value receives 400 before the batch call and does not abort valid
		// entries. With the secondary index disabled, h3_index is ignored.
		h3Index := uint64(0)
		if s.secondaryIndexEnabled && item.H3Index != nil && *item.H3Index != 0 {
			if !plausibleH3Cell(*item.H3Index) {
				statuses[i] = batchInsertItemStatus{Index: i, Key: item.Key, Code: http.StatusBadRequest}
				failed++
				continue
			}
			h3Index = *item.H3Index
		}
		entry := eng.CRDTEntry{
			SystemTime:     now,
			ValidTimeStart: validFrom,
			ValidTimeEnd:   validEnd,
			AssertionTime:  now,
			H3Index:        h3Index,
		}
		batch = append(batch, BatchItem{EntityID: item.Key, Payload: item.Val, Entry: entry})
	}

	// Send valid entries through the ADR-0044 batch path. Success returns one
	// dot per entry in batch order. Any batch error makes all valid entries
	// non-durable. If validation rejected every item, skip the call entirely.
	var dots []eng.CausalDot
	var batchOK bool
	if len(batch) > 0 {
		var berr error
		dots, _, berr = s.gossiper.InsertLocalEventsBatch(batch)
		batchOK = (berr == nil)
	}

	// Dots follow valid-entry order, while statuses follow request order.
	// Walk the original items and advance j only past entries that were not
	// rejected during validation.
	j := 0
	for i := range req.Items {
		if statuses[i].Code == http.StatusBadRequest {
			continue // already rejected during validation
		}
		if batchOK {
			statuses[i] = batchInsertItemStatus{Index: i, Key: req.Items[i].Key, Code: http.StatusOK, DotHex: dotHex(dots[j])}
			inserted++
		} else {
			// A Sync or Write failure leaves the atomic WAL batch non-durable.
			// Mark every valid entry 503 so the client retries the whole batch
			// (ADR-0044 §4). The single-insert route retains its own 503 path.
			statuses[i] = batchInsertItemStatus{Index: i, Key: req.Items[i].Key, Code: http.StatusServiceUnavailable}
			failed++
		}
		j++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(batchInsertResponse{Inserted: inserted, Failed: failed, Items: statuses})
}

// handleGet serves GET /v1/get?key=.... Payload is returned only on a local
// cache hit; PayloadDigest always comes from the selected entry.
//
// PointGet performs an O(log N) per-shard read without allocating arena memory.
// State().Get instead rebuilds the entire merged HAMT and retains O(N·log N)
// arena bytes per call. One PointGet, one selectLatestDot decision, and one
// PayloadForDot lookup against that entry also keep the response consistent:
// separate state reads could combine a payload from one version with the dot
// and digest from another after a concurrent insert.
func (s *ControlServer) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "bad request: missing key", http.StatusBadRequest)
		return
	}
	entries := s.gossiper.engine.PointGet(key) // O(log N) per shard, without a merged State view
	latest, ok := selectLatestDot(entries)     // deterministic total-order selection
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(getResponse{EntityID: key, Present: false})
		return
	}
	// Look up the payload for the same latest entry that supplied the dot and
	// digest, avoiding a second state read and a cross-version response.
	payload, _ := s.gossiper.PayloadForDot(key, latest.Dot()) // gossip.go — originator hit, peer miss
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(getResponse{
		EntityID:      key,
		Present:       true,
		Payload:       payload,
		PayloadDigest: hex.EncodeToString(latest.PayloadDigest[:]),
		DotNodeID:     hex.EncodeToString(latest.DotNodeID[:]),
		DotCounter:    latest.DotCounter,
		OriginNodeID:  hex.EncodeToString(latest.OriginNodeID[:]),
	})
}

// handleQuery serves GET /v1/query?key=<entityID>&valid_time=<rfc3339>&tx_time=<rfc3339>.
// Resolver.AsOf answers which persisted version was dominant at the requested
// valid and transaction times. /v1/get instead reads current live state.
// Together they cover recovery of current state and queries over its history.
//
// A nil resolver returns 503 with {"error":"query-tier disabled (no
// --lsm-root)"}; 404 is reserved for a missing entity so clients can
// distinguish an unavailable query tier from an absent row (ADR-0017 §3).
// PayloadDigestHex is copied from entry.PayloadDigest rather than recomputed,
// because the index does not necessarily hold the corresponding value.
func (s *ControlServer) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.resolver == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: "query-tier disabled (no --lsm-root)"})
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "bad request: missing key", http.StatusBadRequest)
		return
	}
	validTime, err := parseQueryTime(r.URL.Query().Get("valid_time"))
	if err != nil {
		http.Error(w, "bad request: invalid valid_time (expect RFC3339): "+err.Error(), http.StatusBadRequest)
		return
	}
	txTime, err := parseQueryTime(r.URL.Query().Get("tx_time"))
	if err != nil {
		http.Error(w, "bad request: invalid tx_time (expect RFC3339): "+err.Error(), http.StatusBadRequest)
		return
	}

	entry, err := s.resolver.AsOf(r.Context(), key, validTime, txTime)
	if err != nil {
		if errors.Is(err, database.ErrEntityNotFound) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(queryNotFoundBody{Error: "not found", Entity: key})
			return
		}
		// Surfaces — never swallows — the wrapped list/download/scan error.
		http.Error(w, "query: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(queryResponse{
		EntityID:         entry.EntityID,
		SystemTimeNs:     entry.SystemTime,
		ValidTimeStartNs: entry.ValidTimeStart,
		ValidTimeEndNs:   entry.ValidTimeEnd,
		AssertionTimeNs:  entry.AssertionTime,
		H3Index:          entry.H3Index,
		PayloadDigestHex: hex.EncodeToString(entry.PayloadDigest[:]),
		Present:          true,
	})
}

// handleRange serves GET /v1/range?key=<entityID>&valid_time_lo=<rfc3339>&valid_time_hi=<rfc3339>&tx_time=<rfc3339>[&coalesce=true].
// Resolver.Range returns every persisted state whose valid-time interval
// overlaps [vLo, vHi) at the requested transaction time, rather than the single
// dominant point returned by /v1/query. Shared error statuses follow handleQuery
// (ADR-0024). A nil resolver produces the same 503 response, checked before
// parameter validation so an unavailable tier cannot be mistaken for bad input.
//
// Both range bounds must parse as RFC3339Nano and valid_time_hi must be after
// valid_time_lo; an empty half-open interval receives 400 before the disk scan.
// The optional coalesce=true parameter applies CoalesceRange after sorting,
// selecting per-start dominance without changing the resolver's scan or filter
// rules (ADR-0024 §1.1).
//
// PayloadDigestHex is copied from each row. Recomputing it would imply access
// to a value that the index does not necessarily contain (ADR-0017 §3).
func (s *ControlServer) handleRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.resolver == nil {
		// Match handleQuery: return the disabled-tier 503 before validating
		// parameters, so 400 or 404 cannot hide an unavailable resolver.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: "query-tier disabled (no --lsm-root)"})
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "bad request: missing key", http.StatusBadRequest)
		return
	}
	validLo, err := parseQueryTime(r.URL.Query().Get("valid_time_lo"))
	if err != nil {
		http.Error(w, "bad request: invalid valid_time_lo (expect RFC3339): "+err.Error(), http.StatusBadRequest)
		return
	}
	validHi, err := parseQueryTime(r.URL.Query().Get("valid_time_hi"))
	if err != nil {
		http.Error(w, "bad request: invalid valid_time_hi (expect RFC3339): "+err.Error(), http.StatusBadRequest)
		return
	}
	if !validHi.After(validLo) {
		// Reject hi <= lo before scanning. The resolver also rejects empty
		// half-open windows because no row can intersect them.
		http.Error(w, "bad request: valid_time_hi must be after valid_time_lo (half-open window [lo,hi) is empty)", http.StatusBadRequest)
		return
	}
	txTime, err := parseQueryTime(r.URL.Query().Get("tx_time"))
	if err != nil {
		http.Error(w, "bad request: invalid tx_time (expect RFC3339): "+err.Error(), http.StatusBadRequest)
		return
	}
	coalesce := r.URL.Query().Has("coalesce") && r.URL.Query().Get("coalesce") == "true"

	rows, truncated, err := s.resolver.Range(r.Context(), key, validLo, validHi, txTime)
	if err != nil {
		if errors.Is(err, database.ErrEntityNotFound) {
			// No durable row intersects the window at txTime. Match
			// handleQuery's 404 body so clients can distinguish absence from a
			// scan failure.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(queryNotFoundBody{Error: "not found", Entity: key})
			return
		}
		// Surface wrapped list, download, and scan errors as 500, matching
		// handleQuery rather than disguising them as missing rows.
		http.Error(w, "query: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The resolver's collector enforces MaxRangeRows before marshaling
	// (ADR-0024 §1.2), bounding the response size. Copy each durable row and
	// its digest into the response. Coalescing, when requested, is a post-sort
	// handler projection; the resolver's scan is unchanged.
	respRows := make([]windowRow, len(rows))
	for i, ev := range rows {
		respRows[i] = windowRow{
			EntityID:         ev.EntityID,
			SystemTimeNs:     ev.SystemTime,
			ValidTimeStartNs: ev.ValidTimeStart,
			ValidTimeEndNs:   ev.ValidTimeEnd,
			AssertionTimeNs:  ev.AssertionTime,
			H3Index:          ev.H3Index,
			PayloadDigestHex: hex.EncodeToString(ev.PayloadDigest[:]),
		}
	}
	if coalesce {
		// CoalesceRange operates on the resolver's TriTemporalEvent values.
		// Apply it before projecting to windowRow so dominance uses the same
		// SystemTime and mask selected by the resolver.
		coalesced := database.CoalesceRange(rows)
		respRows = make([]windowRow, len(coalesced))
		for i, ev := range coalesced {
			respRows[i] = windowRow{
				EntityID:         ev.EntityID,
				SystemTimeNs:     ev.SystemTime,
				ValidTimeStartNs: ev.ValidTimeStart,
				ValidTimeEndNs:   ev.ValidTimeEnd,
				AssertionTimeNs:  ev.AssertionTime,
				H3Index:          ev.H3Index,
				PayloadDigestHex: hex.EncodeToString(ev.PayloadDigest[:]),
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rangeResponse{
		Entity:    key,
		Rows:      respRows,
		Truncated: truncated,
	})
}

// parseQueryTime parses an RFC3339(-Nano) timestamp from a query param. It
// accepts RFC3339Nano (the superset that preserves the nanosecond precision the
// Arrow rows carry), so a client may pass either second- or ns-precision.
func parseQueryTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	return time.Parse(time.RFC3339Nano, s)
}

// handleMerkle serves GET /v1/merkle. MerkleRootFromShards returns the same
// root as State().MerkleRoot without constructing a merged HAMT view, so
// repeated convergence polling does not grow the arena. Building that view for
// 100 nodes with 10,000 entries each exhausted the arena in an earlier
// measurement. See pkg/sync/merkle_sharded.go.
func (s *ControlServer) handleMerkle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	root := s.gossiper.engine.MerkleRootFromShards() // byte-identical root without a merged HAMT view
	commitCount, commitTotalNs, commitMaxNs := s.gossiper.CommitStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(merkleResponse{
		RootHex:             hex.EncodeToString(root[:]),
		CommitInFlight:      s.gossiper.CommitInFlight(),
		CommitCount:         commitCount,
		CommitTotalAppendNs: commitTotalNs,
		CommitMaxAppendNs:   commitMaxNs,
	})
}

// handleLivecheck is GET /livecheck. It mirrors the plain-HTTP ops surface's
// livecheckBody so the SDK's Status() is consistent across the two surfaces.
func (s *ControlServer) handleLivecheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(livecheckResponse{
		NodeID:     hex.EncodeToString(s.nodeID[:]),
		Peers:      s.peers,
		TLSVersion: "TLS1.3",
	})
}

// dotHex returns the hex of a CausalDot as NodeID||Counter (the receipt the
// /v1/insert caller uses to prove the insert landed locally).
func dotHex(d eng.CausalDot) string {
	b := make([]byte, 0, 48)
	b = append(b, d.NodeID[:]...)
	b = append(b, byte(d.Counter>>56), byte(d.Counter>>48), byte(d.Counter>>40), byte(d.Counter>>32),
		byte(d.Counter>>24), byte(d.Counter>>16), byte(d.Counter>>8), byte(d.Counter))
	return hex.EncodeToString(b)
}

// queryByH3Response is returned by GET /v1/querybyh3. Rows contain the
// resolver's dominant event for each entity. The response also reports the
// queried cell, candidate count, indexed entity count, and index loss counters:
// TieDrops records MaxTieCells eviction and CeilingDrops records memory-ceiling
// eviction. These fields make a reduced candidate set visible to the caller.
type queryByH3Response struct {
	// As with windowRow, this JSON data-transfer object is not a hot-path
	// structure containing contended atomics, so the cache-line stride rule
	// does not apply.
	Cell            uint64          `json:"cell"`
	Rows            []queryResponse `json:"rows"`
	Candidates      int             `json:"candidates"`
	IndexedEntities int             `json:"indexed_entities"`
	TieDrops        uint64          `json:"tie_drops"`
	CeilingDrops    uint64          `json:"ceiling_drops"`
	Truncated       bool            `json:"truncated"`
	CurrentState    bool            `json:"current_state"`
}

// handleQueryByH3 serves GET /v1/querybyh3?cell=0x<hex>&valid_time=<rfc3339>&tx_time=<rfc3339>.
// It returns the dominant persisted event for every entity in the requested
// H3 cell at those temporal coordinates. The cell accepts 0x-prefixed
// hexadecimal, and timestamps follow /v1/query.
//
// A nil resolver returns 503. Disabled and known-degraded indexes also return
// 503, while other resolver failures return 500; partial results are not
// returned as successful responses.
func (s *ControlServer) handleQueryByH3(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.resolver == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: "query-tier disabled (no --lsm-root)"})
		return
	}
	cellStr := r.URL.Query().Get("cell")
	if cellStr == "" {
		http.Error(w, "bad request: missing cell", http.StatusBadRequest)
		return
	}
	cell, cerr := strconv.ParseUint(strings.TrimPrefix(cellStr, "0x"), 16, 64)
	if cerr != nil {
		http.Error(w, "bad request: invalid cell (expect the H3 index as 0x-prefixed hex, e.g. 0x8928308280fffff)", http.StatusBadRequest)
		return
	}
	validTime, verr := parseQueryTime(r.URL.Query().Get("valid_time"))
	if verr != nil {
		http.Error(w, "bad request: invalid valid_time (expect RFC3339): "+verr.Error(), http.StatusBadRequest)
		return
	}
	txTime, terr := parseQueryTime(r.URL.Query().Get("tx_time"))
	if terr != nil {
		http.Error(w, "bad request: invalid tx_time (expect RFC3339): "+terr.Error(), http.StatusBadRequest)
		return
	}
	rows, disc, qerr := s.resolver.QueryByH3(r.Context(), cell, validTime, txTime)
	if qerr != nil {
		if errors.Is(qerr, database.ErrSecondaryIndexDisabled) || errors.Is(qerr, database.ErrSecondaryIndexDegraded) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: qerr.Error()})
			return
		}
		http.Error(w, "query: "+qerr.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]queryResponse, len(rows))
	for i, ev := range rows {
		out[i] = queryResponse{
			EntityID:         ev.EntityID,
			SystemTimeNs:     ev.SystemTime,
			ValidTimeStartNs: ev.ValidTimeStart,
			ValidTimeEndNs:   ev.ValidTimeEnd,
			AssertionTimeNs:  ev.AssertionTime,
			H3Index:          ev.H3Index,
			PayloadDigestHex: hex.EncodeToString(ev.PayloadDigest[:]),
			Present:          true,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(queryByH3Response{
		Cell:            cell,
		Rows:            out,
		Candidates:      disc.Candidates,
		IndexedEntities: disc.IndexedEntities,
		TieDrops:        disc.TieDrops,
		CeilingDrops:    disc.CeilingDrops,
		Truncated:       disc.Truncated,
		CurrentState:    disc.CurrentState,
	})
}

// queryBySystemTimeResponse is returned by GET /v1/querybysystime. It carries
// the same rows, candidate counts, and index loss counters as
// queryByH3Response, keyed by after_ns instead of a cell.
type queryBySystemTimeResponse struct {
	// This response has the same JSON data-transfer layout considerations as
	// queryByH3Response and windowRow.
	AfterNs         int64           `json:"after_ns"`
	Rows            []queryResponse `json:"rows"`
	Candidates      int             `json:"candidates"`
	IndexedEntities int             `json:"indexed_entities"`
	TieDrops        uint64          `json:"tie_drops"`
	CeilingDrops    uint64          `json:"ceiling_drops"`
	Truncated       bool            `json:"truncated"`
	CurrentState    bool            `json:"current_state"`
}

// handleQueryBySystemTime serves GET /v1/querybysystime?after_time=<rfc3339>&valid_time=<rfc3339>&tx_time=<rfc3339>.
// It returns every entity whose resolved current SystemTime is at least
// after_time. Method, input, resolver, and failure handling match
// handleQueryByH3, including 503 for disabled or degraded indexes.
func (s *ControlServer) handleQueryBySystemTime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.resolver == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: "query-tier disabled (no --lsm-root)"})
		return
	}
	after, aerr := parseQueryTime(r.URL.Query().Get("after_time"))
	if aerr != nil {
		http.Error(w, "bad request: invalid after_time (expect RFC3339): "+aerr.Error(), http.StatusBadRequest)
		return
	}
	validTime, verr := parseQueryTime(r.URL.Query().Get("valid_time"))
	if verr != nil {
		http.Error(w, "bad request: invalid valid_time (expect RFC3339): "+verr.Error(), http.StatusBadRequest)
		return
	}
	txTime, terr := parseQueryTime(r.URL.Query().Get("tx_time"))
	if terr != nil {
		http.Error(w, "bad request: invalid tx_time (expect RFC3339): "+terr.Error(), http.StatusBadRequest)
		return
	}
	rows, disc, qerr := s.resolver.QueryBySystemTime(r.Context(), after, validTime, txTime)
	if qerr != nil {
		if errors.Is(qerr, database.ErrSecondaryIndexDisabled) || errors.Is(qerr, database.ErrSecondaryIndexDegraded) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(queryDisabledBody{Error: qerr.Error()})
			return
		}
		http.Error(w, "query: "+qerr.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]queryResponse, len(rows))
	for i, ev := range rows {
		out[i] = queryResponse{
			EntityID:         ev.EntityID,
			SystemTimeNs:     ev.SystemTime,
			ValidTimeStartNs: ev.ValidTimeStart,
			ValidTimeEndNs:   ev.ValidTimeEnd,
			AssertionTimeNs:  ev.AssertionTime,
			H3Index:          ev.H3Index,
			PayloadDigestHex: hex.EncodeToString(ev.PayloadDigest[:]),
			Present:          true,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(queryBySystemTimeResponse{
		AfterNs:         after.UnixNano(),
		Rows:            out,
		Candidates:      disc.Candidates,
		IndexedEntities: disc.IndexedEntities,
		TieDrops:        disc.TieDrops,
		CeilingDrops:    disc.CeilingDrops,
		Truncated:       disc.Truncated,
		CurrentState:    disc.CurrentState,
	})
}
