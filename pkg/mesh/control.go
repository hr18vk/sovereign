package mesh

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// ControlServer is the JSON-over-mTLS control port. It holds a *Gossiper and
// serves the /v1/* routes a downstream SDK consumer calls, plus /livecheck and
// (optionally) /metrics so a single TLS dial reaches every read the SDK offers.
// It is the Day-6 additive control surface — SEPARATE from the peer/gossip
// --bind listener (the data plane) and the plain-HTTP --metrics-addr ops surface
// (ADR-0011 §3: three surfaces, one trust root).
//
// The control port is a LOW-RATE manageability surface (1 op/sec to ~1K
// ops/sec). Its floor is the JSON unmarshal + the engine.InsertLocal CAS
// (~36 ns on 32c apply-class) + the TLS record write (~30-50 ns AES-GCM), NOT
// the 60.19 us Ed25519 verify (verify is the gossip fan-out's gate, not the
// local insert). It does NOT replace the Day-5 batched binary data plane; the
// two do NOT compete (ADR-0011 §2).
//
// The handlers NEVER call engine.InsertLocal directly: the /v1/insert route
// goes through Gossiper.InsertLocalEvents (gossip.go:202) so the payload is
// recorded in the cache a future gossip sweep ships. A route that called
// engine.InsertLocal would bypass the cache -> a future sweep ships a delta
// with no payload -> the peer's ReconstructEntry cross-check FAILS -> the delta
// is a DropVerify on every peer (ADR-0011 §4).
type ControlServer struct {
	gossiper *Gossiper
	nodeID   [16]byte
	peers    []string
	metrics  http.Handler // optional /metrics handler (the metrics.Exporter.Handler); nil disables the route
	// resolver is the Day-12 bitemporal query tier over the persisted Arrow
	// index (Resolver.AsOf — the READ half of the durability tier). It is nil
	// when the snapshot store is OFF (a research/in-memory node, or --lsm-root
	// absent): in that case /v1/query returns an honest 503 ("query-tier
	// disabled (no --lsm-root)"), NOT a silent 404. Wired by cmd/sovereign-node
	// via SetResolver (mirrors the Day-11 SetSnapshotter precedent — keeps
	// NewControlServer's 4-arg signature stable for the existing tests). ADR-0017.
	resolver *database.Resolver
}

// NewControlServer binds a control port to a Gossiper. nodeID and peers feed
// the /livecheck JSON (the same shape the plain-HTTP ops surface serves).
// metrics is the optional /metrics handler (passed as an http.Handler so this
// package does NOT import pkg/metrics — no cycle; the Day-4 seam discipline).
func NewControlServer(g *Gossiper, nodeID [16]byte, peers []string, metrics http.Handler) *ControlServer {
	return &ControlServer{gossiper: g, nodeID: nodeID, peers: peers, metrics: metrics}
}

// SetResolver wires the Day-12 bitemporal query tier (Resolver.AsOf over the
// persisted Arrow index) onto the control port. It mirrors the Day-11
// SetSnapshotter precedent on a SEPARATE seam — a SetResolver method, NOT a
// NewControlServer arg, so the 4-arg constructor signature stays stable for
// the existing mesh tests (which call NewControlServer(g, nodeID, peers,
// metrics)). A nil resolver (or no call) disables /v1/query: the route returns
// an honest 503, NOT a silent 404 (ADR-0017 §3 — the Day-8.5
// honest-no-availability contract). cmd/sovereign-node calls this only when
// --lsm-root is set.
func (s *ControlServer) SetResolver(r *database.Resolver) { s.resolver = r }

// insertRequest is the JSON body POST /v1/insert accepts.
//
// Day 12.5 — the bitemporal opt-in + the honest default. The Day-12 audit
// (byte-verified live this session) found that the legacy body {Key, Val}
// caused handleInsert to stamp an all-zero eng.CRDTEntry{}, whose ValidTime
// range [0, 0) is EMPTY by construction. AsOf's Filter 3 (query.go:360)
// `validTimeNs >= validEnd` then skips the row for every query point, so a
// /v1/insert-written event was UNQUERYABLE via /v1/query. The historical live
// proof: POST /v1/insert wonder=... → 200, GET /v1/get → 200 present, GET
// /v1/query → 404 on the SAME persisted event. The Day-12 teeth passed only
// because they called bridge.PutLocal(.., queryTestEntry(..)) directly with a
// real open-ended range, BYPASSING handleInsert — they proved the
// Resolver.AsOf ↔ LocalFS ↔ Arrow seam, never the production HTTP round-trip.
//
// Fix (honest, NOT a fabrication): expose an OPTIONAL bitemporal claim on the
// write API. ValidFromNs / ValidForNs default to nil = "the client asserted no
// bitemporal window" — which honestly means "valid from write-time,
// indefinitely" (the semantics a non-bitemporal write API can only honestly
// carry). The default is the DOCUMENTED default for a DOCUMENTED absence
// (disclosed here + in ADR-0017 §6), NOT a fabricated range asserted as if the
// client had claimed it. When the client DOES assert valid_from / valid_for,
// both are honored (ValidFor=0 means open-ended on the asserted start; the
// sentinel below is the canonical open end). The open-end sentinel is the
// int64-safe mesh.OpenEndedValidEndNs (year ~2253, < MaxInt64) — NOT
// database.MaxValidTime.UnixNano() (year-9999 overflows int64 to a negative).
type insertRequest struct {
	Key string `json:"key"`
	Val string `json:"val"`

	// ValidFromNs is the optional valid-time start (UnixNano). Nil = write-time (now).
	ValidFromNs *int64 `json:"valid_from_ns,omitempty"`
	// ValidForNs is the optional valid-time DURATION (nanoseconds) from the
	// start. Nil or 0 means open-ended (ValidTimeEnd = OpenEndedValidEndNs).
	ValidForNs *int64 `json:"valid_for_ns,omitempty"`
}

// OpenEndedValidEndNs is the int64-safe sentinel for an open-ended valid-time
// interval end. It is `9e18` ns from epoch = year ~2253, comfortably below
// math.MaxInt64 (~9.22e18) so it does not overflow, and dominates every
// realistic UnixNano SystemTime, making AsOf's Filter 3 (validTime < validEnd)
// accept any validTime >= ValidTimeStart — the honest "valid indefinitely"
// range for a write that asserts no temporal bound. It is DELIBERATELY NOT
// database.MaxValidTime.UnixNano(): MaxValidTime = year 9999 → UnixNano is
// ~2.5e26 ns, far beyond int64's 9.2e18 ceiling, wrapping to a large NEGATIVE
// (verified: -4,852,116,232,933,722,624) — a row with that validEnd is
// unqueryable for every positive validTime. internal/database defines the
// MaxValidTime var for the WRITE schema's "open-ended" documentation but no
// production code calls .UnixNano() on it (verified); mesh owns the int64-safe
// runtime sentinel for its own write boundary. query_test.go's queryValidEndNs
// (Day-12 teeth) is the same value — the teeth pinned the contract first.
const OpenEndedValidEndNs int64 = 9_000_000_000_000_000_000

// insertResponse is the JSON body POST /v1/insert returns. DotHex is the hex
// of the CausalDot (NodeID||Counter) the engine assigned — the receipt the
// caller uses to prove the insert landed locally.
type insertResponse struct {
	DotHex string `json:"dot_hex"`
}

// batchInsertRequest is the JSON body POST /v1/batch-insert accepts. Day 37
// (ADR-0042): the batch-inject endpoint that closes the Day-36 GATE 1 (B) root
// cause — the serial /v1/insert over WAN (10K HTTP round-trips = minutes). One
// POST carries N entries; the server loops the SAME InsertLocalEvents path
// per entry (NO new write code — the existing dot-stamping + payload-digest +
// bridge fsync contract is reused per entry). Each item is the SAME shape the
// single /v1/insert accepts (insertRequest) so the per-entry bitemporal
// stamping + empty-key 400 + the ACK-before-durability 503 contract are
// byte-faithful to handleInsert. The single /v1/insert is NOT removed
// (backward compat — a 1-key probe still uses it).
type batchInsertRequest struct {
	Items []insertRequest `json:"items"`
}

// batchInsertItemStatus is the per-entry honest status in the batch response.
// Code mirrors HTTP status semantics: 200 (inserted, durable — DotHex non-empty),
// 400 (bad entry — empty key, the rest still attempted), 503 (WAL fsync failed
// for THIS entry — the Day-8.5 ACK-before-durability contract is per-entry, NOT
// per-batch: a failed entry does NOT fail the batch). DotHex is "" on 400/503.
// A PARTIAL batch is reported HONESTLY — NOT a lying 200-all. The gate client
// (cmd/day36-gate) sums the failures into its injectFail false-pass guard.
type batchInsertItemStatus struct {
	Index  int    `json:"index"`
	Key    string `json:"key"`
	Code   int    `json:"code"`
	DotHex string `json:"dot_hex,omitempty"`
}

// batchInsertResponse is the JSON body POST /v1/batch-insert returns. Inserted
// is the count of durable entries (Code 200); Failed is 400 + 503 combined. The
// operator reads Inserted == len(Items) as full success; Failed > 0 is the
// honest partial-batch signal (never a 200-all lie on a partial batch).
type batchInsertResponse struct {
	Inserted int                     `json:"inserted"`
	Failed   int                     `json:"failed"`
	Items    []batchInsertItemStatus `json:"items"`
}

// getResponse is the JSON body GET /v1/get returns. It mirrors the SDK's
// GetResult (ADR-0011 §1.1): Payload is NON-EMPTY only on the originator node
// (the cache hit); on a peer it is "" and PayloadDigest carries the digest the
// value was hashed to before Ruling-3 discard. A response that reports the
// digest as if it were the value is a FABRICATION.
type getResponse struct {
	EntityID      string `json:"entity_id"`
	Present       bool   `json:"present"`
	Payload       string `json:"payload"`        // NON-EMPTY only on the originator (Ruling-3)
	PayloadDigest string `json:"payload_digest"` // hex; ALWAYS present when Present=true
	DotNodeID     string `json:"dot_node_id"`    // hex
	DotCounter    uint64 `json:"dot_counter"`
	OriginNodeID  string `json:"origin_node_id"` // hex
}

// queryResponse is the JSON body GET /v1/query returns (Day-12). It reports the
// PERSISTED tri-temporal event Resolver.AsOf dominant-picked from the Arrow
// index on disk — NOT the live HAMT (that is /v1/get's job, ADR-0011 §1.1). It
// is the READ half of the durability tier; the mirror of the Day-11 WRITE half
// (SnapshotToLSM — the index AsOf scans). PayloadDigest is echoed verbatim from
// the index (the HONEST digest the write path stamped — memtable.go:166 trusts
// the caller digest; SnapshotToLSM emits it with a SENTRY payload body). There
// is intentionally NO `payload` field: the index carries an empty body, not the
// value, so reporting one would be the G06.e "digest-is-not-value" fabrication
// the honesty guard forbids (ADR-0017 §3). present mirrors /v1/get for a
// uniform SDK surface.
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

// queryDisabledBody is the honest 503 body when /v1/query is disabled (no
// resolver — the snapshot store is off).
type queryDisabledBody struct {
	Error string `json:"error"`
}

// queryNotFoundBody is the honest 404 body when AsOf has no matching event.
type queryNotFoundBody struct {
	Error  string `json:"error"`
	Entity string `json:"entity"`
}

// windowRow is one durable bitemporal-history row in a /v1/range window
// (Day 19, ADR-0024). It mirrors queryResponse FIELD-FOR-FIELD (the persisted
// tri-temporal event the Arrow index carries) with the SAME Law V contract the
// single-point queryResponse enforces: PayloadDigestHex is the index's HONEST
// digest, echoed verbatim (never recomputed); there is intentionally NO
// `payload` field because the index stores a SENTRY body, not the value (the
// G06.e "digest-is-not-value" fabrication guard, ADR-0017 §3 — carries ONE-FOR-
// ONE across the window surface). present is dropped (a window row IS present by
// construction — Range returns only intersecting rows; an empty window is the
// 404, not a present=false row).
type windowRow struct {
	// Field order: scalars FIRST, then the two strings. Two string fields carry
	// a residual fieldalignment pointer-bytes note (the SAME one Day-12's
	// queryResponse, line 153, carries — the precedent); this is a JSON-marshal
	// DTO, NOT a hot-path contended-atomic struct, so the cache-law (Law II,
	// 128-byte stride for contended atomics) does NOT apply. JSON tags are
	// explicit so the reorder is wire-format-identical.
	SystemTimeNs     int64  `json:"system_time_ns"`
	ValidTimeStartNs int64  `json:"valid_time_start_ns"`
	ValidTimeEndNs   int64  `json:"valid_time_end_ns"`
	AssertionTimeNs  int64  `json:"assertion_time_ns"`
	H3Index          uint64 `json:"h3_index"`
	EntityID         string `json:"entity_id"`
	PayloadDigestHex string `json:"payload_digest_hex"`
}

// rangeResponse is the JSON body GET /v1/range returns (Day 19, ADR-0024). It is
// the multi-row generalization of queryResponse: a SORTED window (by
// validTimeStart ascending) of every durable bitemporal-history row whose
// valid-time interval INTERSECTS the query window [vLo, vHi) and whose SystemTime
// is <= tx_time (the operator's bitemporal-history range read). truncated=true
// signals the MaxRangeRows ceiling was hit (the unbounded-amplification guard —
// the marshal NEVER sees >MaxRangeRows rows; the operator widens the window or
// paginates). It is the READ half of the durability tier over the SAME disk
// /v1/query reads; Range is a SUPERSET of every AsOf point in the window (T2).
type rangeResponse struct {
	Entity    string      `json:"entity"`
	Rows      []windowRow `json:"rows"`
	Truncated bool        `json:"truncated"`
}

// merkleResponse is the JSON body GET /v1/merkle returns.
type merkleResponse struct {
	RootHex string `json:"root_hex"`
}

// livecheckResponse is the JSON body GET /livecheck returns (mirrors the
// plain-HTTP ops surface's livecheckBody so the SDK's Status() is consistent).
type livecheckResponse struct {
	NodeID     string   `json:"node_id"`
	Peers      []string `json:"peers"`
	TLSVersion string   `json:"tls_version"`
}

// Handler returns the http.Handler serving the control-port routes. It is
// mounted on a SEPARATE *tls.Listener (the --control-addr) with the SAME mTLS
// config as the peer path (RequireAndVerifyClientCert, Min==Max==1.3 —
// ADR-0006); a no-cert dial is a hard TLS error (G06.b).
func (s *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/insert", s.handleInsert)
	mux.HandleFunc("/v1/batch-insert", s.handleBatchInsert) // Day 37 ADR-0042
	mux.HandleFunc("/v1/get", s.handleGet)
	mux.HandleFunc("/v1/query", s.handleQuery)
	mux.HandleFunc("/v1/range", s.handleRange)
	mux.HandleFunc("/v1/merkle", s.handleMerkle)
	mux.HandleFunc("/livecheck", s.handleLivecheck)
	if s.metrics != nil {
		mux.Handle("/metrics", s.metrics)
	}
	return mux
}

// handleInsert is POST /v1/insert. It routes through Gossiper.InsertLocalEvents
// (gossip.go:202) — NEVER engine.InsertLocal — so the payload is cached for a
// future gossip sweep (ADR-0011 §4). The insert is LOCAL-ONLY at return; peer
// convergence is eventual (the next gossip sweep).
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
	// The entry's PayloadDigest is stamped inside InsertLocalEvents from the
	// SAME payload the cache stores (gossip.go:212), so digest and payload are
	// consistent by construction — the receive-side C6 tooth stays honest.
	//
	// Day 12.5 — VALID-TIME CONTRACT (the round-trip-closure fix). The legacy
	// `entry := eng.CRDTEntry{}` stamped ValidTimeStart/End/SystemTime = 0, so
	// the row's [validStart, validEnd) = [0, 0) interval was EMPTY and AsOf's
	// Filter 3 skipped it for every query (a live-reproduced 404 on a 200-Put).
	// InsertLocal (crdt.go:949) and bridge.PutLocal preserve the caller's
	// ValidTime fields verbatim, so the WRITE boundary (here) is the ONLY
	// honest place to assert a default. Undisclosed fabrication would be the
	// G06.e "digest-as-value" class — so the default is the DOCUMENTED default
	// for a DOCUMENTED absence (ADR-0017 §6): a client that asserts no
	// bitemporal window means "valid from write-time, indefinitely".
	now := time.Now().UnixNano()
	validFrom := now
	if req.ValidFromNs != nil {
		validFrom = *req.ValidFromNs
	}
	// Claimed SysTime (assertion/transaction time) is the write-time by default.
	// AsOf's Filter 2 (query.go:355: SystemTime <= transactionTime) then admits
	// the row for any tx_time >= write-time — the honest "visible once written"
	// visibility boundary. If ValidForNs is asserted, the open-ended sentinel
	// is overridden by the claimed duration end.
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
	entry := eng.CRDTEntry{
		SystemTime:     now,
		ValidTimeStart: validFrom,
		ValidTimeEnd:   validEnd,
		AssertionTime:  now,
	}
	dot := s.gossiper.InsertLocalEvents(req.Key, req.Val, entry) // gossip.go:202

	// ACK-before-durability contract (Day-8.5 STEP 1). InsertLocalEvents
	// returns a zero eng.CausalDot when the durability Bridge's PutLocal ORIGIN
	// path fsync-failed (gossip.go:316): the write landed in the in-memory
	// engine but NOT in the WAL → NOT durable → the client MUST NOT be ACKed
	// as success. A zero dot is the unambiguous signal (a healthy dot always
	// carries the non-zero localNodeID, so (eng.CausalDot{}) is never a real
	// minted dot). Return 503 instead of a lying 200+zero-dot-hex; the operator
	// reads the reason and retries. WITHOUT this guard a WAL-failed write was
	// HttpSession-ACKed as 200 with an all-zero DotHex — a non-durable write
	// sold as durable, the exact breach the durability floor exists to prevent.
	if dot == (eng.CausalDot{}) && s.gossiper.BridgeActive() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(insertResponse{DotHex: ""})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(insertResponse{DotHex: dotHex(dot)})
}

// handleBatchInsert is POST /v1/batch-insert. Day 37 (ADR-0042) introduced the
// endpoint (closing the Day-36 GATE 1 (B) root cause: 10K serial /v1/insert POSTs
// over cross-region WAN = minutes of inject wall-time). Day 39 (ADR-0044) routes
// it through Gossiper.InsertLocalEventsBatch → Bridge.PutLocals → WAL.AppendMutations
// — ONE fsync per BATCH (the fsync-COUNT cut Day 38 silicon proved is the GATE-1
// binding constraint: ~2.1ms/fsync × 10000 = ~21s > 10s SLO; ONE fsync × 2.1ms =
// 2.1ms inject, the 1000× count cut). The single /v1/insert stays byte-identical
// (handleInsert → InsertLocalEvents → PutLocal → AppendMutation, the per-mutation
// path, backward compat).
//
// ACK GRANULARITY (the ADR-0044 §4 semantic change, disclosed HONESTLY): the
// Day-37 endpoint reported PER-ENTRY 503 (a WAL-failed entry → 503 for THAT
// entry; the rest still 200). Day 39 reports PER-BATCH 503: a Sync failure means
// the WHOLE batch is un-durable (the WAL atomic-batch model — no subset can be
// asserted durable), so ALL items get Code 503 and the client retries the WHOLE
// batch. The per-entry 400 (empty key) STAYS per-entry — a bad entry is
// honest-reported BEFORE the batch call (filtered out, skipped as 400, the rest
// passed to InsertLocalEventsBatch). The Day-37 T-BatchInsertWALFailPerEntry tooth
// stays GREEN: it posts all-success and all-fail batches separately (never a mixed
// batch), so both semantics produce the same all-200 / all-503 observations.
//
// Bitemporal stamping per entry mirrors handleInsert verbatim: a nil
// valid_from_ns means "valid from write-time, indefinitely" (the DOCUMENTED
// default, ADR-0017 §6) — NOT a fabricated range. The whole batch shares ONE
// `now` (write-time) so the entries' SystemTime/AssertionTime are consistent
// within the batch (the same stamping discipline a serial loop would produce).
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

	// Phase 1 — per-entry 400 filter. A bad entry (empty key) is honest-reported
	// BEFORE the batch call and DOES NOT abort the batch: its status is stamped
	// 400 here, and the VALID entries are collected into a []BatchItem for the
	// batch call. The 400s keep their ORIGINAL request index (statuses[i].Index
	// = i) so the client maps the per-entry status back to its request position.
	batch := make([]BatchItem, 0, len(req.Items))
	for i := range req.Items {
		item := req.Items[i]
		if item.Key == "" {
			statuses[i] = batchInsertItemStatus{Index: i, Key: item.Key, Code: http.StatusBadRequest}
			failed++
			continue
		}
		// Verbatim bitemporal stamping from handleInsert (control.go:319-346).
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
		entry := eng.CRDTEntry{
			SystemTime:     now,
			ValidTimeStart: validFrom,
			ValidTimeEnd:   validEnd,
			AssertionTime:  now,
		}
		batch = append(batch, BatchItem{EntityID: item.Key, Payload: item.Val, Entry: entry})
	}

	// Phase 2 — the batch call. If there are valid entries, route them through
	// InsertLocalEventsBatch (gossip.go — the ADR-0044 batch path). On success
	// (err == nil AND failedFrom == -1): ALL valid entries get Code 200 with
	// DotHex=dotHex(dots[j]). On ANY failure (err != nil OR failedFrom != -1):
	// ALL valid entries get Code 503 (the atomic-batch NOT-durable contract).
	// A batch with ONLY 400s (every key empty) skips the batch call entirely —
	// the per-entry 400s are the honest result, no durability attempted.
	var dots []eng.CausalDot
	var batchOK bool
	if len(batch) > 0 {
		var berr error
		dots, _, berr = s.gossiper.InsertLocalEventsBatch(batch)
		batchOK = (berr == nil)
	}

	// Phase 3 — stamp the valid entries' statuses. The dots slice is indexed
	// against the VALID-entry order (batch[j]), NOT the request order; the
	// request-order statuses[i] are filled by walking req.Items again and
	// advancing j past the 400s (the inverse of Phase 1's filter).
	j := 0
	for i := range req.Items {
		if statuses[i].Code == http.StatusBadRequest {
			continue // a 400, already stamped in Phase 1
		}
		if batchOK {
			statuses[i] = batchInsertItemStatus{Index: i, Key: req.Items[i].Key, Code: http.StatusOK, DotHex: dotHex(dots[j])}
			inserted++
		} else {
			// Per-BATCH 503: a Sync/Write failure means the WHOLE batch is
			// un-durable (the WAL atomic-batch model — no subset can be asserted
			// durable). Honest atomicity: ACK ALL valid entries as 503 so the
			// client retries the WHOLE batch. This is the ADR-0044 §4 granularity
			// CHANGE from the Day-37 per-entry 503 (disclosed above + in the ADR).
			// The single /v1/insert path keeps per-entry 503 byte-identical.
			statuses[i] = batchInsertItemStatus{Index: i, Key: req.Items[i].Key, Code: http.StatusServiceUnavailable}
			failed++
		}
		j++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(batchInsertResponse{Inserted: inserted, Failed: failed, Items: statuses})
}

// handleGet is GET /v1/get?key=... It reports the originator-vs-peer boundary
// if it were the value is the fabrication the G06.e tooth catches.
//
// SINGLE-SNAPSHOT DISCIPLINE (Day-6.5 FIX A): State() (crdt.go:1225) rebuilds
// the ENTIRE merged HAMT under stateViewMu and is O(total entries). The OLD
// handler called it TWICE — once here for the digest/dot fields and again
// inside LatestPayload for the payload lookup — so a concurrent
// InsertLocalEvents between the two reads could publish a new shard root and
// yield a response whose payload is from one snapshot and whose digest/dot are
// from another (a TOCTOU tear: the reported PayloadDigest could be the SHA-256
// of a DIFFERENT payload). The fix is ONE State().Get, ONE selectLatestDot
// pick, and ONE PayloadForDot lookup against that single `latest` entry — every
// field of the response derives from the same entry, so the tear is impossible.
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
	entries := s.gossiper.engine.State().Get(key) // crdt.go:1225 -> hamt.go:170
	latest, ok := selectLatestDot(entries)        // FIX B: total-order pick, deterministic
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(getResponse{EntityID: key, Present: false})
		return
	}
	// ONE cache lookup against the SAME `latest` entry the digest/dot fields
	// derive from — no second State() scan, no cross-snapshot tear.
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

// handleQuery is GET /v1/query?key=<entityID>&valid_time=<rfc3339>&tx_time=<rfc3339>.
// It is the Day-12 READ half of the durability tier: the persisted bitemporal
// query over the Arrow index (Resolver.AsOf), the mirror of the Day-11 WRITE
// half (SnapshotToLSM). It answers "what was this entity's value as observed AT
// valid-time V, transaction-time T?" — the question the persisted index exists
// to answer, which /v1/get (the LIVE HAMT, current-state-at-now) CANNOT. A node
// that crashed + bounded-recovered can be re-queried for its live state
// (/v1/get) AND now for its persisted history (/v1/query) — the tier is
// round-trip-closed: write → checkpoint → crash → recover → query-the-history.
//
// HONEST-AVAILABILITY contract (Day-8.5 precedent, ADR-0017 §3): when the
// resolver is nil — a research/in-memory node, or --lsm-root absent — the route
// returns 503 with {"error":"query-tier disabled (no --lsm-root)"}. It does NOT
// return 404: a route-absent 404 is indistinguishable to a client from "entity
// not found", so a disabled query tier that 404'd would be a silent lie. The
// 503 makes the unavailable tier observable — the same discipline as the
// ACK-before-durability 503 in handleInsert (control.go:137).
//
// NO-RECOMPUTE law (Law V, ADR-0017 §3): the PayloadDigest is echoed verbatim
// from entry.PayloadDigest (the index's honest digest). Recomputing it would
// fabricate a value the index may never have held — the G06.e fabrication class.
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

// handleRange is GET /v1/range?key=<entityID>&valid_time_lo=<rfc3339>&valid_time_hi=<rfc3339>&tx_time=<rfc3339>[&coalesce=true].
// It is the Day-19 READ-half multi-row generalization of handleQuery: the
// persisted bitemporal-HISTORY range query over the SAME Arrow index AsOf scans
// (Resolver.Range), answering "give me every state of E asserted as-of txTime T
// whose ValidTime interval intersects [vLo, vHi)" — the question /v1/query (a
// single dominant point) CANNOT. An operator debugging a time window, an auditor
// reconstructing a history, a reconciliation sweep comparing two txTimes are all
// served here. It mirrors /v1/query's 405/503/400/404/500 discipline EXACTLY for
// the shared cases (the route is the operator-facing seam — ADR-0024). The 503-
// disabled contract (Day-8.5 honest-no-availability precedent) carries ONE-FOR-
// ONE: a nil resolver returns 503 + {"error":"query-tier disabled (no --lsm-root)"},
// NOT a silent 404. The 503-disabled guard runs BEFORE param validation (the tier
// is OFF; a malformed range to a disabled tier is "unavailable", not "bad
// request" — the SAME order handleQuery pins so a disabled state is not hidden
// behind a 400).
//
// RANGE-SPECIFIC 400 GUARDS: valid_time_lo + valid_time_hi MUST both parse as
// RFC3339Nano AND form a non-empty half-open window (valid_time_hi > valid_time_lo;
// hi <= lo is the empty-window class the resolver double-guards). These are the
// RANGE-only cases (handleQuery has a single valid_time); the shared key/tx_time
// 400s mirror handleQuery verbatim. The optional ?coalesce=true param switches
// the output from the raw sorted window (the default, ADR-0024 §1.1) to the
// post-sort per-start-dominance coalesce (CoalesceRange — a DIFFERENT projection,
// reusing the SAME Filter-2 + dominance rule; NOT a scanRecordBatch change).
//
// Law V (no-recompute, ADR-0017 §3): PayloadDigestHex is echoed verbatim from each
// row.PayloadDigest (the index's honest digest). Recomputing it would fabricate a
// value the index may never have held — the G06.e fabrication class, carried across
// the window surface (windowRow).
func (s *ControlServer) handleRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.resolver == nil {
		// Honest-no-availability — the SAME 503-body + BEFORE-param-validation
		// order handleQuery uses (a disabled range tier is "unavailable", not a
		// 404-indistinguishable-from-not-found, not a 400-hiding-disabled).
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
		// Empty half-open window: hi <= lo. The resolver double-guards this (no
		// row's [vs,ve) intersects a non-positive-width window); the handler
		// surfaces it as an honest 400 BEFORE the durable scan (waste-free).
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
			// The honest 404: no durable row in the index intersects the window at
			// txTime. Mirrors handleQuery's ErrEntityNotFound 404 surfacing (the
			// SAME body shape — windowRow:Error + windowRow:Entity so a client
			// distinguishes "not found" from a 500 scan failure).
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(queryNotFoundBody{Error: "not found", Entity: key})
			return
		}
		// Surfaces — never swallows — the wrapped list/download/scan error (the
		// SAME 500 boundary handleQuery uses; NOT a 404 hiding a sick tier).
		http.Error(w, "query: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The cap is enforced INSIDE the resolver's collector (pre-marshal), so the
	// marshal here NEVER sees >MaxRangeRows rows — the unbounded-amplification
	// guard (ADR-0024 §1.2). Build the windowRow slice from the durable rows;
	// PayloadDigestHex is echoed verbatim (Law V). The optional coalesce is a
	// POST-sort pass over the collected rows IN THE HANDLER (NOT a resolver
	// scanRecordBatch change) — the default is the raw sorted window.
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
		// CoalesceRange operates on []*TriTemporalEvent (the resolver's in-memory
		// form); build the coalesced view BEFORE projecting to windowRow so the
		// dominance rule reuses the SAME SystemTime/Mask the resolver carried.
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

// handleMerkle is GET /v1/merkle. It returns the engine's current MerkleRoot as
// hex (crdt.go:1225 -> hamt.go:265). Stable across re-reads when the state is
// unchanged (CRDT idempotency — G06.c). Day 37 (ADR-0042): switched the root
// source from engine.State().MerkleRoot() to engine.MerkleRootFromShards() —
// the BYTE-IDENTICAL root computed directly from the per-shard roots with NO
// merged HAMT view (zero arena growth). This is the SILICON convergence oracle
// (the cmd/day36-gate client polls /v1/merkle on all 100 nodes); under State()
// each poll at 100×10K built a 10K-entry merged view → HamtArena OOM
// (hamt_arena.go:638). The root is byte-identical, so the convergence proof
// (same root on convergent nodes) is UNCHANGED. See pkg/sync/merkle_sharded.go.
func (s *ControlServer) handleMerkle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	root := s.gossiper.engine.MerkleRootFromShards() // Day 37 ADR-0042 — merkle_sharded.go (byte-identical to State().MerkleRoot(), no merged-view OOM)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(merkleResponse{RootHex: hex.EncodeToString(root[:])})
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
