// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Command sovereign-node runs a Sovereign Engine node. It accepts TLS 1.3 peer
// connections, reassembles length-prefixed frames, and passes them to the
// receive gate and CRDT engine. Separate listeners serve the metrics, debugging,
// and optional JSON-over-mTLS control surfaces.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/internal/index"
	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
	"github.com/hr18vk/sovereign/pkg/metrics"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
	"github.com/prometheus/client_golang/prometheus"
)

// defaultArenaSize is the off-heap HAMT arena size for the engine. It
// matches the convention used across pkg/sync tests (64 MiB); it is
// overridable via --arena-mib.
const defaultArenaSize uintptr = 64 * 1024 * 1024

// defaultAdmissionBudget is the receive admission budget in nanoseconds. The
// 3.2 MaxHopsForBudget transform converts it to a maximum hop count.
// --admission-budget-ns overrides it.
const defaultAdmissionBudget int64 = 50_000_000 // 50 ms

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sovereign-node: %v\n", err)
		os.Exit(1)
	}
}

// nodeConfig is the parsed flag set, kept in a struct so the /livecheck
// handler and the accept loop share it by reference.
type nodeConfig struct {
	bind            string
	peers           string
	tlsCert         string
	tlsKey          string
	tlsCA           string
	nodeID          string
	metricsAddr     string
	controlAddr     string
	arenaMib        int
	admissionBudget int64
	gossipTick      string
	identitySeed    string
	selftest        bool
	batchSize       int
	// lamportAbsoluteSlack adds an allowance to the engine's Lamport and
	// rate-envelope bound (ADR-0045). The default 1000 rejects far-future
	// stamps while permitting normal clock skew. A cold peer receiving a large
	// batch may need a larger allowance. Zero is coerced to 1000 at startup.
	// This flag does not implement a separate verified-origin transfer protocol.
	lamportAbsoluteSlack uint64
	// stratifiedAntiEntropy selects digest-based reconciliation. When false,
	// each sweep sends the full set; when true, GenerateDelta sends the computed
	// difference after a StrataEstimator and IBLT exchange (ADR-0034).
	stratifiedAntiEntropy bool
	// deferHandler defers a peer for one round after a digest-exchange failure,
	// then sends a bounded rotating slice instead of the full keyset. The slice
	// is limited to 608 received entries per peer per round. It requires
	// --stratified-anti-entropy.
	deferHandler bool
	// deferCrossover permits one bounded full-keyset send per divergence episode
	// after a capacity-class peel failure. It requires --defer-handler.
	deferCrossover bool
	// digestWaitTimeout bounds each stratified digest exchange. A peer answers
	// a digest request immediately, so the wait is governed by round-trip time,
	// not the sweep period. The 500 ms default suits a LAN; wide-area links may
	// need a larger value. Convergence timings are not round-trip measurements.
	digestWaitTimeout time.Duration
	// digestWaitAdaptive replaces the fixed wait with a per-peer value clamped
	// between --digest-wait-timeout and 15 seconds: twice the response-latency
	// EWMA plus 230 ms. Completed and drained exchanges feed the EWMA, samples
	// expire after 60 seconds, and an unobserved pair uses the configured floor.
	// It requires both stratified anti-entropy and the defer handler.
	digestWaitAdaptive bool
	// ibltV2 selects decorrelated key placement, bounded dynamic sizing, and
	// the IBL2 wire format. It requires --stratified-anti-entropy. Mixed v1/v2
	// peers oversend until they use the same version.
	ibltV2           bool
	ibltV2MinBuckets int
	// meshWriteTimeout applies to every mesh frame write through PeerSet.Publish.
	// Zero disables the deadline. The 10-second default bounds a stalled write;
	// a timeout closes the connection so reconnect logic establishes a fresh one.
	meshWriteTimeout time.Duration
	// walPath enables WAL recovery and an fsync for each origin mutation when
	// non-empty. The empty default uses an in-memory engine. The checkpoint
	// interval bounds the replay tail; zero leaves checkpoints to the caller.
	walPath               string
	walCheckpointInterval uint64

	// secondaryIndexEnable wires the optional cross-entity H3 and system-time
	// index, its write feeds, and its query routes. The maximum entity count is
	// uncapped at zero. At a positive ceiling, new-entity records are dropped and
	// counted, and queries return 503 rather than an incomplete answer.
	secondaryIndexEnable      bool
	secondaryIndexMaxEntities int

	// lsmRoot stores recovery snapshots under ckpt/<LamportHigh> and the Arrow
	// query index under l0/. With --wal-path set, recovery loads the snapshot and
	// replays only its tail. An empty value retains full WAL replay.
	lsmRoot string

	// compactionPruneEnable opts into dropping superseded rows during L0-to-L1
	// compaction (ADR-0020). Pruning also requires a positive transaction-time
	// horizon; otherwise NewL1Compactor logs a warning and preserves every row.
	compactionPruneEnable  bool
	compactionPruneHorizon int64
	// compactionPruneBackoff keeps the effective prune horizon behind the
	// observed query frontier (ADR-0027). The horizon is max(operator floor,
	// observed frontier - backoff). The default is five minutes; zero follows
	// the frontier directly while retaining the operator floor.
	compactionPruneBackoff time.Duration

	// compactionReapEnable opts into deleting superseded L0 files and manifests
	// after confirming that the replacement L1 exists (ADR-0021). The default
	// retains them as recovery backstops. The five-minute reaper interval is
	// deliberately longer than the 30-second compaction interval.
	compactionReapEnable   bool
	compactionReapInterval time.Duration
	// otelEnabled arms telemetry.Init with an SDK MeterProvider. Its periodic
	// log exporter is separate from the cumulative Prometheus bridge, so the two
	// exporters do not double-count at /metrics (ADR-0023, ADR-0026).
	otelEnabled  bool
	otelInterval time.Duration

	// certRotationEnable starts the optional leaf-rotation manager (ADR-0035).
	// It polls hourly by default and rotates 30 days before NotAfter. The current
	// in-process minter is available only in --selftest; an operator-supplied PEM
	// setup needs an external transport.RotationMinter. crlPath optionally loads
	// a revoked-serial list that SIGHUP can reload.
	certRotationEnable   bool
	certRotationPoll     time.Duration
	certRotationLifetime time.Duration
	crlPath              string
	// hybridVerifyEnable requires both Ed25519 and ML-DSA-65 signatures on the
	// receive path (ADR-0036). The default retains classical Ed25519 verification.
	// Hybrid signing is controlled independently by hybridSignEnable. The PQ-KEM
	// handshake counter is always wired and increments only for X25519MLKEM768.
	hybridVerifyEnable bool

	// hybridSignEnable signs self-originated batches with both Ed25519 and
	// ML-DSA-65 over the same 120-byte SHAKE256 pad (ADR-0037). Both keys derive
	// from --identity-seed, and the public PQ key is registered for verification.
	// Relayed foreign deltas keep their original signatures.
	hybridSignEnable bool

	// regionAwareEnable selects peers through TopologyManager instead of the
	// full peer set (ADR-0039). Selection retains the intra-region mesh and uses
	// seeded cross-region fan-out. RegionUnset peers are treated as local, so
	// enabling the flag without region tags retains full-mesh behavior.
	regionAwareEnable bool

	// partialIntraViewEnable limits each intra-region sweep to eight targets,
	// or fewer for a small region. A deterministic per-sweep seed rotates the
	// selection so every pair is eventually checked. It requires --region-aware.
	partialIntraViewEnable bool

	// sweepPhaseJitterEnabled offsets each node's sweeps by a deterministic
	// fraction of the active tick, reducing synchronized responder load. For
	// overlap window W and tick T, the overlap factor is 2W/T - (W/T)^2. The
	// default performs no offset; SOVEREIGN_SWEEP_PHASE_JITTER=1 also enables it.
	sweepPhaseJitterEnabled bool

	// selfRegion is this node's numeric region tag. Zero is RegionUnset, which
	// treats untagged peers as local rather than assigning them a foreign region.
	selfRegion int

	// regionFanout bounds cross-region targets per sweep. TopologyManager clamps
	// it to MaxFanout; zero disables cross-region selection.
	regionFanout      int
	gatewaysPerRegion int
	// peerDir names the optional out-of-band peer directory (ADR-0040). Each
	// entry supplies an address, real node ID, verification keys, and optional
	// region for provisioning. A missing or malformed named file fails startup;
	// an empty path leaves peer IDs to dialing and reconciliation.
	peerDir string

	// autoReconcile re-keys an unprovisioned connection from the node ID in the
	// peer's TLS leaf CommonName. This repairs routing state only: it does not
	// install a verification key, so --peer-dir is still required to accept the
	// peer's deltas.
	autoReconcile bool

	// pprofAddr selects the dedicated loopback profile port, or derives it from
	// the metrics port plus 1000. The listener is separate from the metrics mux.
	// diagProfile enables mutex and block sampling; it is disabled by default
	// because it instruments their hot paths. Goroutine profiles need no flag.
	pprofAddr   string
	diagProfile bool
}

func parseFlags(args []string) (*nodeConfig, error) {
	fs := flag.NewFlagSet("sovereign-node", flag.ContinueOnError)
	cfg := &nodeConfig{}
	fs.StringVar(&cfg.bind, "bind", "127.0.0.1:7430", "TLS listener bind address (host:port)")
	fs.StringVar(&cfg.peers, "peers", "", "comma-separated peer addresses; each may carry an @region suffix")
	fs.StringVar(&cfg.tlsCert, "tls-cert", "", "leaf certificate PEM path")
	fs.StringVar(&cfg.tlsKey, "tls-key", "", "leaf private key PEM path")
	fs.StringVar(&cfg.tlsCA, "tls-ca", "", "CA certificate PEM path (trust root)")
	fs.StringVar(&cfg.nodeID, "node-id", "", "16-byte node identity (hex); defaults to a random 16-byte id")
	fs.StringVar(&cfg.metricsAddr, "metrics-addr", "127.0.0.1:7431", "/livecheck control surface bind address (plain HTTP, ops debug)")
	fs.StringVar(&cfg.pprofAddr, "pprof-addr", "", "loopback /debug/pprof port or host:port; the host is discarded, and empty uses the metrics port + 1000")
	fs.BoolVar(&cfg.diagProfile, "diag-profile", false, "enable mutex and block profiling (also SOVEREIGN_DIAG_PROFILE=1); disabled by default because of runtime overhead")
	fs.StringVar(&cfg.controlAddr, "control-addr", "", "JSON-over-mTLS client control listener (host:port); empty disables it")
	fs.IntVar(&cfg.arenaMib, "arena-mib", 64, "off-heap HAMT arena size in MiB")
	fs.Int64Var(&cfg.admissionBudget, "admission-budget-ns", defaultAdmissionBudget, "receive admission budget in nanoseconds (3.2 max-hops transform)")
	fs.StringVar(&cfg.gossipTick, "gossip-tick", "100ms", "anti-entropy sweep interval (default 100ms; healing workloads may use 50ms)")
	fs.StringVar(&cfg.identitySeed, "identity-seed", "", "32-byte hex Ed25519 seed for this node's CRDT-delta signing identity (defaults to a random seed; the derived nodeID dominates --node-id)")
	fs.BoolVar(&cfg.selftest, "selftest", false, "run the built-in self-test (mint a dev CA + leaf, serve /livecheck, exit)")
	fs.IntVar(&cfg.batchSize, "batch-size", 100, "self-originated deltas per signed batch (1-256; one signature verification per batch)")
	fs.Uint64Var(&cfg.lamportAbsoluteSlack, "lamport-absolute-slack", 1000, "additional Lamport skew allowance for admitting batches to cold peers (default 1000; zero is coerced to 1000)")
	fs.BoolVar(&cfg.stratifiedAntiEntropy, "stratified-anti-entropy", false, "exchange StrataEstimator and IBLT digests to send differences instead of full sets; digest failures fall back to full-set sends")
	fs.BoolVar(&cfg.deferHandler, "defer-handler", false, "defer one round after a digest failure, then send a bounded rotating slice instead of the full keyset; requires --stratified-anti-entropy")
	fs.BoolVar(&cfg.deferCrossover, "defer-crossover", false, "allow one full-keyset send per divergence after a capacity peel failure within the 20,000-entry bound; requires --defer-handler")
	fs.DurationVar(&cfg.digestWaitTimeout, "digest-wait-timeout", 500*time.Millisecond, "digest response timeout per peer (default 500ms; increase for wide-area round trips)")

	fs.BoolVar(&cfg.digestWaitAdaptive, "digest-wait-adaptive", false, "adapt each peer's digest wait using its response-latency EWMA, clamped to 15s; requires --stratified-anti-entropy and --defer-handler")
	// Decorrelated placement avoids the double-hash stopping-set floor; the
	// 2-core threshold is B > 1.295*D. Dynamic sizing is capped at 21,845
	// buckets, and mixed v1/v2 peers oversend until they use the same version.
	fs.BoolVar(&cfg.ibltV2, "iblt-v2", false, "use decorrelated IBLT placement, dynamic bucket sizing, and the IBL2 wire format; requires --stratified-anti-entropy and fleet-wide version alignment")
	fs.IntVar(&cfg.ibltV2MinBuckets, "iblt-v2-min-buckets", 0, "minimum starting and decay bucket count for IBLT v2 (0 uses 1024; 21845 supports 10,000 differences at 2.1845x); requires --iblt-v2")
	fs.DurationVar(&cfg.meshWriteTimeout, "mesh-write-timeout", 10*time.Second, "per-frame TLS write timeout; zero disables it, and a timeout closes the connection for redial")
	fs.StringVar(&cfg.walPath, "wal-path", "", "WAL file path; empty uses an in-memory engine without fsync or WAL recovery")
	fs.Uint64Var(&cfg.walCheckpointInterval, "wal-checkpoint-interval", 1000, "mutations between periodic WAL checkpoints (0 = caller-driven checkpoints only)")
	fs.StringVar(&cfg.lsmRoot, "lsm-root", "", "snapshot directory; with --wal-path, recovery replays only the post-checkpoint tail")
	fs.BoolVar(&cfg.compactionPruneEnable, "compaction-prune-enable", false, "drop superseded rows during compaction when they fall before the transaction-time prune horizon")
	fs.Int64Var(&cfg.compactionPruneHorizon, "compaction-prune-horizon-ns", 0, "transaction-time prune horizon in nanoseconds; requires --compaction-prune-enable and must be positive")
	fs.DurationVar(&cfg.compactionPruneBackoff, "compaction-prune-backoff-ns", 5*time.Minute, "distance behind the observed query frontier for the inferred prune horizon (default 5m; 0 tracks the frontier)")
	fs.BoolVar(&cfg.compactionReapEnable, "compaction-reap-enable", false, "delete superseded L0 files and manifests after verifying that the replacement L1 exists")
	fs.DurationVar(&cfg.compactionReapInterval, "compaction-reap-interval", 5*time.Minute, "superseded L0 reaper interval (default 5m)")
	fs.BoolVar(&cfg.otelEnabled, "otel", false, "enable OpenTelemetry log export alongside the Prometheus /metrics bridge")
	fs.DurationVar(&cfg.otelInterval, "otel-interval", 60*time.Second, "OpenTelemetry periodic export interval")
	fs.BoolVar(&cfg.certRotationEnable, "cert-rotation-enable", false, "enable automated leaf rotation; the in-process minter requires --selftest")
	fs.DurationVar(&cfg.certRotationPoll, "cert-rotation-poll", time.Hour, "leaf rotation poll interval (default 1h; must be positive)")
	fs.DurationVar(&cfg.certRotationLifetime, "cert-rotation-lifetime", 30*24*time.Hour, "rotate this long before leaf NotAfter (default 720h)")
	fs.StringVar(&cfg.crlPath, "crl-path", "", "PEM CRL path for rejecting revoked leaf serials; empty disables revocation checks, and SIGHUP reloads it")
	fs.BoolVar(&cfg.hybridVerifyEnable, "hybrid-verify", false, "require Ed25519 and ML-DSA-65 signatures on the receive path; classical-only v1 frames are rejected")
	fs.BoolVar(&cfg.hybridSignEnable, "hybrid-sign", false, "sign self-originated batches with Ed25519 and ML-DSA-65; derive both keys from --identity-seed")
	fs.BoolVar(&cfg.regionAwareEnable, "region-aware", false, "select gossip peers by region; untagged peers are treated as local")
	fs.IntVar(&cfg.selfRegion, "self-region", 0, "numeric region tag for this node (0 = unset)")
	fs.IntVar(&cfg.regionFanout, "region-fanout", 3, "cross-region gossip targets per sweep (default 3; 0 = intra-region only)")
	fs.IntVar(&cfg.gatewaysPerRegion, "gateways-per-region", 0, "regional gateways per region, selected from the first entries in --peer-dir file order; requires --region-aware")
	fs.BoolVar(&cfg.partialIntraViewEnable, "partial-intra-view", false, "limit each intra-region sweep to a rotating subset of up to eight peers; requires --region-aware")
	fs.BoolVar(&cfg.sweepPhaseJitterEnabled, "sweep-phase-jitter", false, "offset sweeps by a deterministic per-node phase; also enabled by SOVEREIGN_SWEEP_PHASE_JITTER=1")
	fs.BoolVar(&cfg.secondaryIndexEnable, "secondary-index", false, "enable the cross-entity H3 and system-time index and its query routes")
	fs.IntVar(&cfg.secondaryIndexMaxEntities, "secondary-index-max-entities", 0, "maximum distinct indexed entities (0 = uncapped; excess new entities are dropped and queries return 503)")
	fs.StringVar(&cfg.peerDir, "peer-dir", "", "out-of-band peer directory: `addr nodeID ed25519_pubkey [mldsa65_pubkey|-] [region|-]` per line; missing or malformed files fail startup")
	fs.BoolVar(&cfg.autoReconcile, "peer-auto-reconcile", false, "re-key unprovisioned peers from their TLS leaf node ID for routing; verification keys still require --peer-dir")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if !cfg.selftest {
		if cfg.tlsCert == "" || cfg.tlsKey == "" || cfg.tlsCA == "" {
			return nil, errors.New("--tls-cert, --tls-key, and --tls-ca are required (or pass --selftest)")
		}
	}
	return cfg, nil
}

// resolveNodeID parses --node-id or generates a random 16-byte node ID.
func resolveNodeID(cfg *nodeConfig) ([16]byte, error) {
	if cfg.nodeID == "" {
		var id [16]byte
		if _, err := io.ReadFull(cryptorand.Reader, id[:]); err != nil {
			return [16]byte{}, err
		}
		return id, nil
	}
	raw, err := hex.DecodeString(cfg.nodeID)
	if err != nil {
		return [16]byte{}, fmt.Errorf("--node-id: %w", err)
	}
	if len(raw) != 16 {
		return [16]byte{}, fmt.Errorf("--node-id: want 16 bytes (32 hex chars), got %d bytes", len(raw))
	}
	var id [16]byte
	copy(id[:], raw)
	return id, nil
}

// parsePeers splits --peers into host:port addresses. It strips each optional
// @region suffix before dialing; parsePeerRegions reads the suffix separately.
// An untagged peer remains RegionUnset and is treated as local.
func parsePeers(peers string) []string {
	if peers == "" {
		return nil
	}
	out := []string{}
	for _, p := range strings.Split(peers, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Strip the region suffix before dialing; parsePeerRegions reads it
		// separately from the original flag value.
		if at := strings.IndexByte(p, '@'); at >= 0 {
			p = strings.TrimSpace(p[:at])
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePeerRegions returns address-to-region mappings from --peers suffixes.
// Addresses without a valid numeric uint8 suffix are omitted and therefore
// remain RegionUnset. Zero is accepted and has the same unset meaning.
func parsePeerRegions(peers string) map[string]mesh.RegionTag {
	if peers == "" {
		return nil
	}
	out := make(map[string]mesh.RegionTag)
	for _, p := range strings.Split(peers, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		at := strings.IndexByte(p, '@')
		if at < 0 {
			continue
		}
		addr := strings.TrimSpace(p[:at])
		regionStr := strings.TrimSpace(p[at+1:])
		if addr == "" || regionStr == "" {
			continue
		}
		r, err := strconv.ParseUint(regionStr, 10, 8)
		if err != nil {
			continue
		}
		out[addr] = mesh.RegionTag(r)
	}
	return out
}

// peerIDForAddr returns the first 16 bytes of SHA-256(addr). This deterministic
// surrogate keys topology state for an unprovisioned address; it is not proof
// of the peer's identity. applySurrogateRegions omits provisioned addresses,
// whose real node IDs key the topology instead.
func peerIDForAddr(addr string) [16]byte {
	sum := sha256.Sum256([]byte(addr))
	var id [16]byte
	copy(id[:], sum[:16])
	return id
}

// applySurrogateRegions registers address-derived region keys only for
// addresses absent from --peer-dir. A provisioned peer is registered under its
// real node ID; retaining its surrogate as well could consume a cross-region
// fan-out slot even though no connection uses that surrogate.
func applySurrogateRegions(topo *mesh.TopologyManager, peers string, provisionedAddr map[string]bool) {
	for addr, region := range parsePeerRegions(peers) {
		if provisionedAddr[addr] {
			continue // provisioned via --peer-dir → region keyed under real nodeID below
		}
		topo.SetRegion(peerIDForAddr(addr), region)
	}
}

// disableAsyncBootDialFault restores sequential boot dialing for the negative
// control used by the boot-dial tests.
var disableAsyncBootDialFault atomic.Bool

// bootDialConcurrency bounds the initial dial worker pool. Same-region targets
// are queued before cross-region targets.
const bootDialConcurrency = 32

// validatePartialIntraViewConfig rejects flags whose behavior requires the
// region-aware topology selector. Without it, a partial-view or gateway flag
// would not affect peer selection.
func validatePartialIntraViewConfig(cfg *nodeConfig) error {
	if cfg.partialIntraViewEnable && !cfg.regionAwareEnable {
		return fmt.Errorf("--partial-intra-view requires --region-aware: the intra view is drawn inside the topology Select path")
	}
	if cfg.gatewaysPerRegion < 0 {
		return fmt.Errorf("--gateways-per-region must be >= 0 (got %d)", cfg.gatewaysPerRegion)
	}
	if cfg.gatewaysPerRegion > 0 && !cfg.regionAwareEnable {
		return fmt.Errorf("--gateways-per-region requires --region-aware: hierarchical regional gateway routing operates inside the region-aware topology selector")
	}
	return nil
}

var disableArenaMiBMinBucketsGuardFault atomic.Bool

func validateConfig(cfg *nodeConfig) error {
	if err := validatePartialIntraViewConfig(cfg); err != nil {
		return err
	}
	if cfg.ibltV2 && !cfg.stratifiedAntiEntropy {
		return fmt.Errorf("--iblt-v2 requires --stratified-anti-entropy: the v2 digest scheme arms inside the stratified digest-exchange; without stratified the flag is a silent no-op and every digest stays the legacy double-hash at the fixed 1024")
	}
	if cfg.ibltV2MinBuckets < 0 {
		return fmt.Errorf("--iblt-v2-min-buckets must be >= 0 (got %d)", cfg.ibltV2MinBuckets)
	}
	if cfg.ibltV2MinBuckets > 0 && !cfg.ibltV2 {
		return fmt.Errorf("--iblt-v2-min-buckets requires --iblt-v2: the v2 bucket floor applies only to the v2 IBLT ladder")
	}
	if !disableArenaMiBMinBucketsGuardFault.Load() && os.Getenv("SOVEREIGN_TEST_FAULT_IBLT_ARENA") != "skip_arena_mib_guard" {
		if cfg.ibltV2MinBuckets > 8192 && cfg.arenaMib < 256 {
			return fmt.Errorf("--iblt-v2-min-buckets %d (> 8192) requires --arena-mib >= 256 (got %d): 21845-bucket v2 digests allocate 512 KiB arena slabs and exhaust a 64 MiB arena under 1,000-node concurrency", cfg.ibltV2MinBuckets, cfg.arenaMib)
		}
	}
	return nil
}

type bootDialTarget struct {
	pa            string
	host          string
	dialPeerID    [16]byte
	isProvisioned bool
}

func startMeshBootDialAndSweep(
	meshCtx context.Context,
	cfg *nodeConfig,
	peers []string,
	provisioned provisionedMap,
	topo *mesh.TopologyManager,
	peerSet *mesh.PeerSet,
	gossiper *mesh.Gossiper,
) error {
	peerSet.SetAutoReconcile(cfg.autoReconcile)
	tickDur, err := time.ParseDuration(cfg.gossipTick)
	if err != nil {
		return fmt.Errorf("--gossip-tick %q: %w", cfg.gossipTick, err)
	}
	intraDialTargets := make([]bootDialTarget, 0, len(peers))
	interDialTargets := make([]bootDialTarget, 0, len(peers))
	for _, pa := range peers {
		host, _, herr := net.SplitHostPort(pa)
		if herr != nil {
			host = "localhost"
		}
		var dialPeerID [16]byte
		isProvisioned := false
		if pid, ok := provisioned[pa]; ok {
			dialPeerID = pid
			isProvisioned = true
		} else if len(provisioned) > 0 {
			log.Printf("sovereign-node: peer %s is in --peers but not --peer-dir; dialing with a zero node ID prevents topology routing and publication. Use the same address string in both settings.", pa)
		}
		if topo != nil && !topo.ShouldDialPeer(dialPeerID) {
			continue
		}
		dt := bootDialTarget{
			pa:            pa,
			host:          host,
			dialPeerID:    dialPeerID,
			isProvisioned: isProvisioned,
		}
		if topo != nil && topo.IsInterRegion(dialPeerID) {
			interDialTargets = append(interDialTargets, dt)
		} else {
			intraDialTargets = append(intraDialTargets, dt)
		}
	}
	dialTargets := append(intraDialTargets, interDialTargets...)
	dialOneTarget := func(dt bootDialTarget) {
		dialErr := peerSet.Dial(meshCtx, dt.pa, dt.host, dt.dialPeerID)
		if dialErr != nil {
			log.Printf("peer dial %s: %v (accept loop still serving; ReconnectLoop retries with backoff)", dt.pa, dialErr)
		} else if dt.isProvisioned {
			log.Printf("sovereign-node: dialed provisioned peer %x at %s", dt.dialPeerID, dt.pa)
		}
		go peerSet.ReconnectLoop(meshCtx, dt.pa, dt.host, dt.dialPeerID, time.Second, 10*time.Second)
	}
	syncBootDialFault := disableAsyncBootDialFault.Load() || os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "sync_boot_dial"
	if syncBootDialFault {
		for _, dt := range dialTargets {
			dialOneTarget(dt)
		}
	}
	go gossiper.SweepLoop(meshCtx, tickDur)
	if len(peers) > 0 {
		log.Printf("sovereign-node: mesh gossip sweep started, tick=%s, peers=%d (dial_targets=%d)", cfg.gossipTick, len(peers), len(dialTargets))
	} else {
		log.Printf("sovereign-node: no peers configured (single-node); sweep idle")
	}
	if !syncBootDialFault && len(dialTargets) > 0 {
		go func(targets []bootDialTarget) {
			workers := bootDialConcurrency
			if workers > len(targets) {
				workers = len(targets)
			}
			var nextIdx atomic.Int64
			var wg sync.WaitGroup
			wg.Add(workers)
			for w := 0; w < workers; w++ {
				go func() {
					defer wg.Done()
					for {
						if meshCtx.Err() != nil {
							return
						}
						idx := int(nextIdx.Add(1) - 1)
						if idx >= len(targets) {
							return
						}
						dialOneTarget(targets[idx])
					}
				}()
			}
			wg.Wait()
		}(dialTargets)
	}
	return nil
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	// Enable mutex and block sampling before startup work so the profiles cover
	// the full run. Collection has runtime overhead; goroutine profiles do not
	// require this flag.
	if cfg.diagProfile || os.Getenv("SOVEREIGN_DIAG_PROFILE") == "1" {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		log.Printf("diag-profile: mutex and block profiling enabled; intended for diagnosis because of runtime overhead")
	}
	nodeID, err := resolveNodeID(cfg)
	if err != nil {
		return err
	}
	peers := parsePeers(cfg.peers)

	// The self-test mints a temporary CA and leaf, serves /livecheck briefly,
	// and exits. Retaining the CA lets the rotation manager issue replacement
	// leaves. The normal PEM-based path has no in-process CA (ADR-0035).
	certPath, keyPath, caPath := cfg.tlsCert, cfg.tlsKey, cfg.tlsCA
	var selftestCA *crypto.MeshCA
	if cfg.selftest {
		certPath, keyPath, caPath, selftestCA, err = mintSelftestCerts(nodeID)
		if err != nil {
			return fmt.Errorf("selftest certgen: %w", err)
		}
		log.Printf("selftest: minted dev CA + leaf (nodeID=%x) into temp dir", nodeID)
	}

	tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		return fmt.Errorf("tls transport: %w", err)
	}

	// A configured CRL must load successfully before the listener starts.
	// VerifyPeerCertificate rejects listed serials, and SIGHUP reloads the file.
	if cfg.crlPath != "" {
		tr.SetCRLPath(cfg.crlPath)
		if err := tr.LoadCRL(); err != nil {
			return fmt.Errorf("CRL load %q: %w; refusing to start without the configured revocation list", cfg.crlPath, err)
		}
		log.Printf("CRL loaded from %q; revoked leaf serials will be rejected", cfg.crlPath)
	}
	tr.SetRevocationReporter(telemetry.CertRevokedRejected.Inc)
	// Go negotiates X25519MLKEM768 by default when both peers support it. This
	// reporter observes that negotiation; it does not enable the KEM or depend
	// on hybrid signature verification.
	tr.SetPQHandshakeReporter(telemetry.PQHandshakeNegotiated.Inc)
	// The rotation manager needs a certificate minter. buildRotationMinter
	// provides one for --selftest and returns an error for the PEM-only path.
	if cfg.certRotationEnable {
		minter, minterErr := buildRotationMinter(selftestCA, nodeID, certPath, keyPath, tr)
		if minterErr != nil {
			return fmt.Errorf("cert rotation: %w", minterErr)
		}
		stopRot, rotErr := tr.StartRotationManager(context.Background(), cfg.certRotationPoll, cfg.certRotationLifetime, minter, telemetry.CertRotationTriggered.Inc)
		if rotErr != nil {
			return fmt.Errorf("cert rotation manager: %w", rotErr)
		}
		defer stopRot()
		log.Printf("automated leaf-cert rotation enabled (poll=%s, rotation window=%s; leaf reloads within %s of NotAfter)",
			cfg.certRotationPoll, cfg.certRotationLifetime, cfg.certRotationLifetime)
	}

	arenaSize := uintptr(cfg.arenaMib) * 1024 * 1024
	if arenaSize == 0 {
		arenaSize = defaultArenaSize
	}
	// An empty WAL path constructs a fresh in-memory engine. Otherwise recovery
	// replays the log and checks it against the checkpoint before opening the
	// WAL for append. A root or fingerprint mismatch prevents startup. The
	// durability bridge appends each accepted local mutation before returning.
	var engine *eng.DeltaCRDTEngine
	var bridge *durability.Bridge
	// The query resolver, compactor, and reaper are constructed only when a
	// durable node has --lsm-root. Without a resolver, /v1/query returns 503.
	// The reaper additionally requires --compaction-reap-enable; otherwise
	// superseded L0 files remain available for recovery (ADR-0017, ADR-0019,
	// ADR-0021).
	var queryResolver *database.Resolver
	var queryCompactor *database.L1Compactor
	var queryReaper *database.L0Reaper
	// bootWitness records recovery facts for /debug/memstats. The HTTP server
	// starts after replay, so the handler reads this record rather than
	// recomputing recovery state. An in-memory node has no witness and reports
	// witness_present=false.
	//
	// The secondary index is constructed before recovery so replay can feed it.
	// Other packages depend on feeder interfaces rather than this concrete type.
	// With --secondary-index=false, feedSecondary remains an unattached no-op.
	var secondaryIndex *index.Index
	feedSecondary := func(entityID string, h3Index uint64, systemTime int64) {}
	if cfg.secondaryIndexEnable {
		secondaryIndex = index.NewWith(index.DefaultShards, index.DefaultEpochNs)
		secondaryIndex.SetEntityCeiling(cfg.secondaryIndexMaxEntities)
		feedSecondary = func(entityID string, h3Index uint64, systemTime int64) {
			secondaryIndex.Apply(index.Record{EntityID: entityID, H3Index: h3Index, SystemTime: systemTime})
		}
	}

	// Select the process-global digest scheme before constructing an engine;
	// each IBLT captures the scheme at construction. Validation also rejects
	// dependent flags without the features that make them effective.
	if err := validateConfig(cfg); err != nil {
		return err
	}
	eng.SetIBLTSchemeV2(cfg.ibltV2)

	var bootWitness *durability.RecoveryWitness
	if cfg.walPath != "" {
		// With --lsm-root, recovery loads the dot-bearing snapshot and replays
		// only the post-checkpoint tail. A missing or unusable snapshot falls
		// back to full replay and records the reason in the recovery witness.
		var snapshotStore durability.SnapshotStore
		if cfg.lsmRoot != "" {
			lfs, lerr := durability.NewLocalFS(cfg.lsmRoot)
			if lerr != nil {
				return fmt.Errorf("lsm-root %s: %w", cfg.lsmRoot, lerr)
			}
			snapshotStore = lfs
		}
		// The fed recovery variant applies snapshot, tail, and repaired records
		// to the secondary index. Without the index, use ordinary recovery.
		var recEngine *eng.DeltaCRDTEngine
		var wal *durability.WAL
		var rep *durability.Replayed
		var witness *durability.RecoveryWitness
		var rerr error
		if cfg.secondaryIndexEnable {
			recEngine, wal, rep, witness, rerr = durability.RecoverEngineWithSnapshotFed(nodeID, cfg.walPath, snapshotStore, arenaSize, feedSecondary)
		} else {
			recEngine, wal, rep, witness, rerr = durability.RecoverEngineWithSnapshot(nodeID, cfg.walPath, snapshotStore, arenaSize)
		}
		if rerr != nil {
			if errors.Is(rerr, durability.ErrRecoveryRootMismatch) {
				log.Fatalf("sovereign-node: %v; refusing to start because the rebuilt Merkle root differs from the checkpoint root", rerr)
			}
			if errors.Is(rerr, durability.ErrRecoveryFingerprintMismatch) {
				log.Fatalf("sovereign-node: %v; refusing to start because the rebuilt state differs from the checkpoint fingerprint", rerr)
			}
			return fmt.Errorf("recovery: %w", rerr)
		}
		engine = recEngine
		bootWitness = witness
		bridge = durability.NewBridge(engine, wal, cfg.walCheckpointInterval)
		// Durable local writes feed the index synchronously after InsertLocal.
		if cfg.secondaryIndexEnable {
			bridge.SetIndexFeeder(feedSecondary)
		}
		// The bridge owns the recovered engine's scratch directory and removes
		// it on Close.
		bridge.SetScratchDir(rep.ScratchDir)
		// Later checkpoints write both the dot-bearing image and the Arrow query
		// index, so subsequent recoveries can also use the post-checkpoint tail.
		if snapshotStore != nil {
			lfs := snapshotStore.(*durability.LocalFS)
			bridge.SetSnapshotter(lfs, true)
			// The resolver and snapshotter share one LocalFS so queries see the
			// Arrow files written beneath the same root (ADR-0017 §2.2). The
			// allocator is a stateless handle: each Arrow scan releases its
			// off-heap read buffers, so the handle needs no shutdown method.
			queryAlloc := database.NewJemallocAllocator()
			queryResolver = database.NewResolver(
				lfs, lfs, queryAlloc, "local", database.DefaultResolverConfig(),
			)
			// The resolver merges the live CRDT state after its durable Arrow
			// scan, using the same dominance rules for both sources. A local
			// insert is therefore visible to /v1/query before the next periodic
			// checkpoint flushes it to L0 (ADR-0032). The adapter wraps the
			// recovered engine and is installed only on this snapshot-store path.
			queryResolver.SetLiveSource(&engineHAMTAdapter{engine: engine})
			// The resolver owns the candidate-source interface; this is the
			// concrete binding for cross-entity secondary-index queries.
			if cfg.secondaryIndexEnable {
				queryResolver.SetSecondaryIndexSource(secondaryIndex)
			}
			// Compaction reads L0 and writes L1 through the same LocalFS as the
			// resolver. Its background scheduler merges an entity's L0 files at
			// the configured trigger, keeping the uncompacted tail within the
			// resolver's L0-file limit without discarding history (ADR-0019).
			//
			// Pruning preserves every row by default. With pruning enabled, the
			// supplied horizon controls which superseded rows compaction may
			// drop; NewL1Compactor warns and preserves rows if the horizon is not
			// positive (ADR-0020).
			compactionCfg := database.DefaultCompactionConfig()
			compactionCfg.EnableDominancePruning = cfg.compactionPruneEnable
			compactionCfg.PruningHorizonInt64Ns = cfg.compactionPruneHorizon
			// Before each compaction sweep, the horizon inferrer uses the
			// resolver's observed transaction-time frontier:
			// max(operator floor, observed frontier - backoff). The configured
			// horizon remains the lower bound (ADR-0027).
			compactionCfg.PruneBackoffInt64Ns = cfg.compactionPruneBackoff.Nanoseconds()
			queryCompactor = database.NewL1Compactor(
				lfs, lfs, lfs, queryAlloc, "local", compactionCfg,
			)
			// The reaper shares the compactor's LocalFS. When explicitly
			// enabled, it deletes superseded L0 files and manifests only after
			// confirming that the replacement L1 exists. Otherwise those files
			// remain as recovery backstops (ADR-0021).
			if cfg.compactionReapEnable {
				queryReaper = database.NewL0Reaper(lfs, lfs, lfs, "local")
			}
		}
		if witness != nil && witness.Bounded {
			log.Printf("sovereign-node: durability enabled; recovered WAL %s from snapshot ckpt/%d (replayed %d post-checkpoint record(s), bridge active)",
				cfg.walPath, witness.SnapshotLamportHigh, witness.ReplayedRecords)
		} else if witness != nil && snapshotStore != nil && witness.FallbackReason != "" {
			log.Printf("sovereign-node: durability enabled; recovered WAL %s by full replay (snapshot fallback: %s; bridge active)", cfg.walPath, witness.FallbackReason)
		} else {
			log.Printf("sovereign-node: durability enabled; recovered WAL %s (bridge active, fsync per mutation)", cfg.walPath)
		}
	} else {
		engine, err = eng.NewDeltaCRDTEngine(nodeID, 1, arenaSize)
		if err != nil {
			return fmt.Errorf("engine: %w", err)
		}
		log.Printf("sovereign-node: durability disabled; using an in-memory engine (--wal-path empty)")
	}
	// Set the skew allowance after either recovery or in-memory construction
	// and before the receiver uses the engine. Zero would leave a cold receiver
	// with only its Lamport and rate-envelope bounds, rejecting ordinary bulk
	// catch-up, so zero uses the documented default of 1000 (ADR-0045).
	if cfg.lamportAbsoluteSlack == 0 {
		log.Printf("sovereign-node: --lamport-absolute-slack=0 would reject cold-peer catch-up; using 1000")
		cfg.lamportAbsoluteSlack = 1000
	}
	engine.SetLamportAbsoluteSlack(cfg.lamportAbsoluteSlack)
	wallClock := clock.NewSystemClock()
	cap := clock.NewIngressHLCScalarCap(wallClock, engine)
	bucket := admission.NewPeerBucket()
	dir := identity.NewDirectory()
	recv := receive.NewReceiver(bucket, cap, wallClock, dir, engine, cfg.admissionBudget)
	// Hybrid verification requires both Ed25519 and ML-DSA-65 signatures;
	// classical-only v1 frames are rejected in that mode (ADR-0036).
	recv.SetHybridVerify(cfg.hybridVerifyEnable)
	// Feed joined remote entries from all three frame handlers to the secondary
	// index. Bind the feeder before the accept loop starts.
	if cfg.secondaryIndexEnable {
		recv.SetIndexFeeder(feedSecondary)
	}

	// The signing public key's first 16 bytes are the node ID used by the
	// engine and receive gate. A supplied identity seed must therefore derive
	// the configured node ID; without a seed, a random identity is generated.
	ident := buildNodeIdentity(cfg, nodeID)
	// Self-registration verifies loopback deltas. Peer verification keys come
	// from --peer-dir; the TLS leaf CommonName supplies only the node ID.
	_ = dir.Register(ident.NodeID, ident.Pub)
	// A hybrid identity carries an ML-DSA-65 keypair as well as Ed25519 keys.
	// Register its public PQ key so loopback frames and frames relayed back to
	// their origin pass hybrid verification through Directory.LookupBoth. Peer
	// PQ keys still come from --peer-dir. Classical identities have no PQ key;
	// RegisterPQ is skipped and hybrid frames from those origins are rejected.
	if ident.PQPub != nil {
		if err := dir.RegisterPQ(ident.NodeID, ident.PQPub); err != nil {
			log.Fatalf("identity: RegisterPQ: %v", err)
		}
	}
	peerSet := mesh.NewPeerSet(tr, recv, ident, engine)
	gossiper := mesh.NewGossiper(peerSet, ident, engine, dir)
	// Batch sizes above one use shipBatchedDelta, which signs up to N local
	// deltas together instead of signing each delta separately. Foreign deltas
	// retain their original frames. SetBatchSize clamps to [1, MaxBatchSize].
	gossiper.SetBatchSize(cfg.batchSize)
	// Local writes on an in-memory node feed the secondary index through the
	// gossiper; durable writes use the bridge feeder installed above.
	if cfg.secondaryIndexEnable {
		gossiper.SetIndexFeeder(feedSecondary)
	}
	// Stratified anti-entropy is optional (ADR-0034). When enabled, a peer
	// exchanges a StrataEstimator and IBLT digest before GenerateDelta computes
	// their difference. Timeouts, malformed digests, and peel failures fall back
	// to a full-set send and increment sovereign_mesh_stratified_fallback.
	// Digests use tagged frames on the peer TLS connection, not the control port.
	gossiper.SetStratifiedAntiEntropy(cfg.stratifiedAntiEntropy)
	// SOVEREIGN_RESPOND_INDEG_DEBUG=1 enables per-arrival responder occupancy
	// tracking and its debug route. When disabled, no tracker is allocated and
	// the response-recording call is a nil-guarded no-op.
	if os.Getenv("SOVEREIGN_RESPOND_INDEG_DEBUG") == "1" {
		gossiper.SetRespondIndegArmed(true)
		log.Printf("respond-indeg: per-arrival responder occupancy tracking enabled (SOVEREIGN_RESPOND_INDEG_DEBUG=1); /debug/responder-indegree")
	}
	// The gossiper reads this local setting for request, response, and sizing
	// decisions. The engine's digest scheme is process-global and was selected
	// before engine construction. A false value leaves v1 behavior unchanged.
	gossiper.SetIBLTV2(cfg.ibltV2)
	gossiper.SetIBLTV2MinBuckets(cfg.ibltV2MinBuckets)
	gossiper.SetStratifiedFallbackReporter(telemetry.StratifiedAntiEntropyFallback.Inc)
	// Deferral is implemented only in the stratified branch of
	// generateSweepDelta. Reject --defer-handler without stratified
	// anti-entropy rather than accepting a flag that cannot affect the sweep.
	if cfg.deferHandler && !cfg.stratifiedAntiEntropy {
		return fmt.Errorf("--defer-handler requires --stratified-anti-entropy: deferral runs only in the stratified digest exchange")
	}
	gossiper.SetDeferHandler(cfg.deferHandler)
	// The saturation crossover runs in the defer handler's capacity-failure
	// branch, so it is invalid without --defer-handler.
	if cfg.deferCrossover && !cfg.deferHandler {
		return fmt.Errorf("--defer-crossover requires --defer-handler: the saturation crossover runs in the defer handler's capacity-failure branch")
	}
	gossiper.SetDeferCrossover(cfg.deferCrossover)
	// Digest requests are answered immediately, so this wait primarily covers
	// network round-trip time rather than the peer's sweep period. It is used
	// only by the stratified exchange.
	gossiper.SetDigestWaitTimeout(cfg.digestWaitTimeout)

	// Adaptive waits run inside the stratified exchange. Expiry defers the peer
	// only when the defer handler is active; otherwise it takes the full-set
	// fallback. Require both features so enabling this flag cannot change the
	// timeout duration and expiry behavior independently.
	if cfg.digestWaitAdaptive && (!cfg.stratifiedAntiEntropy || !cfg.deferHandler) {
		return fmt.Errorf("--digest-wait-adaptive requires --stratified-anti-entropy and --defer-handler: adaptive waits run only in the stratified exchange, and expiry defers only with the handler")
	}
	gossiper.SetDigestWaitAdaptive(cfg.digestWaitAdaptive)
	// All mesh writes pass through PeerSet.Publish and TransmitTLSFrame, so one
	// deadline covers every frame. A timed-out peer is skipped for
	// DefaultSuspectBackoff while ReconnectLoop establishes a fresh connection.
	// The callback increments MeshWriteTimeouts for write timeouts only.
	peerSet.SetWriteTimeout(cfg.meshWriteTimeout)
	peerSet.SetSuspectBackoff(mesh.DefaultSuspectBackoff)
	peerSet.SetWriteTimeoutReporter(telemetry.MeshWriteTimeouts.Inc)
	// Hybrid signing is optional (ADR-0037). It changes locally originated
	// batches from a v1 BatchEnvelope with one Ed25519 signature to a
	// HybridEnvelope carrying Ed25519 and ML-DSA-65 signatures over the same
	// 120-byte SHAKE256 pad. The acceptance counter is always registered so
	// /metrics exposes it even when this node does not sign hybrid frames.
	gossiper.SetHybridSign(cfg.hybridSignEnable)
	recv.SetHybridAcceptReporter(telemetry.HybridFrameAccepted.Inc)
	// Accepted foreign deltas must be retained for both per-frame and batched
	// relay publication. WireRelayHooks installs both receive callbacks before
	// the accept loop starts. RetainForeign takes ownership of the fresh buffer
	// returned by ReadFrame; self-originated payloads remain in payloadCache.
	gossiper.WireRelayHooks(recv)
	// Region-aware gossip is optional (ADR-0039). When enabled,
	// AntiEntropySweep uses topology.Select for the local region mesh and seeded
	// cross-region fan-out instead of iterating the full peer set. RegionUnset
	// peers are local. With the flag disabled, the bound topology is ignored.
	// The reporter counts each inter-region envelope sent.
	topo := mesh.NewTopologyManager(mesh.RegionTag(cfg.selfRegion))
	topo.SetFanout(cfg.regionFanout)
	topo.SetGatewaysPerRegion(cfg.gatewaysPerRegion)
	topo.SetSelfNodeID(nodeID)
	// Parse --peer-dir before registering address-derived region keys.
	// Provisioned connections use their real node IDs, so retaining an
	// address-derived surrogate for the same peer could consume a cross-region
	// fan-out slot and increment the inter-region metric without a send.
	// applyProvisioning later registers the real IDs and their directory keys;
	// the directory's region column takes precedence over an @region suffix.
	provCfgs, provParseErr := parsePeerDir(cfg.peerDir)
	if provParseErr != nil && !errors.Is(provParseErr, ErrPeerDirEmpty) {
		// A named file must exist and parse successfully. ErrPeerDirEmpty is
		// the no-provisioning case, not a startup failure.
		return fmt.Errorf("--peer-dir: %w", provParseErr)
	}
	provisionedAddr := make(map[string]bool, len(provCfgs))
	for _, c := range provCfgs {
		provisionedAddr[c.addr] = true
	}
	// An unprovisioned address has no verified node ID at this point, so its
	// region is keyed by the deterministic SHA-256 surrogate from
	// peerIDForAddr. That surrogate is only topology state, not an identity.
	// Region-aware selection needs real peer IDs from --peer-dir or
	// --peer-auto-reconcile to match these connections. Untagged peers remain
	// RegionUnset and are treated as local. Provisioned addresses are skipped.
	applySurrogateRegions(topo, cfg.peers, provisionedAddr)
	gossiper.SetTopology(topo)
	gossiper.SetRegionAware(cfg.regionAwareEnable)
	gossiper.SetGatewayMode(cfg.gatewaysPerRegion > 0)
	gossiper.SetInterRegionReporter(telemetry.InterRegionEnvelopesShipped.Inc)
	// validateConfig has already rejected partial-view and gateway settings
	// that are not accompanied by region-aware selection.
	gossiper.SetPartialIntraView(cfg.partialIntraViewEnable)
	// Set deterministic sweep offsets before SweepLoop starts. Either the flag
	// or SOVEREIGN_SWEEP_PHASE_JITTER=1 enables them (ADR-0066).
	envJitter := os.Getenv("SOVEREIGN_SWEEP_PHASE_JITTER") == "1"
	if envJitter {
		cfg.sweepPhaseJitterEnabled = true
	}
	gossiper.SetSweepPhaseJitter(cfg.sweepPhaseJitterEnabled)
	// Log the selected mode at startup so environment-enabled offsets are
	// visible without inspecting process flags.
	if cfg.sweepPhaseJitterEnabled {
		log.Printf("sweep-phase-jitter: enabled (flag=%t env=%t); deterministic per-node offsets active (ADR-0066)", cfg.sweepPhaseJitterEnabled && !envJitter, envJitter)
	} else {
		log.Printf("sweep-phase-jitter: disabled; sweep ticks are phase-aligned")
	}
	// A durability bridge routes local InsertLocalEvents calls through PutLocal
	// so the mutation reaches the WAL before the local insert returns.
	if bridge != nil {
		gossiper.SetBridge(bridge)
		// Record peer-driven Lamport advances after accepted joins. Without a
		// record, recovery could reuse a dot counter and rebuild a different
		// Merkle root. RecordClockAdvance reads the engine clock at record time;
		// this can over-record the receiver's exact high-water (ADR-0013).
		recv.SetClockAdvanceRecorder(func(uint64) error {
			return bridge.RecordClockAdvance()
		})
	}

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			// SIGHUP reloads the leaf, CA pool, and configured CRL independently
			// (ADR-0035). Each replacement is atomic under the transport lock. A
			// failed reload leaves the previous material in use, and a leaf failure
			// does not prevent the CA or CRL from being updated.
			if err := tr.Reload(); err != nil {
				log.Printf("SIGHUP: certificate reload failed: %v; previous leaf remains in use", err)
				// Continue with CA and CRL reloads after a leaf failure.
			} else {
				log.Printf("SIGHUP: cert reloaded (new leaf live on next handshake)")
			}
			if err := tr.ReloadCA(); err != nil {
				log.Printf("SIGHUP: CA reload failed: %v; previous CA pool remains in use", err)
			} else {
				log.Printf("SIGHUP: CA pool reloaded (new trust root live on next handshake)")
			}
			if cfg.crlPath != "" {
				if err := tr.ReloadCRL(); err != nil {
					log.Printf("SIGHUP: CRL reload failed: %v; previous revoked-serial set remains in use", err)
				} else {
					log.Printf("SIGHUP: CRL reloaded (new revoked-serial set live on next handshake)")
				}
			}
		}
	}()

	// /livecheck and /metrics share one unauthenticated plain-HTTP debugging
	// server, separate from the peer data plane (ADR-0006, ADR-0008 §3). The
	// exporter uses a per-process Prometheus registry.
	metricsExp := metrics.NewExporter()
	// Count each executed sweep round before SweepLoop starts.
	gossiper.SetRoundReporter(metricsExp.Recorder().IncGossipRound)
	// Expose secondary-index health through gauges evaluated at scrape time.
	// Disabled nodes do not register these series.
	if cfg.secondaryIndexEnable {
		reg := metricsExp.Registry()
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sovereign_secondary_index_entities",
			Help: "Distinct entities currently held by the secondary index (--secondary-index).",
		}, func() float64 { return float64(secondaryIndex.Stats().Entities) }))
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sovereign_secondary_index_tie_drops_total",
			Help: "Index records dropped by the MaxTieCells cap (the disclosed same-ns recall loss).",
		}, func() float64 { _, tie, _, _ := secondaryIndex.IndexHealth(); return float64(tie) }))
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sovereign_secondary_index_ceiling_drops_total",
			Help: "Index records dropped by the --secondary-index-max-entities ceiling (nonzero = the query tier refuses 503).",
		}, func() float64 { _, _, cd, _ := secondaryIndex.IndexHealth(); return float64(cd) }))
	}
	// Initialize OTel before constructing the Prometheus bridge (ADR-0026).
	// telemetry.Init rebuilds the package counters, and NewTelemetryBridge must
	// capture the rebuilt set. The bridge reads cumulative Counter.Value results;
	// OTel callbacks export deltas through lastReported to a separate log
	// destination. With OTel disabled, the nil-Meter fallback leaves the bridge
	// as the only exporter.
	otelShutdown, otelErr := armOTel(cfg.otelEnabled, hex.EncodeToString(nodeID[:]), cfg.otelInterval)
	if otelErr != nil {
		log.Printf("sovereign-node: OTel initialization failed: %v; OTel export disabled, prometheus bridge unaffected", otelErr)
	}
	defer otelShutdown(context.Background())
	// NewTelemetryBridge adapts the internal/telemetry LongAdder counters to
	// cumulative Prometheus series on the same registry as the Recorder's
	// sovereign_* metrics (ADR-0023). It reads Counter.Value and never advances
	// the OTel lastReported state. Register it before the HTTP server starts.
	telemetryBridge := metrics.NewTelemetryBridge()
	metricsExp.Registry().MustRegister(telemetryBridge)
	metricsSrv := startLivecheck(cfg.metricsAddr, nodeID, peers, metricsExp, gossiper, bridge, bootWitness, engine)
	defer metricsSrv.Shutdown(context.Background())

	// The loopback pprof listener allows profile capture without stopping the
	// process. It is separate from the metrics listener, and a bind failure only
	// disables profiling; the node continues without it.
	pprofSrv, pprofErr := startPprof(pprofBindAddr(cfg.metricsAddr, cfg.pprofAddr))
	if pprofErr != nil {
		log.Printf("pprof: unavailable (%v); profile capture disabled on this node", pprofErr)
	} else {
		defer pprofSrv.Shutdown(context.Background())
	}

	// --control-addr enables a separate JSON-over-mTLS listener for /v1 routes.
	// It uses the peer trust configuration and TLS 1.3 but has its own HTTP
	// server, independent of the frame accept loop and plain-HTTP metrics port
	// (ADR-0006, ADR-0011 §3). The empty default disables the client API.
	var controlSrv *http.Server
	if cfg.controlAddr != "" {
		controlSrv = startControlPort(cfg.controlAddr, tr, gossiper, nodeID, peers, metricsExp, queryResolver, cfg.secondaryIndexEnable)
		defer controlSrv.Shutdown(context.Background())
	}

	// Open the TLS peer listener after the optional diagnostic and control
	// services have been configured.
	ln, err := tr.Listen("tcp", cfg.bind)
	if err != nil {
		return fmt.Errorf("tls listen %s: %w", cfg.bind, err)
	}
	defer ln.Close()
	log.Printf("sovereign-node: TLS 1.3 listener bound on %s (nodeID=%x)", cfg.bind, nodeID)
	if len(peers) > 0 {
		log.Printf("peers configured: %v", peers)
	} else {
		log.Printf("no peers configured (single-node)")
	}

	// Each accepted connection gets a goroutine that reassembles length-prefixed
	// frames and calls the receive gate. The caller observes HandleFrame's typed
	// verdict and elapsed time, leaving instrumentation outside the gate stack
	// (ADR-0008 §3).
	acceptCtx, acceptCancel := context.WithCancel(context.Background())
	defer acceptCancel()
	// Route tagged digest frames to the gossiper's DeliverDigest method through
	// a nil-safe adapter. The sink is ready before the accept loop starts; a nil
	// sink drops digests instead of sending them to the receive gate.
	var acceptDigester mesh.DigestSink
	if gossiper != nil {
		acceptDigester = digestDemuxer{g: gossiper}
	}
	go acceptLoopWithDigest(acceptCtx, ln, recv, metricsExp.Recorder(), acceptDigester, peerSet)

	// Start outbound dials and anti-entropy after the accept loop is serving.
	// Dialed connections use the same frame reader through PeerSet, so inbound
	// and outbound connections converge through the same receive path.
	meshCtx, meshCancel := context.WithCancel(context.Background())
	defer meshCancel()
	// applyProvisioning registers each directory entry under its real node ID,
	// including optional PQ keys and region tags, and returns the address-to-ID
	// map used for dialing (ADR-0040). This lets topology selection and Publish
	// use the same identity. An empty directory returns an empty map; malformed
	// or missing named files fail startup. Passing this node's ID skips its own
	// entry when all nodes share one peer directory.
	provisioned, provErr := applyProvisioning(gossiper, dir, topo, provCfgs, nodeID)
	if provErr != nil {
		return fmt.Errorf("--peer-dir: %w", provErr)
	}
	// Provisioning alone does not dial an address: the dial loop iterates only
	// --peers. Warn for directory entries omitted from that list because this
	// node will not publish to them, although they can still dial in. This is a
	// warning rather than an error so keys can be provisioned before dialing.
	if len(provisioned) > 0 {
		peersSet := make(map[string]bool, len(peers))
		for _, pa := range peers {
			peersSet[pa] = true
		}
		for paddr := range provisioned {
			if !peersSet[paddr] {
				log.Printf("sovereign-node: peer %s is in --peer-dir but not --peers; its keys and region are registered, but this node will not dial or publish to it. Add it to --peers or remove the directory entry.", paddr)
			}
		}
	}
	// Optional TLS-leaf reconciliation re-keys an unprovisioned connection from
	// the leaf CommonName to its real node ID. This fixes routing only; delta
	// verification still requires the peer's public key from --peer-dir.
	if err := startMeshBootDialAndSweep(meshCtx, cfg, peers, provisioned, topo, peerSet, gossiper); err != nil {
		return err
	}

	// Sample convergence lag, root equality, and ingest rate once per second.
	// SweepLoop writes the convergence seed; this goroutine only reads it and
	// the verdict counters, keeping gauge updates off the ingest path.
	go convergenceGaugePoller(meshCtx, gossiper, metricsExp)

	// Compact each entity's L0 files into L1 on a separate goroutine so a slow
	// merge does not block writes or gossip (ADR-0019). A nil compactor disables
	// scheduling when --lsm-root is absent. meshCtx cancellation stops downloads
	// during shutdown.
	go compactionSchedulerLoop(meshCtx, queryCompactor, queryResolver)
	if queryCompactor != nil {
		log.Printf("sovereign-node: L0→L1 compaction scheduler started, trigger=%d files/entity (read-L0/write-L1 background; no write-path lock)",
			queryCompactor.L0FilesPerEntityTrigger())
	}

	// The optional reaper deletes superseded L0 files after verifying their L1
	// replacements (ADR-0021). Its default five-minute cadence is slower than
	// compaction, and each sweep covers all entities. A nil reaper preserves the
	// old files. meshCtx cancellation stops its storage operations on shutdown.
	go reaperLoop(meshCtx, queryReaper, cfg.compactionReapInterval)
	if queryReaper != nil {
		log.Printf("sovereign-node: L0 reaper started, interval=%s (replacement L1 verified before deleting superseded L0 files)",
			cfg.compactionReapInterval)
	}

	// Block until SIGINT/SIGTERM. --selftest exits after a short window so
	// the gate can curl /livecheck.
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	if cfg.selftest {
		log.Printf("selftest: serving for 5s for /livecheck curl, then exiting")
		select {
		case <-time.After(5 * time.Second):
			log.Printf("selftest: 5s window elapsed, exiting OK")
			return nil
		case <-stopCh:
			return nil
		}
	}
	<-stopCh
	log.Printf("sovereign-node: shutdown signal received")
	return nil
}

// digestDemuxer adapts a Gossiper to mesh.DigestSink for accepted connections.
// Both dial-side and accept-side readers deliver tagged digest frames to the
// same DeliverDigest method, which wakes the corresponding sweep exchange. A
// nil Gossiper discards digests rather than passing them to the receive gate.
type digestDemuxer struct{ g *mesh.Gossiper }

func (d digestDemuxer) DeliverDigest(peerID [16]byte, frame []byte) {
	if d.g != nil {
		d.g.DeliverDigest(peerID, frame)
	}
}

// acceptLoopWithDigest serves each accepted connection in its own goroutine.
// A peer's digest can arrive on a connection it dialed to this node, so the
// accept-side reader needs the same DigestSink used by dialed connections.
func acceptLoopWithDigest(ctx context.Context, ln net.Listener, recv *receive.Receiver, rec *metrics.Recorder, digester mesh.DigestSink, peerSet *mesh.PeerSet) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v (listener closing)", err)
			return
		}
		go serveConnWithDigest(ctx, conn, recv, rec, digester, peerSet)
	}
}

// serveConnWithDigest reassembles frames and dispatches them for one
// connection. It records the receive gate's typed verdict and elapsed time in
// the caller, outside the gate implementation (ADR-0008 §3). Each connection
// processes one frame at a time. A nil Recorder disables observation.
func serveConnWithDigest(ctx context.Context, conn net.Conn, recv *receive.Receiver, rec *metrics.Recorder, digester mesh.DigestSink, peerSet *mesh.PeerSet) {
	defer conn.Close()
	// RegisterInbound decodes the peer's node ID from its TLS leaf and installs
	// a publishable handle for this accepted connection. It does not start a
	// second reader because this goroutine owns the read side. On exit,
	// ReleaseInboundConn releases only the handle installed here so a declined
	// duplicate cannot close another live connection.
	var inboundNodeID [16]byte
	var myPC *mesh.PeerConnHandle // registered handle for digest and challenge routing
	var declNodeID [16]byte
	var declPC *mesh.PeerConnHandle // challenge handle for a declined duplicate connection
	var tc *tls.Conn                // serving connection used for challenge answers
	if t, ok := conn.(*tls.Conn); ok {
		tc = t
		if err := tc.Handshake(); err != nil {
			log.Printf("tls handshake from %s: %v", conn.RemoteAddr(), err)
			return
		}
		if peerSet != nil {
			// Release the exact handle returned by RegisterInbound. myPC is nil
			// after an identity decode failure or when a live connection already
			// exists. ReleaseInboundConn compares handles before closing, preventing
			// this goroutine from closing a connection it does not own. A declined
			// connection still serves inbound frames without a peers entry.
			inboundNodeID, myPC = peerSet.RegisterInbound(tc)
			defer peerSet.ReleaseInboundConn(inboundNodeID, myPC)
			if myPC == nil {
				declNodeID, declPC = peerSet.ArmDeclinedInbound(tc)
			}
		}
	}
	fr := receive.NewFrameReader(conn) // reassemble length-prefixed frames
	// acceptLogLine limits diagnostic Accept logs; verdict metrics retain the
	// full per-delta count even when repeated relay arrivals are accepted.
	var acceptLogCount int64
	// Include digest delivery and receive-gate execution in accept-side busy
	// time. NoteDispatchBusy performs the enabled check; a nil peerSet skips it.
	noteServeBusy := func(t0 time.Time) {
		if peerSet != nil {
			peerSet.NoteDispatchBusy(mesh.L0ILoopServe, time.Since(t0).Nanoseconds())
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		frame, err := fr.ReadFrame() // reassemble one length-prefixed frame
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("frame read from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		// Every dispatch path records its busy interval before continuing.
		busyT0 := time.Now()
		// Digest and challenge frames are protocol control traffic, not CRDT
		// deltas, and do not enter the receive gate or its verdict metrics.
		// Challenges use the registered connection handle; declined connections
		// use the separate challenge handle armed above (ADR-0034, ADR-0068).
		if peerSet != nil && mesh.IsChallengeFrame(frame) {
			if myPC != nil {
				peerSet.HandleConnChallengeFrame(myPC, tc, frame)
			} else {
				peerSet.HandleDeclinedChallengeFrame(declPC, tc, frame)
			}
			noteServeBusy(busyT0)
			continue
		}
		if attribution.IsDigestFrame(frame) {
			// Deliver only on a connection whose key challenge succeeded. Use
			// the identity established by that connection rather than trusting
			// the sender field in the digest header. A declined simultaneous
			// dial uses the identity and handle from ArmDeclinedInbound; without
			// either, DigestConnVerified rejects the frame (ADR-0068).
			activePC := myPC
			activeID := inboundNodeID
			if activePC == nil {
				activePC = declPC
				activeID = declNodeID
			}
			if digester != nil && peerSet != nil && peerSet.DigestConnVerified(activePC) {
				digester.DeliverDigest(activeID, frame) // mesh.DigestSink -> Gossiper.DeliverDigest
			}
			noteServeBusy(busyT0)
			continue
		}
		// Dispatch on the frame magic. Batch envelopes use HandleBatchFrame,
		// hybrid envelopes use HandleHybridFrame, and other frames use
		// HandleFrame. verdict.Accepted is the number of deltas actually joined;
		// held batch elements do not increment the accept count (ADR-0010 §2).
		// Hybrid batches carry Ed25519 and ML-DSA-65 signatures over the same
		// 120-byte SHAKE256 pad (ADR-0037). Keep this accept-side dispatch order
		// aligned with mesh.DispatchFrame so inbound and dialed connections handle
		// the same envelope types. Use verdict.Accepted rather than the header's
		// batch count because held elements are not joined.
		start := time.Now()
		var verdict receive.AcceptVerdict
		var acceptedDeltas int
		if attribution.IsBatchFrame(frame) {
			verdict = recv.HandleBatchFrame(frame)
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = verdict.Accepted // excludes held batch elements
			}
		} else if attribution.IsHybridFrame(frame) {
			verdict = recv.HandleHybridFrame(frame)
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = verdict.Accepted
			}
		} else {
			verdict = recv.HandleFrame(frame)
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = verdict.Accepted // 1 on the per-frame path
			}
		}
		if rec != nil {
			// Record one timed observation per frame. Accepted batches add N-1
			// zero-duration observations so verdict totals count joined deltas.
			// Every dropped frame contributes one observation, regardless of any
			// batch count in its header.
			rec.RecordIngest(time.Since(start), verdict.Verdict)
			if acceptedDeltas > 1 {
				for i := 1; i < acceptedDeltas; i++ {
					rec.RecordIngest(0, verdict.Verdict)
				}
			}
		}
		if verdict.Verdict == receive.Accept {
			// Report the joined-delta count so an accepted frame that joined no
			// entries is distinguishable from a successful batch. acceptLogLine
			// limits these diagnostics to the initial window and periodic samples.
			acceptLogCount++
			if acceptLogLine(acceptLogCount) {
				log.Printf("accept from %s: verdict=Accept acceptedDeltas=%d (accept #%d on this conn)", conn.RemoteAddr(), acceptedDeltas, acceptLogCount)
			}
			noteServeBusy(busyT0)
			continue
		}
		log.Printf("frame from %s: %s (reason: %v)", conn.RemoteAddr(), verdict.Verdict, verdict.Reason)
		noteServeBusy(busyT0)
	}
}

// livecheckBody is the JSON served by /livecheck.
type livecheckBody struct {
	NodeID     string   `json:"node_id"`
	Peers      []string `json:"peers"`
	TLSVersion string   `json:"tls_version"`
}

// convergenceGaugePoller updates convergence lag, root equality, and ingest
// rate once per second without instrumenting frame handling. The roots-equal
// gauge compares the current local root with the gossiper's last converged
// root; it is a binary indicator, not a quorum decision (ADR-0008).
func convergenceGaugePoller(ctx context.Context, gossiper *mesh.Gossiper, exp *metrics.Exporter) {
	if gossiper == nil || exp == nil {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			exp.SetConvergenceLag(gossiper.ConvergenceLag())
			// roots-equal: the local engine's current root vs the last
			// converged root. Equal => the mesh is at the converged state
			// right now (1.0); diverged => 0.0.
			curRoot := gossiper.CurrentRoot() // read the engine root from its shards
			exp.SetConvergenceRootsEqual(curRoot == gossiper.LastConvergedRoot())
			// ingest pps: the verdict-counter delta over the 1s interval.
			exp.SetIngestPPS(exp.ObserveVerdictDelta(time.Now()))
		}
	}
}

// acceptLogLine reports whether the nth accepted frame on a connection should
// produce a diagnostic log. The first eight aid startup diagnosis and every
// 1024th provides a liveness sample; verdict metrics retain the full count.
func acceptLogLine(n int64) bool {
	return n <= 8 || n%1024 == 0
}

// startLivecheck serves /livecheck, /metrics, and optional diagnostics on one
// unauthenticated plain-HTTP server, separate from the peer data plane. The
// caller owns the returned server's shutdown.
func startLivecheck(addr string, nodeID [16]byte, peers []string, exp *metrics.Exporter, gossiper *mesh.Gossiper, bridge *durability.Bridge, bootWitness *durability.RecoveryWitness, engine *eng.DeltaCRDTEngine) *http.Server {
	// bootWitness was captured during recovery, before this server started;
	// scrapes do not recompute it. bridge supplies the arena high-water mark.
	// In-memory nodes have neither and report witness_present=false.

	mux := http.NewServeMux()
	mux.HandleFunc("/livecheck", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := livecheckBody{
			NodeID:     hex.EncodeToString(nodeID[:]),
			Peers:      peers,
			TLSVersion: "TLS1.3",
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	// The exporter handler uses the per-process registry rather than the
	// Prometheus default registerer, with metadata available from cold start.
	if exp != nil {
		mux.Handle("/metrics", exp.Handler())
	}
	// /debug/memstats separates live Go heap, retained heap, runtime address
	// space, goroutines, and mesh cache memory for RSS diagnosis. The mesh totals
	// account for payload and relay caches, while touched off-heap arena pages
	// remain outside Go's heap statistics.
	//
	// runtime.ReadMemStats runs only on a scrape and briefly stops the world, so
	// this is a pull endpoint rather than a periodic sampler. It shares the
	// existing diagnostics listener and adds no background goroutine.
	mux.HandleFunc("/debug/memstats", func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		// CacheStats reads counters maintained at retain, record, and delete;
		// it does not walk the cache maps. The four byte totals form
		// mesh_cache_bytes. A nil gossiper reports zero cache terms.
		cs := gossiper.CacheStats()
		resp := map[string]any{
			"node_id":                   hex.EncodeToString(nodeID[:]),
			"heap_alloc":                m.HeapAlloc,
			"heap_inuse":                m.HeapInuse,
			"heap_idle":                 m.HeapIdle,
			"heap_released":             m.HeapReleased,
			"heap_objects":              m.HeapObjects,
			"stack_inuse":               m.StackInuse,
			"sys":                       m.Sys,
			"num_gc":                    m.NumGC,
			"goroutines":                runtime.NumGoroutine(),
			"mesh_cache_bytes":          cs.PayloadBytes + cs.RelayFrameBytes + cs.RelayBatchForwardBytes + cs.RelayBatchReverseBytes,
			"payload_entries":           cs.PayloadEntries,
			"payload_bytes":             cs.PayloadBytes,
			"relay_frames":              cs.RelayFrames,
			"relay_frame_bytes":         cs.RelayFrameBytes,
			"relay_batch_forward":       cs.RelayBatchForward,
			"relay_batch_forward_bytes": cs.RelayBatchForwardBytes,
			"relay_batch_reverse":       cs.RelayBatchReverse,
			"relay_batch_reverse_bytes": cs.RelayBatchReverseBytes, // fourth mesh cache byte total
		}
		// Recovery facts belong in this boot-time diagnostic record rather than
		// cumulative metrics. Durable nodes always have a bridge, but recovery
		// may return a nil witness; guard the two independently.
		if bridge != nil {
			resp["recovery_arena_high_water_bytes"] = bridge.LastCheckpointArenaHighWater()
		}
		if bootWitness != nil {
			resp["witness_present"] = true
			resp["recovery_bounded"] = bootWitness.Bounded
			resp["recovery_snapshot_lamport"] = bootWitness.SnapshotLamportHigh
			resp["recovery_replayed_records"] = bootWitness.ReplayedRecords
			resp["recovery_checkpoint_seq"] = bootWitness.CheckpointSeq
			resp["recovery_local_phantoms"] = bootWitness.LocalPhantomsRejected
			resp["recovery_exact_wal_fallback"] = bootWitness.ExactWALFallback
			resp["recovery_fallback_reason"] = bootWitness.FallbackReason
			resp["recovery_legacy_records"] = bootWitness.LegacyRecords
			resp["recovery_holes_repaired"] = bootWitness.HolesRepaired
			// False means recovery did not perform the pre-tail root and
			// fingerprint checks (ADR-0045 §5.1).
			resp["recovery_integrity_checks_armed"] = bootWitness.IntegrityChecksArmed
			resp["recovery_legacy_checkpoint"] = bootWitness.LegacyCheckpoint
			// Record whether the post-tail root and sequence-contiguity checks
			// ran, along with any ClockHigh clamp applied during recovery.
			resp["recovery_post_tail_root_armed"] = bootWitness.PostTailRootArmed
			resp["recovery_seq_contiguity_verified"] = bootWitness.SeqContiguityVerified
			resp["recovery_records_verified"] = bootWitness.RecordsVerified
			resp["recovery_clockhigh_clamped"] = bootWitness.ClockHighClamped
			resp["recovery_clockhigh_raw"] = bootWitness.ClockHighRaw
		} else {
			resp["witness_present"] = false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	// SOVEREIGN_STATE_FP_DEBUG=1 exposes a read-only state fingerprint and
	// entry count. The Merkle root covers dots, while the fingerprint also
	// checks the associated state. StateFingerprint takes its own EBR pin and
	// does not grow the arena. The route is absent unless explicitly enabled.
	if os.Getenv("SOVEREIGN_STATE_FP_DEBUG") == "1" && engine != nil {
		mux.HandleFunc("/debug/state-fingerprint", func(w http.ResponseWriter, r *http.Request) {
			fp := durability.StateFingerprint(engine)
			body := map[string]any{
				"node_id":           hex.EncodeToString(nodeID[:]),
				"state_fingerprint": hex.EncodeToString(fp[:]),
				// Include the entry count alongside the hash so receivers expose
				// how much state the fingerprint covers.
				"state_entry_count": durability.StateEntryCount(engine),
			}
			// SOVEREIGN_TEST_FAULT_FINGERPRINT=oracleblind substitutes the
			// dot-only root as a negative control for fingerprint checking.
			if os.Getenv("SOVEREIGN_TEST_FAULT_FINGERPRINT") == "oracleblind" {
				root := engine.MerkleRootFromShards()
				body["state_fingerprint"] = hex.EncodeToString(root[:])
				body["neutered"] = "oracleblind"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		})
		log.Printf("state-fp: /debug/state-fingerprint enabled (SOVEREIGN_STATE_FP_DEBUG=1)")
	}
	// SOVEREIGN_RESPOND_INDEG_DEBUG=1 exposes RespondIndegSnapshot: whether
	// tracking is enabled, arrival count, the 17-bucket occupancy histogram,
	// and its cap. Otherwise the route is absent.
	if os.Getenv("SOVEREIGN_RESPOND_INDEG_DEBUG") == "1" && gossiper != nil {
		mux.HandleFunc("/debug/responder-indegree", func(w http.ResponseWriter, r *http.Request) {
			snap := gossiper.RespondIndegSnapshot()
			body := map[string]any{
				"node_id":        hex.EncodeToString(nodeID[:]),
				"armed":          snap.Armed,
				"arrivals":       snap.Arrivals,
				"occupancy_hist": snap.Hist,
				"cap":            snap.Cap,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		})
		log.Printf("respond-indeg: /debug/responder-indegree enabled (SOVEREIGN_RESPOND_INDEG_DEBUG=1)")
	}
	// Either digest debug variable enables /debug/heartbeat. It reports the
	// last round's exchange and response byte counts, cumulative exchange
	// totals, and send/arrival timing and busy-time diagnostics directly from
	// the gossiper. Without either variable the route is absent.
	if (os.Getenv("SOVEREIGN_DIGEST_LATENCY_DEBUG") == "1" || os.Getenv("SOVEREIGN_EXCH_DEBUG") == "1") && gossiper != nil {
		mux.HandleFunc("/debug/heartbeat", func(w http.ResponseWriter, r *http.Request) {
			snap := gossiper.DigestLatencyStats()
			l0 := gossiper.L0IStats()
			body := map[string]any{
				"node_id":               hex.EncodeToString(nodeID[:]),
				"last_round":            snap.LastRound,
				"last_exch_done":        snap.LastExchDone,
				"last_exch_drained":     snap.LastExchDrained,
				"last_resp_delta_bytes": snap.LastRespDeltaBytes,
				"exch_completed_total":  snap.ExchCompletedTotal,
				"exch_drained_total":    snap.ExchDrainedTotal,
				"resp_bytes_total":      snap.RespBytesTotal,
				"stamp_broken_total":    snap.StampBrokenTotal,
				"last_ship_bytes":       l0.LastShipBytes,
				"last_digest_req_bytes": l0.LastDigestReqBytes,
				"send_done_count":       l0.SendDoneCount,
				"send_done_span_ns":     l0.SendDoneSpanNs,
				"send_done_max_ns":      l0.SendDoneMaxNs,
				"arrive_count":          l0.ArriveCount,
				"arrive_span_ns":        l0.ArriveSpanNs,
				"arrive_max_ns":         l0.ArriveMaxNs,
				"arrive_broken_total":   l0.ArriveBrokenTotal,
				"holl_read_busy_ns":     l0.ReadBusyNs,
				"holl_read_max_ns":      l0.ReadBusyMaxNs,
				"holl_serve_busy_ns":    l0.ServeBusyNs,
				"holl_serve_max_ns":     l0.ServeBusyMaxNs,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		})
		log.Printf("digest-latency: /debug/heartbeat enabled (SOVEREIGN_DIGEST_LATENCY_DEBUG=1 or SOVEREIGN_EXCH_DEBUG=1)")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("/livecheck + /metrics control surface on %s (plain HTTP, ops debug)", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("/livecheck: %v", err)
		}
	}()
	return srv
}

// pprofBindAddr resolves a loopback-only profiling address. It passes the
// loopback literal to net.JoinHostPort regardless of the configured host.
// An explicit --pprof-addr supplies the port; otherwise it uses the metrics
// port plus 1000, falling back to the default metrics port's derived address.
func pprofBindAddr(metricsAddr, pprofFlag string) string {
	const fallback = "127.0.0.1:8431" // 7431 (default --metrics-addr) + 1000
	port := 0
	if p := strings.TrimSpace(pprofFlag); p != "" {
		// Accept a port or host:port and discard the host so the listener
		// cannot be moved off loopback by configuration.
		if _, hp, err := net.SplitHostPort(p); err == nil {
			p = hp
		}
		if pn, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && pn > 0 {
			port = pn
		}
	}
	if port == 0 && metricsAddr != "" {
		if _, mp, err := net.SplitHostPort(metricsAddr); err == nil {
			if mn, err := strconv.Atoi(strings.TrimSpace(mp)); err == nil && mn > 0 {
				port = mn + 1000
			}
		}
	}
	if port == 0 {
		return fallback
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// startPprof serves goroutine, mutex, and block profiles on a dedicated
// loopback listener without interrupting the process. Mutex and block sampling
// are controlled separately by --diag-profile because collection adds runtime
// overhead. A bind error disables profiling without stopping the node. Addr is
// the actual bound address, including an ephemeral port selected with :0.
func startPprof(addr string) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	// Bind before starting Serve so collisions return an error and :0 resolves
	// to the actual port for the caller.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("pprof: bind %s: %w", addr, err)
	}
	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("pprof: serving /debug/pprof on %s (loopback only)", ln.Addr())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pprof: %v", err)
		}
	}()
	return srv, nil
}

// startControlPort serves JSON /v1 routes on a TLS listener separate from the
// peer listener. tr.ServerConfig requires a client certificate and TLS 1.3.
// Client HTTP requests and peer length-prefixed frames therefore use different
// accept loops (ADR-0011 §3, §6). The injected metrics handler avoids coupling
// pkg/mesh to pkg/metrics; the plain-HTTP metrics listener remains independent.
func startControlPort(addr string, tr *transport.TLSConnections, gossiper *mesh.Gossiper, nodeID [16]byte, peers []string, exp *metrics.Exporter, resolver *database.Resolver, secondaryIndex bool) *http.Server {
	ln, err := tls.Listen("tcp", addr, tr.ServerConfig())
	if err != nil {
		log.Fatalf("control-addr: tls listen %s: %v", addr, err)
	}
	var metricsHandler http.Handler
	if exp != nil {
		metricsHandler = exp.Handler()
	}
	// A nil resolver leaves /v1/query registered but unavailable, returning 503
	// rather than 404 (ADR-0017 §3). SetResolver keeps query construction
	// separate from NewControlServer.
	cs := mesh.NewControlServer(gossiper, nodeID, peers, metricsHandler)
	cs.SetResolver(resolver)
	// The same flag controls cross-entity query routes and h3_index acceptance.
	cs.SetSecondaryIndex(secondaryIndex)
	srv := &http.Server{
		Handler:           cs.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("control port on %s (JSON-over-mTLS, TLS 1.3, client cert required)", addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("control-addr: %v", err)
		}
	}()
	return srv
}

// mintSelftestCerts creates a development CA and leaf in a temporary
// directory. It returns their PEM paths and the CA, which the self-test's
// rotation manager reuses for replacement leaves.
func mintSelftestCerts(nodeID [16]byte) (certPath, keyPath, caPath string, ca *crypto.MeshCA, err error) {
	dir, err := os.MkdirTemp("", "sovereign-selftest-")
	if err != nil {
		return "", "", "", nil, err
	}
	ca, err = crypto.NewMeshCA()
	if err != nil {
		return "", "", "", nil, err
	}
	caPath, err = ca.WriteCAPEM(dir)
	if err != nil {
		return "", "", "", nil, err
	}
	leaf, err := ca.IssueLeaf(hex.EncodeToString(nodeID[:]))
	if err != nil {
		return "", "", "", nil, err
	}
	certPath, keyPath, err = leaf.WritePEM(dir)
	if err != nil {
		return "", "", "", nil, err
	}
	return certPath, keyPath, caPath, ca, nil
}

// buildRotationMinter returns the callback StartRotationManager invokes when
// the live leaf enters its rotation window. The callback issues a new Ed25519
// leaf with the same node ID CommonName, writes its PEM files, and reloads the
// transport for subsequent handshakes.
//
// Only the self-test has an in-process CA. A nil CA returns an error; rotating
// externally supplied PEM files requires a transport.RotationMinter backed by
// an external issuer (ADR-0035).
func buildRotationMinter(ca *crypto.MeshCA, nodeID [16]byte, certPath, keyPath string, tr *transport.TLSConnections) (transport.RotationMinter, error) {
	if ca == nil {
		return nil, fmt.Errorf("--cert-rotation-enable requires an in-process CA; --selftest mints one, while PEM-only setups need an external transport.RotationMinter (ADR-0035)")
	}
	nodeIDHex := hex.EncodeToString(nodeID[:])
	return func() (*big.Int, error) {
		leaf, err := ca.IssueLeaf(nodeIDHex)
		if err != nil {
			return nil, fmt.Errorf("rotation IssueLeaf: %w", err)
		}
		// WritePEM creates cert.pem and key.pem in certPath's directory. The
		// self-test uses those exact paths for the transport, so Reload parses
		// the replacement leaf.
		dir := filepath.Dir(certPath)
		newCert, newKey, err := leaf.WritePEM(dir)
		if err != nil {
			return nil, fmt.Errorf("rotation WritePEM: %w", err)
		}
		// These fixed names are why this helper supports the self-test layout,
		// not arbitrary operator-supplied PEM paths.
		_ = newCert
		_ = newKey
		if err := tr.Reload(); err != nil {
			return nil, fmt.Errorf("rotation Reload: %w", err)
		}
		return leaf.LeafCert().SerialNumber, nil
	}, nil
}

// buildNodeIdentity derives the CRDT-delta signing identity. A configured
// --identity-seed must derive engineNodeID from the public key's first 16
// bytes; a mismatch is fatal. Without a seed, a random signing identity is
// created and its derived node ID can differ from the engine's ID. The startup
// log exposes both values; deterministic identity requires --identity-seed.
//
// Hybrid signing uses NewNodeIdentityHybrid to derive Ed25519 and ML-DSA-65
// keys from the same seed (ADR-0037). Otherwise NewNodeIdentity creates only
// the classical keypair. The caller registers any PQ public key for verification.
func buildNodeIdentity(cfg *nodeConfig, engineNodeID [16]byte) *mesh.NodeIdentity {
	newIdent := mesh.NewNodeIdentity
	if cfg.hybridSignEnable {
		newIdent = mesh.NewNodeIdentityHybrid
	}
	if cfg.identitySeed == "" {
		seed := make([]byte, 32)
		if _, err := cryptorand.Read(seed); err != nil {
			log.Fatalf("identity: mint seed: %v", err)
		}
		ident, err := newIdent(seed)
		if err != nil {
			log.Fatalf("identity: %v", err)
		}
		log.Printf("identity: minted random signing seed; derived nodeID=%x (engine nodeID=%x); deterministic identity requires --identity-seed", ident.NodeID, engineNodeID)
		return ident
	}
	raw, err := hex.DecodeString(cfg.identitySeed)
	if err != nil {
		log.Fatalf("--identity-seed: %v", err)
	}
	ident, err := newIdent(raw)
	if err != nil {
		log.Fatalf("--identity-seed: %v", err)
	}
	if ident.NodeID != engineNodeID {
		log.Fatalf("--identity-seed derives nodeID %x != --node-id %x; the mesh's signed-envelope seam requires the engine's localNodeID to equal the signed OriginNodeID", ident.NodeID, engineNodeID)
	}
	return ident
}

// compactionSchedulerLoop runs an L0-to-L1 merge every 30 seconds for each
// entity at its file-count trigger (ADR-0019). It does not use the CRDT or WAL
// write path and stops on context cancellation. A nil compactor disables it.
// runCompactionSweep also uses the resolver's observed transaction-time
// frontier to update the prune horizon before compacting (ADR-0027).
func compactionSchedulerLoop(ctx context.Context, compactor *database.L1Compactor, resolver *database.Resolver) {
	if compactor == nil {
		return
	}
	const interval = 30 * time.Second // compaction cadence; independent of the write path
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCompactionSweep(ctx, compactor, resolver)
		}
	}
}

// runCompactionSweep discovers entity hashes from l0/{hex(hash8)}/ keys and
// compacts each entity at or above its trigger. An entity failure is logged and
// does not stop the remaining entities.
//
// InferHorizon first computes max(operatorFloor, observedFrontier-backoff) and
// advances the compactor's horizon monotonically (ADR-0027). A nil resolver
// leaves the configured floor unchanged. Disabling pruning still permits the
// horizon and gauges to advance, but DominancePrune does not drop rows.
func runCompactionSweep(ctx context.Context, compactor *database.L1Compactor, resolver *database.Resolver) {
	// InferHorizon owns the frontier read, monotone horizon update, and related
	// telemetry in internal/database. This command only supplies the resolver.
	compactor.InferHorizon(resolver)
	// List every l0/ key without a cap to count each entity's L0 files and
	// discover the entity set. The bucket "local" is ignored by LocalFS; the
	// prefix "l0/" scopes to the per-entity Arrow index.
	l0Keys, err := compactor.ListL0Keys(ctx, "l0/")
	if err != nil {
		log.Printf("compaction sweep: list l0/: %v", err)
		return
	}
	if len(l0Keys) == 0 {
		return
	}
	// Group L0 keys by their entity prefix (l0/{hex8}/) and count.
	trigger := compactor.L0FilesPerEntityTrigger()
	type entityBucket struct {
		hash8 [8]byte
		count int
	}
	buckets := make(map[string]*entityBucket)
	var order []string
	for _, k := range l0Keys {
		// key form: l0/{hex8}/{sysNs}.arrow → prefix l0/{hex8}/
		if len(k) < len("l0/")+16+1 || k[:3] != "l0/" || k[19] != '/' {
			continue
		}
		hexSeg := k[3:19]
		b, ok := buckets[hexSeg]
		if !ok {
			b = &entityBucket{}
			var h [8]byte
			_, err := hexDecode8Into(h[:], hexSeg)
			if err != nil {
				continue
			}
			b.hash8 = h
			buckets[hexSeg] = b
			order = append(order, hexSeg)
		}
		b.count++
	}
	for _, hexSeg := range order {
		b := buckets[hexSeg]
		if b.count < trigger {
			continue
		}
		if err := ctx.Err(); err != nil {
			return
		}
		// The L0 key contains a one-way entity hash, not the entity ID needed
		// for Filter4. CompactionByHash8 therefore uses hash-based filters;
		// per-entity L0 file construction keeps other entities' rows out.
		res, err := compactor.CompactionByHash8(ctx, b.hash8)
		if err != nil {
			log.Printf("compaction sweep: entity %x: %v", b.hash8, err)
			continue
		}
		if res != nil && !res.AlreadyMoved {
			log.Printf("compaction sweep: entity %x merged %d L0 files → L1 %s (%d rows preserved)", b.hash8, len(res.L0Files), res.L1Key, res.Rows)
		}
	}
}

// hexDecode8Into decodes a 16-char lowercase hex string into 8 bytes.
func hexDecode8Into(dst []byte, hex string) (int, error) {
	if len(hex) != 16 {
		return 0, fmt.Errorf("hex: want 16 chars, got %d", len(hex))
	}
	for i := 0; i < 8; i++ {
		hi := hexNibble(hex[2*i])
		lo := hexNibble(hex[2*i+1])
		if hi < 0 || lo < 0 {
			return 0, fmt.Errorf("hex: invalid char")
		}
		dst[i] = byte(hi<<4 | lo)
	}
	return 8, nil
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// reaperLoop periodically asks database.L0Reaper to delete superseded L0
// files after their L1 replacements are verified (ADR-0021). A nil reaper keeps
// all L0 files. The default five-minute interval is slower than compaction and
// amortizes manifest listing and L1 checks across more merges. Context
// cancellation stops the loop during shutdown.
func reaperLoop(ctx context.Context, reaper *database.L0Reaper, interval time.Duration) {
	if reaper == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Minute // nonpositive values use the default
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runReaperSweep(ctx, reaper)
		}
	}
}

// runReaperSweep performs one cross-entity reap and logs its result counts.
// Reap reports per-manifest orphan and deletion failures in ReapResult and logs
// their details, so this function only emits the summary.
func runReaperSweep(ctx context.Context, reaper *database.L0Reaper) {
	if reaper == nil {
		return
	}
	res := reaper.Reap(ctx)
	log.Printf("sovereign-node: L0 reaper sweep: manifests reaped=%d, L0 files deleted=%d, skipped missing or invalid L1=%d, delete errors=%d",
		res.ReapedManifests, res.ReapedL0, res.SkippedOrphan, res.SkippedError)
}

// engineHAMTAdapter implements database.LiveSource at the command boundary,
// where the concrete engine is available and internal/database does not need to
// import pkg/sync. It lets query results include recent local writes before the
// next checkpoint (ADR-0032).
//
// LiveRead applies the transaction-time visibility bound. The Resolver applies
// point or range selection and dominance to the returned entries. Temporal and
// H3 fields map directly; Payload remains nil because CRDTEntry stores only a
// payload digest, matching the durable index representation.
type engineHAMTAdapter struct {
	engine *eng.DeltaCRDTEngine
}

// LiveRead returns entries for entityID whose SystemTime is at most txTimeNs.
// PointGet holds its own EBR pin while copying the entity's entries out of the
// HAMT, so the returned slice is caller-owned and does not retain arena views.
// An empty result means no live entry is visible and is not an error.
func (a *engineHAMTAdapter) LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]database.LiveEvent, error) {
	if a == nil || a.engine == nil {
		return nil, nil
	}
	// PointGet reads only the entity's shard, avoiding construction of a full
	// merged HAMT on each query. Its copy is safe to use after the EBR pin ends.
	entries := a.engine.PointGet(entityID)
	out := make([]database.LiveEvent, 0, len(entries))
	for i := range entries {
		e := entries[i]
		// The visibility bound includes entries whose SystemTime equals txTimeNs,
		// matching the durable Arrow scan's transaction-time filter.
		if e.SystemTime > txTimeNs {
			continue
		}
		out = append(out, database.LiveEvent{
			SystemTime:     e.SystemTime,
			ValidTimeStart: e.ValidTimeStart,
			ValidTimeEnd:   e.ValidTimeEnd,
			AssertionTime:  e.AssertionTime,
			H3Index:        e.H3Index,
			PayloadDigest:  e.PayloadDigest,
			// Payload stays nil because CRDTEntry carries only PayloadDigest.
		})
	}
	return out, nil
}
