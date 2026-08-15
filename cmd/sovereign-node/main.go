// Command sovereign-node is the FIRST production binary of the Sovereign
// Engine. It binds a TLS 1.3 listener (the Day-1 encrypted pipe), constructs
// the FROZEN δ-CRDT engine + the receive gate stack, and drives the
// length-prefixed frame reassembler into Receiver.HandleFrame per accepted
// connection. It also serves a plain-HTTP /livecheck control surface.
//
// Day 1 scope (per the Day-1 executor prompt): the accept loop runs and
// serves /livecheck; the dial loop + gossip sweep are Day 2 (the --peers
// flag is parsed and logged, NOT dialed this track). The /metrics Prometheus
// surface is Day 3; AF_XDP is Day 9; the eBPF --steering flag is Day 8. This
// binary is the encryption ground — every subsequent day's wire is encrypted
// by default because this binary landed.
//
// Symbol gate (every constructor below is grep-verified against the real
// package APIs; see ADR-0006 §Symbol Gate):
//
//	eng.NewDeltaCRDTEngine(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*eng.DeltaCRDTEngine, error)  // pkg/sync/crdt.go:244
//	clock.NewIngressHLCScalarCap(clock clock.WallClock, engine clock.LogicalAdvancer) *clock.IngressHLCScalarCap    // pkg/clock/admission.go:72  (NO epsilon arg; CONSTRAINT Z is a compile-time const)
//	admission.NewPeerBucket() *admission.PeerBucket                                                                  // pkg/admission/ewma.go:150  (zero args)
//	identity.NewDirectory() *identity.Directory                                                                     // pkg/identity/directory.go:47  (zero args)
//	receive.NewReceiver(bucket, cap, wallClock, dir, engine, budget) *receive.Receiver                              // pkg/receive/receiver.go:173
//	receive.NewFrameReader(r io.Reader) *receive.FrameReader                                                         // pkg/receive/receiver.go:474
//	(*receive.FrameReader).ReadFrame() ([]byte, error)                                                               // pkg/receive/receiver.go:486
//	(*receive.Receiver).HandleFrame(frameBytes []byte) receive.AcceptVerdict                                         // pkg/receive/receiver.go:350
//
// The DeltaCRDTEngine satisfies clock.LogicalAdvancer via its pointer
// receiver method AdvanceLamportTo(uint64) (pkg/sync/crdt.go:1639); the
// engine value is passed as the advancer arg.
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
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/durability"
	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/mesh"
	"github.com/hr18vk/supremum/pkg/metrics"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"github.com/hr18vk/supremum/pkg/transport"
)

// defaultArenaSize is the off-heap HAMT arena size for the engine. It
// matches the convention used across pkg/sync tests (64 MiB); it is
// overridable via --arena-mib.
const defaultArenaSize uintptr = 64 * 1024 * 1024

// defaultAdmissionBudget is the receive admission budget in nanoseconds that
// the 3.2 MaxHopsForBudget transform converts to a max hop-count. It is
// INJECTED, never baked into the gate (the forbidden-budget tooth,
// receiver.go:173 doc). Overridable via --admission-budget-ns.
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
	// Day 29 (ADR-0034): --stratified-anti-entropy (opt-IN, default false).
	// OFF keeps the sweep byte-identical to HEAD's oversend path; ON switches to
	// the M3 two-phase digest-exchange (the minimal-delta proportional to |A−B|
	// instead of the full set). See the flag help.
	stratifiedAntiEntropy bool
	// Day 8 durability: --wal-path empty (default) = in-memory research mode =
	// Day-7 back-compat (the silicon bench path UNTOUCHED). Durability is OPT-IN,
	// never claimed by default. When set, the node boots from the WAL via
	// RecoverEngine and the origin write path fsyncs to it.
	walPath               string
	walCheckpointInterval uint64

	// Day 11 bounded recovery: --lsm-root is the directory for the dot-bearing
	// recovery snapshot ("ckpt/<LamportHigh>") + the Arrow query index ("l0/").
	// When non-empty (and --wal-path is set), RecoverEngineWithSnapshot + the
	// Bridge's SetSnapshotter bound recovery to O(post-checkpoint). Empty (or
	// --wal-path empty) = the back-compat full-replay path (Day-8/8.5).
	lsmRoot string

	// Day 15 (ADR-0020): the Level-2 superseded-row prune knobs — the
	// transaction-time GC horizon T_gc an operator sets to opt the compaction
	// merge into dropping provably-dead rows. --compaction-prune-enable=false
	// (the DEFAULT) -> Preserve-All (byte-identical Day-14 behavior); the engine
	// NEVER auto-prunes. --compaction-prune-enable=true WITHOUT a positive
	// --compaction-prune-horizon-ns is SILENTLY WRONG (the §0.4(ii) txTime-gap
	// class); NewL1Compactor traps it with a WARN + coerce-to-Preserve-All.
	compactionPruneEnable  bool
	compactionPruneHorizon int64
	// Day 22 (ADR-0027): the T_gc auto-inference backoff — how far behind the
	// observed live-query txTime frontier the effective DominancePrune floor
	// sits. The inferrer computes effective = max(operatorFloor, observedFrontier
	// - backoff); the backoff tolerates forensic queries `backoff` into the
	// recent past, so a burst of stale-txTime queries does NOT collapse the
	// floor. The operator's role moves from "guess the frontier" (Day-15 static
	// horizon) to "set the safety floor + the backoff window" (the §0.a knob-
	// promotion). --compaction-prune-backoff-ns wires this; default 5m (a
	// HONEST conservative default — see the flag help). 0 = track the frontier
	// directly (no backoff); the operator floor still backstops it.
	compactionPruneBackoff time.Duration

	// Day 16 (ADR-0021): the L0 reaper knobs. The reaper reclaims the
	// manifest-listed superseded L0 files (the cross-entity disk leak ADR-0020
	// §6c deferred) AFTER verifying the L1 still exists — the Stage C safety
	// guard. --compaction-reap-enable=false (the DEFAULT) -> byte-identical
	// Day-15 behavior: the superseded L0 files STAY on disk as the crash-
	// recovery backstop (reap OFF = the honest backstop-forever posture). The
	// reaper MUST NEVER be auto-ON: the Stage C L1-exists check IS the safety
	// constraint, and a storage layer that EVER reports a present L1 as missing
	// would ALSO be one the compactor trusted to WRITE the L1 — the operator
	// turns the reaper on ONLY once they trust their storage. --compaction-
	// reap-interval is the sweep cadence (default 5m, deliberately slower than
	// compaction's 30s — the superseded L0s are a safety net, zero urgency).
	compactionReapEnable   bool
	compactionReapInterval time.Duration
	// Day 21 (ADR-0026): arm telemetry.Init at boot with a real OTel SDK
	// MeterProvider (--otel=false, the DEFAULT, keeps the Day-18 bridge-alone
	// behavior — the OTel-OFF research node; honest-disabled is the 503-precedent
	// sister, NOT a silent no-op). When ON, the package-level counters are
	// rebuilt against a real sdk Meter whose observable callbacks fire on the
	// periodic reader's cadence — the change that makes the cap-hit disclosure
	// counter + the Level-2 prune telemetry honest under a real Meter (the
	// omission landmine ADR-0023 §6 named is closed ADR-0026). The OTel reader
	// (a PeriodicReader over a logOutputExporter) is a SEPARATE destination from
	// the bridge's prometheus Registry (§0.d — the two never double-count at
	// /metrics; cumulative bridge == sum-of-OTel-deltas).
	otelEnabled  bool
	otelInterval time.Duration

	// Day 30 (ADR-0035): the PKI leaf-rotation trigger + the CRL revocation
	// consult — the dormant security gate Day 30 wires (the blueprint Track 5.2
	// "zero-downtime leaf cert rotation every 30 days" + "a node presenting an
	// expired or revoked cert is rejected at the TLS handshake"). The rotation
	// trigger is OPT-IN (--cert-rotation-enable, default false = byte-identical
	// Day-29 — the SIGHUP seam + TestTLSCertRotation_SIGHUP stay byte-identical;
	// the Day-19/23/29 opt-IN precedent). --cert-rotation-poll is the goroutine
	// poll interval (coarse; default 1h); --cert-rotation-lifetime is the
	// pre-expiry threshold at which the rotation fires (default 30d — the
	// blueprint's 30-day cadence is the LIFETIME, NOT the poll — the M4 honest
	// calibration: poll at 1h, the leaf lives 1 year, rotate 30d before NotAfter).
	// --crl-path is the on-disk CRL the transport hot-reloads (opt-IN; empty =
	// no revocation consult = byte-identical Day-29; a node with NO revoked
	// serials needs no CRL). The flags are documented in the flag block below.
	certRotationEnable   bool
	certRotationPoll     time.Duration
	certRotationLifetime time.Duration
	crlPath              string
	// Day 31 (ADR-0036): the post-quantum transport readiness knobs — the
	// hybrid (Ed25519 + ML-DSA-65) signature verify gate + the PQ-KEM
	// disclosure counter. BOTH are OPT-IN (the Day-19/23/29/30 opt-IN
	// precedent); the DEFAULTS leave the node byte-identical Day-30.
	//
	// --hybrid-verify=false (the DEFAULT) keeps the receive path on the
	// classical-only identity.VerifyCRDTFrame seam (verify.go:68, the circl
	// Ed25519 check + the RejectSmallOrderKey cofactor gate) — byte-identical
	// Day-30. ON switches the receive path's two verify call sites
	// (receiver.go:350 HandleFrame + :586 HandleBatchFrame) to the hybrid
	// VerifyCRDTFrame_Hybrid seam (identity/hybrid_verify.go) — BOTH-sigs-
	// required, defense-in-depth (a classical break does NOT compromise a PQ
	// frame; a PQ break does NOT compromise a classical frame; the EITHER-or
	// gate is the BUG-INJECT control T-PQ-HYBRID-VERIFY-DUAL PROVES the BOTH
	// gate rejects). The hybrid SIGN (a frame carries BOTH sigs) is a FUTURE
	// fork (the CRDT-delta wire shape change — disclosed ADR-0036 §6; the
	// FROZEN-crdt.go seam is the HONEST question a future fork answers); Day
	// 31 wires the VERIFY + the KEM proof, NOT the production sign.
	//
	// The PQ-KEM counter (PQHandshakeNegotiated) is wired UNCONDITIONALLY (the
	// Day-30 SetRevocationReporter precedent — the reporter seam is bound at
	// boot; the flag gates the SIGNATURE verify, NOT the KEM disclosure). The
	// counter fires on the transport.Dial seam (RecordHandshake reads
	// ConnectionState().CurveID==4588) — a classical fallback for a non-MLKEM
	// peer does NOT increment (PQ-KEM-only, NOT every handshake).
	hybridVerifyEnable bool

	// hybridSignEnable is the Day-32 (ADR-0037) hybrid-SIGN opt-IN flag.
	// --hybrid-sign=false (the DEFAULT) keeps the self-originated delta path on
	// the v1 BatchEnvelope (one Ed25519 per batch) — byte-identical Day-31 (NO
	// hybrid frame is produced; the receive-side --hybrid-verify gate never
	// sees one). --hybrid-sign=true switches shipBatchedDelta's self-originated
	// path to ShipBatchHybrid: one Ed25519 + one ML-DSA-65 sig over the SAME
	// 120-byte SHAKE256 pad of batchWire, carried in a HybridEnvelope. The owner
	// identity is constructed via NewNodeIdentityHybrid when this is true (the
	// PQ key is minted from the SAME --identity-seed); the PQ pubkey is
	// registered in the Directory via RegisterPQ so peers' hybrid verify
	// resolves it. The relay/foreign path stays per-frame regardless (the
	// self-origin boundary — a relayer holds ONLY its own PQ key, CANNOT
	// re-origin-sign a foreign delta under EITHER sig).
	hybridSignEnable bool

	// regionAwareEnable is the Day-34 (ADR-0039) region-aware gossip data-plane
	// opt-IN flag. --region-aware=false (the DEFAULT) keeps AntiEntropySweep on
	// the full-mesh peers.Peers() path — byte-identical Day-33 (the T-TOPO-OFF-
	// IS-BYTE-IDENTICAL tooth; NO topology selector runs). --region-aware=true
	// switches the sweep's iteration source to topology.Select(ctx) (intra-
	// region full-mesh + inter-region fan-out-N, prefer cross-region, seeded-
	// deterministic — the O(log N) rounds convergence the blueprint names). The
	// knob is INDEPENDENT of the per-peer region tags: a node can set
	// --region-aware=true with NO peers tagged (all peers RegionUnset = SAME-
	// region = intra-only = the full-mesh path with the topology seam armed but
	// idle — the honest "arm first, tag later" discipline). opt-IN (NOT opt-OUT)
	// per the Day-19/23/29/30/31/32 discipline — the SEVENTH opt-IN fork.
	regionAwareEnable bool

	// selfRegion is the Day-34 (ADR-0039) --self-region flag value — this node's
	// OWN region tag (the intra/inter split key). A uint8 parsed from the flag
	// string (e.g. "1" for region-1); 0 (the DEFAULT — RegionUnset) makes EVERY
	// peer intra-region (sameRegion returns true for RegionUnset on either side)
	// = byte-identical to the full-mesh path. A production fork that wants named
	// regions (us-east, eu-west) ships a registry uint8→string in a SEPARATE
	// fork (the Day-19 opt-IN discipline: ship the SIMPLE thing first).
	selfRegion int

	// regionFanout is the Day-34 (ADR-0039) --region-fanout flag value — the
	// inter-region fan-out N (the blueprint's default 3 — the O(log_3 N) rounds
	// convergence at fan-out 3). Clamped to [0, MaxFanout] by the TopologyManager;
	// 0 = intra-region full-mesh only (the honest degenerate case — the
	// T-TOPO-CONNECTION-CUT tooth asserts fan-out 0 -> intra-only).
	regionFanout int

	// peerDir is the Day-35 (ADR-0040) --peer-dir flag value — the OOB peer-
	// Directory pubkey provisioning config path (Seam A). OPT-IN (default "" =
	// no provisioning = the dial loop keeps the zero peerID = byte-identical
	// Day-34). When set, cmd/sovereign-node/provisioning.go's applyProvisioning
	// parses the line-oriented config (addr → {nodeID, ed25519_pubkey, optional
	// mldsa65_pubkey, optional region}) + calls gossiper.RegisterPeer
	// (+ dir.RegisterPQ for the optional PQ arm) + topo.SetRegion under the REAL
	// nodeID — retiring the Day-34 §7.1 zero-peerID hazard. A NON-EMPTY path that
	// does not exist OR a malformed entry FAILS THE BOOT (a deploy
	// misconfiguration MUST surface loudly, NOT silently fall back to
	// zero-peerID — the honest-negative posture). See provisioning.go for the
	// FAILSAFE parser + the T-OOB-CONFIG-PARSE bug-inject control.
	peerDir string

	// autoReconcile is the Day-35 (ADR-0040) --peer-auto-reconcile flag value —
	// the runtime TLS-leaf reconcile (Seam B). OPT-IN (default false = byte-
	// identical Day-34 — the dial loop keys peers under the caller-supplied
	// peerID; reconcilePeerID is NOT called). ON switches PeerSet.Dial to read
	// the peer's TLS leaf CommonName (hex.DecodeString the 32-char CN → [16]byte)
	// + re-key the peerConn under the REAL nodeID so the topology selector HITS
	// even WITHOUT a --peer-dir config (the ROUTING bonus — a deploy that
	// opts into --peer-auto-reconcile alone ROUTES via the handshake; it does
	// NOT CONVERGE — the receiver's Directory.Lookup MISSES without the OOB
	// verification pubkey → DropVerify → deltas DROPPED LOUD; convergence
	// REQUIRES --peer-dir's RegisterPQ/RegisterPeer. The binary harness RUN 3
	// honest-negative PROVES reconcile-only does NOT converge). ROUTING-only per
	// M3: the reconcile re-keys the ROUTING map; it NEVER touches the
	// verification pubkey (the Directory's OOB-provisioned key is the
	// verification anchor; a self-announced node with NO OOB pubkey is ROUTED but
	// NOT VERIFIED → its deltas DROPPED LOUD via VerifyFail). See pkg/mesh/peer.go
	// reconcilePeerID for the leaf-CN decode + the T-OOB-RECONCILE control.
	autoReconcile bool
}

func parseFlags(args []string) (*nodeConfig, error) {
	fs := flag.NewFlagSet("sovereign-node", flag.ContinueOnError)
	cfg := &nodeConfig{}
	fs.StringVar(&cfg.bind, "bind", "127.0.0.1:7430", "TLS listener bind address (host:port)")
	fs.StringVar(&cfg.peers, "peers", "", "comma-separated peer addresses (Day-2 dial loop; parsed + logged Day 1)")
	fs.StringVar(&cfg.tlsCert, "tls-cert", "", "leaf certificate PEM path")
	fs.StringVar(&cfg.tlsKey, "tls-key", "", "leaf private key PEM path")
	fs.StringVar(&cfg.tlsCA, "tls-ca", "", "CA certificate PEM path (trust root)")
	fs.StringVar(&cfg.nodeID, "node-id", "", "16-byte node identity (hex); defaults to a random 16-byte id")
	fs.StringVar(&cfg.metricsAddr, "metrics-addr", "127.0.0.1:7431", "/livecheck control surface bind address (plain HTTP, ops debug)")
	fs.StringVar(&cfg.controlAddr, "control-addr", "", "JSON-over-mTLS client control port bind address (host:port; empty=disabled — no accidental exposure; a SEPARATE TLS listener from --bind)")
	fs.IntVar(&cfg.arenaMib, "arena-mib", 64, "off-heap HAMT arena size in MiB")
	fs.Int64Var(&cfg.admissionBudget, "admission-budget-ns", defaultAdmissionBudget, "receive admission budget in nanoseconds (3.2 max-hops transform)")
	fs.StringVar(&cfg.gossipTick, "gossip-tick", "100ms", "anti-entropy sweep tick (steady-state default 100ms; the heal-control-plane Day-4 override is 50ms — one knob, two documented workloads)")
	fs.StringVar(&cfg.identitySeed, "identity-seed", "", "32-byte hex Ed25519 seed for this node's CRDT-delta signing identity (defaults to a random seed; the derived nodeID dominates --node-id)")
	fs.BoolVar(&cfg.selftest, "selftest", false, "run the built-in self-test (mint a dev CA + leaf, serve /livecheck, exit)")
	fs.IntVar(&cfg.batchSize, "batch-size", 100, "Day-5 batched delta transport: number of self-originated deltas per signed batch (1=per-frame back-compat; max 256; one Ed25519 verify amortizes over N deltas — the arithmetic unlock)")
	// Day 29 (ADR-0034): stratified anti-entropy is OPT-IN. --stratified-anti-
	// entropy=false (the DEFAULT) keeps the sweep byte-identical to HEAD's
	// oversend path (GenerateDelta against an empty IBLT — every entry to every
	// peer every round; the CRDT-idempotent Join converges in one round). When
	// set, the sweep runs the M3 two-phase digest-exchange per peer: SEND the
	// local StrataEstimator + the full local IBLT digest, RECEIVE the peer's,
	// call GenerateDelta(remoteIBLT) (the FROZEN set-reconciliation primitive
	// that subtracts the peer's POPULATED IBLT — the M2 fix; the broken
	// GenerateDeltaStratified that subtracted an EMPTY remote IBLT is DELETED)
	// for a minimal delta proportional to |A−B| instead of the full set. The
	// fallback to oversend on a digest timeout / malformed digest / peel failure
	// is the M5 honest path (counted via sovereign_mesh_stratified_fallback).
	fs.BoolVar(&cfg.stratifiedAntiEntropy, "stratified-anti-entropy", false, "Day-29 stratified anti-entropy: per-peer StrataEstimator digest-exchange before the GenerateDelta (a minimal delta proportional to |A−B| instead of the full set). OFF (default) = byte-identical oversend; ON = the M3 two-phase digest-exchange with oversend fallback on timeout/malformed/peel-failure (counted via sovereign_mesh_stratified_fallback).")
	// Day 8: durability is OPT-IN. --wal-path empty (default) = in-memory
	// research mode = Day-7 back-compat (the silicon bench path UNTOUCHED, no
	// fsync on the origin write path). When set, the node boots from the WAL
	// (RecoverEngine) and the origin write path fsyncs the engine-STAMPED dot
	// per mutation. --wal-checkpoint-interval bounds replay length (a periodic
	// MerkleRoot+LamportHigh anchor every K mutations); 0 = caller-driven only.
	fs.StringVar(&cfg.walPath, "wal-path", "", "engine WAL path (empty=in-memory research mode, Day-7 back-compat, durability OFF; set to a file path to enable fsync-per-mutation durability + WAL recovery on boot)")
	fs.Uint64Var(&cfg.walCheckpointInterval, "wal-checkpoint-interval", 1000, "periodic WAL checkpoint interval in mutations (bounds replay length; 0=caller-driven checkpoints only; the fsync-per-mutation floor is NOT downgraded)")
	// Day 11: bounded recovery is OPT-IN alongside durability. --lsm-root empty
	// (default) = full-replay back-compat (Day-8/8.5, unchanged). Set to a dir
	// to enable the LSM↔DURABILITY snapshot seam: recovery loads the dot-bearing
	// snapshot at "ckpt/<LamportHigh>" + replays only the post-checkpoint tail
	// (O(post-ckpt), not O(writes-since-boot)). Created if missing. A missing or
	// corrupt snapshot silently falls back to full replay (recovery always
	// rebuilds; boundedness is best-effort).
	fs.StringVar(&cfg.lsmRoot, "lsm-root", "", "Day-11 recovery snapshot directory (empty=full-replay back-compat; set to a dir to bound WAL recovery to the post-checkpoint tail via the snapshot seam)")
	// Day 15 (ADR-0020): the Level-2 superseded-row prune knobs. The default
	// is Preserve-All (EnableDominancePruning=false) — byte-identical Day-14
	// compaction; the engine NEVER auto-prunes. An operator opts in by setting
	// BOTH --compaction-prune-enable=true AND a positive
	// --compaction-prune-horizon-ns (the transaction-time GC horizon T_gc — a
	// monotone non-decreasing tx-time at/after which no live query looks back;
	// ADR-0020 §2). ENABLED + horizon<=0 is SILENTLY WRONG (the §0.4(ii) txTime
	// gap); NewL1Compactor traps it with a WARN + coerce-to-Preserve-All.
	fs.BoolVar(&cfg.compactionPruneEnable, "compaction-prune-enable", false, "Day-15 Level-2 superseded-row prune: enable dropping provably-dead merged rows at the compaction seam under the (C1)&&(C2)&&(C3) SAFE-DROP rule (default false=Preserve-All, the byte-identical Day-14 behavior)")
	fs.Int64Var(&cfg.compactionPruneHorizon, "compaction-prune-horizon-ns", 0, "Day-15 transaction-time GC horizon T_gc in nanoseconds (the (C3) claw; REQUIRES --compaction-prune-enable; <=0 with prune enabled is trapped as silently-wrong + coerced to Preserve-All)")
	// Day 22 (ADR-0027): the T_gc auto-inference backoff. The observed live-query
	// txTime frontier the Resolver tracks (queried at every AsOf) is fed to the
	// compaction scheduler's HorizonInferrer; the effective DominancePrune floor
	// is max(--compaction-prune-horizon-ns, observedFrontier - this-backoff).
	// The horizon flag becomes the operator's HARD floor backstop (the inferrer
	// FLOORS the knob, it does NOT replace it); this backoff is the operator's
	// "I may query up to T now - backoff into the past" contract. Default 5m
	// tolerates forensic queries 5min into the recent past (a HONEST conservative
	// default; an operator whose workload queries deeper over-retains, one that
	// NEVER queries the past can lower it OR raise the hard floor — §6.a).
	fs.DurationVar(&cfg.compactionPruneBackoff, "compaction-prune-backoff-ns", 5*time.Minute, "Day-22 T_gc auto-inference backoff: how far behind the observed live-query txTime frontier the effective DominancePrune floor sits (effective = max(--compaction-prune-horizon-ns, observedFrontier - backoff); tolerates forensic queries `backoff` into the recent past; default 5m; 0=track the frontier directly, the operator floor still backstops)")
	// Day 16 (ADR-0021): the L0 reaper. Default OFF — byte-identical Day-15
	// (the superseded L0s stay as the crash-recovery backstop). The reaper
	// deletes a manifest-listed L0 ONLY after verifying the L1 still exists
	// (Stage C); turning it ON reclaims disk but requires trusting the storage
	// layer's existence-probe (a layer that EVER reports a present L1 as
	// missing would make the reaper delete the sole durable copy). NEVER auto-ON.
	fs.BoolVar(&cfg.compactionReapEnable, "compaction-reap-enable", false, "Day-16 L0 reaper: reclaim manifest-listed superseded L0 files + the manifest AFTER verifying the L1 still exists (default false=backstop-forever byte-identical Day-15; the reaper is NEVER auto-ON — Stage C L1-exists guard is the safety constraint)")
	fs.DurationVar(&cfg.compactionReapInterval, "compaction-reap-interval", 5*time.Minute, "Day-16 L0 reaper sweep cadence (slower than compaction's 30s — the superseded L0s are a safety net, zero urgency to delete)")
	fs.BoolVar(&cfg.otelEnabled, "otel", false, "Day-21 arm telemetry.Init at boot with a real OTel SDK MeterProvider (default false=Day-18 bridge-alone; OTel reader is a SEPARATE destination from the bridge's prometheus Registry)")
	fs.DurationVar(&cfg.otelInterval, "otel-interval", 60*time.Second, "Day-21 OTel periodic reader export interval (the cadence the int64-observable callbacks fire on; the bridge scrapes cumulatively at the /metrics cadence)")
	// Day 30 (ADR-0035): --cert-rotation-enable (OPT-IN, default false). OFF
	// keeps the transport byte-identical Day-29 (the SIGHUP seam +
	// TestTLSCertRotation_SIGHUP stay byte-identical; the automated trigger is a
	// NEW goroutine that OFF never starts). ON launches a goroutine
	// (transport.StartRotationManager) that polls the live leaf's NotAfter +
	// fires the rotation when the leaf is within --cert-rotation-lifetime of
	// expiry (the pre-expiry threshold). The rotation mints a NEW Ed25519 leaf
	// via the in-process dev-mesh CA + Reloads the SAME transport (the existing
	// seam — the NEXT handshake presents the NEW serial). The trigger fires the
	// CertRotationTriggered counter (the operator-visible audit trail). The
	// blueprint's 30-day cadence is the LIFETIME (the pre-expiry window), NOT
	// the poll — the goroutine polls at --cert-rotation-poll (default 1h, coarse)
	// and the leaf lives 1 year (certgen IssueLeaf); the rotation fires 30 days
	// before the 1-year NotAfter. A production fork that rotates via an
	// out-of-process minter (KMS/HSM) substitutes the minter — the trigger's
	// polling + reload mechanism is the load-bearing wiring this flag arms.
	fs.BoolVar(&cfg.certRotationEnable, "cert-rotation-enable", false, "Day-30 automated leaf-cert rotation: launch the poll goroutine that mints a NEW leaf + Reloads the transport when the live leaf is within --cert-rotation-lifetime of expiry (default false=SIGHUP-only manual rotation, byte-identical Day-29; the goroutine fires the supremum_pki_cert_rotation_triggered counter)")
	fs.DurationVar(&cfg.certRotationPoll, "cert-rotation-poll", time.Hour, "Day-30 rotation goroutine poll interval (how often the trigger checks the live leaf's NotAfter; coarse — default 1h; MUST be > 0 or the trigger traps; a smaller poll rotates sooner but burns a goroutine tick more often)")
	fs.DurationVar(&cfg.certRotationLifetime, "cert-rotation-lifetime", 30*24*time.Hour, "Day-30 rotation pre-expiry threshold: fire the rotation when the live leaf's NotAfter is within this duration of now (default 30d = the blueprint's 30-day cadence; the lifetime is the pre-expiry GRACE window, NOT the poll interval, NOT the leaf's actual 1-year validity — the M4 honest-calibration)")
	// Day 30 (ADR-0035): --crl-path is the on-disk CRL (PEM, type "X509 CRL") the
	// transport hot-reloads into an in-memory revoked-serial set; the
	// VerifyPeerCertificate callback rejects a presented leaf whose serial is in
	// the set (the blueprint Track 5.2 revocation gate). OPT-IN: empty (the
	// DEFAULT) = no revocation consult = byte-identical Day-29 (the callback
	// returns nil on an empty set). A SIGHUP re-reads the CRL live
	// (transport.ReloadCRL) so an operator revokes a serial by publishing a NEW
	// crl.pem + sending SIGHUP — the NEXT handshake against the revoked serial
	// aborts (the CertRevokedRejected counter fires). The CRL is signed by the
	// dev-mesh CA (certgen.IssueCRL); a production fork ships a CRL from an
	// out-of-process CA (the Ed25519-CheckSignatureFrom stdlib quirk is disclosed
	// ADR-0035 §6 — the consult is serial-scoped, NOT a per-handshake signature
	// re-verify).
	fs.StringVar(&cfg.crlPath, "crl-path", "", "Day-30 on-disk CRL PEM path (empty=no revocation consult=byte-identical Day-29; set to a crl.pem to arm the VerifyPeerCertificate serial-reject; a SIGHUP re-reads it live via ReloadCRL)")
	// Day 31 (ADR-0036): --hybrid-verify (OPT-IN, default false). OFF keeps
	// the receive path on the classical-only identity.VerifyCRDTFrame seam
	// (verify.go:68) — byte-identical Day-30 (the production default stays
	// classical-only; the hybrid is a defense-in-depth ADD, NOT a replace).
	// ON switches the receive path's two verify call sites (receiver.go:350
	// HandleFrame + :586 HandleBatchFrame) to the hybrid
	// VerifyCRDTFrame_Hybrid seam — BOTH Ed25519 + ML-DSA-65 sigs required
	// (defense-in-depth; the EITHER-or gate is the BUG-INJECT control the
	// T-PQ-HYBRID-VERIFY-DUAL tooth PROVES the BOTH gate rejects). The hybrid
	// SIGN (a frame carries BOTH sigs) is a FUTURE fork — the CRDT-delta wire
	// shape change — disclosed ADR-0036 §6; the FROZEN-crdt.go seam is the
	// HONEST question a future fork answers. The PQ-KEM counter
	// (PQHandshakeNegotiated) is wired UNCONDITIONALLY regardless of this flag
	// (the KEM disclosure is the transport seam, NOT the signature verify).
	fs.BoolVar(&cfg.hybridVerifyEnable, "hybrid-verify", false, "Day-31 hybrid (Ed25519 + ML-DSA-65) signature verify: switch the receive path to the BOTH-sigs-required VerifyCRDTFrame_Hybrid seam (defense-in-depth — a classical break does NOT compromise a PQ frame, a PQ break does NOT compromise a classical frame; default false=classical-only byte-identical Day-30; the hybrid SIGN is a future fork)")
	// Day 32 (ADR-0037): --hybrid-sign (OPT-IN, default false). OFF keeps the
	// self-originated delta path on the v1 BatchEnvelope (one Ed25519 per batch)
	// — byte-identical Day-31 (NO hybrid frame is produced; the receive-side
	// --hybrid-verify gate never sees one — T-PQ-HYBRID-OFF-IS-BYTE-IDENTICAL).
	// ON switches shipBatchedDelta's self-originated path to ShipBatchHybrid: one
	// Ed25519 + one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad of
	// batchWire, carried in a HybridEnvelope (attribution.MarshalHybridFrame).
	// The owner identity is constructed via NewNodeIdentityHybrid when this is
	// true (the PQ key is minted from the SAME --identity-seed); the PQ pubkey
	// is registered in the Directory via RegisterPQ. The relay/foreign path
	// stays per-frame regardless (the self-origin boundary). A misconfigured
	// --hybrid-sign on a non-PQ owner returns an error from ShipBatchHybrid's
	// nil-pqPriv guard (logged + the batch skipped, NOT a panic).
	fs.BoolVar(&cfg.hybridSignEnable, "hybrid-sign", false, "Day-32 hybrid-PQ SIGN: switch the self-originated delta path to ShipBatchHybrid (one Ed25519 + one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad of batchWire, carried in a HybridEnvelope; the owner is minted via NewNodeIdentityHybrid + the PQ pubkey is registered via RegisterPQ; default false=v1 BatchEnvelope byte-identical Day-31; the relay/foreign path stays per-frame regardless)")
	// Day 34 (ADR-0039): --region-aware (OPT-IN, default false). OFF keeps
	// AntiEntropySweep on the full-mesh peers.Peers() path — byte-identical
	// Day-33 (NO topology selector runs; the T-TOPO-OFF-IS-BYTE-IDENTICAL
	// tooth). ON switches the sweep's iteration source to topology.Select(ctx)
	// (intra-region full-mesh + inter-region fan-out-N, prefer cross-region,
	// seeded-deterministic — the O(log N) rounds convergence the blueprint
	// names). The fan-out is the blueprint's default 3 (override via
	// --region-fanout); the self-region is --self-region (0 = RegionUnset =
	// every peer intra = byte-identical full-mesh); the per-peer region tags
	// are parsed from the --peers addr@region suffix (a peer with NO @region
	// suffix is RegionUnset = SAME-region = intra). The knob is INDEPENDENT of
	// the per-peer tags: --region-aware=true with NO peers tagged = the full-
	// mesh path with the topology seam armed but idle (the honest "arm first,
	// tag later" discipline). NO new module dep (stdlib only); NO AWS this fork
	// (the 100-node silicon convergence gate is the Day-35+ AWS arc — the
	// loopback gate is the SIMULATED N=100 mesh round-count, NOT silicon wall-
	// time).
	fs.BoolVar(&cfg.regionAwareEnable, "region-aware", false, "Day-34 region-aware gossip data-plane: switch AntiEntropySweep's iteration source from the full-mesh peers.Peers() (O(N²) connections at N nodes) to topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N, prefer cross-region, seeded-deterministic — the O(log N) rounds convergence the blueprint names). default false=full-mesh Peers() byte-identical Day-33; the per-peer region tags are parsed from --peers addr@region suffixes; --self-region is this node's own region (0=RegionUnset=every-peer-intra=byte-identical full-mesh); --region-fanout is the inter-region fan-out N (default 3)")
	// Day 34 (ADR-0039): --self-region is this node's OWN region tag (the
	// intra/inter split key). A uint8 (0-255); 0 (the DEFAULT — RegionUnset)
	// makes EVERY peer intra-region (sameRegion returns true for RegionUnset on
	// either side) = byte-identical to the full-mesh path. A production fork
	// that wants named regions (us-east, eu-west) ships a registry uint8→string
	// in a SEPARATE fork (the Day-19 opt-IN discipline: ship the SIMPLE thing
	// first). The honest call is the uint8 (cache-friendly — the prompt's
	// "the honest call is the uint8"; a string is human-readable but a uint8 is a
	// single-byte compare).
	fs.IntVar(&cfg.selfRegion, "self-region", 0, "Day-34 this node's own region tag (the intra/inter split key; a uint8 0-255; 0=RegionUnset=every-peer-intra=byte-identical full-mesh; peers with the SAME region are intra=full-mesh, peers with a DIFFERENT region are inter=fan-out-N candidates)")
	// Day 34 (ADR-0039): --region-fanout is the inter-region fan-out N (the
	// blueprint's default 3 — the O(log_3 N) rounds convergence at fan-out 3).
	// Clamped to [0, MaxFanout] by the TopologyManager; 0 = intra-region full-
	// mesh only (the honest degenerate case — the T-TOPO-CONNECTION-CUT tooth
	// asserts fan-out 0 -> intra-only). A larger fan-out converges faster but
	// burns more per-sweep bandwidth (the trade-off the operator dials).
	fs.IntVar(&cfg.regionFanout, "region-fanout", 3, "Day-34 inter-region fan-out N (the blueprint's default 3 — the O(log_3 N) rounds convergence; clamped to [0, MaxFanout]; 0=intra-region full-mesh only — the honest degenerate case)")
	// Day 35 (ADR-0040): --peer-dir is the OOB peer-Directory pubkey provisioning
	// config path (Seam A — the deterministic gate). OPT-IN (default "" = no
	// provisioning = the dial loop keeps the zero peerID = byte-identical Day-34).
	// The config is line-oriented (zero-dependency: no TOML/YAML dep): one peer per
	// line, whitespace-separated positional columns `addr nodeID ed25519_pubkey
	// [mldsa65_pubkey|-] [region|-]`; `#` comments; a NON-EMPTY path that does not
	// exist OR a malformed entry FAILS THE BOOT (a deploy misconfiguration MUST
	// surface loudly, NOT silently fall back to zero-peerID). See
	// cmd/sovereign-node/provisioning.go's parsePeerDir for the FAILSAFE parser +
	// the column contract.
	fs.StringVar(&cfg.peerDir, "peer-dir", "", "Day-35 OOB peer-Directory pubkey provisioning config path (Seam A — the deterministic gate; OPT-IN default \"\"=no provisioning=byte-identical Day-34). Line-oriented: `addr nodeID ed25519_pubkey [mldsa65_pubkey|-] [region|-]` per line, `#` comments; a non-empty-but-absent OR malformed entry FAILS the boot (a deploy misconfiguration MUST be loud, NOT a silent zero-peerID fallback)")
	// Day 35 (ADR-0040): --peer-auto-reconcile is the runtime TLS-leaf reconcile
	// (Seam B — the routing complement to Seam A). OPT-IN (default false =
	// byte-identical Day-34). ON switches PeerSet.Dial to read the peer's TLS leaf
	// CommonName (hex.DecodeString the 32-char CN → [16]byte) + re-key the
	// peerConn under the REAL nodeID so the topology selector HITS for a peer
	// whose dial supplied the zero peerID. ROUTING-only per M3: the reconcile
	// re-keys the ROUTING map; it NEVER touches the verification pubkey (the
	// Directory's OOB-provisioned key is the verification anchor). A self-announced
	// node with NO OOB pubkey is ROUTED but NOT VERIFIED → its deltas DROPPED LOUD
	// via VerifyFail (the correct zero-trust posture). The binary harness RUN 3
	// honest-negative PROVES reconcile-only does NOT converge (the receiver's
	// Directory.Lookup at receiver.go:436 MISSES without --peer-dir's RegisterPeer
	// → DropVerify → no convergence); Seam B is a routing COMPLEMENT to Seam A,
	// NOT a standalone convergence path. See pkg/mesh/peer.go reconcilePeerID.
	fs.BoolVar(&cfg.autoReconcile, "peer-auto-reconcile", false, "Day-35 runtime TLS-leaf reconcile (Seam B — the routing complement to Seam A; OPT-IN default false=byte-identical Day-34). ON switches PeerSet.Dial to read the peer leaf CommonName (hex.DecodeString → [16]byte) + re-key the peerConn under the REAL nodeID so the topology selector HITS. ROUTING-only per M3 (the verification pubkey stays the deploy's OOB concern via --peer-dir; reconcile ALONE routes but does NOT converge — Directory.Lookup misses → DropVerify)")
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

// resolveNodeID parses the --node-id hex (or mints a random 16-byte id) and
// returns the [16]byte the FROZEN engine constructor expects.
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

// parsePeers splits the --peers comma list into a slice of host:port strings.
// Day 1 parses + logs them; the dial loop is Day 2. Day 34 (ADR-0039): a peer
// may carry an `addr@region` suffix (the per-peer region tag for the region-
// aware sweep); parsePeers STRIPS the `@region` suffix so the addr passed to
// peerSet.Dial is a clean host:port (net.SplitHostPort would reject the `@`
// suffix). The region suffix is parsed SEPARATELY by parsePeerRegions (which
// reads the SAME --peers string + extracts the addr→region map). A peer with
// NO `@region` suffix is RegionUnset (the honest conservative default — an
// untagged peer routes as SAME-region = intra, NOT foreign).
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
		// Day 34: strip the `@region` suffix (if present) so the dial addr is
		// a clean host:port. The region is parsed separately by parsePeerRegions.
		if at := strings.IndexByte(p, '@'); at >= 0 {
			p = strings.TrimSpace(p[:at])
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePeerRegions parses the --peers comma list's `addr@region` suffixes into
// an addr→RegionTag map (the Day-34 per-peer region registry). A peer with NO
// `@region` suffix is OMITTED (RegionUnset — the honest conservative default;
// an untagged peer routes as SAME-region = intra via the TopologyManager's
// untagged=local default). The region is a uint8 parsed from the suffix string
// (e.g. "1.2.3.4:7430@1" → region 1); a parse error (non-numeric, out of
// uint8 range) is silently skipped (RegionUnset — the honest FAILSAFE: a
// malformed region tag NEVER crashes the boot; the peer routes as local, NOT
// foreign, the conservative default). Called once at boot; the returned map is
// the TopologyManager's region registry (keyed by peerIDForAddr(addr), the
// deterministic addr-derived [16]byte).
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
			continue // no region suffix -> RegionUnset (untagged = local)
		}
		addr := strings.TrimSpace(p[:at])
		regionStr := strings.TrimSpace(p[at+1:])
		if addr == "" || regionStr == "" {
			continue
		}
		// Parse the region tag as a uint8 (0-255). A parse error OR an
		// out-of-range value is silently skipped (RegionUnset — the honest
		// FAILSAFE; a malformed region tag NEVER crashes the boot). A value of
		// 0 is RegionUnset (the same as no suffix) — accepted but inert.
		r, err := strconv.ParseUint(regionStr, 10, 8)
		if err != nil {
			continue
		}
		out[addr] = mesh.RegionTag(r)
	}
	return out
}

// peerIDForAddr derives a DETERMINISTIC [16]byte peerID surrogate from a peer
// addr (SHA-256 of the addr, truncated to 16 bytes). The Day-2 dial loop stores
// peers under a PLACEHOLDER zero peerID (the peer's real nodeID is unknown until
// the peer presents its leaf — the Day-2 honest gap; real peer provisioning
// ships the Day-35+ OOB arc). The TopologyManager is keyed by [16]byte peerID,
// so the cmd path registers region tags under this deterministic addr-derived
// surrogate — a STABLE key the future OOB-provisioning fork reconciles with the
// real nodeID (once the dial loop carries real peerIDs, the same topology
// works under the real keys). The HONEST N=2 NO-OP: the cmd dial loop's zero
// peerID does NOT match this addr-derived key, so the region lookup misses →
// every peer routes as RegionUnset = intra = byte-identical full-mesh; the
// loopback gate is the SIMULATED N=100 mesh (in-process, REAL peerIDs), NOT the
// 2-node binary run (the prompt's §III gate honest residual).
func peerIDForAddr(addr string) [16]byte {
	sum := sha256.Sum256([]byte(addr))
	var id [16]byte
	copy(id[:], sum[:16])
	return id
}

// applySurrogateRegions registers the --peers addr@region suffixes as
// TopologyManager region tags keyed by peerIDForAddr(addr) — the Day-34
// SHA-256 surrogate — EXCEPT for any addr in provisionedAddr (a peer
// --peer-dir provisions under the REAL nodeID). The Day-35 /code-review
// surrogate-pollution fix (altitude #1 + Angle C #2): a peer tagged @region
// in --peers AND provisioned in --peer-dir would otherwise leave a DEAD
// surrogate in topo.regions (no live peerConn keys it) → topology.Select
// iterates BOTH the surrogate + the real nodeID → the dead surrogate consumes
// an inter-region fan-out slot, evicting a real cross-region peer →
// convergence slows/stalls + the 24th SSoT counter over-counts. The gate
// skips the surrogate for a provisioned addr; its region comes from
// applyProvisioning's SetRegion(realNodeID, region) instead. Extracted to a
// helper so the surrogate-pollution fix is FALSIFIABLE (T-OOB-SURROGATE-
// RETIREMENT calls this directly, NOT a re-implementation).
func applySurrogateRegions(topo *mesh.TopologyManager, peers string, provisionedAddr map[string]bool) {
	for addr, region := range parsePeerRegions(peers) {
		if provisionedAddr[addr] {
			continue // provisioned via --peer-dir → region keyed under real nodeID below
		}
		topo.SetRegion(peerIDForAddr(addr), region)
	}
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	nodeID, err := resolveNodeID(cfg)
	if err != nil {
		return err
	}
	peers := parsePeers(cfg.peers)

	// --selftest: mint a dev CA + leaf into a temp dir, point the transport
	// at them, serve /livecheck, and exit after a short window so the gate
	// can curl it. This is box-independent (no silicon required). Day 30: the
	// in-process CA is ALSO returned so the automated rotation trigger can mint
	// NEW leaves via the SAME CA under --selftest (the operator path has NO
	// in-process CA — it loads PEMs from disk — so rotation on the operator
	// path needs an out-of-process minter, disclosed ADR-0035 §6).
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

	// Day 30 (ADR-0035): the PKI revocation consult + the automated rotation
	// trigger — wired on the transport the binary just constructed. Both are
	// OPT-IN (the Day-19/23/29 opt-IN precedent); a node with --crl-path empty
	// AND --cert-rotation-enable=false (the DEFAULTS) leaves the transport
	// byte-identical Day-29 (the VerifyPeerCertificate callback returns nil on
	// an empty revoked set; no rotation goroutine starts).
	//
	// (1) The CRL revocation consult: --crl-path set arms the on-disk CRL the
	// transport hot-reloads. LoadCRL parses it once at boot (the construction-
	// time arm); a SIGHUP re-reads it live (ReloadCRL, wired in the SIGHUP
	// handler below). The VerifyPeerCertificate callback (wired inside the
	// transport's ServerConfig/ClientConfig) rejects a presented leaf whose
	// serial is in the set + fires the CertRevokedRejected counter.
	if cfg.crlPath != "" {
		tr.SetCRLPath(cfg.crlPath)
		if err := tr.LoadCRL(); err != nil {
			return fmt.Errorf("Day-30 CRL load %q: %w (the transport will NOT start with a configured-but-unloadable CRL — the honest-negative posture; a corrupt CRL is NEVER silently dropped to 'trust everything')", cfg.crlPath, err)
		}
		log.Printf("Day-30: CRL loaded from %q — revoked-serial consult armed (VerifyPeerCertificate rejects a presented leaf whose serial is in the CRL)", cfg.crlPath)
	}
	// (2) The revocation-reject counter seam: the transport's
	// VerifyPeerCertificate callback fires the reporter on each CRL reject.
	// nil (the default) leaves the reject silent; the binding here wires the
	// SSoT counter so the operator SEES the rejects on /metrics (Law V).
	tr.SetRevocationReporter(telemetry.CertRevokedRejected.Inc)
	// (2b) Day 31 (ADR-0036): the PQ-KEM-negotiated counter seam. The
	// transport's RecordHandshake (fired by transport.Dial after each
	// completed TLS handshake) increments the reporter IFF the negotiated
	// CurveID is X25519MLKEM768 (the PQ KEM — a classical fallback does NOT
	// increment). nil (the default) leaves the negotiation silent; the
	// binding here wires the SSoT counter so the operator SEES the PQ KEM
	// happening on /metrics (Law V — the prove-NOT-enable disclosure: the
	// engine ALREADY negotiates X25519MLKEM768 by Go 1.24+ default; the
	// counter is the PROOF, NOT the mechanism). Wired UNCONDITIONALLY (the
	// --hybrid-verify flag gates the SIGNATURE verify, NOT the KEM disclosure).
	tr.SetPQHandshakeReporter(telemetry.PQHandshakeNegotiated.Inc)
	// (3) The automated leaf-rotation trigger: --cert-rotation-enable arms the
	// poll goroutine. The minter is the in-process dev-mesh CA (the selftest
	// path mints one in mintSelftestCerts; the operator path uses on-disk PEMs
	// the operator provides — NO in-process CA — so the rotation minter is
	// wired ONLY for the selftest path here; a production fork that wants
	// automated rotation on the operator path supplies an out-of-process minter
	// via the certMinter seam, disclosed ADR-0035 §6). The trigger fires the
	// CertRotationTriggered counter.
	if cfg.certRotationEnable {
		minter, minterErr := buildRotationMinter(selftestCA, nodeID, certPath, keyPath, tr)
		if minterErr != nil {
			return fmt.Errorf("Day-30 cert rotation: %w", minterErr)
		}
		stopRot, rotErr := tr.StartRotationManager(context.Background(), cfg.certRotationPoll, cfg.certRotationLifetime, minter, telemetry.CertRotationTriggered.Inc)
		if rotErr != nil {
			return fmt.Errorf("Day-30 cert rotation manager: %w", rotErr)
		}
		defer stopRot()
		log.Printf("Day-30: automated leaf-cert rotation armed (poll=%s, pre-expiry-lifetime=%s; the goroutine mints a NEW leaf + Reloads when the live leaf is within %s of its NotAfter)",
			cfg.certRotationPoll, cfg.certRotationLifetime, cfg.certRotationLifetime)
	}

	// Construct the FROZEN engine + the receive gate stack. Every constructor
	// here is grep-verified (see the package doc above + ADR-0006).
	arenaSize := uintptr(cfg.arenaMib) * 1024 * 1024
	if arenaSize == 0 {
		arenaSize = defaultArenaSize
	}
	// Day 8: durability is OPT-IN. --wal-path empty (default) = in-memory
	// research mode = Day-7 back-compat: a fresh engine at initialCounter=1, NO
	// WAL, NO fsync on the origin write path (the silicon bench path UNTOUCHED).
	// When --wal-path is set, boot from the WAL via RecoverEngine: replay the
	// durable log into a fresh engine, assert crash-consistency against the last
	// checkpoint, and reopen the WAL for append. ErrRecoveryRootMismatch is
	// FATAL — a sick engine that fails Merkle-equality on recovery MUST NOT
	// start (the Codex: "every error path must be loud"). The bridge binds the
	// recovered engine + WAL so InsertLocalEvents fsyncs the engine-STAMPED dot
	// per mutation (the physical order, §6).
	var engine *eng.DeltaCRDTEngine
	var bridge *durability.Bridge
	// queryResolver is the Day-12 bitemporal query tier over the persisted
	// Arrow index (Resolver.AsOf → /v1/query). It is nil by default: a
	// research/in-memory node (--wal-path empty) OR a durable node started
	// WITHOUT --lsm-root never constructs it, so /v1/query returns the honest
	// 503 (control.go handleQuery). Only the --lsm-root snapshot-store branch
	// below constructs it. ADR-0017.
	// queryResolver is the Day-12 bitemporal query tier over the persisted
	// Arrow index (Resolver.AsOf → /v1/query). It is nil by default: a
	// research/in-memory node (--wal-path empty) OR a durable node started
	// WITHOUT --lsm-root never constructs it, so /v1/query returns the honest
	// 503 (control.go handleQuery). Only the --lsm-root snapshot-store branch
	// below constructs it. ADR-0017.
	// queryCompactor is the Day-14 L0→L1 per-entity compaction tier over the
	// SAME *LocalFS the resolver reads. Nil by default (same gate as
	// queryResolver — --lsm-root + enableIndex=true). ADR-0019.
	var queryResolver *database.Resolver
	var queryCompactor *database.L1Compactor
	// Day 16 (ADR-0021): the L0 reaper. nil (the default — --compaction-reap-
	// enable=false) means byte-identical Day-15 behavior (superseded L0s stay as
	// the backstop). Non-nil only when --lsm-root + --compaction-reap-enable.
	var queryReaper *database.L0Reaper
	if cfg.walPath != "" {
		// Day 11: when --lsm-root is a directory, bounded recovery loads the
		// dot-bearing snapshot + replays only the post-checkpoint tail. The
		// snapshot store is a *LocalFS over cfg.lsmRoot; a failing/absent
		// snapshot there silently falls back to full replay (store != nil but
		// image missing → fallbackReason logged by RecoverEngineWithSnapshot).
		var snapshotStore durability.SnapshotStore
		if cfg.lsmRoot != "" {
			lfs, lerr := durability.NewLocalFS(cfg.lsmRoot)
			if lerr != nil {
				return fmt.Errorf("lsm-root %s: %w", cfg.lsmRoot, lerr)
			}
			snapshotStore = lfs
		}
		recEngine, wal, rep, witness, rerr := durability.RecoverEngineWithSnapshot(nodeID, cfg.walPath, snapshotStore, arenaSize)
		if rerr != nil {
			if errors.Is(rerr, durability.ErrRecoveryRootMismatch) {
				log.Fatalf("sovereign-node: %v — sick engine refuses boot (rebuilt Merkle root != checkpoint root; data loss)", rerr)
			}
			return fmt.Errorf("recovery: %w", rerr)
		}
		engine = recEngine
		bridge = durability.NewBridge(engine, wal, cfg.walCheckpointInterval)
		// Day 8.5 MAJOR-1: the recovered engine's scratch data dir is owned by
		// the bridge so Close RemoveAll's it (no /tmp leak across restarts).
		bridge.SetScratchDir(rep.ScratchDir)
		// Day 11: wire the snapshot into the bridge's checkpoint path so future
		// AppendCheckpoint calls (explicit + periodic inside PutLocal) write
		// the dot-bearing image + Arrow index, keeping bounded recovery useful
		// across the node's lifetime (not just the first boot). enableIndex=true
		// writes the query-tier Arrow snapshot too (M8: wires internal/database).
		if snapshotStore != nil {
			lfs := snapshotStore.(*durability.LocalFS)
			bridge.SetSnapshotter(lfs, true)
			// Day 12: construct the bitemporal query Resolver over the SAME
			// *LocalFS the snapshotter writes the l0/*.arrow index to (one root,
			// one FS handle — avoids divergent dir state; ADR-0017 §2.2). The
			// Resolver is the off-heap READ buffer allocator for AsOf's Arrow
			// file scan. It is gated on enableIndex=true — the SAME flag
			// SetSnapshotter flips — so a research node (no --lsm-root) keeps
			// queryResolver nil and /v1/query returns the honest 503.
			//
			// Allocator lifecycle: JemallocAllocator is a stateless handle
			// (struct{bytesAllocated atomic.Int64}; NewJemallocAllocator is a
			// trivial ctor, no arena init — the same handle NewSnapshotMemTable
			// constructs per-checkpoint). It has NO Close: AsOf releases each
			// read buffer per scanFile via defer (query.go:216-220), so no
			// off-heap bytes survive a query; the handle itself holds nothing.
			// Zero shutdown teardown needed; the per-buffer Free IS the
			// lifecycle. ADR-0017 §4.
			queryAlloc := database.NewJemallocAllocator()
			queryResolver = database.NewResolver(
				lfs, lfs, queryAlloc, "local", database.DefaultResolverConfig(),
			)
			// Day 27 (ADR-0032): wire the read-your-writes live source. The
			// resolver consults the live δ-CRDT HAMT (engine.State().Get, EBR-
			// pinned by the adapter) AFTER its durable Arrow scan, merging the
			// live dominant under the SAME bitemporal dominance so a POST
			// /v1/insert is visible to /v1/query IMMEDIATELY — before the
			// bridge's periodic AppendCheckpoint flushes SnapshotToLSM→L0
			// (bridge.go:213, gated by checkpointInterval default 1000). With
			// the default, every IMMEDIATE /v1/query → 404 without this seam
			// (empirically confirmed Day-26; --wal-checkpoint-interval=1 was
			// REQUIRED for the durable read path to work at all).
			//
			// The adapter wraps the recovered engine (the SAME engine handleGet
			// reads through gossiper.engine — main.go:339 sets engine=recEngine).
			// It is constructed ONLY here (--lsm-root set, the SAME gate that
			// constructs the resolver), injected via SetLiveSource (the Day-12
			// SetResolver precedent carried to the live source — NOT a NewResolver
			// ctor arg, so NewResolver keeps its 5-arg signature). A research node
			// (no --lsm-root) keeps queryResolver nil → SetLiveSource is never
			// called → /v1/query returns the honest 503 (control.go:404), AND a
			// durable node with the resolver but a nil live source keeps the
			// durable-only behavior byte-identical to Day-26 (the nil-guard in
			// AsOf/Range — query.go:535/795).
			queryResolver.SetLiveSource(&engineHAMTAdapter{engine: engine})
			// Day 14 (ADR-0019): the L0→L1 per-entity compaction tier over the
			// SAME *LocalFS the resolver reads + the snapshotter writes the
			// l0/*.arrow index to. It is gated on enableIndex=true (the SAME
			// flag SetSnapshotter flips) + --lsm-root: a research node (no
			// --lsm-root) keeps queryCompactor nil. The compactor is a
			// READ-L0 -> WRITE-L1 background job — it never touches the
			// SkipList/HAMT/WAL write path. The scheduler goroutine (started
			// below alongside the convergence poller) periodically lists the
			// entity prefixes under l0/ and runs a Compaction job for any
			// entity with >= L0FilesPerEntityTrigger L0 files, merging them into
			// ONE sorted L1 file so AsOf's MaxL0Files cap bounds the TAIL (a
			// perf cap), NOT the full history (the silent-data-loss cap form).
			//
			// Day 15 (ADR-0020): the config honors the operator Level-2
			// superseded-row prune knobs. The DEFAULT is Preserve-All
			// (cfg.compactionPruneEnable=false) -> byte-identical Day-14
			// compaction. ENABLED + a positive horizon opts the merge into
			// dropping provably-dead rows under the (C1)&&(C2)&&(C3) SAFE-DROP
			// rule. ENABLED + horizon<=0 is trapped by NewL1Compactor (WARN +
			// coerce-to-Preserve-All) — the loud path; the config is built with
			// the operator's values VERBATIM so the WARN is honest.
			compactionCfg := database.DefaultCompactionConfig()
			compactionCfg.EnableDominancePruning = cfg.compactionPruneEnable
			compactionCfg.PruningHorizonInt64Ns = cfg.compactionPruneHorizon
			// Day 22 (ADR-0027): the T_gc auto-inference backoff. The inferrer
			// computes effective = max(operatorFloor, observedFrontier - backoff);
			// the operator-set PruningHorizonInt64Ns is the HARD floor backstop
			// (the inferrer FLOORS the knob, it does NOT replace it — §0.a). The
			// scheduler reads the Resolver's observed txTime frontier + calls
			// SetInferredHorizon BEFORE each per-entity CompactionByHash8, so the
			// effective horizon advances with the workload, never an operator
			// guess. Default 5m (the --compaction-prune-backoff-ns default);
			// the operator can lower it OR raise the hard floor.
			compactionCfg.PruneBackoffInt64Ns = cfg.compactionPruneBackoff.Nanoseconds()
			queryCompactor = database.NewL1Compactor(
				lfs, lfs, lfs, queryAlloc, "local", compactionCfg,
			)
			// Day 16 (ADR-0021): the L0 reaper over the SAME *LocalFS the
			// compactor + resolver share (one FS root, one keyspace). The
			// reaper injects the SAME lfs handle for all three seams (S3Lister
			// to scan manifests, S3Downloader to read a manifest + probe its L1,
			// the NEW S3Deleter to remove an L0 + the manifest). The reaper is
			// GATED on --compaction-reap-enable (default false) — OFF means the
			// superseded L0s stay on disk as the crash-recovery backstop (byte-
			// identical Day-15). The reaper goroutine (started below alongside
			// the compaction scheduler) reclaims the L0s the compactor
			// superseded AFTER verifying the L1 still exists (Stage C). It is
			// NEVER auto-ON: the operator opts in ONLY once they trust their
			// storage layer's existence-probe.
			if cfg.compactionReapEnable {
				queryReaper = database.NewL0Reaper(lfs, lfs, lfs, "local")
			}
		}
		if witness != nil && witness.Bounded {
			log.Printf("sovereign-node: durability ON — bounded recovery booted from WAL %s + snapshot ckpt/%d (replayed %d post-checkpoint record(s), bridge active)",
				cfg.walPath, witness.SnapshotLamportHigh, witness.ReplayedRecords)
		} else if witness != nil && snapshotStore != nil && witness.FallbackReason != "" {
			log.Printf("sovereign-node: durability ON — full-replay recovery booted from WAL %s (bounded recovery fallback: %s; bridge active)", cfg.walPath, witness.FallbackReason)
		} else {
			log.Printf("sovereign-node: durability ON — booted from WAL %s (bridge active, fsync-per-mutation)", cfg.walPath)
		}
	} else {
		engine, err = eng.NewDeltaCRDTEngine(nodeID, 1, arenaSize) // crdt.go:244
		if err != nil {
			return fmt.Errorf("engine: %w", err)
		}
		log.Printf("sovereign-node: durability OFF — in-memory research mode (--wal-path empty, Day-7 back-compat)")
	}
	wallClock := clock.NewSystemClock()                                                   // clock.go:48 (WallClock)
	cap := clock.NewIngressHLCScalarCap(wallClock, engine)                                // admission.go:72 (engine IS the LogicalAdvancer)
	bucket := admission.NewPeerBucket()                                                   // ewma.go:150 (zero args)
	dir := identity.NewDirectory()                                                        // directory.go:47 (zero args)
	recv := receive.NewReceiver(bucket, cap, wallClock, dir, engine, cfg.admissionBudget) // receiver.go:173
	// Day 31 (ADR-0036): --hybrid-verify (opt-IN, default false). OFF keeps the
	// receive path on the classical-only identity.VerifyCRDTFrame seam —
	// byte-identical Day-30 (the production default stays classical-only; the
	// hybrid is a defense-in-depth ADD, NOT a replace). ON switches the two
	// verify call sites (receiver.go HandleFrame + HandleBatchFrame) to the
	// hybrid VerifyCRDTFrame_Hybrid seam — BOTH Ed25519 + ML-DSA-65 sigs
	// required. The v1 envelope carries ONLY the Ed25519 sig, so under
	// --hybrid-verify a v1 frame is REJECTED (the STRICT mode) until the hybrid-
	// SIGN fork ships a frame carrying BOTH sigs + the Directory carries the
	// peer's ML-DSA-65 pubkey — disclosed ADR-0036 §6 (the honest NOT-YET).
	recv.SetHybridVerify(cfg.hybridVerifyEnable)

	// SIGHUP -> cert rotation (the live-reload seam). A reload error is
	// logged, not fatal — a stale cert keeps serving; a failed reload is an
	// honest NEGATIVE recorded in the ADR.
	// ── Day 2: CRDT-delta signing identity + the mesh (dial + gossip sweep) ──
	// The engine's localNodeID is the [16]byte the gate stack keys on. For the
	// mesh's signed-envelope seam the gossiper signs with an Ed25519 seed whose
	// derived pubkey's first 16 bytes MUST equal that localNodeID, so the
	// receive-side Directory.Lookup(originNodeID) resolves back to this node's
	// pubkey. If --identity-seed is provided it overrides (and --node-id must
	// match its derived nodeID); otherwise a random seed is minted and its
	// derived nodeID is what the engine runs under.
	ident := buildNodeIdentity(cfg, nodeID)
	// Register this node's OWN pubkey in the Directory so it can verify its
	// own loopback deltas (a peer that echoes a frame back to the origin still
	// verifies). The peer pubkeys are registered out-of-band by the deploy
	// (the dev-mesh CA's leaf CommonName carries the hex nodeID; a deploy-time
	// directory provisioning step reads each peer's pubkey. Day 2's binary
	// documents this honestly; programmatic peer-pubkey provisioning ships
	// with the Day-7 cluster deploy).
	_ = dir.Register(ident.NodeID, ident.Pub)
	// Day 32 (ADR-0037): when --hybrid-sign is set, the owner was constructed
	// via NewNodeIdentityHybrid (buildNodeIdentity) so it carries the ML-DSA-65
	// keypair. Register the PQ pubkey in the Directory via RegisterPQ so this
	// node's OWN loopback hybrid frames verify (a peer that echoes a hybrid
	// frame back to the origin still verifies — the SAME self-registration
	// discipline the classical Register above uses) AND so peers' hybrid verify
	// resolves this origin's PQ key via LookupBoth. A non-hybrid-sign owner (the
	// DEFAULT) has ident.PQPub == nil -> RegisterPQ is skipped (NO PQ key is
	// registered; the Directory's mPQ map is unpopulated for this nodeID -> a
	// hybrid verify from a peer would reject via the nil-pqPub STRICT mode —
	// the honest posture under the default). The peer PQ pubkeys are
	// provisioned out-of-band by the deploy (the SAME OOB model the classical
	// peer pubkeys use — directory.go:20 comment; programmatic peer-PQ-pubkey
	// provisioning ships with the future directory-gossip fork).
	if ident.PQPub != nil {
		if err := dir.RegisterPQ(ident.NodeID, ident.PQPub); err != nil {
			log.Fatalf("identity: RegisterPQ: %v", err)
		}
	}
	peerSet := mesh.NewPeerSet(tr, recv, ident, engine)
	gossiper := mesh.NewGossiper(peerSet, ident, engine, dir)
	// Day-5 batched delta transport: --batch-size > 1 switches the self-originated
	// delta path from per-frame shipDelta (one Ed25519 per delta) to shipBatchedDelta
	// (one Ed25519 per N deltas — the arithmetic unlock). 1 keeps the per-frame
	// path (back-compat); the relay/foreign path stays per-frame regardless (the
	// self-origin boundary). SetBatchSize clamps to [1, MaxBatchSize].
	gossiper.SetBatchSize(cfg.batchSize)
	// Day 29 (ADR-0034): --stratified-anti-entropy (opt-IN, default false). OFF
	// keeps the sweep byte-identical to HEAD's oversend path (the existing
	// convergence + partition teeth stay GREEN); ON switches to the M3 two-phase
	// digest-exchange (per-peer SE + full IBLT digest → GenerateDelta(remoteIBLT)
	// for a minimal delta proportional to |A−B| — the M2 fix; the broken
	// GenerateDeltaStratified that subtracted an EMPTY remote IBLT is DELETED).
	// The fallback to oversend on a
	// digest timeout / malformed digest / peel failure is the M5 honest path,
	// counted via sovereign_mesh_stratified_fallback (the 19th SSoT counter,
	// bound below so the operator SEES the oversend-vs-stratified cut). The
	// digest-exchange rides the peer-TLS data-plane (a WireDigestMagic-tagged
	// frame), NOT a control-port route — the mesh is pure peer-TLS data-plane
	// (the test infra builds NO ControlServer; a control route would be
	// unreachable from the sweep).
	gossiper.SetStratifiedAntiEntropy(cfg.stratifiedAntiEntropy)
	gossiper.SetStratifiedFallbackReporter(telemetry.StratifiedAntiEntropyFallback.Inc)
	// Day 32 (ADR-0037): --hybrid-sign (opt-IN, default false). OFF keeps the
	// self-originated delta path on the v1 BatchEnvelope (one Ed25519 per batch)
	// — byte-identical Day-31 (NO hybrid frame is produced; the receive-side
	// --hybrid-verify gate never sees one — T-PQ-HYBRID-OFF-IS-BYTE-IDENTICAL).
	// ON switches shipBatchedDelta's self-originated path to ShipBatchHybrid
	// (one Ed25519 + one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad,
	// carried in a HybridEnvelope). The owner was constructed via
	// NewNodeIdentityHybrid when this is true (buildNodeIdentity) so the PQ key
	// is minted + registered (above). The HybridFrameAccepted counter
	// (the 23rd SSoT) is wired UNCONDITIONALLY regardless of this flag (the
	// SetStratifiedFallbackReporter precedent — the reporter seam is bound at
	// boot; the flag gates the SIGN, NOT the accept disclosure). The counter
	// fires on the Receiver.HandleHybridFrame seam; a node with
	// --hybrid-sign=false (the DEFAULT) never produces a hybrid frame so the
	// counter stays 0 (a peer that dials it sends a v1 BatchEnvelope), but the
	// counter is still PRESENT on /metrics (the bridge auto-surface §0.f —
	// PRESENCE not value, the SAME discipline Day-29/30/31 used).
	gossiper.SetHybridSign(cfg.hybridSignEnable)
	recv.SetHybridAcceptReporter(telemetry.HybridFrameAccepted.Inc)
	// Day 34 (ADR-0039): the region-aware gossip data-plane. --region-aware
	// (OPT-IN, default false) switches AntiEntropySweep's iteration source from
	// the full-mesh peers.Peers() (O(N²) connections at N nodes) to
	// topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N,
	// prefer cross-region, seeded-deterministic — the O(log N) rounds
	// convergence the blueprint names). The TopologyManager is built from
	// --self-region (this node's own region tag — the intra/inter split key; 0 =
	// RegionUnset = every peer intra = byte-identical full-mesh) + the per-peer
	// region tags parsed from --peers' addr@region suffixes (a peer with NO
	// @region suffix is RegionUnset = SAME-region = intra — the honest
	// conservative default). SetTopology binds the seam; SetRegionAware arms the
	// selector (the "wire first, arm later" discipline — both must be true);
	// SetInterRegionReporter wires the M6 disclosure counter (the 24th SSoT —
	// fires once per inter-region envelope shipped). The wiring is OPT-IN: with
	// --region-aware=false (the DEFAULT), AntiEntropySweep takes the full-mesh
	// peers.Peers() path — byte-identical Day-33 (T-TOPO-OFF-IS-BYTE-IDENTICAL;
	// the topology is built + bound but the selector is NOT armed, so the sweep
	// ignores it). NO new module dep (stdlib only); NO AWS this fork.
	topo := mesh.NewTopologyManager(mesh.RegionTag(cfg.selfRegion))
	topo.SetFanout(cfg.regionFanout)
	// Day 35 (ADR-0040): parse --peer-dir ONCE here, BEFORE the Day-34
	// surrogate region loop, so the loop can SKIP a peer that --peer-dir
	// provisions (the /code-review surrogate-pollution finding: altitude #1 +
	// Angle C #2). The Day-34 loop keys region tags under peerIDForAddr(addr) —
	// a SHA-256 surrogate — but a PROVISIONED peer's dial keys the peerConn
	// under the REAL nodeID (applyProvisioning's SetRegion(realNodeID, region)),
	// NEVER the surrogate. So a peer tagged @region in --peers AND provisioned in
	// --peer-dir would leave a DEAD surrogate in topo.regions (no live peerConn
	// keys it) → topology.Select iterates BOTH the surrogate + the real nodeID
	// → the dead surrogate consumes an inter-region fan-out slot, evicting a
	// real cross-region peer → convergence slows/stalls at scale + the 24th SSoT
	// counter over-counts (IsInterRegion(surrogate)=true fires the reporter
	// though no envelope ships). The fix: the surrogate loop skips any addr
	// --peer-dir provisions (the provisioned peer gets its region via
	// applyProvisioning's SetRegion(realNodeID, region) instead). The provisioned
	// peer's region column takes precedence over the @region suffix (the
	// --peer-dir file is the authoritative OOB source). The side-effecting
	// applyProvisioning runs LATER (the dial loop, line ~1232) with these same
	// cfgs (the cheap FAILSAFE parse here is pure; no double side-effect).
	provCfgs, provParseErr := parsePeerDir(cfg.peerDir)
	if provParseErr != nil && !errors.Is(provParseErr, ErrPeerDirEmpty) {
		// A named-but-absent file OR a malformed entry FAILS the boot here (a
		// deploy misconfiguration MUST be loud — the FAILSAFE discipline). The
		// empty --peer-dir (ErrPeerDirEmpty) is the OPT-IN no-op: provCfgs stays
		// empty + the surrogate loop runs for every peer (byte-identical Day-34).
		return fmt.Errorf("--peer-dir: %w", provParseErr)
	}
	provisionedAddr := make(map[string]bool, len(provCfgs))
	for _, c := range provCfgs {
		provisionedAddr[c.addr] = true
	}
	// Register the per-peer region tags parsed from --peers' addr@region
	// suffixes. The dial-side peerID is a PLACEHOLDER zero (the Day-2 honest gap
	// — the peer's nodeID is unknown until the peer presents its leaf; the
	// Directory resolves the pubkey regardless), so the region tag is keyed by
	// a DETERMINISTIC addr-derived [16]byte (SHA-256 of the peer addr,
	// truncated — a STABLE peerID surrogate the future OOB-provisioning fork
	// reconciles with the real nodeID once the dial loop carries real peerIDs).
	// A peer with NO @region suffix is RegionUnset (the honest conservative
	// default — an untagged peer routes as SAME-region = intra, NOT foreign).
	// The HONEST N=2 NO-OP: the cmd dial loop stores peers under the ZERO
	// peerID (peer.go:267 ps.peers[zeroPeerID]), so peers.Peers() returns zero
	// peerIDs that do NOT match the addr-derived keys the region tags are
	// registered under → the region lookup misses → every peer routes as
	// RegionUnset = intra = byte-identical full-mesh. --region-aware ON at N=2
	// is therefore a NO-OP UNLESS the peers are tagged AND the dial loop carries
	// real peerIDs (the Day-35+ OOB-provisioning arc). The loopback gate is the
	// SIMULATED N=100 mesh (in-process, REAL peerIDs), NOT the 2-node binary
	// run — the same honest residual the prompt's §III gate names.
	// Day 35 (ADR-0040): SKIP the surrogate for a PROVISIONED addr (the dead-
	// surrogate-pollution fix above) — its region comes from --peer-dir.
	applySurrogateRegions(topo, cfg.peers, provisionedAddr)
	gossiper.SetTopology(topo)
	gossiper.SetRegionAware(cfg.regionAwareEnable)
	gossiper.SetInterRegionReporter(telemetry.InterRegionEnvelopesShipped.Inc)
	// Day 8: bind the durability bridge so InsertLocalEvents routes the origin
	// write through PutLocal (InsertLocal → AppendMutation fsync) when --wal-path
	// is set. A nil bridge (the in-memory default) keeps the Day-7 bare-
	// engine.InsertLocal path UNTOUCHED.
	if bridge != nil {
		gossiper.SetBridge(bridge)
		// Day 8.5: wire the receive-seam clock-advance recorder so a peer-driven
		// Join (foreign AdvanceLamportTo inside the FROZEN engine) is WAL-recorded.
		// Without this, a foreign clock jump is un-recorded → the recovery seed
		// under-counts → replay re-mints different dots → Merkle diverges (the
		// Day-8 foreign-advance CRITICAL). The recorder fires post-Accept in
		// Receiver.HandleFrame/HandleBatchFrame; nil (the in-memory default) is a
		// no-op, so the Day-7 research path is untouched. See ADR-0013 §7 for the
		// over-record caveat (post-Accept high-water vs exact foreign counter).
		recv.SetClockAdvanceRecorder(func(c uint64) error {
			return bridge.WAL().AppendClockAdvance(c)
		})
	}

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			// Day 30 (ADR-0035): a SIGHUP reloads the FULL triple — leaf, CA
			// pool, CRL — NOT just the leaf (the pre-Day-30 behavior the :126
			// comment named). Each reload is INDEPENDENT + atomic under the
			// transport's RWMutex; a FAILED reload of one surface leaves the
			// stale version in place (the honest-negative posture — the transport
			// NEVER trust-degrades OR revocation-degrades on a failed reload).
			// The leaf reload stays FIRST (the byte-identical pre-Day-30 seam +
			// the TestTLSCertRotation_SIGHUP contract). The CA + CRL reloads are
			// BEST-EFFORT: a SIGHUP with no --crl-path leaves the CRL reload a
			// no-op (ReloadCRL returns ErrNoCRLPath, logged + swallowed — the
			// opt-OUT default). The CA reload is unconditional (caPath is always
			// set at construction).
			if err := tr.Reload(); err != nil {
				log.Printf("SIGHUP: cert reload FAILED: %v (stale leaf still serving)", err)
				// Continue to the CA + CRL reloads — a failed leaf reload does
				// NOT block a CA or CRL update (the triple is independent).
			} else {
				log.Printf("SIGHUP: cert reloaded (new leaf live on next handshake)")
			}
			if err := tr.ReloadCA(); err != nil {
				log.Printf("SIGHUP: CA reload FAILED: %v (stale CA pool still serving — the transport NEVER trust-degrades on a failed reload)", err)
			} else {
				log.Printf("SIGHUP: CA pool reloaded (new trust root live on next handshake)")
			}
			if cfg.crlPath != "" {
				if err := tr.ReloadCRL(); err != nil {
					log.Printf("SIGHUP: CRL reload FAILED: %v (stale revoked-serial set still consulting)", err)
				} else {
					log.Printf("SIGHUP: CRL reloaded (new revoked-serial set live on next handshake)")
				}
			}
		}
	}()

	// /livecheck + /metrics control surface: PLAIN net/http, no TLS. It is ops
	// debug, NOT the data plane (named in ADR-0006; the C1 boundary — /metrics
	// is the SAME plain-HTTP control surface as /livecheck, NOT the data
	// plane). Day 3 adds the /metrics Prometheus scrape route to the SAME mux
	// (one server, one mux, the --metrics-addr flag already binds it) + the
	// per-process Registry (the duplicate-registration root-cause fix,
	// ADR-0008 §3). A TLS-or + auth-hardened /metrics is a future hardened-ops
	// track, honestly deferred (ADR-0006 §8 item 3 + ADR-0008 §8).
	metricsExp := metrics.NewExporter()
	// Wire the gossip-round counter seam: every executed sweep round increments
	// sovereign_gossip_rounds_total (the datapath-restored signal the silicon
	// partition harness reads — FACT 2). Bound before SweepLoop starts below.
	gossiper.SetRoundReporter(metricsExp.Recorder().IncGossipRound)
	// Day 21 (ADR-0026): arm telemetry.Init at boot with a real OTel SDK
	// MeterProvider when --otel is set. This MUST precede the bridge
	// construction below: telemetry.Init triggers rebuildCounters, which
	// reassigns the package-level *Counter pointers AND rebinds the SSoT slice
	// (counters = allCounters()). The bridge calls telemetry.Counters() at
	// NewTelemetryBridge() (the SSoT snapshot), so Init must run BEFORE that so
	// the bridge captures the post-Init counter pointers. The OTel reader (a
	// PeriodicReader over logOutputExporter) exports through a SEPARATE
	// destination from the bridge's prometheus Registry — the two-exporter
	// separation (§0.d): the bridge reads CUMULATIVE via Counter.Value() (never
	// lastReported); the OTel callback reads DELTA via lastReported. cumulative
	// == sum-of-deltas; the two never collide at /metrics because OTel is NOT a
	// prometheus.Collector. --otel=false (the DEFAULT) keeps the Day-18
	// bridge-alone behavior byte-identical (the synchronous-nop Meter fallback
	// in registry.go governs; the bridge still scrapes 12 cumulative series).
	otelShutdown, otelErr := armOTel(cfg.otelEnabled, hex.EncodeToString(nodeID[:]), cfg.otelInterval)
	if otelErr != nil {
		log.Printf("sovereign-node: OTel arming FAILED: %v — OTel dark, prometheus bridge unaffected (the bridge reads the SAME Counter.Value() it always did)", otelErr)
	}
	defer otelShutdown(context.Background())
	// Day 18 (ADR-0023): bridge the internal/telemetry LongAdder counters (the
	// 12 distinct supremum.* counters surfaced since Day 13) onto the
	// per-process /metrics Registry. Until today the data plane Add()/Inc() on
	// every flush / compaction / prune / reap touched those counters but NONE
	// reached /metrics — including the SAFETY-CRITICAL
	// supremum_compaction_l0_reap_manifests_skipped_orphan (the Stage-C reaper
	// guard's operator signal). The bridge is the prometheus.Collector that
	// closes that operator-blindness defect: it enumerates
	// telemetry.Counters() and emits one cumulative const series per counter
	// (CUMULATIVE not delta — see the §0.b double-count trap in ADR-0023; the
	// bridge reads Counter.Value() and NEVER touches lastReported). Registered
	// into the SAME per-process Registry as the Recorder's sovereign_* series
	// (the two series coexist by name — sovereign_* vs supremum_*, never
	// colliding). NOTE the deliberate absence of telemetry.Init: wiring a real
	// colliding). Day 21 (ADR-0026) ARMED telemetry.Init above (when --otel is
	// set); the bridge stays SAFE whether or not that happens — the
	// lastReported callback that arming Init fires is the OTel layer's concern,
	// NOT the bridge's (the bridge reads only Counter.Value(), never
	// lastReported — the §0.b trap is disarmed by the two-exporter separation
	// in armOTel, not by sharing a value). Registering BEFORE startLivecheck
	// fires the first scrape.
	telemetryBridge := metrics.NewTelemetryBridge()
	metricsExp.Registry().MustRegister(telemetryBridge)
	metricsSrv := startLivecheck(cfg.metricsAddr, nodeID, peers, metricsExp)
	defer metricsSrv.Shutdown(context.Background())

	// Day 6: the JSON-over-mTLS client control port. --control-addr defaults OFF
	// (empty) — no client API unless the operator explicitly enables it, so a
	// misconfigured node is still a peer in the mesh (the data plane is
	// unaffected). When set, it is a SEPARATE *tls.Listener (NOT the --bind peer
	// listener, NOT the --metrics-addr plain-HTTP surface) serving the /v1/* JSON
	// routes with the SAME mTLS config as the peer path (RequireAndVerifyClientCert,
	// Min==Max==1.3 — ADR-0006). Three surfaces, one trust root (ADR-0011 §3).
	// The control port does NOT touch the receive gate stack (receiver.go /
	// ingress_epoll.go stay byte-locked); it has its own http.Server.
	var controlSrv *http.Server
	if cfg.controlAddr != "" {
		controlSrv = startControlPort(cfg.controlAddr, tr, gossiper, nodeID, peers, metricsExp, queryResolver)
		defer controlSrv.Shutdown(context.Background())
	}

	// TLS listener (the Day-1 encrypted pipe).
	ln, err := tr.Listen("tcp", cfg.bind)
	if err != nil {
		return fmt.Errorf("tls listen %s: %w", cfg.bind, err)
	}
	defer ln.Close()
	log.Printf("sovereign-node: TLS 1.3 listener bound on %s (nodeID=%x)", cfg.bind, nodeID)
	if len(peers) > 0 {
		log.Printf("peers configured: %v — dial loop pending Day 2", peers)
	} else {
		log.Printf("no peers configured (single-node Day 1)")
	}

	// Accept loop: per *tls.Conn, install a goroutine that reassembles
	// length-prefixed frames and drives the gate stack. The gate-stack order
	// at receiver.go:244 is PROVEN and UNTOUCHED; this binary is a CALLER.
	// Day 3 (Option B — the observer wrapper, ADR-0008 §3): the per-conn
	// goroutine wraps HandleFrame with `start := time.Now(); av := HandleFrame;
	// recorder.RecordIngest(time.Since(start), av.Verdict)`. receiver.go stays
	// byte-locked (md5 9dfde188); the Verdict enum carries 100% of the per-gate
	// signal, so the wrapper captures it at the caller, not in the gate stack.
	acceptCtx, acceptCancel := context.WithCancel(context.Background())
	defer acceptCancel()
	// Day-29 (ADR-0034): thread the Gossiper as the digest sink so the
	// accept-side serveConn can route a WireDigestMagic-tagged frame to
	// DeliverDigest (the sweep's per-peer blocking-receive producer). The
	// digestDemuxer is a nil-safe shim: a --selftest path that constructs no
	// gossiper passes a nil digester + serveConn's digest branch is a no-op
	// drop (the honest cold-start when stratified is OFF). The gossiper is
	// constructed above (main.go:515) before the accept loop starts, so the
	// sink is bound at accept-loop launch.
	var acceptDigester mesh.DigestSink
	if gossiper != nil {
		acceptDigester = digestDemuxer{g: gossiper}
	}
	go acceptLoopWithDigest(acceptCtx, ln, recv, metricsExp.Recorder(), acceptDigester)

	// ── Day 2: dial each configured peer + start the anti-entropy sweep ──
	// The accept loop is already serving (Day 1); this is the dial side. Each
	// dial reuses the Day-1 accept-side readLoop via the PeerSet, so a node that
	// both dials and accepts converges symmetrically.
	meshCtx, meshCancel := context.WithCancel(context.Background())
	defer meshCancel()
	// Day 35 (ADR-0040): the OOB peer-Directory pubkey provisioning (Seam A).
	// applyProvisioning parses --peer-dir (the line-oriented config mapping
	// addr → {nodeID, ed25519_pubkey, optional mldsa65_pubkey, optional region}),
	// calls gossiper.RegisterPeer (+ dir.RegisterPQ for the optional PQ arm) +
	// topo.SetRegion under the REAL nodeID, + returns the addr→nodeID map the
	// dial loop branches on. This retires the Day-34 §7.1 zero-peerID hazard:
	// the region tags now key on real nodeIDs (NOT peerIDForAddr surrogates),
	// so the topology selector HITS → Publish(realNodeID) succeeds → the 2-node
	// binary mesh converges → the 24th SSoT counter fires A=1 B=1. OPT-IN: an
	// empty --peer-dir (the default) returns an empty map + nil error (the
	// honest no-op — the dial loop's ELSE arm runs for every peer, byte-
	// identical Day-34). A NON-EMPTY path that does not exist OR a malformed
	// entry FAILS THE BOOT (a deploy misconfiguration MUST surface loudly, NOT
	// silently fall back to zero-peerID — the honest-negative posture; the
	// §III tooth T-OOB-CONFIG-PARSE bug-inject-proves the FAILSAFE parser).
	// gossiper (:947), dir (:893), + topo (:1007) are all guaranteed non-nil
	// here (constructed unconditionally above); no nil-guard needed.
	provisioned, provErr := applyProvisioning(gossiper, dir, topo, provCfgs)
	if provErr != nil {
		return fmt.Errorf("--peer-dir: %w", provErr)
	}
	// Day 35 /code-review finding #2 (the /code-review parent synthesis): a
	// --peer-dir addr NOT in --peers is registered (RegisterPeer/RegisterPQ +
	// SetRegion fire for it) but NEVER dialed — the dial loop iterates ONLY
	// --peers (parsePeers, main.go:655). The peer's pubkey sits in the Directory
	// unused on the dial side; this node never ships deltas to it (a silent
	// ONE-WAY partition — the peer can still send TO this node if IT dials out,
	// but this node's sweep never Publishes to it). The FAILSAFE parser cannot
	// catch this (each file is well-formed on its own); a strict subset check
	// would fail a legitimate bootstrap-peer config (an operator MAY provision a
	// peer's pubkey ahead of adding it to --peers). The honest posture: a
	// WARNING per unmatched --peer-dir addr makes the silent one-way partition
	// OBSERVABLE without failing a forward-provisioning deploy. `peers` is the
	// parsePeers(cfg.peers) slice in scope at main.go:655.
	if len(provisioned) > 0 {
		peersSet := make(map[string]bool, len(peers))
		for _, pa := range peers {
			peersSet[pa] = true
		}
		for paddr := range provisioned {
			if !peersSet[paddr] {
				log.Printf("sovereign-node: WARNING: peer %s is in --peer-dir but NOT in --peers — it is registered (RegisterPeer/RegisterPQ/SetRegion) but the dial loop never dials it, so this node never ships deltas to it (a silent one-way partition). Add it to --peers to dial it, or remove it from --peer-dir.", paddr)
			}
		}
	}
	// Day 35 (ADR-0040) Seam B: arm the runtime TLS-leaf reconcile. OPT-IN
	// (default false = byte-identical Day-34 — reconcilePeerID is NOT called,
	// the peerConn stays keyed under the caller-supplied peerID). ON switches
	// PeerSet.Dial to read the peer leaf CommonName + re-key under the REAL
	// nodeID for an UN-PROVISIONED peer (the routing complement — a deploy that
	// opts into --peer-auto-reconcile alone ROUTES via the handshake but does NOT
	// CONVERGE; convergence REQUIRES --peer-dir's RegisterPeer verification
	// pubkey, else the receiver's Directory.Lookup MISSES → DropVerify → no
	// convergence; the binary harness RUN 3 honest-negative PROVES reconcile-only
	// does NOT converge). ROUTING-only per M3.
	peerSet.SetAutoReconcile(cfg.autoReconcile)
	for _, pa := range peers {
		host, _, herr := net.SplitHostPort(pa)
		if herr != nil {
			host = "localhost"
		}
		// Day 35 (ADR-0040): the dial-peerID branch — the load-bearing fix that
		// retires the Day-2 zero-peerID hazard. IF the peer was provisioned via
		// --peer-dir (Seam A), dial under the REAL nodeID so the topology
		// selector HITS + Publish(realNodeID) succeeds → the 2-node binary mesh
		// converges. ELSE keep the zero peerID (byte-identical Day-34 back-
		// compat — the honest "operator did not provision this peer" default).
		// Seam B (--peer-auto-reconcile ON) further re-keys an UN-PROVISIONED
		// peer's peerConn to the real nodeID at the handshake (reconcilePeerID
		// in PeerSet.Dial); a PROVISIONED peer skips the reconcile (the peer is
		// keyed correctly already — the leaf CN is a redundant signal).
		var dialPeerID [16]byte
		isProvisioned := false
		if pid, ok := provisioned[pa]; ok {
			dialPeerID = pid
			isProvisioned = true
		} else if len(provisioned) > 0 {
			// Day 35 /code-review (altitude #3 + Angle C #3): the addr-consistency
			// WARNING. --peer-dir is set (provisioned is non-empty) BUT this --peers
			// addr is NOT in the provisioned map → the peer dials under the ZERO
			// peerID → topology.Select (keyed under the real nodeID by
			// applyProvisioning) misses → Publish(real) finds no live peerConn → a
			// SILENT PARTITION (the exact Day-34 §7.1 no-op the fork retires). The
			// common cause: a --peers addr (DNS name, leading-zero port, trailing
			// whitespace, IPv6 shorthand) that does not string-match the --peer-dir
			// first column. The FAILSAFE parser cannot catch cross-file mismatches
			// (each file is well-formed on its own); this WARNING makes the silent
			// partition OBSERVABLE without failing a legitimate bootstrap-peer
			// config (an operator MAY list a bootstrap peer in --peers not yet in
			// --peer-dir). A deploy that wants strict consistency can grep the boot
			// log for this WARNING. The honest posture: loud observation, not a
			// silent fall back to zero-peerID.
			log.Printf("sovereign-node: WARNING: peer %s is in --peers but NOT in --peer-dir — it will dial under the zero peerID (topology.Select will miss; Publish will find no live peerConn → silent partition). Verify the --peers addr string-matches the --peer-dir first column (DNS vs IP, port, whitespace).", pa)
		}
		// Day 35 carry-forward (ADR-0040): wire the production reconnect
		// watcher. The Day-2 dial loop was ONE-SHOT — a peer not yet listening
		// at boot (the inevitable 2-node startup race: whichever node boots
		// first dials the second, which is not up yet) = a PERMANENT miss; the
		// "dial loop pending Day 2" residual the boot log discloses. The
		// ReconnectLoop primitive (peer.go:528, docstring: "the production
		// binary wires it") re-dials with bounded exponential backoff until the
		// peer connects, then watches the conn + re-dials on drop. This retires
		// the RETRY half of the Day-2 dial hazard (the peerID half is retired
		// by the dial-peerID branch above) — the natural completion of "retire
		// the Day-2 dial hazard" so the 2-node binary mesh actually converges.
		// Idempotent + safe in all three modes: (a) a PROVISIONED peer (Seam A)
		// re-dials under the real nodeID; (b) an UN-PROVISIONED peer with
		// --peer-auto-reconcile ON (Seam B) re-keys at each successful dial via
		// reconcilePeerID; (c) an UN-PROVISIONED peer with reconcile OFF keeps
		// the zero peerID (byte-identical Day-34 — the reconnect just retries
		// the same honest "operator did not provision" no-op). Bounded by
		// meshCtx (cancels on shutdown) + a 10s backoff ceiling.
		dialErr := peerSet.Dial(meshCtx, pa, host, dialPeerID)
		if dialErr != nil {
			log.Printf("peer dial %s: %v (accept loop still serving; ReconnectLoop retries with backoff)", pa, dialErr)
		} else if isProvisioned {
			log.Printf("sovereign-node: dialed provisioned peer %x at %s (Seam A — real nodeID; topology selector will HIT)", dialPeerID, pa)
		}
		go peerSet.ReconnectLoop(meshCtx, pa, host, dialPeerID, time.Second, 10*time.Second)
	}
	tickDur, err := time.ParseDuration(cfg.gossipTick)
	if err != nil {
		return fmt.Errorf("--gossip-tick %q: %w", cfg.gossipTick, err)
	}
	go gossiper.SweepLoop(meshCtx, tickDur)
	if len(peers) > 0 {
		log.Printf("sovereign-node: mesh gossip sweep started, tick=%s, peers=%d", cfg.gossipTick, len(peers))
	} else {
		log.Printf("sovereign-node: no peers configured (single-node); sweep idle")
	}

	// Day 3: the 1s convergence-gauge poller. It reads the Gossiper's
	// convergence-lag seed OFF the hot path (the SweepLoop is the single
	// writer; this is the single reader) and feeds the three poller-driven
	// gauges: sovereign_convergence_lag_seconds (time since the last stable
	// root), sovereign_convergence_roots_equal (1.0 when the local root
	// matches the last converged root, 0.0 otherwise), and sovereign_ingest_pps
	// (instantaneous frames/sec from the verdict-counter delta). The poller
	// does NOT touch the ingest hot path.
	go convergenceGaugePoller(meshCtx, gossiper, metricsExp)

	// Day 14 (ADR-0019): the L0→L1 per-entity compaction scheduler. It has its
	// OWN goroutine (NOT the MemTable flush goroutine + NOT the sweep loop) so a
	// slow merge stalls compaction but NOT writes and NOT the anti-entropy mesh.
	// It periodically lists the l0/ entity prefixes; for each entity with ≥
	// L0FilesPerEntityTrigger L0 files it runs a Compaction job (READ-L0 →
	// WRITE-L1). The scheduler is nil (no --lsm-root) for a research node — no
	// compaction, the MaxL0Files cap stays the Day-13 silent-loss form
	// (compaction is opt-in, honestly disclosed); the L1 resolver remains query
	// correct over the uncompacted tail. Gated alongside meshCtx so SIGINT/SIGTERM
	// cancels it (the compaction honors ctx.Err() at every L0 download).
	go compactionSchedulerLoop(meshCtx, queryCompactor, queryResolver)
	if queryCompactor != nil {
		log.Printf("sovereign-node: L0→L1 compaction scheduler started, trigger=%d files/entity (read-L0/write-L1 background; no write-path lock)",
			queryCompactor.L0FilesPerEntityTrigger())
	}

	// Day 16 (ADR-0021): the L0 reaper goroutine. It reclaims manifest-listed
	// superseded L0 files AFTER verifying the L1 still exists (Stage C safety
	// guard). It is COMPLEMENTARY to the compaction scheduler (which DRIVES new
	// L1s + manifests; the reaper RECLAIMS the L0s the compactor superseded),
	// runs LESS often (default 5m vs compaction's 30s — the superseded L0s are
	// a safety net, zero urgency), and reaps ALL entities per sweep (not one at
	// a time like the per-entity compactor). A nil reaper (--compaction-reap-
	// enable=false, or no --lsm-root) makes this a no-op — byte-identical Day-
	// 15 (the backstop kept forever). Gated alongside meshCtx so SIGINT/SIGTERM
	// cancels it (the reaper honors ctx.Err() at every list/download/delete).
	go reaperLoop(meshCtx, queryReaper, cfg.compactionReapInterval)
	if queryReaper != nil {
		log.Printf("sovereign-node: L0 reaper started, interval=%s (cross-entity superseded-L0 reclaim; Stage C verifies the L1 before any L0 delete; NEVER auto-on)",
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

// digestDemuxer adapts the Gossiper to the mesh.DigestSink contract for the
// cmd accept-side serveConn. The accept-side serveConn does NOT hold the
// Gossiper directly (it holds the *receive.Receiver); the Day-29 digest
// exchange routes a WireDigestMagic-tagged frame to the Gossiper's
// DeliverDigest via this adapter so the sweep's per-peer blocking-receive
// channel gets the peer's StrataEstimator. A nil Gossiper (the --selftest path
// that constructs no gossiper) makes the digester nil — DispatchFrame's digest
// branch is then a no-op drop (the honest cold-start when stratified is OFF).
//
// It is a thin wrapper (NOT a new object graph) so the readLoop + serveConn +
// serveTestConn all reach the SAME Gossiper's DeliverDigest — one digest sink
// per node, shared across the dial-side readLoop and the accept-side serveConn.
type digestDemuxer struct{ g *mesh.Gossiper }

func (d digestDemuxer) DeliverDigest(peerID [16]byte, frame []byte) {
	if d.g != nil {
		d.g.DeliverDigest(peerID, frame)
	}
}

// acceptLoopWithDigest is the Day-29 accept loop: it threads the digestSink so
// the accept-side serveConn can route a WireDigestMagic-tagged frame to the
// Gossiper's DeliverDigest (the dial-side readLoop already routes via the
// PeerSet's digester; the accept-side needs the same sink because a digest
// arrives on the conn the PEER dialed in, which the local node reads on its
// accept side, NOT its dial-side readLoop). A nil digester (the --selftest
// path) keeps serveConn's digest branch a no-op drop.
func acceptLoopWithDigest(ctx context.Context, ln net.Listener, recv *receive.Receiver, rec *metrics.Recorder, digester mesh.DigestSink) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v (listener closing)", err)
			return
		}
		go serveConnWithDigest(ctx, conn, recv, rec, digester)
	}
}

// serveConn drives the frame reassembler + the gate stack for one TLS
// connection. It logs the typed verdict per frame (the gate-stack decision is
// the load-bearing attribution signal). A malformed/closed connection ends
// the goroutine; the gate stack never panics on adversarial input.
//
// Day 3 (Option B — the observer wrapper, ADR-0008 §3): the per-frame
// observation is an ACCEPT-LOOP concern, NOT a gate-stack concern. The
// per-conn goroutine is uncontended (one frame at a time per conn), so the
// Recorder's atomic Observe/Inc is wait-free here. receiver.go stays
// byte-locked (md5 9dfde188); the Verdict enum (receiver.go:81, six values)
// carries 100% of the per-gate signal, so the wrapper captures it at the
// caller. A nil Recorder disables observation (the --selftest path may run
// without one if constructed that way; here it is always non-nil).
func serveConnWithDigest(ctx context.Context, conn net.Conn, recv *receive.Receiver, rec *metrics.Recorder, digester mesh.DigestSink) {
	defer conn.Close()
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			log.Printf("tls handshake from %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
	fr := receive.NewFrameReader(conn) // receiver.go:474
	for {
		if ctx.Err() != nil {
			return
		}
		frame, err := fr.ReadFrame() // receiver.go:486
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("frame read from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		// Day-29 digest branch (ADR-0034): a WireDigestMagic-tagged frame is a
		// StrataEstimator digest, NOT a CRDT delta. It routes to the Gossiper's
		// DeliverDigest (via the digester shim), NOT the gate stack — a digest
		// never reaches HandleFrame (which would DropMalformed it; the
		// gossip.go:356 comment names this). It is NOT timed/recorded as a
		// gate-stack verdict: a digest is advisory, the signed delta that
		// follows is the authoritative state transfer the gate stack + recorder
		// cover (the threat model in wire_v1.go's WireDigestMagic comment).
		// The accept side passes a zero peerID (it does not know the sender from
		// the conn alone); DeliverDigest reads the authoritative senderID from
		// the digest-frame header.
		if attribution.IsDigestFrame(frame) {
			if digester != nil {
				digester.DeliverDigest([16]byte{}, frame) // mesh.DigestSink -> Gossiper.DeliverDigest
			}
			continue
		}
		// Option B observer: time the full gate-stack composition (cheap gates
		// + the ~60us Verify when it fires) and record the latency + the
		// typed verdict. The bimodal histogram (sub-1us cheap-reject + ~60us
		// verify-pass) is the tooth this produces.
		//
		// Day-5 dispatch: peek the post-length-prefix body's first 4 bytes.
		// A BatchEnvelope magic (attribution.IsBatchFrame) routes to
		// HandleBatchFrame (the batch path — one Ed25519 over N deltas); the
		// RelayEnvelope path (the default) routes to HandleFrame (the FROZEN
		// per-frame gate stack). On a batch Accept, the per-delta verdict
		// counter is incremented by N (BatchAcceptCount), NOT +1 — the counter
		// is PER-DELTA, so a batch of N accepted deltas adds N to the Accept
		// label (ADR-0010 §2).
		//
		// Day-32 dispatch arm (ADR-0037 — the /verify-audit fix): a
		// HybridEnvelope magic (attribution.IsHybridFrame) routes to
		// HandleHybridFrame (the hybrid-PQ batch gate stack — BOTH Ed25519 +
		// ML-DSA-65 over the SAME 120-byte SHAKE256 pad). On a hybrid Accept,
		// the per-delta verdict counter is incremented by N via
		// HybridAcceptCount (the hybrid-frame sibling of BatchAcceptCount — it
		// parses the WireHybridPQMagic header, which BatchAcceptCount's
		// WireV1Magic parser would reject → return 0 → silent undercount). The
		// dispatch order is load-bearing: IsBatchFrame first (the highest-rate
		// opt-in path), then IsHybridFrame (the hybrid-PQ batch), then the
		// default routes to the FROZEN relay/HandleFrame — the SAME 4-way order
		// pkg/mesh/digest.go DispatchFrame uses (the dial-side readLoop +
		// the test serveTestConn both call DispatchFrame; this arm brings the
		// ACCEPT-side production path to parity with the dial side, closing the
		// asymmetry the audit surfaced: a hybrid frame on an INBOUND connection
		// previously fell through to HandleFrame → the RelayEnvelope parser saw
		// WireHybridPQMagic not the 0x02/0x03 version prefix → DropMalformed →
		// the hybrid delta was SILENTLY DROPPED on the accept side +
		// HybridFrameAccepted never fired. The teeth masked this because
		// serveTestConn calls DispatchFrame (the 4-way router) which the
		// production accept side did NOT call).
		start := time.Now()
		var verdict receive.AcceptVerdict
		var acceptedDeltas int
		if attribution.IsBatchFrame(frame) {
			verdict = recv.HandleBatchFrame(frame) // receiver.go — the Day-5 batch gate stack
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = receive.BatchAcceptCount(frame)
			}
		} else if attribution.IsHybridFrame(frame) {
			verdict = recv.HandleHybridFrame(frame) // receiver.go — the Day-32 hybrid-PQ batch gate stack
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = receive.HybridAcceptCount(frame)
			}
		} else {
			verdict = recv.HandleFrame(frame) // receiver.go:350 — the FROZEN gate stack
			if verdict.Verdict == receive.Accept {
				acceptedDeltas = 1
			}
		}
		if rec != nil {
			// Record the per-delta verdict: +N on a batch Accept, +1 on a
			// per-frame Accept, +1 on any drop (a drop is one frame's verdict,
			// regardless of the batch it would have carried). The latency is
			// observed once per frame (the gate-stack composition time), so the
			// histogram sees one sample per frame; the verdict counter sees the
			// per-delta count (the throughput signal).
			rec.RecordIngest(time.Since(start), verdict.Verdict)
			if acceptedDeltas > 1 {
				for i := 1; i < acceptedDeltas; i++ {
					rec.RecordIngest(0, verdict.Verdict)
				}
			}
		}
		if verdict.Verdict == receive.Accept {
			continue
		}
		log.Printf("frame from %s: %s (reason: %v)", conn.RemoteAddr(), verdict.Verdict, verdict.Reason)
	}
}

// livecheckBody is the JSON served by /livecheck.
type livecheckBody struct {
	NodeID     string   `json:"node_id"`
	Peers      []string `json:"peers"`
	TLSVersion string   `json:"tls_version"`
}

// convergenceGaugePoller feeds the three poller-driven /metrics gauges off the
// hot path on a 1s ticker. It reads the Gossiper's convergence-lag seed (the
// SweepLoop is the single writer; this is the single reader) and the verdict-
// counter delta (sovereign_ingest_pps). It does NOT touch the ingest hot path.
// The roots-equal gauge is 1.0 when the local engine's current MerkleRoot
// matches the last converged root (the mesh is converged RIGHT NOW), 0.0
// otherwise — a 2-node binary indicator (a 3-node quorum-aware gauge is a
// future track, ADR-0008 §8).
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
			curRoot := gossiper.CurrentRoot() // gossip.go CurrentRoot -> crdt.go:1225 + hamt.go:265
			exp.SetConvergenceRootsEqual(curRoot == gossiper.LastConvergedRoot())
			// ingest pps: the verdict-counter delta over the 1s interval.
			exp.SetIngestPPS(exp.ObserveVerdictDelta(time.Now()))
		}
	}
}

// startLivecheck serves /livecheck AND /metrics on ONE PLAIN http.Server (no
// TLS — ops debug, not the data plane; the C1 boundary). Day 3 adds the
// /metrics Prometheus scrape route to the SAME mux (one server, one mux — the
// --metrics-addr flag already binds it; a second HTTP server is NOT spawned).
// Returns the server so the caller can Shutdown it.
func startLivecheck(addr string, nodeID [16]byte, peers []string, exp *metrics.Exporter) *http.Server {
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
	// /metrics: the Prometheus scrape surface. promhttp.HandlerFor is bound to
	// the per-process Registry (NOT DefaultRegisterer); it is non-blocking (the
	// scrape iterates instruments, no hot-path lock). The seven sovereign_*
	// series are scrapeable with HELP+TYPE from a cold start (G03.c).
	if exp != nil {
		mux.Handle("/metrics", exp.Handler())
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

// startControlPort serves the JSON-over-mTLS client control port on addr. It
// is a SEPARATE *tls.Listener from the --bind peer listener: it uses the SAME
// mTLS config (tr.ServerConfig — RequireAndVerifyClientCert, Min==Max==1.3) so
// a no-cert dial is a hard TLS error, but its accept loop drives an http.Server
// (the /v1/* routes), NOT the length-prefixed frame reassembler the peer path
// uses. A client's JSON request and a peer's length-prefixed BatchEnvelope do
// NOT share an accept loop (ADR-0011 §3, §6 — the primary-risk mitigation).
// The metrics handler is injected as an http.Handler so the control port can
// serve /metrics over TLS to SDK consumers without coupling pkg/mesh to
// pkg/metrics (the Day-4 seam discipline); the plain-HTTP --metrics-addr
// surface stays for unauthenticated ops scrape (ADR-0006).
func startControlPort(addr string, tr *transport.TLSConnections, gossiper *mesh.Gossiper, nodeID [16]byte, peers []string, exp *metrics.Exporter, resolver *database.Resolver) *http.Server {
	ln, err := tls.Listen("tcp", addr, tr.ServerConfig())
	if err != nil {
		log.Fatalf("control-addr: tls listen %s: %v", addr, err)
	}
	var metricsHandler http.Handler
	if exp != nil {
		metricsHandler = exp.Handler()
	}
	// Day 12: SetResolver wires the bitemporal query tier onto /v1/query.
	// resolver is nil when --lsm-root is absent (or enableIndex false) — in
	// that case /v1/query returns the honest 503, NOT a silent 404 (ADR-0017
	// §3). SetResolver is the SEPARATE seam that keeps NewControlServer's
	// 4-arg signature stable for the mesh tests (mirrors Day-11 SetSnapshotter).
	cs := mesh.NewControlServer(gossiper, nodeID, peers, metricsHandler)
	cs.SetResolver(resolver)
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

// mintSelftestCerts mints a dev CA + leaf into a temp dir and returns the
// PEM paths + the in-process CA (so the Day-30 automated rotation trigger can
// mint NEW leaves via the SAME CA under --selftest). It uses pkg/crypto (the
// dev-mesh CA) so --selftest exercises the same certgen the TLS tests use.
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

// buildRotationMinter constructs the transport.RotationMinter the automated
// leaf-rotation trigger (StartRotationManager) calls when the live leaf is
// within --cert-rotation-lifetime of expiry. The minter mints a NEW Ed25519
// leaf via the in-process dev-mesh CA (the SAME CA mintSelftestCerts returned
// under --selftest), writes the PEM to the transport's cert+key paths, and
// calls tr.Reload so the NEXT handshake presents the NEW serial.
//
// The operator path (NOT --selftest) has NO in-process CA — it loads PEMs
// from disk the operator provides — so a nil ca returns a clear error. A
// production fork that wants automated rotation on the operator path supplies
// an out-of-process minter (a KMS/HSM-backed CA) via the transport.RotationMinter
// seam directly (bypassing this helper); the trigger's polling + reload
// mechanism is the load-bearing wiring, the minter is the swappable seam
// (disclosed ADR-0035 §6). The nodeID is the leaf CommonName (the SAME field
// IssueLeaf embeds; a rotated leaf has a NEW serial but the SAME nodeID — the
// identity is stable, the credential rotates).
func buildRotationMinter(ca *crypto.MeshCA, nodeID [16]byte, certPath, keyPath string, tr *transport.TLSConnections) (transport.RotationMinter, error) {
	if ca == nil {
		return nil, fmt.Errorf("--cert-rotation-enable requires an in-process CA (the --selftest path mints one; the operator path loads PEMs from disk + has NO in-process CA — supply an out-of-process minter via transport.RotationMinter for operator-path rotation, ADR-0035 §6)")
	}
	nodeIDHex := hex.EncodeToString(nodeID[:])
	return func() (*big.Int, error) {
		leaf, err := ca.IssueLeaf(nodeIDHex)
		if err != nil {
			return nil, fmt.Errorf("rotation IssueLeaf: %w", err)
		}
		// Write the NEW PEM to the SAME paths the transport loaded at
		// construction (certPath/keyPath) so the Reload re-parses the NEW leaf.
		// WritePEM writes cert.pem + key.pem INTO a dir — but certPath/keyPath
		// are FILE paths (the transport's exact paths). The rotation must write
		// the EXACT files, so call WritePEM into the dir + the returned paths
		// OVERWRITE the transport's paths only if they match (the selftest path
		// mints into a temp dir; the returned paths ARE the transport's paths).
		dir := filepath.Dir(certPath)
		newCert, newKey, err := leaf.WritePEM(dir)
		if err != nil {
			return nil, fmt.Errorf("rotation WritePEM: %w", err)
		}
		// WritePEM writes cert.pem/key.pem (FIXED names) into dir; the
		// transport's paths are dir/cert.pem + dir/key.pem (the selftest
		// convention). If the operator's paths differ, the rotation writes the
		// fixed names + the Reload reads the operator's paths — a mismatch the
		// selftest path does NOT hit (the selftest uses the WritePEM names). The
		// operator-path rotation is the out-of-process-minter concern (above).
		_ = newCert
		_ = newKey
		if err := tr.Reload(); err != nil {
			return nil, fmt.Errorf("rotation Reload: %w", err)
		}
		return leaf.LeafCert().SerialNumber, nil
	}, nil
}

// buildNodeIdentity derives the node's CRDT-delta signing identity. If
// --identity-seed is set it MUST produce the same nodeID the engine runs under
// (the derived pubkey's first 16 bytes); a mismatch fails fast. If unset a
// random seed is minted for the already-resolved nodeID — but a randomly-minted
// seed derives its OWN nodeID, so when --identity-seed is empty we re-derive the
// nodeID from the seed and the engine's localNodeID is taken as the seed's
// derived nodeID (the binary logs both; the deploy MUST pass --identity-seed for
// a deterministic node identity).
//
// Day 32 (ADR-0037): when --hybrid-sign is set, the owner is constructed via
// mesh.NewNodeIdentityHybrid (the Ed25519 keypair + the ML-DSA-65 keypair, BOTH
// derived from the SAME --identity-seed — one identity space, the Day-2 deploy
// discipline). A non-hybrid-sign owner (the DEFAULT) is constructed via the
// classical NewNodeIdentity — byte-identical Day-31 (NO PQ key is minted; the
// gossiper's hybrid arm is disarmed; NO hybrid frame is produced). The PQ pubkey
// is registered in the Directory via RegisterPQ at the wiring site (the owner
// carries it; the Directory is the OOB provisioning layer the hybrid verify
// resolves).
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
		log.Printf("identity: minted random signing seed; derived nodeID=%x (engine nodeID=%x) — a deterministic identity REQUIRES --identity-seed", ident.NodeID, engineNodeID)
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

// compactionSchedulerLoop (Day 14, ADR-0019) periodically lists the l0/ entity
// prefixes and runs a Compaction job for each entity whose L0 file count is at
// the trigger threshold. It is a background READ-L0 → WRITE-L1 job — it never
// touches the SkipList/HAMT/WAL write path. A nil compactor (the research / no
// --lsm-root default) makes this a no-op. The loop honors ctx cancellation so
// SIGINT/SIGTERM stops it cleanly.
//
// Day 22 (ADR-0027): the loop also carries the query *Resolver so runCompactionSweep
// can read the observed live-query txTime frontier (QueryTxTimeFrontier) and feed
// the inferrer BEFORE each per-entity CompactionByHash8. A nil resolver (the
// research node with no --lsm-root keeps queryResolver nil) leaves the inferrer
// inert — the compactor's operator-set horizon stands unchanged (byte-identical
// Day-15). The inferrer is the §0.a "engine tracks the frontier itself" seam.
func compactionSchedulerLoop(ctx context.Context, compactor *database.L1Compactor, resolver *database.Resolver) {
	if compactor == nil {
		return
	}
	const interval = 30 * time.Second // the compaction cadence; tunable, NOT on the write path
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

// runCompactionSweep lists the distinct entity prefixes under l0/ (one compaction
// job per entity at/over the trigger) and runs the per-entity L0→L1 merge. It is
// best-effort: a per-entity error is logged and the sweep continues to the next
// entity (one sick entity does NOT stall compaction for the rest). The entity
// set is derived from the L0 key prefixes (l0/{hex(hash8)}/); a future fork
// may cache the live entity set off the CRDT engine to avoid the prefix list.
//
// Day 22 (ADR-0027): BEFORE the per-entity compactions, the sweep runs the T_gc
// auto-inferrer step — read the Resolver's observed live-query txTime frontier,
// compute the effective horizon = max(operatorFloor, observedFrontier - backoff),
// advance the compactor's horizon via SetInferredHorizon (the §0.c monotone
// clamp; a retreat is refused + counted + logged). The inferrer is inert when
// pruning is OFF (EnableDominancePruning=false) — SetInferredHorizon still
// advances the horizon but DominancePrune is skipped at the seam (the §0.e
// byte-identical-Day-14 guard at l1_compactor.go:540), so the effective horizon
// advances but no rows drop (the operator-visible gauges still surface it). A
// nil resolver leaves the inferrer inert (the research node keeps queryResolver
// nil — no --lsm-root).
func runCompactionSweep(ctx context.Context, compactor *database.L1Compactor, resolver *database.Resolver) {
	// Day 22 (ADR-0027): the T_gc auto-inferrer step (the §0.a "engine tracks
	// the frontier itself" seam). InferHorizon reads the Resolver's observed
	// live-query txTime frontier, computes effective = max(operatorFloor,
	// observedFrontier - backoff), advances the compactor's horizon
	// monotonically (the §0.c clamp; a retreat is refused + counted + logged
	// inside SetInferredHorizon), and surfaces the two gauges. Inert when
	// pruning is OFF (DominancePrune is skipped at the seam — the §0.e guard —
	// so the horizon advances but no rows drop; the gauges still surface the
	// inferrer's state). A nil resolver (research node, no --lsm-root) leaves
	// the inferrer inert — the horizon stands at the operator's static knob
	// (byte-identical Day-15). The gauge-advance + counter reads live in
	// internal/database (the database package imports internal/telemetry for
	// the prune-seam counters already); cmd does NOT import internal/telemetry
	// directly (the §0.d two-exporter separation — the ONE Init caller is
	// armOTel in otel.go; reading counters is not an Init caller).
	compactor.InferHorizon(resolver)
	// List ALL l0/ keys (uncapped) to count per-entity L0 files + discover the
	// entity set. The bucket "local" is ignored by LocalFS; the prefix "l0/"
	// scopes to the per-entity Arrow index.
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
		// The compaction needs the entityID to re-verify Filter4 rows; the
		// scheduler derives it from the L0 keys themselves is NOT available
		// (the hash is one-way). The Day-14 L1Compactor.Compaction takes the
		// entityID + hash8; the scheduler cannot invert the hash. HONEST design:
		// the compaction is entity-list-driven via the CRDT engine's live
		// entity set (a future fork caches it); for Day-14 the scheduler calls
		// CompactionByHash8 (below) which uses hash8-only Filters (Filter1, no
		// Filter4) — defense-in-depth is maintained by the L0 file's per-entity
		// construction (Day-13 keying guarantees only the one entity's rows).
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

// reaperLoop (Day 16, ADR-0021) periodically runs ONE cross-entity reaper sweep
// that reclaims manifest-listed superseded L0 files AFTER verifying the L1
// still exists (the Stage C safety guard in database.L0Reaper.Reap). It is the
// reaper analogue of compactionSchedulerLoop: a nil reaper (the default —
// --compaction-reap-enable=false, or no --lsm-root) makes this a no-op, so the
// superseded L0s stay on disk as the crash-recovery backstop (byte-identical
// Day-15). The loop honors ctx cancellation so SIGINT/SIGTERM stops it cleanly.
// It runs LESS often than the compactor (default 5m vs 30s) — the superseded
// L0s are a safety net with zero urgency to delete; the slower cadence also
// amortizes the manifest-list + L1-probe cost over more compactions.
func reaperLoop(ctx context.Context, reaper *database.L0Reaper, interval time.Duration) {
	if reaper == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Minute // sane floor; --compaction-reap-interval=0 is treated as the default
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

// runReaperSweep runs ONE database.L0Reaper.Reap and logs the honest result
// (Law V — disclose the counts, not adjectives). A Reap error is impossible —
// Reap returns a ReapResult tally, not an error; per-manifest failures are
// counted INTO the result (SkippedOrphan / SkippedError) + logged inside Reap.
// So this logs the sweep summary line; the per-manifest WARN/detail lines live
// in database.L0Reaper.Reap (the reaper owns its own honest-negative logging).
func runReaperSweep(ctx context.Context, reaper *database.L0Reaper) {
	if reaper == nil {
		return
	}
	res := reaper.Reap(ctx)
	log.Printf("sovereign-node: L0 reaper sweep — manifests reaped=%d, L0s deleted=%d, skipped orphan(L1 gone/sick)=%d, skipped error(delete failed)=%d",
		res.ReapedManifests, res.ReapedL0, res.SkippedOrphan, res.SkippedError)
}

// engineHAMTAdapter (Day 27, ADR-0032) is the read-your-writes live source: a
// database.LiveSource whose impl wraps the live δ-CRDT HAMT. It is constructed
// at the cmd/sovereign-node boundary — the ONLY place the concrete
// eng.DeltaCRDTEngine is in scope (internal/database does NOT import pkg/sync,
// so the seam is the LiveSource interface, owned by internal/database, impl'd
// here — the SetResolver / SetSnapshotter precedent).
//
// LiveRead pins the live store with the EXACT EBR pattern SnapshotToLSM uses
// (snapshot.go:391-394): ebr.Acquire() → participant.Enter(ebr) → defer
// ebr.Release(participant). Enter() sets active=true, epoch=globalEpoch
// (reclamation.go:120) which holds freeRetiredList back, so a concurrent
// InsertLocal's CAS CANNOT retire+free a shard root the LiveRead is iterating
// (the production-grade concurrent-read guard handleGet already proves under
// -race; control.go:356 reads engine.State().Get WITHOUT an EBR pin because
// the HTTP read is tolerant — the Resolver's merged answer is held to the
// SAME correctness bar as SnapshotToLSM, so it pins). It is NOT a SkipList
// freeze; it does NOT touch skiplist_arena.go (the SkipList is the per-checkpoint
// index writer, NOT the live read target — the §0 audit's decisive refutation).
//
// Filter2 (SystemTime <= txTimeNs) is applied HERE — the visibility bound
// well-defined for BOTH AsOf and Range. Filter3 (point OR window) + dominance
// are applied by the Resolver (the LiveRead returns the full Filter2-passing
// set; the Resolver's AsOf/Range callers apply their own Filter3). This split is
// the resolution of the prompt's point-form LiveRead signature vs the Range
// window: the adapter owns Filter2; the Resolver owns Filter3+dominance.
//
// CRDTEntry → LiveEvent mapping: SystemTime/ValidTimeStart/ValidTimeEnd/
// AssertionTime/H3Index/PayloadDigest carry one-for-one. Payload is nil (the
// durable Arrow index's payload=sentry discipline, snapshot.go:435, carried to
// the live path — the no-recompute law means the digest IS the identity; a
// future fork surfacing live Payload through the query response is a SEPARATE
// seam, ADR-0032 §6). CRDTEntry carries NO payload body (hamt.go:29, ADR 10:
// 120-byte struct) — only PayloadDigest — so the nil Payload is the honest
// value, NOT a fabrication.
//
// SCALE BOUND (§0.b — the dictated-design-detail-the-bytes-refine class,
// disclosed in ADR-0032 §6, NOT silently filled in): LiveRead calls
// engine.State().Get(entityID) — engine.State() is the production read API
// handleGet uses (control.go:356), and it is O(total entries): it materializes
// a FULL merged view of every entity's dot set into a fresh HAMT on EACH call
// (crdt.go:1348, documented O(total entries)), AND the previously-built merged
// view is EBR-retired (freed after 3 epoch advances, crdt.go:1362-1370) — so
// HIGH read concurrency accumulates retired merged views across the grace
// window. This does NOT affect read-your-writes CORRECTNESS (the T-LIVE-READ-
// YOUR-WRITES tooth proves the property over a real engine), only the live-set
// scale + read-concurrency at which the State()-backed read path is economical.
// The O(1) per-entity alternative (routeShard → shards[i].ptr.Load().Get, the
// InsertLocal path at crdt.go:984) is a SEPARATE fork — crdt.go is FROZEN (md5
// 5cebad26), so this fork does NOT add it; it stays faithful to the production
// handleGet read path + discloses the scale bound. For the research-node scale
// the live source targets (a live set small relative to the durable tier), the
// State() cost is negligible; a production-scale live-Get seam is ADR-0032 §6.
type engineHAMTAdapter struct {
	engine *eng.DeltaCRDTEngine
}

// LiveRead implements database.LiveSource. It returns the live entries for
// entityID visible at txTimeNs (Filter2: SystemTime <= txTimeNs), EBR-pinned
// for the call duration. A nil/empty result is NOT an error (no live entry is
// visible at txTime → the durable answer stands alone). An error is returned
// only on a pin/State failure (the Resolver logs it via QueryLiveSourceReads
// + NEVER fails the query — the SAME failure-honesty loadSupersededL0Keys uses).
func (a *engineHAMTAdapter) LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]database.LiveEvent, error) {
	if a == nil || a.engine == nil {
		return nil, nil
	}
	ebr := a.engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	defer ebr.Release(participant)

	state := a.engine.State()
	if state == nil {
		return nil, nil
	}
	entries := state.Get(entityID) // crdt.go:1348 → hamt.go:170 (the FULL dot set, EBR-pinned by Enter above)
	out := make([]database.LiveEvent, 0, len(entries))
	for i := range entries {
		e := entries[i]
		// Filter2: SystemTime <= txTimeNs — the visibility bound. STRICT <=
		// (a row AT sysTime==txTime passes — byte-identical to scanRecordBatch's
		// Filter2 at query.go:969, the Day-24 boundary in reverse).
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
			// Payload: nil — CRDTEntry carries no payload body (ADR 10); the
			// digest is the no-recompute identity (control.go:441, Law V).
		})
	}
	return out, nil
}
