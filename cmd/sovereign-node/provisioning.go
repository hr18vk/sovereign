// Package main (cmd/sovereign-node) — Day 35 (ADR-0040): the OOB peer-Directory
// pubkey provisioning layer.
//
// provisioning.go is the NEW seam that retires the Day-2 zero-peerID dial hazard
// (cmd/sovereign-node/main.go:1169 dials `peerSet.Dial(meshCtx, pa, host,
// zeroPeerID)` — every peer is a 0x00…00 book-keeping key). The region tags the
// Day-34 TopologyManager keys under `peerIDForAddr(addr)` (a SHA-256 addr
// surrogate) never match the zero peerID the dial stores under, so the region
// lookup misses → every peer routes RegionUnset = intra = byte-identical
// full-mesh — the Day-34 §7.1 N=2 no-op. Day 35 retires the zero peerID by
// class-elimination: this file reads a `--peer-dir` config mapping each peer
// addr → {nodeID, Ed25519 pubkey, optional ML-DSA-65 pubkey, optional region},
// calls `gossiper.RegisterPeer` (+ `dir.RegisterPQ` for the optional PQ arm)
// + `topo.SetRegion` under the REAL nodeID, and returns an addr→nodeID map the
// dial loop branches on (provisioned peers dial under the real nodeID;
// un-provisioned peers keep the zero peerID = byte-identical Day-34 back-compat).
//
// The PQ arm reconstructs the ML-DSA-65 public key from its 1952-byte wire
// encoding via `mldsa.NewPublicKey(mldsa.MLDSA65(), encoded1952)` (the
// `Bytes()`/`NewPublicKey` round-trip — mldsa.go:201 `NewPublicKey` takes the
// serialized encoding, NOT a private-key seed; the day32 path carries the
// in-memory *mldsa.PublicKey and never serializes; this file is the FIRST site
// that reconstructs a directory PQ pubkey from a serialized config blob).
//
// FAILSAFE discipline (the Day-25 EnableFirstSysSkip precedent, INVERTED for
// identity): parsePeerRegions (main.go:512) silently SKIPS a malformed region
// tag (a region tag is a routing hint — wrong is conservative-local, NOT a
// security defect). A peer pubkey is a VERIFICATION anchor (the receiver's
// Directory.Lookup resolves originNodeID → pubkey; a wrong pubkey makes a
// genuine delta DROPPED as a forged signature). So parsePeerDir REJECTS a
// malformed entry with an error naming the line + the field; it NEVER silently
// coerces a short/truncated key to zero (the §III RED tooth T-OOB-CONFIG-PARSE
// injects a 16-byte-truncated pubkey + asserts the parser REJECTS it — remove
// the length check and the tooth FAILS, proving the guard is load-bearing).
//
// ZERO new module dep: filippo.io/mldsa is ALREADY in go.mod (the blank import
// at pkg/crypto since commit 6db6132, pinned at go.mod line 8). This file adds
// the first DIRECT cmd-side import of the symbol API (the anti-fab discipline
// of pq_mldsa.go: each mldsa symbol call site cites the module-cache file:line).
//
// ZERO FROZEN touched: this file is a NEW caller of pkg/mesh.Gossiper.RegisterPeer
// + pkg/identity.Directory.RegisterPQ + pkg/mesh.TopologyManager.SetRegion —
// all pre-existing seams. The 44f89527 streak is PRESERVED (Day 35 is
// IDENTITY/ROUTING, NOT CRDT — pkg/sync is untouched).

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"filippo.io/mldsa"

	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/mesh"
)

// peerDirConfig is one parsed --peer-dir entry: a peer addr bound to its
// CRDT-delta signing identity (the Ed25519 pubkey the receiver's Directory
// resolves) + the OPTIONAL ML-DSA-65 pubkey (the hybrid-verify arm, under
// --hybrid-verify) + the OPTIONAL region tag (the Day-34 TopologyManager key).
//
// The Ed25519 pubkey is the load-bearing field: it is the verification anchor
// the receiver's Directory.Lookup returns, so a wrong pubkey makes a genuine
// peer delta DROPPED as a forged signature (the honest-negative posture — a
// misconfigured deploy is a SILENT PARTITION, NOT a security hole). The ML-DSA-65
// pubkey is OPTIONAL (nil = the peer is classical-only; the hybrid verify rejects
// a nil pqPub via the Day-31 STRICT mode — the SAME posture a peer that registered
// ONLY the classical key has). The region tag is OPTIONAL (0 = RegionUnset =
// routes as SAME-region = intra — the Day-34 conservative default).
//
// hasRegion is the explicit "region field was present" flag (a region of 0 is
// a VALID tag the operator MAY set explicitly, indistinguishable from "absent"
// by the RegionTag zero-value alone; the flag keeps the two distinct so a
// topo.SetRegion(realNodeID, 0) call happens ONLY when the operator named 0,
// NOT when the field was omitted — the honest distinction the §III tooth
// T-OOB-PROVISION-RETIRES-SURROGATE asserts).
// peerDirConfig is one parsed peer-directory line. Field order is the
// fieldalignment manual reorder per the memory `fieldalignment_fix_is_destructive`
// (NEVER `fieldalignment -fix`): the two pointers (addr string header +
// mldsa65Pub) first, then the two fixed byte arrays, then the two bools packed
// at the tail (72→24 pointer-bytes). The residual "24 could be 16" is a known
// fieldalignment false-positive for string headers — it counts the string's
// (ptr,len) as 2 pointers but reports "could be 16" as if the len half were
// free; 24 IS the structural floor for a struct carrying a string + a pointer.
// This is a config-parse struct allocated ONCE per peer at boot (NOT a hot-path
// contended-atomic — the cache law does NOT apply); the reorder is hygiene, not
// a performance gate. mldsa65Pub is the OPTIONAL reconstructed ML-DSA-65 public
// key (nil = the peer is classical-only), reconstructed from the 1952-byte wire
// encoding via mldsa.NewPublicKey(mldsa.MLDSA65(), encoded) (mldsa.go:201 — the
// Bytes()/NewPublicKey round-trip); owned by the parsed config, never mutated
// post-parse.
type peerDirConfig struct {
	addr       string
	mldsa65Pub *mldsa.PublicKey
	nodeID     [16]byte
	ed25519Pub [32]byte
	region     mesh.RegionTag
	hasRegion  bool
}

// peerDirConfig fields (positional, by column):
//
//	1  addr            host:port (REQUIRED, must contain a ":")
//	2  nodeID          32-hex-char (16-byte) node identity (REQUIRED)
//	3  ed25519_pubkey  64-hex-char (32-byte) Ed25519 public key (REQUIRED)
//	4  mldsa65_pubkey  3904-hex-char (1952-byte) ML-DSA-65 public key (OPTIONAL)
//	5  region          uint8 region tag 0-255 (OPTIONAL, only if col 4 present)
//
// The columns are positional + whitespace-separated (NOT named keys) — the
// zero-dependency discipline (no TOML/YAML/JSON dep; the prompt names this three
// times). A `#` to end-of-line is a comment (stripped before field split). Blank
// lines + comment-only lines are skipped. The OPTIONAL columns are TRAILING: a
// line with 3 fields is classical-only + no region; a line with 4 fields adds the
// PQ pubkey; a line with 5 fields adds the region. A line with 5 fields where col
// 4 is "-" is classical-only WITH a region (the explicit-skip sentinel — a peer
// that has a region but NO PQ key, the common case once region-aware is GA).
const (
	peerDirColAddr = iota
	peerDirColNodeID
	peerDirColEd25519
	peerDirColMldsa65
	peerDirColRegion
	peerDirColCount // the max column count (region + 1)
)

// mldsa65SkipSentinel is the explicit-skip marker for the OPTIONAL ML-DSA-65
// column: a line "addr nodeID ed25519 - 3" provisions a classical-only peer in
// region 3 (the common case — a region-tagged peer with NO PQ key). Without the
// sentinel a 5-field line would be ambiguous (is col 4 a 3904-hex PQ key or a
// region?); the sentinel makes col 4's absence explicit so col 5 is unambiguously
// the region. A line with 4 fields has NO region (col 4 is the PQ key OR the
// sentinel — but a 4-field line with "-" is classical-only + no region, the
// honest degenerate case the parser accepts).
const mldsa65SkipSentinel = "-"

// ErrPeerDirEmpty is returned by applyProvisioning when --peer-dir is empty
// (the OPT-IN default — no provisioning, the dial loop keeps the zero peerID,
// byte-identical Day-34). It is NOT a boot error: an empty path is the honest
// "operator did not opt in" signal, surfaced as a logged no-op (the caller
// returns an empty provisioned map → the dial loop's ELSE arm runs for every
// peer). Distinct from a NON-EMPTY path that does not exist (a real boot error:
// the operator named a file that is absent — a deploy misconfiguration that
// MUST fail loudly, NOT silently fall back to zero-peerID).
var ErrPeerDirEmpty = errors.New("provisioning: --peer-dir is empty (no OOB provisioning; dial loop keeps the zero peerID — byte-identical Day-34)")

// parsePeerDir reads + parses the --peer-dir config file into a []peerDirConfig.
// The FAILSAFE discipline (inverted from parsePeerRegions' silent-skip):
//
//   - a NON-EMPTY path that does not exist → error (a deploy misconfiguration
//     that MUST fail loudly — silently falling back to zero-peerID would mask
//     a missing config as a byte-identical-Day-34 no-op, the silent-partition
//     class the honest-negative posture forbids).
//   - a malformed entry (bad hex, wrong field length, unparseable region) →
//     error naming the line number + the field (NEVER silently coerced to zero;
//     a truncated pubkey is a VERIFICATION anchor defect, NOT a routing hint).
//   - a duplicate addr → error (a deploy conflict the operator must resolve; the
//     dial loop keys byAddr, so a duplicate would silently shadow the first).
//
// The returned slice is in FILE ORDER (the order the operator wrote the lines);
// applyProvisioning iterates it in that order so the provisioned map + the
// Directory registrations are deterministic across runs (the Day-34
// seeded-determinism discipline generalized to the config layer).
func parsePeerDir(path string) ([]peerDirConfig, error) {
	if path == "" {
		return nil, ErrPeerDirEmpty
	}
	f, err := os.Open(path)
	if err != nil {
		// A named-but-absent file is a deploy misconfiguration: surface it
		// loudly. os.Open already names the path in the error; wrap it so the
		// boot log identifies the --peer-dir that failed.
		return nil, fmt.Errorf("provisioning: open --peer-dir %q: %w", path, err)
	}
	defer f.Close()
	var out []peerDirConfig
	seen := make(map[string]int)         // addr -> first line seen (1-indexed)
	seenNodeID := make(map[[16]byte]int) // nodeID -> first line seen (the /code-review nodeID-dedup)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // a 1952B hex pubkey = 3904 chars; allow 4MiB lines
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		// Strip a `#` comment (to end-of-line). A `#` inside a hex value is
		// impossible (hex is [0-9a-f]), so the first `#` is unambiguously a
		// comment start. The comment is stripped BEFORE the field split so a
		// trailing comment does not become a spurious 6th field.
		if h := strings.IndexByte(raw, '#'); h >= 0 {
			raw = raw[:h]
		}
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue // blank or comment-only line
		}
		if len(fields) < peerDirColEd25519+1 {
			return nil, fmt.Errorf("provisioning: %s:%d: need ≥3 fields (addr nodeID ed25519_pubkey), got %d", path, lineNo, len(fields))
		}
		if len(fields) > peerDirColCount {
			return nil, fmt.Errorf("provisioning: %s:%d: too many fields (max %d, got %d) — is col %d a stray region?", path, lineNo, peerDirColCount, len(fields), peerDirColCount)
		}
		cfg, err := parsePeerDirLine(path, lineNo, fields)
		if err != nil {
			return nil, err
		}
		if first, dup := seen[cfg.addr]; dup {
			return nil, fmt.Errorf("provisioning: %s:%d: duplicate peer addr %q (first seen at line %d)", path, lineNo, cfg.addr, first)
		}
		// Day 35 /code-review (Angle D #3 + Angle C #8): dedup on NODEID too,
		// not just addr. Two config lines with the SAME nodeID but DIFFERENT
		// addrs would both pass the addr-dedup (distinct addrs) + both
		// applyProvisioning → the second RegisterPeer/RegisterPQ silently
		// OVERWRITES the first's Directory binding (directory.go d.m[nodeID]=
		// canonical, no error) → the first peer's deltas (signed under the
		// first peer's seed) are DROPPED as FORGED at VerifyCRDTFrame → a silent
		// partition the FAILSAFE parser must catch. A duplicate nodeID is a
		// deploy misconfiguration (two peers sharing an identity — a copy-paste
		// error OR a恶意 peer presenting a forged nodeID); the boot MUST fail
		// loudly, NOT silently shadow. The nodeID-dedup is DISTINCT from the
		// addr-dedup (a peer MAY legitimately appear once per addr; it may NOT
		// appear twice per identity).
		if first, dup := seenNodeID[cfg.nodeID]; dup {
			return nil, fmt.Errorf("provisioning: %s:%d: duplicate peer nodeID %x (first seen at line %d) — two peers sharing an identity silently shadow the first's Directory binding; the boot MUST fail loudly", path, lineNo, cfg.nodeID, first)
		}
		seen[cfg.addr] = lineNo
		seenNodeID[cfg.nodeID] = lineNo
		out = append(out, cfg)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("provisioning: scan --peer-dir %q: %w", path, err)
	}
	return out, nil
}

// parsePeerDirLine parses ONE non-blank, comment-stripped line's fields into a
// peerDirConfig. The length guard ran in parsePeerDir; this does the per-field
// decode + the length checks that are the load-bearing FAILSAFE gates (the
// §III RED tooth T-OOB-CONFIG-PARSE injects a 16-byte-truncated nodeID + a
// 16-byte-truncated pubkey + asserts REJECT; removing the length checks makes
// the tooth FAIL — the guards are load-bearing, NOT vestigial).
func parsePeerDirLine(path string, lineNo int, fields []string) (peerDirConfig, error) {
	cfg := peerDirConfig{addr: fields[peerDirColAddr]}
	if strings.IndexByte(cfg.addr, ':') < 0 {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: addr %q has no ':' (want host:port)", path, lineNo, cfg.addr)
	}
	// nodeID: 32 hex chars → 16 bytes.
	nid, err := hex.DecodeString(fields[peerDirColNodeID])
	if err != nil {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: nodeID %q: %w", path, lineNo, fields[peerDirColNodeID], err)
	}
	if len(nid) != 16 {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: nodeID %q: want 16 bytes (32 hex chars), got %d bytes", path, lineNo, fields[peerDirColNodeID], len(nid))
	}
	copy(cfg.nodeID[:], nid)
	// Ed25519 pubkey: 64 hex chars → 32 bytes. The load-bearing verification
	// anchor — a wrong length is a deploy defect, NOT a hint.
	pub, err := hex.DecodeString(fields[peerDirColEd25519])
	if err != nil {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: ed25519_pubkey %q: %w", path, lineNo, fields[peerDirColEd25519], err)
	}
	if len(pub) != 32 {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: ed25519_pubkey: want 32 bytes (64 hex chars), got %d bytes", path, lineNo, len(pub))
	}
	copy(cfg.ed25519Pub[:], pub)
	// OPTIONAL ML-DSA-65 pubkey (col 4) + region (col 5). The trailing columns
	// are present iff the line has ≥4 / ≥5 fields. The sentinel "-" in col 4
	// means classical-only (no PQ key) — a 5-field line with col 4 == "-"
	// provisions a classical-only peer WITH a region (the common region-aware
	// case). A 4-field line with col 4 == "-" is classical-only + no region
	// (the degenerate explicit-skip).
	if len(fields) >= peerDirColMldsa65+1 {
		mldsaField := fields[peerDirColMldsa65]
		if mldsaField != mldsa65SkipSentinel {
			// Reconstruct the ML-DSA-65 public key from its 1952-byte wire
			// encoding. mldsa.NewPublicKey(params, encoding) — mldsa.go:201,
			// the inner NewPublicKey65(pk []byte) at internal/.../mldsa.go:309.
			// A wrong length is a deploy defect (the key cannot verify); reject
			// it loudly, do NOT coerce.
			enc, err := hex.DecodeString(mldsaField)
			if err != nil {
				return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: mldsa65_pubkey %q: %w", path, lineNo, mldsaField, err)
			}
			// mldsa.MLDSA65PublicKeySize = 1952 (mldsa.go:22). The exact size is
			// the load-bearing gate — a truncated PQ key would silently verify
			// NOTHING (mldsa.Verify rejects a malformed pk), masking a deploy
			// defect as a "hybrid verify always fails" mystery.
			if len(enc) != mldsa.MLDSA65PublicKeySize {
				return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: mldsa65_pubkey: want %d bytes (%d hex chars), got %d bytes", path, lineNo, mldsa.MLDSA65PublicKeySize, mldsa.MLDSA65PublicKeySize*2, len(enc))
			}
			pqPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), enc)
			if err != nil {
				return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: mldsa65_pubkey: reconstruct: %w", path, lineNo, err)
			}
			cfg.mldsa65Pub = pqPub
		}
	}
	if len(fields) >= peerDirColRegion+1 {
		regionField := fields[peerDirColRegion]
		// A region of 0 is a VALID explicit tag (RegionUnset = routes as local).
		// The sentinel "-" here means "no region" (a 5-field line where the
		// operator wrote a PQ key but left region absent via "-" — the explicit
		// no-region sentinel so a 4-field PQ line is NOT ambiguous with a
		// 4-field region line). Accept uint8 0-255; reject out-of-range.
		if regionField == mldsa65SkipSentinel {
			cfg.hasRegion = false
		} else {
			r, err := strconv.ParseUint(regionField, 10, 8)
			if err != nil {
				return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: region %q: %w", path, lineNo, regionField, err)
			}
			cfg.region = mesh.RegionTag(r)
			cfg.hasRegion = true
		}
	}
	return cfg, nil
}

// provisionedMap is the addr→nodeID map applyProvisioning returns for the dial
// loop to branch on. A peer addr in this map dials under the REAL nodeID (the
// provisioned path — the selector HITS); an addr NOT in this map keeps the zero
// peerID (the byte-identical Day-34 back-compat path). It is the load-bearing
// return value: the dial loop's IF/ELSE arm keys off it.
type provisionedMap map[string][16]byte

// applyProvisioning parses the --peer-dir config + applies it to the live
// gossiper Directory + the TopologyManager. For each parsed entry it:
//
//  1. gossiper.RegisterPeer(nodeID, ed25519Pub[:]) — registers the peer's Ed25519
//     pubkey in the Directory (gossip.go:597; delegates to the SAME Directory
//     the local node's own pubkey is in via g.domains, gossip.go:288). This is
//     the binary mirror of the in-process gate's gA.RegisterPeer(identB.NodeID,
//     identB.Pub) (day34_topo_test.go:183) — the asymmetry it closes: today the
//     binary registers the LOCAL node's own pubkey (main.go:875 dir.Register)
//     but NO peer pubkeys at all.
//  2. dir.RegisterPQ(nodeID, mldsa65Pub) — registers the OPTIONAL ML-DSA-65
//     pubkey (identity.Directory.RegisterPQ, directory.go:154). The Gossiper
//     exposes NO RegisterPQ (grep-verified: gossip.go has RegisterPeer ONLY), so
//     the PQ arm goes through the Directory DIRECTLY — the SAME path run() uses
//     for the local node's own PQ key (main.go:891 dir.RegisterPQ). A nil
//     mldsa65Pub (the classical-only default) SKIPS the RegisterPQ call (a
//     classical-only peer leaves mPQ unpopulated → LookupBoth returns (edPub,
//     nil, true) → the hybrid verify rejects via the Day-31 STRICT mode — the
//     documented posture).
//  3. topo.SetRegion(nodeID, region) — re-keys the TopologyManager's region tag
//     under the REAL nodeID (NOT peerIDForAddr(addr)). This is the load-bearing
//     Day-35 fix: the Day-34 region tags key under the addr surrogate
//     (main.go:977), which the zero-peerID dial never populates → the region
//     lookup misses → every peer routes intra. Provisioning under the real
//     nodeID makes the selector HIT → the inter-region arm fires → the 24th SSoT
//     counter fires A=1 B=1. ONLY called when hasRegion (an absent region field
//     leaves the Day-34 peerIDForAddr(addr) registration in place — the honest
//     "operator did not tag this peer" default; the §III tooth
//     T-OOB-PROVISION-RETIRES-SURROGATE asserts a provisioned+tagged peer's
//     region key is the real nodeID, NOT the surrogate).
//
// Returns the provisionedMap (addr → real nodeID) for the dial loop + a nil
// error on success. An empty --peer-dir (ErrPeerDirEmpty) returns an empty map +
// a nil error (the OPT-IN no-op — the dial loop's ELSE arm runs for every peer,
// byte-identical Day-34). A NON-EMPTY path that fails to parse returns the
// error + an empty map (the caller FAILS the boot — a deploy misconfiguration
// MUST surface loudly, NOT silently fall back to zero-peerID).
//
// gossiper + topo + dir are all guaranteed non-nil at the call site (constructed
// unconditionally in run() before applyProvisioning is called — gossiper at
// main.go:896, topo at main.go:956, dir at main.go:842). No nil-guard needed.
// applyProvisioning applies the pre-parsed peer-dir configs to the live
// Directory + TopologyManager: gossiper.RegisterPeer (the CRDT verification
// pubkey), dir.RegisterPQ (the ML-DSA-65 pubkey, when present — the hybrid
// arm), + topo.SetRegion(realNodeID, region) (the topology re-key under the
// REAL nodeID — the Day-34 surrogate retirement). It returns the
// provisionedMap (addr → real nodeID) the dial loop reads to pick the
// dialPeerID. The caller parses --peer-dir ONCE (parsePeerDir) + passes the
// cfgs here (the Day-35 /code-review refactor: the surrogate region loop in
// main.go needs the provisioned ADDR SET before applyProvisioning's side
// effects, to SKIP the dead surrogate SetRegion for a provisioned peer — see
// main.go's parsePeerDir call before the surrogate loop). Idempotent re-apply
// is safe (RegisterPeer/RegisterPQ overwrite; SetRegion overwrites).
func applyProvisioning(gossiper *mesh.Gossiper, dir *identity.Directory, topo *mesh.TopologyManager, cfgs []peerDirConfig) (provisionedMap, error) {
	out := make(provisionedMap, len(cfgs))
	for _, c := range cfgs {
		if err := gossiper.RegisterPeer(c.nodeID, c.ed25519Pub[:]); err != nil {
			return nil, fmt.Errorf("provisioning: RegisterPeer %x at %s: %w", c.nodeID, c.addr, err)
		}
		if c.mldsa65Pub != nil {
			if err := dir.RegisterPQ(c.nodeID, c.mldsa65Pub); err != nil {
				return nil, fmt.Errorf("provisioning: RegisterPQ %x at %s: %w", c.nodeID, c.addr, err)
			}
		}
		if c.hasRegion {
			topo.SetRegion(c.nodeID, c.region)
		}
		out[c.addr] = c.nodeID
	}
	return out, nil
}
