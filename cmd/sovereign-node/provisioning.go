// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package main implements out-of-band peer-directory provisioning (ADR-0040).
//
// Without a peer directory, the dial loop uses a zero peerID while region tags
// are keyed by peerIDForAddr(addr), a SHA-256 address surrogate. Those keys do
// not match, so region lookup fails and peers use the full-mesh route. The
// --peer-dir file binds each address to a nodeID, an Ed25519 public key, and
// optionally an ML-DSA-65 public key and region. Provisioning registers those
// keys and regions under the real nodeID and returns the address-to-nodeID map
// used by the dial loop. Unprovisioned peers retain the zero-peerID behavior.
//
// ML-DSA-65 keys use their 1,952-byte public-key encoding.
// mldsa.NewPublicKey(mldsa.MLDSA65(), encoded) reconstructs the value returned
// by PublicKey.Bytes; it does not accept a private-key seed.
//
// Region parsing and identity parsing have different failure policies. A
// malformed region suffix can fall back to conservative local routing, but a
// malformed public key cannot be ignored: Directory.Lookup uses that key to
// verify the peer's deltas. parsePeerDir therefore reports the line and field
// for malformed entries instead of coercing truncated keys to zero.

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"filippo.io/mldsa"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

// peerDirConfig is one parsed --peer-dir entry. The address is bound to the
// Ed25519 public key used to verify the peer's CRDT deltas, with optional
// ML-DSA-65 and region fields for hybrid verification and region-aware routing.
//
// A wrong Ed25519 key causes the receiver to reject genuine deltas as forgeries,
// so a configuration error can partition a peer. A nil ML-DSA-65 key means the
// peer is classical-only; strict hybrid verification rejects a missing PQ key
// (ADR-0036). RegionUnset, the zero region, uses conservative same-region
// routing (ADR-0039).
//
// hasRegion distinguishes an explicitly configured RegionUnset from an omitted
// region. applyProvisioning calls SetRegion only in the former case.
//
// The address and ML-DSA-65 pointer precede the fixed-size fields to reduce the
// pointer-bearing portion of the struct. These values are allocated while
// parsing configuration, not on the write path, and are not mutated afterward.
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
//	1  addr            host:port (required, must contain a ":")
//	2  nodeID          32-hex-char (16-byte) node identity (required)
//	3  ed25519_pubkey  64-hex-char (32-byte) Ed25519 public key (required)
//	4  mldsa65_pubkey  3904-hex-char (1952-byte) ML-DSA-65 public key (optional)
//	5  region          uint8 region tag 0-255 (optional, only if col 4 present)
//
// Columns are positional and whitespace-separated, so parsing needs no
// configuration-file dependency. Text from # to the end of a line is a comment.
// Blank and comment-only lines are skipped. Optional columns are trailing: three
// fields specify a classical-only peer with no region, four add a PQ public key,
// and five add a region. Use "-" in column 4 to specify a region without a PQ
// key.
const (
	peerDirColAddr = iota
	peerDirColNodeID
	peerDirColEd25519
	peerDirColMldsa65
	peerDirColRegion
	peerDirColCount // the max column count (region + 1)
)

// mldsa65SkipSentinel marks an omitted optional key or region. In
// "addr nodeID ed25519 - 3" it leaves the peer classical-only and assigns region
// 3. It also makes a five-field line unambiguous: column 4 contains a key or the
// sentinel, and column 5 contains the region. A four-field line with "-" is
// accepted and specifies neither a PQ key nor a region.
const mldsa65SkipSentinel = "-"

// ErrPeerDirEmpty reports that --peer-dir was not set. parsePeerDir returns this
// error for the default empty path; the caller treats it as a no-op and leaves
// the dial loop on its zero-peerID compatibility path. A non-empty path that
// cannot be opened is a configuration error and fails startup instead.
var ErrPeerDirEmpty = errors.New("provisioning: --peer-dir is empty (no OOB provisioning; dial loop keeps the zero peerID — byte-identical back-compat)")

// parsePeerDir reads a --peer-dir file and returns its entries in file order.
// File order also determines registration and gateway-selection order.
//
// A non-empty path that cannot be opened returns an error rather than falling
// back to zero-peerID dialing. Malformed keys, regions, and field counts return
// errors naming the line and field. Duplicate addresses and nodeIDs are also
// rejected: the dial loop is keyed by address, and a second registration for
// the same nodeID would replace the first peer's Directory binding.
func parsePeerDir(path string) ([]peerDirConfig, error) {
	if path == "" {
		return nil, ErrPeerDirEmpty
	}
	f, err := os.Open(path)
	if err != nil {
		// A named but absent file is a configuration error. os.Open includes the
		// path; wrapping the error identifies the --peer-dir that failed.
		return nil, fmt.Errorf("provisioning: open --peer-dir %q: %w", path, err)
	}
	defer f.Close()
	var out []peerDirConfig
	seen := make(map[string]int)         // addr -> first line seen (1-indexed)
	seenNodeID := make(map[[16]byte]int) // nodeID -> first line seen
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // a 1952B hex pubkey = 3904 chars; allow 4MiB lines
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		// Strip a `#` comment (to end-of-line). A `#` inside a hex value is
		// impossible (hex is [0-9a-f]), so the first `#` is unambiguously a
		// comment start. The comment is stripped before the field split so a
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
		// Distinct addresses may not share a nodeID. Otherwise both entries pass
		// the address check, and the second RegisterPeer or RegisterPQ call would
		// replace the first entry's Directory binding. Deltas from the first peer
		// would then fail signature verification. Rejecting the duplicate during
		// parsing prevents that partial loss of connectivity at startup.
		if first, dup := seenNodeID[cfg.nodeID]; dup {
			return nil, fmt.Errorf("provisioning: %s:%d: duplicate peer nodeID %x (first seen at line %d) — two peers sharing an identity silently shadow the first's Directory binding; the boot must fail loudly", path, lineNo, cfg.nodeID, first)
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

// parsePeerDirLine decodes one non-blank, comment-stripped line after
// parsePeerDir has checked its field count. Exact key lengths are enforced here
// so truncated identities cannot enter the Directory or topology registry.
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
	// anchor — a wrong length is a deploy defect, not a hint.
	pub, err := hex.DecodeString(fields[peerDirColEd25519])
	if err != nil {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: ed25519_pubkey %q: %w", path, lineNo, fields[peerDirColEd25519], err)
	}
	if len(pub) != 32 {
		return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: ed25519_pubkey: want 32 bytes (64 hex chars), got %d bytes", path, lineNo, len(pub))
	}
	copy(cfg.ed25519Pub[:], pub)
	// Column 4 optionally contains an ML-DSA-65 public key, and column 5 a
	// region. The "-" sentinel in column 4 selects classical-only operation;
	// column 5 may then supply a region. A four-field line with "-" has neither
	// optional value.
	if len(fields) >= peerDirColMldsa65+1 {
		mldsaField := fields[peerDirColMldsa65]
		if mldsaField != mldsa65SkipSentinel {
			// Reconstruct the ML-DSA-65 public key from its serialized encoding.
			// NewPublicKey expects the public-key bytes, not a private seed.
			enc, err := hex.DecodeString(mldsaField)
			if err != nil {
				return peerDirConfig{}, fmt.Errorf("provisioning: %s:%d: mldsa65_pubkey %q: %w", path, lineNo, mldsaField, err)
			}
			// MLDSA65PublicKeySize is 1952 bytes. Reject other lengths here so a
			// malformed key is reported as a configuration error rather than as a
			// signature verification failure later.
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
		// RegionUnset is valid when written explicitly as 0. The "-" sentinel
		// leaves hasRegion false, while every other value must fit in a uint8.
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

// provisionedMap maps a configured address to its real nodeID. The dial loop
// uses the mapped identity for provisioned peers and retains the zero peerID
// for addresses absent from the map.
type provisionedMap map[string][16]byte

// applyProvisioning registers pre-parsed entries with the live Directory and
// TopologyManager. Each non-self entry contributes its Ed25519 key through
// gossiper.RegisterPeer, its optional ML-DSA-65 key through dir.RegisterPQ, and,
// when hasRegion is set, its region through topo.SetRegion. PQ registration uses
// the Directory directly because Gossiper exposes no RegisterPQ method. A nil PQ
// key leaves LookupBoth with a classical key only, which strict hybrid
// verification rejects (ADR-0036).
//
// Regions are keyed by real nodeID rather than peerIDForAddr so the topology
// selector can find the same identity used by peer connections. If hierarchical
// gateways are enabled, the first configured entries in each region, up to
// GatewaysPerRegion, are designated as gateways in file order. An entry matching
// selfNodeID is logged and excluded from registration and the returned map, but
// still participates in gateway designation.
//
// The returned map directs the dial loop to real nodeIDs. Empty cfgs produce an
// empty map and no error. Registration failures return an error; parsing and
// missing-file errors are handled by the caller before this function runs. run
// constructs gossiper, dir, and topo before calling applyProvisioning.
func applyProvisioning(gossiper *mesh.Gossiper, dir *identity.Directory, topo *mesh.TopologyManager, cfgs []peerDirConfig, selfNodeID [16]byte) (provisionedMap, error) {
	out := make(provisionedMap, len(cfgs))
	var gwCountByRegion map[mesh.RegionTag]int
	gwPerReg := 0
	if topo != nil {
		gwPerReg = topo.GatewaysPerRegion()
		if gwPerReg > 0 {
			gwCountByRegion = make(map[mesh.RegionTag]int)
			topo.SetSelfGateway(false)
		}
	}
	for _, c := range cfgs {
		if gwPerReg > 0 && c.hasRegion && c.region != mesh.RegionUnset {
			gwCountByRegion[c.region]++
			if gwCountByRegion[c.region] <= gwPerReg {
				if c.nodeID == selfNodeID {
					topo.SetSelfGateway(true)
				} else {
					topo.SetGateway(c.nodeID, true)
				}
			}
		}
		// A shared peer directory can include the local node. TopologyManager
		// knows its own region but not its own nodeID, so registering that entry
		// would let Select return the local identity and the sweep would try to
		// publish to a peer connection that does not exist. Skip registration and
		// omit the address from provisionedMap so the dial loop also excludes it.
		// The log distinguishes this intentional skip from a parsing failure.
		if c.nodeID == selfNodeID {
			log.Printf("provisioning: skipped SELF entry %x at %s — a node is never its own peer (shared-peerdir deploy)", c.nodeID, c.addr)
			continue
		}
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
