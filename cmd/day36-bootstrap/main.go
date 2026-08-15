// Command day36-bootstrap mints the FULL mesh-bootstrap for the Day-36
// 100-node 3-region silicon gate: a dev CA, 100 per-node leaf certs, 100
// unique Ed25519 signing identities (seed + derived nodeID + pubkey), the
// shared 100-line --peer-dir config, and a manifest the orchestrator consumes
// to scp each per-node bundle to its host.
//
// WHY THIS EXISTS — the orchestrator's STEP 1/STEP 2 were STUBBED (no peer-dir,
// no CA/leafs, a FIXED all-AA identity-seed for every node). Without a real
// bootstrap, STEP 3 launched 100 ISOLATED nodes that could NOT gossip (no
// --peer-dir → the receiver's Directory.Lookup misses → deltas DROPPED LOUD;
// a shared identity → every node signs under ONE key → a single-identity
// "mesh" that is NOT 100 nodes). This helper is the HONEST mesh-wiring the
// gate requires — it is the named prerequisite the ADR-0041 carry-forward
// "inject-batch-CLI / peer-dir-bootstrap gap" named, now built.
//
// THE DERIVATION (must match the binary EXACTLY):
//
//	seed_i    = sha256("day36-node-" + i)                        (32 bytes)
//	nodeID_i  = ed25519.NewKeyFromSeed(seed_i).Public()[:16]     (16 bytes)
//	pubkey_i  = ed25519.NewKeyFromSeed(seed_i).Public()          (32 bytes)
//
// The binary's buildNodeIdentity (cmd/sovereign-node/main.go:1858) derives
// the SAME nodeID from --identity-seed + fatalf's if it != --node-id, so the
// orchestrator MUST pass --identity-seed <seed_hex> AND --node-id <nodeID_hex>
// (both from this manifest). The peer-dir line for node i is:
//
//	<addr> <nodeID_hex> <pubkey_hex> - <region>
//
// where <addr> = <host_public_ip>:<mesh_port> (the mesh port = MESH_PORT_BASE +
// the per-region LOCAL index; cross-region peers dial the public IP — the SG
// opens the mesh port 0.0.0.0/0 for the run, tightened post-launch).
//
// USAGE (run LOCALLY on the executor — it needs the Go crypto deps):
//
//	day36-bootstrap -out-dir /tmp/day36-bootstrap \
//	    -regions us-east-1=192.0.2.10,eu-west-1=203.0.113.10,ap-southeast-2=198.51.100.10 \
//	    -split 34,33,33 -mesh-port-base 7373
//
// OUTPUTS (under -out-dir):
//
//	ca.pem                 — the shared trust anchor (every host gets this)
//	peerdir                — the 100-line --peer-dir config (every host gets this)
//	manifest               — one line per node: i region ip mesh_port seed_hex nodeID_hex cert key
//	node-<i>/seed.hex      — the --identity-seed value
//	node-<i>/nodeid.hex    — the --node-id value
//	node-<i>/cert.pem     — the --tls-cert value (certgen.go IssueLeafWithIP → WritePEM writes cert.pem)
//	node-<i>/key.pem      — the --tls-key value (WritePEM writes key.pem)
//	node-<i>/meta          — i region ip mesh_port (the orchestrator's scp + launch key)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/mesh"
)

func main() {
	outDir := flag.String("out-dir", "", "output directory (required)")
	regionsCSV := flag.String("regions", "", "region=ip,region=ip,region=ip (required, in NODES_CSV order)")
	splitCSV := flag.String("split", "34,33,33", "per-region node counts (must sum to -require-n for the silicon run; a local smoke test passes e.g. 1,1,1 with -require-n 3)")
	meshPortBase := flag.Int("mesh-port-base", 7373, "the mesh port base; node i binds mesh-port-base + (per-region local index)")
	requireN := flag.Int("require-n", 100, "the total node count the split MUST sum to (100 for the silicon gate; 3 for a local smoke test)")
	flag.Parse()

	if *outDir == "" || *regionsCSV == "" {
		fmt.Fprintln(os.Stderr, "day36-bootstrap: -out-dir and -regions are required")
		os.Exit(2)
	}
	type region struct {
		name string
		ip   string
	}
	var regions []region
	for _, pair := range strings.Split(*regionsCSV, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			fmt.Fprintf(os.Stderr, "day36-bootstrap: bad region pair %q (want name=ip)\n", pair)
			os.Exit(2)
		}
		regions = append(regions, region{name: kv[0], ip: kv[1]})
	}
	if len(regions) != 3 {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: need exactly 3 regions, got %d\n", len(regions))
		os.Exit(2)
	}
	var split []int
	for _, s := range strings.Split(*splitCSV, ",") {
		n, err := strconv.Atoi(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "day36-bootstrap: bad split %q: %v\n", s, err)
			os.Exit(2)
		}
		split = append(split, n)
	}
	if len(split) != 3 {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: need exactly 3 split counts, got %d\n", len(split))
		os.Exit(2)
	}
	total := split[0] + split[1] + split[2]
	if total != *requireN {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: split sums to %d, want %d (-require-n)\n", total, *requireN)
		os.Exit(2)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: mkdir out-dir: %v\n", err)
		os.Exit(1)
	}

	// ── 1. Mint the dev CA (the shared trust anchor). ──
	ca, err := crypto.NewMeshCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: NewMeshCA: %v\n", err)
		os.Exit(1)
	}
	caPath, err := ca.WriteCAPEM(*outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: WriteCAPEM: %v\n", err)
		os.Exit(1)
	}
	// WriteCAPEM writes ca.pem inside outDir; the returned path is the full path.
	_ = caPath

	// ── 1b. Mint ONE client leaf (signed by the SAME CA) for the gate client. ──
	// The gate client (cmd/day36-gate) presents this leaf to each node's mTLS
	// control port (--control-addr, RequireAndVerifyClientCert). The client CN
	// is distinct from every node CN (the "client" suffix) so the per-node
	// nodeID-dedup in parsePeerDir is irrelevant (the client is NOT a peer; it
	// is an SDK consumer of the control port). One client leaf dials ALL 100
	// nodes (the CA is the trust anchor; the client cert is the credential).
	clientDir := filepath.Join(*outDir, "client")
	if err := os.MkdirAll(clientDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: mkdir client dir: %v\n", err)
		os.Exit(1)
	}
	clientLeaf, err := ca.IssueLeaf("day36-gate-client")
	if err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: IssueLeaf client: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := clientLeaf.WritePEM(clientDir); err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: WritePEM client: %v\n", err)
		os.Exit(1)
	}

	// ── 2. Derive the 100 identities + mint 100 leafs, building the peer-dir. ─
	// Global node index → (region, per-region local index) via the split, the
	// SAME mapping the orchestrator's node_region() uses.
	var peerDirLines []string
	var manifestLines []string
	var allAddrs []string // every node's mesh addr; each node's --peers = allAddrs minus its own
	globalIdx := 0
	for ridx, r := range regions {
		for localIdx := 0; localIdx < split[ridx]; localIdx++ {
			// Deterministic per-node seed: sha256("day36-node-<globalIdx>").
			seed := sha256.Sum256([]byte("day36-node-" + strconv.Itoa(globalIdx)))
			ident, err := mesh.NewNodeIdentity(seed[:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: NewNodeIdentity node %d: %v\n", globalIdx, err)
				os.Exit(1)
			}
			nodeIDHex := hex.EncodeToString(ident.NodeID[:])
			pubkeyHex := hex.EncodeToString(ident.Pub)
			seedHex := hex.EncodeToString(seed[:])

			// Mint the leaf cert (CN = nodeID hex; the handshake identifies the
			// node by the leaf CN; --peer-auto-reconcile hex-decodes the CN). The
			// leaf carries the host's IP in its IPAddresses SAN (IssueLeafWithIP)
			// so the peer dial — which uses the peer addr's HOST as the TLS
			// ServerName (main.go:1381 splitHostPort) — verifies against the IP
			// SAN, NOT a DNSName (the default IssueLeaf has IPAddresses=nil; that
			// works ONLY for localhost-loopback dials, where ServerName=localhost
			// matches the leaf's "localhost" DNSName). For silicon the peers dial
			// the PUBLIC IP → the leaf MUST carry it. A nil/empty IP (parse fail)
			// falls back to DNSNames-only — logged but NOT fatal (a localhost
			// smoke test passes 127.0.0.1, which parses; a malformed IP is a
			// deploy error the boot handshake surfaces as "no IP SAN").
			var leafIPs []net.IP
			if pip := net.ParseIP(r.ip); pip != nil {
				leafIPs = []net.IP{pip}
			} else {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: WARN: region %q ip %q is not a parseable IP — leaf minted DNSNames-only (peer dial by this addr's host will FAIL the TLS hostname check)\n", r.name, r.ip)
			}
			leaf, err := ca.IssueLeafWithIP(nodeIDHex, leafIPs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: IssueLeafWithIP node %d: %v\n", globalIdx, err)
				os.Exit(1)
			}
			nodeDir := filepath.Join(*outDir, fmt.Sprintf("node-%d", globalIdx))
			if err := os.MkdirAll(nodeDir, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: mkdir node dir: %v\n", err)
				os.Exit(1)
			}
			certPath, keyPath, err := leaf.WritePEM(nodeDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: WritePEM node %d: %v\n", globalIdx, err)
				os.Exit(1)
			}
			_ = certPath
			_ = keyPath
			if err := os.WriteFile(filepath.Join(nodeDir, "seed.hex"), []byte(seedHex+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: write seed: %v\n", err)
				os.Exit(1)
			}
			if err := os.WriteFile(filepath.Join(nodeDir, "nodeid.hex"), []byte(nodeIDHex+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: write nodeid: %v\n", err)
				os.Exit(1)
			}
			// meta: the orchestrator's scp + launch key (which node, which host, which port).
			meta := fmt.Sprintf("%d %s %s %d\n", globalIdx, r.name, r.ip, *meshPortBase+localIdx)
			if err := os.WriteFile(filepath.Join(nodeDir, "meta"), []byte(meta), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "day36-bootstrap: write meta: %v\n", err)
				os.Exit(1)
			}

			// peer-dir line: <addr> <nodeID_hex> <pubkey_hex> - <region>
			// addr = host public IP : mesh port (cross-region dial via public IP;
			// the SG opens the mesh port for the run).
			addr := fmt.Sprintf("%s:%d", r.ip, *meshPortBase+localIdx)
			allAddrs = append(allAddrs, addr)
			// The peer-dir region column is a uint8 region TAG (0-255), NOT a
			// region NAME — the binary's parsePeerDir ParseUint's it into a
			// mesh.RegionTag (provisioning.go: a name like "us-east-1" is
			// "invalid syntax" → boot fatalf). r.name is for the manifest (human
			// reading); the peer-dir carries the INDEX (0/1/2 = the --self-region
			// tag space, 0=RegionUnset=intra default; we use 1/2/3 to leave 0 as
			// the explicit-Unset sentinel the engine reserves).
			regionTag := ridx + 1
			peerDirLines = append(peerDirLines, fmt.Sprintf("%s %s %s - %d", addr, nodeIDHex, pubkeyHex, regionTag))
			manifestLines = append(manifestLines, fmt.Sprintf("%d %s %s %d %s %s %s %s",
				globalIdx, r.name, r.ip, *meshPortBase+localIdx, seedHex, nodeIDHex,
				filepath.Join(filepath.Base(nodeDir), "cert.pem"),
				filepath.Join(filepath.Base(nodeDir), "key.pem")))
			globalIdx++
		}
	}

	// ── 3. Write the peer-dir + the manifest. ──
	peerDirPath := filepath.Join(*outDir, "peerdir")
	peerDirContent := strings.Join(peerDirLines, "\n") + "\n"
	if err := os.WriteFile(peerDirPath, []byte(peerDirContent), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: write peerdir: %v\n", err)
		os.Exit(1)
	}
	manifestPath := filepath.Join(*outDir, "manifest")
	manifestContent := strings.Join(manifestLines, "\n") + "\n"
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "day36-bootstrap: write manifest: %v\n", err)
		os.Exit(1)
	}

	// ── 3b. Write each node's --peers list (all OTHER nodes' mesh addrs). ──
	// The binary's dial loop keys off --peers (the Day-2 dial list); --peer-dir
	// only REGISTERS the peer's verification identity (the Day-35 anchor). The
	// boot WARNS "peer X in --peer-dir but NOT in --peers — never dialed — a
	// silent one-way partition" if a peer-dir peer is missing from --peers. So
	// a node MUST pass BOTH: --peer-dir (the shared config) AND --peers (every
	// OTHER node's addr, comma-joined). Each node's peers.txt is allAddrs minus
	// its OWN addr (a node does not dial itself).
	for i := range allAddrs {
		var others []string
		for j, a := range allAddrs {
			if j != i {
				others = append(others, a)
			}
		}
		nodeDir := filepath.Join(*outDir, fmt.Sprintf("node-%d", i))
		peersPath := filepath.Join(nodeDir, "peers.txt")
		if err := os.WriteFile(peersPath, []byte(strings.Join(others, ",")+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "day36-bootstrap: write peers.txt node %d: %v\n", i, err)
			os.Exit(1)
		}
	}

	// ── 4. Self-verify: re-derive nodeID from a random seed file + confirm the ─
	//        peer-dir has 100 lines + every nodeID is unique (the FAILSAFE the ─
	//        binary's parsePeerDir enforces; a duplicate nodeID fatalf's the boot). ─
	seen := make(map[string]bool)
	for _, l := range peerDirLines {
		fields := strings.Fields(l)
		if len(fields) < 3 {
			fmt.Fprintf(os.Stderr, "day36-bootstrap: INTERNAL: bad peer-dir line %q\n", l)
			os.Exit(1)
		}
		if seen[fields[1]] {
			fmt.Fprintf(os.Stderr, "day36-bootstrap: INTERNAL: duplicate nodeID %s (the boot would fatalf)\n", fields[1])
			os.Exit(1)
		}
		seen[fields[1]] = true
	}

	fmt.Printf("day36-bootstrap: OK — %d nodes, CA + peer-dir + manifest + per-node bundles written to %s\n", globalIdx, *outDir)
	fmt.Printf("  regions: %s\n", *regionsCSV)
	fmt.Printf("  split:   %s (sum=%d)\n", *splitCSV, total)
	fmt.Printf("  outputs: ca.pem, peerdir (%d lines), manifest, node-<i>/{seed.hex,nodeid.hex,cert.pem,key.pem,meta}\n", len(peerDirLines))
}
