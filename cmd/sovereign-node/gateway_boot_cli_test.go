// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// TestBootDial_NonBlockingSweepStart checks that slow peer addresses do not
// delay the sweep or prevent a live local peer from converging. Boot dials use
// up to 32 workers; SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=sync_boot_dial restores
// sequential dialing as a negative control.
func TestBootDial_NonBlockingSweepStart(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "sync_boot_dial" {
		disableAsyncBootDialFault.Store(true)
		t.Cleanup(func() { disableAsyncBootDialFault.Store(false) })
	}

	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dirPath := t.TempDir()
	caPath, err := ca.WriteCAPEM(dirPath)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}

	makeNode := func(idx byte) (
		ident *mesh.NodeIdentity,
		addr string,
		ps *mesh.PeerSet,
		g *mesh.Gossiper,
		engine *eng.DeltaCRDTEngine,
		cancel context.CancelFunc,
	) {
		var seed [32]byte
		for i := range seed {
			seed[i] = idx*31 + byte(i+1)
		}
		var err error
		ident, err = mesh.NewNodeIdentity(seed[:])
		if err != nil {
			t.Fatalf("NewNodeIdentity: %v", err)
		}
		nodeID := ident.NodeID

		leaf, err := ca.IssueLeaf(hex.EncodeToString(nodeID[:]))
		if err != nil {
			t.Fatalf("IssueLeaf: %v", err)
		}
		nodeDir := fmt.Sprintf("%s/node-%d", dirPath, idx)
		if err := os.MkdirAll(nodeDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		cPath, kPath, err := leaf.WritePEM(nodeDir)
		if err != nil {
			t.Fatalf("WritePEM: %v", err)
		}
		tr, err := transport.NewTLSTransport(cPath, kPath, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport: %v", err)
		}
		ln, err := tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		addr = "localhost:" + port

		engine, err = eng.NewDeltaCRDTEngine(nodeID, 1, 16*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine: %v", err)
		}
		engine.SetLamportAbsoluteSlack(1000)
		wallClock := clock.NewSystemClock()
		capGate := clock.NewIngressHLCScalarCap(wallClock, engine)
		bucket := admission.NewPeerBucket()
		dir := identity.NewDirectory()
		_ = dir.Register(ident.NodeID, ident.Pub)
		rx := receive.NewReceiver(bucket, capGate, wallClock, dir, engine, defaultAdmissionBudget)
		ps = mesh.NewPeerSet(tr, rx, ident, engine)
		g = mesh.NewGossiper(ps, ident, engine, dir)
		g.SetBatchSize(10)
		g.SetStratifiedAntiEntropy(true)
		g.SetDigestWaitTimeout(100 * time.Millisecond)
		g.WireRelayHooks(rx)

		ctx, cfn := context.WithCancel(context.Background())
		go acceptLoopWithDigest(ctx, ln, rx, nil, digestDemuxer{g: g}, ps)
		// Cancellation does not join SweepLoop or serveConnWithDigest. Closing the
		// engine here could therefore unmap the HAMT arena while a goroutine is
		// still reading it through MerkleRootFromShards. The node has the same
		// lifecycle: run returns without closing the engine before process exit.
		cancel = func() {
			cfn()
			_ = ln.Close()
			ps.Close()
		}
		return
	}

	identA, addrA, psA, gA, engA, cancelA := makeNode(1)
	defer cancelA()
	identB, addrB, psB, gB, engB, cancelB := makeNode(2)
	defer cancelB()

	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)

	// Four listeners accept TCP and delay TLS completion for 1.5 seconds. Their
	// addresses precede the live peer in the boot list.
	var slowAddrs []string
	var slowIDs [][16]byte
	for i := 0; i < 4; i++ {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen slow peer: %v", err)
		}
		t.Cleanup(func() { _ = rawLn.Close() })
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					time.Sleep(1500 * time.Millisecond)
					_ = conn.Close()
				}(c)
			}
		}(rawLn)
		slowAddrs = append(slowAddrs, rawLn.Addr().String())
		sid := [16]byte{0x48, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(10 + i)}
		slowIDs = append(slowIDs, sid)
		_ = gA.RegisterPeer(sid, identB.Pub)
	}

	// Insert 10 keys on Node A via Gossiper.InsertLocalEvents before boot dial.
	for i := 0; i < 10; i++ {
		var pd [32]byte
		pd[0] = byte(i + 1)
		_ = gA.InsertLocalEvents(fmt.Sprintf("boot-key-%02d", i), fmt.Sprintf("payload-%02d", i), eng.CRDTEntry{
			SystemTime:    1789000000000000000,
			PayloadDigest: pd,
		})
	}

	topoA := mesh.NewTopologyManager(mesh.RegionTag(1))
	topoA.SetRegion(identB.NodeID, mesh.RegionTag(1))
	provA := make(provisionedMap)
	for i, sa := range slowAddrs {
		topoA.SetRegion(slowIDs[i], mesh.RegionTag(1))
		provA[sa] = slowIDs[i]
	}
	provA[addrB] = identB.NodeID
	gA.SetTopology(topoA)
	gA.SetRegionAware(true)

	topoB := mesh.NewTopologyManager(mesh.RegionTag(1))
	topoB.SetRegion(identA.NodeID, mesh.RegionTag(1))
	provB := provisionedMap{addrA: identA.NodeID}
	gB.SetTopology(topoB)
	gB.SetRegionAware(true)

	peersA := append(append([]string{}, slowAddrs...), addrB)
	cfg := &nodeConfig{gossipTick: "25ms"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	if err := startMeshBootDialAndSweep(ctx, cfg, []string{addrA}, provB, topoB, psB, gB); err != nil {
		t.Fatalf("startMeshBootDialAndSweep B: %v", err)
	}
	if err := startMeshBootDialAndSweep(ctx, cfg, peersA, provA, topoA, psA, gA); err != nil {
		t.Fatalf("startMeshBootDialAndSweep A: %v", err)
	}
	bootElapsed := time.Since(start)
	if bootElapsed > 300*time.Millisecond {
		t.Fatalf("startMeshBootDialAndSweep blocked for %v (> 300ms) behind slow boot dials", bootElapsed)
	}

	deadline := start.Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rA := engA.MerkleRootFromShards()
		rB := engB.MerkleRootFromShards()
		if rA != ([32]byte{}) && rA == rB {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("live local peer B did not converge within 500ms while slow boot dials were in flight (elapsed=%v)", time.Since(start))
}

// TestProvisioning_GatewayDesignationAndOrphanGuards checks gateway selection
// and dependent-flag validation. With g = 3, applyProvisioning designates the
// first three entries per region in --peer-dir file order, not the lowest node
// IDs. validateConfig also rejects gateway and IBLT sizing flags without the
// features they configure.
func TestProvisioning_GatewayDesignationAndOrphanGuards(t *testing.T) {
	// The first three entries in each six-entry region have higher node IDs
	// than the last three, so selection by file order differs from selection
	// by lexicographic node ID.
	var cfgs []peerDirConfig
	for _, reg := range []mesh.RegionTag{1, 2} {
		for i := 0; i < 6; i++ {
			var id [16]byte
			if i < 3 {
				id[0] = 0xF0 + byte(i)
			} else {
				id[0] = 0x10 + byte(i-3)
			}
			id[1] = byte(reg)
			binary.BigEndian.PutUint32(id[12:16], uint32(i))
			var pub [32]byte
			for k := range pub {
				pub[k] = id[0] ^ id[1] ^ byte(k+1)
			}
			cfgs = append(cfgs, peerDirConfig{
				addr:       fmt.Sprintf("10.0.%d.%d:7373", reg, i+1),
				nodeID:     id,
				ed25519Pub: pub,
				region:     reg,
				hasRegion:  true,
			})
		}
	}

	// The first entry in a region is a gateway, including when it is this node.
	selfGW := cfgs[0].nodeID
	dir1 := identity.NewDirectory()
	topo1 := mesh.NewTopologyManager(mesh.RegionTag(1))
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") != "provisioning_order" {
		topo1.SetGatewaysPerRegion(3)
	}
	topo1.SetSelfNodeID(selfGW)
	g1 := mesh.NewGossiper(nil, nil, nil, dir1)
	if _, err := applyProvisioning(g1, dir1, topo1, cfgs, selfGW); err != nil {
		t.Fatalf("applyProvisioning(selfGW): %v", err)
	}
	if !topo1.IsSelfGateway() {
		t.Fatalf("selfGW (1st entry in region 1) must have IsSelfGateway() == true")
	}
	for idx, c := range cfgs {
		if c.nodeID == selfGW {
			continue
		}
		posInReg := idx % 6
		wantGW := posInReg < 3
		if got := topo1.IsGateway(c.nodeID); got != wantGW {
			t.Fatalf("entry idx=%d (posInReg=%d id=%x) IsGateway=%v, want %v", idx, posInReg, c.nodeID[:4], got, wantGW)
		}
	}

	// The fifth entry in the same region is an interior node.
	selfInt := cfgs[4].nodeID
	dir2 := identity.NewDirectory()
	topo2 := mesh.NewTopologyManager(mesh.RegionTag(1))
	topo2.SetGatewaysPerRegion(3)
	topo2.SetSelfNodeID(selfInt)
	g2 := mesh.NewGossiper(nil, nil, nil, dir2)
	if _, err := applyProvisioning(g2, dir2, topo2, cfgs, selfInt); err != nil {
		t.Fatalf("applyProvisioning(selfInt): %v", err)
	}
	if topo2.IsSelfGateway() {
		t.Fatalf("selfInt (5th entry in region 1) must have IsSelfGateway() == false")
	}

	// Flags that depend on region-aware gossip or IBLT v2 are rejected alone.
	cfgGWOrphan, err := parseFlags([]string{"--selftest", "--gateways-per-region", "3"})
	if err != nil {
		t.Fatalf("parseFlags(--gateways-per-region 3): %v", err)
	}
	if err := validateConfig(cfgGWOrphan); err == nil || !strings.Contains(err.Error(), "--gateways-per-region requires --region-aware") {
		t.Fatalf("expected --gateways-per-region orphan error, got %v", err)
	}

	cfgIBLTOrphan, err := parseFlags([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2-min-buckets", "21845"})
	if err != nil {
		t.Fatalf("parseFlags(--iblt-v2-min-buckets 21845): %v", err)
	}
	if err := validateConfig(cfgIBLTOrphan); err == nil || !strings.Contains(err.Error(), "--iblt-v2-min-buckets requires --iblt-v2") {
		t.Fatalf("expected --iblt-v2-min-buckets orphan error, got %v", err)
	}

	cfgValid, err := parseFlags([]string{"--selftest", "--region-aware", "--gateways-per-region", "3", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "21845", "--arena-mib", "256"})
	if err != nil {
		t.Fatalf("parseFlags(valid): %v", err)
	}
	if err := validateConfig(cfgValid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// TestValidateConfig_ArenaMiBGuard checks that bucket counts above 8192
// require a 256 MiB arena in both validateConfig and run. Smaller bucket counts
// work with the 64 MiB default. SOVEREIGN_TEST_FAULT_IBLT_ARENA can disable the
// guard as a negative control.
func TestValidateConfig_ArenaMiBGuard(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_IBLT_ARENA") == "skip_arena_mib_guard" {
		disableArenaMiBMinBucketsGuardFault.Store(true)
		defer disableArenaMiBMinBucketsGuardFault.Store(false)
	}

	// Check validateConfig before invoking run, which also creates a listener.
	cfg64, err := parseFlags([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "21845", "--arena-mib", "64"})
	if err != nil {
		t.Fatalf("parseFlags(arena-mib 64): %v", err)
	}
	if err := validateConfig(cfg64); err == nil || !strings.Contains(err.Error(), "requires --arena-mib >= 256") {
		t.Fatalf("expected --arena-mib >= 256 error for --iblt-v2-min-buckets 21845 --arena-mib 64, got %v", err)
	}

	// The 64 MiB default is also insufficient for 21,845 buckets.
	cfgDefault, err := parseFlags([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "21845"})
	if err != nil {
		t.Fatalf("parseFlags(default arena-mib): %v", err)
	}
	if err := validateConfig(cfgDefault); err == nil || !strings.Contains(err.Error(), "requires --arena-mib >= 256") {
		t.Fatalf("expected --arena-mib >= 256 error for default --arena-mib, got %v", err)
	}

	// run applies the same validation before opening the self-test listener.
	if err := run([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "21845", "--arena-mib", "64"}); err == nil || !strings.Contains(err.Error(), "requires --arena-mib >= 256") {
		t.Fatalf("expected --arena-mib >= 256 error from run(), got %v", err)
	}

	// A 256 MiB arena accepts the 21,845-bucket configuration.
	cfg256, err := parseFlags([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "21845", "--arena-mib", "256"})
	if err != nil {
		t.Fatalf("parseFlags(arena-mib 256): %v", err)
	}
	if err := validateConfig(cfg256); err != nil {
		t.Fatalf("expected --iblt-v2-min-buckets 21845 --arena-mib 256 to be accepted, got %v", err)
	}

	// The 4,096-bucket configuration remains below the arena-size threshold.
	cfg4096, err := parseFlags([]string{"--selftest", "--stratified-anti-entropy", "--iblt-v2", "--iblt-v2-min-buckets", "4096", "--arena-mib", "64"})
	if err != nil {
		t.Fatalf("parseFlags(min-buckets 4096, arena-mib 64): %v", err)
	}
	if err := validateConfig(cfg4096); err != nil {
		t.Fatalf("expected --iblt-v2-min-buckets 4096 --arena-mib 64 to be accepted, got %v", err)
	}
}
