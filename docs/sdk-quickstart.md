# Sovereign Engine SDK — Quickstart

A developer who has never read the engine internals connects to a running mesh
over mutual TLS and performs a state operation in under 50 lines of Go. This
quickstart is the path from zero to a working insert/get loop.

## 1. What you need

- Go 1.26+ (the engine targets `go 1.26.1`).
- A running `sovereign-node` with the control port enabled (`--control-addr`).
- A client certificate signed by the same CA the node trusts (mTLS — the same
  trust root as the peer path; see §3).

## 2. Start a node with the control port

```bash
go build -o sovereign-node ./cmd/sovereign-node

# Mint a dev CA + a node leaf (see §3 for the one-liner), then:
./sovereign-node \
  --control-addr 127.0.0.1:7432 \
  --bind          127.0.0.1:7430 \
  --metrics-addr  127.0.0.1:7431 \
  --tls-cert node.crt --tls-key node.key --tls-ca ca.pem \
  --node-id 27c04aec476bd59d3191a050d55a06bb
```

The control port (`--control-addr`) is a SEPARATE TLS listener from the peer
gossip port (`--bind`) and the plain-HTTP ops surface (`--metrics-addr`):
**three surfaces, one trust root**. `--control-addr` defaults OFF — a node with
no `--control-addr` is still a peer in the mesh; the data plane is unaffected.

## 3. Mint a dev CA + client cert (one-liner)

The engine ships a dev-mesh CA in `pkg/crypto/certgen` (a DEV CA, not a
production PKI — post-10-day). Reuse it to mint the CA, a node leaf, and a
client leaf the SDK presents as its mTLS client cert:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/mesh"
)

func main() {
	ca, _ := crypto.NewMeshCA()
	caPath, _ := ca.WriteCAPEM(".")          // writes ca.pem

	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	ident, _ := mesh.NewNodeIdentity(seed)
	nodeHex := hex.EncodeToString(ident.NodeID[:])
	leaf, _ := ca.IssueLeaf(nodeHex)          // node leaf (CommonName = nodeID hex)
	certPath, keyPath, _ := leaf.WritePEM("node")
	fmt.Println("CA:", caPath, "node cert/key:", certPath, keyPath, "nodeID:", nodeHex)

	cleaf, _ := ca.IssueLeaf("sdk-client")    // client leaf (the SDK's mTLS cert)
	ccert, ckey, _ := cleaf.WritePEM("client")
	fmt.Println("client cert/key:", ccert, ckey)
}
```

Run it: `go run ./cmd/mint-dev-certs` (or inline). The node leaf's `DNSNames`
include both the nodeID hex and `localhost`, so the SDK can verify the server
cert with `ServerName: "localhost"`.

## 4. The <50-line example

`examples/sdk/main.go` is the canonical "how to use this" file — 49 lines,
importing ONLY the `sovereign` SDK + stdlib (zero `internal/` or `pkg/`
imports; the SDK hides them):

```bash
go run ./examples/sdk \
  -addr 127.0.0.1:7432 \
  -cert client/cert.pem -key client/key.pem -ca ca.pem
```

Output:

```
inserted 100 keys; merkle=dafcbb3716958349fbf93a7f766ecc1e946341f416ca39b143a35f131ce4771c
get key-0: payload="value-0" digest=bcdbcd7f... (originator cache hit)
```

The example dials the control port, inserts 100 key/value pairs, prints the
Merkle root, and reads one key back. The cert-loading boilerplate lives in the
SDK (`sovereign.DialWithCerts`), not the example — the example is the caller,
not a helper library.

## 5. The SDK surface

```go
cli, err := sovereign.DialWithCerts(addr, certPath, keyPath, caPath, "localhost")
// or: sovereign.Dial(addr, tlsCfg)  // bring your own *tls.Config (Min==Max==1.3 forced)

dotHex, err := cli.InsertLocal(key, val)   // POST /v1/insert -> InsertLocalEvents
got, err     := cli.Get(key)               // GET  /v1/get    -> GetResult
root, err    := cli.MerkleRoot()           // GET  /v1/merkle
status, err  := cli.Status()               // GET  /livecheck
metrics, err := cli.Metrics()              // GET  /metrics   (sovereign_* series)
cli.Close()
```

`Dial` forces `Min==Max==TLS 1.3` — a <1.3 negotiation is a hard failure. The
caller's `tls.Config` carries a client cert signed by the mesh CA; a no-cert
dial fails the server's `RequireAndVerifyClientCert` gate (the mTLS tooth).

## 6. The honest read-path boundary (Ruling 3 — read this before you ship)

The engine stores ONLY the `PayloadDigest` on a joined `CRDTEntry`; the original
value is discarded after the integrity cross-check (Ruling 3 — the payload would
10x the on-disk footprint for no CRDT-merge benefit). The value survives ONLY on
the originator node's payload cache (the node that `InsertLocalEvents`-ed it).

`Get` returns a `GetResult` that makes the boundary VISIBLE:

- **On the originator node**, `Payload` is the cached string (a cache hit).
- **On a peer node**, `Payload` is `""` and `PayloadDigest` carries the digest
  the value was hashed to before Ruling-3 discard.

A `Get` that reports the digest hex as if it were the value is a FABRICATION;
the SDK reports both paths honestly. If you need the VALUE on a peer, re-publish
it or hold it out-of-band — the SDK does not paper over the boundary.

## 7. Eventual convergence (not linearizability)

`InsertLocal` returns at **local-apply**: the insert is durable on the node you
dialed, but peer convergence is **eventual** — the next gossip sweep ships the
delta. A client that inserts then immediately reads from a DIFFERENT node may see
stale state until the sweep lands. The SDK does NOT offer a read-your-writes
guarantee across nodes; the doc says so. For high-rate ingest (>1K ops/sec),
ride the Day-5 batched binary data plane (`--bind`), not the JSON control port —
the control port is a low-rate manageability surface, not a throughput path.

## 8. Compile + verify

```bash
go build ./...                     # whole repo builds (no regression)
go test -race -count=1 ./sdk/sovereign/   # the SDK gate tests (race-clean)
wc -l examples/sdk/main.go         # < 50 (the developer-can-use-this gate)
```

See `docs/architecture/adr/0011_sdk_control_port_track06.md` for the full
decision record (the control/data-plane separation, the read-path honesty tooth,
the honest weaknesses, and the self-adversarial critique).
