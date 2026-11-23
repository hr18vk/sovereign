# Sovereign Engine SDK — Quickstart

A developer who has never read the engine internals can connect to a running
mesh over mutual TLS and perform a state operation in under 50 lines of Go.
This quickstart is the path from zero to a working insert/get loop.

Run these commands from the repository root. Leave the node running in one
terminal and use another terminal for the SDK commands.

## 1. What you need

- Linux with gcc and the jemalloc development files; see the
  [installation commands](../README.md#try-it).
- Go 1.26+ (the engine targets `go 1.26.1`).
- A client certificate signed by the same CA the node trusts. The development
  helper below creates the CA, node certificate, and client certificate.

## 2. Mint a development CA and certificates

The helper in `pkg/crypto` (`certgen.go`) creates a development CA, not a
production PKI. Save this program as `/tmp/mint_dev_certs.go`:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

func main() {
	ca, _ := crypto.NewMeshCA()
	caPath, _ := ca.WriteCAPEM(".")

	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	ident, _ := mesh.NewNodeIdentity(seed)
	nodeHex := hex.EncodeToString(ident.NodeID[:])
	leaf, _ := ca.IssueLeaf(nodeHex)
	certPath, keyPath, _ := leaf.WritePEM("node")

	cleaf, _ := ca.IssueLeaf("sdk-client")
	ccert, ckey, _ := cleaf.WritePEM("client")

	fmt.Println("identity seed:", hex.EncodeToString(seed))
	fmt.Println("node ID:", nodeHex)
	fmt.Println("CA:", caPath)
	fmt.Println("node cert/key:", certPath, keyPath)
	fmt.Println("client cert/key:", ccert, ckey)
}
```

Run it from the repository root:

```bash
go run /tmp/mint_dev_certs.go
```

The program writes `ca.pem`, `node/cert.pem`, `node/key.pem`,
`client/cert.pem`, and `client/key.pem`. Keep the printed identity seed and
node ID for the next command. The seed determines the identity that signs CRDT
deltas; it is separate from the TLS private key. The node certificate includes
both the node ID and `localhost` in its DNS names, which lets the SDK verify it
with server name `localhost`.

## 3. Start a node with the control port

Substitute the identity seed and node ID printed by the helper:

```bash
go build -o sovereign-node ./cmd/sovereign-node

./sovereign-node \
  --control-addr 127.0.0.1:7432 \
  --bind          127.0.0.1:7430 \
  --metrics-addr  127.0.0.1:7431 \
  --tls-cert node/cert.pem --tls-key node/key.pem --tls-ca ca.pem \
  --identity-seed <identity-seed-printed-by-the-helper> \
  --node-id <node-ID-printed-by-the-helper>
```

`--identity-seed` must derive `--node-id`; startup rejects a mismatch. The
control port is a separate mTLS listener from the peer gossip port. They use
the same CA trust root. The operations listener on `--metrics-addr` is plain
HTTP and serves `/livecheck` and `/metrics` without client authentication.
These example addresses keep all three listeners on loopback.

`--control-addr` is empty by default, which disables the client API without
affecting peer gossip.

## 4. The 44-line example

`examples/sdk/main.go` imports only the `sovereign` SDK and the Go standard
library. It does not import `internal/` or `pkg/` packages:

```bash
go run ./examples/sdk \
  -addr 127.0.0.1:7432 \
  -cert client/cert.pem -key client/key.pem -ca ca.pem
```

The example dials the control port, inserts 100 key/value pairs, reads the
Merkle root, and reads `key-0` back from the originator. Output has this form;
the Merkle root varies by run:

```text
inserted 100 keys; merkle=<hex>; key-0 payload="value-0" digest=<hex>
```

`sovereign.DialWithCerts` loads the certificate and CA files, so the example
contains only flag handling, the dial, and the demo call.

## 5. The SDK surface

```go
cli, err := sovereign.DialWithCerts(addr, certPath, keyPath, caPath, "localhost")
// Or supply a config: sovereign.Dial(addr, tlsCfg).

dotHex, err := cli.InsertLocal(key, val) // POST /v1/insert
got, err := cli.Get(key)                 // GET /v1/get
root, err := cli.MerkleRoot()            // GET /v1/merkle
status, err := cli.Status()              // GET /livecheck
metrics, err := cli.Metrics()            // GET /metrics (sovereign_* series)
cli.Close()
```

`Dial` clones the supplied `tls.Config` and sets both its minimum and maximum
versions to TLS 1.3. The caller supplies a client certificate signed by the
mesh CA. The server requires and verifies that certificate during the
handshake.

## 6. The read-path payload boundary

A joined `CRDTEntry` stores only `PayloadDigest`; see the payload-boundary
decision in [ADR-0045](architecture/adr/0045_mesh_transport_invariants.md). The
receive path discards the plaintext after verifying it against that digest.
Retaining every payload would grow the on-disk footprint roughly 10x without
improving CRDT merges.

The originator's gossiper keeps the plaintext in an in-memory cache. `Get`
returns a `GetResult` that distinguishes a cache hit from a digest-only read:

- On an originator cache hit, `Payload` contains the cached string.
- On a peer that received the entry through gossip, `Payload` is `""` and
  `PayloadDigest` contains the verified digest.

An empty `Payload` does not mean the key is absent; check `Present`. The cache
is not restored from the WAL, so an originator can also return an empty payload
after a restart. The SDK never substitutes the digest for the value. An
application that needs plaintext on another node must republish it there or
store it separately.

## 7. Local apply, durability, and convergence

`InsertLocal` returns after the local apply. If `--wal-path` is configured, the
node appends and fsyncs the mutation before returning success. The command
above leaves `--wal-path` empty, so its state is in memory and a successful
insert is not disk-durable.

Peer convergence is asynchronous. A client that inserts and immediately reads
from a different node can see stale or missing state until a gossip sweep
delivers the delta. The SDK does not provide cross-node read-your-writes or
linearizable reads.

The JSON control port is for low-rate management operations, up to roughly
1K ops/sec. High-rate replication uses the batched binary protocol on `--bind`.

## 8. Compile and verify

```bash
go build ./...
go test -race -count=1 ./sdk/sovereign/
wc -l examples/sdk/main.go
```

[ADR-0011](architecture/adr/0011_sdk_control_port.md) records the control-port
and read-path decisions.
