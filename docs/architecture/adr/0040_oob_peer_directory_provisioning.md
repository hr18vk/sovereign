# ADR-0040: OOB Peer-Directory Pubkey Provisioning

- **Status:** Accepted
- **Date:** 2026-08-13

## Context

ADR-0039 added region-aware selection: `topology.Select(ctx)` chooses an
intra-region full mesh plus inter-region fan-out peers. A two-node binary mesh
could not use that selection. The command's dial loop keyed each `peerConn`
under a placeholder zero peerID because the peer's real nodeID was unknown,
while the topology registry keyed the region under `peerIDForAddr(addr)`, a
SHA-256 address surrogate. `Select` returned the surrogate, but `Publish` could
find no connection under that identity. Region-aware routing therefore fell
back to full-mesh behavior and the two nodes did not converge.

The provisioning gap had two parts:

1. The dial keyed the connection under a zero or incorrect nodeID, so
   `Publish(realNodeID)` missed the live-peer map.
2. Boot dialing was one-shot. A peer that was not yet listening remained
   disconnected, with no reconnect attempt.

This decision supplies peer identities and verification keys out of band, adds
optional certificate-based routing reconciliation, and wires the existing
reconnect loop into the node binary. It does not change the CRDT merge or wire
schema, and it adds no telemetry counter.

## Decision

### Provision identities and keys with `--peer-dir`

`cmd/sovereign-node/provisioning.go` parses a line-oriented peer directory with
these positional fields:

```
addr nodeID ed25519_pubkey [mldsa65_pubkey|-] [region|-]
```

The address is a host and port. The nodeID is 16 bytes encoded as 32 hexadecimal
characters, and the Ed25519 key is 32 bytes. The optional ML-DSA-65 key uses its
1,952-byte public-key encoding; `-` omits it. A region is an unsigned 8-bit
value, and `-` leaves it unset. Blank lines and text following `#` are ignored.

`parsePeerDir` rejects malformed hexadecimal, incorrect key lengths, duplicate
addresses or nodeIDs, and out-of-range regions with an error naming the line and
field. An empty path returns `ErrPeerDirEmpty`, which the caller treats as
provisioning being disabled. A named file that cannot be opened fails startup.
Invalid identities are never replaced with zero values.

`applyProvisioning` registers each Ed25519 key through
`gossiper.RegisterPeer`, each optional ML-DSA-65 key through `dir.RegisterPQ`,
and each configured region through `topo.SetRegion`, all under the real nodeID.
`mldsa.NewPublicKey(mldsa.MLDSA65(), enc)` reconstructs the post-quantum public
key from its serialized encoding. The returned address-to-nodeID map makes the
dial loop use the same identity as the topology registry. `Select` can then
return an identity for which `Publish` has a live connection.

### Reconcile routing from the TLS leaf

The optional `--peer-auto-reconcile` flag enables `PeerSet.reconcilePeerID`.
`crypto.MeshCA.IssueLeaf` sets the leaf's CommonName to the hexadecimal nodeID.
After the handshake, reconciliation decodes those 32 characters into a
`[16]byte` and keys the `peerConn` under that identity. A peer already dialed
with a provisioned nodeID skips this step.

Reconciliation changes only the `ps.peers` routing entry. The TLS certificate
key is not the CRDT verification key, and reconciliation does not populate
`identity.Directory`. Without a separately provisioned verification key, the
receiver's `Directory.Lookup` fails and its frame handlers return `DropVerify`.
Certificate reconciliation is therefore a routing complement, not a standalone
convergence mechanism.

### Wire `ReconnectLoop` into boot dialing

The node binary previously left `(*PeerSet).ReconnectLoop` unused and attempted
each boot dial only once. After each `Dial`, whether it succeeds or fails, the
command now starts:

```go
go peerSet.ReconnectLoop(meshCtx, pa, host, dialPeerID, 1s, 10s)
```

The loop waits for an established peer to disconnect and retries failed or
dropped dials with exponential backoff from 1 second to a 10-second ceiling.
This absorbs the startup race in which one node begins listening after its peer
has already tried to dial. Provisioning and reconciliation remain optional; an
unprovisioned peer with reconciliation disabled retains the earlier routing
behavior.

### Correct connection lifecycle and configuration failures

The initial tests used persistent loopback connections and did not exercise a
natural peer drop. A dropped peer left a `peerConn` whose TLS pointer was still
non-nil. `Dial` treated it as live, while `ReconnectLoop` repeatedly attempted
the same suppressed re-dial and consumed 100% of a CPU without restoring the
connection. The implementation corrects that failure and six related defects:

1. **`Dial` determines liveness from `pc.done`.** A closed `*tls.Conn` remains
   non-nil, so the old `existing.conn != nil` check could prevent re-dialing a
   dead peer forever. A closed `done` channel now permits replacement. The stale
   connection is retained for closure after releasing the peer-set lock.
2. **Reconnect lookup uses the configured address.** Reconciliation can replace
   the caller's zero peerID with the leaf's real nodeID. Looking only in
   `ps.peers[peerID]` then misses the live connection, skips the wait, and
   causes a tight loop. `byAddr` provides the stable key shared by boot dialing
   and reconnection.
3. **`readLoop` closes its connection.** Previously only `ClosePeer` or a later
   `Dial` closed it, so a drop during shutdown could leak the connection and its
   descriptor. Deferred calls close `pc.done` before closing the connection,
   preserving the channel as the liveness signal.
4. **Stale connections close outside `ps.mu`.** `tls.Conn.Close` can block while
   sending close-notify. Holding the peer-set write lock across that call would
   stall concurrent `Publish` and `Peers` calls. `Dial` now captures the stale
   pointer under the lock and closes it after unlocking.
5. **Reconnect rechecks cancellation before dialing.** A peer drop and shutdown
   can wake together. Because the transport dialer does not accept a context,
   dialing after cancellation could install a connection that shutdown never
   reclaims. The loop returns instead when `ctx.Err()` is non-nil.
6. **Backoff timers are stopped.** `time.NewTimer` replaces `time.After`, with a
   stop and channel drain on cancellation so an in-backoff loop does not retain
   its timer until the delay expires.
7. **Provisioned addresses do not retain surrogate regions.** The old `@region`
   path registered both the address surrogate and the real nodeID. `Select`
   could spend an inter-region slot on the surrogate, which had no connection.
   `applySurrogateRegions` now skips addresses present in `--peer-dir`.

Two startup warnings cover mismatches that neither file can detect alone: an
address in `--peers` but absent from `--peer-dir` uses zero-peerID dialing, and
an address in `--peer-dir` but absent from `--peers` is registered but never
dialed. The parser also rejects duplicate nodeIDs at different addresses.
Without that check, the second registration would replace the first peer's
Directory binding and deltas from the first peer would fail verification.

### Subsequent changes

`applyProvisioning` now accepts pre-parsed entries and the local nodeID. A shared
directory may therefore list every node in the deployment: registration and
dialing skip the local entry. When hierarchical routing is enabled, file order
selects regional gateways as described in
[ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md).

Boot dialing now runs in `startMeshBootDialAndSweep` with up to 32 workers.
Same-region targets are queued before cross-region targets, and
`TopologyManager.ShouldDialPeer` filters targets before dialing. The reconnect
loop still starts after every dial attempt.

[ADR-0045](0045_mesh_transport_invariants.md) extends the lifecycle handling.
The read loop removes its dead entries from both peer maps, reconnect checks
liveness again after waking, and backoff sleeps use per-peer jitter. Reconnect
also recognizes a live inbound edge for the same nodeID instead of dialing a
duplicate outbound connection. The two-node mechanism described here was later
exercised in the 100-node, three-region runs recorded in
[ADR-0041](0041_100_node_silicon_convergence.md) and ADR-0045.

## Consequences

- A two-node binary mesh with a mutual peer directory converges with
  region-aware selection enabled. Provisioning supplies the verification anchor
  and a consistent routing identity; reconnect handles the startup race and
  later disconnects. Enabling certificate reconciliation alongside provisioning
  does not change the result.
- `--peer-auto-reconcile` alone is insufficient for convergence. It can repair
  the outbound routing key, but the receiver still has no verification public
  key and drops the peer's deltas with `DropVerify`. Deployments must distribute
  the peer directory, including its Ed25519 keys and any ML-DSA-65 keys required
  by their verification mode.
- Both provisioning mechanisms are opt-in. An empty `--peer-dir` and disabled
  reconciliation preserve the previous unprovisioned behavior. No telemetry
  counter or merge-law code was added; the two-node run did provide the first
  binary observation of `InterRegionEnvelopesShipped` incrementing on both
  nodes.
- The initial evidence is a functional two-node result over loopback TLS 1.3 on
  a 4-core development machine, not a multi-region latency or scale measurement.
  The Raft metadata plane and the 32-bit frame-length hardening tracked in
  ADR-0038 remain separate work.

## Evidence

### Unit and connection tests

The tests exercise the same parser, Directory, topology, and peer-set code used
by the node binary. Negative cases retain the surrogate-keyed and malformed
identity behavior that the change is intended to reject.

- **`TestOOBConfigParse`** round-trips a three-peer configuration containing
  classical and hybrid entries, with and without regions. The reconstructed
  ML-DSA-65 key has the same bytes as the original. Four malformed cases cover
  a short nodeID, non-hexadecimal public key, duplicate address, and
  out-of-range region; each must return an error.
- **`TestOOBProvisionRetiresSurrogate`** contrasts surrogate-only topology
  registration with registration under the real nodeID. Only the latter makes
  `IsInterRegion` true and lets `Select` return the identity used by `Publish`.
- **`TestOOBReconcile`** uses a real TLS leaf to check decoding of the
  32-character CommonName into a 16-byte nodeID. A CommonName that does not
  decode to exactly 16 bytes is rejected instead of being truncated into an
  invalid identity.
- **`TestOOBOffByteIdentical`** checks that an unregistered peer retains
  same-region classification and that an empty topology selects no peers, so
  the sweep continues to use its full-mesh path when region routing is not
  provisioned.
- **`TestOOBRace`** runs concurrent gossip sweeps and peer-map snapshots under
  the race detector, with the original run using `GOMAXPROCS=4`.
- **`TestOOBApply`**, **`TestOOBEmptyNoOp`**, and
  **`TestOOBMissingPathFails`** cover Directory registration of all three
  Ed25519 keys and the optional ML-DSA-65 key, real-nodeID region registration,
  the disabled empty path, and startup failure for a named missing file.
- **`TestOOBReconnectHeals`** closes the server side of a live two-node
  loopback TLS connection without calling `ClosePeer`. The client read loop
  must close `pc.done` and remove both dead map entries. `ReconnectLoop` then
  has 8 seconds to install a distinct live `peerConn`. The old non-nil-pointer
  liveness check would instead suppress re-dialing until the deadline failed.
- **`TestOOBSurrogateRetirement`** calls the command's actual
  `applySurrogateRegions` helper. With no peer directory, an `@region` suffix
  registers the address surrogate. With the address provisioned, the surrogate
  is omitted, the real nodeID receives the region, and `Select` returns that
  real identity rather than wasting a fan-out slot.
- **`TestOOBNodeIDDedup`** gives two addresses the same nodeID and requires a
  "duplicate peer nodeID" parse error. A second two-line fixture with distinct
  nodeIDs must parse, showing that the rejection is specific to identity
  duplication rather than malformed key lengths.

### Two-node binary harness

A three-run harness drove two `sovereign-node` binaries on a 4-core development
machine over loopback TLS 1.3. The nodes used deterministic 32-byte identity
seeds (`0xAA` for A and `0xBB` for B), a shared development CA, and
`localhost:port` peer addresses. The shared CA let each node trust the other's
leaf. The `localhost` server name matched the leaf's DNS names, which contained
the nodeID and `localhost` but not `127.0.0.1`.

- **Provisioning:** both nodes used mutual `--peer-dir` files,
  `--region-aware`, and self-regions 1 and 2. An insert on A was subsequently
  queried on B with HTTP **200**, and an insert on B was queried on A with HTTP
  **200**. `InterRegionEnvelopesShipped` incremented once on each node.
- **Provisioning and reconciliation:** adding `--peer-auto-reconcile` on both
  nodes preserved the same convergence result. Provisioned peers already had
  their real nodeIDs and skipped reconciliation.
- **Reconciliation alone:** both nodes used `--peer-auto-reconcile` without
  `--peer-dir`. The nodes did not converge, and the cross-node query returned
  HTTP 404. Reconciliation repaired routing, but the receiver's
  `Directory.Lookup` found no verification key and returned `DropVerify` for
  every delta.
