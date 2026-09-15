# ADR-0040: OOB Peer-Directory Pubkey Provisioning

- **Status:** ACCEPTED
- **Date:** 2026-08-13
- **Scope:** the identity/provisioning half of the region-aware mesh work —
  the complement to ADR-0039's region-aware data-plane.
- **Core files:** the merge-law/wire-schema files are untouched — the
  provisioning layer is an identity/routing addition, not a CRDT/data-layer
  change.
- **Telemetry:** no new counter, no `registry.go` change. The existing
  `InterRegionEnvelopesShipped` counter firing A=1 B=1 in the 2-node binary
  mesh is its first runtime disclosure.

## Context

ADR-0039 shipped the region-aware **selection** logic — `topology.Select(ctx)`
picks intra-region full-mesh + inter-region fan-out-N peers. Its honest
residual was the **N=2 no-op**: the cmd dial loop keyed the peerConn under a
placeholder zero peerID (the long-standing honest gap — "the peer's real
nodeID is unknown until the peer presents its leaf"), while the topology
registry keyed the region tag under `peerIDForAddr(addr)` (a SHA-256
surrogate). The zero peerID never matched the surrogate → `Select` returned
the surrogate → `Publish(surrogate)` found no live peer (the dial keyed zero)
→ silent fallback → the mesh **never converged** at N=2 in the binary.
ADR-0039 shipped the selection logic; this change ships the **provisioning
logic** that makes a real 2-node binary mesh converge.

The zero-peerID hazard has two halves:

1. **the peerID half** — the dial keys the peerConn under a wrong/zero
   nodeID, so `Publish(realNodeID)` misses the live-peer map (routing).
2. **the retry half** — the dial loop is one-shot; a peer not yet listening
   at boot (the inevitable 2-node startup race) is a permanent miss, with no
   reconnect.

This change retires both halves.

## Decision

Ship two seams plus the retry watcher.

### Seam A — `--peer-dir` deterministic provisioning (the load-bearing arm)

A new `cmd/sovereign-node/provisioning.go` with a line-oriented failsafe
parser mapping `addr → {nodeID, ed25519_pubkey, optional mldsa65_pubkey,
optional region}`. `applyProvisioning` calls
`gossiper.RegisterPeer(realNodeID, pub)` (the CRDT verification pubkey into
the Directory) + `dir.RegisterPQ` (the ML-DSA-65 pubkey, when present — the
hybrid arm) + `topo.SetRegion(realNodeID, region)` (the topology re-key under
the real nodeID — the retirement of the surrogate). The dial loop's new
peerID branch: a provisioned peer dials under the real nodeID → the topology
selector hits → `Publish(realNodeID)` finds the live peer → the inter-region
arm fires → the 2-node mesh converges.

The parser is failsafe: a malformed entry (bad hex / wrong length / duplicate
addr / out-of-range region) is rejected with a named-line error, never
coerced to zero. The ML-DSA-65 pubkey round-trips via
`mldsa.NewPublicKey(mldsa.MLDSA65(), enc)` from a 1952-byte serialized config
blob — the first site that reconstructs a directory post-quantum pubkey from
a serialized config.

### Seam B — `--peer-auto-reconcile` runtime TLS-leaf reconcile (the routing complement)

`pkg/mesh/peer.go`'s `autoReconcile` field + `reconcilePeerID`: read the
peer's TLS leaf `CommonName` (the certgen mirror — `IssueLeaf` sets
`CommonName: hex(nodeID)`) → `hex.DecodeString` the 32-char CN → `[16]byte` →
re-key the peerConn under the real nodeID. Routing-only (cert key ≠ CRDT
key): the reconcile changes which `ps.peers` entry `Publish` writes to; it
never touches the verification pubkey (the Directory's OOB-provisioned key is
the verification anchor). A provisioned peer (Seam A already dialed under the
real nodeID) skips the reconcile — the peer is keyed correctly and the leaf
CN is a redundant signal.

### The retry watcher — `ReconnectLoop` wired

`pkg/mesh/peer.go:528` `ReconnectLoop` (docstring: "the production binary
wires it") was not wired in the binary's dial loop — the one-shot residual of
the original dial path. This change wires it: after each `Dial` (success or
failure), spawn `go peerSet.ReconnectLoop(meshCtx, pa, host, dialPeerID, 1s,
10s)` — bounded exponential backoff until the peer connects, then watch +
re-dial on drop. This retires the retry half: a peer not yet listening at
boot re-dials until it is up, so the 2-node startup race is absorbed.
Idempotent and safe in all three modes (provisioned / reconcile /
un-provisioned-no-reconcile = byte-identical to the previous behavior).

### The files

- **`cmd/sovereign-node/provisioning.go`** (new): the `peerDirConfig` struct
  + `parsePeerDir` (the failsafe line parser) + `parsePeerDirLine` (per-field
  decode with length checks) + `applyProvisioning`
  (RegisterPeer/RegisterPQ/SetRegion under the real nodeID) +
  `ErrPeerDirEmpty` (the opt-in no-op).
- **`pkg/mesh/peer.go`** (modified): the `autoReconcile` field (tail-placed —
  absorbs into existing padding, fieldalignment net-neutral) +
  `SetAutoReconcile` + `reconcilePeerID` (the leaf-CN hex-decode) + the
  `Dial` reconcile branch + the `ReconnectLoop` primitive (pre-existing, now
  wired from main.go).
- **`cmd/sovereign-node/main.go`** (modified): the `--peer-dir` +
  `--peer-auto-reconcile` flags + `applyProvisioning` wiring before the dial
  loop + the dial-peerID branch (provisioned → real nodeID; else zero =
  byte-identical to the previous behavior) + the `go
  peerSet.ReconnectLoop(...)` watcher wiring.
- **`pkg/mesh/oob_provision_test.go`** (new): the mesh-side guards.
- **`cmd/sovereign-node/provisioning_test.go`** (new): the cmd-side guards
  (plus the malformed-entry RED cases).

### The guards (all green)

1. **`TestOOBConfigParse`** — `parsePeerDir` round-trips a 3-peer config (1
   ML-DSA + 2 classical + 1 region); the ML-DSA-65 `Bytes()`/`NewPublicKey`
   round-trip is byte-identical. Four malformed-entry RED cases (short
   nodeID / bad-hex pubkey / dup addr / out-of-range region) are rejected
   with named-line errors, not coerced to zero.
2. **`TestOOBProvisionRetiresSurrogate`** (the load-bearing headline) — the
   provisioned path (region keyed under the real nodeID) makes
   `topo.IsInterRegion` true + `Select` returns the real nodeID →
   `Publish(real)` hits → the inter-region arm fires → convergence. RED: the
   previous surrogate keying → `Select` returns the surrogate →
   `Publish(real)` misses → the no-op reproduces.
3. **`TestOOBReconcile`** — `reconcilePeerID` hex-decodes the leaf CN → the
   real nodeID (the production-cert-minter mirror; routing-only). RED: a
   non-hex CN is rejected (ok=false) — the hex-decode guard is load-bearing
   (a naive `copy(id[:], cn)` would truncate 32-char hex to 16 garbage
   bytes).
4. **`TestOOBOffByteIdentical`** — `--peer-dir ""` + `--peer-auto-reconcile
   false` is byte-identical to the previous behavior (an un-provisioned peer
   routes intra = `IsInterRegion=false` = byte-identical full-mesh).
5. **`TestOOBRace`** — the reconcile + the `autoReconcile` field are race-free
   under concurrent `Dial` + `reconcilePeerID` (green under `-race`
   GOMAXPROCS=4).
6. **`TestOOBApply` / `TestOOBEmptyNoOp` / `TestOOBMissingPathFails`** —
   `applyProvisioning` resolves all 3 pubkeys (hybrid via `LookupBoth`); an
   empty `--peer-dir` is a no-op (byte-identical to the previous behavior);
   a non-empty-but-missing path fails the boot — a deploy misconfiguration
   must be loud.

### The binary harness (the 2-node convergence proof, overall pass)

A 3-run harness driving two sovereign-node binaries with a mutual
`--peer-dir`, deterministic `--identity-seed` (0xAA×32 / 0xBB×32 →
reproducible nodeIDs), a shared dev CA (the 2-node gotcha — each node's dial
must trust the other's leaf; a per-node CA fails as "signed by unknown
authority"), and the `localhost:port` peer addr (the leaf's DNSNames are
`{nodeID, "localhost"}`, not `127.0.0.1` → the dial's TLS ServerName must be
`localhost` or it fails "no IP SANs"):

- **RUN 1 (Seam A)**: mutual `--peer-dir`, `--region-aware` on,
  `--self-region` 1-vs-2. Converges — insert A → query B **200**, insert B →
  query A **200**. The headline: the zero-peerID hazard is retired. The
  inter-region telemetry counter fires A=1 B=1.
- **RUN 2 (Seam A + Seam B)**: `--peer-dir` + `--peer-auto-reconcile`.
  Converges — the reconcile composes with provisioning without regression (a
  provisioned peer skips the reconcile; redundant signal).
- **RUN 3 (Seam B only — the honest negative)**: `--peer-auto-reconcile`, no
  `--peer-dir`. Does not converge (404) — the reconcile routes, but the
  receiver's `Directory.Lookup` misses (receiver.go:436) → DropVerify →
  every delta dropped. This is the premise correction below, asserted by a
  guard.

## §6 — The premise-audit correction (the load-bearing finding)

Seam B was originally framed as the "zero-config bonus — a deploy that opts
into `--peer-auto-reconcile` alone converges via the handshake." The binary
harness RUN 3 **proved this wrong**: without `--peer-dir`, the Directory has
no verification pubkey for the peer (`RegisterPeer` was never called) → the
receiver's `Directory.Lookup(originNodeID)` at `receiver.go:436` misses →
the incoming CRDT delta is `DropVerify`'d → the mesh cannot converge. Seam B
is a **routing complement** to Seam A (it re-keys the PeerSet so `Publish`
routes under the real nodeID), not a standalone convergence path. Convergence
requires Seam A's OOB-provisioned verification pubkey. The committed-source
comment sites that repeated the "converges via the handshake" framing were
corrected to disclose the DropVerify honestly, and the binary harness RUN 3
honest-negative guard asserts the non-convergence.

## Review hardening (7 confirmed defects + 3 new guards)

A multi-pass review of the change before merge surfaced a class of
root-cause defects the guards had not caught: the guards used persistent
loopback conns that never drop, so none of them exercised a natural peer
drop. A natural drop left a stale dead peerConn in `ps.byAddr`/`ps.peers`
whose `conn` pointer was non-nil → `Dial`'s `existing.conn != nil` guard
returned "already live" → `ReconnectLoop` tight-spun at 100% CPU, never
re-dialing → the mesh never healed. The seven confirmed findings and their
fixes:

1. **`Dial` liveness guard** (`peer.go:302`) — the `existing.conn != nil`
   guard mis-reads a dead peer (a closed `*tls.Conn` is non-nil) as live →
   the re-dial is skipped → permanent silent partition. **Fix:** the guard
   now checks `pc.done` (the readLoop's goroutine-signal), not the conn
   pointer — a dead peer's `done` is closed (the readLoop exited) → the
   re-dial falls through. The stale conn is captured and closed out of the
   lock (fix 4).
2. **`ReconnectLoop` addr-keyed lookup** (`peer.go:621`) — the pre-existing
   lookup was `ps.peers[peerID]` (the caller-supplied zero peerID), but
   `Dial` re-keys a reconciled peer under the real nodeID → the lookup
   missed → the wait skipped → `Dial`'s old guard returned "already live"
   for the live reconciled peer → a tight CPU spin. **Fix:** look up by addr
   (the stable identity the dial loop and the reconnect watcher share), not
   by peerID.
3. **`readLoop` never closes the conn** (`peer.go:458`) — only `defer
   close(pc.done)`; the conn was closed only by `ClosePeer` (never called on
   a natural drop) or the `Dial` dead-branch (never fires during a
   `meshCtx`-canceled shutdown). A drop during shutdown leaked the conn + fd
   for the process lifetime. **Fix:** `defer pc.conn.Close()` (LIFO-ordered
   so `close(pc.done)` runs first — the liveness signal stays the gate, not
   a conn-state sniff).
4. **`Dial` dead-branch closes under the write-lock** (`peer.go:310`) —
   `tls.Conn.Close()` sends a close-notify alert via a blocking Write; under
   `ps.mu` it stalls every concurrent `Publish`/`Peers()` (no
   `SetWriteDeadline` exists in `pkg/transport`). **Fix:** capture the stale
   conn under the lock, release the lock, then close it.
5. **`ReconnectLoop` no ctx-recheck before Dial** (`peer.go:603`) — a woken
   ReconnectLoop (the runtime picks `pc.done` at the instant `meshCancel`
   fires) falls straight to `ps.Dial` with a canceled ctx; `tls.Dial` is not
   ctx-aware → it completes a real dial → installs a conn that is never
   reclaimed. **Fix:** re-check `ctx.Err()` after the `pc.done` wait and
   before the dial.
6. **`ReconnectLoop` `time.After` timer leak** (`peer.go:634`) —
   `time.After` returns no `Stop()` handle → a timer per in-backoff loop
   leaks on shutdown. **Fix:** `time.NewTimer` + `Stop()` (draining the
   channel if Stop reports the timer already fired).
7. **Surrogate region-tag pollution** (`main.go:1035`) — the previous
   `@region` loop keys `peerIDForAddr(addr)` surrogates; `applyProvisioning`
   adds real-nodeID keys but never deletes the surrogates → `Select`
   iterates both → the dead surrogate consumes an inter-region fan-out slot,
   evicting a real cross-region peer. **Fix:** `applySurrogateRegions`
   (extracted helper) skips the surrogate for a `--peer-dir`-provisioned
   addr — its region comes from `applyProvisioning`'s
   `SetRegion(realNodeID, region)` instead.

Plus two consistency warnings (the failsafe parser cannot catch cross-file
mismatches — each file is well-formed on its own):

- a `--peers` addr not in `--peer-dir` → silent zero-peerID fallback (a
  warning makes it observable);
- a `--peer-dir` addr not in `--peers` → registered but never dialed (a
  silent one-way partition — a warning makes it observable).

And the nodeID-dedup: `parsePeerDir` deduped on addr only → two lines with
the same nodeID but different addrs both passed → `applyProvisioning`'s
second `RegisterPeer`/`RegisterPQ` silently overwrote the first's Directory
binding → the first peer's deltas dropped as forged. **Fix:** `parsePeerDir`
now dedups on nodeID too — a duplicate-nodeID deploy error is rejected with
a named-line error, not silently shadowed.

### The 3 new guards (runtime proofs that the fixes compose)

- **`TestOOBReconnectHeals`** (`pkg/mesh/oob_provision_test.go`) — the runtime
  proof. Builds a 2-node loopback TLS mesh, dials a peer (live), closes the
  server-side conn (a natural drop — readLoop io.EOF, not `ClosePeer`),
  spawns `ReconnectLoop`, and asserts the mesh heals (a fresh live peerConn
  overwrites the stale entry within 8s). RED control (in the comment): with
  the old `existing.conn != nil` guard, `Dial` would return "already live" →
  the heal would never happen → the 8s deadline would `t.Fatalf`. The guard
  passing proves the liveness fix + the readLoop conn-close + the addr-keyed
  ReconnectLoop + the ctx-recheck + the timer-stop compose.
- **`TestOOBSurrogateRetirement`** (`cmd/sovereign-node/provisioning_test.go`)
  — calls `applySurrogateRegions` (the real helper `main.go` calls, not a
  re-implementation) and asserts: a peer tagged `@region` in `--peers` and
  provisioned in `--peer-dir` has its region keyed under the real nodeID
  (not the surrogate) → `Select` returns the real nodeID, not the dead
  surrogate (no fan-out slot wasted). RED control: an empty
  `provisionedAddr` (no `--peer-dir`) keys the surrogate (the previous
  pollution reproduces) → the guard is load-bearing.
- **`TestOOBNodeIDDedup`** (`cmd/sovereign-node/provisioning_test.go`) — a
  2-line config with the same nodeID and different addrs is rejected by
  `parsePeerDir` with a "duplicate peer nodeID" error (the dedup fired, not
  a length check — the error message is asserted). RED control: a 2-line
  config with distinct nodeIDs is accepted (the dedup is nodeID-specific,
  not a false reject).

One further reported finding — that the dead-branch leaves both the real and
the zero peerID in `Peers()` forever — was refuted on closer analysis: the
leaf CN is the stable hex nodeID across mint/rotation/reboot, so
`reconcilePeerID` succeeds on every reconnect of the same peer and
`ps.peers[real]` is overwritten; the lingering-both outcome is unreachable.
That finding was dropped; the seven stand.

## Consequences

- **Positive:** the 2-node binary mesh converges (RUN 1 + RUN 2 green) — the
  zero-peerID dial hazard is retired by class elimination (the peerID half
  via the dial-peerID branch + the provisioning; the retry half via the
  `ReconnectLoop` wiring). The region-aware data-plane (ADR-0039) now has its
  provisioning complement — `--region-aware` on at N=2 is no longer a no-op.
  The inter-region telemetry counter fires A=1 B=1 in the real binary — the
  previous single-node harness could only assert its presence. The failsafe
  parser, the reconcile hex-decode guard, and the nodeID dedup are all
  bug-inject-proven.
- **Negative / honest residual:** Seam B alone does not converge (the
  DropVerify disclosure — the RUN 3 honest negative). A deploy must supply
  `--peer-dir` for the verification pubkey; `--peer-auto-reconcile` is a
  routing convenience, not a zero-config convergence path. The 32-bit-build
  length-bomb residual (the ADR-0038 known limitation) is not patched here. The
  harness runs on a 4-core development box over loopback TLS 1.3, not on
  production-scale hardware — the silicon-scale 100-node convergence and the
  multi-AZ `--peer-dir` distribution remain open.
- **Future work:** the Raft metadata-plane (the data plane here is its
  substrate); the 100-node silicon convergence gate; the multi-AZ
  `--peer-dir` distribution (the production deploy work — the harness proves
  N=2 over loopback, not the multi-AZ WAN); the 32-bit length-bomb hardening
  (the ADR-0038 future work).

## The 4-core honesty

The binary harness runs on a 4-core development box over loopback TLS 1.3,
not on production-scale hardware. The convergence is a 2-node loopback proof
(insert → converge → cross-query 200), not a silicon-scale wall-time gate.
The guards prove the correctness (the failsafe parser + the topology re-key +
the reconcile hex-decode + byte-identity-when-off), the mechanism (the
provisioning makes `Select` hit and `Publish` route), the disclosure (the
inter-region counter fires A=1 B=1), and the honest negative (Seam B alone
DropVerify's) — the silicon-scale number remains future work.
