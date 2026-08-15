# ADR-0040: OOB Peer-Directory Pubkey Provisioning (Track 35)

- **Status:** ACCEPTED
- **Date:** 2026-08-13 (Day 35)
- **Track:** 5.1 (the OOB provisioning arc that retires the Day-2 zero-peerID dial
  hazard — the data-plane's provisioning complement)
- **Fork count:** EIGHTEENTH clean-chain fork (the Day-34 ADR-0039 region-aware
  data-plane was the SEVENTEENTH)
- **Streak:** Day-29 `44f89527` streak PRESERVED (NO streak-breaker — the 5
  md5-FROZEN files are UNTOUCHED; the provisioning layer is an identity/routing
  addition, NOT a CRDT/data-layer change)
- **SSoT:** 24 → **STAYS 24** (M6 — the user's choice; NO 25th counter, NO
  `registry.go` change; the 24th counter `InterRegionEnvelopesShipped` firing
  A=1 B=1 in the 2-node binary mesh IS the first runtime disclosure)

## Context

Day 34 shipped the region-aware **SELECTION** logic — `topology.Select(ctx)` picks
intra-region full-mesh + inter-region fan-out-N peers. The Day-34 ADR's honest
residual was the **N=2 no-op**: the cmd dial loop keyed the peerConn under a
PLACEHOLDER zero peerID (the Day-2 honest gap — "the peer's real nodeID is
unknown until the peer presents its leaf"), while the topology registry keyed
the region tag under `peerIDForAddr(addr)` (a SHA-256 surrogate). The zero
peerID never matched the surrogate → `Select` returned the surrogate →
`Publish(surrogate)` found no live peer (the dial keyed zero) → silent fallback
→ the mesh **never converged** at N=2 in the binary. Day 34 shipped the
selection logic; Day 35 ships the **provisioning logic** that makes a REAL
2-node binary mesh converge.

The Day-2 zero-peerID hazard has TWO halves:

1. **the peerID half** — the dial keys the peerConn under a wrong/zero nodeID,
   so `Publish(realNodeID)` misses the live-peer map (routing).
2. **the retry half** — the dial loop is ONE-SHOT (the "dial loop pending Day 2"
   boot log); a peer not yet listening at boot (the inevitable 2-node startup
   race) = a PERMANENT miss (no reconnect).

Day 35 retires BOTH halves.

## Decision

Ship TWO seams + the retry watcher:

### Seam A — `--peer-dir` deterministic provisioning (the load-bearing arm)

A NEW `cmd/sovereign-node/provisioning.go` with a line-oriented FAILSAFE parser
mapping `addr → {nodeID, ed25519_pubkey, optional mldsa65_pubkey, optional
region}`. `applyProvisioning` calls `gossiper.RegisterPeer(realNodeID, pub)`
(the CRDT verification pubkey into the Directory) + `dir.RegisterPQ` (the
ML-DSA-65 pubkey, when present — the hybrid arm) + `topo.SetRegion(realNodeID,
region)` (the topology re-key under the REAL nodeID — the retirement). The dial
loop's NEW peerID branch: a provisioned peer dials under the REAL nodeID → the
topology selector HITS → `Publish(realNodeID)` finds the live peer → the
inter-region arm fires → the 2-node mesh converges.

The parser is FAILSAFE: a malformed entry (bad hex / wrong length / dup addr /
out-of-range region) is REJECTED with a named-line error, NEVER coerced to zero
(the Day-19/23/29 `fieldalignment_fix_is_destructive` + the FAILSAFE discipline).
The ML-DSA-65 pubkey round-trips via `mldsa.NewPublicKey(mldsa.MLDSA65(), enc)`
from a 1952-byte serialized config blob — the FIRST site that reconstructs a
directory PQ pubkey from a serialized config.

### Seam B — `--peer-auto-reconcile` runtime TLS-leaf reconcile (the routing complement)

`pkg/mesh/peer.go`'s `autoReconcile` field + `reconcilePeerID`: read the peer's
TLS leaf `CommonName` (the certgen mirror — `IssueLeaf` sets `CommonName:
hex(nodeID)`) → `hex.DecodeString` the 32-char CN → `[16]byte` → re-key the
peerConn under the REAL nodeID. ROUTING-only per M3 (cert key ≠ CRDT key): the
reconcile changes WHICH `ps.peers` entry `Publish` writes to; it NEVER touches
the verification pubkey (the Directory's OOB-provisioned key is the verification
anchor). A PROVISIONED peer (Seam A already dialed under the real nodeID)
SKIPS the reconcile (the peer is keyed correctly; the leaf CN is a redundant
signal).

### The retry watcher — `ReconnectLoop` wired (the carry-forward)

`pkg/mesh/peer.go:528` `ReconnectLoop` (docstring: "the production binary wires
it") was NOT wired in the binary's dial loop (the one-shot "pending Day 2"
residual). Day 35 wires it: after each `Dial` (success OR failure), spawn
`go peerSet.ReconnectLoop(meshCtx, pa, host, dialPeerID, 1s, 10s)` — bounded
exponential backoff until the peer connects, then watch + re-dial on drop. This
retires the RETRY half (a peer not yet listening at boot re-dials until up →
the 2-node startup race is absorbed). Idempotent + safe in all three modes
(provisioned / reconcile / un-provisioned-no-reconcile = byte-identical Day-34).

### The 7 files

- **`cmd/sovereign-node/provisioning.go`** (NEW): the `peerDirConfig` struct +
  `parsePeerDir` (the FAILSAFE line parser) + `parsePeerDirLine` (per-field
  decode with length checks) + `applyProvisioning` (RegisterPeer/RegisterPQ/
  SetRegion under the real nodeID) + `ErrPeerDirEmpty` (the OPT-IN no-op).
- **`pkg/mesh/peer.go`** (MODIFIED): `autoReconcile` field (tail-placed — absorbs
  into existing padding = fieldalignment NET-NEUTRAL) + `SetAutoReconcile` +
  `reconcilePeerID` (the leaf-CN hex-decode) + the `Dial` reconcile branch +
  the `ReconnectLoop` primitive (PRE-EXISTING, now WIRED from main.go).
- **`cmd/sovereign-node/main.go`** (MODIFIED): the `--peer-dir` +
  `--peer-auto-reconcile` flags + `applyProvisioning` wiring before the dial
  loop + the dial-peerID branch (provisioned → real nodeID; else zero =
  byte-identical Day-34) + the `go peerSet.ReconnectLoop(...)` watcher wiring.
- **`pkg/mesh/day35_oob_test.go`** (NEW): the mesh-side teeth (5 teeth).
- **`cmd/sovereign-node/provisioning_test.go`** (NEW): the cmd-side teeth (4
  teeth + 4 malformed-entry REDs).
- **`pkg/receive/track36_day35_scope_test.go`** (NEW): the SCOPE negative-control
  tooth (the tamper test that proves the scope tooth is load-bearing, NOT
  vacuous — the Day-33 `/ruthless-auditor` class).
- **`pkg/receive/track36_crosscheck_test.go`** (MODIFIED): the
  `track36ExemptDay35` map + the consume block (the per-track scope tooth
  exemption).

### The §III gate (8 T-OOB teeth + the binary harness, all GREEN)

1. **T-OOB-CONFIG-PARSE** — `parsePeerDir` round-trips a 3-peer config (1
   ML-DSA + 2 classical + 1 region); the ML-DSA-65 `Bytes()`/`NewPublicKey`
   round-trip is byte-identical. 4 malformed-entry REDs (short nodeID / bad-hex
   pubkey / dup addr / out-of-range region) REJECTED with named-line errors,
   NOT coerced to zero (the FAILSAFE discipline).
2. **T-OOB-PROVISION-RETIRES-SURROGATE** (the LOAD-BEARING headline) — the
   Day-35 path (region keyed under the REAL nodeID) makes `topo.IsInterRegion`
   TRUE + `Select` returns the real nodeID → `Publish(real)` HITS → the
   inter-region arm fires → convergence. RED: the Day-34 surrogate keying →
   `Select` returns the surrogate → `Publish(real)` misses → the no-op
   reproduces.
3. **T-OOB-RECONCILE** — `reconcilePeerID` hex-decodes the leaf CN → real
   nodeID (the production-cert-minter mirror; ROUTING-only per M3). RED: a
   non-hex CN REJECTED (ok=false) — the hex-decode guard is load-bearing (a
   naive `copy(id[:], cn)` would truncate 32-char hex to 16 garbage bytes).
4. **T-OOB-OFF-BYTE-IDENTICAL** — `--peer-dir ""` + `--peer-auto-reconcile
   false` = byte-identical Day-34 (an un-provisioned peer routes intra =
   `IsInterRegion=false` = byte-identical full-mesh).
5. **T-OOB-NO-FROZEN-TOUCH** (M7) — the 5 md5-FROZEN files are byte-identical
   pre-AND-post (the `44f89527` streak PRESERVED; NO streak-breaker). The tooth
   GUARDS FILE EXISTENCE via `os.Stat` (the Day-34 lesson — a wrong-path tooth
   passes vacuously when the path resolves to nothing) + bug-inject-proven.
6. **T-OOB-RACE** — the reconcile + the `autoReconcile` field are race-free
   under concurrent `Dial` + `reconcilePeerID` (GREEN under `-race`
   GOMAXPROCS=4).
7. **T-OOB-SCOPE** — the per-track scope tooth exempts the 6 in-scope Day-35
   files (positive control) + a NEW negative control: write `// x\n` to an
   out-of-scope git-tracked file (`pkg/durability/wal.go`) → assert it SURFACES
   in `git diff --name-only HEAD -- pkg/` + is NOT in any exempt map → the real
   scope tooth WOULD fire `t.Errorf` (the tooth is load-bearing, NOT vacuous —
   the Day-33 `/ruthless-auditor` class); revert via deferred `git checkout`.
8. **T-OOB-APPLY / T-OOB-EMPTY-NO-OP / T-OOB-MISSING-PATH-FAILS** —
   `applyProvisioning` resolves all 3 pubkeys (hybrid via `LookupBoth`); empty
   `--peer-dir` = no-op (byte-identical Day-34); a non-empty-but-MISSING path
   FAILS the boot (a deploy misconfiguration MUST be loud).

### The binary harness — `verify_day35.go` (the 2-node convergence proof, OVERALL PASS)

The job-dir 3-run harness (NOT committed — the verify SKILL mold, extended from
`verify_day34.go`'s single-node to TWO sovereign-node binaries with a mutual
`--peer-dir`, deterministic `--identity-seed` (0xAA×32 / 0xBB×32 → reproducible
nodeIDs), a SHARED dev CA (the 2-node gotcha — each node's dial must trust the
other's leaf; a per-node CA fails as "signed by unknown authority"), + the
`localhost:port` peer addr (the leaf's DNSNames are `{nodeID, "localhost"}`,
NOT `127.0.0.1` → the dial's TLS ServerName must be `localhost` or it fails
"no IP SANs")):

- **RUN 1 (Seam A)**: mutual `--peer-dir`, `--region-aware ON`, `--self-region`
  1-vs-2. CONVERGES — insert A → query B **200**, insert B → query A **200**.
  The headline: the Day-2 zero-peerID hazard is RETIRED. The 24th SSoT counter
  fires A=1 B=1.
- **RUN 2 (Seam A + Seam B both)**: `--peer-dir` + `--peer-auto-reconcile`.
  CONVERGES — the reconcile composes with provisioning without regression (a
  provisioned peer skips the reconcile; redundant signal).
- **RUN 3 (Seam B only — the honest-negative)**: `--peer-auto-reconcile`, NO
  `--peer-dir`. Does NOT converge (404) — the reconcile routes but the
  receiver's `Directory.Lookup` MISSES (receiver.go:436) → DropVerify → every
  delta dropped. The premise-audit correction made into a tooth.

## The premise-audit correction (the load-bearing finding)

The plan's Seam B was framed as the "zero-config bonus — a deploy that opts into
`--peer-auto-reconcile` alone converges via the handshake." The binary harness
RUN 3 **PROVED THIS WRONG**: without `--peer-dir`, the Directory has NO
verification pubkey for the peer (`RegisterPeer` was never called) → the
receiver's `Directory.Lookup(originNodeID)` at `receiver.go:436` MISSES → the
incoming CRDT delta is `DropVerify`'d → the mesh CANNOT converge. Seam B is a
**routing complement** to Seam A (it re-keys the PeerSet so `Publish` routes
under the real nodeID), NOT a standalone convergence path. Convergence
REQUIRES Seam A's OOB-provisioned verification pubkey. The 4 committed-source
comment sites that repeated the "converges via the handshake" framing were
corrected to disclose the DropVerify honestly; the binary harness RUN 3
honest-negative tooth ASSERTS the non-convergence.

## The /code-review hardening (7 review-found bugs + 3 new teeth)

A `/code-review` (5 reviewer angles + a verifier) ran over the Day-35 bytes
BEFORE the commit. The prompt's 8 teeth were GREEN but used **persistent
loopback conns that NEVER drop** — so they did NOT catch a class of root-cause
defects the reviewers unanimously flagged: a natural peer drop left a stale
DEAD peerConn in `ps.byAddr`/`ps.peers` whose `conn` pointer was non-nil →
`Dial`'s `existing.conn != nil` guard returned "already live" → `ReconnectLoop`
tight-spun at 100% CPU, never re-dialing → the mesh **never healed**. The 7
confirmed findings + the fixes:

1. **`Dial` liveness guard** (`peer.go:302`) — the `existing.conn != nil`
   guard mis-reads a DEAD peer (closed `*tls.Conn` is non-nil) as LIVE → the
   re-dial is skipped → permanent silent partition. **FIX:** the guard now
   checks `pc.done` (the readLoop's goroutine-signal), NOT the conn pointer —
   a DEAD peer's `done` is closed (the readLoop exited) → the re-dial falls
   through. The stale conn is captured + closed OUT of the lock (fix #4).
2. **`ReconnectLoop` addr-keyed lookup** (`peer.go:621`) — the PRE-EXISTING
   lookup was `ps.peers[peerID]` (the caller-supplied zero peerID), but `Dial`
   re-keys a reconciled peer under the REAL nodeID → the lookup MISSed → the
   wait skipped → `Dial`'s old guard returned "already live" for the LIVE
   reconciled peer → a tight CPU spin. **FIX:** look up by ADDR (the stable
   identity the dial loop + the reconnect watcher share), NOT by peerID.
3. **`readLoop` never closes the conn** (`peer.go:458`) — only `defer
   close(pc.done)`; the conn was closed only by `ClosePeer` (never called on a
   natural drop) or the `Dial` DEAD-branch (never fires during a
   `meshCtx`-canceled shutdown). A drop during shutdown leaked the conn + fd
   for the process lifetime. **FIX:** `defer pc.conn.Close()` (LIFO-ordered so
   `close(pc.done)` runs first — the liveness signal stays the gate, not a
   conn-state sniff).
4. **`Dial` DEAD-branch closes under the write-lock** (`peer.go:310`) —
   `tls.Conn.Close()` sends a close-notify alert via a BLOCKING Write; under
   `ps.mu` it stalls every concurrent `Publish`/`Peers()` (no
   `SetWriteDeadline` exists in `pkg/transport`). **FIX:** capture the stale
   conn under the lock, release the lock, THEN close it.
5. **`ReconnectLoop` no ctx-recheck before Dial** (`peer.go:603`) — a woken
   ReconnectLoop (the runtime picks `pc.done` at the instant `meshCancel`
   fires) falls straight to `ps.Dial` with a canceled ctx; `tls.Dial` is NOT
   ctx-aware → it completes a real dial → installs a conn that's never
   reclaimed. **FIX:** re-check `ctx.Err()` after the `pc.done` wait + before
   the dial.
6. **`ReconnectLoop` `time.After` Timer leak** (`peer.go:634`) — `time.After`
   returns no `Stop()` handle → a Timer per in-backoff loop leaks on shutdown.
   **FIX:** `time.NewTimer` + `Stop()` (+ drain the channel if Stop reports
   the timer already fired).
7. **Surrogate region-tag pollution** (`main.go:1035`) — the Day-34 `@region`
   loop keys `peerIDForAddr(addr)` surrogates; `applyProvisioning` adds
   real-nodeID keys but never deletes the surrogates → `Select` iterates BOTH
   → the dead surrogate consumes an inter-region fan-out slot, evicting a real
   cross-region peer. **FIX:** `applySurrogateRegions` (extracted helper) skips
   the surrogate for a `--peer-dir`-provisioned addr — its region comes from
   `applyProvisioning`'s `SetRegion(realNodeID, region)` instead.

Plus the two consistency WARNINGs (the FAILSAFE parser cannot catch cross-file
mismatches — each file is well-formed on its own):
- a `--peers` addr NOT in `--peer-dir` → silent zero-peerID fallback (a WARNING
  makes it observable);
- a `--peer-dir` addr NOT in `--peers` → registered but never dialed (a silent
  one-way partition — a WARNING makes it observable).

And the **nodeID-dedup** (Angle D #3 + Angle C #8): `parsePeerDir` deduped on
addr only → two lines with the SAME nodeID but different addrs both passed →
`applyProvisioning`'s second `RegisterPeer`/`RegisterPQ` silently OVERWROTE the
first's Directory binding → the first peer's deltas DROPPED as forged. **FIX:**
`parsePeerDir` now dedups on nodeID too (a duplicate-nodeID deploy error is
REJECTED with a named-line error, NOT silently shadowed).

### The 3 new teeth (the runtime proofs the fixes compose)

- **T-OOB-RECONNECT-HEALS** (`pkg/mesh/day35_oob_test.go`) — the runtime proof.
  Builds a 2-node loopback TLS mesh, dials a peer (live), CLOSES the
  server-side conn (a natural drop — readLoop io.EOF, NOT `ClosePeer`),
  spawns `ReconnectLoop`, + asserts the mesh HEALS (a FRESH live peerConn
  overwrites the stale entry within 8s). RED control (in the comment): with
  the OLD `existing.conn != nil` guard, `Dial` would return "already live" →
  the heal would never happen → the 8s deadline would `t.Fatalf`. The tooth
  PASSING proves the liveness fix + the readLoop conn-close + the addr-keyed
  ReconnectLoop + the ctx-recheck + the timer-stop compose.
- **T-OOB-SURROGATE-RETIREMENT** (`cmd/sovereign-node/provisioning_test.go`)
  — calls `applySurrogateRegions` (the REAL helper `main.go` calls, NOT a
  re-implementation) + asserts: a peer tagged `@region` in `--peers` AND
  provisioned in `--peer-dir` has its region keyed under the REAL nodeID
  (NOT the surrogate) → `Select` returns the real nodeID, NOT the dead
  surrogate (no fan-out slot wasted). RED control: an empty `provisionedAddr`
  (no `--peer-dir`) keys the surrogate (the Day-34 pollution reproduces) →
  the gate is load-bearing.
- **T-OOB-NODEID-DEDUP** (`cmd/sovereign-node/provisioning_test.go`) — a
  2-line config with the SAME nodeID + different addrs is REJECTED by
  `parsePeerDir` with a "duplicate peer nodeID" error (the dedup fired, NOT
  a length check — the error message is asserted). RED control: a 2-line
  config with DISTINCT nodeIDs is ACCEPTED (the dedup is nodeID-specific, not
  a false reject).

The `/code-review` verifier REFUTED one finding (the "DEAD-branch orphan leaves
both real AND zero in `Peers()` forever" claim) with a code-grounded argument
the synthesis independently confirmed: the leaf CN is the stable hex nodeID
across mint/rotation/reboot, so `reconcilePeerID` succeeds on every reconnect
of the same engine peer + `ps.peers[real]` is overwritten — the lingering-both
outcome is unreachable. The finding was dropped (the 7 stand).

## Consequences

- **Positive:** the 2-node binary mesh CONVERGES (RUN 1 + RUN 2 GREEN) — the
  Day-2 zero-peerID dial hazard is RETIRED by class-elimination (the peerID
  half via the dial-peerID branch + the provisioning; the retry half via the
  `ReconnectLoop` wiring). The region-aware data-plane (Day 34) now has its
  provisioning complement — `--region-aware ON` at N=2 is no longer a no-op.
  The 24th SSoT counter fires A=1 B=1 in the real binary (the M6 disclosure
  the Day-34 harness could only assert PRESENCE of, single-node). The
  FAILSAFE parser + the reconcile hex-decode guard + the scope negative-control
  are all bug-inject-proven.
- **Negative / honest residual:** Seam B alone does NOT converge (the
  DropVerify disclosure — RUN 3 honest-negative). A deploy MUST supply
  `--peer-dir` for the verification pubkey; `--peer-auto-reconcile` is a
  routing convenience, not a zero-config convergence path. The 32-bit-build
  length-bomb residual (Day-33 carry-forward) is NOT patched. The harness runs
  on the 4-core executor box over loopback TLS 1.3, NOT named silicon — the
  silicon-scale 100-node convergence + the multi-AZ `--peer-dir` distribution
  is the AWS arc.
- **Carry-forwards:** the Raft metadata-plane (Track 5.1b — the data plane is
  the substrate); the 100-node silicon convergence gate (the AWS arc); the
  multi-AZ `--peer-dir` distribution (the production deploy arc — the harness
  proves N=2 over loopback, NOT the multi-AZ WAN); the 32-bit length-bomb
  hardening (Day-33 carry-forward).

## The 4c Honesty (Law VI)

The binary harness runs on the 4-core executor box over loopback TLS 1.3, NOT
on named silicon. The convergence is a 2-node loopback proof (insert → converge
→ cross-query 200), NOT a silicon-scale wall-time gate. The teeth prove the
CORRECTNESS (the parser FAILSAFE + the topology re-key + the reconcile hex-decode
+ byte-identity-when-OFF) + the MECHANISM (the provisioning makes `Select` HIT +
`Publish` route) + the DISCLOSURE (the 24th counter fires A=1 B=1) + the
HONEST-NEGATIVE (Seam B alone DropVerify's) — the silicon-scale NUMBER is the
AWS arc.
