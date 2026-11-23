# ADR-0068: Gateway identity verification

- **Status:** Accepted; amended by [ADR-0069](0069_trust_quintet.md),
  [ADR-0070](0070_receive_path_admission_and_attribution.md), and
  [ADR-0072](0072_ebr_hoist_mesh_dial_and_digest_gating.md).
- **Date:** 2026-10-11

## Context

The receive path rejected frames whose origin could not be verified against the
identity Directory, but the send path addressed peers by a TLS leaf CommonName
and accepted self-stamped digest identities. The development CA copies the node
ID into that CommonName without an issuance policy, so neither field proves
possession of the corresponding node signing key. A caller could therefore
receive state under an identity that ingress verification would reject.

## Decision

### Prove key possession on each connection

Add a mutual connect-time challenge bound to the Directory identity. The `SGWC`
family uses magic `0x53475743`, a fixed 53-byte `CHALLENGE` with role `0x01`,
and a fixed 133-byte `RESPONSE` with role `0x02`. The responder signs the
97-byte message `domain || nonce || responderID || challengerID`, where the
domain is `sovereign-mesh-keyed-challenge-v1`. The magic is distinct from the
`SBAT`, `SDST`, and `SHYB` families and from relay version prefixes `0x02` and
`0x03`.

`PeerSet.Dial` arms and sends its challenge before starting `readLoop`.
`RegisterInbound` arms the connection before publishing it in the peer maps,
then sends on the accept goroutine before that goroutine resumes reading. Each
side generates a fresh nonce. `HandleConnChallengeFrame` rejects a missing or
mismatched challenge, responder, or nonce before calling
`identity.VerifyCRDTFrame` with the key returned by `Directory.Lookup`.
Only successful verification sets that connection's `remoteVerified` bit;
Directory membership alone is not verification.

A connection declined because a live edge already exists still answers
challenges statelessly through `writeToPC`. The responder reveals only its own
signature over the challenger's nonce and does not initiate a challenge on that
connection. [ADR-0069](0069_trust_quintet.md) bounds this signing work, and
[ADR-0070](0070_receive_path_admission_and_attribution.md) makes its declined
reservations expire safely.

### Apply verification at every digest and sweep seam

The gateway is on by default and has no disable option:

- The sweep checks verification before root announcements, stratified requests,
  and delta publication. Checking only at the final ship call would leave the
  earlier frames unguarded.
- `Gossiper.DeliverDigest` requires a nonzero connection identity, a verified
  connection, and an exact match between that identity and the frame's claimed
  sender. The same gate covers root recording, digest-wait routing, and request
  answers.
- `respondToDigest` checks again immediately before publication because the
  registered connection can change while a response is pending.
- The dial `readLoop` and accepted-connection `DigestConnVerified` check the
  receiving connection's own bit. A newer `Dial` cannot lend its verified state
  to an older, unverified connection through the ID-keyed peer map.
- `PeerSet.Publish` remains a routing operation rather than an authorization
  gate. An unprovisioned identity can retain a route and is counted and logged,
  but receives no data-plane egress.

The classical challenge protects hybrid traffic only when `--hybrid-verify` is
enabled. `Receiver.HandleHybridFrame` rejects hybrid frames before decoding
when that option is off.

Initially, a declined connection had no armed challenge of its own and could
not pass the digest gate, so simultaneous mutual dialing could suppress digest
exchange while signed-delta oversend still converged. ADR-0072 adds
`ArmDeclinedInbound` and `HandleDeclinedChallengeFrame` for a declined
Directory-provisioned peer, and restricts digest-channel deposits to response
roles.

## Consequences

Peers that do not complete the handshake, including older binaries, receive no
mesh state. Verification is part of connection establishment rather than an
optional hardening mode.

The final `respondToDigest` check and `Publish` are separate operations. A
connection replacement between them remains a small race window; moving the
gate into `Publish` would change its routing contract. This residual does not
permit an unverified connection to pass the earlier sweep, receive, or digest
checks.

## Evidence

These are loopback TLS regression tests with separately counted failure modes,
not multi-region performance measurements.

- `TestGatewayHandshakeWrongKey`, `TestGatewayHandshakeReplay`, and
  `TestGatewayHandshakeNoEntry` in `pkg/mesh/gateway_fault_test.go` cover a bad
  signature, a reused nonce, and a missing Directory entry. Separate
  `challengeSigFail`, `challengeReplay`, and `challengeNoEntry` counters keep
  those outcomes distinguishable; `challengeVerified` records success.
- `TestGatewayMutualGreen` proves the positive mutual-handshake path.
- `TestGatewaySweepExfilBlocked`, `TestGatewayDigestExfilBlocked`, and
  `TestGatewayRootAnnouncePoisonBlocked` in `pkg/mesh/gateway_guards_test.go`
  cover the sweep, digest, and root-announcement seams.
- With `SOVEREIGN_TEST_FAULT_GATEWAY` enabled,
  `TestGatewayNegativeControlEgressGateOff`,
  `TestGatewayNegativeControlDigestChannelGateOff`, and
  `TestGatewayNegativeControlChallengeVerifyOff` restore each removed hole and
  require the corresponding test to fail closed when the control is absent.
- `digestSeamDrops` observes per-connection read-seam rejection;
  `digestUnverifiedDrops` and `digestIdentityDrops` distinguish verification
  failure from a claimed-sender mismatch.
