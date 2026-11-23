# ADR-0073: Hierarchical gateway topology and boot dialing

- **Status:** Accepted; amended on 2026-11-05, with the remaining allocator and
  request-leg hazards resolved by
  [ADR-0074](0074_var_freelist_aba_and_v2_digest_requests.md)
- **Date:** 2026-11-04

## Context

Initial peer dialing ran sequentially before `SweepLoop` started, so a slow or
unreachable peer delayed all anti-entropy work. The region-aware selector also
allowed every node to sweep foreign peers directly, concentrating cross-region
connections and duplicate shipping instead of routing them through a bounded
set of gateways.

Two exchange details added avoidable work. A gateway with an empty local root
could publish that root and still build a digest despite having no entries to
send. With v2 enabled, a new peer started at the default 1,024 buckets even
when the expected difference required a larger table. For a 10,000-entry
difference, the sizing configuration uses 21,845 buckets, a 2.1845 ratio above
the `c_4 = 1.295` peeling requirement.

Mesh digests had a separate lifetime problem. Returning their arena slabs
through EBR retained them until epoch advancement, but the responder path did
not itself advance epochs. Digest memory could therefore accumulate with
inbound request traffic.

## Decision

`startMeshBootDialAndSweep` starts `SweepLoop` before initial dialing. It checks
peer-directory consistency, filters targets through `ShouldDialPeer`, orders
same-region targets first, and bounds concurrent dialing with a 32-worker pool.

Add `--gateways-per-region`, disabled at its default value of zero and valid
only with `--region-aware`. Provisioning designates the first requested entries
in each region's peer-directory file order before skipping the local node. A
deterministic node-ID ordering supplies the gateway cache when topology users
do not designate gateways explicitly.

Interior nodes reject cross-region dials and select only their intra-region
view. Within an eight-peer local view, a gateway pins up to `g-1` live sibling
gateways, fills the remaining positions with interior peers, and adds one live
foreign gateway per foreign region. Selection excludes unverified,
disconnected, or recently deferred gateways. The timeout-deferral threshold is
refined in ADR-0074.

After publishing an empty local root in gateway mode, skip digest generation
for that sweep. There is no local delta to reconcile.

Add `--iblt-v2-min-buckets`, also disabled at zero and valid only with
`--iblt-v2`. Its clamped value floors initial sizing, escalation, and decay in
`digestBucketsFor`, `ladderEscalate`, and `ladderCleanPeel`. Leaving it unset
retains the default sizing behavior.

Return request and response digests with `releaseMeshDigest` and
`(*IBLT).ReleaseLocal`. Each digest is built, marshaled, and released on one
goroutine and is never published. `MarshalIBLT` copies every field into a newly
allocated wire buffer before the arena slabs return to the local free list.

## Consequences

Boot dialing no longer gates the start of anti-entropy. Interior nodes depend
on their regional gateways for foreign exchange, so gateway designation and
peer-directory order are part of deployment configuration. Both new flags are
opt-in; their zero defaults preserve the previous topology and sizing paths.

Direct digest return bounds the lifetime of goroutine-local allocations without
waiting for unrelated epoch activity. It also makes concurrent direct free-list
pushes part of normal operation; ADR-0074 supplies the required ABA and header
atomicity and adds the arena-size guard for large bucket floors.

## Evidence

- `TestBootDial_NonBlockingSweepStart` checks that sweeping begins while boot
  dialing is blocked.
- `TestGatewayInteriorNodeSelectsIntraOnly` and
  `TestGatewayNodeSelectsPinnedSiblingsAndForeignGateways` cover the two
  selection modes. `TestGatewayDeadGatewayEvictionFailover` covers replacement
  of an unhealthy gateway.
- `TestGatewayEmptySelfRootShortCircuit` checks the empty-root path.
- `TestGatewayIBLTV2MinBucketsSingleRoundPeelAt10K` exercises the configured
  bucket floor, and `TestGatewaySelectNoHotPathAlloc` checks selection
  allocations.
- `TestProvisioning_GatewayDesignationAndOrphanGuards` covers file-order
  designation and flag dependencies.
- `TestMeshDigestReleaseLocalRateIndependentArena` distinguishes direct digest
  return from deferred EBR release and checks that reclamation does not depend
  on request-driven epoch advancement.
