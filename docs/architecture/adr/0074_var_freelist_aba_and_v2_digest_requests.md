# ADR-0074: Variable-size free-list ABA protection and v2 digest requests

- **Status:** Accepted
- **Date:** 2026-11-06

## Context

The variable-size arena free list stored an untagged head offset and kept the
next pointer in the same header word that allocation overwrote with a size
class. Direct `ReleaseLocal` calls and EBR reclamation could therefore race with
an allocation in two ways: an ABA sequence could allocate one block twice, or a
class value could be consumed as the next head offset. IBLT structs and
one-entry CRDT arrays can share a size class, making the second failure visible
across otherwise unrelated engine paths.

The v2 request leg also carried a complete local IBLT even though the responder
read only its scheme magic and bucket count. At 21,845 buckets this produced a
digest frame of 436,959 bytes, or 436,963 bytes with its length prefix, for
eight bytes of request information. Besides the avoidable cold-socket traffic, one
timeout deferral was enough to evict a gateway, and only the requester announced
its root. The responder's unchanged root could therefore trigger another
unnecessary exchange.

These are the remaining hazards from
[ADR-0073](0073_hierarchical_gateway_topology_and_boot_dial.md), not separate
protocol features.

## Decision

Represent each variable-size free-list head as a tagged Treiber-stack pointer.
The upper 32 bits hold a monotonically increasing generation and the lower
32 bits hold the block offset in eight-byte words. Every successful push or pop
changes the generation.

Pack the block header as `(nextWordOffset << 8) | classIdx` and access it with
`atomic.LoadUint64` and `atomic.StoreUint64`. A pop or bump allocation stores
only the class, clearing the next offset. Both direct returns and EBR-driven
reclamation use this representation.

Replace the v2 request body with the eight-byte header built by
`buildV2DigestRequestBody`: little-endian `IBLTWireMagicV2` followed by the
clamped bucket count. `digestRequestBuckets` already reads exactly this prefix.
The resulting digest frame is 49 bytes, or 53 bytes with the length prefix; the
requester builds its local IBLT when the response arrives. The response still
contains the requested table.

When gateway mode and stratified anti-entropy are enabled, `respondToDigest`
also sends a length-prefixed root announcement built from the responder's
current Merkle root. The announcement uses the same authenticated digest
receive path as other frames.

Require two consecutive timeout deferrals within the gateway health window
before evicting a gateway. A publish deferral still evicts after one strike,
and a disconnected or unverified gateway remains immediately ineligible.

Finally, `validateConfig` rejects `--iblt-v2-min-buckets` values above 8,192
unless `--arena-mib` is at least 256. `run` calls this single validation entry
point before applying the configuration.

## Consequences

Concurrent direct and deferred returns no longer rely on EBR alone to prevent
free-list ABA or torn next pointers. The wire change removes request-side bucket
serialization and reduces the maximum-sized request frame by 8,244.6 times; it
does not reduce the response table needed for reconciliation.

A single transient timeout no longer replaces a gateway, while publish and
identity failures retain their immediate effects. Responder root announcements
let both directions observe convergence without a separate request solely to
learn the responder's root.

The arena guard affects only configurations that opt into a bucket floor above
8,192. The default bucket floor and the default 64 MiB arena remain accepted.

## Evidence

- `TestVarFreelist_ABARaceDoesNotCorruptBlocks` forces interleavings around the
  free-list head and block header, and checks that direct returns cannot
  duplicate or misalign allocations.
- `TestV2RequestHeaderOnlyWireFrame` checks the request body and framed length.
- `TestResponderRootAnnounceQuenchesRedundantSweep` covers the responder root
  announcement.
- `TestTwoStrikeGatewayTimeoutEviction` separates transient timeout deferrals
  from repeated failure and publish eviction.
- `TestValidateConfig_ArenaMiBGuard` covers acceptance and rejection at the
  bucket-floor and arena-size boundaries.
- `TestMeshDigestReleaseLocalRateIndependentArena` continues to cover the
  goroutine-local digest lifecycle introduced in ADR-0073.

These tests check wire structure, configuration, and concurrent behavior. Fleet
convergence timings are outside the evidence stated in this record.
