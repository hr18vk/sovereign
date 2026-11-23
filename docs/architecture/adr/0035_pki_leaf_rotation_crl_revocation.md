# ADR-0035: Rotate TLS leaves and enforce CRL revocation

**Status:** Accepted  
**Date:** 2026-08-11

## Context

The transport already required TLS 1.3 mutual authentication and could reload its leaf on SIGHUP. It did not consult a certificate revocation list, reload the CA pool, or trigger leaf rotation automatically. A revoked but unexpired certificate therefore remained valid until an operator replaced the trust configuration or the leaf expired.

Normal Go TLS chain validation already rejects expired certificates before `VerifyPeerCertificate` runs. The new work is revocation of otherwise valid leaves and live replacement of trust material, not a second expiry check.

## Decision

Add serial-based CRL checks and independent leaf, CA, and CRL reloads to `TLSConnections`.

- `verifyPeerCertificate` parses the peer leaf after standard chain validation, formats its serial in base 10, and rejects a serial present in `revokedSerials` with `ErrCertRevoked`. It invokes the configured reporter before returning the error. An empty set leaves revocation checks disabled.
- `SetCRLPath`, `LoadCRL`, and `ReloadCRL` read a PEM X.509 v2 CRL with `x509.ParseRevocationList` and replace the serial map. `ErrNoCRLPath` reports an unset path. Read and parse failures preserve the previous set.
- `ReloadCA` rebuilds the CA pool without replacing it on failure. On the server, `GetConfigForClient` captures the current pool for each subsequent handshake. `ClientConfig` captures a pool when called, so a dialing caller constructs a new configuration after a CA reload.
- SIGHUP attempts leaf, CA, and configured CRL reloads independently, in that order. A failure on one does not prevent the others or discard the last valid material.
- `StartRotationManager` polls the live leaf's `NotAfter`. When the remaining validity is at most the configured pre-expiry lifetime, it calls a `RotationMinter`; the minter writes and reloads the replacement, after which `CertRotationTriggered` increments. A failed mint leaves the current leaf in service for a later attempt.
- `MeshCA` gains leaf revocation, CRL issuance and writing, and caller-selected leaf lifetimes. `CertRevokedRejected` and `CertRotationTriggered` raised the counter registry from 19 to 21 entries when introduced.

The command exposes `--crl-path`, `--cert-rotation-enable`, `--cert-rotation-poll`, and `--cert-rotation-lifetime`. Revocation and automatic rotation are disabled by default. The current defaults are a one-hour poll and a thirty-day pre-expiry window. The window controls when renewal starts; it is not the new leaf's lifetime, which is one year in `MeshCA.IssueLeaf`.

The built-in minter is available only with `--selftest`, where the process owns a CA. A PEM-only deployment has no in-process issuer, so enabling the command's rotation manager there returns an error. External issuer integration must supply a `transport.RotationMinter` directly.

## Consequences

Both client and server handshakes reject a revoked serial while ordinary expiry and chain checks remain in the Go standard library. Revoking one leaf does not revoke siblings issued by the same CA. Later handshakes can observe reloaded material without restarting the listener.

`LoadCRL` does not verify the CRL's signature. Control of the configured file is therefore part of the trust model, as with the CA file. Deployments must protect that path rather than treat a parsed CRL as an independently authenticated revocation channel.

Automatic rotation is implemented and tested, but the command's in-process issuer is limited to self-test use. Full CRLs are reparsed on reload; delta CRLs, partitioned CRLs, OCSP stapling, and large-list lookup optimizations are not implemented. The loopback tests do not establish the handshake cost of a 10k-entry CRL or a 100-node deployment.

## Evidence

`pkg/transport/pki_rotation_crl_test.go` covers rejection and telemetry for a revoked leaf, acceptance of an unrevoked sibling, standard-library expiry rejection, CA and CRL hot reloads, disabled-revocation compatibility, and both new counters. The existing `TestTLSCertRotation_SIGHUP` remains the leaf-reload regression test.

`TestPKI_RotationTrigger` compresses the timing conditions into a 2 s leaf lifetime, a 1 s pre-expiry window, and a 100 ms poll. Its minter writes and reloads a replacement and its reporter observes the trigger. These are test parameters, not production timing recommendations.

At acceptance, the runtime check passed all 7 checks against the real mTLS node and confirmed that both PKI counter series appeared in `/metrics`; presence did not imply that either counter had incremented with the features disabled. The focused loopback tests included 9 new cases and 3 existing TLS cases. Fieldalignment findings for `TLSConnections` fell from 88 bytes to 56 bytes, and the zero-allocation hot-path test remained green. Repo-wide vet retained the same 35 pre-existing `unsafe.Pointer` warnings. These measurements belong to the acceptance environment; no fleet-scale revocation-latency measurement is claimed.
