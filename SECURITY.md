# Security Policy

Sovereign Engine takes its security claims seriously — post-quantum key exchange (on
by default), opt-in post-quantum signatures, mTLS mesh transport, and Cedar-based
authorization are core to the design, and a real vulnerability in any of them matters. If you find one, I want to
hear about it directly and will treat it as a priority.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report privately via **GitHub Private Vulnerability Reporting** on this repository
(*Security* tab → *Report a vulnerability*). That gives us a private channel to
discuss, reproduce, and fix before any public disclosure.

Include, if you can:

- A description of the issue and the attack scenario it enables.
- The affected version/commit and the environment (OS, arch, Go version).
- A minimal reproduction or a pointer to the implicated code path.
- Whether you believe it's exploitable in a default configuration.

## What to expect

- **Acknowledgement** of your report as soon as I've read it (this is a
  solo-maintained project; allow a few days).
- **A candid assessment** of severity and whether it reproduces — I would rather
  confirm a real issue honestly than wave one off.
- **A fix and credit** (with your permission) in the release notes and the
  relevant ADR.

## Scope notes

- **In scope:** the CRDT merge/apply path, the WAL/durability path, the mesh
  transport (TLS/mTLS/PQ handshake), the signed-envelope attribution path, and the
  authorization seam.
- **Cryptographic agility:** the hybrid constructions (Ed25519 + ML-DSA-65,
  X25519 + ML-KEM) are designed so a break in one primitive does not break the
  whole. If you find a weakness in the *construction* (not just a primitive), that
  is especially valuable.
- **Out of scope:** vulnerabilities requiring you to already have root on the host,
  and issues in third-party dependencies (report those upstream — though I'm glad
  to hear about them too).

## A note on the honest boundary

The engine's own documentation is explicit about what is and is not yet built (see
the README's "Where it stands" and `docs/evidence/`). Claims about the security
posture are held to the same standard as the performance numbers: stated precisely,
with their limits named.
