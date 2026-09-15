# ADR-0003: live BPF_PROG_TYPE_SK_REUSEPORT on c8g kernel 6.18 (BPF steering half silicon-proven; epoll + NIC + performance + wiring pending)
> Status: ACCEPTED (scoped to the BPF steering half)     Date: 2026-07-25..26
> Supersedes: none     Superseded by: none     Promotes: ADR-0002 partially — only the BPF steering half; the epoll + NIC + performance + wiring half remains deferred

## 1. Context

ADR-0002 built and measured the in-process seam that the design record's
decision gates — the deterministic decision function a kernel
`BPF_PROG_TYPE_SK_REUSEPORT` program loaded via `SO_ATTACH_REUSEPORT_EBPF`
would implement — and explicitly deferred the live kernel eBPF load:

> ADR-0002 §1: "The kernel eBPF load (binding a real `SO_REUSEPORT` socket
> group, loading the program via `bpf(2)`, and verifying flow stickiness on
> `c8g` with `CAP_BPF`) is a future step."

The earlier plan permitted the in-process path first: acceptance used the
in-process `internal/chaos` VirtualNet infra, not the kernel, until real c8g
was available; the kernel path was gated on real hardware. This ADR discharges
that deferral: real c8g is now available (a Spot `c8g.8xlarge`, Graviton4
0xd4f, kernel 6.18.38, `CAP_BPF` granted via `sudo` on a box with
`unprivileged_bpf_disabled=1`).

The architecture decision is recorded in the architecture design record:

- (the design record's decision): "(a) epoll + SO\_ATTACH\_REUSEPORT\_EBPF vs
  io\_uring: PROVEN ... Implementing epoll coupled with the Linux kernel's
  SO\_ATTACH\_REUSEPORT\_EBPF custom socket steering provides the necessary
  packet fanout on Linux 6.18 without compromising scheduler stability."
- (the matrix row): "Socket ingress must utilize edge-triggered epoll
  combined with native BPF steering programs (bpf\_sk\_select\_reuseport) to
  achieve concurrent scale."
- (the SOCKHASH rationale): "... utilizing a BPF SOCKHASH map to pin
  stateful connections to specific processor cores, thereby eradicating cache
  invalidation and thread migration latency during periods of high peer
  mobility and network churn."

This ADR records the silicon promotion: the in-process analogue (ADR-0002) is
now backed by a measured kernel load on `c8g` kernel 6.18 with `CAP_BPF`. It
transcribes; it does not re-prove the decision itself (that lives in the design record).
The eBPF route key is the same plaintext Application Connection ID the
in-process selector keys on — `originNodeID [16]byte`, read before any crypto
(`pkg/attribution/envelope.go`):

- `:345` `func (e *RelayEnvelope) OriginNodeID() [OriginNodeIDSize]byte` —
  the no-crypto accessor the selector reads.
- `:498-503` the Marshal offset doc: "dotCounter at [72:80], originNodeID at
  [80:96]" — the envelope wire window the eBPF program reads (at `ctx->data
  [88:104]` = UDP-header(8) + envelope-offset(80), since `sk_reuseport_md.data`
  begins at the UDP header per `bpf.h:6587`).
- `:143-144` "dotCounter and originNodeID are read from the header BEFORE any
  capnp decode, so the cheap 3.1/3.0 gates run against header fields, not a
  capnp unmarshal" — the same read-before-Verify seam the eBPF program honors
  (it runs in kernel context before userspace crypto; it cannot call
  `Open`/`Verify`).

## 2. Decision Drivers

- **D1: Silicon over assumption (the assumed→measured advance).** ADR-0002's
  in-process seam was an assumed analogue of the kernel program — a pure-Go
  FNV-1a hash standing in for `bpf_sk_select_reuseport`. My discipline
  throughout has been to advance every architectural claim from "assumed" to
  "measured" once the silicon is available. The c8g box is now available; the
  kernel load was the single largest assumed→measured gap remaining, and this
  ADR closes it.
- **D2: CAP_BPF is a user-provisioned property, not a harness property.** The
  harness asserts the capability (kernel >= 6.18 and CAP_BPF present); it does
  not grant it. The box has `unprivileged_bpf_disabled=1`, so the eBPF tests
  run via `sudo` (root has CAP_BPF implicitly). A future Terraform manifest
  that bakes CAP_BPF into the Karpenter NodePool user-data would discharge
  this recursively (the manifest is the reproducibility artifact; this ADR is
  the measurement).
- **D3: Anti-fabrication on the bpf(2) syscall path.** `golang.org/x/sys@v0.46.0`
  ships the bpf(2) constants (`BPF_PROG_TYPE_SK_REUSEPORT` ztypes_linux.go:2831
  = 0x15, `SO_ATTACH_REUSEPORT_EBPF` zerrors_linux_arm64.go:336 = 0x34, `SYS_BPF`
  zsysnum_linux_arm64.go:274 = 280) but no Go wrappers and no `bpf_attr` Go
  types for the live-program path (grep-verified: no `BpfProgLoad`/`BpfMapCreate`/
  `bpf_attr`/`bpf_sk_reuseport_md` in x/sys/unix). Calling a fabricated
  `unix.BpfProgLoad` is exactly the anti-fabrication failure I have disciplined
  out of this engine (an earlier revision fabricated `ed25519.SignWithOptions`).
  The live-program path therefore uses the `cilium/ebpf` v0.22.0 loader, which
  owns the `bpf(2)` syscall + the `bpf_attr` union + the typed program/map load
  path, so this ADR calls its typed API, not hand-rolled `unix.Syscall` bytes.
- **D4: Kernel-faithful map type.** The `bpf_sk_select_reuseport` helper (id
  82) doc at `include/uapi/linux/bpf.h @ v6.18:3718-3721` names
  `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` as the canonical map, but the verifier's
  `check_map_func_compatibility` (`kernel/bpf/verifier.c:10125-10128`: the
  `BPF_FUNC_sk_select_reuseport` case accepts `REUSEPORT_SOCKARRAY`, `SOCKMAP`,
  or `SOCKHASH`) explicitly allows all three. The map this ADR uses is
  `BPF_MAP_TYPE_SOCKHASH` (cilium `ebpf.SockHash`, types.go:74; x/sys
  `ztypes_linux.go:2794` = 0x12) — a real hash map keyed on the 16-byte
  OriginNodeID, valued on the socket FD (uint64). SOCKHASH is chosen over
  REUSEPORT_SOCKARRAY because the latter is an array map keyed on a `u32`
  index, which cannot be keyed on a 16-byte CID; SOCKHASH looks the 16-byte CID
  up directly (no in-program hash) — the silicon form of the in-process
  `(cid -> worker index)` remap, and the SOCKHASH rationale the design record
  names ("utilizing a BPF SOCKHASH map to pin stateful connections to specific
  processor cores"). The map's userspace update path
  (`net/core/sock_map.c:565` `ufd = *(u64*)value; sockfd_lookup(ufd)`) accepts a
  socket FD as the value, exactly like REUSEPORT_SOCKARRAY — so the map is
  populated from userspace via `ebpf.Map.Update(cid, fd)`. SILICON-PROVEN: the
  SOCKHASH map loads and the program's `bpf_sk_select_reuseport` lookup hits on
  the 16-byte CID on c8g kernel 6.18 (TestEBPFRoamStickiness_32Sockets: 0/1000
  mis-routes).
- **D5: Honesty about scope.** This ADR is not an acceptance-verdict blocker;
  it does not touch the performance/correctness gates. It advances an
  architectural claim (the design record's coupling decision, marked "PROVEN")
  from "in-process proven" to "silicon proven" — it does not flip the overall
  engine acceptance verdict, does not promote the post-quantum envelope (which
  stays gated), and does not touch `crdt.go`.

## 3. Considered Options

- **Option A: hand-roll the bpf(2) syscall + bpf_attr union + BPF bytecode.**
  Hand-define the `bpf_attr` union + `bpf_sk_reuseport_md` context from the
  kernel UAPI header, load the program via
  `unix.Syscall(unix.SYS_BPF, BPF_PROG_LOAD, ptr_to_bpf_attr, size)`, and
  hand-write the BPF instruction stream. **Rejected** — the largest
  fabrication surface is the `bpf_attr` union + the BPF bytecode; hand-rolling
  it re-introduces the exact anti-fabrication risk D3 exists to eliminate. The
  box has `clang` 15 + `llc` (bpf target) but Option B removes the surface
  entirely.
- **Option B: cilium/ebpf loader + asm DSL for the instruction stream.** Use
  `cilium/ebpf` v0.22.0 (the industry-standard loader) to own the `bpf(2)`
  syscall + `bpf_attr` union + typed program/map load, and build the BPF
  instruction stream in Go via cilium's `asm` DSL (`asm.Instructions`), loaded
  via `ebpf.NewProgram`. cilium does not carry a Go `bpf_sk_reuseport_md`
  type, so the context field offsets the program reads are hand-defined from
  the kernel UAPI header (`include/uapi/linux/bpf.h @ v6.18:6585`), cited per
  field — the only struct this ADR hand-defines, and it cites its kernel
  source line. **Accepted.**

## 4. Decision (the load-bearing claim)

Accept Option B. `pkg/transport/ebpf_reuseport.go` (gated
`//go:build ebpf_kernel`) is the live kernel counterpart of the in-process
`ReusePortFanout` (`pkg/transport/fanout.go`). `KernelFanout` binds a real
32-member `SO_REUSEPORT` (0xf) UDP socket group, loads a
`BPF_PROG_TYPE_SK_REUSEPORT` (0x15) eBPF program that reads the same wire
field the in-process selector hashes (OriginNodeID `[80:96]`,
`envelope.go:498-503`), looks it up in a `BPF_MAP_TYPE_SOCKHASH` map, and
calls `bpf_sk_select_reuseport` (helper id 82) to pin the flow to the
selected socket. The program is attached to the group via
`setsockopt(SOL_SOCKET=0x1, SO_ATTACH_REUSEPORT_EBPF=0x34, &progFd)` (the
existing `unix.SetsockoptInt` already wraps setsockopt — the
capnp_server.go:158 precedent — not a fabricated helper). The kernel then
invokes the program on every ingress packet and delivers it to the one socket
the program selects — the silicon form of "same CID -> same core."

The program's return value is `enum sk_action` (`bpf.h:6561`): **`SK_DROP=0`,
`SK_PASS=1`** (inverted from intuition). On `SK_PASS` the kernel returns the
`bpf_sk_select_reuseport`-selected socket; if the helper was not called /
missed, `selected_sk` is NULL and the kernel falls back to
`reuseport_select_sock_by_hash` (`sock_reuseport.c:602`) — the
`SELECT_OR_MIGRATE` fallback. The program never returns `SK_DROP`: a
malformed / out-of-bounds / map-miss frame is a verdict (fall back to the
kernel hash), never a crash or a drop — the same contract the in-process
`TestNoPanicOnZeroFrame` proves and `pkg/receive/receiver.go:244` `HandleFrame`
honors.

This decision is enforced structurally, not merely documented:

- `TestEBPFRoamStickiness_32Sockets` (`pkg/transport/ebpf_reuseport_test.go`)
  is the silicon form of `TestRoamStickiness_32ListIncomplete` (`fanout_test.go`):
  32 real sockets, 1000 packets, the 4-tuple changes / CID constant -> all 1000
  land on one socket (the pinned core). 0 failures. `t.Fatalf` on any
  mis-route.
- `TestEBPFDeterminism` is the silicon form of `TestSelectRouteDeterminism`:
  same CID -> same socket.
- `TestNoCryptoBeforeRoute_EBPF` is the silicon form of `TestNoCryptoBeforeRoute`:
  the strip-from-packet eBPF invariant holds in the kernel too (the program
  runs in kernel context before userspace crypto; it cannot call
  `Open`/`Verify`).
- `TestEBPFMalformedFrameNoDrop` is the silicon form of
  `TestNoPanicOnZeroFrame`: a short / out-of-bounds payload falls back to the
  kernel hash, not a drop.
- `requireCapBPF` is the non-vacuous silicon guard: a run with CAP_BPF
  revoked `t.Skip`s (does not pass) — a capability-absent pass-faking is
  forbidden.

## 5. Rationale (R1-R5; transcribed, not re-proven)

The coupling decision is proven in the design record; this ADR does not
re-prove it. It is the canonical citable home for the silicon seam that
decision gates, discharging ADR-0002's deferral.

- **R1: Silicon promotion of the in-process seam.** ADR-0002's
  `ReusePortFanout.SelectRoute` was a faithful in-process analogue of
  `bpf_sk_select_reuseport`; this ADR replaces the analogue with the real
  kernel program on c8g silicon. The determinism + stickiness + no-crypto
  properties proven in-process now hold on the live kernel load.
- **R2: The cheap seam (no crypto) holds in the kernel.** The eBPF program
  reads `OriginNodeID()` (`envelope.go:345`) and never calls `Open`/`Verify`.
  This is the same read-before-crypto property the 3.0/3.1 gates already use
  (`envelope.go:143-144`); the eBPF program cannot Verify (it runs in kernel
  context before userspace crypto), so the silicon load must not either — and
  `TestNoCryptoBeforeRoute_EBPF` proves it routes a zero-sig / zero-hop frame
  on the plaintext OriginNodeID alone.
- **R3: The design record's PROVEN coupling decision is citable unchanged.** The architecture
  decision lives in the design record; this ADR builds and measures the
  silicon seam it gates — it does not re-derive the epoll-vs-io_uring decision.
- **R4: The in-process carve-out is partially discharged.** "The kernel path
  is gated on real hardware" — real c8g is now available, the **BPF steering
  half** of the kernel load is measured (0/1000 mis-routes on silicon, kernel
  6.18), so that half's gate is discharged. The **epoll half** of the coupling
  ("epoll coupled with SO_ATTACH_REUSEPORT_EBPF" — the two together) is not
  measured here: this ADR never calls EpollWait/EpollCtl on the SO_REUSEPORT
  socket group (grep-verified, zero epoll references in pkg/transport/; the
  live loop is the existing internal/transport/capnp_server.go:119/222/486,
  not wired to the selector). The epoll half remains gated on follow-up work.
- **R5: cilium/ebpf is the anti-fabrication loader.** It owns the `bpf(2)`
  syscall + `bpf_attr` union so this ADR calls its typed API, not hand-rolled
  `unix.Syscall` bytes — anti-fabrication on a struct `x/sys@v0.46.0` does not
  carry. The version pin is exact (v0.22.0); the BPF instruction stream is
  built via cilium's `asm` DSL with every kernel UAPI field cited.

## 6. Consequences (N1-N4)

- **N1:** The **BPF steering half** of the seam is silicon-proven on one Spot
  `c8g.8xlarge`, kernel 6.18.x, single-AZ. It is not a multi-AZ /
  multi-iteration variance claim; the failure rate is the deterministic
  stickiness (0/1000), gear-independent, but the kernel load (the capability)
  is silicon-specific. The claim is scoped to the steering half: per the §8
  addendum, this ADR measured the steering property on **loopback only**
  (127.0.0.1, no NIC/RSS/XPS/interrupt affinity — a flow "pinned to a core" on
  loopback pins to nothing meaningful, because there is no hardware delivery
  to keep local), measured **zero performance numbers** (no `testing.B` — a
  performance-driven architectural decision measured with zero
  latency/throughput benches), and wired `KernelFanout` into **no production
  code** (grep: `KernelFanout` is imported by zero non-test files;
  receiver.go:244 `HandleFrame(frameBytes []byte)` takes already-delivered
  bytes and never calls the selector). The full "epoll + eBPF" coupling seam
  is therefore half-proven; the epoll + NIC + performance + wiring half is
  deferred. My original "4 honest weaknesses" listed the soft four (single-AZ,
  CAP_BPF provisioning, FNV-vs-SOCKHASH, cilium dep) and omitted the hard four
  (no epoll, loopback, no perf, not wired) — a weakness-curation gap the §8
  addendum owns explicitly (named, not hidden: an honesty discipline that
  stamps out pass-faking must also stamp out weakness-curation).
- **N2:** CAP_BPF provisioning is a user-provisioned property. The harness
  asserts the capability; it does not grant it. A future Terraform manifest
  that bakes CAP_BPF into the Karpenter NodePool user-data would discharge
  this recursively.
- **N3:** The eBPF program reads the same wire field (OriginNodeID `[80:96]`
  of the envelope payload) the in-process `ReusePortFanout.SelectRoute` hashes.
  Because `sk_reuseport_md.data` begins at the UDP header (`bpf.h:6587`), the
  program reads `ctx->data [88:104]` = UDP-header(8) + envelope-offset(80) —
  the same 16 payload bytes the in-process selector hashes (the prior draft
  read `ctx->data [80:96]` = a garbage key and every lookup missed; the +8
  correction is the load-bearing silicon fix). The kernel program uses a
  `SOCKHASH` lookup keyed on the 16-byte CID (not the in-process FNV-1a); the
  determinism guard is parameterized to whatever the live program uses, so a
  hash swap does not break stickiness as long as it stays deterministic. The
  FNV-1a in `fanout.go` is the in-process substitute, not the kernel contract.
- **N4:** `cilium/ebpf` v0.22.0 is a new go.mod dep — the first
  production-loadable eBPF dependency. It is gated behind the `ebpf_kernel`
  build tag (the default build excludes it; no production code imports
  `KernelFanout`). The version pin is exact; the go.mod/go.sum carry only the
  cilium/ebpf addition (plus the unavoidable transitive testify sub-dep version
  nudges `davecgh/go-spew` / `pmezard/go-difflib` that v0.22.0's go.mod
  requires — they are testify's own sub-deps, not new deps).

## 7. Relationships

- **R1:** Cites the architecture design record's coupling decision, the
  matrix row, and the SOCKHASH rationale.
- **R2:** Cites `pkg/attribution/envelope.go:345` (the `OriginNodeID()`
  read-before-crypto seam), `:498-503` (the Marshal offset doc:
  "originNodeID at [80:96]"), `:143-144` (the read-before-capnp comment).
- **R3:** Cites `pkg/transport/fanout.go` (the in-process analogue this ADR
  promotes to silicon) + `pkg/transport/fanout_test.go` (the in-process
  guards the silicon guards are the silicon form of).
- **R4:** Cites the kernel UAPI `include/uapi/linux/bpf.h @ v6.18` for the
  hand-defined `sk_reuseport_md` context (`:6585`), the
  `bpf_sk_select_reuseport` helper doc (`:3718-3721`), the `enum sk_action`
  return values (`:6561`: `SK_DROP=0`, `SK_PASS=1`), and the
  `BPF_SK_REUSEPORT_SELECT` / `SELECT_OR_MIGRATE` attach types
  (`:1117-1118`); the kernel impl `net/core/filter.c:11343`
  (`sk_select_reuseport`) + `net/core/sock_reuseport.c:602`
  (`reuseport_select_sock` hash fallback) + `kernel/bpf/reuseport_array.c:232`
  (the fd-valued map update); and `golang.org/x/sys@v0.46.0/unix` for the
  constants (`BPF_PROG_TYPE_SK_REUSEPORT` ztypes_linux.go:2831,
  `SO_ATTACH_REUSEPORT_EBPF` zerrors_linux_arm64.go:336, `SO_REUSEPORT`
  zerrors_linux_arm64.go:387, `SOL_SOCKET` zerrors_linux_arm64.go:332,
  `SYS_BPF` zsysnum_linux_arm64.go:274).
- **R5:** Promotes ADR-0002 from "in-process proven" to "silicon proven";
  enforced structurally via the guards at
  `pkg/transport/ebpf_reuseport_test.go` — `TestEBPFRoamStickiness_32Sockets`
  (the 32-listener stickiness gate) + `TestEBPFDeterminism` (the determinism
  guard) + `TestNoCryptoBeforeRoute_EBPF` (the strip-from-packet eBPF
  invariant) + `TestEBPFMalformedFrameNoDrop` (the malformed-frame no-drop
  contract) + `requireCapBPF` (the non-vacuous silicon guard).

## 8. Scope-Correction Addendum (2026-07-26) — the four gaps, not a re-proof

This addendum narrows the claim to its measured scope. It does not re-run a
test, does not change a single byte of `pkg/transport/`, does not touch the
rest of the source tree (crdt.go / crdt_apply.go / schema.capnp(.go) /
envelope.go all unchanged),
does not weaken any integrity guard (the 5 eBPF guards still hold on silicon),
and does not change the overall engine acceptance verdict (this ADR was never
an acceptance blocker; the addendum changes nothing about that).

**What the addendum corrects.** The original framing (this ADR's title and
Status/Promotes/N1/R4 wording) claimed a "silicon promotion of the in-process
work" and a full discharge of ADR-0002's "kernel path gated on real hardware."
That overstates the measured scope by about half. The four gaps below are
referenced throughout the receive/transport code as Gap-1 … Gap-4:

1. **Gap-1 — no epoll half on silicon.** The acceptance criterion rules on "epoll coupled
   with SO_ATTACH_REUSEPORT_EBPF" — the two together. This ADR measured only the
   `SO_ATTACH_REUSEPORT_EBPF` steering half. `grep -rnE 'EpollWait|EpollCtl|EpollCreate'
   pkg/transport/` returns zero; the ingress loop is never driven. The live epoll
   loop is the existing `internal/transport/capnp_server.go:119/222/486` and is
   not wired to the selector. The "epoll + eBPF" seam is half-proven; epoll on
   the ingress path is deferred.
2. **Gap-2 — loopback only.** Every frame crossed 127.0.0.1 (the run log
   records "32 sockets on 127.0.0.1:51177"). The eBPF program runs in the
   kernel's sk_reuseport path regardless of ingress interface, so loopback is a
   valid exercise of the program — but the architectural claim is about
   "concurrent scale" and "cache invalidation and thread migration latency
   during high peer mobility and network churn," none of which is measurable on
   loopback (no NIC queue, no RSS, no XPS, no interrupt affinity, no real packet
   distribution). A flow "pinned to a core" on loopback is pinned to nothing
   meaningful. One real-NIC run (secondary ENI or tc-redirect) is deferred.
3. **Gap-3 — no latency / throughput measurement.** `grep -rnE 'func
   Benchmark|testing.B|ns/op' pkg/transport/` returns only the comment
   justifying the fixed-sample test idiom. The point of the epoll+steering
   acceptance criterion is that eBPF
   steering + epoll beats the hash fallback on scheduler stability and cache
   locality at scale. This ADR proved the steering is correct (0/1000
   mis-routes); it did not prove it is fast, that it reduces cache invalidation,
   or that it scales concurrently. One latency benchmark (eBPF-steered vs
   kernel-hash-fallback at 32c under churn) is deferred.
4. **Gap-4 — not wired into the production receive path.** `grep -rn
   KernelFanout` (excluding test and the source file itself) returns zero;
   `grep KernelFanout|SelectRoute|fanout pkg/receive/receiver.go` returns zero.
   `receiver.go:244 HandleFrame(frameBytes []byte)` takes already-delivered frame
   bytes and never calls the selector. The seam is proven in a test harness, not
   in the engine. Wiring `KernelFanout` into `receiver.go`'s ingress (behind the
   `//go:build ebpf_kernel` tag, so the default build is byte-identical) is
   deferred.

**The weakness-curation gap, owned.** The original change listed the soft four
(single-AZ, CAP_BPF provisioning, FNV-vs-SOCKHASH, cilium dep) while omitting
the hard four above. An honesty discipline that stamps out "pass-faking" must
also stamp out "weakness-curation" — curating the least-damaging four while
hiding the most-damaging four is the softer form of the same failure. The hard
four are now in the record (this addendum + the narrowed Status/N1/R4 wording).
Naming this is the correction; hiding it would repeat the very defect being
corrected.

**Net scope claim (honest, post-addendum):** ADR-0003 records a genuine,
non-trivial silicon result — a real `BPF_PROG_TYPE_SK_REUSEPORT` program loads
on kernel 6.18.38 via cilium/ebpf v0.22.0; `bpf_sk_select_reuseport` keyed on
the 16-byte OriginNodeID pins a flow to one socket across a 4-tuple roam
(0/1000 mis-routes, all 1000 on socket 0); the +8 offset fix (data[88:104],
since `sk_reuseport_md.data` begins at the UDP header per `bpf.h:6587`) is real
root-cause debugging; determinism, no-crypto-before-route, and malformed-no-drop
all hold on silicon. That is the **BPF steering half** of the epoll +
SO_ATTACH_REUSEPORT_EBPF criterion,
silicon-proven on one box, on loopback, correctness-only. It partially
discharges ADR-0002's "kernel path gated on real hardware" — the eBPF steering
half. It does not prove the full epoll + SO_ATTACH_REUSEPORT_EBPF criterion on
silicon. The overall engine acceptance
verdict is unchanged. Production verify stays circl Ed25519 @ 60.19µs 32c. The
post-quantum envelope stays gated. crdt.go is untouched. The remaining
half is deferred: epoll on the ingress path, one real-NIC run, one latency
benchmark, and `receiver.go` wiring.
