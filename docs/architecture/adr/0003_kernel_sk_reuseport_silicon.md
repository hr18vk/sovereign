# ADR-0003: live BPF_PROG_TYPE_SK_REUSEPORT on c8g kernel 6.18 (BPF steering half silicon-proven; epoll + NIC + perf + wiring pending)
> Status: ACCEPTED (SCOPED to the BPF steering half)     Date: 2026-07-25..26     Track: Phase 3 Track 12.0 (corrected by Move-A framing addendum 2026-07-26)
> Supersedes: none     Superseded by: none     Promotes: ADR-0002 (Track 2.1) PARTIALLY — only the BPF steering half; the epoll + NIC + perf + wiring half remains deferrable to Track 12.1

## 1. Context

ADR-0002 (Track 2.1) built + measured the IN-PROCESS seam the Phase-3 §2.X1(a)
decision gates — the deterministic decision function a kernel
`BPF_PROG_TYPE_SK_REUSEPORT` program loaded via `SO_ATTACH_REUSEPORT_EBPF`
would implement — and explicitly DEFERRED the live kernel eBPF load:

> ADR-0002 §1: "The kernel eBPF load (binding a real `SO_REUSEPORT` socket
> group, loading the program via `bpf(2)`, and verifying flow stickiness on
> `c8g` with `CAP_BPF`) is **Subphase 12.0**, a FUTURE track."

The roadmap line 51 carve-out permitted the in-process path FIRST: "Acceptance
uses the in-process `internal/chaos` VirtualNet infra, NOT the kernel, until
real c8g is available; the kernel path is CONDITIONAL-GO pending Subphase
12.0." This track (12.0) DISCHARGES that deferral: real c8g is now available
(a Spot `c8g.8xlarge`, Graviton4 0xd4f, kernel 6.18.38, `CAP_BPF` granted via
`sudo` on a box with `unprivileged_bpf_disabled=1`).

The architecture decision is PROVEN in the prose at
`phase-03/Final_Sovereign_Architecture_Phase3.md`:

- **:358** (§2.X1(a), the ruling): "(a) epoll + SO\_ATTACH\_REUSEPORT\_EBPF vs
  io\_uring: PROVEN ... Implementing epoll coupled with the Linux kernel's
  SO\_ATTACH\_REUSEPORT\_EBPF custom socket steering provides the necessary
  packet fanout on Linux 6.18 without compromising scheduler stability."
- **:108** (the matrix row): "Socket ingress must utilize edge-triggered epoll
  combined with native BPF steering programs (bpf\_sk\_select\_reuseport) to
  achieve concurrent scale."
- **:102** (the SOCKHASH rationale): "... utilizing a BPF SOCKHASH map to pin
  stateful connections to specific processor cores, thereby eradicating cache
  invalidation and thread migration latency during periods of high peer
  mobility and network churn."

This ADR RECORDS the silicon promotion: the in-process analogue (Track 2.1 /
ADR-0002) is now backed by a MEASURED kernel load on `c8g` kernel 6.18 with
`CAP_BPF`. It transcribes; it does NOT re-prove §2.X1(a) (that lives in the
prose). The eBPF route key is the SAME plaintext Application Connection ID the
in-process selector keys on — `originNodeID [16]byte`, read BEFORE any crypto
(`pkg/attribution/envelope.go`):

- **:345** `func (e *RelayEnvelope) OriginNodeID() [OriginNodeIDSize]byte` —
  the no-crypto accessor the selector reads.
- **:498-503** the Marshal offset doc: "dotCounter at [72:80], originNodeID at
  [80:96]" — the envelope wire window the eBPF program reads (at `ctx->data
  [88:104]` = UDP-header(8) + envelope-offset(80), since `sk_reuseport_md.data`
  begins at the UDP header per `bpf.h:6587`).
- **:143-144** "dotCounter and originNodeID are read from the header BEFORE any
  capnp decode, so the cheap 3.1/3.0 gates run against header fields, not a
  capnp unmarshal" — the SAME read-before-Verify seam the eBPF program honors
  (it runs in kernel context BEFORE userspace crypto; it CANNOT call
  `Open`/`Verify`).

## 2. Decision Drivers

- **D1: Silicon over assumption (the assumed→measured advance).** ADR-0002's
  in-process seam was an ASSUMED analogue of the kernel program — a pure-Go
  FNV-1a hash standing in for `bpf_sk_select_reuseport`. The engine's
  discipline all phase has been to advance every architectural claim from
  "assumed" to "measured" once the silicon is available. The c8g box is now
  available; the kernel load is the single largest assumed→measured gap
  remaining in Phase 3. This track closes it.
- **D2: CAP_BPF is a user-provisioned property, not a harness property.** The
  harness ASSERTS the capability (the BLOCK 7 gate: kernel >= 6.18 AND CAP_BPF
  present); it does NOT grant it. The box has `unprivileged_bpf_disabled=1`,
  so the eBPF tests run via `sudo` (root has CAP_BPF implicitly). A future
  Track-4.0 Terraform manifest that bakes CAP_BPF into the Karpenter NodePool
  user-data would discharge this recursively (Track 4.0 is the reproducibility
  manifest; 12.0 is the measurement).
- **D3: Anti-fabrication on the bpf(2) syscall path.** `golang.org/x/sys@v0.46.0`
  ships the bpf(2) CONSTANTS (`BPF_PROG_TYPE_SK_REUSEPORT` ztypes_linux.go:2831
  = 0x15, `SO_ATTACH_REUSEPORT_EBPF` zerrors_linux_arm64.go:336 = 0x34, `SYS_BPF`
  zsysnum_linux_arm64.go:274 = 280) but NO Go wrappers and NO `bpf_attr` Go
  types for the live-program path (grep-verified: no `BpfProgLoad`/`BpfMapCreate`/
  `bpf_attr`/`bpf_sk_reuseport_md` in x/sys/unix). Calling a fabricated
  `unix.BpfProgLoad` is the exact anti-fabrication failure this engine
  disciplined out (Rev 2 fabricated `ed25519.SignWithOptions`). The live-program
  path therefore uses the `cilium/ebpf` v0.22.0 loader, which owns the `bpf(2)`
  syscall + the `bpf_attr` union + the typed program/map load path, so this
  track calls its typed API, not hand-rolled `unix.Syscall` bytes.
- **D4: Kernel-faithful map type.** The `bpf_sk_select_reuseport` helper (id
  82) doc at `include/uapi/linux/bpf.h @ v6.18:3718-3721` names
  `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` as the canonical map, but the verifier's
  `check_map_func_compatibility` (`kernel/bpf/verifier.c:10125-10128`: the
  `BPF_FUNC_sk_select_reuseport` case accepts `REUSEPORT_SOCKARRAY`, `SOCKMAP`,
  OR `SOCKHASH`) explicitly allows all three. The map this track uses is
  `BPF_MAP_TYPE_SOCKHASH` (cilium `ebpf.SockHash`, types.go:74; x/sys
  `ztypes_linux.go:2794` = 0x12) — a real HASH map keyed on the 16-byte
  OriginNodeID, valued on the socket FD (uint64). SOCKHASH is chosen over
  REUSEPORT_SOCKARRAY because the latter is an ARRAY map keyed on a `u32`
  index, which CANNOT be keyed on a 16-byte CID; SOCKHASH looks the 16-byte CID
  up DIRECTLY (no in-program hash) — the silicon form of the in-process
  `(cid -> worker index)` remap, and the `§2.X1(a)` ":102 SOCKHASH rationale"
  the architecture prose names ("utilizing a BPF SOCKHASH map to pin stateful
  connections to specific processor cores"). The map's userspace update path
  (`net/core/sock_map.c:565` `ufd = *(u64*)value; sockfd_lookup(ufd)`) accepts a
  socket FD as the value, exactly like REUSEPORT_SOCKARRAY — so the map is
  populated from userspace via `ebpf.Map.Update(cid, fd)`. SILICON-PROVEN: the
  SOCKHASH map loads + the program's `bpf_sk_select_reuseport` lookup HITS on the
  16-byte CID on c8g kernel 6.18 (TestEBPFRoamStickiness_32Sockets: 0/1000
  mis-routes).
- **D5: The §5 honesty lock.** This track is NOT a §5 verdict-blocker. It does
  NOT touch E1/E2/E3/E5. UNCONDITIONAL-GO stays closed honestly (E5 is a
  physics-negative; no track flips it). The §5 numeric pending set is already
  ZERO. This track advances an ARCHITECTURAL claim (§2.X1(a) "PROVEN") from
  "in-process proven" to "silicon proven" — it does NOT flip the §5 gate, does
  NOT upgrade UNCONDITIONAL-GO, does NOT promote the PQ envelope (Track 1.3
  GATED stays GATED), and does NOT open `crdt.go` (Track 9.0
  BLOCKED-BY-POLICY).

## 3. Considered Options

- **Option A: hand-roll the bpf(2) syscall + bpf_attr union + BPF bytecode.**
  Hand-define the `bpf_attr` union + `bpf_sk_reuseport_md` context from the
  kernel UAPI header, load the program via
  `unix.Syscall(unix.SYS_BPF, BPF_PROG_LOAD, ptr_to_bpf_attr, size)`, and
  hand-write the BPF instruction stream. **REJECTED** — the largest
  fabrication surface is the `bpf_attr` union + the BPF bytecode; hand-rolling
  it re-introduces the exact anti-fabrication risk D3 exists to eliminate. The
  box has `clang` 15 + `llc` (bpf target) but option B removes the surface
  entirely.
- **Option B: cilium/ebpf loader + asm DSL for the instruction stream.** Use
  `cilium/ebpf` v0.22.0 (the industry-standard loader) to own the `bpf(2)`
  syscall + `bpf_attr` union + typed program/map load, and build the BPF
  instruction stream in Go via cilium's `asm` DSL (`asm.Instructions`), loaded
  via `ebpf.NewProgram`. cilium does NOT carry a Go `bpf_sk_reuseport_md`
  type, so the context field offsets the program reads are hand-defined FROM
  THE KERNEL UAPI header (`include/uapi/linux/bpf.h @ v6.18:6585`), cited per
  field — the ONLY struct this track hand-defines, and it cites its kernel
  source line. ✅ **ACCEPTED.**

## 4. Decision (the load-bearing claim)

**ACCEPT Option B.** `pkg/transport/ebpf_reuseport.go` (gated
`//go:build ebpf_kernel`) is the LIVE kernel counterpart of the in-process
`ReusePortFanout` (`pkg/transport/fanout.go`). `KernelFanout` binds a real
32-member `SO_REUSEPORT` (0xf) UDP socket group, loads a
`BPF_PROG_TYPE_SK_REUSEPORT` (0x15) eBPF program that reads the SAME wire
field the in-process selector hashes (OriginNodeID `[80:96]`,
`envelope.go:498-503`), looks it up in a `BPF_MAP_TYPE_SOCKHASH` map, and
calls `bpf_sk_select_reuseport` (helper id 82) to pin the flow to the
selected socket. The program is attached to the group via
`setsockopt(SOL_SOCKET=0x1, SO_ATTACH_REUSEPORT_EBPF=0x34, &progFd)` (the
existing `unix.SetsockoptInt` already wraps setsockopt — the capnp_server.go:158
precedent — NOT a fabricated helper). The kernel then invokes the program on
every ingress packet and delivers it to the ONE socket the program selects —
the silicon form of "same CID -> same core."

The program's return value is `enum sk_action` (`bpf.h:6561`): **`SK_DROP=0`,
`SK_PASS=1`** (inverted from intuition). On `SK_PASS` the kernel returns the
`bpf_sk_select_reuseport`-selected socket; if the helper was not called /
missed, `selected_sk` is NULL and the kernel falls back to
`reuseport_select_sock_by_hash` (`sock_reuseport.c:602`) — the
`SELECT_OR_MIGRATE` fallback. The program NEVER returns `SK_DROP`: a
malformed / out-of-bounds / map-miss frame is a Verdict (fall back to the
kernel hash), NEVER a crash or a drop — the SAME contract the in-process
`TestNoPanicOnZeroFrame` proves and `pkg/receive/receiver.go:244` `HandleFrame`
honors.

This decision is enforced structurally, not merely documented:

- `TestEBPFRoamStickiness_32Sockets` (`pkg/transport/ebpf_reuseport_test.go`)
  is the SILICON form of `TestRoamStickiness_32ListIncomplete` (`fanout_test.go`):
  32 real sockets, 1000 packets, the 4-tuple changes / CID constant -> all 1000
  land on ONE socket (the pinned core). 0 failures. `t.Fatalf` on any
  mis-route.
- `TestEBPFDeterminism` is the silicon form of `TestSelectRouteDeterminism`:
  same CID -> same socket.
- `TestNoCryptoBeforeRoute_EBPF` is the silicon form of `TestNoCryptoBeforeRoute`:
  the strip-from-packet eBPF invariant holds in the KERNEL too (the program
  runs in kernel context BEFORE userspace crypto; it CANNOT call
  `Open`/`Verify`).
- `TestEBPFMalformedFrameNoDrop` is the silicon form of
  `TestNoPanicOnZeroFrame`: a short / out-of-bounds payload falls back to the
  kernel hash, NOT a drop.
- `requireCapBPF` is the non-vacuous silicon tooth (G12.c): a run with CAP_BPF
  revoked `t.Skip`'s (NOT passes) — a capability-absent pass-faking is
  forbidden.

## 5. Rationale (R1-R5; TRANSCRIBED, not re-proven)

The §2.X1(a) decision is PROVEN in the prose (Phase3.md:358/:108/:102); this
ADR does NOT re-prove it. It is the canonical citable home for the SILICON
seam that decision gates, discharging ADR-0002's deferral.

- **R1: Silicon promotion of the in-process seam.** ADR-0002's
  `ReusePortFanout.SelectRoute` was a FAITHFUL in-process analogue of
  `bpf_sk_select_reuseport`; this track replaces the analogue with the real
  kernel program on c8g silicon. The determinism + stickiness + no-crypto
  properties proven in-process (Track 2.1) now hold on the LIVE kernel load.
- **R2: The cheap seam (no crypto) holds in the kernel.** The eBPF program
  reads `OriginNodeID()` (`envelope.go:345`) and never calls `Open`/`Verify`.
  This is the same read-before-crypto property the 3.0/3.1 gates already use
  (`envelope.go:143-144`); the eBPF program CANNOT Verify (it runs in kernel
  context before userspace crypto), so the silicon load MUST not either — and
  `TestNoCryptoBeforeRoute_EBPF` proves it routes a zero-sig / zero-hop frame
  on the plaintext OriginNodeID alone.
- **R3: The §2.X1(a) PROVEN decision is citable unchanged.** The architecture
  decision lives in the prose (Phase3.md:358/:108/:102); this track builds +
  measures the SILICON seam it gates, it does not re-derive the
  epoll-vs-io_uring ruling.
- **R4: The in-process carve-out in roadmap line 51 is PARTIALLY DISCHARGED.**
  "the kernel path is CONDITIONAL-GO pending Subphase 12.0" — real c8g is now
  available, the **BPF steering half** of the kernel load is measured (0/1000
  mis-routes on silicon, kernel 6.18), so that half's CONDITIONAL-GO is
  DISCHARGED. The **epoll half** of §2.X1(a) ("epoll coupled with
  SO_ATTACH_REUSEPORT_EBPF", Phase3.md:358 — the two TOGETHER) is NOT measured
  by 12.0: 12.0 never calls EpollWait/EpollCtl on the SO_REUSEPORT socket
  group (grep-verified, zero epoll references in pkg/transport/; the live loop
  is the existing internal/transport/capnp_server.go:119/222/486, NOT wired to
  the 12.0 selector). The epoll half remains CONDITIONAL-GO pending Track 12.1.
- **R5: cilium/ebpf is the anti-fabrication loader.** It owns the `bpf(2)`
  syscall + `bpf_attr` union so this track calls its typed API, not hand-rolled
  `unix.Syscall` bytes — anti-fabrication on a struct `x/sys@v0.46.0` does NOT
  carry. The version pin is exact (v0.22.0); the BPF instruction stream is
  built via cilium's `asm` DSL with every kernel UAPI field cited.

## 6. Consequences (N1-N4)

- **N1:** The **BPF steering half** of the seam is SILICON-PROVEN on ONE
  Spot `c8g.8xlarge`, kernel 6.18.x, single-AZ. It is NOT a multi-AZ /
  multi-iteration variance claim; the failure rate is the DETERMINISTIC
  stickiness (0/1000), gear-independent in the §5 SCISSORS sense, but the
  KERNEL LOAD (the capability) is silicon-specific. The claim is SCOPED to the
  steering half: per the Move-A framing addendum (§8 below), 12.0 measured the
  steering property on **loopback only** (127.0.0.1, no NIC/RSS/XPS/interrupt
  affinity — a flow "pinned to a core" on loopback pins to nothing meaningful,
  because there is no hardware delivery to keep local), measured **zero
  performance numbers** (no `testing.B` — a performance-driven architectural
  decision measured with zero latency/throughput benches), and wired
  `KernelFanout` into **NO production code** (grep: `KernelFanout` is imported
  by zero non-test files; receiver.go:244 `HandleFrame(frameBytes []byte)` takes
  already-delivered bytes and never calls the selector). The full §2.X1(a)
  "epoll + eBPF" seam is therefore half-proven; the epoll + NIC + perf +
  wiring half is pending Track 12.1. The original 12.0 "4 honest weaknesses"
  listed the soft four (single-AZ, CAP_BPF provisioning, FNV-vs-SOCKHASH,
  cilium dep) and OMITTED the hard four (no epoll, loopback, no perf, not
  wired) — a weakness-curation gap this addendum owns explicitly (named, not
  hidden: a §5-honesty regime that disciplines out pass-faking must discipline
  out weakness-curation too).
- **N2:** CAP_BPF provisioning is a USER-PROVISIONED property. The harness
  ASSERTS the capability (the BLOCK 7 gate); it does NOT grant it. A future
  Track-4.0 Terraform manifest that bakes CAP_BPF into the Karpenter NodePool
  user-data would discharge this recursively.
- **N3:** The eBPF program reads the SAME wire field (OriginNodeID `[80:96]`
  of the envelope payload) the in-process `ReusePortFanout.SelectRoute` hashes.
  Because `sk_reuseport_md.data` begins at the UDP header (`bpf.h:6587`), the
  program reads `ctx->data [88:104]` = UDP-header(8) + envelope-offset(80) —
  the SAME 16 payload bytes the in-process selector hashes (the prior draft read
  `ctx->data [80:96]` = a garbage key and every lookup missed; the +8 correction
  is the load-bearing silicon fix). The kernel program uses a `SOCKHASH` lookup
  keyed on the 16-byte CID (not the in-process FNV-1a); the determinism tooth is
  parameterized to whatever the live program uses, so a hash swap does not break
  stickiness as long as it stays deterministic. The FNV-1a in `fanout.go` is the
  IN-PROCESS substitute, not the kernel contract.
- **N4:** `cilium/ebpf` v0.22.0 is a NEW go.mod dep — the FIRST
  production-loadable eBPF dependency. It is gated behind the `ebpf_kernel`
  build tag (the DEFAULT build excludes it; NO production code imports
  `KernelFanout`). The version pin is exact; the go.mod/go.sum carry ONLY the
  cilium/ebpf addition (+ the unavoidable transitive testify sub-dep version
  nudges `davecgh/go-spew` / `pmezard/go-difflib` that v0.22.0's go.mod
  requires — they are testify's own sub-deps, not new deps).

## 7. Relationships

- **R1:** Cites `phase-03/Final_Sovereign_Architecture_Phase3.md:358` (the
  §2.X1(a) ruling), `:108` (the matrix row), `:102` (the SOCKHASH rationale).
- **R2:** Cites `pkg/attribution/envelope.go:345` (the `OriginNodeID()`
  read-before-crypto seam), `:498-503` (the Marshal offset doc:
  "originNodeID at [80:96]"), `:143-144` (the read-before-capnp comment).
- **R3:** Cites `pkg/transport/fanout.go` (the in-process analogue this track
  promotes to silicon) + `pkg/transport/fanout_test.go` (the in-process teeth
  the silicon teeth are the SILICON form of).
- **R4:** Cites the kernel UAPI `include/uapi/linux/bpf.h @ v6.18` for the
  hand-defined `sk_reuseport_md` context (`:6585`), the `bpf_sk_select_reuseport`
  helper doc (`:3718-3721`), the `enum sk_action` return values (`:6561`:
  `SK_DROP=0`, `SK_PASS=1`), and the `BPF_SK_REUSEPORT_SELECT` /
  `SELECT_OR_MIGRATE` attach types (`:1117-1118`); the kernel impl
  `net/core/filter.c:11343` (`sk_select_reuseport`) +
  `net/core/sock_reuseport.c:602` (`reuseport_select_sock` hash fallback) +
  `kernel/bpf/reuseport_array.c:232` (the fd-valued map update); and
  `golang.org/x/sys@v0.46.0/unix` for the constants (`BPF_PROG_TYPE_SK_REUSEPORT`
  ztypes_linux.go:2831, `SO_ATTACH_REUSEPORT_EBPF` zerrors_linux_arm64.go:336,
  `SO_REUSEPORT` zerrors_linux_arm64.go:387, `SOL_SOCKET`
  zerrors_linux_arm64.go:332, `SYS_BPF` zsysnum_linux_arm64.go:274).
- **R5:** Promotes ADR-0002 (Track 2.1) from "in-process proven" to "silicon
  proven"; enforced structurally via the teeth at
  `pkg/transport/ebpf_reuseport_test.go` — `TestEBPFRoamStickiness_32Sockets`
  (the 32-listener stickiness gate) + `TestEBPFDeterminism` (the determinism
  tooth) + `TestNoCryptoBeforeRoute_EBPF` (the strip-from-packet eBPF
  invariant) + `TestEBPFMalformedFrameNoDrop` (the malformed-frame no-drop
  contract) + `requireCapBPF` (the non-vacuous silicon tooth).

## 8. Move-A Framing Addendum (2026-07-26) — scope correction, not a re-proof

This addendum NARROWS the 12.0 claim to its measured scope. It does NOT re-run a
test, does NOT change a single byte of `pkg/transport/`, does NOT touch the
FROZEN substrate (crdt.go / crdt_apply.go / schema.capnp(.go) md5-unchanged;
envelope.go md5 `b1beba1e9de81294bc66a823dece6ab6` unchanged), does NOT weaken
any integrity tooth (the 5 eBPF teeth still hold on silicon), and does NOT touch
the §5 gate (the §5 verdict STAYS CONDITIONAL-GO — 12.0 was never an
E1/E2/E3/E5 verdict-blocker; this addendum changes nothing about §5).

**What the addendum corrects.** The original 12.0 framing (ADR-0003 title,
roadmap line 53 "DISCHARGED", the ADR Status/Promotes/N1/R4 wording) claimed a
"silicon promotion of Track 2.1" and a full discharge of ADR-0002's
"CONDITIONAL-GO pending 12.0". That overstates the measured scope by ~half:

1. **NO epoll half on silicon.** §2.X1(a) (Phase3.md:358) rules on "epoll coupled
   with SO_ATTACH_REUSEPORT_EBPF" — the two TOGETHER. 12.0 measured only the
   `SO_ATTACH_REUSEPORT_EBPF` steering half. `grep -rnE 'EpollWait|EpollCtl|EpollCreate'
   pkg/transport/` returns zero; 12.0 never drives an ingress loop. The live epoll loop
   is the existing `internal/transport/capnp_server.go:119/222/486` and is NOT wired to
   the 12.0 selector. The "epoll + eBPF" seam is HALF-proven; epoll on the ingress path
   is pending Track 12.1.
2. **Loopback only.** Every frame crossed 127.0.0.1 (track4_12.0_*.log line 34:
   "32 sockets on 127.0.0.1:51177"). The eBPF program runs in the kernel's
   sk_reuseport path regardless of ingress interface, so loopback IS a valid exercise
   of the program — but the Architectural claim is about "concurrent scale" and "cache
   invalidation and thread migration latency during high peer mobility and network churn"
   (Phase3.md:102), NONE of which is measurable on loopback (no NIC queue, no RSS, no XPS,
   no interrupt affinity, no real packet distribution). A flow "pinned to a core" on
   loopback is pinned to nothing meaningful. One real-NIC run (secondary ENI or tc-redirect)
   is pending Track 12.1.
3. **NO latency / throughput measurement.** `grep -rnE 'func Benchmark|testing.B|ns/op'
   pkg/transport/` returns only the comment justifying the fixed-sample Test idiom. The
   point of §2.X1(a) is that eBPF steering + epoll BEATS the hash fallback on scheduler
   stability and cache locality at scale. 12.0 proved the steering is CORRECT (0/1000
   mis-routes); it did NOT prove it is FAST, that it reduces cache invalidation, or that
   it scales concurrently. One latency Benchmark (eBPF-steered vs kernel-hash-fallback at
   32c under churn) is pending Track 12.1.
4. **NOT wired into the production receive path.** `grep -rn KernelFanout` (excluding
   test and the source file itself) returns zero; `grep KernelFanout|SelectRoute|fanout
   pkg/receive/receiver.go` returns zero. `receiver.go:244 HandleFrame(frameBytes []byte)`
   takes already-delivered frame bytes and never calls the selector. The seam is proven
   in a test harness, NOT in the engine. Wiring `KernelFanout` into `receiver.go`'s
   ingress (behind the `//go:build ebpf_kernel` tag, so the DEFAULT build is byte-identical
   to today) is pending Track 12.1.

**The weakness-curation gap, owned.** The original 12.0 commit body lists the soft four
(single-AZ, CAP_BPF provisioning, FNV-vs-SOCKHASH, cilium dep) while OMITTING the hard four
above. A §5-honesty regime that disciplines out "pass-faking" must discipline out
"weakness-curation" too — curating the least-damaging four while hiding the most-damaging
four is the softer form of the same sin. The hard four are now IN the record (this
addendum + the ADR Status/N1/R4 narrowing + the roadmap line-53 narrowing + the README
index narrowing). Naming this is the correction; hiding it would repeat the very defect
being corrected.

**Net scope claim (honest, post-addendum):** ADR-0003 records a genuine, non-trivial
silicon result — a real `BPF_PROG_TYPE_SK_REUSEPORT` program loads on kernel 6.18.38 via
cilium/ebpf v0.22.0; `bpf_sk_select_reuseport` keyed on the 16-byte OriginNodeID pins a
flow to one socket across a 4-tuple roam (0/1000 mis-routes, all 1000 on socket 0); the
+8 offset fix (data[88:104], since `sk_reuseport_md.data` begins at the UDP header per
`bpf.h:6587`) is real root-cause debugging; determinism, no-crypto-before-route, and
malformed-no-drop all hold on silicon. That is the **BPF steering half** of §2.X1(a),
silicon-proven on one box, on loopback, correctness-only. It PARTIALLY discharges
ADR-0002's "CONDITIONAL-GO pending 12.0" — the eBPF steering half. It does NOT prove
§2.X1(a) on silicon. The §5 verdict STAYS CONDITIONAL-GO. Production Verify stays circl
Ed25519 @ 60.19µs 32c (Track 1.1/4.M). The PQ envelope STAYS GATED (Track 1.3). crdt.go
STAYS FROZEN (Track 9.0 BLOCKED-BY-POLICY). The remaining half lands in Track 12.1:
epoll on the ingress path, one real-NIC run, one latency Benchmark, and `receiver.go`
wiring.
