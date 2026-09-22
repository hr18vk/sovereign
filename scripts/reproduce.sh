#!/usr/bin/env bash
# Copyright 2026 Harsh Rawat
#
# Use of this software is governed by the Business Source License 1.1,
# which can be found in the LICENSE file. Production use requires a written
# grant from the Licensor until the Change Date (2029-08-15).

# Sovereign Engine — re-run every receipt in docs/evidence on this machine.
#
# One command, a provenance header (machine, kernel, Go, jemalloc, commit), every
# gate and benchmark behind the numbers in docs/evidence, and a saved transcript.
# Every step runs even if an earlier one fails; each prints its exit status, and
# the script's own exit status is 0 only if every step passed.
#
#   ./scripts/reproduce.sh                 # everything, GOMAXPROCS = nproc
#   CPUS=32 ./scripts/reproduce.sh         # pin the GOMAXPROCS tier
#   SKIP_INGEST=1 ./scripts/reproduce.sh   # skip the ~15-60 s ingest benchmark
#   SKIP_GATE=1 ./scripts/reproduce.sh     # skip the ~30 s core scaling gate
#
# Output: reproduce-<UTC timestamp>-<git sha>.txt in the repo root (also on screen).
# The receipts in docs/evidence were taken on c8g.8xlarge (32 vCPU Graviton4) and
# c7gd.8xlarge (Graviton3). Fewer cores give lower absolute numbers. The
# zero-allocation, struct-layout, PQ and CRDT-law gates hold on any Linux box; the
# scaling gate needs eight or more cores and asserts 50M ops/s at its top tier, so
# a small machine can fail it on throughput alone. The transcript records whatever
# happened.
#
# Needs: Go 1.26.1, a C toolchain (gcc), libjemalloc-dev, Linux.

set -uo pipefail

case "${1:-}" in
  -h|--help)
    cat <<USAGE
sovereign reproduce — every receipt in docs/evidence, on this machine
  CPUS=N         GOMAXPROCS tier for the ingest benchmark and the scaling gate (default: nproc)
  SKIP_INGEST=1  skip step 6, the Ed25519 ingest benchmark
  SKIP_GATE=1    skip step 7, the core scaling gate
USAGE
    exit 0 ;;
  "") ;;
  *) echo "unknown flag: $1 (this script is driven by CPUS, SKIP_INGEST and SKIP_GATE)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

CPUS="${CPUS:-$(nproc)}"
SHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$ROOT/reproduce-$STAMP-$SHA.txt"
exec > >(tee "$LOG") 2>&1

FAILS=0
hr()  { printf '\n==== %s ====\n' "$*"; }
run() {
  printf '\n$ %s\n' "$*"
  "$@"
  local rc=$?
  echo "[exit $rc]"
  [ "$rc" -eq 0 ] || FAILS=$((FAILS + 1))
}

hr "provenance"
echo "utc:        $(date -u)"
# Strip any user:token@ from the remote URL before it lands in a transcript.
echo "repo:       $(git config --get remote.origin.url 2>/dev/null | sed -E 's#://[^/@]+@#://#' || echo '?')  commit: $SHA  $(git status --porcelain 2>/dev/null | grep -q . && echo '(dirty tree)' || echo '(clean tree)')"
echo "kernel:     $(uname -sr)  arch: $(uname -m)"
echo "cpus:       $(nproc) online, GOMAXPROCS tier for this run: $CPUS"
lscpu 2>/dev/null | grep -iE 'model name|cpu part|vendor id' | sed 's/^/            /'
# EC2 instance type via IMDSv2 (silently skipped anywhere else).
TOKEN=$(curl -s --max-time 1 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
  ITYPE=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || true)
  IREGION=$(curl -s --max-time 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)
  # Only print when the answer looks like an EC2 type (other clouds answer this address with HTML).
  if printf '%s' "$ITYPE" | grep -Eq '^[a-z0-9]+\.[a-z0-9]+$'; then echo "ec2:        $ITYPE in ${IREGION:-?}"; fi
fi
echo "go:         $(go version)"
JEMALLOC="$(ldconfig -p 2>/dev/null | grep -o 'libjemalloc\.so[^ ]*' | head -n 1 || true)"
if [ -n "$JEMALLOC" ]; then
  echo "jemalloc:   $JEMALLOC"
else
  echo "jemalloc:   WARNING: libjemalloc not found (sudo apt-get install -y libjemalloc-dev)"
fi

hr "1. zero-allocation gate + benchmark (pkg/sync)"
run go test -run TestHotPathZeroAllocations -count=1 ./pkg/sync/
run go test -run '^$' -bench=BenchmarkHAMTInsertZeroAlloc -benchmem -count=1 ./pkg/sync/

hr "2. struct layout gate (128-byte stride, cache-line alignment)"
run go test -run 'TestHamtNodeOffsets|TestCRDTEntry_SizeAndAlignment|TestHamtLeaf_SizeAndAlignment' -count=1 -v ./pkg/sync/

hr "3. false-sharing benchmark (unpadded vs padded counters)"
run go test -run '^$' -bench='BenchmarkFalseSharing' -benchmem -count=1 ./pkg/sync/

hr "4. CRDT algebra (commutative, associative, idempotent; property-based)"
run go test -run 'TestCRDTJoin|TestCRDTConvergenceMultiNode|TestCRDTMonotonicGrowth' -count=1 -v ./pkg/sync/

hr "5. post-quantum key exchange (X25519MLKEM768 must be negotiated)"
run go test -run 'TestPQ_' -count=1 -v ./pkg/transport/

if [ "${SKIP_INGEST:-0}" != 1 ]; then
  hr "6. ingest: one Ed25519 verify per frame, then envelope + merge per delta (pkg/receive)"
  run go test -run '^$' -bench=BenchmarkBatchedVerifyParallel -benchmem -count=1 -cpu="$CPUS" ./pkg/receive/
fi

if [ "${SKIP_GATE:-0}" != 1 ]; then
  hr "7. core scaling gate (RUN_CRUCIBLE=1; runs on 8+ cores, asserts 50M ops/s at the top tier)"
  RUN_CRUCIBLE=1 run go test -run TestScalingGate -count=1 -v -cpu="$CPUS" ./pkg/sync/
fi

hr "done"
echo "steps with a non-zero exit: $FAILS"
echo "transcript: $LOG"
[ "$FAILS" -eq 0 ]
