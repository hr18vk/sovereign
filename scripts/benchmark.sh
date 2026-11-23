#!/usr/bin/env bash
# Copyright 2026 Harsh Rawat
#
# Use of this software is governed by the Business Source License 1.1,
# which can be found in the LICENSE file. Production use requires a written
# grant from the Licensor until the Change Date stated in the LICENSE file.

# Sovereign Engine — core benchmark runner.
#
# Provisions the Go 1.26.1 toolchain used for the recorded core-microbench
# measurements, builds the engine with it, runs the asymmetric producer-consumer
# scaling gate, and measures HAMT allocations and cache-line sharing. The published
# gate floor is 50,736,038 ops/s; docs/evidence/core-crucible.txt records
# 68,278,197 ops/s at 32 cores on a c8g.8xlarge Graviton4.
#
#   ./scripts/benchmark.sh --core-count=32
#
# The optional --pprof flag exports SUPREMUM_PPROF=:6060 for compatibility.
# Current packages do not read it, and this script does not start a pprof listener.
#
# This is a clone-and-run script, not a deploy script. It requires bash, curl,
# a C compiler and jemalloc headers. GOOS and GOARCH are detected with uname.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly HERMETIC_ROOT="${SUPREMUM_HERMETIC_ROOT:-${HOME}/.sovereign/hermetic}"
readonly GO_VERSION="1.26.1"
# Go officially publishes arm64 as linux-arm64 and amd64 as linux-amd64.
GO_ARCH="$(uname -m | sed -E 's/aarch64|arm64/arm64/; s/x86_64|amd64/amd64/')"
readonly GO_ARCH
GO_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
readonly GO_OS

CORES=32
PPROF=0
RUN_CRUCIBLE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --core-count=*)  CORES="${1#*=}" ;;
    --core-count)    shift; CORES="$1" ;;
    --pprof)         PPROF=1 ;;
    --no-crucible)   RUN_CRUCIBLE=0 ;;
    -h|--help)
      cat <<USAGE
sovereign benchmark — core scaling and allocation benchmarks
  --core-count=N   GOMAXPROCS tier to pin (default 32, the recorded silicon tier)
  --pprof          export SUPREMUM_PPROF=:6060 (no profiling listener is started)
  --no-crucible    run benchmarks without RUN_CRUCIBLE=1 (faster sanity checks)
USAGE
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- 1. Hermetic Go toolchain ------------------------------------------------
# Download the exact compiler release used for the recorded numbers, install it
# under HERMETIC_ROOT, and shim it onto PATH ahead of any system go. Bypasses the
# developer's local toolchain entirely.
install_hermetic_go() {
  local goroot="${HERMETIC_ROOT}/go${GO_VERSION}"
  if "${goroot}/bin/go" version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    export GOROOT="${goroot}"
    export PATH="${goroot}/bin:${PATH}"
    return 0
  fi
  local tarball="go${GO_VERSION}.${GO_OS}-${GO_ARCH}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  mkdir -p "${HERMETIC_ROOT}"
  log "provisioning hermetic Go ${GO_VERSION} (${GO_OS}/${GO_ARCH})"
  curl -fsSL --retry 3 --connect-timeout 30 -o "/tmp/${tarball}" "${url}"
  rm -rf "${goroot}"
  tar -C "${HERMETIC_ROOT}" -xzf "/tmp/${tarball}"
  mv "${HERMETIC_ROOT}/go" "${goroot}"
  rm -f "/tmp/${tarball}"
  export GOROOT="${goroot}"
  export PATH="${goroot}/bin:${PATH}"
}

log()  { printf '\033[2mbenchmark: %s\033[0m\n' "$*"; }
ERR()  { printf '\033[31mbenchmark: %s\033[0m\n' "$*" >&2; }

# --- 2. Build the engine -----------------------------------------------------
build_engine() {
  log "building sovereign engine (CGO enabled for jemalloc, GOMAXPROCS=${CORES})"
  cd "${REPO_ROOT}"
  # `go build ./...` compiles every package and command without requesting a
  # single output file for multiple binaries. CGO_ENABLED=1 is required because
  # internal/database/memory_allocator.go binds jemalloc through cgo. GOOS and
  # GOARCH come from uname, so the build matches the host rather than a fixed
  # recording platform.
  CGO_ENABLED=1 GOOS="${GO_OS}" GOARCH="${GO_ARCH}" \
    go build -trimpath ./...
}

# --- 3. Run the scaling gate and microbenchmarks ------------------------------
run_crucible() {
  log "running scaling gate (GOMAXPROCS=${CORES})"
  if [ "${PPROF}" -eq 1 ]; then
    export SUPREMUM_PPROF=:6060
    log "SUPREMUM_PPROF=:6060 exported; no profiling listener is started"
  fi
  export GOMAXPROCS="${CORES}"
  export RUN_CRUCIBLE="${RUN_CRUCIBLE}"

  # RUN_CRUCIBLE=1 enables TestScalingGate and its throughput assertion.
  go test ./pkg/sync/ \
    -run 'TestScalingGate' \
    -count=1 -v

  # Run the allocation and cache-line benchmarks with taskset when available.
  # BenchmarkHAMTInsertZeroAlloc should report 0 B/op and 0 allocs/op.
  # BenchmarkFalseSharingPadded and BenchmarkFalseSharingUnpadded compare
  # counters separated by CacheLinePad with counters that share a cache line.
  # The gate itself is the Test* form invoked above.
  local pin=""
  if command -v taskset >/dev/null 2>&1; then
    local range="0-$((CORES - 1))"
    pin="taskset -c ${range}"
    log "pinning to cores ${range}"
  fi
  ${pin} go test ./pkg/sync/ \
    -run '^$' \
    -bench 'BenchmarkHAMTInsertZeroAlloc$|BenchmarkFalseSharing' \
    -benchmem -count=3 \
    | tee "${HERMETIC_ROOT}/bench.txt"

  log "raw results -> ${HERMETIC_ROOT}/bench.txt"
  log "published gate floor: 50,736,038 ops/s; record hardware and toolchain with any discrepancy"
}

main() {
  install_hermetic_go
  go version
  build_engine
  run_crucible
}

main "$@"
