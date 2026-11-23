#!/usr/bin/env bash
# Copyright 2026 Harsh Rawat
#
# Use of this software is governed by the Business Source License 1.1,
# which can be found in the LICENSE file. Production use requires a written
# grant from the Licensor until the Change Date stated in the LICENSE file.

# Sovereign Engine — a configurable mesh on one machine.
#
# NODES sovereign-node processes use three loopback addresses standing in for
# three regions, with one convergence-gate client. Everything here is the public
# tooling: cmd/mesh-bootstrap (CA, node identities, peer directory),
# cmd/sovereign-node and cmd/convergence-gate. The manual bring-up is in
# docs/SOVEREIGN_ENGINE_REFERENCE.md §6.4.
#
#   ./scripts/local-mesh.sh                  # 3 nodes, inject, gate
#   CRASH=1 ./scripts/local-mesh.sh          # then restart node 0 on its WAL and
#                                            # compare one root per region
#   NODES=30 CRASH=1 ./scripts/local-mesh.sh # 30 processes on this machine
#   KEYS=500 ./scripts/local-mesh.sh         # fewer keys
#   OUT=/path ./scripts/local-mesh.sh        # keep the CA, WALs and logs
#
# NODES defaults to 3 and accepts 3 through 100. Nodes are divided across the
# regions as evenly as possible. This is a single-machine counterpart for local
# checks, not a substitute for multi-machine network tests or the fleet harness.
# Boot dialing is a full mesh, so process, file-descriptor and port use grows
# quickly. Each node maps a 256 MiB arena: NODES=30 maps 7680 MiB in total before
# the Go runtimes, WALs and LSM data. Check memory, file descriptors and disk.
#
# KEYS defaults to 1000 and accepts 1 through 1000. A fresh receiver with no
# observed inbound rate admits DotCounters up to its Lamport clock + 1000 (the
# default absolute slack, pkg/sync/crdt_reconstruct_skew.go). In a larger batch,
# entries above that bound are held while valid entries join; later sweeps can
# retry them. The gate sends this smoke test's keys in one batch.
#
# Needs: Go 1.26.1, a C toolchain, libjemalloc-dev and Linux. Region addresses
# are 127.0.0.1, 127.0.0.2 and 127.0.0.3. Each node's local index in its region
# offsets its mesh, control and metrics ports from 7373, 8443 and 9100. Linux
# routes the whole 127/8 block to lo, so the addresses need no setup. Profiling
# uses 127.0.0.1 with the metrics port + 1000, without the regional address;
# nodes sharing that derived port log non-fatal bind failures and continue
# without profiling, which the gate does not use.
# The exit status is the convergence gate's verdict: 0 on PASS.

set -euo pipefail

case "${1:-}" in
  -h|--help)
    cat <<USAGE
sovereign local mesh — configurable nodes, three loopback regions, one gate
  NODES=N    node processes (default 3; accepts 3 through 100)
  KEYS=N     keys to inject into node 0 (default 1000; accepts 1 through 1000)
  CRASH=1    after the gate passes, kill -9 node 0, restart it on its WAL, compare the roots
  OUT=DIR    working directory for the CA, identities, WALs and logs (default: mktemp under /tmp)
USAGE
    exit 0 ;;
  "") ;;
  *) echo "unknown flag: $1 (this script is driven by NODES, KEYS, CRASH and OUT)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODES="${NODES:-3}"
KEYS="${KEYS:-1000}"
if ! [[ "$NODES" =~ ^[0-9]{1,3}$ ]] || (( 10#$NODES < 3 || 10#$NODES > 100 )); then
  echo "NODES must be an integer from 3 through 100 (got: $NODES)" >&2
  exit 2
fi
if ! [[ "$KEYS" =~ ^[0-9]{1,4}$ ]] || (( 10#$KEYS < 1 || 10#$KEYS > 1000 )); then
  echo "KEYS must be an integer from 1 through 1000 (got: $KEYS)" >&2
  exit 2
fi
NODES=$((10#$NODES))
KEYS=$((10#$KEYS))
OUT="${OUT:-$(mktemp -d /tmp/sovereign-mesh.XXXXXX)}"
mkdir -p "$OUT"
cd "$ROOT"

echo "== build (cmd/mesh-bootstrap, cmd/sovereign-node, cmd/convergence-gate)"
go build -o bin/ ./cmd/...

REGION_NAMES=(us-east-1 eu-west-1 ap-southeast-2)
REGION_IPS=(127.0.0.1 127.0.0.2 127.0.0.3)
MESH_PORT_BASE=7373
CONTROL_PORT_BASE=8443
METRICS_PORT_BASE=9100
base_count=$((NODES / ${#REGION_NAMES[@]}))
extra_count=$((NODES % ${#REGION_NAMES[@]}))
split_counts=()
regions_csv=""
for r in "${!REGION_NAMES[@]}"; do
  count=$base_count
  if (( r < extra_count )); then
    count=$((count + 1))
  fi
  split_counts+=("$count")
  if [ -n "$regions_csv" ]; then
    regions_csv+=","
  fi
  regions_csv+="${REGION_NAMES[r]}=${REGION_IPS[r]}"
done
SPLIT="$(IFS=,; printf '%s' "${split_counts[*]}")"

echo "== bootstrap: CA, $NODES node identities, peer directory, manifest -> $OUT"
./bin/mesh-bootstrap -out-dir "$OUT" \
  -regions "$regions_csv" -split "$SPLIT" -require-n "$NODES"

declare -a PIDS=() NODE_REGIONS=() NODE_IPS=() REGION_TAGS=()
declare -a MESH_PORTS=() CONTROL_PORTS=() METRICS_PORTS=()
for ((i = 0; i < NODES; i++)); do
  read -r node_index region ip port < "$OUT/node-$i/meta"
  if [ "$node_index" -ne "$i" ]; then
    echo "manifest node index $node_index does not match expected index $i" >&2
    exit 1
  fi
  local_idx=$((port - MESH_PORT_BASE))
  PIDS[i]=""
  NODE_REGIONS[i]=$region
  NODE_IPS[i]=$ip
  MESH_PORTS[i]=$port
  CONTROL_PORTS[i]=$((CONTROL_PORT_BASE + local_idx))
  METRICS_PORTS[i]=$((METRICS_PORT_BASE + local_idx))
  case "$region" in
    "${REGION_NAMES[0]}") REGION_TAGS[i]=1 ;;
    "${REGION_NAMES[1]}") REGION_TAGS[i]=2 ;;
    "${REGION_NAMES[2]}") REGION_TAGS[i]=3 ;;
    *) echo "unknown region in node-$i metadata: $region" >&2; exit 1 ;;
  esac
done

start_node() {
  local i=$1
  ./bin/sovereign-node \
    --bind "${NODE_IPS[i]}:${MESH_PORTS[i]}" \
    --control-addr "${NODE_IPS[i]}:${CONTROL_PORTS[i]}" \
    --metrics-addr "${NODE_IPS[i]}:${METRICS_PORTS[i]}" \
    --tls-cert "$OUT/node-$i/cert.pem" --tls-key "$OUT/node-$i/key.pem" --tls-ca "$OUT/ca.pem" \
    --node-id "$(cat "$OUT/node-$i/nodeid.hex")" --identity-seed "$(cat "$OUT/node-$i/seed.hex")" \
    --peer-dir "$OUT/peerdir" --peers "$(cat "$OUT/node-$i/peers.txt")" \
    --self-region "${REGION_TAGS[i]}" --region-aware \
    --wal-path "$OUT/node-$i/wal" --lsm-root "$OUT/node-$i/lsm" --arena-mib 256 \
    >> "$OUT/node-$i.log" 2>&1 &
  PIDS[i]=$!
  echo "   node $i  ${NODE_REGIONS[i]}  ${NODE_IPS[i]}:${MESH_PORTS[i]}  pid ${PIDS[i]}  (WAL $OUT/node-$i/wal)"
}
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

echo "== start $NODES nodes (durability on: WAL + LSM per node)"
for ((i = 0; i < NODES; i++)); do : > "$OUT/node-$i.log"; start_node "$i"; done

# Wait for every node to answer /livecheck (30 s budget), then give the full mesh
# up to 10 s to log NODES-1 dialed or accepted edges per node before injecting.
wait_live() {
  local i=$1 tries=0
  local address="${NODE_IPS[i]}:${METRICS_PORTS[i]}"
  until curl -s --max-time 1 "http://$address/livecheck" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -ge 300 ]; then
      echo "node $i on $address did not answer /livecheck within 30 s; last log lines:" >&2
      tail -n 5 "$OUT"/node-*.log >&2 || true
      exit 1
    fi
    sleep 0.1
  done
}
for ((i = 0; i < NODES; i++)); do wait_live "$i"; done
edges_of() { local n; n=$(grep -c -e 'mesh: dialed peer' -e 'registered inbound peer' "$1" || true); echo "${n:-0}"; }
EXPECTED_EDGES=$((NODES - 1))
ready=0
for _ in $(seq 1 40); do
  ready=1
  for ((i = 0; i < NODES; i++)); do
    [ "$(edges_of "$OUT/node-$i.log")" -ge "$EXPECTED_EDGES" ] || ready=0
  done
  [ "$ready" = 1 ] && break
  sleep 0.25
done
if [ "$ready" != 1 ]; then
  echo "mesh did not log $EXPECTED_EDGES edges per node within 10 s; the gate will check convergence" >&2
fi
grep -h -e "durability ON" -e "cold boot" "$OUT"/node-*.log | sed 's/^/   /' || true

echo "== gate: inject $KEYS keys into node 0 (${NODE_REGIONS[0]}), wait for all $NODES Merkle roots to agree"
./bin/convergence-gate -bootstrap "$OUT" -keys "$KEYS" -split "$SPLIT" -require-n "$NODES" -slo-secs 60

if [ "${CRASH:-0}" = 1 ]; then
  echo
  echo "== crash test: kill -9 node 0, then restart it on the same WAL and LSM"
  kill -9 "${PIDS[0]}"; wait "${PIDS[0]}" 2>/dev/null || true
  origin_metrics="${NODE_IPS[0]}:${METRICS_PORTS[0]}"
  if curl -s --max-time 2 "http://$origin_metrics/livecheck" >/dev/null 2>&1; then
    echo "   node 0 still answers /livecheck on $origin_metrics (unexpected)"
  else
    echo "   node 0 is dead: /livecheck on $origin_metrics gets no answer"
  fi
  T0=$(date +%s%N)
  start_node 0
  wait_live 0
  echo "   node 0 answering again after $(( ($(date +%s%N) - T0) / 1000000 )) ms"
  grep -h -e "recovery" -e "replayed" "$OUT/node-0.log" | tail -n 2 | sed 's/^/   /' || true
  sleep 1
  echo "== roots after recovery (one per region; all ${#REGION_NAMES[@]} must match)"
  ./bin/convergence-gate -bootstrap "$OUT" -split "$SPLIT" -require-n "$NODES" -merkle-only
fi

echo "== done. logs: $OUT/node-0.log through $OUT/node-$((NODES - 1)).log"
