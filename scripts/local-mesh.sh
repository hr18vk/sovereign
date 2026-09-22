#!/usr/bin/env bash
# Copyright 2026 Harsh Rawat
#
# Use of this software is governed by the Business Source License 1.1,
# which can be found in the LICENSE file. Production use requires a written
# grant from the Licensor until the Change Date (2029-08-15).

# Sovereign Engine — a three-node mesh on one machine.
#
# Three sovereign-node processes, three loopback addresses standing in for three
# regions, one convergence-gate client. Everything here is the public tooling:
# cmd/mesh-bootstrap (CA, node identities, peer directory), cmd/sovereign-node and
# cmd/convergence-gate. No fleet, no cloud account, no private script. The manual
# version of this bring-up is docs/SOVEREIGN_ENGINE_REFERENCE.md §6.7.
#
#   ./scripts/local-mesh.sh            # build, bootstrap, start 3 nodes, inject, gate
#   CRASH=1 ./scripts/local-mesh.sh    # ...then kill -9 the origin node, restart it on
#                                      # the same WAL, show the three roots agree again
#   KEYS=500 ./scripts/local-mesh.sh   # fewer keys
#   OUT=/path ./scripts/local-mesh.sh  # keep the CA, WALs and logs somewhere specific
#
# KEYS defaults to 1000. A fresh receiver admits inbound DotCounters up to its
# Lamport clock + 1000 (the Lamport skew bound, pkg/sync/crdt_reconstruct_skew.go).
# One burst of more than ~1000 keys into a brand-new three-node mesh can therefore
# be rejected in whole batches and never ratchet the receivers forward. The 100-node
# runs stream 10,000 keys through the fleet and do not hit this; the single-box smoke
# test does. Keep KEYS at or below 1000 here.
#
# Needs: Go 1.26.1, a C toolchain, libjemalloc-dev, Linux. Ports 7373, 8443 and 9100
# on 127.0.0.1, 127.0.0.2 and 127.0.0.3 must be free (Linux routes the whole 127/8
# block to lo, so the two extra loopback addresses need no setup).
# The exit status is the convergence gate's verdict: 0 on PASS.

set -euo pipefail

case "${1:-}" in
  -h|--help)
    cat <<USAGE
sovereign local mesh — three nodes, three loopback regions, one gate
  KEYS=N     keys to inject into node 0 (default 1000; keep at or below 1000, see the header)
  CRASH=1    after the gate passes, kill -9 node 0, restart it on its WAL, compare the roots
  OUT=DIR    working directory for the CA, identities, WALs and logs (default: mktemp under /tmp)
USAGE
    exit 0 ;;
  "") ;;
  *) echo "unknown flag: $1 (this script is driven by KEYS, CRASH and OUT)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS="${KEYS:-1000}"
OUT="${OUT:-$(mktemp -d /tmp/sovereign-mesh3.XXXXXX)}"
mkdir -p "$OUT"
cd "$ROOT"

echo "== build (cmd/mesh-bootstrap, cmd/sovereign-node, cmd/convergence-gate)"
go build -o bin/ ./cmd/...

echo "== bootstrap: CA, three node identities, peer directory, manifest -> $OUT"
./bin/mesh-bootstrap -out-dir "$OUT" \
  -regions us-east-1=127.0.0.1,eu-west-1=127.0.0.2,ap-southeast-2=127.0.0.3 \
  -split 1,1,1 -require-n 3

declare -a PIDS=("" "" "")
start_node() {
  local i=$1 region ip port
  read -r _ region ip port < "$OUT/node-$i/meta"
  ./bin/sovereign-node \
    --bind "$ip:$port" --control-addr "$ip:8443" --metrics-addr "$ip:9100" \
    --tls-cert "$OUT/node-$i/cert.pem" --tls-key "$OUT/node-$i/key.pem" --tls-ca "$OUT/ca.pem" \
    --node-id "$(cat "$OUT/node-$i/nodeid.hex")" --identity-seed "$(cat "$OUT/node-$i/seed.hex")" \
    --peer-dir "$OUT/peerdir" --peers "$(cat "$OUT/node-$i/peers.txt")" \
    --self-region $((i + 1)) --region-aware \
    --wal-path "$OUT/node-$i/wal" --lsm-root "$OUT/node-$i/lsm" --arena-mib 256 \
    >> "$OUT/node-$i.log" 2>&1 &
  PIDS[i]=$!
  echo "   node $i  $region  $ip:$port  pid ${PIDS[i]}  (WAL $OUT/node-$i/wal)"
}
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

echo "== start three nodes (durability on: WAL + LSM per node)"
for i in 0 1 2; do : > "$OUT/node-$i.log"; start_node "$i"; done

# Wait for every node to answer /livecheck (30 s budget), then give the mesh up to
# 10 s to show two live edges per node (dialed or accepted), before injecting anything.
wait_live() {
  local ip=$1 tries=0
  until curl -s --max-time 1 "http://$ip:9100/livecheck" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -ge 300 ]; then
      echo "node on $ip did not answer /livecheck within 30 s; last log lines:" >&2
      tail -n 5 "$OUT"/node-*.log >&2 || true
      exit 1
    fi
    sleep 0.1
  done
}
for ip in 127.0.0.1 127.0.0.2 127.0.0.3; do wait_live "$ip"; done
edges_of() { local n; n=$(grep -c -e 'mesh: dialed peer' -e 'registered inbound peer' "$1" || true); echo "${n:-0}"; }
for _ in $(seq 1 40); do
  ready=1
  for i in 0 1 2; do [ "$(edges_of "$OUT/node-$i.log")" -ge 2 ] || ready=0; done
  [ "$ready" = 1 ] && break
  sleep 0.25
done
grep -h -e "durability ON" -e "cold boot" "$OUT"/node-*.log | sed 's/^/   /' || true

echo "== gate: inject $KEYS keys into node 0 (us-east-1), wait for all three Merkle roots to agree"
./bin/convergence-gate -bootstrap "$OUT" -keys "$KEYS" -split 1,1,1 -require-n 3 -slo-secs 60

if [ "${CRASH:-0}" = 1 ]; then
  echo
  echo "== crash test: kill -9 node 0, then restart it on the same WAL and LSM"
  kill -9 "${PIDS[0]}"; wait "${PIDS[0]}" 2>/dev/null || true
  if curl -s --max-time 2 http://127.0.0.1:9100/livecheck >/dev/null 2>&1; then
    echo "   node 0 still answers /livecheck (unexpected)"
  else
    echo "   node 0 is dead: /livecheck on 127.0.0.1:9100 gets no answer"
  fi
  T0=$(date +%s%N)
  start_node 0
  wait_live 127.0.0.1
  echo "   node 0 answering again after $(( ($(date +%s%N) - T0) / 1000000 )) ms"
  grep -h -e "recovery" -e "replayed" "$OUT/node-0.log" | tail -n 2 | sed 's/^/   /' || true
  sleep 1
  echo "== roots after recovery (one per region; all three must match)"
  ./bin/convergence-gate -bootstrap "$OUT" -split 1,1,1 -require-n 3 -merkle-only
fi

echo "== done. logs: $OUT/node-{0,1,2}.log"
