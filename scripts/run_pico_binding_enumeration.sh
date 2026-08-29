#!/usr/bin/env bash
# LACUNA — generic BIND-O1 (store--load timestamp) enumeration on the pico target.
#
#   sites   = every static LD site of the accepted baseline whose pc executes exactly
#             once (so the pc identifies the memory row uniquely)
#   variant = {bind_o1_swap, neg_control_no_swap}
#
# Usage: run_pico_binding_enumeration.sh <out_dir> [shards] [threads_per_shard]
set -uo pipefail

PICO=${PICO_DIR:-$HOME/pico}
OUT_DIR=${1:?usage: $0 <out_dir> [shards] [threads_per_shard]}
SHARDS=${2:-4}
THREADS=${3:-8}

BIN=$(ls -t "$PICO"/target/release/deps/pico_vm-* 2>/dev/null \
      | grep -vE '\.(d|txt|rmeta|rlib)$' | head -1)
[ -n "$BIN" ] || { echo "test binary not built" >&2; exit 1; }

mkdir -p "$OUT_DIR"
date -u +"start_utc=%Y-%m-%dT%H:%M:%SZ" | tee "$OUT_DIR/run_meta.txt"
echo "shards=$SHARDS threads_per_shard=$THREADS" >> "$OUT_DIR/run_meta.txt"
echo "binary=$BIN" >> "$OUT_DIR/run_meta.txt"
echo "pico_rev=$(git -C "$PICO" rev-parse HEAD)" >> "$OUT_DIR/run_meta.txt"

for i in $(seq 0 $((SHARDS-1))); do
  rm -f "$OUT_DIR/bind_shard_$i.csv"
  ( cd "$PICO" && \
    RAYON_NUM_THREADS=$THREADS \
    LACUNA_TAG="bind_s$i" \
    LACUNA_SHARD="$i/$SHARDS" \
    LACUNA_OUT="$OUT_DIR/bind_shard_$i.csv" \
    /usr/bin/time -v "$BIN" lacuna_binding_enumeration --ignored --nocapture \
      > "$OUT_DIR/bind_shard_$i.log" 2> "$OUT_DIR/bind_shard_$i.time" ) &
done
wait
date -u +"end_utc=%Y-%m-%dT%H:%M:%SZ" >> "$OUT_DIR/run_meta.txt"
wc -l "$OUT_DIR"/bind_shard_*.csv | tail -1
