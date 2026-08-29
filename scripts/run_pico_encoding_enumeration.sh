#!/usr/bin/env bash
# LACUNA — complete encoding-mutation enumeration on the pico target.
#
#   sites = every distinct static register-writeback site of the accepted baseline
#           (pico fib ELF, stdin n=10), taken at its last dynamic execution
#   mu    = the 9-entry instruction-independent rewriting menu
#           (ENC-E1 x5, ENC-E2 x1, ENC-E3 x2  -> see lacuna_eval.rs::menu_all)
#
# Each candidate goes through the REAL pipeline: perturbed record -> pico's own
# witness generation (all 46 chips, all lookups on) -> real prove -> real verify.
#
# Usage: run_pico_encoding_enumeration.sh <out_dir> [shards] [threads_per_shard]
set -uo pipefail

PICO=${PICO_DIR:-$HOME/pico}
OUT_DIR=${1:?usage: $0 <out_dir> [shards] [threads_per_shard]}
SHARDS=${2:-11}
THREADS=${3:-12}
SITES=${LACUNA_SITES:-all}
MU=${LACUNA_MU:-all}

BIN=$(ls -t "$PICO"/target/release/deps/pico_vm-* 2>/dev/null \
      | grep -vE '\.(d|txt|rmeta|rlib)$' | head -1)
if [ -z "$BIN" ]; then
  echo "test binary not built; run: cd $PICO && cargo test --release -p pico-vm --lib --no-run" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
echo "binary : $BIN"
echo "shards : $SHARDS x $THREADS rayon threads"
echo "sites  : $SITES    mu: $MU"
date -u +"start_utc=%Y-%m-%dT%H:%M:%SZ" | tee "$OUT_DIR/run_meta.txt"
echo "shards=$SHARDS threads_per_shard=$THREADS sites=$SITES mu=$MU" >> "$OUT_DIR/run_meta.txt"
echo "binary=$BIN" >> "$OUT_DIR/run_meta.txt"
echo "pico_rev=$(git -C "$PICO" rev-parse HEAD)" >> "$OUT_DIR/run_meta.txt"

for i in $(seq 0 $((SHARDS-1))); do
  rm -f "$OUT_DIR/enc_shard_$i.csv"
  ( cd "$PICO" && \
    RAYON_NUM_THREADS=$THREADS \
    LACUNA_TAG="enc_s$i" \
    LACUNA_SITES=$SITES \
    LACUNA_MU=$MU \
    LACUNA_SHARD="$i/$SHARDS" \
    LACUNA_OUT="$OUT_DIR/enc_shard_$i.csv" \
    /usr/bin/time -v "$BIN" lacuna_encoding_enumeration --ignored --nocapture \
      > "$OUT_DIR/enc_shard_$i.log" 2> "$OUT_DIR/enc_shard_$i.time" ) &
done
wait

date -u +"end_utc=%Y-%m-%dT%H:%M:%SZ" >> "$OUT_DIR/run_meta.txt"
echo "done. rows:"
wc -l "$OUT_DIR"/enc_shard_*.csv | tail -1
