#!/usr/bin/env bash
# LACUNA — per-stage CPU/wall calibration on the pico target.  BOTH modes.
#
# SERIAL: exactly one candidate in flight at a time.  One process per (mode, seed),
# processes run one after another (no `&`), and inside a process the enumeration
# loop is a plain sequential for-loop over candidates.  libtest is given
# --test-threads 1 as well.  The prover's internal rayon pool is left at the same
# width the original enumeration used (RAYON_NUM_THREADS=10, see
# data/runs/pico_seeds/run_meta.txt "shards=12 threads=10") so that the
# CPU/wall ratio is comparable with the original .time files.
#
# The per-stage probes are the additive, default-OFF LACUNA stage accounting in
# vm/src/machine/lacuna_stage.rs; they switch on only because LACUNA_CPU_CSV is set.
#
# Cross-check design: every worker process is wrapped in its own `/usr/bin/time -v`
# and the whole driver is wrapped in one more.  The per-candidate CPU sum is then
# compared PER PROCESS against that process's own User+System (the earlier attempt
# compared an 8-process candidate sum against a 6-process .time sum, which is what
# made the ratio exceed 1).
set -uo pipefail

PICO=${PICO_DIR:-$HOME/pico}
GUESTS=${LACUNA_GUESTS:-$(cd "$(dirname "$0")/../guests/lacuna_seeds/elf" && pwd)}
OUT_DIR=${1:?usage: $0 <out_dir>}
CPU_CSV=${LACUNA_CPU_CSV:-$PWD/pico_cpu_calibration.csv}

BIN=$PICO/target/release/deps/pico_vm-4d3bf33dc4ffd6a6
[ -x "$BIN" ] || { echo "test binary missing: $BIN" >&2; exit 1; }

mkdir -p "$OUT_DIR" "$(dirname "$CPU_CSV")"
rm -f "$CPU_CSV"

export RAYON_NUM_THREADS=10
export LACUNA_CPU_CSV="$CPU_CSV"

date -u +"cal_start_utc=%Y-%m-%dT%H:%M:%SZ" | tee "$OUT_DIR/cal_meta.txt"
echo "binary=$BIN"            >> "$OUT_DIR/cal_meta.txt"
echo "rayon_num_threads=10"   >> "$OUT_DIR/cal_meta.txt"
echo "pico_rev=$(git -C $PICO rev-parse HEAD)" >> "$OUT_DIR/cal_meta.txt"
echo "nproc=$(nproc) clk_tck=$(getconf CLK_TCK)" >> "$OUT_DIR/cal_meta.txt"

# ---- 1-minute load average sampled every 10 s, for the contention report ----
( while :; do echo "$(date -u +%H:%M:%S) $(cut -d' ' -f1-3 /proc/loadavg)"; sleep 10; done ) \
  > "$OUT_DIR/loadavg.txt" &
LOADPID=$!
trap 'kill $LOADPID 2>/dev/null' EXIT

# ---------------- encoding ----------------
# seed | elf | stdin | structure | opcodes | pc_lo | pc_hi | site_limit
ENC_JOBS=(
 "op_srlw|op_srlw|0x123456789ABCDEF0,13|Single operation|SRLW|0x200bb8|0x200cfc|99"
 "op_sraw|op_sraw|0x123456789ABCDEF0,13|Single operation|SRAW|0x200bb8|0x200cfc|99"
 "op_srliw|op_srliw|0x123456789ABCDEF0,13|Single operation|SRLW|0x200bb8|0x200cf4|99"
 "op_mul|op_mul|0x123456789ABCDEF0,13|Single operation|MUL|0x200bb8|0x200d50|99"
 "op_div|op_div|0x123456789ABCDEF0,13|Single operation|DIV|0x200bb8|0x200d64|99"
 "op_xor|op_xor|0x123456789ABCDEF0,13|Single operation|XOR|0x200bb8|0x200d50|99"
 "op_slt|op_slt|0x123456789ABCDEF0,13|Single operation|SLT|0x200bb8|0x200d50|99"
 "st_initial_state|st_initial_state|0|Initial state|LD|0x200bb8|0x200c40|99"
)
for j in "${ENC_JOBS[@]}"; do
  IFS='|' read -r seed elf stdin struct ops lo hi lim <<< "$j"
  tag="CAL_E_$seed"
  rm -f "$OUT_DIR/$tag.csv"
  echo "[enc] $seed $(date -u +%H:%M:%S)"
  ( cd "$PICO" && /usr/bin/time -v -o "$OUT_DIR/$tag.time" \
    env LACUNA_SEED_ID="$seed" LACUNA_STRUCT="$struct" LACUNA_STDIN="$stdin" \
        LACUNA_ELF="$GUESTS/$elf" LACUNA_TAG="$tag" \
        LACUNA_MU=all LACUNA_SITES=ops LACUNA_OPS="$ops" \
        LACUNA_PC_LO="$lo" LACUNA_PC_HI="$hi" LACUNA_LIMIT="$lim" \
        LACUNA_OUT="$OUT_DIR/$tag.csv" \
    "$BIN" lacuna_encoding_enumeration --ignored --nocapture --test-threads 1 \
      > "$OUT_DIR/$tag.log" 2>&1 )
  echo "[enc] $seed rc=$?"
done

# ---------------- binding ----------------
# The reported dataset's B_* stage covers exactly these 5 seeds (run_lacuna_pico.py
# SEEDS[...] with run-binding=True).  LACUNA_LIMIT caps SITES; each site yields two
# candidates (bind_o1_swap = BIND-O1, neg_control_no_swap = BIND-V3), so LIMIT=6
# gives 12 candidates per seed = 60 binding candidates.
# seed | elf ("FIB" = the fibonacci ELF checked into the pico tree) | stdin | structure | site_limit
BIND_JOBS=(
 "st_store_load|st_store_load|0x1111111111111111,0x2222222222222222|Store--load|6"
 "st_store_load_tail|st_store_load_tail|0x1111111111111111,0x2222222222222222,0x3333333333333333|Store--load|6"
 "st_redirect|st_redirect|0x1111111111111111,0x2222222222222222|Redirect|6"
 "st_initial_state|st_initial_state|0|Initial state|6"
 "fib|FIB|10|Whole program|6"
)
for j in "${BIND_JOBS[@]}"; do
  IFS='|' read -r seed elf stdin struct lim <<< "$j"
  tag="CAL_B_$seed"
  rm -f "$OUT_DIR/$tag.csv"
  echo "[bind] $seed $(date -u +%H:%M:%S)"
  if [ "$elf" = "FIB" ]; then
    ELFARG=()          # no LACUNA_ELF -> driver default = pico's fibonacci ELF
  else
    ELFARG=("LACUNA_ELF=$GUESTS/$elf")
  fi
  ( cd "$PICO" && /usr/bin/time -v -o "$OUT_DIR/$tag.time" \
    env LACUNA_SEED_ID="$seed" LACUNA_STRUCT="$struct" LACUNA_STDIN="$stdin" \
        "${ELFARG[@]}" LACUNA_TAG="$tag" LACUNA_LIMIT="$lim" \
        LACUNA_OUT="$OUT_DIR/$tag.csv" \
    "$BIN" lacuna_binding_enumeration --ignored --nocapture --test-threads 1 \
      > "$OUT_DIR/$tag.log" 2>&1 )
  echo "[bind] $seed rc=$?"
done

# ---------------- CPU/wall control ----------------
# The SAME encoding candidate set as job [enc] op_srlw, but with the stage probes
# OFF (LACUNA_CPU_CSV unset).  That restores the unmodified driver exactly: the
# chunk-level rayon parallelism is back and no /proc/self/stat is read.  Its .time
# file gives today's CPU/wall ratio for the UNMODIFIED driver on this (shared)
# machine, which is what the instrumented ratio has to be compared against.
echo "[ctl] op_srlw (probes OFF) $(date -u +%H:%M:%S)"
( cd "$PICO" && /usr/bin/time -v -o "$OUT_DIR/CAL_CTL_op_srlw.time" \
  env -u LACUNA_CPU_CSV \
      LACUNA_SEED_ID=op_srlw LACUNA_STRUCT="Single operation" \
      LACUNA_STDIN="0x123456789ABCDEF0,13" \
      LACUNA_ELF="$GUESTS/op_srlw" LACUNA_TAG=CAL_CTL_op_srlw \
      LACUNA_MU=all LACUNA_SITES=ops LACUNA_OPS=SRLW \
      LACUNA_PC_LO=0x200bb8 LACUNA_PC_HI=0x200cfc \
      LACUNA_OUT="$OUT_DIR/CAL_CTL_op_srlw.csv" \
  "$BIN" lacuna_encoding_enumeration --ignored --nocapture --test-threads 1 \
    > "$OUT_DIR/CAL_CTL_op_srlw.log" 2>&1 )
echo "[ctl] rc=$?"

# same control, for the BINDING driver
echo "[ctl] bind st_store_load (probes OFF) $(date -u +%H:%M:%S)"
( cd "$PICO" && /usr/bin/time -v -o "$OUT_DIR/CAL_CTL_bind_st_store_load.time" \
  env -u LACUNA_CPU_CSV \
      LACUNA_SEED_ID=st_store_load LACUNA_STRUCT="Store--load" \
      LACUNA_STDIN="0x1111111111111111,0x2222222222222222" \
      LACUNA_ELF="$GUESTS/st_store_load" LACUNA_TAG=CAL_CTL_bind_st_store_load \
      LACUNA_LIMIT=6 \
      LACUNA_OUT="$OUT_DIR/CAL_CTL_bind_st_store_load.csv" \
  "$BIN" lacuna_binding_enumeration --ignored --nocapture --test-threads 1 \
    > "$OUT_DIR/CAL_CTL_bind_st_store_load.log" 2>&1 )
echo "[ctl] rc=$?"

date -u +"cal_end_utc=%Y-%m-%dT%H:%M:%SZ" >> "$OUT_DIR/cal_meta.txt"
echo "rows: $(( $(grep -c "" "$CPU_CSV") - 1 ))"
