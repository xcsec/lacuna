#!/usr/bin/env bash
# LACUNA — program-structure catalog enumeration on the nexus target.
#
#   seeds = the 121 (structure, variant, opcode) cells of
#           evaluation/spec/STRUCTURE_MANIFEST.yaml that the feasibility matrix
#           marks reachable on nexus, built by
#           prover2/machine/src/lacuna_eval.rs::structure_seeds
#   sites = every distinct static register-writeback site of each accepted
#           baseline, armed at nth = -1 (k_trace emulates twice behind one global
#           occurrence counter, so per-execution arming is unavailable here)
#   mu    = the same 11-entry instruction-independent rewriting menu the shipped
#           encoding enumeration uses, masked per site_role by the manifest's
#           mu_menu.role_masks
#
# Each candidate goes through the REAL pipeline: armed emulation -> perturbed
# record and its View -> real prove (all 55 BASE_COMPONENTS) -> real verify.
#
# This is ADDITIVE. It does not touch `lacuna_encoding_enumeration_nexus`, whose
# output is the published nexus corpus.
#
# Usage: run_nexus_structure_enumeration.sh <out_dir> [shards] [threads_per_shard]
set -uo pipefail

NEXUS=${NEXUS_DIR:-$HOME/nexus}
OUT_DIR=${1:?usage: $0 <out_dir> [shards] [threads_per_shard]}
SHARDS=${2:-4}
THREADS=${3:-6}
MU=${LACUNA_MU:-all}

# One shard per line; each line is a LACUNA_STRUCTURES value. Controls and the
# calibration are in shard 0 so a truncated run still produces the rows that make
# every other shard's REJECTs interpretable (run-matrix rule R7).
ALL_SHARDS=(
  "st_hint_advice,st_dead_write,st_initial_state,st_initial_image,st_finalize_only"
  "st_op_then_state,st_boundary_operand,st_subword_lane"
  "st_store_load,st_redirect,st_pointer_indirect,st_hazard_chain,st_fanout_read"
  "st_control_flow,st_provenance_chain,st_reg_alias,st_x0_dark_write,st_indirect_jump,st_pc_imm_value,st_pv_plumbing,st_early_exit,st_loop_repeat,st_whole_program"
)

BIN=$(ls -t "$NEXUS"/target/release/deps/nexus_vm_prover2-* 2>/dev/null \
      | grep -vE '\.(d|txt|rmeta|rlib)$' | head -1)
if [ -z "$BIN" ]; then
  echo "test binary not built; run: cd $NEXUS && cargo test -p nexus-vm-prover2 --release --no-run" >&2
  exit 1
fi
if [ "$SHARDS" -gt "${#ALL_SHARDS[@]}" ]; then
  echo "at most ${#ALL_SHARDS[@]} shards (the structure groups above)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
echo "binary : $BIN"
echo "shards : $SHARDS x $THREADS rayon threads"
echo "mu     : $MU"
date -u +"start_utc=%Y-%m-%dT%H:%M:%SZ" | tee "$OUT_DIR/run_meta.txt"
echo "shards=$SHARDS threads_per_shard=$THREADS mu=$MU" >> "$OUT_DIR/run_meta.txt"
echo "binary=$BIN" >> "$OUT_DIR/run_meta.txt"
echo "nexus_rev=$(git -C "$NEXUS" rev-parse HEAD)" >> "$OUT_DIR/run_meta.txt"
# R3: nexus has no ESTABLISHED unbound opcode, so the unbound arm of the
# deconfounding pair is the SUBSTITUTED shift family and the tag has to say so.
echo "unbound_probe=substituted" >> "$OUT_DIR/run_meta.txt"

for i in $(seq 0 $((SHARDS-1))); do
  rm -f "$OUT_DIR/struct_shard_$i.csv"
  ( cd "$NEXUS" && \
    RAYON_NUM_THREADS=$THREADS \
    LACUNA_TAG="struct_s${i}_unbound_probe=substituted" \
    LACUNA_STRUCTURES="${ALL_SHARDS[$i]}" \
    LACUNA_MU=$MU \
    LACUNA_OUT="$OUT_DIR/struct_shard_$i.csv" \
    /usr/bin/time -v "$BIN" lacuna_structure_enumeration_nexus --ignored --nocapture \
      > "$OUT_DIR/struct_shard_$i.log" 2> "$OUT_DIR/struct_shard_$i.time" ) &
done
wait

date -u +"end_utc=%Y-%m-%dT%H:%M:%SZ" >> "$OUT_DIR/run_meta.txt"
echo "done. rows:"
wc -l "$OUT_DIR"/struct_shard_*.csv | tail -1
