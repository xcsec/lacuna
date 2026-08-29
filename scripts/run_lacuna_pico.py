#!/usr/bin/env python3
"""LACUNA — driver for the pico target.

Runs the mutation enumeration over the seed corpus and writes one CSV per
(seed, stage, shard) under <out_dir>/.  Nothing here decides what a bug is; it
only schedules the enumeration and records raw per-candidate rows.

Stages
------
E1  encoding, site-complete:  every static writeback site of the seed's target
    opcode(s), one template (ENC-E3 bit 0).  This is the *localization* pass: a
    site is on the committed-output dataflow iff its ENC-E3 probe changes the
    committed output.  The decision is mechanical, not hand-made.
E2  encoding, template-complete:  the full 9-entry template menu at every site
    that E1 marked as being on the committed-output dataflow.
B   binding (BIND-O1 store--load timestamp): every static LD site whose pc
    executes exactly once, run twice (mutation + negative control).

Usage:
  run_lacuna_pico.py <out_dir> [--stages E1,E2,B] [--seeds a,b,...]
                     [--shards N] [--threads N] [--set published|wave2|all]

Seed sets
---------
`--set published` schedules exactly the frozen 38-seed corpus behind the published
numbers; `--set wave2` schedules only the additive structure coverage; `all` (the
default) schedules both.  Wave-2 rows never edit a published row: they are new
seed_ids, some pointing at new guest ELFs and some re-running a frozen ELF with a
different stdin or a wider opcode filter.  Their structure_id / variant /
operand_source / candidate_class are written into run_meta.txt, because the CSV
column set is frozen.
"""
import argparse
import csv
import os
import shutil
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

PICO = os.environ.get("PICO_DIR") or os.path.expanduser("~/pico")
GUESTS = os.environ.get("LACUNA_GUESTS") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guests", "lacuna_seeds", "elf")
REV = "22b0aae6321c1f63c72aafd0b506b5f45b91ffb1"

A = "0x123456789ABCDEF0"
B = "13"
V1 = "0x1111111111111111"
V2 = "0x2222222222222222"
V3 = "0x3333333333333333"

# name -> (elf, stdin, program_structure, target opcodes, run binding?)
SEEDS = {
    # ---- Single operation, one concrete opcode each -------------------------
    "op_add":   ("op_add",   f"{A},{B}", "Single operation", "ADD",   False),
    "op_sub":   ("op_sub",   f"{A},{B}", "Single operation", "SUB",   False),
    "op_xor":   ("op_xor",   f"{A},{B}", "Single operation", "XOR",   False),
    "op_or":    ("op_or",    f"{A},{B}", "Single operation", "OR",    False),
    "op_and":   ("op_and",   f"{A},{B}", "Single operation", "AND",   False),
    "op_sll":   ("op_sll",   f"{A},{B}", "Single operation", "SLL",   False),
    "op_srl":   ("op_srl",   f"{A},{B}", "Single operation", "SRL",   False),
    "op_sra":   ("op_sra",   f"{A},{B}", "Single operation", "SRA",   False),
    "op_slt":   ("op_slt",   f"{A},{B}", "Single operation", "SLT",   False),
    "op_sltu":  ("op_sltu",  f"{A},{B}", "Single operation", "SLTU",  False),
    "op_mul":   ("op_mul",   f"{A},{B}", "Single operation", "MUL",   False),
    "op_mulh":  ("op_mulh",  f"{A},{B}", "Single operation", "MULH",  False),
    "op_mulhu": ("op_mulhu", f"{A},{B}", "Single operation", "MULHU", False),
    "op_div":   ("op_div",   f"{A},{B}", "Single operation", "DIV",   False),
    "op_divu":  ("op_divu",  f"{A},{B}", "Single operation", "DIVU",  False),
    "op_rem":   ("op_rem",   f"{A},{B}", "Single operation", "REM",   False),
    "op_remu":  ("op_remu",  f"{A},{B}", "Single operation", "REMU",  False),
    "op_addw":  ("op_addw",  f"{A},{B}", "Single operation", "ADDW",  False),
    "op_subw":  ("op_subw",  f"{A},{B}", "Single operation", "SUBW",  False),
    "op_sllw":  ("op_sllw",  f"{A},{B}", "Single operation", "SLLW",  False),
    "op_srlw":  ("op_srlw",  f"{A},{B}", "Single operation", "SRLW",  False),
    "op_sraw":  ("op_sraw",  f"{A},{B}", "Single operation", "SRAW",  False),
    "op_mulw":  ("op_mulw",  f"{A},{B}", "Single operation", "MULW",  False),
    "op_divw":  ("op_divw",  f"{A},{B}", "Single operation", "DIVW",  False),
    "op_divuw": ("op_divuw", f"{A},{B}", "Single operation", "DIVUW", False),
    "op_remw":  ("op_remw",  f"{A},{B}", "Single operation", "REMW",  False),
    "op_remuw": ("op_remuw", f"{A},{B}", "Single operation", "REMUW", False),
    "op_addi":  ("op_addi",  f"{A},{B}", "Single operation", "ADD",   False),
    "op_slli":  ("op_slli",  f"{A},{B}", "Single operation", "SLL",   False),
    "op_srli":  ("op_srli",  f"{A},{B}", "Single operation", "SRL",   False),
    "op_srliw": ("op_srliw", f"{A},{B}", "Single operation", "SRLW",  False),
    # ---- state-interaction structures --------------------------------------
    "st_store_load":      ("st_store_load",      f"{V1},{V2}",      "Store--load",   "LD", True),
    "st_store_load_tail": ("st_store_load_tail", f"{V1},{V2},{V3}", "Store--load",   "LD", True),
    "st_hazard_chain":    ("st_hazard_chain",    f"{V1},{V2}",      "Hazard chain",  "ADD", False),
    "st_redirect":        ("st_redirect",        f"{V1},{V2}",      "Redirect",      "LD", True),
    "st_control_flow":    ("st_control_flow",    f"1,{V1},{V2}",    "Control flow",  "ADD,LD", False),
    "st_initial_state":   ("st_initial_state",   "0",               "Initial state", "LD", True),
    # ---- realistic whole program -------------------------------------------
    "fib":                (None,                 "10",              "Whole program", "ALL", True),
}

# The 38 rows above are the PUBLISHED corpus: their seed_id, ELF, stdin, structure
# label and opcode filter are frozen, and every number in the paper was produced by
# running exactly them.  Nothing below changes any of them.
PUBLISHED_SEEDS = tuple(SEEDS)

# =========================================================================
# WAVE 2 — additive structure coverage.
#
# Source of truth: evaluation/spec/STRUCTURE_MANIFEST.yaml (per-structure
# `targets[target == pico]`) and evaluation/spec/TARGET_CAPABILITIES.yaml.
# Every row below is a NEW seed_id; no published row is edited.
#
# WHY THE OPCODE COLUMN MATTERS HERE (run_matrix_rules R1-R4).  Five of the seven
# published structures were pinned to ADD and LD -- opcodes pico binds correctly --
# while all 24 encoding accepted cases sit on SRLW/SRAW, which only the
# Single-operation seeds reach.  Structure and opcode never varied independently, so
# "four structures found nothing" is not evidence about those structures.
#
# Simply widening LACUNA_OPS on the published state-interaction rows cannot fix that,
# and this was checked rather than assumed: disassembling `main` in the five shipped
# state-interaction ELFs finds NO W-form shift at all
# (st_store_load: ld/sd/lbu/slli/or/addi/auipc/jalr/lui/bgeu; likewise the others).
# There is no SRLW site to enumerate.  So wave 2 does two separate things:
#   (a) *_wops rows re-run the frozen ELFs with an opcode filter widened to the
#       opcodes their `main` actually contains (SLL/OR/LBU from the read_as byte
#       assembly), which the published ops=ADD / ops=LD rows never enumerated; and
#   (b) the st_op_then_state guests put SRLW/SRAW/SRLIW *and* ADD inside one `main`
#       in front of a state interaction, which is the shape that makes structure and
#       opcode vary independently for real.
# =========================================================================

V1B = "0x1B1B1B1B1B1B1B1B"   # second write to SLOT1, arms the stale-load guard
CC = "0x0F0F0F0F0F0F0F0F"    # third operand of the provenance chains
INTMIN1 = "0x8000000000000001"   # INT_MIN + 1, one mu-step from the DIV overflow case
NEG1 = "0xFFFFFFFFFFFFFFFF"

# R2 deconfounding pair: one opcode from alu_bound_reference plus the whole of
# pico's established target_unbound_probe set (TARGET_CAPABILITIES
# known_unbound_opcodes = SRLW, SRAW, SRLIW; SRLIW decodes to Opcode::SRLW).
OPS_DECONF = "ADD,SRLW,SRAW"
# The opcodes the read_as byte assembly actually leaves in `main` on every seed.
OPS_INPUT_PATH = "LD,SLL,OR,LBU"

WAVE2_SEEDS = {
    # -- st_op_then_state -- the deconfounding shape (manifest priority: must) -----
    "ots_mem":    ("st_op_then_state_mem",    f"{A},{B}", "Operation then state",
                   f"{OPS_DECONF},LD", True),
    "ots_addr":   ("st_op_then_state_addr",   f"{A},{B}", "Operation then state",
                   f"{OPS_DECONF},LD,SRL", False),
    "ots_branch": ("st_op_then_state_branch", f"{A},{B}", "Operation then state",
                   OPS_DECONF, False),

    # -- st_boundary_operand ------------------------------------------------------
    # The operand sits one mu-step from a constraint discontinuity, so the mutation
    # drives an AIR-derived SELECTOR (is_zero, the shift decomposition, the INT_MIN
    # special case) instead of an AIR-derived value.
    "bd_zero":     ("bd_div",   f"{A},1",   "Boundary operand", "LD,DIVU,REMU", False),
    "bd_exactdiv": ("bd_div",   "8,2",      "Boundary operand", "LD,DIVU,REMU", False),
    "bd_evenrem":  ("bd_div",   "10,6",     "Boundary operand", "LD,DIVU,REMU", False),
    "bd_intmin":   ("bd_sdiv",  f"{INTMIN1},{NEG1}", "Boundary operand",
                    "LD,DIV,REM", False),
    "bd_shamt":    ("bd_shift", f"{A},1",   "Boundary operand",
                    "LD,SLL,SRL,SRA,SLLW,SRLW,SRAW", False),
    # Limb / sign boundaries need no new guest: same frozen ELF, boundary stdin.
    "bd_limb":     ("op_add",   "0x7FFFFFFF,1",          "Boundary operand", "ADD,LD", False),
    "bd_limb16":   ("op_add",   "0xFFFF,1",              "Boundary operand", "ADD,LD", False),
    "bd_limbmax":  ("op_mul",   "0xFFFFFFFF,0xFFFFFFFF", "Boundary operand", "MUL,LD", False),
    "bd_limbmaxh": ("op_mulhu", "0xFFFFFFFF,0xFFFFFFFF", "Boundary operand", "MULHU,LD", False),

    # -- st_subword_lane ----------------------------------------------------------
    "sw_lane_load":  ("sw_lane_load",  f"{A},{B}", "Sub-word lane",
                      "LB,LBU,LH,LHU,LW,LWU,LD", True),
    "sw_lane_store": ("sw_lane_store", f"{A},{B}", "Sub-word lane", "LD,ADD", False),

    # -- st_redirect (binding-armed twin; the shipped seed stays untouched) --------
    "st_redirect_armed": ("st_redirect_armed", f"{V1},{V1B},{V2}", "Redirect",
                          "ADD,AUIPC,LD", True),

    # -- st_pointer_indirect ------------------------------------------------------
    "st_pointer_indirect": ("st_pointer_indirect", f"{V1},{V2}", "Pointer indirect",
                            "LD,ADD,AUIPC", True),

    # -- st_provenance_chain ------------------------------------------------------
    "pv_chain2": ("pv_chain2", f"{A},{B},{CC}", "Provenance chain",
                  "SRLW,SRAW,ADD,MUL,LD", False),
    "pv_chain4": ("pv_chain4", f"{A},{B},{CC}", "Provenance chain",
                  "SRLW,SRAW,ADD,MUL,LD", True),

    # -- st_loop_repeat -- one static pc, N dynamic write-backs -------------------
    "lp_n16":   ("lp_accum", f"{A},16",   "Loop repeat", "ADD", False),
    "lp_n256":  ("lp_accum", f"{A},256",  "Loop repeat", "ADD", False),
    "lp_n4096": ("lp_accum", f"{A},4096", "Loop repeat", "ADD", False),

    # -- st_multishard -- store in chunk i, load in chunk j > i -------------------
    "ms_carry": ("ms_carry", f"{A},4000", "Cross-shard continuation", "ADD,MUL,LD", False),

    # -- st_hint_advice -- CALIBRATION, expected ACCEPT, never a bug count ---------
    "hint_passthrough": ("hint_passthrough", A, "Nondeterministic advice",
                         f"{OPS_INPUT_PATH},ADD", False),
    "hint_checked":     ("hint_checked", "3,9", "Nondeterministic advice",
                         f"{OPS_INPUT_PATH},MUL", False),

    # -- st_indirect_jump ---------------------------------------------------------
    "ij_table": ("ij_table", "1", "Indirect jump", "ADD,LD,JALR", False),
    "ij_bit0":  ("ij_table", "1", "Indirect jump", "ADD,LD,JALR", False),

    # -- st_pc_imm_value -- LUI decodes to Opcode::ADD (rrs.rs:328-332) ------------
    "pc_imm": ("pc_imm", A, "PC-immediate value", "AUIPC,ADD,JAL", False),

    # -- st_fanout_read -----------------------------------------------------------
    "fanout": ("fanout", f"{A},{B}", "Fan-out read", "ADD,SRLW,XOR,LD", False),

    # -- st_reg_alias -------------------------------------------------------------
    "reg_alias":    ("reg_alias",    f"{A},{B}", "Register aliasing", "ADD,MUL,MULW", False),
    "reg_alias_rd": ("reg_alias_rd", f"{A},{B}", "Register aliasing", "ADD,MUL", False),

    # -- st_pv_plumbing -----------------------------------------------------------
    "pv_eight": ("pv_eight", f"{A},{B}", "Public-value plumbing", "ADD,XOR,LD", False),
    "pv_alias": ("pv_alias", f"{V1},{V2}", "Public-value plumbing", "LD,ADD", False),

    # -- st_early_exit -- see the note in STRUCTURE_META: unfalsifiable under the
    #    frozen accepted_case_strict predicate; score under accepted_case_v2 --------
    "ee_truncate": ("ee_truncate", f"0,{A},{B}", "Early exit", "LD,ADD", False),

    # -- st_finalize_only -- DECLARED NEGATIVE CONTROL, excluded from coverage -----
    "fo_sink": ("fo_sink", f"{A},{B}", "Finalize-only write", "ADD,SRLW,XOR,LD", False),

    # -- st_precompile -- SHA_EXTEND, the first accelerator chip LACUNA touches ----
    "pc_sha_extend": ("pc_sha_extend", A, "Precompile boundary", "MUL,AND,ADD,LD", False),

    # -- (a) above: the frozen ELFs, re-run with the opcode filter widened to the
    #    opcodes their `main` really contains.  New seed_ids, so the published rows
    #    and their outcomes are untouched.
    "st_store_load_wops":      ("st_store_load",      f"{V1},{V2}",      "Store--load",
                                f"ADD,{OPS_INPUT_PATH}", False),
    "st_store_load_tail_wops": ("st_store_load_tail", f"{V1},{V2},{V3}", "Store--load",
                                f"ADD,{OPS_INPUT_PATH}", False),
    "st_hazard_chain_wops":    ("st_hazard_chain",    f"{V1},{V2}",      "Hazard chain",
                                f"ADD,{OPS_INPUT_PATH}", False),
    "st_redirect_wops":        ("st_redirect",        f"{V1},{V2}",      "Redirect",
                                f"ADD,{OPS_INPUT_PATH}", False),
    "st_control_flow_wops":    ("st_control_flow",    f"1,{V1},{V2}",    "Control flow",
                                f"ADD,{OPS_INPUT_PATH}", False),
    "st_initial_state_wops":   ("st_initial_state",   "0",               "Initial state",
                                f"ADD,{OPS_INPUT_PATH}", False),
}
SEEDS.update(WAVE2_SEEDS)

# Structure identity for the wave-2 rows, as spec data rather than driver logic:
#   seed_id -> (structure_id, variant, operand_source, candidate_class)
# The CSV column set is frozen, so this is emitted into run_meta.txt instead and the
# join is done downstream.  operand_source is `input` everywhere on pico: LACUNA_STDIN
# is bincode-serialised into the guest's stdin and pulled with read_as::<u64>(); no
# operand is baked into the vk-committed program as an immediate.
STRUCTURE_META = {
    "ots_mem":    ("st_op_then_state", "mem",    "input", "probe"),
    "ots_addr":   ("st_op_then_state", "addr",   "input", "probe"),
    "ots_branch": ("st_op_then_state", "branch", "input", "probe"),
    "bd_zero":     ("st_boundary_operand", "zero",     "input", "probe"),
    "bd_exactdiv": ("st_boundary_operand", "exactdiv", "input", "probe"),
    "bd_evenrem":  ("st_boundary_operand", "exactdiv", "input", "probe"),
    "bd_intmin":   ("st_boundary_operand", "intmin",   "input", "probe"),
    "bd_shamt":    ("st_boundary_operand", "shamt",    "input", "probe"),
    "bd_limb":     ("st_boundary_operand", "limb",     "input", "probe"),
    "bd_limb16":   ("st_boundary_operand", "limb",     "input", "probe"),
    "bd_limbmax":  ("st_boundary_operand", "limbmax",  "input", "probe"),
    "bd_limbmaxh": ("st_boundary_operand", "limbmax",  "input", "probe"),
    "sw_lane_load":  ("st_subword_lane", "load",  "input", "probe"),
    "sw_lane_store": ("st_subword_lane", "store", "input", "probe"),
    "st_redirect_armed":   ("st_redirect", "armed", "input", "probe"),
    "st_pointer_indirect": ("st_pointer_indirect", "", "input", "probe"),
    "pv_chain2": ("st_provenance_chain", "d2", "input", "probe"),
    "pv_chain4": ("st_provenance_chain", "d4", "input", "probe"),
    "lp_n16":   ("st_loop_repeat", "n16",   "input", "probe"),
    "lp_n256":  ("st_loop_repeat", "n256",  "input", "probe"),
    "lp_n4096": ("st_loop_repeat", "n4096", "input", "probe"),
    "ms_carry": ("st_multishard", "", "input", "probe"),
    # CALIBRATION.  Expected verdict ACCEPT.  An output-changing accept here is a
    # TRUE accept and a FALSE FINDING -- report it in a calibration column, never in
    # a bug count.  Its purpose is the converse: no calibration accept means the hook
    # does not reach the constraint system and every pico REJECT is uninterpretable.
    "hint_passthrough": ("st_hint_advice", "unchecked", "input", "calibration"),
    "hint_checked":     ("st_hint_advice", "checked",   "input", "calibration"),
    "ij_table": ("st_indirect_jump", "table", "input", "probe"),
    "ij_bit0":  ("st_indirect_jump", "bit0",  "input", "probe"),
    "pc_imm":   ("st_pc_imm_value", "auipc+lui+jal", "input", "probe"),
    "fanout":   ("st_fanout_read", "", "input", "probe"),
    "reg_alias":    ("st_reg_alias", "rs1rs2",   "input", "probe"),
    "reg_alias_rd": ("st_reg_alias", "rdrs1rs2", "input", "probe"),
    "pv_eight": ("st_pv_plumbing", "words8", "input", "probe"),
    "pv_alias": ("st_pv_plumbing", "alias",  "input", "probe"),
    # UNFALSIFIABLE UNDER THE FROZEN PREDICATE.  accepted_case_strict requires a
    # NON-EMPTY committed output and success here means the output is absent, so the
    # accepted_case column can never fire.  This wave does not touch the predicate.
    # Score these rows under accepted_case_v2 ("differs from honest, INCLUDING by
    # being absent") or do not draw a conclusion from them.
    "ee_truncate": ("st_early_exit", "", "input", "probe"),
    # DECLARED NEGATIVE CONTROL, EXCLUDED FROM COVERAGE COUNTS.  Nothing about final
    # state is public on pico (public_values.rs:16, instances/machine/riscv.rs:562-597),
    # so the forged value has no route to the public output and an unbound finalise
    # write-back must NOT score as an accepted case.
    "fo_sink": ("st_finalize_only", "mem", "input", "control"),
    "pc_sha_extend": ("st_precompile", "sha256_extend", "input", "probe"),
    "st_store_load_wops":      ("st_store_load",   "wide_ops", "input", "probe"),
    "st_store_load_tail_wops": ("st_store_load",   "wide_ops", "input", "probe"),
    "st_hazard_chain_wops":    ("st_hazard_chain", "wide_ops", "input", "probe"),
    "st_redirect_wops":        ("st_redirect",     "wide_ops", "input", "probe"),
    "st_control_flow_wops":    ("st_control_flow", "wide_ops", "input", "probe"),
    "st_initial_state_wops":   ("st_initial_state", "wide_ops", "input", "probe"),
}

# ROLE MASK for address-carrying sites (STRUCTURE_MANIFEST mu_menu.role_masks,
# site_role == "address").  On a pointer the menu is mostly self-destructive:
# plus_B0 / minus_B0 / xor_b0 break word alignment, zero is a null dereference,
# boundary_msb / boundary_max / xor_b63 land outside any mapped region, and plus_B3
# (+2^48) aborts the whole enumeration PROCESS because a Rust allocation abort is not
# unwindable.  The mask is applied WITHOUT touching the menu itself, by running one
# template per process through the driver's existing LACUNA_MU_ONLY.
#
# allowed        n role_masks = {plus_B1, minus_B1, xor_b15}
# implemented    n pico menu  = {plus_B1, minus_B1}          (xor_b15 is not in menu_all)
# The single documented exception is the st_indirect_jump `bit0` variant, where
# xor_b0 IS the experiment: RISC-V requires JALR to clear bit 0.
MU_ALLOW = {
    "ots_addr":            ["plus_B1", "minus_B1"],
    "st_redirect_armed":   ["plus_B1", "minus_B1"],
    "st_pointer_indirect": ["plus_B1", "minus_B1"],
    "ij_table":            ["plus_B1", "minus_B1"],
    "ij_bit0":             ["xor_b0"],
}

# Per-seed extra process environment.  EmulatorOpts::default() reads CHUNK_SIZE /
# CHUNK_BATCH_SIZE / SPLIT_THRESHOLD straight from the environment
# (vm/src/emulator/opts.rs:47-58), so st_multishard needs no driver change: lowering
# the chunk size is what puts the store and the load on opposite sides of a real
# chunk boundary.  Seeds absent from this map run with exactly the environment the
# published corpus used.
SEED_ENV = {
    "ms_carry": {"CHUNK_SIZE": "8192", "CHUNK_BATCH_SIZE": "4"},
}



FIB_ELF = os.path.join(PICO, "vm/src/compiler/test_elf/riscv64im-pico-fibnacci-elf")


def elf_path(seed):
    elf = SEEDS[seed][0]
    return os.path.join(GUESTS, elf) if elf else FIB_ELF


def main_symbol_range(elf):
    """(lo, hi) of the guest's own `main` FUNC symbol, read from the ELF symbol
    table. This is the mechanical definition of 'the operation the seed is about':
    every other site of the same opcode belongs to the zkVM's Rust runtime."""
    out = subprocess.check_output(["readelf", "-sW", elf], text=True)
    for line in out.splitlines():
        f = line.split()
        # Num: Value Size Type Bind Vis Ndx Name
        if len(f) >= 8 and f[3] == "FUNC" and f[-1] == "main":
            lo = int(f[1], 16)
            size = int(f[2])
            return lo, lo + size
    raise RuntimeError(f"no main symbol in {elf}")


def test_binary():
    cands = [
        os.path.join(PICO, "target/release/deps", f)
        for f in os.listdir(os.path.join(PICO, "target/release/deps"))
        if f.startswith("pico_vm-") and not re.search(r"\.(d|txt|rmeta|rlib)$", f)
    ]
    cands = [c for c in cands if os.access(c, os.X_OK)]
    cands.sort(key=os.path.getmtime, reverse=True)
    if not cands:
        sys.exit("pico test binary not built")
    return cands[0]


def run_one(binary, out_dir, env_extra, logname, testname):
    env = dict(os.environ)
    env.update(env_extra)
    env["LACUNA_OUT"] = os.path.join(out_dir, logname + ".csv")
    if os.path.exists(env["LACUNA_OUT"]):
        os.remove(env["LACUNA_OUT"])
    t0 = time.monotonic()
    with open(os.path.join(out_dir, logname + ".log"), "w") as lo, \
         open(os.path.join(out_dir, logname + ".time"), "w") as te:
        rc = subprocess.call(
            ["/usr/bin/time", "-v", binary, testname, "--ignored", "--nocapture"],
            cwd=PICO, env=env, stdout=lo, stderr=te)
    return logname, rc, time.monotonic() - t0


def commit_path_pcs(out_dir, seed):
    """pcs whose ENC-E3 probe changed the committed output (E1 -> E2 filter)."""
    pcs = []
    for f in sorted(os.listdir(out_dir)):
        if not f.startswith(f"E1_{seed}_") or not f.endswith(".csv"):
            continue
        with open(os.path.join(out_dir, f)) as fh:
            for row in csv.DictReader(fh):
                if row.get("output_changed") == "true" and row.get("outcome") == "ACCEPT":
                    pcs.append(row["pc"])
    return sorted(set(pcs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--stages", default="E1,E2,B")
    ap.add_argument("--seeds", default="")
    ap.add_argument("--shards", type=int, default=12)
    ap.add_argument("--threads", type=int, default=10)
    # Which corpus to schedule.  `published` reproduces the frozen 38-seed run
    # exactly; `wave2` is the additive structure coverage; `all` (default) is both.
    ap.add_argument("--set", dest="seed_set", default="all",
                    choices=["published", "wave2", "all"])
    # E1 is site-complete over the WHOLE ELF by default, which is how the published
    # corpus was produced and what makes the localization pass mechanical.  On a
    # wave-2 seed that costs thousands of candidates in the zkVM runtime's own code
    # (a single guest carries ~680 static SRLW sites inside the SHA-256 that hashes
    # the public-value stream), so `--e1-scope main` restricts E1 to the guest's own
    # `main` symbol, exactly as E2 already does.  Sampling is part of the result:
    # whichever is used must be named in the run tag (run_matrix_rules R6).
    ap.add_argument("--e1-scope", dest="e1_scope", default="all",
                    choices=["all", "main"])
    a = ap.parse_args()

    a.out_dir = os.path.abspath(a.out_dir)
    os.makedirs(a.out_dir, exist_ok=True)
    binary = test_binary()
    stages = [s.strip() for s in a.stages.split(",") if s.strip()]
    if a.seed_set == "published":
        default_seeds = list(PUBLISHED_SEEDS)
    elif a.seed_set == "wave2":
        default_seeds = list(WAVE2_SEEDS)
    else:
        default_seeds = list(SEEDS)
    seeds = [s.strip() for s in a.seeds.split(",") if s.strip()] or default_seeds

    meta = os.path.join(a.out_dir, "run_meta.txt")
    with open(meta, "a") as m:
        m.write(f"start_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        m.write(f"binary={binary}\npico_rev={REV}\nshards={a.shards} threads={a.threads}\n")
        m.write(f"stages={stages}\nseeds={seeds}\nseed_set={a.seed_set}\n")
        m.write(f"e1_scope={a.e1_scope}\n")
        # seed_id -> structure_id | variant | operand_source | candidate_class,
        # for the wave-2 rows.  The CSV column set is frozen, so the join key lives
        # here.  run_matrix_rules R8: probe, control and calibration rows must be
        # aggregated separately in every table.
        for sd in seeds:
            if sd in STRUCTURE_META:
                sid, var, osrc, cls = STRUCTURE_META[sd]
                m.write(f"structure_meta[{sd}]={sid}|{var}|{osrc}|{cls}\n")
            if sd in MU_ALLOW:
                m.write(f"mu_mask[{sd}]={','.join(MU_ALLOW[sd])}\n")
            if sd in SEED_ENV:
                kv = " ".join(f"{k}={v}" for k, v in sorted(SEED_ENV[sd].items()))
                m.write(f"seed_env[{sd}]={kv}\n")

    def base_env(seed, threads):
        elf, stdin, _struct, _ops, _b = SEEDS[seed]  # noqa: F841
        e = {"RAYON_NUM_THREADS": str(threads),
             "LACUNA_SEED_ID": seed,
             "LACUNA_STRUCT": _struct,
             "LACUNA_STDIN": stdin}
        if elf:
            e["LACUNA_ELF"] = os.path.join(GUESTS, elf)
        # Per-seed emulator configuration (st_multishard lowers CHUNK_SIZE so the
        # store and the load land in different chunks).  Seeds absent from SEED_ENV
        # keep exactly the environment the published corpus ran under.
        e.update(SEED_ENV.get(seed, {}))
        return e

    pool = ThreadPoolExecutor(max_workers=a.shards)

    if "E1" in stages:
        jobs = []
        for seed in seeds:
            _elf, _stdin, _struct, ops, _b = SEEDS[seed]
            for i in range(a.shards):
                e = base_env(seed, a.threads)
                e.update({"LACUNA_TAG": f"E1_{seed}_s{i}",
                          "LACUNA_MU": "xorb0",
                          "LACUNA_SHARD": f"{i}/{a.shards}"})
                if a.e1_scope == "main":
                    lo1, hi1 = main_symbol_range(elf_path(seed))
                    e["LACUNA_PC_LO"] = hex(lo1)
                    e["LACUNA_PC_HI"] = hex(hi1)
                if seed in MU_ALLOW:
                    # ENC-E3 xor_b0 is FORBIDDEN at an address-role site (it breaks
                    # word alignment and traps the executor), so the localization
                    # pass uses the first entry of the seed's role mask instead.
                    e["LACUNA_MU"] = "all"
                    e["LACUNA_MU_ONLY"] = MU_ALLOW[seed][0]
                if ops == "ALL":
                    e["LACUNA_SITES"] = "all"
                else:
                    e["LACUNA_SITES"] = "ops"
                    e["LACUNA_OPS"] = ops
                jobs.append(pool.submit(run_one, binary, a.out_dir, e,
                                        f"E1_{seed}_s{i}", "lacuna_encoding_enumeration"))
        for j in jobs:
            n, rc, dt = j.result()
            print(f"[E1] {n} rc={rc} {dt:.1f}s", flush=True)

    if "E2" in stages:
        jobs = []
        for seed in seeds:
            elf = elf_path(seed)
            lo, hi = main_symbol_range(elf)
            pcs = commit_path_pcs(a.out_dir, seed)
            with open(meta, "a") as m:
                m.write(f"main_range[{seed}]={hex(lo)}-{hex(hi)}\n")
                m.write(f"E1_commit_path_pcs[{seed}]={','.join(pcs) if pcs else 'NONE'}\n")
            _elf, _stdin, _struct, ops, _b = SEEDS[seed]
            e = base_env(seed, a.threads)
            e.update({"LACUNA_TAG": f"E2_{seed}",
                      "LACUNA_MU": "all",
                      "LACUNA_PC_LO": hex(lo),
                      "LACUNA_PC_HI": hex(hi)})
            if ops == "ALL":
                e["LACUNA_SITES"] = "all"
            else:
                e["LACUNA_SITES"] = "ops"
                e["LACUNA_OPS"] = ops
            if seed in MU_ALLOW:
                # Address-role mask, applied WITHOUT touching the frozen menu: one
                # allowed template per process via LACUNA_MU_ONLY.  Running one
                # template per process also bounds the blast radius, since a
                # self-destructive parameter on a pointer can abort the process
                # rather than raising a catchable EXECFAIL.
                for label in MU_ALLOW[seed]:
                    em = dict(e)
                    em["LACUNA_TAG"] = f"E2_{seed}_{label}"
                    em["LACUNA_MU_ONLY"] = label
                    jobs.append(pool.submit(run_one, binary, a.out_dir, em,
                                            f"E2_{seed}_{label}",
                                            "lacuna_encoding_enumeration"))
            else:
                jobs.append(pool.submit(run_one, binary, a.out_dir, e,
                                        f"E2_{seed}", "lacuna_encoding_enumeration"))
        for j in jobs:
            n, rc, dt = j.result()
            print(f"[E2] {n} rc={rc} {dt:.1f}s", flush=True)

    if "B" in stages:
        jobs = []
        for seed in seeds:
            if not SEEDS[seed][4]:
                continue
            nsh = a.shards if seed == "fib" else 2
            for i in range(nsh):
                e = base_env(seed, a.threads)
                e.update({"LACUNA_TAG": f"B_{seed}_s{i}",
                          "LACUNA_SHARD": f"{i}/{nsh}"})
                jobs.append(pool.submit(run_one, binary, a.out_dir, e,
                                        f"B_{seed}_s{i}", "lacuna_binding_enumeration"))
        for j in jobs:
            n, rc, dt = j.result()
            print(f"[B] {n} rc={rc} {dt:.1f}s", flush=True)

    pool.shutdown()
    with open(meta, "a") as m:
        m.write(f"end_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    print("done")


if __name__ == "__main__":
    main()
