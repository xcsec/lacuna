#!/usr/bin/env python3
"""LACUNA program-structure enumeration driver for ZisK.

Companion to `run_zisk_enumeration.py`, which is the FROZEN driver behind the published
42-candidate ZisK run (data/runs/zisk_seeds/E_zisk.csv, program_structure
"single-op-commit").  That file is vendored verbatim and is NOT touched here -- its md5 is
recorded in this directory's README and must keep matching.

This driver is additive.  It runs the program structures of
`evaluation/spec/STRUCTURE_MANIFEST.yaml` against a SECOND guest ELF, `lacuna-struct`, built from
`zisk/examples/lacuna-seed/src/bin/lacuna-struct.rs`.  Nothing it does can move a published
number: a different ELF, a different selector range (>= 100) and a different output CSV.  The one
exception is st_boundary_operand, which needs no new guest code at all -- it is a new INPUT
FRAMING for the frozen guest -- so those eight seeds run the FROZEN ELF read-only with the frozen
24-byte frame and still write to this wave's CSV.

WHAT IS DIFFERENT FROM THE FROZEN DRIVER
  1. SITE DISCOVERY BY DISASSEMBLY.  The frozen driver finds its mutation pc by arming
     ZISK_WB_REPORT with the expected honest result and hoping the value is unique.  That does not
     generalise: st_initial_state's honest load value is 0, and several structures have more than
     one interesting site in one function.  Here every guest arm is `#[no_mangle] #[inline(never)]`
     and a site is named `(symbol, mnemonic regex, occurrence)`, resolved with objdump.  Robust
     across rebuilds, and it makes the site table self-documenting.
  2. THE WHOLE OUTPUT REGION.  The frozen driver reads the first two u32 that `ziskemu -c` prints.
     st_pv_plumbing commits eight words, so this driver reads all 64.
  3. ROLE-MASKED MU.  `mu_menu.role_masks` in the manifest forbids most of the menu at an
     address-role site.  Value and selector sites get the seven mu the frozen run used; address
     sites get plus_B1 / minus_B1 / xor_b15, which on ZisK are ENC-E1 with ZISK_WB_ARG=2 and
     ENC-E3 with ZISK_WB_ARG=15.  The MENU IS UNCHANGED -- these are the same three ENC families
     with different documented arguments, as the role mask requires.
  4. THE NEW CSV COLUMNS of the manifest's csv_contract: operand_source, candidate_class,
     accepted_case_v2, site_role, nth, scored_against.

SAMPLING POLICY (manifest rule R6: sampling is part of the result)
  ZisK costs ~73 s wall and ~5,000 CPU-s per candidate, so the full structure x opcode x site x mu
  cross product is not affordable.  `--opcodes` selects the opcode axis and the choice is recorded
  in run_tag:
    sampled  (default)  add, srlw, sraw, mulhu, divu -- one alu_bound_reference opcode plus four
                        probes.  A per-structure yield computed from this matrix does NOT satisfy
                        rule R2 and must be labelled `opcodes=sampled` wherever it is published.
    r3full              R2/R3-compliant: add plus the FULL shift_family, shift_family_w and m_ext.
                        16 opcodes.  This is the run a per-structure claim needs.
  ZisK's TARGET_CAPABILITIES.known_unbound_opcodes is empty, so rule R3 applies either way and
  run_tag always carries `unbound_probe=substituted`.

  `nth` is always -1.  TARGET_CAPABILITIES.capability.nth_supported is false / NOT DETERMINED for
  ZisK, so manifest rule R5 forbids a per-execution nth here.

CONTROLS BEFORE PROBES (rule R7).  `--order controls-first` (the default) runs st_hint_advice
(calibration) and st_dead_write (control) before any probe.  ZisK has never produced an accepted
case; without the calibration a reader cannot tell a sound VM from a hook that never reaches the
constraint system, and without the dead-write control none of its 42 REJECTs is interpretable.

USAGE
    python3 run_zisk_structures.py sites                 # resolve every site pc, run nothing
    python3 run_zisk_structures.py honest                # honest emulation of every seed
    python3 run_zisk_structures.py prove [--seeds a,b]   # the real enumeration; writes CSV+JSON

Paths are taken from the environment, never hardcoded to a scratchpad:
    ZISK_ROOT     zisk checkout            (default: <repo>/../zkvm_fuzz/third_party/zisk)
    LACUNA_WORK   scratch for input files  (default: a fresh mkdtemp)
    LACUNA_OUT    output directory         (default: <repo>/data/runs/zisk_structures)
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))  # the artifact root

ZISK = os.environ.get(
    "ZISK_ROOT", os.path.abspath(os.path.join(REPO, "..", "zkvm_fuzz", "third_party", "zisk"))
)
CZ = os.path.join(ZISK, "target", "release", "cargo-zisk")
ZE = os.path.join(ZISK, "target", "release", "ziskemu")
GUEST_DIR = os.path.join(ZISK, "examples", "lacuna-seed")
ELF = os.path.join(
    GUEST_DIR, "target", "elf", "riscv64ima-zisk-zkvm-elf", "release", "lacuna-struct"
)
# st_boundary_operand needs no new guest code, so it runs against the FROZEN single-operation ELF
# with new inputs.  Read-only here: this driver never rebuilds it and never writes its CSV.
FROZEN_ELF = os.path.join(
    GUEST_DIR, "target", "elf", "riscv64ima-zisk-zkvm-elf", "release", "lacuna-seed"
)
OBJDUMP = os.environ.get("RISCV_OBJDUMP", "riscv64-unknown-elf-objdump")

OUTDIR = os.environ.get("LACUNA_OUT", os.path.join(REPO, "runs", "zisk_structures"))
CSV_OUT = os.path.join(OUTDIR, "E_zisk_structures.csv")
JSON_OUT = os.path.join(OUTDIR, "zisk_structures.json")

M64 = (1 << 64) - 1

# --------------------------------------------------------------------------------------------
# the mu menu, UNCHANGED, split by the manifest's role masks
# --------------------------------------------------------------------------------------------

# (mu_label, mutation_template, mu_kind, mu_arg, env)
MU_VALUE = [
    ("E1_add_i0", "ENC-E1", "add", 0, {"ZISK_WB_TMPL": "E1", "ZISK_WB_KIND": "add", "ZISK_WB_ARG": "0"}),
    ("E1_sub_i0", "ENC-E1", "sub", 0, {"ZISK_WB_TMPL": "E1", "ZISK_WB_KIND": "sub", "ZISK_WB_ARG": "0"}),
    ("E2_zero", "ENC-E2", "boundary", 0, {"ZISK_WB_TMPL": "E2", "ZISK_WB_ARG": "0"}),
    ("E2_2p63", "ENC-E2", "boundary", 1, {"ZISK_WB_TMPL": "E2", "ZISK_WB_ARG": "1"}),
    ("E2_max", "ENC-E2", "boundary", 2, {"ZISK_WB_TMPL": "E2", "ZISK_WB_ARG": "2"}),
    ("E3_j0", "ENC-E3", "xor", 0, {"ZISK_WB_TMPL": "E3", "ZISK_WB_ARG": "0"}),
    ("E3_j63", "ENC-E3", "xor", 63, {"ZISK_WB_TMPL": "E3", "ZISK_WB_ARG": "63"}),
]

# role_masks.address allows exactly plus_B1 / minus_B1 / xor_b15.  ZisK's ENC-E1 uses a byte base,
# so B^1 = 2^16 is ZISK_WB_ARG=2, and xor_b15 is ENC-E3 with ZISK_WB_ARG=15.
MU_ADDRESS = [
    ("E1_add_i2", "ENC-E1", "add", 2, {"ZISK_WB_TMPL": "E1", "ZISK_WB_KIND": "add", "ZISK_WB_ARG": "2"}),
    ("E1_sub_i2", "ENC-E1", "sub", 2, {"ZISK_WB_TMPL": "E1", "ZISK_WB_KIND": "sub", "ZISK_WB_ARG": "2"}),
    ("E3_j15", "ENC-E3", "xor", 15, {"ZISK_WB_TMPL": "E3", "ZISK_WB_ARG": "15"}),
]

MU_BY_ROLE = {"value": MU_VALUE, "selector": MU_VALUE, "address": MU_ADDRESS}

# --------------------------------------------------------------------------------------------
# the opcode axis: index into lacuna_ax, mnemonic as objdump prints it, manifest opcode set
# --------------------------------------------------------------------------------------------

AX = [
    (0, "add", "alu_bound_reference"),
    (1, "xor", "alu_bound_reference"),
    (2, "and", "alu_bound_reference"),
    (3, "sll", "shift_family"),
    (4, "srl", "shift_family"),
    (5, "sra", "shift_family"),
    (6, "sllw", "shift_family_w"),
    (7, "srlw", "shift_family_w"),
    (8, "sraw", "shift_family_w"),
    (9, "srliw", "shift_family_w"),
    (10, "mul", "m_ext"),
    (11, "mulh", "m_ext"),
    (12, "mulhu", "m_ext"),
    (13, "mulhsu", "m_ext"),
    (14, "div", "m_ext"),
    (15, "divu", "m_ext"),
    (16, "rem", "m_ext"),
    (17, "remu", "m_ext"),
    (18, "mulw", "m_ext_w"),
    (19, "divw", "m_ext_w"),
    (20, "divuw", "m_ext_w"),
    (21, "remw", "m_ext_w"),
    (22, "remuw", "m_ext_w"),
]
AX_BY_K = {k: (mn, s) for k, mn, s in AX}

OPCODE_SETS = {
    "sampled": [0, 7, 8, 12, 15],
    "r3full": [0] + [k for k, _, s in AX if s in ("shift_family", "shift_family_w", "m_ext")],
}

# `add a0,a1,a2` appears twice in lacuna_ax: the k=0 arm and the `_ =>` fallback.  Every other
# mnemonic appears once.  Occurrence 0 is always the real arm because the fallback is emitted last.
def ax_site(k):
    mn = AX_BY_K[k][0]
    if mn == "srliw":
        insn = r"srliw\s+a0,a1,"
    else:
        insn = r"\b" + mn + r"\s+a0,a1,a2\b"
    return {"symbol": "lacuna_ax", "insn": insn, "occ": 0}


def cx_site(k2):
    mn = {0: "add", 1: "slt", 2: "mul"}[k2]
    return {"symbol": "lacuna_cx", "insn": r"\b" + mn + r"\s+a0,a1,a2\b", "occ": 0}


# --------------------------------------------------------------------------------------------
# operands
# --------------------------------------------------------------------------------------------

P1 = (0x0123456789ABCDEF, 0x1122334455667788)  # the frozen driver's pair
P2 = (0xFEDCBA9876543210, 0x0000000012345678)  # the frozen driver's DIVISION pair

# Per-opcode default operands for the axis.  The frozen driver already splits its table this way:
# with P1 the dividend is smaller than the divisor, so every quotient is 0 and half a dozen seeds
# would commit a constant zero and carry no information.  Same split, same constants.
DIV_FAMILY = {14, 15, 16, 17, 19, 20, 21, 22}  # div, divu, rem, remu and the four W forms


def ax_operands(k):
    return P2 if k in DIV_FAMILY else P1
# Operand pairs whose honest lacuna_ax result IS zero, so that the small mu entries (not just
# E2_zero) can flip a zero-comparison branch.  Verified with `honest` mode, never assumed.
ZERO_PAIR = {
    0: (1, M64),               # add:   1 + (-1)
    1: (0xDEADBEEF, 0xDEADBEEF),  # xor:  x ^ x
    2: (0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0),  # and: disjoint masks
    7: (0x00000000000000FF, 8),  # srlw: 0xFF >> 8
    8: (0x00000000000000FF, 8),  # sraw: 0xFF >>a 8
    12: (2, 3),                # mulhu: high half of 6
    15: (1, 2),                # divu:  1 / 2
}

# --------------------------------------------------------------------------------------------
# the seed table
#
# One entry per (structure, variant).  `sites` lists every mutation site the arm exposes; the
# enumeration is the cross product of sites and the role-masked mu menu.  `axis` is True when the
# arm carries the opcode axis in `c`, in which case one seed is instantiated per sampled opcode.
# --------------------------------------------------------------------------------------------

def S(**kw):
    kw.setdefault("axis", False)
    kw.setdefault("operand_source", "input")
    kw.setdefault("scored_against", "out_of_circuit")
    kw.setdefault("expected_verdict", "not_determined")
    kw.setdefault("mutation_mode", "encoding")
    kw.setdefault("operands", P1)
    kw.setdefault("note", "")
    kw.setdefault("elf", "struct")   # "struct" = lacuna-struct, "frozen" = lacuna-seed
    kw.setdefault("frame", 32)
    return kw


AX_SITE = {"label": "op", "site_role": "value", "site": None}  # filled in per opcode

STRUCTURES = [
    # ---- R7: calibration and controls first -------------------------------------------------
    S(
        seed_id="st_hint_advice_unchecked",
        structure_id="st_hint_advice",
        published_name="Nondeterministic advice",
        variant="unchecked",
        sel=100,
        candidate_class="calibration",
        expected_verdict="ACCEPT",
        sites=[{"label": "carry_add", "site_role": "value",
                "site": {"symbol": "st_hint_advice_unchecked", "insn": r"\badd\s+a0,a0,a1\b", "occ": 0}}],
        note="Is ZisK's input region bound to a public value at all?  Decides whether the "
             "corpus-wide ZisK oracle can be 'output != honest' or must be 'output != spec(input)'.",
    ),
    S(
        seed_id="st_hint_advice_checked",
        structure_id="st_hint_advice",
        published_name="Nondeterministic advice",
        variant="checked",
        sel=101,
        candidate_class="calibration",
        expected_verdict="ACCEPT",
        operands=(0x123456789, (0x123456789 * 0x123456789) & M64),
        sites=[{"label": "carry_add", "site_role": "value",
                "site": {"symbol": "st_hint_advice_checked", "insn": r"\badd\s+a0,a0,a1\b", "occ": 0}}],
        note="b must be a*a or the guest panics.  Asks whether an in-guest check binds the value "
             "in the CIRCUIT or only in the executor.",
    ),
    S(
        seed_id="st_dead_write_overwritten",
        structure_id="st_dead_write",
        published_name="Dead write-back",
        variant="overwritten",
        sel=102,
        candidate_class="control",
        expected_verdict="REJECT_or_ACCEPT_UNCHANGED_OUTPUT",
        sites=[{"label": "dead_op", "site_role": "value",
                "site": {"symbol": "st_dead_write_overwritten", "insn": r"\bsrlw\s+a2,a0,a1\b", "occ": 0}},
               {"label": "live_mv", "site_role": "value",
                "site": {"symbol": "st_dead_write_overwritten", "insn": r"\bmv\s+a2,a1\b",
                         "occ": 0, "after": r"\bsrlw\s+a2,a0,a1\b"}}],
        operands=(P1[0], P1[1], 1),
        note="c=1 selects the srlw arm.  dead_op must be invisible; live_mv is the paired live "
             "site that proves the arm is reachable at all.",
    ),
    S(
        seed_id="st_dead_write_neverread",
        structure_id="st_dead_write",
        published_name="Dead write-back",
        variant="neverread",
        sel=103,
        candidate_class="control",
        expected_verdict="REJECT_or_ACCEPT_UNCHANGED_OUTPUT",
        operands=(P1[0], P1[1], 1),
        sites=[{"label": "dead_op", "site_role": "value",
                "site": {"symbol": "st_dead_write_neverread", "insn": r"\bsrlw\s+", "occ": 0}}],
        note="c=1 selects the srlw arm.  The result register is never read at all.",
    ),
    # ---- probes ------------------------------------------------------------------------------
    S(
        seed_id="st_store_load",
        structure_id="st_store_load",
        published_name="Store--load",
        variant="",
        sel=105,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None},
               {"label": "store_dead", "site_role": "value",
                "site": {"symbol": "st_store_load", "insn": r"\bsd\s+s0,-?\d+\(a1\)", "occ": 0}},
               {"label": "store_live", "site_role": "value",
                "site": {"symbol": "st_store_load", "insn": r"\bsd\s+a0,", "occ": 0}},
               {"label": "load", "site_role": "value",
                "site": {"symbol": "st_store_load", "insn": r"\bld\s+a0,", "occ": 0}}],
        note="ZisK's primary reachable record field is EmuTrace.mem_reads[i].  store_live is the "
             "STORE_IND write-back that lands in memory and is therefore what the later load "
             "records; load is the register-side reference that does NOT move mem_reads.",
    ),
    S(
        seed_id="st_store_load_tail",
        structure_id="st_store_load",
        published_name="Store--load",
        variant="tail",
        sel=106,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None},
               {"label": "store_live", "site_role": "value",
                "site": {"symbol": "st_store_load_tail", "insn": r"\bsd\s+a0,", "occ": 0}},
               {"label": "load", "site_role": "value",
                "site": {"symbol": "st_store_load_tail", "insn": r"\bld\s+a0,", "occ": 0}}],
        note="Trailing store keeps the load off the finalize boundary: separates S5 from S9.",
    ),
    S(
        seed_id="st_subword_lane_load_lwu_hi",
        structure_id="st_subword_lane",
        published_name="Sub-word lane",
        variant="load",
        sel=107,
        candidate_class="probe",
        operands=(P1[0], 0, 4),
        sites=[{"label": "wide_store", "site_role": "value",
                "site": {"symbol": "st_subword_lane_load", "insn": r"\bsd\s+a0,0\(a1\)", "occ": 0}},
               {"label": "narrow_load", "site_role": "value",
                "site": {"symbol": "st_subword_lane_load", "insn": r"\blwu\s+a0,4", "occ": 0}}],
        note="c=4 is LWU at offset 4, the HIGH LANE -- the direct record-layer probe of ZisK "
             "base-ISA catalog #16 (mem_align_sm.rs:118,155 take all eight lanes of the V row "
             "from the record value).",
    ),
    S(
        seed_id="st_subword_lane_load_lhu_hi",
        structure_id="st_subword_lane",
        published_name="Sub-word lane",
        variant="load",
        sel=107,
        candidate_class="probe",
        operands=(P1[0], 0, 2),
        sites=[{"label": "narrow_load", "site_role": "value",
                "site": {"symbol": "st_subword_lane_load", "insn": r"\blhu\s+a0,6", "occ": 0}}],
        note="c=2 is LHU at offset 6: the other half of catalog #16.",
    ),
    S(
        seed_id="st_subword_lane_store_unaligned_sw",
        structure_id="st_subword_lane",
        published_name="Sub-word lane",
        variant="store",
        sel=108,
        candidate_class="probe",
        operands=(P1[0], P1[1], 3),
        sites=[{"label": "narrow_store", "site_role": "value",
                "site": {"symbol": "st_subword_lane_store", "insn": r"\bsw\s+a1,1\(a3\)", "occ": 0}},
               {"label": "reassembled_load", "site_role": "value",
                "site": {"symbol": "st_subword_lane_store", "insn": r"\bld\s+a0,0\(a3\)",
                         "occ": 0, "after": r"\bsw\s+a1,1\(a3\)"}}],
        note="c=3 is an UNALIGNED SW, so the MemAlign state machine rather than the plain Mem SM "
             "is the chip under test, and the untouched lanes are the sibling-preservation question.",
    ),
    S(
        seed_id="st_redirect",
        structure_id="st_redirect",
        published_name="Redirect",
        variant="",
        sel=109,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "ptr_materialise", "site_role": "address",
                "site": {"symbol": "st_redirect", "insn": r"\baddi\s+s1,a1,", "occ": 0}},
               {"label": "ptr_use", "site_role": "address",
                "site": {"symbol": "st_redirect", "insn": r"\bld\s+s2,8\(sp\)", "occ": 0}}],
        note="The two slots are exactly 2^16 bytes apart, so plus_B1 -- the only alignment-"
             "preserving delta the address role mask allows -- is an EXACT redirect rather than a "
             "jump into unmapped memory.  ptr_materialise shifts the WHOLE object (both stores and "
             "the load move together, so the honest output is expected to survive: an internal "
             "control); ptr_use moves only the load and is the real redirect.  Consequence of the "
             "mem_reads replay (see NOT_BUILT/st_pointer_indirect): in the witness passes the "
             "redirected load still receives the honest slice entry by position, so what this seed "
             "measures is whether the memory bus catches a row whose ADDRESS moved while its "
             "delivered value did not.",
    ),
    S(
        seed_id="st_hazard_chain_first",
        structure_id="st_hazard_chain",
        published_name="Hazard chain",
        variant="first",
        sel=104,
        candidate_class="probe",
        operands=(P1[0], P1[1], 1),
        sites=[{"label": "waw_first", "site_role": "value",
                "site": {"symbol": "st_hazard_chain", "insn": r"\bsrlw\s+a2,a0,a1\b", "occ": 0}}],
        note="c=1 selects srlw, which is non-commutative, so the two writes carry different honest "
             "values.  The FIRST write is dead: its best outcome is ACCEPT-with-unchanged-output.",
    ),
    S(
        seed_id="st_hazard_chain_second",
        structure_id="st_hazard_chain",
        published_name="Hazard chain",
        variant="second",
        sel=104,
        candidate_class="probe",
        operands=(P1[0], P1[1], 1),
        sites=[{"label": "waw_second", "site_role": "value",
                "site": {"symbol": "st_hazard_chain", "insn": r"\bsrlw\s+a2,a1,a0\b", "occ": 0}}],
        note="The SECOND write reaches the commit directly.",
    ),
    S(
        seed_id="st_control_flow_datadiv",
        structure_id="st_control_flow",
        published_name="Control flow",
        variant="datadiv",
        sel=110,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "cond_producer", "site_role": "selector", "site": None}],
        note="Site is the instruction PRODUCING the branch condition, so a forged value changes "
             "which rows exist and then selects which input word is committed.",
    ),
    S(
        seed_id="st_control_flow_dataident",
        structure_id="st_control_flow",
        published_name="Control flow",
        variant="dataident",
        sel=111,
        axis=True,
        candidate_class="probe",
        expected_verdict="REJECT_or_ACCEPT_UNCHANGED_OUTPUT",
        sites=[{"label": "cond_producer", "site_role": "selector", "site": None}],
        note="ZISK CAVEAT: the committed object is the fixed output REGION, not a cycle or pc "
             "public, so output_changed is FALSE here by construction.  Kept because the "
             "asymmetry against ceno/openvm/risc0 is itself a result.",
    ),
    S(
        seed_id="st_reg_alias_rs1rs2",
        structure_id="st_reg_alias",
        published_name="Register aliasing",
        variant="rs1rs2",
        sel=112,
        candidate_class="probe",
        operands=(P1[0], 0, 1),
        sites=[{"label": "alias_op", "site_role": "value",
                "site": {"symbol": "st_reg_alias_rs1rs2", "insn": r"\bsrlw\s+a0,a0,a0\b", "occ": 0}}],
        note="c=1 selects srlw with rs1 == rs2.",
    ),
    S(
        seed_id="st_reg_alias_rdrs1rs2",
        structure_id="st_reg_alias",
        published_name="Register aliasing",
        variant="rdrs1rs2",
        sel=113,
        candidate_class="probe",
        operands=(P1[0], 0, 1),
        sites=[{"label": "alias_op", "site_role": "value",
                "site": {"symbol": "st_reg_alias_rdrs1rs2", "insn": r"\bsrlw\s+a0,a0,a0\b", "occ": 0}}],
        note="rd == rs1 == rs2: one register read twice and written in the same cycle.",
    ),
    S(
        seed_id="st_pv_plumbing_words8",
        structure_id="st_pv_plumbing",
        published_name="Public-value plumbing",
        variant="words8",
        sel=114,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="Eight committed words, so the enumeration reads all 64 output u32.  With nth = -1 "
             "all eight commits move together; whether EACH word is bound or only the aggregate is "
             "the question.  A per-word arming needs nth, which rule R5 forbids on ZisK.",
    ),
    S(
        seed_id="st_pv_plumbing_alias",
        structure_id="st_pv_plumbing",
        published_name="Public-value plumbing",
        variant="alias",
        sel=115,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="Output cursor reset between two commits, so the second aliases the first.  Use a "
             "non-commutative opcode or the two commits are equal.",
    ),
    S(
        seed_id="st_op_then_state_mem",
        structure_id="st_op_then_state",
        published_name="Operation then state",
        variant="mem",
        sel=116,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="THE DECONFOUNDING SHAPE.  Same armed site as st_single_op, one memory hop before the "
             "commit: an accept proves the forgery survived a re-binding hop.",
    ),
    S(
        seed_id="st_op_then_state_addr",
        structure_id="st_op_then_state",
        published_name="Operation then state",
        variant="addr",
        sel=117,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="The forged result becomes an ADDRESS (masked to 3 bits, so both paths stay in "
             "bounds and EXECFAIL cannot mask a REJECT).",
    ),
    S(
        seed_id="st_op_then_state_branch",
        structure_id="st_op_then_state",
        published_name="Operation then state",
        variant="branch",
        sel=118,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="The variant the manifest's ZisK cell asks for first: no read-side hook needed.  The "
             "forged result becomes a DECISION.  Instantiated twice per opcode -- once with the "
             "frozen operand pair (honest result non-zero, only E2_zero flips the branch) and once "
             "with a pair whose honest result is zero (every mu flips it).",
    ),
    S(
        seed_id="st_provenance_chain_d2",
        structure_id="st_provenance_chain",
        published_name="Provenance chain",
        variant="d2",
        sel=119,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op1", "site_role": "value", "site": None},
               {"label": "op2_add", "site_role": "value", "site": cx_site(0)},
               {"label": "op2_mul", "site_role": "value", "site": cx_site(2)}],
        note="Depth 2.  c packs OP1 in the low byte and OP2 in the second byte; the driver sets "
             "OP2 = MUL (consumer_set) for the op1 site.  Depth 4 is deliberately not built: ZisK "
             "replays loads against mem_reads, so the extra hop carries no information.",
    ),
    S(
        seed_id="st_fanout_read",
        structure_id="st_fanout_read",
        published_name="Fan-out read",
        variant="",
        sel=120,
        axis=True,
        candidate_class="probe",
        sites=[{"label": "op", "site_role": "value", "site": None}],
        note="One forged value, two consumers with different operand decompositions; both results "
             "reach the commit.",
    ),
    S(
        seed_id="st_loop_repeat_n16",
        structure_id="st_loop_repeat",
        published_name="Loop repeat",
        variant="n16",
        sel=121,
        candidate_class="probe",
        operands=(P1[0], 0, 16),
        sites=[{"label": "loop_body", "site_role": "value",
                "site": {"symbol": "st_loop_repeat", "insn": r"\badd\s+a1,a1,a0\b", "occ": 0}}],
        note="ONE static pc executed 16 times, written in assembly so LLVM cannot unroll it into "
             "several pcs.  nth = -1 only (rule R5), so all 16 executions are forged and the "
             "per-row / aggregate distinction the structure exists to make is NOT available on "
             "ZisK until nth_supported is resolved.",
    ),
    S(
        seed_id="st_initial_state_bss",
        structure_id="st_initial_state",
        published_name="Initial state",
        variant="bss",
        sel=122,
        candidate_class="probe",
        sites=[{"label": "unwritten_load", "site_role": "value",
                "site": {"symbol": "st_initial_state_bss", "insn": r"\bld\s+a0,0\(a0\)", "occ": 0}}],
        note="The only site LACUNA can arm is the LD's REGISTER write-back; ZisK re-derives the "
             "delivered value from mem_reads, which this hook does not touch, so a COHERENT "
             "initial-state mutation needs the read-side hook that capability "
             "init_value_hookable=partial describes.  Expect a bus imbalance.",
    ),
    S(
        seed_id="st_initial_image_data",
        structure_id="st_initial_image",
        published_name="Initial image",
        variant="data",
        sel=123,
        candidate_class="control",
        expected_verdict="REJECT",
        sites=[{"label": "image_load", "site_role": "value",
                "site": {"symbol": "st_initial_image_data", "insn": r"\bld\s+a0,0\(a0\)", "occ": 0}}],
        note="PAIRED NEGATIVE for st_initial_state: this address's initial value is non-zero and "
             "comes from the vk-committed image.  An ACCEPT is not a control failure -- it is a "
             "probe-grade finding and must be re-graded as one.",
    ),
    S(
        seed_id="st_initial_image_bssboundary",
        structure_id="st_initial_image",
        published_name="Initial image",
        variant="bssboundary",
        sel=124,
        candidate_class="control",
        expected_verdict="REJECT",
        sites=[{"label": "boundary_load", "site_role": "value",
                "site": {"symbol": "st_initial_image_bssboundary", "insn": r"\bld\s+a0,", "occ": 0}}],
        note="The aligned dword straddling the end of the initialised image: the record-layer "
             "question raised by the loader-layer golds (ZisK T-1, SP1 L-1, Pico L-1, Nexus N-1).",
    ),
    S(
        seed_id="st_pc_imm_value_auipc",
        structure_id="st_pc_imm_value",
        published_name="PC-immediate value",
        variant="auipc",
        sel=125,
        candidate_class="probe",
        operand_source="immediate",
        sites=[{"label": "auipc", "site_role": "value",
                "site": {"symbol": "st_pc_imm_value_auipc", "insn": r"\bauipc\s+a0,", "occ": 0}}],
        note="The jal variant is UNREACHABLE on ZisK: get_value_to_store returns pc + jmp_offset2 "
             "ahead of the hook when instruction.store_pc is set (emu.rs:2781).",
    ),
    S(
        seed_id="st_pc_imm_value_lui",
        structure_id="st_pc_imm_value",
        published_name="PC-immediate value",
        variant="lui",
        sel=126,
        candidate_class="probe",
        operand_source="immediate",
        sites=[{"label": "lui", "site_role": "value",
                "site": {"symbol": "st_pc_imm_value_lui", "insn": r"\blui\s+a0,", "occ": 0}}],
    ),
    S(
        seed_id="st_indirect_jump_table",
        structure_id="st_indirect_jump",
        published_name="Indirect jump",
        variant="table",
        sel=127,
        candidate_class="probe",
        sites=[{"label": "target_materialise", "site_role": "address",
                "site": {"symbol": "st_indirect_jump_table", "insn": r"\baddi\s+a0,a0,", "occ": 0}},
               {"label": "target_use", "site_role": "address",
                "site": {"symbol": "st_indirect_jump_table", "insn": r"\bld\s+a0,0\(sp\)",
                         "occ": 0, "after": r"\baddi\s+a0,a0,"}}],
        note="target_use is the load feeding JALR.  Expect the ROM lookup to bind the target: the "
             "ZisK fetch relation is total and keyed by pc.  The bit0 variant is not built -- the "
             "link value rd = pc+4 is behind the store_pc branch and out of reach.",
    ),
    S(
        seed_id="st_x0_dark_write",
        structure_id="st_x0_dark_write",
        published_name="x0 dark write",
        variant="",
        sel=128,
        candidate_class="probe",
        sites=[{"label": "x0_write", "site_role": "value",
                "site": {"symbol": "st_x0_dark_write", "insn": r"\badd\s+zero,a0,a1\b", "occ": 0}},
               {"label": "x0_read", "site_role": "value",
                "site": {"symbol": "st_x0_dark_write", "insn": r"\bli\s+a2,0\b", "occ": 0}}],
        note="Resolves an OPEN QUESTION: TARGET_CAPABILITIES.capability.x0_hookable is "
             "not_determined for ZisK.  MEASURED 2026-08-28: it is FALSE, structurally. "
             "ZiskInstBuilder::store (core/src/zisk_inst_builder.rs:164-167) returns early when the "
             "destination is register 0, so the instruction is built with store = STORE_NONE and "
             "the write-back never reaches get_value_to_store.  Arming x0_write gives WB_HITS=0 (a "
             "NOOP row); arming x0_read -- `li a2,0`, which IS the read of x0 (addi a2,x0,0) -- "
             "gives WB_HITS=1 and moves the committed output, so the arm is reachable and the "
             "negative is about x0, not about the seed.",
    ),
]

# --------------------------------------------------------------------------------------------
# structures deliberately NOT built.  A blocked cell is a published result; keep the reason next
# to the code so it cannot drift.
# --------------------------------------------------------------------------------------------

NOT_BUILT = [
    {"structure_id": "st_pointer_indirect", "manifest_status": "blocked",
     "reason": "BLOCKER CONFIRMED IN CODE.  In the witness-generating passes a load's delivered "
               "value is taken from the recorded slice BY POSITION, never by address: "
               "emulator/src/emu.rs:605 and :650 (Emu::source_b_mem_reads_consume, the SRC_MEM and "
               "SRC_IND arms) and :724, :794 (the _databus variant) all do "
               "`inst_ctx.b = mem_reads[*mem_reads_index]` and then advance the index.  The "
               "computed address is used for the memory-bus key and the alignment test, not to "
               "fetch.  A forged pointer therefore changes WHERE the record claims to have read "
               "while the dereference still delivers the honest bytes -- no coherent RAM-mediated "
               "forgery on ZisK today, exactly as on sp1.  Unblocking it needs a read-side hook, "
               "for which core/src/mem.rs:33-46 zisk_forge_narrow_load is the ready-made template."},
    {"structure_id": "st_finalize_only", "manifest_status": "blocked",
     "reason": "ZisK's committed public object is the fixed 256-byte output region at OUTPUT_ADDR "
               "(core/src/mem.rs:145, pil/zisk.pil:60,146-148), not the whole final image, so a "
               "finalize-only write has no committed object to move."},
    {"structure_id": "st_early_exit", "manifest_status": "moderate, blocked on the predicate",
     "reason": "accepted_case_strict requires a NON-EMPTY committed output and st_early_exit "
               "succeeds precisely by making it absent.  Buildable here in three lines, but it "
               "scores only under accepted_case_v2 and no ZisK row has ever been scored that way; "
               "held back so the v2 column lands with a target that can also read its in-circuit "
               "object."},
    {"structure_id": "st_multishard", "manifest_status": "hard, blocked",
     "reason": "full VADCOP aggregation errors during GENERATE_VADCOP_FINAL_PROOF on these seeds; "
               "the published run used -a (no aggregation), which still checks Global Constraint "
               "#0 but not the full cross-instance chain."},
    {"structure_id": "st_whole_program", "manifest_status": "hard, blocked",
     "reason": "~73 s wall and ~5,000 CPU-s per candidate makes a realistic-guest site census "
               "unaffordable.  Out of budget, not unimplemented."},
    {"structure_id": "st_precompile", "manifest_status": "moderate",
     "reason": "NOT BUILT in this wave.  Needs a ziskos precompile call plus the ArithEq / Keccak "
               "input plumbing, and the interesting cell (catalog #24, sel_prove not bound to the "
               "ROM) sits in the arith_eq dispatch rather than on the write-back path.  Landing it "
               "cleanly is a wave of its own."},
]

# --------------------------------------------------------------------------------------------
# st_boundary_operand: ZERO new guest code.  The FROZEN single-operation guest
# (examples/lacuna-seed/src/main.rs, selectors 0..19) already reads (sel, a, b) from the input, so
# this structure is a new INPUT FRAMING for the frozen ELF, run with the frozen 24-byte frame.
# The seeds below therefore carry elf="frozen" and frame=24 and are byte-for-byte the same
# executable the published run used -- only the operands are new, and they land in a different CSV.
#
# site_role = selector: the honest operand sits one mu-step from a constraint discontinuity, so the
# information is in the SMALL menu entries.  Variant suffixes are the manifest's.
# --------------------------------------------------------------------------------------------

BOUNDARY_OPERANDS = [
    # (variant, frozen selector, mnemonic, a, b, the discontinuity the honest operands sit next to)
    ("zero", 14, "divu", 0x00000000DEADBEEF, 1,
     "divisor one mu-step from 0: the DivRem is_zero selector"),
    ("zero", 16, "remu", 0x00000000DEADBEEF, 1,
     "divisor one mu-step from 0, remainder side"),
    ("shamt", 5, "sll", 0x0123456789ABCDEF, 1,
     "shift amount in a REGISTER (SLL, not SLLI), one step from 0 and from XLEN"),
    ("shamt", 6, "srl", 0x0123456789ABCDEF, 63,
     "shift amount at the top of the 6-bit mask: +1 wraps the decomposition"),
    ("intmin", 13, "div", (1 << 63) + 1, M64,
     "INT_MIN+1 / -1: one step from the INT_MIN/-1 special case"),
    ("limb", 0, "add", 0x000000000000FFFF, 1,
     "limb boundary at B^1 = 2^16"),
    ("exactdiv", 14, "divu", 8, 2,
     "exactly divisible, EVEN divisor -- the shape nexus catalog #13 needs"),
    ("limbmax", 10, "mul", 0x00000000FFFFFFFF, 0x00000000FFFFFFFF,
     "0xFFFFFFFF squared -- the shape ceno #8/#9 need"),
]

for _variant, _sel, _mn, _a, _b, _why in BOUNDARY_OPERANDS:
    STRUCTURES.append(S(
        seed_id=f"st_boundary_operand_{_mn}_{_variant}",
        structure_id="st_boundary_operand",
        published_name="Boundary operand",
        variant=_variant,
        sel=_sel,
        elf="frozen",
        frame=24,
        candidate_class="probe",
        operands=(_a, _b),
        sites=[{"label": "operand_op", "site_role": "selector",
                "site": {"symbol": r"lacuna_seed8dispatch", "insn": r"\b" + _mn + r"\s+a0,a1,a2\b",
                         "occ": 0}}],
        note="FROZEN ELF, frozen 24-byte frame, new operands only.  " + _why,
    ))
del _variant, _sel, _mn, _a, _b, _why

# --------------------------------------------------------------------------------------------
# site discovery
# --------------------------------------------------------------------------------------------

_DIS_CACHE = {}


def disassemble(elf):
    if elf in _DIS_CACHE:
        return _DIS_CACHE[elf]
    r = subprocess.run([OBJDUMP, "-d", elf], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{OBJDUMP} failed on {elf}: {r.stderr[:200]}")
    lines = r.stdout.splitlines()
    # symbol -> [(pc, text), ...].  A function's body runs to the next symbol that is not one of
    # the assembler's local `.Lpcrel_hi*` labels.
    marks = []
    for i, l in enumerate(lines):
        m = re.match(r"^([0-9a-f]{16}) <(.+)>:$", l)
        if m:
            marks.append((i, m.group(2)))
    bodies = {}
    for j, (i, name) in enumerate(marks):
        if name.startswith("."):
            continue
        k = j + 1
        while k < len(marks) and marks[k][1].startswith("."):
            k += 1
        end = marks[k][0] if k < len(marks) else len(lines)
        insns = []
        for l in lines[i + 1:end]:
            m = re.match(r"^\s+([0-9a-f]+):\s+[0-9a-f]+\s+\t(.*)$", l)
            if m:
                insns.append((int(m.group(1), 16), m.group(2).strip()))
        bodies[name] = insns
    _DIS_CACHE[elf] = bodies
    return bodies


def resolve_site(elf, site):
    """(symbol, insn regex, occurrence) -> (pc, text, n_matches).

    An optional `after` regex restricts the search to instructions that follow the first match of
    that anchor, which is how a site inside one arm of a `match` is named without depending on the
    order the compiler happened to lay the arms out in.  Raises rather than guessing.
    """
    bodies = disassemble(elf)
    sym = site["symbol"]
    if sym not in bodies:
        # Fall back to a regex over symbol names, for a Rust-mangled symbol whose hash is not
        # stable across rebuilds (the frozen guest's `dispatch`).  Must match exactly one.
        cands = [k for k in bodies if re.search(sym, k)]
        if len(cands) != 1:
            raise KeyError(f"symbol /{sym}/ matched {len(cands)} in {os.path.basename(elf)}")
        sym = cands[0]
    body = bodies[sym]
    if site.get("after"):
        arx = re.compile(site["after"])
        anchors = [pc for pc, txt in body if arx.search(txt)]
        if not anchors:
            raise LookupError(f"{sym}: anchor /{site['after']}/ not found")
        body = [(pc, txt) for pc, txt in body if pc > anchors[0]]
    rx = re.compile(site["insn"])
    hits = [(pc, txt) for pc, txt in body if rx.search(txt)]
    if len(hits) <= site["occ"]:
        raise LookupError(f"{sym}: /{site['insn']}/ matched {len(hits)}, wanted occ {site['occ']}")
    return hits[site["occ"]][0], hits[site["occ"]][1], len(hits)


# --------------------------------------------------------------------------------------------
# emulation and proving
# --------------------------------------------------------------------------------------------

def workdir():
    d = os.environ.get("LACUNA_WORK")
    if not d:
        d = tempfile.mkdtemp(prefix="lacuna_zisk_")
    os.makedirs(d, exist_ok=True)
    return d


WORK = None


def mkinput(sel, a, b, c, frame=32):
    """[u64 payload_len][u64 sel][u64 a][u64 b]([u64 c]) -- frame 24 is the FROZEN framing, byte
    for byte what run_zisk_enumeration.py writes; frame 32 adds the structure arm's parameter."""
    path = os.path.join(WORK, f"in_{frame}_{sel}_{a:016x}_{b:016x}_{c:x}.bin")
    with open(path, "wb") as f:
        if frame == 24:
            f.write(struct.pack("<QQQQ", 24, sel, a & M64, b & M64))
        else:
            f.write(struct.pack("<QQQQQ", 32, sel, a & M64, b & M64, c & M64))
    return path


OUT_RE = re.compile(r"^[0-9a-fA-F]{8}$")


def emu_output(inp, env=None, elf=None):
    """Returns (output words as a list of u64, hits, wall ms, CompletedProcess)."""
    elf = elf or ELF
    e = dict(os.environ)
    if env:
        e.update(env)
    t0 = time.time()
    r = subprocess.run([ZE, "-e", elf, "-i", inp, "-c"], capture_output=True, text=True, env=e,
                       timeout=300)
    dt = (time.time() - t0) * 1000
    w = [l.strip() for l in r.stdout.splitlines() if OUT_RE.fullmatch(l.strip())]
    vals = []
    for i in range(0, len(w) - 1, 2):
        vals.append((int(w[i + 1], 16) << 32) | int(w[i], 16))
    hits = 0
    m = re.search(r"WB_HITS=(\d+)", r.stderr)
    if m:
        hits = int(m.group(1))
    return vals, hits, dt, r


def pv_hex(vals):
    """The committed output as a hex string.  Trailing all-zero words are dropped so a one-word
    commit reads exactly like the frozen driver's pv_hex, and an eight-word commit is visible."""
    v = list(vals)
    while v and v[-1] == 0:
        v.pop()
    if not v:
        return "0x" + "0" * 16  # an all-zero commit is still a commit
    return "|".join("0x%016x" % x for x in v)


def run_prove(inp, env, elf=None):
    elf = elf or ELF
    e = dict(os.environ)
    if env:
        e.update(env)
    for f in os.listdir("/dev/shm"):
        if f.startswith("ZISK_"):
            try:
                os.remove("/dev/shm/" + f)
            except OSError:
                pass
    t0 = time.time()
    r = subprocess.run([CZ, "prove", "-e", elf, "-i", inp, "-a", "-y", "-l"],
                       capture_output=True, text=True, env=e, timeout=1800)
    dt = (time.time() - t0) * 1000
    log = r.stdout + "\n" + r.stderr
    accept = "All proofs were successfully verified" in log
    reject = ("were not verified" in log) or ("Not all global constraints" in log) or \
             ("Basic proofs were not verified" in log)
    vt = "NA"
    m = re.search(r"VERIFYING_PROOFS \((\d+)ms\)", log)
    if m:
        vt = m.group(1)
    return accept, reject, dt, vt, log


def git_rev():
    r = subprocess.run(["git", "-C", ZISK, "rev-parse", "--short", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip()


# --------------------------------------------------------------------------------------------
# candidate expansion
# --------------------------------------------------------------------------------------------

def seed_elf(s):
    return FROZEN_ELF if s["elf"] == "frozen" else ELF


def expand(opcode_set):
    """The seed table x the opcode axis -> concrete seeds, each with resolved operands."""
    out = []
    for s in STRUCTURES:
        if not s["axis"]:
            ops = s["operands"]
            a, b = ops[0], ops[1]
            c = ops[2] if len(ops) > 2 else 0
            out.append(dict(s, _a=a, _b=b, _c=c, _opcode="NA", _seed_id=s["seed_id"]))
            continue
        for k in opcode_set:
            mn = AX_BY_K[k][0]
            pairs = [("", ax_operands(k))]
            if s["variant"] == "branch":
                if k in ZERO_PAIR:
                    pairs.append(("_zeroresult", ZERO_PAIR[k]))
            for suffix, (a, b) in pairs:
                c = k
                if s["structure_id"] == "st_provenance_chain":
                    c = k | (2 << 8)  # OP2 = MUL, from consumer_set
                sites = []
                for site in s["sites"]:
                    site = dict(site)
                    if site["site"] is None:
                        site["site"] = ax_site(k)
                    sites.append(site)
                out.append(dict(s, sites=sites, _a=a, _b=b, _c=c, _opcode=mn,
                                _seed_id=f"{s['seed_id']}_{mn}{suffix}"))
    return out


# --------------------------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------------------------

# The frozen header, verbatim, plus the six columns csv_contract requires.
HEADER = ("run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,dead,"
          "dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,"
          "hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,"
          "t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed,"
          "operand_source,candidate_class,accepted_case_v2,site_role,scored_against,"
          "structure_id,variant,site_label,input_a,input_b,input_c")


def csvrow(d):
    return ",".join(str(d.get(k, "NA")) for k in HEADER.split(","))


# --------------------------------------------------------------------------------------------
# modes
# --------------------------------------------------------------------------------------------

def mode_sites(args):
    seeds = expand(OPCODE_SETS[args.opcodes])
    print(f"ELF        {ELF}")
    print(f"FROZEN ELF {FROZEN_ELF}  (st_boundary_operand only)")
    bad = 0
    n = 0
    for s in seeds:
        for site in s["sites"]:
            n += 1
            try:
                pc, txt, nmatch = resolve_site(seed_elf(s), site["site"])
                print(f"  {s['_seed_id']:44s} {site['label']:18s} {site['site_role']:8s} "
                      f"pc=0x{pc:08x}  {txt:28s} (matches={nmatch})")
            except Exception as exc:
                bad += 1
                print(f"  {s['_seed_id']:44s} {site['label']:18s} UNRESOLVED: {exc}")
    print(f"{len(seeds)} seeds, {n} sites, {bad} unresolved")
    return 1 if bad else 0


def mode_honest(args):
    global WORK
    WORK = workdir()
    seeds = expand(OPCODE_SETS[args.opcodes])
    bad = 0
    for s in seeds:
        inp = mkinput(s["sel"], s["_a"], s["_b"], s["_c"], s["frame"])
        vals, hits, dt, r = emu_output(inp, elf=seed_elf(s))
        ok = r.returncode == 0
        note = ""
        if s["variant"] == "branch":
            zero_expected = s["_seed_id"].endswith("_zeroresult")
            took_zero = bool(vals) and vals[0] == (s["_a"] & M64)
            if zero_expected != took_zero:
                note = "  <-- BRANCH PAIR WRONG: honest result is not on the expected side"
                bad += 1
        print(f"  {s['_seed_id']:44s} rc={r.returncode} {pv_hex(vals):24s}{note}")
        if not ok:
            bad += 1
    print(f"{len(seeds)} seeds, {bad} problems")
    return 1 if bad else 0


def mode_prove(args):
    global WORK
    WORK = workdir()
    seeds = expand(OPCODE_SETS[args.opcodes])
    if args.seeds:
        want = set(args.seeds.split(","))
        seeds = [s for s in seeds if s["_seed_id"] in want or s["structure_id"] in want]
    if args.order == "controls-first":
        rank = {"calibration": 0, "control": 1, "probe": 2}
        seeds.sort(key=lambda s: rank[s["candidate_class"]])

    rev = git_rev() + "+wb-hook"
    run_tag = ("zisk_struct_" + time.strftime("%Y%m%d_%H%M%S") +
               f"_opcodes={args.opcodes}_unbound_probe=substituted_nth=-1")
    csv_out = CSV_OUT
    if args.dry_run:
        run_tag = "DRYRUN_" + run_tag
        csv_out = CSV_OUT.replace(".csv", "_dryrun.csv")
    os.makedirs(OUTDIR, exist_ok=True)
    report = {
        "target": "zisk", "revision": rev, "run_tag": run_tag,
        "elf": ELF, "guest": "examples/lacuna-seed/src/bin/lacuna-struct.rs",
        "frozen_elf_read_only": FROZEN_ELF,
        "frozen_elf_used_by": "st_boundary_operand seeds only, with the frozen 24-byte input frame",
        "driver": "evaluation/scripts/zisk/run_zisk_structures.py",
        "frozen_run_untouched": "data/runs/zisk_seeds/E_zisk.csv (different ELF, "
                                "different selector range, different CSV)",
        "sampling_policy": {
            "opcodes": args.opcodes, "opcode_indices": OPCODE_SETS[args.opcodes],
            "mu_value_role": [m[0] for m in MU_VALUE],
            "mu_address_role": [m[0] for m in MU_ADDRESS],
            "nth": -1,
            "rule_R2_satisfied": args.opcodes == "r3full",
            "note": "R6: the sampling policy is part of the result.  With opcodes=sampled a "
                    "per-structure yield is NOT R2-compliant and must be labelled.",
        },
        "public_output": {
            "scored_against": "out_of_circuit",
            "in_circuit_gap": "the -a (no-aggregation) path returns an empty public-values slice, "
                              "so pil_public_inputs64 is NOT captured; divergence between the two "
                              "objects cannot be measured on ZisK today.",
        },
        "not_built": NOT_BUILT,
        "candidates": 0, "proofs": 0, "verifier_accepts": 0,
        "accepted_cases": 0, "accepted_cases_v2": 0, "accepted_case_detail": [],
        "baselines": {"attempted": 0, "verified": 0, "rejected": 0, "rejected_detail": []},
        "unresolved_sites": [],
    }

    report["dry_run"] = bool(args.dry_run)
    with open(csv_out, "w") as f:
        f.write(HEADER + "\n")
        f.flush()
        for s in seeds:
            elf = seed_elf(s)
            inp = mkinput(s["sel"], s["_a"], s["_b"], s["_c"], s["frame"])
            hon_vals, _, _, hr = emu_output(inp, elf=elf)
            honest_pv = pv_hex(hon_vals)
            report["baselines"]["attempted"] += 1
            hacc, hrej, hdt, hvt, hlog = (True, False, 0, "NA", "") if args.dry_run \
                else run_prove(inp, None, elf=elf)
            if hacc:
                report["baselines"]["verified"] += 1
            else:
                report["baselines"]["rejected"] += 1
                report["baselines"]["rejected_detail"].append(
                    {"seed_id": s["_seed_id"], "tail": hlog.strip().splitlines()[-3:]})
                continue
            for site in s["sites"]:
                try:
                    pc, txt, _ = resolve_site(elf, site["site"])
                except Exception as exc:
                    report["unresolved_sites"].append(
                        {"seed_id": s["_seed_id"], "site": site["label"], "error": str(exc)})
                    continue
                for mu_label, tmpl, kind, arg, envx in MU_BY_ROLE[site["site_role"]]:
                    env = {"ZISK_WB_ENABLE": "1", "ZISK_WB_PC": "0x%x" % pc}
                    env.update(envx)
                    cvals, hits, cdt, _ = emu_output(inp, env, elf=elf)
                    pv = pv_hex(cvals)
                    changed = (cvals != hon_vals)
                    report["candidates"] += 1
                    row = {
                        "run_tag": run_tag, "target": "zisk", "revision": rev,
                        "seed_id": s["_seed_id"], "mutation_mode": "writeback-perturb",
                        "program_structure": s["published_name"], "opcode": s["_opcode"],
                        "pc": "0x%x" % pc, "nth": -1, "dead": "NA", "dead_final": "NA",
                        "site_execs": "NA", "mu_label": mu_label, "mutation_template": tmpl,
                        "mu_kind": kind, "mu_arg": arg, "hits": hits, "pv_hex": pv,
                        "honest_pv_hex": honest_pv,
                        "output_changed": str(changed).lower(),
                        "t_record_ms": int(cdt),
                        "committed_digest": pv, "honest_committed_digest": honest_pv,
                        "digest_changed": str(changed).lower(),
                        "operand_source": s["operand_source"],
                        "candidate_class": s["candidate_class"],
                        "site_role": site["site_role"],
                        "scored_against": s["scored_against"],
                        "structure_id": s["structure_id"], "variant": s["variant"] or "NA",
                        "site_label": site["label"],
                        "input_a": "0x%016x" % (s["_a"] & M64),
                        "input_b": "0x%016x" % (s["_b"] & M64),
                        "input_c": "0x%x" % (s["_c"] & M64),
                    }
                    if args.dry_run:
                        row.update({"outcome": "NOTRUN", "failure_stage": "dry-run",
                                    "accepted_case": "false", "accepted_case_v2": "false",
                                    "t_prove_ms": "NA", "t_verify_ms": "NA",
                                    "reason": "dry-run:prover-not-called"})
                        f.write(csvrow(row) + "\n")
                        continue
                    if hits == 0:
                        row.update({"outcome": "NOOP", "failure_stage": "mutation",
                                    "accepted_case": "false", "accepted_case_v2": "false",
                                    "t_prove_ms": "NA", "t_verify_ms": "NA",
                                    "reason": "mutation-did-not-fire"})
                        f.write(csvrow(row) + "\n")
                        f.flush()
                        continue
                    acc, rej, pdt, vt, log = run_prove(inp, env, elf=elf)
                    report["proofs"] += 1
                    row["t_prove_ms"] = int(pdt)
                    row["t_verify_ms"] = vt
                    if acc:
                        report["verifier_accepts"] += 1
                        # accepted_case_strict, kept VERBATIM: accept AND fired AND non-empty AND
                        # different from honest.
                        strict = bool(changed and cvals)
                        # accepted_case_v2 additionally counts an output that changed by becoming
                        # absent or truncated.
                        v2 = strict or (changed and not cvals)
                        row.update({"outcome": "ACCEPT", "failure_stage": "accepted_proof",
                                    "accepted_case": str(strict).lower(),
                                    "accepted_case_v2": str(v2).lower(),
                                    "reason": "verifier-accepted" if strict
                                              else "accepted-but-output-unchanged"})
                        if strict:
                            report["accepted_cases"] += 1
                            report["accepted_case_detail"].append(
                                {"seed_id": s["_seed_id"], "site": site["label"],
                                 "mu": mu_label, "pv": pv, "honest": honest_pv,
                                 "candidate_class": s["candidate_class"]})
                        if v2:
                            report["accepted_cases_v2"] += 1
                    elif rej:
                        row.update({"outcome": "REJECT", "failure_stage": "verify",
                                    "accepted_case": "false", "accepted_case_v2": "false",
                                    "reason": "constraint-rejected(global-or-basic)"})
                    else:
                        tail = " | ".join(log.strip().splitlines()[-2:])[:180].replace(",", " ")
                        row.update({"outcome": "EXECFAIL", "failure_stage": "prove",
                                    "accepted_case": "false", "accepted_case_v2": "false",
                                    "reason": "prove-error:" + tail})
                    f.write(csvrow(row) + "\n")
                    f.flush()
            json.dump(report, open(JSON_OUT, "w"), indent=2)
    json.dump(report, open(JSON_OUT, "w"), indent=2)
    print("DONE candidates=%d accepts=%d accepted_cases=%d (v2 %d)" %
          (report["candidates"], report["verifier_accepts"],
           report["accepted_cases"], report["accepted_cases_v2"]))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["sites", "honest", "prove"])
    ap.add_argument("--opcodes", choices=sorted(OPCODE_SETS), default="sampled")
    ap.add_argument("--seeds", default=None, help="comma-separated seed_id or structure_id filter")
    ap.add_argument("--order", choices=["controls-first", "table"], default="controls-first")
    ap.add_argument("--dry-run", action="store_true",
                    help="expand the matrix and emit the CSV with outcome=NOTRUN, without calling "
                         "the prover.  Validates the csv_contract and the site table in seconds "
                         "instead of ~73 s per candidate.  Writes to E_zisk_structures_dryrun.csv "
                         "and stamps DRYRUN into run_tag so the rows can never be mistaken for "
                         "measurements.")
    args = ap.parse_args()
    for p in (ELF, ZE):
        if not os.path.exists(p):
            print(f"missing: {p}", file=sys.stderr)
            return 2
    if args.mode == "prove" and not args.dry_run and not os.path.exists(CZ):
        print(f"missing: {CZ}", file=sys.stderr)
        return 2
    return {"sites": mode_sites, "honest": mode_honest, "prove": mode_prove}[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
