//! LACUNA EVALUATION DRIVER for OpenVM -- instrumented, candidate-level enumeration of
//! ENCODING mutations on the OpenVM execution record.
//!
//! Contains no bug knowledge. It enumerates
//!
//!     site = (static pc, n-th execution of that pc)
//!     mu   = one entry of an instruction-independent rewriting menu
//!
//! over OpenVM's architectural write-back path. OpenVM splits each instruction record
//! into (adapter record, core record). The value an instruction produces reaches:
//!   * VM memory, via the single write path `openvm_rv32im_circuit::adapters::timed_write`
//!     (extensions/rv32im/circuit/src/adapters/mod.rs:119) -- used by EVERY rv32im chip;
//!   * a core record, but only `Rv32JalLuiCoreRecord::rd_data`
//!     (extensions/rv32im/circuit/src/jal_lui/core.rs:198) and `Rv32HintStoreVar::data`
//!     (extensions/rv32im/circuit/src/hintstore/mod.rs:481): every other rv32im core
//!     record stores the operands and the trace filler recomputes the result.
//! All three are hooked by `openvm_circuit::arch::wb_perturb`, armed per (pc, nth) from
//! `interpreter_preflight::execute_instruction`.
//!
//! Each candidate runs the REAL pipeline: keygen (once, shared) -> honest metered
//! execution for segment/trace-height estimates -> PERTURBED preflight execution ->
//! trace generation -> `engine.prove` -> `verify_segments` (the real OpenVM verifier).
//! The committed public output is the bytes the program `reveal`s into address space
//! `PUBLIC_VALUES_AS = 3`, which is bound into the proof through the memory Merkle root
//! that `verify_segments` chains and returns.
//!
//! # Program structures
//!
//! The seed corpus is a table of PROGRAM STRUCTURES, specified normatively in
//! `evaluation/spec/STRUCTURE_MANIFEST.yaml` and `evaluation/spec/TARGET_CAPABILITIES.yaml`
//! of the LACUNA evaluation repository. Every seed below names the structure it
//! implements, the constraint surface it exercises, and the path by which a forged
//! write-back reaches the committed public output. The eighteen `op_<mnemonic>` seeds are
//! the FROZEN published corpus (structure "Single operation") and are byte-identical to
//! the shipped enumeration: same words, same site list, same menu, same order.
//!
//! # Environment (all optional)
//!
//!   LACUNA_OUT    path of the CSV to append to (default: stdout only)
//!   LACUNA_TAG    free-form run tag copied into every row
//!   LACUNA_OPS    comma-separated opcode names to enumerate (default: all). This is the
//!                 recommended shard key: openvm costs ~10 s/candidate.
//!   LACUNA_MU     "xorb0" (single mu) | "all" (the 11-entry menu, default)
//!   LACUNA_SITES  "op" (only each seed's primary sites) | "all" (default: every
//!                 architectural write-back site derived from the seed's own words)
//!   LACUNA_SEEDS  comma-separated seed_id prefixes to keep (default: all)
//!   LACUNA_STRUCT comma-separated structure ids to keep (default: all)
//!   LACUNA_AXIS   "full" (default; R2/R3-compliant opcode axis) | "min" (ADD + SRL only,
//!                 which VIOLATES run-matrix rule R2 -- say so in LACUNA_TAG if you use it)
//!   LACUNA_LIST   if set, print the seed corpus and its candidate counts, prove nothing
//!
//! # CSV columns
//!
//! The thirty published columns are unchanged. Six columns are appended:
//! `structure_id, operand_source, candidate_class, site_role, scored_against,
//! accepted_case_v2, nth_armed`. `accepted_case` is the FROZEN strict predicate and is
//! computed exactly as before. `nth` keeps its published value (0, the occurrence the
//! shipped corpus renders); `nth_armed` records the value actually passed to
//! `wb_perturb::with`, which is -1 ("arm every execution of this pc") on this target
//! because `TARGET_CAPABILITIES.capability.nth_supported` is NOT DETERMINED for openvm.

use std::{collections::VecDeque, io::Write, panic::AssertUnwindSafe, time::Instant};

use openvm_circuit::{
    arch::{
        execution_mode::Segment, verify_segments, vm::VirtualMachine, wb_perturb,
        PreflightExecutionOutput, Streams, MERKLE_AIR_ID,
    },
    utils::{test_system_config, TestStarkEngine},
};
use openvm_instructions::{
    exe::{SparseMemoryImage, VmExe},
    program::Program,
    riscv::RV32_MEMORY_AS,
};
use openvm_rv32im_circuit::{Rv32IConfig, Rv32ImBuilder, Rv32ImConfig};
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_stark_sdk::{
    openvm_stark_backend::{
        keygen::types::MultiStarkVerifyingKey,
        p3_field::{PrimeCharacteristicRing, PrimeField32},
        StarkEngine, SystemParams,
    },
    config::baby_bear_poseidon2::BabyBearPoseidon2Config,
    p3_baby_bear::BabyBear,
};
use openvm_transpiler::transpiler::Transpiler;

type F = BabyBear;

const REV: &str = "8f021b1f2 (v2.0.1-2-g8f021b1f2)";
const PUBLIC_VALUES_AS: u32 = 3;

// ---------------------------------------------------------------------------------
// Seed corpus: built PROGRAMMATICALLY as RISC-V words, then pushed through OpenVM's
// REAL transpiler, so no guest toolchain is needed.
// ---------------------------------------------------------------------------------

fn r_type(opcode: u32, rd: u32, funct3: u32, rs1: u32, rs2: u32, funct7: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn i_type(opcode: u32, rd: u32, funct3: u32, rs1: u32, imm: u32) -> u32 {
    ((imm & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn u_type(opcode: u32, rd: u32, imm20: u32) -> u32 {
    ((imm20 & 0xfffff) << 12) | (rd << 7) | opcode
}
/// S-type (stores). `imm` is a signed 12-bit byte displacement.
fn s_type(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = imm as u32;
    (((i >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((i & 0x1f) << 7)
        | opcode
}
/// B-type (branches). `imm` is a signed byte displacement from this instruction.
fn b_type(opcode: u32, funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = imm as u32;
    (((i >> 12) & 1) << 31)
        | (((i >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((i >> 1) & 0xf) << 8)
        | (((i >> 11) & 1) << 7)
        | opcode
}
/// J-type (JAL). `imm` is a signed byte displacement from this instruction.
fn j_type(opcode: u32, rd: u32, imm: i32) -> u32 {
    let i = imm as u32;
    (((i >> 20) & 1) << 31)
        | (((i >> 1) & 0x3ff) << 21)
        | (((i >> 11) & 1) << 20)
        | (((i >> 12) & 0xff) << 12)
        | (rd << 7)
        | opcode
}

const OP_ALU: u32 = 0b0110011;
const OP_IMM: u32 = 0b0010011;
const OP_LUI: u32 = 0b0110111;
const OP_AUIPC: u32 = 0b0010111;
const OP_LOAD: u32 = 0b0000011;
const OP_STORE: u32 = 0b0100011;
const OP_BRANCH: u32 = 0b1100011;
const OP_JAL: u32 = 0b1101111;
const OP_JALR: u32 = 0b1100111;
/// OpenVM custom system opcode (`openvm_rv32im_guest::SYSTEM_OPCODE`).
const OP_SYSTEM: u32 = 0x0b;
/// `openvm_rv32im_guest::REVEAL_FUNCT3`
const REVEAL_FUNCT3: u32 = 0b010;
/// `openvm_rv32im_guest::TERMINATE_FUNCT3`
const TERMINATE_FUNCT3: u32 = 0b000;
/// `openvm_rv32im_guest::HINT_FUNCT3`
const HINT_FUNCT3: u32 = 0b001;
/// `openvm_rv32im_guest::HINT_STOREW_IMM`
const HINT_STOREW_IMM: u32 = 0;

/// (name, funct3, funct7) for the R-type operation under test.
fn opcodes() -> Vec<(&'static str, u32, u32)> {
    vec![
        ("ADD", 0b000, 0x00),
        ("SUB", 0b000, 0x20),
        ("SLL", 0b001, 0x00),
        ("SLT", 0b010, 0x00),
        ("SLTU", 0b011, 0x00),
        ("XOR", 0b100, 0x00),
        ("SRL", 0b101, 0x00),
        ("SRA", 0b101, 0x20),
        ("OR", 0b110, 0x00),
        ("AND", 0b111, 0x00),
        ("MUL", 0b000, 0x01),
        ("MULH", 0b001, 0x01),
        ("MULHSU", 0b010, 0x01),
        ("MULHU", 0b011, 0x01),
        ("DIV", 0b100, 0x01),
        ("DIVU", 0b101, 0x01),
        ("REM", 0b110, 0x01),
        ("REMU", 0b111, 0x01),
    ]
}

/// LACUNA seed -- program structure: Single operation.
///
/// ```text
/// 0x00: LUI    x1, a>>12          ; x1 = a (hi)
/// 0x04: ADDI   x1, x1, a&0xfff    ; x1 = a
/// 0x08: LUI    x2, b>>12          ; x2 = b (hi)
/// 0x0c: ADDI   x2, x2, b&0xfff    ; x2 = b
/// 0x10: OP     x5, x1, x2         ; x5 = a OP b      <- the operation under test
/// 0x14: REVEAL x5 -> [x0+0]_3     ; public_values[0..4] = x5   <- makes it observable
/// 0x18: TERMINATE 0
/// ```
/// The `reveal` at 0x14 is what makes the operation's result publicly observable:
/// address space 3 is hashed into the memory Merkle root that the verifier chains.
/// Constants are chosen so the low 12 bits are < 0x800, so `ADDI` does not sign-extend
/// into the LUI half.
fn build_words(funct3: u32, funct7: u32, a: u32, b: u32) -> Vec<u32> {
    assert!(a & 0xfff < 0x800 && b & 0xfff < 0x800);
    vec![
        u_type(OP_LUI, 1, a >> 12),
        i_type(OP_IMM, 1, 0b000, 1, a & 0xfff),
        u_type(OP_LUI, 2, b >> 12),
        i_type(OP_IMM, 2, 0b000, 2, b & 0xfff),
        r_type(OP_ALU, 5, funct3, 1, 2, funct7),
        // reveal!(rd = x0 (base), rs1 = x5 (value), imm = 0)
        i_type(OP_SYSTEM, 0, REVEAL_FUNCT3, 5, 0),
        i_type(OP_SYSTEM, 0, TERMINATE_FUNCT3, 0, 0),
    ]
}

/// The static pcs at which the SINGLE-OPERATION seed program performs an architectural
/// write-back. (Everything except the final TERMINATE.) Kept as a literal so that the
/// published enumeration is provably unmoved: `debug_assert`ed against `write_sites`,
/// which every seed -- old and new -- actually uses.
const WRITE_SITES: [u32; 6] = [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14];
/// The pc of the operation under test.
const OP_SITE: u32 = 0x10;

/// FROZEN entry point of the published enumeration. Kept verbatim (the seed table calls
/// `build_words` and `exe_from_words` directly) so that the shipped shape stays readable
/// next to the structures that were added around it.
#[allow(dead_code)]
fn build_exe(funct3: u32, funct7: u32, a: u32, b: u32) -> VmExe<F> {
    let words = build_words(funct3, funct7, a, b);
    exe_from_words(&words)
}

/// Push a raw RV32IM word vector through OpenVM's REAL transpiler. `pc == 4 * index`
/// because `Program::pc_base == 0` and `DEFAULT_PC_STEP == 4`.
fn exe_from_words(words: &[u32]) -> VmExe<F> {
    let insns = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension)
        .with_extension(Rv32IoTranspilerExtension)
        .transpile(words)
        .expect("transpile seed");
    VmExe::new(Program::new_without_debug_infos_with_option(&insns, 0)).with_pc_start(0)
}

// ---------------------------------------------------------------------------------
// Architectural write-back sites, DERIVED from the seed's own instruction words.
//
// The shipped driver hard-coded a six-entry site list, which silently capped every new
// program structure at the shape of the single-operation seed. This decides, per word,
// whether the instruction performs a write-back that reaches `timed_write` (and hence
// the LACUNA hook):
//
//   * LUI / AUIPC / JAL / JALR / ALU / ALU-imm / LOAD with rd != 0 -- a register write.
//     With rd == 0 the transpiler either emits a NOP (`from_r_type` / `from_i_type` /
//     `from_u_type`, crates/toolchain/transpiler/src/util.rs:27,45,136) or clears the
//     `enabled` flag (`from_load` :69), and in BOTH cases no `timed_write` happens --
//     see `st_x0_dark_write` below.
//   * STORE -- a memory write. On openvm SB and SH also go through the 4-byte
//     `timed_write` (the adapter merges the lane and writes the whole aligned word,
//     adapters/loadstore.rs:459-465), so the hook reaches the narrow stores too.
//   * REVEAL -- a STOREW into address space 3, i.e. the committed public output itself.
//   * HINT_STOREW -- a memory write of a hint word.
// ---------------------------------------------------------------------------------
fn write_sites(words: &[u32]) -> Vec<u32> {
    let mut sites = Vec::new();
    for (i, &w) in words.iter().enumerate() {
        let rd = (w >> 7) & 0x1f;
        let funct3 = (w >> 12) & 0x7;
        let writes = match w & 0x7f {
            OP_LUI | OP_AUIPC | OP_JAL | OP_JALR | OP_ALU | OP_IMM | OP_LOAD => rd != 0,
            OP_STORE => true,
            OP_SYSTEM => funct3 == REVEAL_FUNCT3 || funct3 == HINT_FUNCT3,
            OP_BRANCH => false,
            _ => false,
        };
        if writes {
            sites.push(4 * i as u32);
        }
    }
    sites
}

// ---------------------------------------------------------------------------------
// Assembler helpers for the new program structures.
// ---------------------------------------------------------------------------------

/// `LUI rd, v>>12` -- ONE word. Requires `v & 0xfff == 0`.
///
/// Preferred for every constant that can afford it, because LUI is the one rv32im
/// instruction whose core record carries a RESULT (`Rv32JalLuiCoreRecord::rd_data`) and
/// is therefore hook site 2: perturbing it leaves record and memory COHERENT instead of
/// producing a self-contradictory row that the prover's offline memory check kills.
fn lui(rd: u32, v: u32) -> u32 {
    assert_eq!(v & 0xfff, 0, "lui() constant {v:#x} has low bits");
    u_type(OP_LUI, rd, v >> 12)
}
/// `li rd, v` as LUI+ADDI -- ALWAYS two words, so instruction offsets are predictable.
fn li2(rd: u32, v: u32) -> [u32; 2] {
    let hi = (v.wrapping_add(0x800)) >> 12;
    let lo = v & 0xfff;
    [u_type(OP_LUI, rd, hi), i_type(OP_IMM, rd, 0b000, rd, lo)]
}
fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(OP_IMM, rd, 0b000, rs1, imm as u32)
}
fn xori(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(OP_IMM, rd, 0b100, rs1, imm as u32)
}
fn slli(rd: u32, rs1: u32, shamt: u32) -> u32 {
    i_type(OP_IMM, rd, 0b001, rs1, shamt)
}
fn srli(rd: u32, rs1: u32, shamt: u32) -> u32 {
    i_type(OP_IMM, rd, 0b101, rs1, shamt)
}
fn alu(rd: u32, rs1: u32, rs2: u32, funct3: u32, funct7: u32) -> u32 {
    r_type(OP_ALU, rd, funct3, rs1, rs2, funct7)
}
fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    alu(rd, rs1, rs2, 0b000, 0x00)
}
fn xor(rd: u32, rs1: u32, rs2: u32) -> u32 {
    alu(rd, rs1, rs2, 0b100, 0x00)
}
fn lw(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(OP_LOAD, rd, 0b010, rs1, imm as u32)
}
fn load(rd: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    i_type(OP_LOAD, rd, funct3, rs1, imm as u32)
}
fn sw(rs2: u32, rs1: u32, imm: i32) -> u32 {
    s_type(OP_STORE, 0b010, rs1, rs2, imm)
}
fn store(rs2: u32, rs1: u32, imm: i32, funct3: u32) -> u32 {
    s_type(OP_STORE, funct3, rs1, rs2, imm)
}
fn jal(rd: u32, imm: i32) -> u32 {
    j_type(OP_JAL, rd, imm)
}
fn jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(OP_JALR, rd, 0b000, rs1, imm as u32)
}
fn reveal(value_reg: u32, base_reg: u32, off: u32) -> u32 {
    i_type(OP_SYSTEM, base_reg, REVEAL_FUNCT3, value_reg, off)
}
fn terminate(code: u32) -> u32 {
    i_type(OP_SYSTEM, 0, TERMINATE_FUNCT3, 0, code)
}
/// `HINT_STOREW` -- pops one 4-byte word off the hint stream and writes it to `[ptr_reg]`.
fn hint_storew(ptr_reg: u32) -> u32 {
    i_type(OP_SYSTEM, ptr_reg, HINT_FUNCT3, 0, HINT_STOREW_IMM)
}

// ---------------------------------------------------------------------------------
// Scratch RAM layout.
//
// `test_system_config()` gives address space 2 exactly `1 << 22` cells while
// `pointer_max_bits` is 29, so the loadstore adapter's `assert!(ptr < 1 << 29)` does NOT
// protect an address above 4 MiB: `GuestMemory::read/write` is `get_unchecked` and
// "panics or segfaults" (system/memory/online.rs:55). Every address below is chosen so
// that the whole ADDRESS-role mu mask -- +2^16, -2^16 and ^2^15, the alignment-preserving
// entries -- stays inside the mapped region.
// ---------------------------------------------------------------------------------
/// The primary scratch slot. Low 12 bits are zero so a single `LUI` forms it.
const RAM_BASE: u32 = 0x0010_0000;
/// Where mu = plus_B1 (+2^16) redirects an access based at `RAM_BASE`.
const RAM_PLUS_B1: u32 = RAM_BASE + 0x0001_0000;
/// Where mu = minus_B1 (-2^16) redirects it.
const RAM_MINUS_B1: u32 = RAM_BASE - 0x0001_0000;
/// Where mu = xor_b15 (^2^15) redirects it.
const RAM_XOR_B15: u32 = RAM_BASE ^ 0x0000_8000;
/// An address the program never writes -- the `st_initial_state` target.
const RAM_UNWRITTEN: u32 = 0x0020_0000;
/// An address the ELF-equivalent initial memory image initialises to a NON-ZERO value --
/// the `st_initial_image` target.
const RAM_IMAGE: u32 = 0x0030_0000;

/// Distinct payloads, all `LUI`-formable, so a redirect is unambiguous in the CSV.
const PAY_0: u32 = 0x0A00_0000;
const PAY_1: u32 = 0x0B00_0000;
const PAY_2: u32 = 0x0C00_0000;
const PAY_3: u32 = 0x0D00_0000;
/// The constant a "the data output does not move" seed reveals.
const PAY_CONST: u32 = 0x00C0_F000;
/// The value `st_initial_image` puts in the committed initial memory image.
const IMAGE_WORD: u32 = 0xDEAD_BEEF;
/// The hint word `st_hint_advice` delivers (LUI-formable, so the checked variant can
/// compare against it with a single instruction).
const HINT_WORD: u32 = 0x00AB_C000;

// ---------------------------------------------------------------------------------
// The instruction-independent rewriting menu. (label, template, mu_kind, mu_arg)
// Identical to the nexus/pico menu: word width 32, limb base B = 2^16.
// FROZEN by the shared spec: this driver declares which entries are legal at which
// site role (below); it never adds, removes or re-parameterises one.
// ---------------------------------------------------------------------------------
fn menu(all: bool) -> Vec<(&'static str, &'static str, usize, i64)> {
    let full = vec![
        ("xor_b0", "ENC-E3", wb_perturb::MU_XORBIT, 0),
        ("plus_B0", "ENC-E1", wb_perturb::MU_ADDK, 1),
        ("minus_B0", "ENC-E1", wb_perturb::MU_ADDK, -1),
        ("plus_B1", "ENC-E1", wb_perturb::MU_ADDK, 1 << 16),
        ("minus_B1", "ENC-E1", wb_perturb::MU_ADDK, -(1i64 << 16)),
        ("xor_b15", "ENC-E3", wb_perturb::MU_XORBIT, 15),
        ("xor_b31", "ENC-E3", wb_perturb::MU_XORBIT, 31),
        ("zero", "ENC-E2", wb_perturb::MU_ZERO, 0),
        ("boundary_msb", "ENC-E2", wb_perturb::MU_SET, 0x8000_0000),
        ("boundary_max", "ENC-E2", wb_perturb::MU_SET, 0xFFFF_FFFF),
        ("plus_B1_hi", "ENC-E1", wb_perturb::MU_ADDK, 1 << 24),
    ];
    if all {
        full
    } else {
        vec![full[0]]
    }
}

// ---------------------------------------------------------------------------------
// Site roles and the mu-menu role mask.
//
// The mask is DECLARATIVE, exactly as the shared spec defines it: it selects which of
// the eleven existing menu entries are legal at a site, and never changes an entry.
//
// `address` is the only restrictive role and it is restrictive for a hard reason. The
// spec's allowed set for a pointer is the alignment-preserving one (+2^16, -2^16, ^2^15);
// the spec additionally lists +2^24 / +2^32 / ^2^31 as "allowed, EXECFAIL expected". On
// openvm those three are NOT allowed here, because an out-of-region address is not a
// catchable EXECFAIL: address space 2 has 4 MiB of cells but the loadstore adapter only
// asserts `ptr < 2^29`, and `GuestMemory` accesses past the end are `get_unchecked`.
// Admitting them would take down the enumeration PROCESS, not the candidate.
//
// Every seed's DEFAULT role is `value` (the unmasked menu), so the frozen
// single-operation seeds are unaffected: they contain no pointer.
// ---------------------------------------------------------------------------------
const ROLE_VALUE: &str = "value";
const ROLE_ADDRESS: &str = "address";
const ROLE_SELECTOR: &str = "selector";

fn mu_allowed(role: &str, label: &str) -> bool {
    match role {
        ROLE_ADDRESS => matches!(label, "plus_B1" | "minus_B1" | "xor_b15"),
        // `value` and `selector` take the whole menu. For `selector` the spec RECOMMENDS
        // the small steps first; ordering is the runner's business, not the driver's.
        _ => true,
    }
}

/// R2/R3 of the shared run matrix: STRUCTURE AND OPCODE VARY INDEPENDENTLY. Every
/// structure that admits an opcode parameter is run against at least one opcode from
/// `alu_bound_reference` AND the whole of the target's `target_unbound_probe` set.
/// openvm's `known_unbound_opcodes` is EMPTY, so the SUBSTITUTION RULE applies: the full
/// `shift_family` plus the full `m_ext`. A run using this axis must carry
/// `unbound_probe=substituted` in its run tag.
fn deconfound_axis() -> Vec<(&'static str, u32, u32)> {
    let min = std::env::var("LACUNA_AXIS").unwrap_or_else(|_| "full".to_string()) == "min";
    let names: &[&str] = if min {
        // NOT R2-compliant. Smoke-test only.
        &["ADD", "SRL"]
    } else {
        &[
            // alu_bound_reference (the BOUND arm of the deconfounding pair)
            "ADD", // shift_family + m_ext (the SUBSTITUTED unbound probe set)
            "SLL", "SRL", "SRA", "MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM", "REMU",
        ]
    };
    opcodes()
        .into_iter()
        .filter(|(n, _, _)| names.contains(n))
        .collect()
}

/// The branch opcodes, for the structures whose opcode axis is the branch chip.
/// (name, funct3, taken-when-honest-operands-are (a=NONZERO, b=0))
fn branch_axis() -> Vec<(&'static str, u32)> {
    vec![
        ("BEQ", 0b000),
        ("BNE", 0b001),
        ("BLT", 0b100),
        ("BGE", 0b101),
        ("BLTU", 0b110),
        ("BGEU", 0b111),
    ]
}

// ---------------------------------------------------------------------------------
// A seed: one program structure instance.
// ---------------------------------------------------------------------------------
struct Seed {
    /// `<structure_id>[_<opcode>][_<variant>]`, or a FROZEN legacy `op_<mnemonic>`.
    seed_id: String,
    /// The manifest structure id this seed implements.
    structure_id: &'static str,
    /// The manifest `published_name`. Must match a manifest string exactly.
    published_name: &'static str,
    /// The value of the CSV `opcode` column; also the LACUNA_OPS shard key.
    opcode: String,
    words: Vec<u32>,
    /// `probe` | `control` | `calibration`, from the manifest cell.
    candidate_class: &'static str,
    /// `input` | `hint` | `immediate`, from the manifest input contract.
    operand_source: &'static str,
    /// `target_default` (openvm: the AS3 byte read) or `in_circuit_state_object`
    /// (MemoryMerklePvs.final_root). Drives `accepted_case_v2`.
    scored_against: &'static str,
    /// Sites this structure is actually ABOUT; LACUNA_SITES=op runs only these.
    primary_sites: Vec<u32>,
    /// Per-site role overrides; anything not listed is `value`.
    site_roles: Vec<(u32, &'static str)>,
    /// How many bytes of address space 3 form the committed public output.
    pv_len: usize,
    /// Hint words delivered on the hint stream (`st_hint_advice`).
    hints: Vec<u32>,
    /// Committed initial memory image, `(address_space, ptr) -> byte`
    /// (`st_initial_image`).
    init_memory: SparseMemoryImage,
    /// Lower the metered pass's memory budget so a long seed segments
    /// (`st_multishard`). `None` keeps the default.
    max_memory: Option<usize>,
}

impl Seed {
    fn new(
        seed_id: String,
        structure_id: &'static str,
        published_name: &'static str,
        opcode: &str,
        words: Vec<u32>,
    ) -> Self {
        let primary_sites = write_sites(&words);
        Seed {
            seed_id,
            structure_id,
            published_name,
            opcode: opcode.to_string(),
            words,
            candidate_class: "probe",
            operand_source: "immediate",
            scored_against: "target_default",
            primary_sites,
            site_roles: Vec::new(),
            pv_len: 4,
            hints: Vec::new(),
            init_memory: SparseMemoryImage::new(),
            max_memory: None,
        }
    }
    fn primary(mut self, sites: &[u32]) -> Self {
        self.primary_sites = sites.to_vec();
        self
    }
    fn roles(mut self, roles: &[(u32, &'static str)]) -> Self {
        self.site_roles = roles.to_vec();
        self
    }
    fn class(mut self, c: &'static str) -> Self {
        self.candidate_class = c;
        self
    }
    fn scored(mut self, s: &'static str) -> Self {
        self.scored_against = s;
        self
    }
    fn pv(mut self, n: usize) -> Self {
        self.pv_len = n;
        self
    }
    fn hint(mut self, words: &[u32]) -> Self {
        self.hints = words.to_vec();
        self
    }
    fn image(mut self, entries: &[(u32, u32)]) -> Self {
        for &(addr, word) in entries {
            for (i, byte) in word.to_le_bytes().into_iter().enumerate() {
                self.init_memory
                    .insert((RV32_MEMORY_AS, addr + i as u32), byte);
            }
        }
        self
    }
    fn segment_budget(mut self, bytes: usize) -> Self {
        self.max_memory = Some(bytes);
        self
    }
    fn role_of(&self, pc: u32) -> &'static str {
        self.site_roles
            .iter()
            .find(|(p, _)| *p == pc)
            .map(|(_, r)| *r)
            .unwrap_or(ROLE_VALUE)
    }
    fn exe(&self) -> VmExe<F> {
        let exe = exe_from_words(&self.words);
        if self.init_memory.is_empty() {
            exe
        } else {
            exe.with_init_memory(self.init_memory.clone())
        }
    }
    fn streams(&self) -> Streams<F> {
        let mut s = Streams::<F>::default();
        s.hint_stream = self
            .hints
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| F::from_u32(b as u32))
            .collect::<VecDeque<_>>();
        s
    }
}
// =================================================================================
// PROGRAM STRUCTURES
//
// One builder per manifest structure. Each carries: the structure id, the constraint
// surface it exercises, and the path by which a forged write-back reaches the committed
// public output. Operands are IMMEDIATE on this target (`operand_source = immediate`):
// openvm's only non-immediate channel is the hint channel, which is a free column by
// design, and the shared spec forbids silently sourcing ordinary operands from it --
// see `st_hint_advice`, which measures exactly that.
// =================================================================================

/// Default operands. `a` is negative as i32 so DIV/REM/SRA/MULH exercise signs; `b` is a
/// small odd non-power-of-two so shifts (b & 31 = 23) and divisions are non-degenerate.
const A_DEF: u32 = 0x8765_4321;
const B_DEF: u32 = 0x0000_0037;

/// `st_boundary_operand` -- Boundary operand.
///
/// SURFACE: S17, the AIR-derived selectors and guard flags -- DivRem's `is_zero`, the
/// shift-amount decomposition, the INT_MIN/-1 special case, the limb-carry chain. The
/// forged word is an OPERAND, so the honest witness generator recomputes the result
/// coherently and the only thing that can come loose is a flag the AIR derives by copy.
/// PATH: the recomputed result is REVEALed into address space 3, one hop.
/// class=probe, operand_source=immediate, site_role=selector (the operands sit one mu
/// step from a constraint discontinuity, which is the whole experiment).
fn build_boundary_operand(funct3: u32, funct7: u32, a: u32, b: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, a)); //  0x00,0x04  x1 = a
    w.extend(li2(2, b)); //  0x08,0x0c  x2 = b
    w.push(alu(5, 1, 2, funct3, funct7)); // 0x10  x5 = a OP b
    w.push(reveal(5, 0, 0)); //             0x14
    w.push(terminate(0)); //                0x18
    w
}

/// `st_op_then_state` variant `mem` -- Operation then state, through memory.
///
/// SURFACE: the opcode chip AND the memory chip IN SERIES, with the register-consistency
/// argument as the carrier. A forged value needs only ONE unbound link in the chain, so
/// this measures where the binding actually is. This is the DECONFOUNDING shape: the
/// opcode axis moves independently of the structure axis (run-matrix rule R1).
/// PATH: OP -> x5 -> SW -> RAM -> LW -> x6 -> REVEAL -> address space 3.
fn build_op_then_state_mem(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x10  x5 = a OP b
    w.push(lui(3, RAM_BASE)); //                0x14  x3 = scratch      [address]
    w.push(sw(5, 3, 0)); //                     0x18  *x3 = x5
    w.push(lw(6, 3, 0)); //                     0x1c  x6 = *x3
    w.push(reveal(6, 0, 0)); //                 0x20
    w.push(terminate(0)); //                    0x24
    (w, vec![(0x14, ROLE_ADDRESS)])
}

/// `st_op_then_state` variant `addr` -- the forged value BECOMES an address (sink S2).
///
/// SURFACE: the opcode chip and the ADDRESS-FORMATION path in series. openvm is the
/// canonical case: `Rv32LoadStoreAdapterRecord::rs1_val` lands in BOTH `rs1_data[0..4]`
/// and `mem_ptr_limbs[0..2]` (adapters/loadstore.rs:510-519,541), so a coherent retarget
/// is expected rather than a self-contradiction.
/// PATH: OP -> x5 (an offset) -> ADD -> pointer -> LW -> REVEAL.
/// The four candidate objects are pre-stored at RAM_BASE, RAM_BASE+2^16, RAM_BASE^2^15
/// and RAM_BASE-2^16, i.e. exactly where the ADDRESS-role mu mask can redirect the load.
/// Operands are chosen so the honest offset is 0 for EVERY opcode on the axis: `a = 0`
/// makes every shift, multiply, divide and remainder zero, and ADD uses `b = 0` too.
fn build_op_then_state_addr(
    name: &str,
    funct3: u32,
    funct7: u32,
) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let (a, b) = if name == "ADD" { (0, 0) } else { (0, B_DEF) };
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //           0x00  x3 = base              [address]
    w.push(lui(7, PAY_0)); //              0x04
    w.push(sw(7, 3, 0)); //                0x08  *(base)        = PAY_0
    w.push(lui(7, PAY_1)); //              0x0c
    w.push(lui(4, RAM_PLUS_B1)); //        0x10                          [address]
    w.push(sw(7, 4, 0)); //                0x14  *(base+2^16)  = PAY_1
    w.push(lui(7, PAY_2)); //              0x18
    w.push(lui(4, RAM_XOR_B15)); //        0x1c                          [address]
    w.push(sw(7, 4, 0)); //                0x20  *(base^2^15)  = PAY_2
    w.push(lui(7, PAY_3)); //              0x24
    w.push(lui(4, RAM_MINUS_B1)); //       0x28                          [address]
    w.push(sw(7, 4, 0)); //                0x2c  *(base-2^16)  = PAY_3
    w.extend(li2(1, a)); //                0x30,0x34
    w.extend(li2(2, b)); //                0x38,0x3c
    w.push(alu(5, 1, 2, funct3, funct7)); //0x40 x5 = a OP b == 0        [address]
    w.push(add(6, 3, 5)); //               0x44  x6 = base + x5          [address]
    w.push(lw(8, 6, 0)); //                0x48
    w.push(reveal(8, 0, 0)); //            0x4c
    w.push(terminate(0)); //               0x50
    (
        w,
        vec![
            (0x00, ROLE_ADDRESS),
            (0x10, ROLE_ADDRESS),
            (0x1c, ROLE_ADDRESS),
            (0x28, ROLE_ADDRESS),
            (0x40, ROLE_ADDRESS),
            (0x44, ROLE_ADDRESS),
        ],
    )
}

/// `st_op_then_state` variant `branch` -- the forged value becomes a DECISION (sink S3).
///
/// SURFACE: the opcode chip and the branch chip in series -- the comparison columns and
/// the taken/not-taken -> next_pc transition.
/// PATH: OP -> x5 -> BEQ -> which arm runs -> x6 -> REVEAL.
/// The two arms are EQUAL LENGTH and use the SAME chips (one LUI, one JAL). They have to
/// be: openvm's metered pass runs UNPERTURBED and sizes the record arenas from it, so a
/// divergence that lengthens execution surfaces as EXECFAIL rather than as a verdict.
fn build_op_then_state_branch(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                    0x00,0x04
    w.extend(li2(2, B_DEF)); //                    0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //       0x10  x5 = a OP b     [selector]
    w.push(b_type(OP_BRANCH, 0b000, 5, 0, 0x0c)); //0x14 BEQ x5,x0,0x20
    w.push(lui(6, PAY_0)); //                      0x18  arm A: LUI
    w.push(jal(0, 0x0c)); //                       0x1c  arm A: JAL -> 0x28
    w.push(lui(6, PAY_1)); //                      0x20  arm B: LUI
    w.push(jal(0, 0x04)); //                       0x24  arm B: JAL -> 0x28
    w.push(reveal(6, 0, 0)); //                    0x28
    w.push(terminate(0)); //                       0x2c
    (w, vec![(0x10, ROLE_SELECTOR)])
}

/// `st_store_load` -- Store--load.
///
/// SURFACE: S5, read-after-write at ONE address -- does the offline-memory argument bind
/// the delivered value to the MOST RECENT write? `LoadStoreCoreRecord::read_data` and
/// `prev_data` (loadstore/core.rs:246,248) are real record fields here, which with
/// `jal_lui` and `hintstore` makes this one of only three openvm shapes whose core record
/// carries a value rather than an operand.
/// PATH: the loaded word is REVEALed directly.
/// `tail` appends a third store AFTER the load, which takes the finalize boundary row out
/// of the picture and so separates S5 from S9.
fn build_store_load(funct3: u32, funct7: u32, tail: bool) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //                0x00  x3 = slot          [address]
    w.extend(li2(1, A_DEF)); //                 0x04,0x08
    w.extend(li2(2, B_DEF)); //                 0x0c,0x10
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x14  v1
    w.push(sw(5, 3, 0)); //                     0x18  *slot = v1
    w.push(addi(4, 2, 1)); //                   0x1c  b + 1
    w.push(alu(6, 1, 4, funct3, funct7)); //    0x20  v2 (differs from v1)
    w.push(sw(6, 3, 0)); //                     0x24  *slot = v2
    w.push(lw(7, 3, 0)); //                     0x28  x7 = *slot
    if tail {
        w.push(sw(5, 3, 0)); //                 0x2c  *slot = v1 again
    }
    w.push(reveal(7, 0, 0));
    w.push(terminate(0));
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_redirect` -- Redirect.
///
/// SURFACE: S6, address derivation -- is the memory argument's address key bound to
/// rs1+imm, or free? The armed site is the LUI that forms the LOAD's pointer, formed
/// SEPARATELY from the stores' pointer so that a redirect actually changes what is read
/// instead of moving the whole conversation to another address.
/// PATH: the redirected load's value is REVEALed. The record claims a read of S1 while
/// delivering S2's contents.
/// The three sibling objects sit at exactly S1+2^16, S1^2^15 and S1-2^16, the three
/// alignment-preserving entries of the ADDRESS role mask.
fn build_redirect(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //                0x00  store pointer      [address]
    w.extend(li2(1, A_DEF)); //                 0x04,0x08
    w.extend(li2(2, B_DEF)); //                 0x0c,0x10
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x14  v1
    w.push(sw(5, 3, 0)); //                     0x18  *S1 = v1
    w.push(addi(4, 2, 1)); //                   0x1c
    w.push(alu(6, 1, 4, funct3, funct7)); //    0x20  v1b
    w.push(sw(6, 3, 0)); //                     0x24  *S1 = v1b  (second store, arms S5)
    w.push(lui(7, RAM_PLUS_B1)); //             0x28                     [address]
    w.push(lui(8, PAY_1)); //                   0x2c
    w.push(sw(8, 7, 0)); //                     0x30  *(S1+2^16) = PAY_1
    w.push(lui(9, RAM_XOR_B15)); //             0x34                     [address]
    w.push(lui(10, PAY_2)); //                  0x38
    w.push(sw(10, 9, 0)); //                    0x3c  *(S1^2^15) = PAY_2
    w.push(lui(11, RAM_MINUS_B1)); //           0x40                     [address]
    w.push(lui(12, PAY_3)); //                  0x44
    w.push(sw(12, 11, 0)); //                   0x48  *(S1-2^16) = PAY_3
    w.push(lui(13, RAM_BASE)); //               0x4c  THE SITE           [address]
    w.push(lw(14, 13, 0)); //                   0x50
    w.push(reveal(14, 0, 0)); //                0x54
    w.push(terminate(0)); //                    0x58
    (
        w,
        vec![
            (0x00, ROLE_ADDRESS),
            (0x28, ROLE_ADDRESS),
            (0x34, ROLE_ADDRESS),
            (0x40, ROLE_ADDRESS),
            (0x4c, ROLE_ADDRESS),
        ],
    )
}

/// `st_pointer_indirect` -- Pointer indirect.
///
/// SURFACE: composition of the memory plane with the ADDRESSING plane. The forged word is
/// a POINTER loaded out of memory; the dereference that follows is entirely honest. It
/// tests whether an unbound quantity in the memory plane becomes a CAPABILITY in the
/// addressing plane -- the escalation step a value forgery needs to become address
/// control.
/// PATH: LW (forged rd = a pointer) -> LW (honest deref) -> REVEAL.
/// PP, &A and &B are 2^16 apart so the ADDRESS mask can move the pointer between them.
fn build_pointer_indirect() -> (Vec<u32>, Vec<(u32, &'static str)>) {
    const ADDR_A: u32 = RAM_BASE + 0x0001_0000;
    const ADDR_B: u32 = RAM_BASE + 0x0002_0000;
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //   0x00  pp                              [address]
    w.push(lui(4, ADDR_A)); //     0x04  &A                              [address]
    w.push(lui(5, PAY_0)); //      0x08
    w.push(sw(5, 4, 0)); //        0x0c  A = PAY_0
    w.push(lui(6, ADDR_B)); //     0x10  &B                              [address]
    w.push(lui(7, PAY_1)); //      0x14
    w.push(sw(7, 6, 0)); //        0x18  B = PAY_1
    w.push(sw(4, 3, 0)); //        0x1c  *pp = &A
    w.push(sw(6, 3, 0)); //        0x20  *pp = &B    (the live pointer)
    w.push(lw(8, 3, 0)); //        0x24  p = *pp     THE SITE            [address]
    w.push(lw(9, 8, 0)); //        0x28  honest dereference
    w.push(reveal(9, 0, 0)); //    0x2c
    w.push(terminate(0)); //       0x30
    (
        w,
        vec![
            (0x00, ROLE_ADDRESS),
            (0x04, ROLE_ADDRESS),
            (0x10, ROLE_ADDRESS),
            (0x24, ROLE_ADDRESS),
        ],
    )
}

/// `st_hazard_chain` -- Hazard chain.
///
/// SURFACE: S4, register write-after-write retirement -- the second write's
/// `(prev_value, prev_timestamp)` must equal the first write's record. openvm's
/// `writes_aux.prev_data` (rdwrite.rs:271-278, alu.rs:295-297) and `prev_timestamp` are
/// real record fields and are DEGENERATE in every frozen seed.
/// PATH: the second (live) write reaches the REVEAL directly. The first write is retired
/// before any read -- but openvm commits the whole final image INCLUDING the register
/// file, so even a retired write is state; the two site classes are distinguished in the
/// CSV by their pc.
fn build_hazard_chain(funct3: u32, funct7: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(addi(4, 2, 1)); //                   0x10  b+1
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x14  v1
    w.push(add(9, 5, 0)); //                    0x18  W1: x9 = v1  (retired)
    w.push(alu(6, 1, 4, funct3, funct7)); //    0x1c  v2
    w.push(add(9, 6, 0)); //                    0x20  W2: x9 = v2  (live)
    w.push(reveal(9, 0, 0)); //                 0x24
    w.push(terminate(0)); //                    0x28
    w
}

/// `st_provenance_chain` variant `d2` -- Provenance chain, depth 2, register-only.
///
/// SURFACE: the operand-READ side of a chip that did not produce the value. A consumer's
/// operand limb decomposition and range checks are usually tighter than the same chip's
/// result binding, so the measurement is the HOP at which ACCEPT flips to REJECT.
/// PATH: OP1 -> x5 -> ADD (the consumer) -> x6 -> REVEAL.
fn build_provenance_d2(funct3: u32, funct7: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x10  t = a OP1 b
    w.push(add(6, 5, 1)); //                    0x14  x = t + a   (consumer_set: ADD)
    w.push(reveal(6, 0, 0)); //                 0x18
    w.push(terminate(0)); //                    0x1c
    w
}

/// `st_provenance_chain` variant `d4` -- LUI -> store -> load -> consumer -> REVEAL.
///
/// The single most valuable provenance shape on openvm: `Rv32JalLuiCoreRecord::rd_data`
/// is the one rv32im core record with a RESULT field, so a mutation at 0x04 is COHERENT
/// (record and memory agree) instead of dying in the prover's offline memory check. This
/// is the only structure in which that coherent forgery then has to survive a store, a
/// load and somebody else's operand columns before it is committed.
/// PATH: LUI (hook site 2) -> SW -> RAM -> LW -> OP2 operand columns -> REVEAL.
fn build_provenance_d4(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //                0x00                     [address]
    w.push(lui(5, PAY_0)); //                   0x04  t, from hook site 2
    w.push(sw(5, 3, 0)); //                     0x08
    w.push(lw(6, 3, 0)); //                     0x0c
    w.extend(li2(1, A_DEF)); //                 0x10,0x14
    w.push(alu(7, 6, 1, funct3, funct7)); //    0x18  the consumer chip
    w.push(reveal(7, 0, 0)); //                 0x1c
    w.push(terminate(0)); //                    0x20
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_fanout_read` -- Fan-out read.
///
/// SURFACE: whether the register BUS binds the read value, or only the producing chip
/// does. Two chip rows consume the same register at two clks; on openvm the landing
/// points are `BaseAluCoreRecord::b/c` versus the adapter's read-aux records.
/// PATH: both uses feed the REVEAL, so a forgery that survives at one read point and not
/// the other still changes the committed output.
fn build_fanout_read(funct3: u32, funct7: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x10  t          THE SITE
    w.push(addi(6, 5, 0x123)); //               0x14  u = t + K1   (read point 1)
    w.push(xori(7, 5, 0x2aa)); //               0x18  v = t ^ K2   (read point 2)
    w.push(xor(8, 6, 7)); //                    0x1c
    w.push(reveal(8, 0, 0)); //                 0x20
    w.push(terminate(0)); //                    0x24
    w
}

/// `st_reg_alias` -- Register aliasing.
///
/// SURFACE: within-row ordering of the register memory argument -- two reads and a write
/// at ONE address at ONE clk, distinguished only by subcycle, against openvm's two
/// read-aux records and one write-aux record.
/// PATH: the result is REVEALed as usual.
/// `rs1rs2` is `OP x6,x5,x5`; `rdrs1rs2` is `OP x5,x5,x5`.
fn build_reg_alias(funct3: u32, funct7: u32, rd_aliases: bool) -> Vec<u32> {
    let rd = if rd_aliases { 5 } else { 6 };
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.push(add(5, 1, 0)); //                    0x08  x5 = a
    w.push(alu(rd, 5, 5, funct3, funct7)); //   0x0c  rd = x5 OP x5
    w.push(reveal(rd, 0, 0)); //                0x10
    w.push(terminate(0)); //                    0x14
    w
}

/// `st_dead_write` -- Dead write-back.
///
/// SURFACE: none, deliberately. The mutation is invisible to the honest instruction
/// stream, so the perturbed execution is instruction-for-instruction identical to the
/// honest one and any REJECT is attributable to the constraint system alone.
/// PATH -- AND THE REASON THE VERDICT FLIPS ON THIS TARGET: openvm chains
/// `final_memory_root` across segments (arch/vm.rs:1268-1319) and `MemoryDimensions`
/// indexes ALL address spaces from ADDR_SPACE_OFFSET = 1, so the final REGISTER FILE is
/// inside the committed root. A dead register write IS observable here, and an accepted
/// one with a changed root is a real -- if weaker -- state forgery. Scored against
/// `in_circuit_state_object`, i.e. the digest column, NOT the AS3 byte read, and
/// therefore under `accepted_case_v2`.
fn build_dead_write(funct3: u32, funct7: u32, overwritten: bool) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x10  DEAD
    if overwritten {
        w.push(addi(5, 0, 0x111)); //           0x14  x5 overwritten before any read
        w.push(reveal(5, 0, 0)); //             0x18
    } else {
        w.push(addi(6, 0, 0x111)); //           0x14  x5 never read at all
        w.push(reveal(6, 0, 0)); //             0x18
    }
    w.push(terminate(0)); //                    0x1c
    w
}

/// `st_finalize_only` -- Finalize-only write.
///
/// SURFACE: S9, the memory/register finalise boundary row and the committed final image.
/// The ONLY structure in which the forged value reaches the public object without
/// traversing any consumer chip, operand bus or commit chip.
/// PATH: purely through `MemoryMerklePvs.final_root`; the DATA output is a constant and
/// does not move. First-class probe on openvm because the root covers the whole image.
/// Scored against `in_circuit_state_object` -- reading only AS3 here would report a
/// guaranteed false negative.
fn build_finalize_only(funct3: u32, funct7: u32, to_mem: bool) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    let mut roles = Vec::new();
    if to_mem {
        w.push(lui(3, RAM_BASE)); //            0x00                     [address]
        roles.push((0x00u32, ROLE_ADDRESS));
    }
    w.extend(li2(1, A_DEF));
    w.extend(li2(2, B_DEF));
    w.push(alu(5, 1, 2, funct3, funct7));
    if to_mem {
        w.push(sw(5, 3, 0)); // stored to a scratch address never read again
    }
    w.push(lui(9, PAY_CONST));
    w.push(reveal(9, 0, 0));
    w.push(terminate(0));
    (w, roles)
}

/// `st_x0_dark_write` -- x0 dark write.
///
/// SURFACE: the write-suppression predicate. openvm has a `needs_write` column with a
/// `u32::MAX` sentinel (adapters/rdwrite.rs:364, loadstore.rs:474).
/// CONFIRMED STRUCTURAL LIMIT ON THIS TARGET, recorded here rather than asserted: neither
/// x0 form carries a hookable write-back, so the dark write's own pc is ABSENT from this
/// seed's derived site list and only its neighbours are enumerated.
///   * `OP x0,x1,x2` never reaches a chip at all -- `from_r_type` transpiles rd == 0 to a
///     PHANTOM nop (crates/toolchain/transpiler/src/util.rs:27). The word is kept in the
///     program below so the transpiler's behaviour is visible in the artefact.
///   * `LW x0,0(x3)` DOES reach the loadstore chip with `enabled == 0`, but the adapter
///     then takes the `else` branch, sets `rd_rs2_ptr = u32::MAX` and calls
///     `increment_timestamp()` instead of `timed_write` (adapters/loadstore.rs:471-476).
/// PATH (of the neighbours): x11 -> REVEAL; the honest output is 0, so any accepted
/// forgery is the cleanest possible output-changed signal.
fn build_x0_dark_write(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //                0x00                     [address]
    w.extend(li2(1, A_DEF)); //                 0x04,0x08
    w.extend(li2(2, B_DEF)); //                 0x0c,0x10
    w.push(sw(1, 3, 0)); //                     0x14
    w.push(alu(0, 1, 2, funct3, funct7)); //    0x18  ALU dark write -> PHANTOM nop
    w.push(lw(0, 3, 0)); //                     0x1c  LOAD dark write -> needs_write = 0
    w.push(add(11, 0, 0)); //                   0x20  honest x11 = 0
    w.push(reveal(11, 0, 0)); //                0x24
    w.push(terminate(0)); //                    0x28
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_pv_plumbing` variant `words8` -- Public-value plumbing, eight words.
///
/// SURFACE: S14, the output path itself. On openvm a REVEAL is a `STOREW` into address
/// space 3 (transpiler lib.rs:174-186), so the question is whether EACH word is bound
/// individually or only the aggregate root. Address space 3 has exactly
/// `num_public_values = 32` cells, so eight words at offsets 0,4,..,28 fill it exactly.
/// PATH: each word is committed directly; `pv_len = 32` so the CSV records all of it.
fn build_pv_words8(funct3: u32, funct7: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                     0x00,0x04
    w.extend(li2(2, B_DEF)); //                     0x08,0x0c
    for i in 0..8u32 {
        w.push(xori(3, 1, i as i32)); //            a ^ i
        w.push(alu(5, 3, 2, funct3, funct7)); //    (a ^ i) OP b
        w.push(reveal(5, 0, 4 * i)); //             -> public_values[4i..4i+4]
    }
    w.push(terminate(0));
    w
}

/// `st_pv_plumbing` variant `alias` -- two REVEALs of DIFFERENT values at the SAME offset.
///
/// SURFACE: whether the output region behaves as memory (last writer wins, and the
/// intermediate write is still a row on the bus) or as a set of one-shot commitments.
/// PATH: offset 0 is committed twice; the honest output is the second value.
fn build_pv_alias(funct3: u32, funct7: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(2, B_DEF)); //                 0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //    0x10
    w.push(reveal(5, 0, 0)); //                 0x14  first write to offset 0
    w.push(addi(6, 5, 1)); //                   0x18
    w.push(reveal(6, 0, 0)); //                 0x1c  second write, same offset
    w.push(terminate(0)); //                    0x20
    w
}

/// `st_hint_advice` -- Nondeterministic advice. CALIBRATION, NOT A PROBE.
///
/// SURFACE: S18, the boundary of "spec". A hint word is a free column BY DESIGN, so an
/// output-changing ACCEPT here is a TRUE accept and a FALSE finding. Its purpose is the
/// converse: if this does not accept, the hook does not reach openvm's constraint system
/// and every REJECT this target reports is uninterpretable.
/// `Rv32HintStoreVar::data` (hintstore/mod.rs:313) is copied verbatim into `cols.data`
/// (:606) and its ONLY AIR constraint is the byte-pair range check (:235).
/// PATH: hint stream -> record.data (hook site 3) -> RAM -> LW -> REVEAL.
/// `checked` adds the in-guest comparison the manifest asks for, which is the real
/// question: does an in-guest check bind the value in the CIRCUIT, or only in the
/// executor? A failed check terminates with exit code 1, which openvm's verifier sees.
fn build_hint_advice(checked: bool) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //             0x00                        [address]
    w.push(hint_storew(3)); //               0x04  *x3 = next hint word
    w.push(lw(5, 3, 0)); //                  0x08
    if checked {
        w.push(lui(6, HINT_WORD)); //        0x0c  the value the guest expects
        w.push(b_type(OP_BRANCH, 0b001, 5, 6, 0x08)); // 0x10 BNE -> 0x18
        w.push(jal(0, 0x08)); //             0x14  -> 0x1c
        w.push(terminate(1)); //             0x18  in-guest check failed
        w.push(reveal(5, 0, 0)); //          0x1c
        w.push(terminate(0)); //             0x20
    } else {
        w.push(reveal(5, 0, 0)); //          0x0c
        w.push(terminate(0)); //             0x10
    }
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_subword_lane` -- Sub-word lane.
///
/// SURFACE: S7, lane selection and extension in the load AIR; lane merge and
/// sibling-lane preservation in the store AIR.
/// CORRECTION TO THE MANIFEST'S openvm CELL, recorded because it changes what is
/// reachable: the store side is NOT blocked on admitting a narrow `timed_write`. openvm's
/// loadstore adapter merges the lane in the core and always writes the FULL aligned
/// 4-byte word through `timed_write` (adapters/loadstore.rs:459-465), so SB and SH reach
/// the existing 4-byte hook exactly as SW does. Both variants are therefore shipped.
/// PATH (load): the narrowed lane is the rd write-back and is REVEALed directly.
/// PATH (store): the merged word is read back with LW and REVEALed, which additionally
/// shows whether the UNTOUCHED sibling lanes were bound.
fn build_subword_load(funct3: u32, off: i32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //             0x00                        [address]
    w.extend(li2(1, A_DEF)); //              0x04,0x08
    w.push(sw(1, 3, 0)); //                  0x0c
    w.push(load(5, 3, off, funct3)); //      0x10  the narrowing load
    w.push(reveal(5, 0, 0)); //              0x14
    w.push(terminate(0)); //                 0x18
    (w, vec![(0x00, ROLE_ADDRESS)])
}
fn build_subword_store(funct3: u32, off: i32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //             0x00                        [address]
    w.extend(li2(1, A_DEF)); //              0x04,0x08
    w.push(sw(1, 3, 0)); //                  0x0c  the full word first
    w.extend(li2(2, B_DEF)); //              0x10,0x14
    w.push(store(2, 3, off, funct3)); //     0x18  the narrow store (merges one lane)
    w.push(lw(5, 3, 0)); //                  0x1c  read the merged word back
    w.push(reveal(5, 0, 0)); //              0x20
    w.push(terminate(0)); //                 0x24
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_indirect_jump` variant `table` -- Indirect jump through a two-entry table.
///
/// SURFACE: S12, the pc transition computed from a register and the program-table lookup
/// at the forged pc. openvm is the richest target for it: `Rv32JalrCoreRecord::rs1_val`
/// is a real record field feeding `rs1_data[0..4]` (jalr/core.rs:178,310) AND `from_pc`
/// is re-encoded into `rd_data[0..3]` (:311-318) -- two copies of the pc in one row that
/// the AIR never equates.
/// PATH: the selector (not the pointer) is the armed site, so mu = plus_B0 moves the
/// jump by one TABLE ENTRY rather than by one byte: sel -> sel*8 -> JALR target -> which
/// body runs -> x5 -> REVEAL. The two bodies are EQUAL LENGTH and use the same chips.
fn build_indirect_jump_table() -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(addi(3, 0, 0)); //                0x00  sel = 0               [selector]
    w.push(slli(4, 3, 3)); //                0x04  sel * 8 (one body)    [selector]
    w.push(addi(6, 0, 0x14)); //             0x08  table base pc         [selector]
    w.push(add(7, 6, 4)); //                 0x0c  target                [selector]
    w.push(jalr(1, 7, 0)); //                0x10  -> 0x14 + 8*sel
    w.push(addi(5, 0, 0x101)); //            0x14  body 0
    w.push(jal(0, 0x0c)); //                 0x18  -> 0x24
    w.push(addi(5, 0, 0x202)); //            0x1c  body 1
    w.push(jal(0, 0x04)); //                 0x20  -> 0x24
    w.push(reveal(5, 0, 0)); //              0x24
    w.push(terminate(0)); //                 0x28
    (
        w,
        vec![
            (0x00, ROLE_SELECTOR),
            (0x04, ROLE_SELECTOR),
            (0x08, ROLE_SELECTOR),
            (0x0c, ROLE_SELECTOR),
        ],
    )
}

/// `st_indirect_jump` variant `bit0` -- the RISC-V "JALR clears bit 0" requirement.
///
/// SURFACE: openvm's `run_jalr` computes `to_pc = rs1 + imm` with NO bit-0 mask
/// (jalr/core.rs:324-328), while the interpreter's `get_pc_index` is `pc / 4`
/// (arch/interpreter.rs:556) and so silently truncates. The consequence is that the
/// candidate does NOT die in the executor: it runs to completion with the entire
/// subsequent pc chain shifted by one, and the verdict therefore comes from the program
/// bus rather than from a trap. That makes `xor_b0` -- forbidden at address sites
/// everywhere else -- the point of this variant, exactly as the shared spec's role-mask
/// exception says.
/// PATH: the landing body's value reaches the REVEAL; the pc chain reaches the connector
/// and program AIRs.
fn build_indirect_jump_bit0() -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(addi(7, 0, 0x0c)); //             0x00  target = 0x0c         [selector]
    w.push(jalr(1, 7, 0)); //                0x04
    w.push(addi(5, 0, 0x555)); //            0x08  skipped honestly
    w.push(addi(5, 0, 0x111)); //            0x0c  the landing body
    w.push(reveal(5, 0, 0)); //              0x10
    w.push(terminate(0)); //                 0x14
    (w, vec![(0x00, ROLE_SELECTOR)])
}

/// `st_pc_imm_value` -- PC-immediate value. THE HIGHEST-VALUE openvm SHAPE.
///
/// SURFACE: S13, value derivation from the pc column and from the program table's
/// immediate, with no register operand in the relation. It asks the one question no other
/// structure asks -- is rd bound to the COMMITTED PROGRAM? -- and the answer route is the
/// preprocessed program/fetch bus, not the register bus.
/// PATH: `lui` and `jal` both land in `Rv32JalLuiCoreRecord::rd_data`
/// (jal_lui/core.rs:198), the ONLY rv32im core record with a result field and LACUNA hook
/// site 2, so this is the one openvm shape in which a FULLY COHERENT record+memory
/// forgery reaches the verifier instead of dying in the prover's offline memory check.
/// `auipc` is the PAIRED PREDICTED NEGATIVE: `Rv32AuipcCoreRecord{from_pc, imm}` has no
/// result field and the filler recomputes rd, so only the memory copy can move.
/// The pc/immediate-derived word is the committed DATUM here rather than a pointer, which
/// is what turns the site from a guaranteed EXECFAIL into a clean verdict.
fn build_pc_imm_value(variant: &str) -> Vec<u32> {
    match variant {
        "lui" => vec![
            lui(5, 0x1234_5000), //   0x00  hook site 2
            reveal(5, 0, 0),      //   0x04
            terminate(0),         //   0x08
        ],
        "auipc" => vec![
            u_type(OP_AUIPC, 5, 0x12345), // 0x00  no core-record result field
            reveal(5, 0, 0),               // 0x04
            terminate(0),                  // 0x08
        ],
        "jal" => vec![
            jal(5, 0x08),        //   0x00  rd = pc + 4, via hook site 2; -> 0x08
            addi(5, 0, 0x555),   //   0x04  skipped
            reveal(5, 0, 0),     //   0x08
            terminate(0),        //   0x0c
        ],
        _ => unreachable!(),
    }
}

/// `st_early_exit` -- Early exit.
///
/// SURFACE: S14', COMPLETENESS of the public-value stream. openvm's verifier checks
/// `is_terminate` and `exit_code == Success`; is it also bound to the fact that the
/// program reached its real end and that the REVEAL actually happened?
/// PATH: forging the branch condition to zero skips the REVEAL entirely, so the committed
/// output is the untouched initial content of address space 3 rather than the honest
/// word. UNFALSIFIABLE UNDER THE STRICT PREDICATE BY CONSTRUCTION when the output becomes
/// empty; scored under `accepted_case_v2`.
fn build_early_exit(funct3: u32, funct7: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                     0x00,0x04
    w.extend(li2(2, B_DEF)); //                     0x08,0x0c
    w.push(alu(5, 1, 2, funct3, funct7)); //        0x10                 [selector]
    w.push(b_type(OP_BRANCH, 0b000, 5, 0, 0x08)); //0x14  BEQ -> 0x1c
    w.push(reveal(5, 0, 0)); //                     0x18  skipped if forged to zero
    w.push(terminate(0)); //                        0x1c
    (w, vec![(0x10, ROLE_SELECTOR)])
}

/// `st_control_flow` -- Control flow. The BRANCH CHIP is the opcode axis here.
///
/// SURFACE: S11, the branch chip's comparison columns and the taken/not-taken -> next_pc
/// transition. The only structure in which a forged value changes WHICH ROWS EXIST.
/// PATH (`datadiv`): the selected value is REVEALed directly.
/// PATH (`dataident`): both arms write the SAME value, so the DATA output is held fixed
/// and only the pc/clk chain and the per-chip row identity move -- which isolates the pc
/// binding from the value binding. On openvm that reaches `verify_segments`'s chained
/// initial/final pc and the committed final root, so it is scored against the state
/// object.
/// Both arms are EQUAL LENGTH and use the SAME chips, because the metered pass sizes the
/// record arenas from an UNPERTURBED execution.
fn build_control_flow(bfunct3: u32, data_divergent: bool) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let (v_a, v_b) = if data_divergent {
        (PAY_0, PAY_1)
    } else {
        (PAY_0, PAY_0)
    };
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                         0x00,0x04
    w.extend(li2(2, B_DEF)); //                         0x08,0x0c
    w.push(add(5, 1, 0)); //                            0x10  the condition [selector]
    w.push(b_type(OP_BRANCH, bfunct3, 5, 2, 0x0c)); //  0x14  -> 0x20
    w.push(lui(6, v_a)); //                             0x18  arm A: LUI
    w.push(jal(0, 0x0c)); //                            0x1c  arm A: JAL -> 0x28
    w.push(lui(6, v_b)); //                             0x20  arm B: LUI
    w.push(jal(0, 0x04)); //                            0x24  arm B: JAL -> 0x28
    w.push(reveal(6, 0, 0)); //                         0x28
    w.push(terminate(0)); //                            0x2c
    (w, vec![(0x10, ROLE_SELECTOR)])
}

/// `st_loop_repeat` -- Loop repeat: ONE static pc, N dynamic write-backs.
///
/// SURFACE: S16, lookup and range-check MULTIPLICITY accounting, plus per-row identity
/// and the pc/clk continuity chain. Forging one of N identical rows moves one
/// multiplicity out of a bucket of size N; forging all N moves the whole bucket.
/// PATH: the accumulator is REVEALed directly.
/// The loop COUNTER is a separate register that the accumulator site never touches, so
/// the trip count -- and hence the honestly-metered arena size -- does not change when
/// the accumulator is forged. The arming is nth = -1 (every execution), because
/// `TARGET_CAPABILITIES.capability.nth_supported` is NOT DETERMINED on openvm and
/// run-matrix rule R5 forbids emitting a per-execution nth until it is; `site_execs` in
/// the CSV records how many executions were actually perturbed.
fn build_loop_repeat(funct3: u32, funct7: u32, n: u32) -> Vec<u32> {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                 0x00,0x04
    w.extend(li2(6, n)); //                     0x08,0x0c  counter
    w.push(addi(5, 0, 0)); //                   0x10  acc = 0
    w.push(alu(5, 5, 1, funct3, funct7)); //    0x14  LOOP: acc = acc OP a
    w.push(addi(6, 6, -1)); //                  0x18
    w.push(b_type(OP_BRANCH, 0b001, 6, 0, -8)); //0x1c BNE x6,x0,0x14
    w.push(reveal(5, 0, 0)); //                 0x20
    w.push(terminate(0)); //                    0x24
    w
}

/// `st_multishard` -- Cross-shard continuation.
///
/// SURFACE: S15, the chained public values that openvm's `verify_segments` carries
/// between segment proofs -- `final_memory_root` and the pc (arch/vm.rs:1154,1268-1319).
/// Every candidate in the published corpus is single-segment, so this machinery is
/// verified today against a one-element sequence.
/// PATH: the value is written to RAM in the first segment and read back in a later one,
/// then REVEALed. The seed lowers the METERED pass's memory budget
/// (`MeteredCtx::with_max_memory`) so the two loops fall in different segments; nothing
/// about keygen or the AIRs changes, so this shares the one proving key with every other
/// seed. RISK, recorded rather than hidden: the metered pass sizes segments HONESTLY, so
/// a perturbation that moves a segment boundary surfaces as EXECFAIL, and whether this
/// program segments at all at a given budget is a run-time fact the baseline row reports.
fn build_multishard(n: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.extend(li2(1, A_DEF)); //                     0x00,0x04
    w.extend(li2(6, n)); //                         0x08,0x0c
    w.push(addi(5, 0, 0)); //                       0x10
    w.push(add(5, 5, 1)); //                        0x14  loop 1 body
    w.push(addi(6, 6, -1)); //                      0x18
    w.push(b_type(OP_BRANCH, 0b001, 6, 0, -8)); //  0x1c
    w.push(lui(3, RAM_BASE)); //                    0x20                 [address]
    w.push(sw(5, 3, 0)); //                         0x24  CARRY = s
    w.extend(li2(7, n)); //                         0x28,0x2c
    w.push(addi(8, 0, 0)); //                       0x30
    w.push(add(8, 8, 1)); //                        0x34  loop 2 body (pads into shard j)
    w.push(addi(7, 7, -1)); //                      0x38
    w.push(b_type(OP_BRANCH, 0b001, 7, 0, -8)); //  0x3c
    w.push(lw(9, 3, 0)); //                         0x40  read CARRY back
    w.push(reveal(9, 0, 0)); //                     0x44
    w.push(terminate(0)); //                        0x48
    (w, vec![(0x20, ROLE_ADDRESS)])
}

/// `st_whole_program` -- Whole program.
///
/// SURFACE: no unique one, which is the point: it provides a realistic OPCODE CENSUS in a
/// single shard with many chips live simultaneously, so lookup multiplicities interact,
/// and it answers "does this find anything on code somebody would actually run". The body
/// is a Fibonacci recurrence with shifts, a word store/load round trip, a multiply and a
/// sub-word store/load round trip, so LUI, ADDI, ADD, SLLI, SRLI, XOR, SW, LW, MUL, SB,
/// LBU, BNE, REVEAL and TERMINATE are all live in one trace.
/// PATH: the final accumulator is REVEALed. Both public-output objects must be recorded:
/// on pico this structure is the ONE place where the byte output and the committed digest
/// have been observed to diverge.
fn build_whole_program(n: u32) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_BASE)); //                    0x00                 [address]
    w.push(addi(1, 0, 0)); //                       0x04  x = 0
    w.push(addi(2, 0, 1)); //                       0x08  y = 1
    w.extend(li2(6, n)); //                         0x0c,0x10
    w.push(add(4, 1, 2)); //                        0x14  LOOP: t = x + y
    w.push(add(1, 2, 0)); //                        0x18  x = y
    w.push(add(2, 4, 0)); //                        0x1c  y = t
    w.push(slli(7, 2, 3)); //                       0x20
    w.push(srli(8, 2, 5)); //                       0x24
    w.push(xor(9, 7, 8)); //                        0x28
    w.push(sw(9, 3, 0)); //                         0x2c
    w.push(lw(10, 3, 0)); //                        0x30
    w.push(alu(11, 10, 2, 0b000, 0x01)); //         0x34  MUL
    w.push(store(11, 3, 4, 0b000)); //              0x38  SB
    w.push(load(12, 3, 4, 0b100)); //               0x3c  LBU
    w.push(addi(6, 6, -1)); //                      0x40
    w.push(b_type(OP_BRANCH, 0b001, 6, 0, -0x30)); //0x44 BNE -> 0x14
    w.push(xor(13, 2, 12)); //                      0x48
    w.push(reveal(13, 0, 0)); //                    0x4c
    w.push(terminate(0)); //                        0x50
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_initial_state` -- Initial state. DECLARED NEGATIVE, SHIPPED TO BE MEASURED.
///
/// SURFACE: S8, the boundary chip's claim about pre-execution RAM.
/// CONFIRMED BLOCKER on openvm, stated by the manifest and re-checked in the tree: the
/// boundary chip is built from the MEMORY IMAGE, not from any execution record
/// (crates/vm/src/system/memory/persistent.rs), and the volatile path whose `initial_data`
/// was a free witness column was REMOVED in v2.0.0. There is therefore no record
/// correspondent for the initial value and no record-layer mutation can move it. The only
/// hookable site in this seed is the LOAD's rd write-back, which forges the DELIVERED
/// value while `LoadStoreCoreRecord::read_data` keeps the honest one -- a guaranteed bus
/// imbalance. `candidate_class = control`, `expected_verdict = REJECT`: the negative is
/// measured, not asserted, and its REJECT is the interpretability anchor for this
/// target's other REJECTs.
fn build_initial_state() -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let mut w = Vec::new();
    w.push(lui(3, RAM_UNWRITTEN)); //        0x00  never written by this program [address]
    w.push(lw(5, 3, 0)); //                  0x04
    w.push(reveal(5, 0, 0)); //              0x08
    w.push(terminate(0)); //                 0x0c
    (w, vec![(0x00, ROLE_ADDRESS)])
}

/// `st_initial_image` -- Initial image. THE PAIRED NEGATIVE for `st_initial_state`.
///
/// SURFACE: whether the initial value of an IN-IMAGE address -- one the committed program
/// image initialises to a NON-ZERO value, the `.data` case rather than the `.bss` case --
/// is bound to the vk-committed image or is a free boundary column. Same chip as
/// `st_initial_state`, different column, OPPOSITE expected verdict.
/// WHY IT IS A DISTINCT SURFACE: the project's loader-layer ledger records `.data`/`.bss`
/// boundary defects on five of eight VMs with three end-to-end golds, and a seed that
/// only ever reads a never-written zero address cannot reach any of them.
/// PATH: the initialised word is REVEALed directly. `class = control`,
/// `expected_verdict = REJECT` -- but an ACCEPT here is NOT a control failure: it would
/// mean the prover can claim an initial value the vk does not commit, which is a
/// probe-grade finding and must be re-graded as one.
/// `bssboundary` reads the word IMMEDIATELY AFTER the initialised one, which the image
/// does not cover -- the dword-boundary shape the ledger's defects sit on.
fn build_initial_image(at_boundary: bool) -> (Vec<u32>, Vec<(u32, &'static str)>) {
    let off = if at_boundary { 4 } else { 0 };
    let mut w = Vec::new();
    w.push(lui(3, RAM_IMAGE)); //            0x00                        [address]
    w.push(lw(5, 3, off)); //                0x04
    w.push(reveal(5, 0, 0)); //              0x08
    w.push(terminate(0)); //                 0x0c
    (w, vec![(0x00, ROLE_ADDRESS)])
}

// =================================================================================
// The seed table. Adding a structure is adding rows HERE; the enumeration loop below
// is structure-agnostic.
// =================================================================================

/// The boundary-operand table: (variant, a, b) per opcode family, from the manifest's
/// `variant_suffixes` for `st_boundary_operand`.
fn boundary_cases(name: &str) -> Vec<(&'static str, u32, u32)> {
    match name {
        "SLL" | "SRL" | "SRA" => vec![
            // shift amount lives in a REGISTER (SLL, not SLLI) so it is perturbable, and
            // sits at 1 -- one mu step from 0, 32 and 2^16.
            ("shamt", A_DEF, 0x0000_0001),
            ("limb", 0x0000_FFFF, 0x0000_0001),
        ],
        "DIV" | "DIVU" | "REM" | "REMU" => vec![
            ("zero", A_DEF, 0x0000_0001), // mu(b) -> 0 is the zero-divisor selector
            ("intmin", 0x8000_0001, 0xFFFF_FFFF), // mu(a) -> INT_MIN with b = -1
            ("exactdiv", 0x0000_0008, 0x0000_0002),
            ("limb", 0x0000_FFFF, 0x0000_0001),
        ],
        "MUL" | "MULH" | "MULHU" | "MULHSU" => vec![
            ("limbmax", 0xFFFF_FFFF, 0xFFFF_FFFF),
            ("limb", 0x0000_FFFF, 0x0000_0001),
            ("intmin", 0x8000_0001, 0xFFFF_FFFF),
        ],
        // the bound reference arm of the deconfounding pair
        _ => vec![("limb", 0x0000_FFFF, 0x0000_0001)],
    }
}

fn seeds() -> Vec<Seed> {
    let mut out: Vec<Seed> = Vec::new();

    // ---- FROZEN: the published "Single operation" corpus. ---------------------
    // Same words, same site list, same order as the shipped enumeration. `write_sites`
    // is asserted to reproduce the hard-coded WRITE_SITES exactly, so deriving the sites
    // from the program cannot have moved a published candidate.
    for (name, funct3, funct7) in opcodes() {
        let words = build_words(funct3, funct7, A_DEF, B_DEF);
        // Checked in release too: this is the guarantee that deriving sites from the
        // program did not move a single published candidate.
        assert_eq!(write_sites(&words), WRITE_SITES.to_vec());
        out.push(
            Seed::new(
                format!("op_{}", name.to_lowercase()),
                "st_single_op",
                "Single operation",
                name,
                words,
            )
            .primary(&[OP_SITE]),
        );
    }

    let axis = deconfound_axis();

    // ---- st_boundary_operand ---------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        for (variant, a, b) in boundary_cases(name) {
            out.push(
                Seed::new(
                    format!("st_boundary_operand_{}_{variant}", name.to_lowercase()),
                    "st_boundary_operand",
                    "Boundary operand",
                    name,
                    build_boundary_operand(*funct3, *funct7, a, b),
                )
                .primary(&[0x00, 0x04, 0x08, 0x0c])
                .roles(&[
                    (0x00, ROLE_SELECTOR),
                    (0x04, ROLE_SELECTOR),
                    (0x08, ROLE_SELECTOR),
                    (0x0c, ROLE_SELECTOR),
                ]),
            );
        }
    }

    // ---- st_op_then_state (the deconfounding shape: 3 variants x the opcode axis) --
    for (name, funct3, funct7) in axis.iter() {
        let (w, roles) = build_op_then_state_mem(*funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_op_then_state_{}_mem", name.to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                name,
                w,
            )
            .primary(&[0x10])
            .roles(&roles),
        );
        let (w, roles) = build_op_then_state_addr(name, *funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_op_then_state_{}_addr", name.to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                name,
                w,
            )
            .primary(&[0x40, 0x44])
            .roles(&roles),
        );
        let (w, roles) = build_op_then_state_branch(*funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_op_then_state_{}_branch", name.to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                name,
                w,
            )
            .primary(&[0x10])
            .roles(&roles),
        );
    }

    // ---- st_store_load ---------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        for tail in [false, true] {
            let (w, roles) = build_store_load(*funct3, *funct7, tail);
            let id = if tail {
                format!("st_store_load_{}_tail", name.to_lowercase())
            } else {
                format!("st_store_load_{}", name.to_lowercase())
            };
            out.push(
                Seed::new(id, "st_store_load", "Store--load", name, w)
                    .primary(&[0x18, 0x24, 0x28])
                    .roles(&roles),
            );
        }
    }

    // ---- st_redirect -----------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        let (w, roles) = build_redirect(*funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_redirect_{}", name.to_lowercase()),
                "st_redirect",
                "Redirect",
                name,
                w,
            )
            .primary(&[0x4c])
            .roles(&roles),
        );
    }

    // ---- st_pointer_indirect ---------------------------------------------------
    {
        let (w, roles) = build_pointer_indirect();
        out.push(
            Seed::new(
                "st_pointer_indirect".to_string(),
                "st_pointer_indirect",
                "Pointer indirect",
                "LW",
                w,
            )
            .primary(&[0x24])
            .roles(&roles),
        );
    }

    // ---- st_hazard_chain -------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        out.push(
            Seed::new(
                format!("st_hazard_chain_{}", name.to_lowercase()),
                "st_hazard_chain",
                "Hazard chain",
                name,
                build_hazard_chain(*funct3, *funct7),
            )
            // 0x18 is the RETIRED write (variant `first`), 0x20 the LIVE one (`second`).
            .primary(&[0x18, 0x20]),
        );
    }

    // ---- st_provenance_chain ---------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        out.push(
            Seed::new(
                format!("st_provenance_chain_{}_d2", name.to_lowercase()),
                "st_provenance_chain",
                "Provenance chain",
                name,
                build_provenance_d2(*funct3, *funct7),
            )
            .primary(&[0x10, 0x14]),
        );
        let (w, roles) = build_provenance_d4(*funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_provenance_chain_{}_d4", name.to_lowercase()),
                "st_provenance_chain",
                "Provenance chain",
                name,
                w,
            )
            .primary(&[0x04, 0x08, 0x0c, 0x18])
            .roles(&roles),
        );
    }

    // ---- st_fanout_read --------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        out.push(
            Seed::new(
                format!("st_fanout_read_{}", name.to_lowercase()),
                "st_fanout_read",
                "Fan-out read",
                name,
                build_fanout_read(*funct3, *funct7),
            )
            .primary(&[0x10]),
        );
    }

    // ---- st_reg_alias ----------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        out.push(
            Seed::new(
                format!("st_reg_alias_{}_rs1rs2", name.to_lowercase()),
                "st_reg_alias",
                "Register aliasing",
                name,
                build_reg_alias(*funct3, *funct7, false),
            )
            .primary(&[0x08, 0x0c]),
        );
        out.push(
            Seed::new(
                format!("st_reg_alias_{}_rdrs1rs2", name.to_lowercase()),
                "st_reg_alias",
                "Register aliasing",
                name,
                build_reg_alias(*funct3, *funct7, true),
            )
            .primary(&[0x08, 0x0c]),
        );
    }

    // ---- st_dead_write (scored against the committed MEMORY ROOT) ---------------
    for (name, funct3, funct7) in axis.iter() {
        for (variant, overwritten) in [("overwritten", true), ("neverread", false)] {
            out.push(
                Seed::new(
                    format!("st_dead_write_{}_{variant}", name.to_lowercase()),
                    "st_dead_write",
                    "Dead write-back",
                    name,
                    build_dead_write(*funct3, *funct7, overwritten),
                )
                .primary(&[0x10])
                .scored("in_circuit_state_object"),
            );
        }
    }

    // ---- st_finalize_only (scored against the committed MEMORY ROOT) ------------
    for (name, funct3, funct7) in axis.iter() {
        for (variant, to_mem) in [("mem", true), ("reg", false)] {
            let (w, roles) = build_finalize_only(*funct3, *funct7, to_mem);
            let primary = if to_mem { vec![0x14, 0x18] } else { vec![0x10] };
            out.push(
                Seed::new(
                    format!("st_finalize_only_{}_{variant}", name.to_lowercase()),
                    "st_finalize_only",
                    "Finalize-only write",
                    name,
                    w,
                )
                .primary(&primary)
                .roles(&roles)
                .scored("in_circuit_state_object"),
            );
        }
    }

    // ---- st_x0_dark_write ------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        let (w, roles) = build_x0_dark_write(*funct3, *funct7);
        out.push(
            Seed::new(
                format!("st_x0_dark_write_{}", name.to_lowercase()),
                "st_x0_dark_write",
                "x0 dark write",
                name,
                w,
            )
            // The dark writes at 0x18 and 0x1c carry NO hookable write-back on openvm
            // (see the builder), so they are deliberately absent from this list: their
            // absence from the CSV is the measurement.
            .primary(&[0x20])
            .roles(&roles),
        );
    }

    // ---- st_pv_plumbing --------------------------------------------------------
    // opcodes_required = alu_bound_reference. The `index` variant the manifest lists is
    // NOT APPLICABLE on openvm: a REVEAL's output offset is an IMMEDIATE in the
    // instruction word (transpiler lib.rs:174-186), not a register, so there is no index
    // write-back to perturb -- and the spec forbids the `syscall_arg` role everywhere
    // today in any case.
    for name in ["ADD", "XOR", "AND"] {
        let (_, funct3, funct7) = *opcodes().iter().find(|(n, _, _)| *n == name).unwrap();
        out.push(
            Seed::new(
                format!("st_pv_plumbing_{}_words8", name.to_lowercase()),
                "st_pv_plumbing",
                "Public-value plumbing",
                name,
                build_pv_words8(funct3, funct7),
            )
            .pv(32),
        );
        out.push(
            Seed::new(
                format!("st_pv_plumbing_{}_alias", name.to_lowercase()),
                "st_pv_plumbing",
                "Public-value plumbing",
                name,
                build_pv_alias(funct3, funct7),
            )
            .primary(&[0x14, 0x1c]),
        );
    }

    // ---- st_hint_advice (CALIBRATION) ------------------------------------------
    for (variant, checked) in [("unchecked", false), ("checked", true)] {
        let (w, roles) = build_hint_advice(checked);
        // The HINT_STOREW write-back and the LOAD that reads it back.
        let site = [0x04u32, 0x08];
        out.push(
            Seed::new(
                format!("st_hint_advice_{variant}"),
                "st_hint_advice",
                "Nondeterministic advice",
                "HINT_STOREW",
                w,
            )
            .class("calibration")
            .primary(&site)
            .roles(&roles)
            .hint(&[HINT_WORD]),
        );
    }

    // ---- st_subword_lane -------------------------------------------------------
    for (name, funct3, off) in [
        ("LB", 0b000u32, 3i32),
        ("LH", 0b001, 2),
        ("LW", 0b010, 0),
        ("LBU", 0b100, 3),
        ("LHU", 0b101, 2),
    ] {
        let (w, roles) = build_subword_load(funct3, off);
        out.push(
            Seed::new(
                format!("st_subword_lane_{}_load", name.to_lowercase()),
                "st_subword_lane",
                "Sub-word lane",
                name,
                w,
            )
            .primary(&[0x10])
            .roles(&roles),
        );
    }
    for (name, funct3, off) in [("SB", 0b000u32, 1i32), ("SH", 0b001, 2), ("SW", 0b010, 0)] {
        let (w, roles) = build_subword_store(funct3, off);
        out.push(
            Seed::new(
                format!("st_subword_lane_{}_store", name.to_lowercase()),
                "st_subword_lane",
                "Sub-word lane",
                name,
                w,
            )
            .primary(&[0x18, 0x1c])
            .roles(&roles),
        );
    }

    // ---- st_indirect_jump ------------------------------------------------------
    {
        let (w, roles) = build_indirect_jump_table();
        out.push(
            Seed::new(
                "st_indirect_jump_table".to_string(),
                "st_indirect_jump",
                "Indirect jump",
                "JALR",
                w,
            )
            .primary(&[0x00, 0x0c])
            .roles(&roles),
        );
        let (w, roles) = build_indirect_jump_bit0();
        out.push(
            Seed::new(
                "st_indirect_jump_bit0".to_string(),
                "st_indirect_jump",
                "Indirect jump",
                "JALR",
                w,
            )
            .primary(&[0x00])
            .roles(&roles),
        );
    }

    // ---- st_pc_imm_value (the highest-value openvm shape) -----------------------
    for (variant, op) in [("lui", "LUI"), ("auipc", "AUIPC"), ("jal", "JAL")] {
        out.push(
            Seed::new(
                format!("st_pc_imm_value_{variant}"),
                "st_pc_imm_value",
                "PC-immediate value",
                op,
                build_pc_imm_value(variant),
            )
            .primary(&[0x00]),
        );
    }

    // ---- st_early_exit (scored under accepted_case_v2) --------------------------
    for name in ["ADD", "XOR", "AND"] {
        let (_, funct3, funct7) = *opcodes().iter().find(|(n, _, _)| *n == name).unwrap();
        let (w, roles) = build_early_exit(funct3, funct7);
        out.push(
            Seed::new(
                format!("st_early_exit_{}", name.to_lowercase()),
                "st_early_exit",
                "Early exit",
                name,
                w,
            )
            .primary(&[0x10])
            .roles(&roles),
        );
    }

    // ---- st_control_flow (the BRANCH chip is the opcode axis) -------------------
    for (bname, bfunct3) in branch_axis() {
        for (variant, divergent) in [("datadiv", true), ("dataident", false)] {
            let (w, roles) = build_control_flow(bfunct3, divergent);
            let mut s = Seed::new(
                format!("st_control_flow_{}_{variant}", bname.to_lowercase()),
                "st_control_flow",
                "Control flow",
                bname,
                w,
            )
            .primary(&[0x10])
            .roles(&roles);
            if !divergent {
                // The DATA output is held fixed on purpose, so only the state object can
                // move; scoring against AS3 would report a guaranteed false negative.
                s = s.scored("in_circuit_state_object");
            }
            out.push(s);
        }
    }

    // ---- st_loop_repeat --------------------------------------------------------
    for (name, funct3, funct7) in axis.iter() {
        for (variant, n) in [("n16", 16u32), ("n256", 256)] {
            out.push(
                Seed::new(
                    format!("st_loop_repeat_{}_{variant}", name.to_lowercase()),
                    "st_loop_repeat",
                    "Loop repeat",
                    name,
                    build_loop_repeat(*funct3, *funct7, n),
                )
                .primary(&[0x14]),
            );
        }
    }

    // ---- st_multishard ---------------------------------------------------------
    {
        let (w, roles) = build_multishard(2048);
        out.push(
            Seed::new(
                "st_multishard".to_string(),
                "st_multishard",
                "Cross-shard continuation",
                "ADD",
                w,
            )
            .primary(&[0x14, 0x24, 0x40])
            .roles(&roles)
            // Small enough that the two loops fall in different segments; the baseline
            // row prints the segment count actually produced.
            .segment_budget(1 << 18),
        );
    }

    // ---- st_whole_program ------------------------------------------------------
    {
        let (w, roles) = build_whole_program(64);
        out.push(
            Seed::new(
                "st_whole_program".to_string(),
                "st_whole_program",
                "Whole program",
                "CENSUS",
                w,
            )
            .roles(&roles),
        );
    }

    // ---- st_initial_state / st_initial_image (CONTROLS) -------------------------
    {
        let (w, roles) = build_initial_state();
        out.push(
            Seed::new(
                "st_initial_state_bss".to_string(),
                "st_initial_state",
                "Initial state",
                "LW",
                w,
            )
            .class("control")
            .roles(&roles),
        );
        for (variant, at_boundary) in [("data", false), ("bssboundary", true)] {
            let (w, roles) = build_initial_image(at_boundary);
            out.push(
                Seed::new(
                    format!("st_initial_image_{variant}"),
                    "st_initial_image",
                    "Initial image",
                    "LW",
                    w,
                )
                .class("control")
                .roles(&roles)
                .image(&[(RAM_IMAGE, IMAGE_WORD)]),
            );
        }
    }

    out
}

fn hexbytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn trunc(s: &str) -> String {
    let s = s.replace(['\n', ',', '"'], " ");
    s.chars().take(160).collect()
}

struct Out {
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    hits: usize,
    site_execs: usize,
    pv: Option<Vec<u8>>,
    digest: String,
    honest_v: u32,
    forged_v: u32,
    segments: usize,
    t_record_ms: u128,
    t_prove_ms: u128,
    t_verify_ms: u128,
}

type Vm = VirtualMachine<TestStarkEngine, Rv32ImBuilder>;

/// One candidate through the REAL pipeline. `arm == None` runs the honest baseline.
///
/// Metered execution (which only sizes the record arenas / segments) is run honestly;
/// the perturbation is applied in PREFLIGHT execution, which is the run whose records
/// become the trace and whose final memory becomes the committed Merkle root.
fn run_once(
    vm: &mut Vm,
    vk: &MultiStarkVerifyingKey<BabyBearPoseidon2Config>,
    exe: &VmExe<F>,
    input: Streams<F>,
    pv_len: usize,
    max_memory: Option<usize>,
    arm: Option<(u32, usize, i64)>,
) -> Out {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
        type Fail = (String, &'static str, u128, Option<Vec<u8>>);
        let body = |vm: &mut Vm| -> Result<Out, Fail> {
            let t0 = Instant::now();
            let input = input.clone();
            let mut metered_ctx = vm.build_metered_ctx(exe);
            if let Some(m) = max_memory {
                metered_ctx = metered_ctx.with_max_memory(m);
            }
            let segments = match vm
                .metered_interpreter(exe)
                .map_err(|e| (format!("metered_interpreter: {e:?}"), "fork_exec", 0u128, None))
                .and_then(|it| {
                    it.execute_metered(input.clone(), metered_ctx)
                        .map_err(|e| (format!("execute_metered: {e:?}"), "fork_exec", 0u128, None))
                }) {
                Ok((segments, _)) => segments,
                Err(e) => return Err(e),
            };
            let num_segments = segments.len();
            let cached = vm.commit_program_on_device(&exe.program);
            vm.load_program(cached);
            let mut pf = match vm.preflight_interpreter(exe) {
                Ok(x) => x,
                Err(e) => {
                    return Err((
                        format!("preflight_interpreter: {e:?}"),
                        "fork_exec",
                        t0.elapsed().as_millis(),
                        None,
                    ))
                }
            };
            let mut state = Some(vm.create_initial_state(exe, input));
            let mut proofs = Vec::new();
            let mut t_prove = 0u128;
            let mut final_pv: Option<Vec<u8>> = None;
            for segment in segments.iter() {
                let Segment {
                    num_insns,
                    trace_heights,
                    ..
                } = segment.clone();
                let from_state = Option::take(&mut state).unwrap();
                vm.transport_init_memory_to_device(&from_state.memory);
                let PreflightExecutionOutput {
                    system_records,
                    record_arenas,
                    to_state,
                } = match vm.execute_preflight(&mut pf, from_state, Some(num_insns), &trace_heights)
                {
                    Ok(x) => x,
                    Err(e) => {
                        return Err((
                            format!("execute_preflight: {e:?}"),
                            "fork_exec",
                            t0.elapsed().as_millis(),
                            final_pv.clone(),
                        ))
                    }
                };
                // The committed public output: address space 3, bytes 0..pv_len.
                // SAFETY: PUBLIC_VALUES_AS is configured with 32 cells of type u8 and
                // every seed's `pv_len` is <= 32.
                final_pv = Some(
                    unsafe { to_state.memory.memory.get_u8_slice(PUBLIC_VALUES_AS, 0, pv_len) }
                        .to_vec(),
                );
                state = Some(to_state);
                let ctx = match vm.generate_proving_ctx(system_records, record_arenas) {
                    Ok(c) => c,
                    Err(e) => {
                        return Err((
                            format!("tracegen: {e:?}"),
                            "prove",
                            t0.elapsed().as_millis(),
                            final_pv.clone(),
                        ))
                    }
                };
                let t1 = Instant::now();
                let proof = match vm.engine.prove(vm.pk(), ctx) {
                    Ok(p) => p,
                    Err(e) => {
                        return Err((
                            format!("prove: {e:?}"),
                            "prove",
                            t0.elapsed().as_millis(),
                            final_pv.clone(),
                        ))
                    }
                };
                t_prove += t1.elapsed().as_millis();
                proofs.push(proof);
            }
            let t_record = t0.elapsed().as_millis().saturating_sub(t_prove);
            // The Merkle final root committed by the last segment proof.
            let digest = proofs
                .last()
                .map(|p| {
                    let pvs = &p.public_values[MERKLE_AIR_ID];
                    // MemoryMerklePvs = { initial_root: [F; 8], final_root: [F; 8] }
                    pvs[pvs.len() / 2..]
                        .iter()
                        .map(|f| format!("{:08x}", f.as_canonical_u32()))
                        .collect::<String>()
                })
                .unwrap_or_else(|| "NA".to_string());

            let t2 = Instant::now();
            let vres = verify_segments(&vm.engine, vk, &proofs);
            let t_verify = t2.elapsed().as_millis();
            let (outcome, stage, reason) = match vres {
                Ok(_) => ("ACCEPT", "accepted_proof", String::new()),
                Err(e) => ("REJECT", "verify", trunc(&format!("{e}"))),
            };
            Ok(Out {
                outcome,
                failure_stage: stage,
                reason,
                hits: wb_perturb::hits(),
                site_execs: wb_perturb::site_execs(),
                pv: final_pv,
                digest,
                honest_v: wb_perturb::honest_value(),
                forged_v: wb_perturb::forged_value(),
                segments: num_segments,
                t_record_ms: t_record,
                t_prove_ms: t_prove,
                t_verify_ms: t_verify,
            })
        };
        match arm {
            None => body(vm),
            // nth = -1: arm EVERY execution of this static pc. Run-matrix rule R5 --
            // openvm's `nth_supported` is NOT DETERMINED, so a per-execution nth must not
            // be emitted until it is measured.
            Some((pc, kind, arg)) => wb_perturb::with(pc, -1, kind, arg, || body(vm)),
        }
    }));
    std::panic::set_hook(prev);
    match r {
        Ok(Ok(o)) => o,
        Ok(Err((msg, stage, t, pv))) => Out {
            outcome: if stage == "prove" { "REJECT" } else { "EXECFAIL" },
            failure_stage: stage,
            reason: trunc(&msg),
            hits: wb_perturb::hits(),
            site_execs: wb_perturb::site_execs(),
            pv,
            digest: "NA".to_string(),
            honest_v: wb_perturb::honest_value(),
            forged_v: wb_perturb::forged_value(),
            segments: 0,
            t_record_ms: t,
            t_prove_ms: 0,
            t_verify_ms: 0,
        },
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque panic>".to_string());
            // A panic inside tracegen/prove is the prover refusing to produce a proof.
            let proveish = msg.contains("trace")
                || msg.contains("Trace")
                || msg.contains("constraint")
                || msg.contains("height")
                || msg.contains("interaction");
            Out {
                outcome: if proveish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if proveish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits: wb_perturb::hits(),
                site_execs: wb_perturb::site_execs(),
                pv: None,
                digest: "NA".to_string(),
                honest_v: wb_perturb::honest_value(),
                forged_v: wb_perturb::forged_value(),
                segments: 0,
                t_record_ms: 0,
                t_prove_ms: 0,
                t_verify_ms: 0,
            }
        }
    }
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
#[ignore = "LACUNA evaluation run: openvm record-layer encoding enumeration; use --release"]
fn lacuna_encoding_enumeration_openvm() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "openvm".to_string());
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let sites_all = std::env::var("LACUNA_SITES").unwrap_or_else(|_| "all".to_string()) == "all";
    let want: Vec<String> = env_list("LACUNA_OPS")
        .into_iter()
        .map(|s| s.to_uppercase())
        .collect();
    let want_seeds = env_list("LACUNA_SEEDS");
    let want_structs = env_list("LACUNA_STRUCT");

    // LACUNA_LIST: print the corpus and exit without proving anything. The sampling
    // policy is part of the result (run-matrix rule R6), so the runner has to be able to
    // see the full cross product before it decides what to spend.
    if std::env::var("LACUNA_LIST").is_ok() {
        println!(
            "seed_id,structure_id,program_structure,opcode,candidate_class,operand_source,\
scored_against,insns,sites_all,sites_primary,candidates_all,candidates_primary"
        );
        let (mut tot_all, mut tot_prim) = (0usize, 0usize);
        for seed in seeds() {
            let all = write_sites(&seed.words);
            let count = |sites: &[u32]| -> usize {
                sites
                    .iter()
                    .map(|pc| {
                        let role = seed.role_of(*pc);
                        menu(true)
                            .iter()
                            .filter(|(l, _, _, _)| mu_allowed(role, l))
                            .count()
                    })
                    .sum()
            };
            let (ca, cp) = (count(&all), count(&seed.primary_sites));
            tot_all += ca;
            tot_prim += cp;
            println!(
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                seed.seed_id,
                seed.structure_id,
                seed.published_name,
                seed.opcode,
                seed.candidate_class,
                seed.operand_source,
                seed.scored_against,
                seed.words.len(),
                all.len(),
                seed.primary_sites.len(),
                ca,
                cp
            );
        }
        println!("LACUNA_LIST_TOTAL,candidates_all={tot_all},candidates_primary={tot_prim}");
        return;
    }

    let mut sink: Option<std::fs::File> = std::env::var("LACUNA_OUT").ok().map(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .expect("open LACUNA_OUT")
    });
    let header = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,\
dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,\
pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,\
committed_digest,honest_committed_digest,digest_changed,structure_id,operand_source,\
candidate_class,site_role,scored_against,accepted_case_v2,nth_armed";
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    // Keygen ONCE and reuse for every seed and candidate: the proving/verifying key
    // depends only on the config, not on the program. Every seed in the table -- the
    // segmenting one included -- runs under this one configuration.
    let config = Rv32ImConfig {
        rv32i: Rv32IConfig {
            system: test_system_config(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut params = SystemParams::new_for_testing(22);
    params.max_constraint_degree = 3;
    let engine = TestStarkEngine::new(params);
    let (mut vm, pk) = Vm::new_with_keygen(engine, Rv32ImBuilder, config).expect("keygen");
    let vk = pk.get_vk();
    println!("LACUNA_AIRS,{}", vm.air_names().collect::<Vec<_>>().join("|"));

    for seed in seeds() {
        if !want.is_empty() && !want.contains(&seed.opcode.to_uppercase()) {
            continue;
        }
        if !want_seeds.is_empty() && !want_seeds.iter().any(|p| seed.seed_id.starts_with(p)) {
            continue;
        }
        if !want_structs.is_empty() && !want_structs.iter().any(|p| p == seed.structure_id) {
            continue;
        }
        let exe = seed.exe();
        let sid = &seed.seed_id;
        let name = &seed.opcode;
        let structure = seed.published_name;

        // ---- honest baseline: real prove + real verify ----
        let h = run_once(
            &mut vm,
            &vk,
            &exe,
            seed.streams(),
            seed.pv_len,
            seed.max_memory,
            None,
        );
        let honest_hex = h
            .pv
            .as_ref()
            .map(|v| hexbytes(v))
            .unwrap_or_else(|| "NONE".into());
        if h.outcome != "ACCEPT" {
            println!(
                "LACUNA_BASELINE,{tag},openvm,{sid},{}_{},{}",
                h.outcome, h.failure_stage, h.reason
            );
            continue;
        }
        let honest_digest = h.digest.clone();
        println!(
            "LACUNA_BASELINE,{tag},openvm,{sid},VERIFIED,honest_pv={honest_hex},\
digest={honest_digest},segments={},t_prove_ms={},t_verify_ms={}",
            h.segments, h.t_prove_ms, h.t_verify_ms
        );

        let sites: Vec<u32> = if sites_all {
            write_sites(&seed.words)
        } else {
            seed.primary_sites.clone()
        };
        for pc in sites {
            let role = seed.role_of(pc);
            for (label, template, kind, arg) in menu(mu_all) {
                // The mu-menu ROLE MASK. Declarative: it selects which of the eleven
                // existing entries are legal at this site, and never changes one.
                if !mu_allowed(role, label) {
                    continue;
                }
                let c = run_once(
                    &mut vm,
                    &vk,
                    &exe,
                    seed.streams(),
                    seed.pv_len,
                    seed.max_memory,
                    Some((pc, kind, arg)),
                );
                let pv_hex = c
                    .pv
                    .as_ref()
                    .map(|v| hexbytes(v))
                    .unwrap_or_else(|| "NONE".into());
                let nonempty = pv_hex != "NONE" && !pv_hex.is_empty();
                // `output_changed` reports the perturbed run's committed public output
                // regardless of the verdict (strictly more information); `accepted_case`
                // additionally requires the REAL verifier to have accepted.
                let changed = nonempty && pv_hex != honest_hex;
                // FROZEN strict predicate -- kept verbatim so no published number moves.
                let accepted = c.outcome == "ACCEPT" && c.hits > 0 && changed;
                let digest_changed = c.digest != "NA" && c.digest != honest_digest;
                // accepted_case_v2: strict, OR the DECLARED committed state object moved.
                // Never turns a strict accept into a non-accept, so v2 >= strict on every
                // row. On openvm the state object is MemoryMerklePvs.final_root, which
                // covers the whole final image INCLUDING the register file.
                let accepted_v2 = accepted
                    || (c.outcome == "ACCEPT"
                        && c.hits > 0
                        && seed.scored_against == "in_circuit_state_object"
                        && digest_changed);
                let outcome = if c.hits == 0 && c.outcome == "ACCEPT" {
                    "NOOP"
                } else {
                    c.outcome
                };
                let stage = if c.hits == 0 && c.outcome == "ACCEPT" {
                    "mutation"
                } else {
                    c.failure_stage
                };
                let row = format!(
                    "{tag},openvm,{REV},{sid},encoding,{structure},{name},{pc:#x},0,\
NA,NA,{},{label},{template},{kind},{arg},{outcome},{stage},{},{pv_hex},{honest_hex},{changed},\
{accepted},{},{},{},\"{}\",{},{honest_digest},{digest_changed},{},{},{},{role},{},{accepted_v2},-1",
                    c.site_execs,
                    c.hits,
                    c.t_record_ms,
                    c.t_prove_ms,
                    c.t_verify_ms,
                    c.reason,
                    c.digest,
                    seed.structure_id,
                    seed.operand_source,
                    seed.candidate_class,
                    seed.scored_against,
                );
                println!("LACUNA_ROW,{row}");
                if let Some(f) = sink.as_mut() {
                    writeln!(f, "{row}").unwrap();
                    f.flush().ok();
                }
                if accepted_v2 {
                    println!(
                        "  *** ACCEPTED CASE ({}): {sid} @ {pc:#x} mu={label}  write-back {:#x} \
-> {:#x}; committed public output {honest_hex} -> {pv_hex}; digest_changed={digest_changed}",
                        seed.candidate_class, c.honest_v, c.forged_v
                    );
                }
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}
