//! LACUNA EVALUATION DRIVER for sp1 — instrumented, candidate-level enumeration of
//! record-layer mutations, each one carried through the REAL prover and the REAL
//! verifier.
//!
//! Contains no bug knowledge. It enumerates
//!
//!     site = (static pc, n-th execution of that pc)   [mode `encoding`]
//!            (index into an event vector)             [mode `meminit` / `memfinal`]
//!     mu   = one entry of an instruction-independent rewriting menu
//!
//! Two hooks are used, both default OFF:
//!
//!   * `sp1_core_executor::wb_perturb` — the single architectural write-back choke
//!     point of the record-producing executor (`CoreVM::rw`, vm.rs). Perturbing
//!     there makes the honest executor continue from the rewritten value, so every
//!     later register read, dependent store and memory record follows naturally.
//!
//!   * `crate::utils::prove::record_perturb` — rewrites one field of an already
//!     generated `ExecutionRecord` just before `generate_dependencies`, for record
//!     fields that no instruction write-back produces (the global memory
//!     initialize/finalize event values).
//!
//! The committed public output of an SP1 core proof is
//! `PublicValues::committed_value_digest`, which the guest fills with the `COMMIT`
//! syscall; every seed routes the operation's result into it, so a mutation that the
//! constraint system fails to bind would be visible to a verifier.
//!
//! Environment (all optional):
//!   LACUNA_OUT    path of the CSV to append to (default: stdout only)
//!   LACUNA_TAG    free-form run tag copied into every row
//!   LACUNA_OPS    comma-separated opcode names to enumerate (default: all)
//!   LACUNA_MU     "xorb0" (single mu) | "all" (the full menu, default)
//!   LACUNA_MODE   "encoding" | "meminit" | "both" (default "both")
//!   LACUNA_LSH    log_stacking_height (default 21)
//!   LACUNA_MLRC   max_log_row_count (default 22)
//!
//! Added with the structure catalog (all optional, all defaulting to the
//! published behaviour):
//!   LACUNA_SEEDS       comma-separated manifest structure ids or seed suffixes
//!                      to enumerate (default: the whole seed table).
//!                      `LACUNA_SEEDS=st_single_op` is the published enumeration.
//!   LACUNA_SITE_STRIDE enumerate every n-th write-back site (default 1)
//!   LACUNA_MAX_SITES   stop after this many sites per seed (default: no limit)
//!   LACUNA_MAX_CYCLES  skip a seed whose HONEST execution exceeds this many
//!                      cycles (default 2^20) -- the max-cycle abort
//!
//! `LACUNA_MODE` gains a third arm, `memfinal`
//! (`global_memory_finalize_events[k].value`), which `both` includes.

#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]

use std::{borrow::Borrow, io::Write, sync::Arc, time::Instant};

use sp1_primitives::fri_params::core_fri_config;
use sp1_core_executor::{
    add_halt, wb_perturb, ExecutionRecord, Instruction, Opcode, Program, SP1Context, SP1CoreOpts,
};
use slop_algebra::PrimeField32;
use sp1_hypercube::{
    air::{PublicValues, PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    prover::{CpuShardProver, SP1InnerPcsProver, SimpleProver},
    MachineVerifyingKey, SP1InnerPcs, ShardVerifier,
};
use sp1_primitives::{SP1Field, SP1GlobalContext};

use sp1_core_machine::{
    io::SP1Stdin,
    riscv::RiscvAir,
    utils::{generate_records, record_perturb},
};

use crate::{verify::SP1Verifier, SP1CoreProofData};
use sp1_hypercube::SP1VerifyingKey;
use sp1_verifier::VerifierRecursionVks;

/// git revision of the sp1 tree this driver was run against.
const REV: &str = "51f6efcb2971540d2ce1f48b35fd8bcf848a8b9f";

/// `SyscallCode::COMMIT`.
const COMMIT_SYSCALL: u64 = 0x00_00_00_10;
/// `SyscallCode::COMMIT_DEFERRED_PROOFS` — the SP1 core verifier rejects a proof in
/// which it was never called (crates/prover/src/verify.rs:486).
const COMMIT_DEFERRED_SYSCALL: u64 = 0x00_00_00_1a;

/// LACUNA seed — program structure: Single operation.
///
/// ```text
/// pc 0x00: ADDI x28, x0, b        ; x28 = b
/// pc 0x04: ADDI x29, x0, c        ; x29 = c
/// pc 0x08: OP   x30, x28, x29     ; x30 = b OP c    <- the operation under test
/// pc 0x0c: ADDI x10, x0, 0        ; a0 = digest word index 0
/// pc 0x10: ADD  x11, x30, x0      ; a1 = the result <- routes the result to the commit
/// pc 0x14: ADDI x5,  x0, 0x10     ; t0 = SyscallCode::COMMIT
/// pc 0x18: ECALL                  ; committed_value_digest[0] = x11
/// pc 0x1c: ADDI x10, x0, 0
/// pc 0x20: ADDI x11, x0, 0
/// pc 0x24: ADDI x5,  x0, 0x1a     ; t0 = SyscallCode::COMMIT_DEFERRED_PROOFS
/// pc 0x28: ECALL                  ; required by the SP1 core verifier
/// pc 0x2c: ADD  x5,  x0, x0       ; (add_halt) t0 = SyscallCode::HALT
/// pc 0x30: ADD  x10, x0, x0       ; a0 = exit code 0
/// pc 0x34: ECALL
/// ```
/// The `COMMIT` at pc 0x18 is what makes the operation's result publicly
/// observable; without it a mutation could be accepted without changing anything a
/// verifier is shown.
fn build_op_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut instructions = vec![
        Instruction::new(Opcode::ADDI, 28, 0, b, false, true),
        Instruction::new(Opcode::ADDI, 29, 0, c, false, true),
        Instruction::new(op, 30, 28, 29, false, false),
        Instruction::new(Opcode::ADDI, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 11, 30, 0, false, false),
        Instruction::new(Opcode::ADDI, 5, 0, COMMIT_SYSCALL, false, true),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        Instruction::new(Opcode::ADDI, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADDI, 11, 0, 0, false, true),
        Instruction::new(Opcode::ADDI, 5, 0, COMMIT_DEFERRED_SYSCALL, false, true),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ];
    add_halt(&mut instructions);
    Program::new(instructions, 0, 0)
}

/// LACUNA seed — program structure: Single operation + memory round trip.
///
/// Same as above, but the result additionally makes a round trip through a RAM
/// address that is NOT part of the program image, so the record carries a
/// `global_memory_initialize_events` entry for a non-register address.
///
/// ```text
/// pc 0x00: ADDI x28, x0, b
/// pc 0x04: ADDI x29, x0, c
/// pc 0x08: OP   x30, x28, x29        <- the operation under test
/// pc 0x0c: ADDI x6,  x0, SCRATCH
/// pc 0x10: SD   x30, 0(x6)
/// pc 0x14: LD   x7,  0(x6)
/// pc 0x18: ADDI x10, x0, 0
/// pc 0x1c: ADD  x11, x7, x0
/// pc 0x20: ADDI x5,  x0, 0x10
/// pc 0x24: ECALL
/// (add_halt)
/// ```
const SCRATCH: u64 = 0x0000_0000_0001_0000;

fn build_op_mem_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut instructions = vec![
        Instruction::new(Opcode::ADDI, 28, 0, b, false, true),
        Instruction::new(Opcode::ADDI, 29, 0, c, false, true),
        Instruction::new(op, 30, 28, 29, false, false),
        Instruction::new(Opcode::ADDI, 6, 0, SCRATCH, false, true),
        Instruction::new(Opcode::SD, 30, 6, 0, false, true),
        Instruction::new(Opcode::LD, 7, 6, 0, false, true),
        Instruction::new(Opcode::ADDI, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 11, 7, 0, false, false),
        Instruction::new(Opcode::ADDI, 5, 0, COMMIT_SYSCALL, false, true),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        Instruction::new(Opcode::ADDI, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADDI, 11, 0, 0, false, true),
        Instruction::new(Opcode::ADDI, 5, 0, COMMIT_DEFERRED_SYSCALL, false, true),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ];
    add_halt(&mut instructions);
    Program::new(instructions, 0, 0)
}

// ===========================================================================
// LACUNA STRUCTURE CATALOG  (ADDITIVE — new seeds only)
// ===========================================================================
//
// Everything below implements the shared structure manifest,
// `evaluation/spec/STRUCTURE_MANIFEST.yaml`, for the sp1 target. It is purely
// additive: the two seeds above (`op_<op>` / `op_<op>_mem`) keep their builders,
// their seed ids, their modes and their rows, so the published enumeration is
// unchanged. New structures are new builder functions plus new rows in `seeds()`.
//
// THREE sp1 FACTS EVERY SEED COMMENT BELOW IS WRITTEN AGAINST.
//
//  (1) THE OBSERVABLE. `PublicValues::committed_value_digest`, filled word by
//      word by the COMMIT syscall (`crates/core/executor/src/vm/syscall/commit.rs`).
//      A forged write-back is only visible to a verifier if it reaches the
//      register the COMMIT ecall reads as `a1`. `commit_tail` is that path.
//      COMMIT panics unless the word fits in u32 (commit.rs:9-11), so every seed
//      keeps its committed value below 2^32 honestly; a mutation that lifts it
//      above 2^32 surfaces as EXECFAIL, not as a verdict.
//
//  (2) THE TWO-PASS EXECUTOR. Phase 1 is `MinimalExecutorRunner`, which is NOT
//      hooked; phase 2 is `CoreVM` (splicing + tracing), which is. Phase 2 has no
//      memory: `CoreVM::mr` (crates/core/executor/src/vm.rs:745-758) returns the
//      next value of the phase-1 `mem_reads` oracle and IGNORES its address
//      argument, and `emit_globals` takes the finalize values from the phase-1
//      final memory. So on sp1 a forged value that is STORED and then LOADED back
//      does not come back forged, and the record that results is internally
//      inconsistent in the memory argument. A REJECT on a RAM-routed seed is
//      therefore NOT evidence that the constraint system binds anything — it is
//      the driver's own inconsistency being caught. Those seeds carry
//      `note: RAM_ROUTED` and print it next to their site line. This is the
//      `honest_limits` entry "TWO TARGETS CANNOT PRODUCE A COHERENT RAM-MEDIATED
//      FORGERY AT ALL TODAY", confirmed in code for this wave.
//
//  (3) nth IS DEAD ON sp1. `wb_perturb::SEEN` is one global counter and every
//      candidate runs two `CoreVM` passes, so only `nth = -1` (mutate every
//      execution of the pc) is legal here — manifest run-matrix rule R5. Every
//      seed below, including the loop seeds, is armed at nth = -1.

/// A never-written, never-imaged scratch doubleword: the "initial state" address.
const SCRATCH2: u64 = 0x0000_0000_0002_0000;
/// Two live slots one `plus_B1` (2^16) apart, for the address-role structures.
const REDIRECT_A: u64 = 0x0000_0000_0003_0000;
const REDIRECT_B: u64 = 0x0000_0000_0004_0000;
/// Base of the non-zero initial image used by `st_initial_image`.
const IMAGE_ADDR: u64 = 0x0000_0000_0005_0000;
/// The word the ELF image initialises `IMAGE_ADDR` to. Same constant the
/// loader-layer golds use (PIPELINE_LAYER_SOUNDNESS_CATALOG #1 SP1 L-1).
const IMAGE_WORD: u64 = 0xDEAD_BEEF;

/// The published commit tail, factored for the new seeds: route `src` into
/// `committed_value_digest[0]`, then the `COMMIT_DEFERRED_PROOFS` ecall the SP1
/// core verifier requires (crates/prover/src/verify.rs:481-490), then halt.
///
/// Byte-for-byte the same instruction sequence the two published builders write
/// inline; they are left untouched so their rows cannot move.
fn commit_tail(out: &mut Vec<Instruction>, src: u8) {
    out.push(Instruction::new(Opcode::ADDI, 10, 0, 0, false, true));
    out.push(Instruction::new(Opcode::ADD, 11, u64::from(src), 0, false, false));
    out.push(Instruction::new(Opcode::ADDI, 5, 0, COMMIT_SYSCALL, false, true));
    out.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    out.push(Instruction::new(Opcode::ADDI, 10, 0, 0, false, true));
    out.push(Instruction::new(Opcode::ADDI, 11, 0, 0, false, true));
    out.push(Instruction::new(Opcode::ADDI, 5, 0, COMMIT_DEFERRED_SYSCALL, false, true));
    out.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    add_halt(out);
}

/// Materialise an arbitrary 64-bit constant into `rd` with instructions a real
/// RISC-V assembler could emit: one `ADDI` when it fits a signed 12-bit
/// immediate, `LUI`+`ADDI` when it fits signed 32 bits, otherwise six 11-bit
/// chunks shifted in. `Program::new` marks the program trusted
/// (`instructions_encoded: None`), so `Instruction::encode` — and its 12-bit
/// assertion — is never reached; the sequence is still kept encodable so the
/// seeds stay honest programs rather than artefacts of the driver.
fn li(out: &mut Vec<Instruction>, rd: u8, v: u64) {
    let sv = v as i64;
    if (-2048..2048).contains(&sv) {
        out.push(Instruction::new(Opcode::ADDI, rd, 0, v, false, true));
        return;
    }
    if sv == i64::from(sv as i32) {
        // LUI writes the sign-extended upper immediate, ADDI adds the signed low 12.
        let mut lo = (sv & 0xFFF) as i64;
        if lo >= 2048 {
            lo -= 4096;
        }
        let hi = (sv - lo) as u64;
        out.push(Instruction::new(Opcode::LUI, rd, hi, hi, true, true));
        if lo != 0 {
            out.push(Instruction::new(Opcode::ADDI, rd, u64::from(rd), lo as u64, false, true));
        }
        return;
    }
    for i in (0..6).rev() {
        let chunk = (v >> (11 * i)) & 0x7FF;
        if i == 5 {
            out.push(Instruction::new(Opcode::ADDI, rd, 0, chunk, false, true));
        } else {
            out.push(Instruction::new(Opcode::SLL, rd, u64::from(rd), 11, false, true));
            if chunk != 0 {
                out.push(Instruction::new(Opcode::ADDI, rd, u64::from(rd), chunk, false, true));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// st_boundary_operand  —  "Boundary operand", probe, operand_source=immediate,
// site_role=selector.
//
// Same shape as Single operation, but the honest operands sit one mu-step from a
// constraint DISCONTINUITY (divide-by-zero flag, shift-amount mask, INT_MIN/-1
// special case, limb boundary), so the mutation drives an AIR-DERIVED SELECTOR
// rather than an AIR-derived value. The forged operand reaches the committed
// output the same way Single operation does: the honest executor recomputes the
// result from it and `commit_tail` puts that result in digest word 0.
// ---------------------------------------------------------------------------
fn build_boundary_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    i.push(Instruction::new(op, 30, 28, 29, false, false));
    // Keep the honest committed word inside u32 (commit.rs:9-11) without hiding
    // the mutation: the low 32 bits of the result are what is published.
    i.push(Instruction::new(Opcode::SLL, 30, 30, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 30, 30, 32, false, true));
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_subword_lane  —  "Sub-word lane", probe, immediate, value.
//
// Constraint surface: the byte/half/word lane selection and sign-extension of the
// load and store chips (`compute_load_value` / `compute_store_value`,
// crates/core/executor/src/vm.rs:659-731) and the eighteen sp1 load/store chips
// that no LACUNA candidate has ever instantiated, because the published driver
// only ever ran the memory seed in `meminit` mode.
//
// Path to the output: the loaded value is committed directly. The interesting
// site is the LOAD's own rd write-back — that one is COHERENT on sp1, because the
// memory read record it must agree with is the honest one, so the question the
// candidate asks is exactly "does the load chip bind rd to the lane it read".
// The earlier sites in the same seed are RAM-routed (see fact (2) above).
// ---------------------------------------------------------------------------
/// The `load` variant: store a full doubleword, read one lane back.
fn build_subword_load_program(load_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    // 0x0123_4567 keeps every lane of every load form non-negative and below 2^32,
    // so the honest COMMIT never trips the u32 conversion.
    li(&mut i, 28, 0x0123_4567);
    li(&mut i, 6, SCRATCH);
    i.push(Instruction::new(Opcode::SD, 28, 6, 0, false, true));
    i.push(Instruction::new(load_op, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

/// The `store` variant: write one lane, read the whole doubleword back.
fn build_subword_store_program(store_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, 0x0123_4567);
    li(&mut i, 6, SCRATCH);
    i.push(Instruction::new(store_op, 28, 6, 0, false, true));
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_store_load  —  "Store--load", probe, immediate, value.
//
// The seed already existed (`build_op_mem_program`); what did not exist was the
// mode. The published driver gated it to `meminit` only, so its seventeen
// write-back sites — including the LD's own rd write — were never enumerated.
// This wave registers the SAME program under a second seed id in `encoding`
// mode; the published `op_<op>_mem` / `meminit` rows are untouched.
//
// `_tail` adds one more SD after the LD so that the forged value also has to
// survive a second write into the memory argument.
// ---------------------------------------------------------------------------
fn build_store_load_tail_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    i.push(Instruction::new(op, 30, 28, 29, false, false));
    li(&mut i, 6, SCRATCH);
    i.push(Instruction::new(Opcode::SD, 30, 6, 0, false, true));
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    i.push(Instruction::new(Opcode::SD, 7, 6, 8, false, true));
    i.push(Instruction::new(Opcode::LD, 8, 6, 8, false, true));
    i.push(Instruction::new(Opcode::SLL, 8, 8, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 8, 8, 32, false, true));
    commit_tail(&mut i, 8);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_redirect  —  "Redirect", probe, immediate, site_role=ADDRESS.
//
// Two live slots exactly 2^16 apart, both written, one read. The site is the
// pointer register's write-back and the mu menu is masked to the manifest's
// address role, so `plus_B1` lands the load exactly on the OTHER live slot.
//
// Constraint surface: the memory-consistency argument's address column — does the
// read row have to name the address whose last write it claims? Path to the
// output: the loaded word is committed. On sp1 the delivered value comes from the
// address-blind phase-1 oracle (fact (2)), so what the record ends up claiming is
// "a read at B that returns A's value with A's previous timestamp"; that is
// exactly the malicious-prover record this structure is about, but it also means a
// REJECT here can come from the driver's own inconsistency.
// ---------------------------------------------------------------------------
fn build_redirect_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 6, REDIRECT_A); //  site 0: the pointer under test (address role)
    li(&mut i, 8, REDIRECT_B);
    li(&mut i, 28, 0x0A5A_0001);
    li(&mut i, 29, 0x0B5B_0002);
    i.push(Instruction::new(Opcode::SD, 28, 6, 0, false, true));
    i.push(Instruction::new(Opcode::SD, 29, 8, 0, false, true));
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_initial_state (variant `bss`)  —  "Initial state", probe, immediate, value.
//
// Read an address that was never written and is not in the image; commit it.
// Honest value 0.
//
// HONEST SCOPE. The manifest asks for a COHERENT TRIPLE here (a read-side hook in
// `CoreVM::mr`, plus F_MEM_INIT_VALUE, plus F_MEM_FINAL_VALUE, all armed with one
// mu). That hook does not exist and this wave did not add it, so what ships is:
//   * the `encoding` arm, which is coherent — it forges the load's rd write-back
//     and asks whether the load chip binds rd to the value it read; and
//   * the `meminit` arm, which is the SINGLE LEG the manifest warns about: it
//     moves `global_memory_initialize_events[k].value` while the phase-1 oracle
//     still hands the load the honest 0, so the memory bus sees a mismatch that
//     the prover could not have produced. Its REJECT is not evidence of binding.
// ---------------------------------------------------------------------------
fn build_initial_state_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 6, SCRATCH2);
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_initial_image  —  "Initial image", DECLARED CONTROL (expected REJECT),
// immediate, value.
//
// Read an address the program IMAGE initialises to a non-zero word. This is the
// paired negative for st_initial_state and the record-layer form of the question
// the SP1 L-1 loader gold raises (committed initial memory != ELF initial memory).
//
// A STRUCTURAL RESULT THIS WAVE CONFIRMED IN CODE, refining the manifest's sp1
// cell: an address that is in `Program::memory_image` gets NO
// `global_memory_initialize_events` entry at all — `emit_globals`
// (crates/core/machine/src/utils/prove.rs:311-315) filters exactly those
// addresses out, because they are initialised by the preprocessed MemoryProgram
// chip out of `Program::initial_global_cumulative_sum`
// (crates/core/executor/src/program.rs:169-192), which is part of the vk. So the
// in-image initial value is NOT a record field on sp1 and F_MEM_INIT_VALUE cannot
// reach it; the record-layer operator can only forge the LOADED value, which is
// what the `encoding` arm does. `memfinal` is armed here as the third leg the
// manifest asks for, and is a declared control: nothing about final RAM is public.
//
// The `bssboundary` variant additionally loads the never-initialised doubleword
// immediately after the image word — the .data/.bss boundary shape of the
// loader-layer ledger — and commits the sum, so a perturbation of either word is
// observable.
// ---------------------------------------------------------------------------
fn build_initial_image_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 6, IMAGE_ADDR);
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    let mut p = Program::new(i, 0, 0);
    p.memory_image = Arc::new([(IMAGE_ADDR, IMAGE_WORD)].into_iter().collect());
    p
}

fn build_initial_image_bss_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 6, IMAGE_ADDR);
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true)); // .data word, in image
    i.push(Instruction::new(Opcode::LD, 8, 6, 8, false, true)); // .bss tail, never written
    i.push(Instruction::new(Opcode::ADD, 9, 7, 8, false, false));
    commit_tail(&mut i, 9);
    let mut p = Program::new(i, 0, 0);
    p.memory_image = Arc::new([(IMAGE_ADDR, IMAGE_WORD)].into_iter().collect());
    p
}

// ---------------------------------------------------------------------------
// st_hazard_chain  —  "Hazard chain", probe, immediate, value.
//
// Two write-backs to the SAME register at two static pcs, the first immediately
// overwritten by the second. Site 1 is dead, site 2 is live, and because they are
// different pcs the broken global SEEN counter is not in the way. Path to the
// output: the second write is what `commit_tail` reads.
// ---------------------------------------------------------------------------
fn build_hazard_program(_op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    i.push(Instruction::new(Opcode::ADD, 30, 28, 0, false, false)); // dead
    i.push(Instruction::new(Opcode::ADD, 30, 29, 0, false, false)); // live
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_provenance_chain (variant `d2`)  —  "Provenance chain", probe, immediate,
// value.
//
// The forged value has to survive being an OPERAND of a second chip before it is
// committed: OP1 produces it, OP2 consumes it, and only OP2's result is public.
// The consumer is drawn from the manifest's `consumer_set` (chips with a tight
// operand decomposition), so the question is whether the forgery survives someone
// else's operand-side range checks.
// ---------------------------------------------------------------------------
fn build_chain2_program_with(op: Opcode, consumer: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    li(&mut i, 27, 3);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // producer, under test
    i.push(Instruction::new(consumer, 31, 30, 27, false, false)); // consumer
    i.push(Instruction::new(Opcode::SLL, 31, 31, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 31, 31, 32, false, true));
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

fn build_chain2_add_program(op: Opcode, b: u64, c: u64) -> Program {
    build_chain2_program_with(op, Opcode::ADD, b, c)
}

fn build_chain2_mul_program(op: Opcode, b: u64, c: u64) -> Program {
    build_chain2_program_with(op, Opcode::MUL, b, c)
}

// ---------------------------------------------------------------------------
// st_fanout_read  —  "Fan-out read", probe, immediate, value.
//
// One write-back, TWO consumers at two different clks. This is the program-level
// form of the over-propagation question: if the witness generator feeds the same
// record field to a free column and to a pinned sibling, a single-site mutation
// breaks a sound constraint and the REJECT is a false negative. With two distinct
// reads the two consumers are separate rows, so the split becomes expressible.
// ---------------------------------------------------------------------------
fn build_fanout_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    li(&mut i, 27, 5);
    li(&mut i, 26, 9);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // the value read twice
    i.push(Instruction::new(Opcode::ADD, 6, 30, 27, false, false)); // consumer 1
    i.push(Instruction::new(Opcode::XOR, 7, 30, 26, false, false)); // consumer 2
    i.push(Instruction::new(Opcode::XOR, 31, 6, 7, false, false));
    i.push(Instruction::new(Opcode::SLL, 31, 31, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 31, 31, 32, false, true));
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_reg_alias  —  "Register aliasing", probe, immediate, value.
//
// `rs1rs2`: OP rd, x28, x28 — the two operand reads are the same register in the
// same cycle, which tests whether the second read's prev_timestamp is the first
// read's or the pre-instruction one.
// `rdrs1rs2`: OP x30, x30, x30 — the destination is also both sources.
// ---------------------------------------------------------------------------
fn build_reg_alias_rs_program(op: Opcode, b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    i.push(Instruction::new(op, 30, 28, 28, false, false));
    i.push(Instruction::new(Opcode::SLL, 30, 30, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 30, 30, 32, false, true));
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

fn build_reg_alias_all_program(op: Opcode, b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    i.push(Instruction::new(Opcode::ADD, 30, 28, 0, false, false));
    i.push(Instruction::new(op, 30, 30, 30, false, false));
    i.push(Instruction::new(Opcode::SLL, 30, 30, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 30, 30, 32, false, true));
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_dead_write  —  "Dead write-back", DECLARED CONTROL, immediate, value.
//
// The write-back under test can NOT reach the committed output: `overwritten` has
// its result overwritten before any read, `neverread` writes a register nobody
// reads. Its REJECT is the interpretability anchor for every other REJECT on this
// target, and it removes sp1's biggest confound — 1,670 of 5,226 published
// candidates are EXECFAIL from perturbing a register the COMMIT ecall then reads.
// A candidate here that is ACCEPTED with an unchanged digest is the expected
// outcome, not a finding.
// ---------------------------------------------------------------------------
fn build_dead_overwritten_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    li(&mut i, 27, 7);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // dead: overwritten below
    i.push(Instruction::new(Opcode::ADD, 30, 27, 0, false, false));
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

fn build_dead_neverread_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    li(&mut i, 27, 7);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // dead: x30 is never read
    i.push(Instruction::new(Opcode::ADD, 31, 27, 0, false, false));
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_x0_dark_write  —  "x0 dark write", probe, immediate, value.
//
// Writes the opcode's result to x0 and commits x0. sp1 dedicates four chips to
// this case — AluX0, AluX0User, LoadX0, LoadX0User (crates/core/machine/src/riscv/mod.rs)
// — and no sp1 LACUNA candidate has ever produced a row in any of them.
//
// KNOWN LIMIT OF THE ARM AT THE x0 SITE ITSELF. `CoreVM::rw` zeroes the value for
// register x0 (crates/core/executor/src/vm.rs) and this wave applies the LACUNA
// hook AFTER that squash, precisely so that the dark write is expressible; see the
// note in vm.rs. The other sites of this seed are ordinary value sites.
// ---------------------------------------------------------------------------
fn build_x0_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    i.push(Instruction::new(op, 0, 28, 29, false, false)); // the dark write
    i.push(Instruction::new(Opcode::ADD, 31, 0, 0, false, false)); // honest value: 0
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_pc_imm_value  —  "PC-immediate value", probe, immediate, value.
//
// LUI, AUIPC and the JAL link write in one program: three result values that come
// from the pc and the instruction word rather than from a register. UTypeChip and
// UTypeUser are in the sp1 machine and have never been instantiated by a LACUNA
// candidate. All three are summed into the committed word, so each of the three
// sites has a path to the output.
// ---------------------------------------------------------------------------
fn build_utype_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    i.push(Instruction::new(Opcode::LUI, 28, 0x0001_2000, 0x0001_2000, true, true));
    i.push(Instruction::new(Opcode::AUIPC, 29, 0x0000_1000, 0x0000_1000, true, true));
    i.push(Instruction::new(Opcode::JAL, 30, 8, 0, true, true)); // link write, skips the next
    i.push(Instruction::new(Opcode::ADDI, 31, 0, 0x7AD, false, true)); // jumped over
    i.push(Instruction::new(Opcode::ADD, 28, 28, 29, false, false));
    i.push(Instruction::new(Opcode::ADD, 28, 28, 30, false, false));
    commit_tail(&mut i, 28);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_indirect_jump  —  "Indirect jump", probe, immediate, site_role=ADDRESS.
//
// JALR through a register: the forged value becomes the next pc, so the ROM
// lookup and the pc-limb decomposition are what has to bind. Both arms write a
// different value, and the link register is added into the committed word so the
// JALR rd site is observable too.
//
// MU MASKING, and an honest statement of its limit. The manifest allows `xor_b0`
// at this structure and nowhere else, because clearing bit 0 is the RISC-V JALR
// requirement (`next_pc = (rs1 + imm) & !1`) and the whole point of the bit0
// variant. The address role's other entries (+/-2^16, xor_b15, +/-2^32) all land
// the pc far outside a nine-instruction program, so on sp1 they are EXECFAIL by
// construction — expected, and recorded as such rather than as verdicts. A
// meaningful table-redirect would need the `addr_delta_w` menu entry, which the
// manifest lists as PROPOSED, NOT IMPLEMENTED ANYWHERE; this wave does not add it.
// ---------------------------------------------------------------------------
fn build_jalr_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    // index 0..: pc = 4 * index, pc_base = 0.
    i.push(Instruction::new(Opcode::ADDI, 6, 0, 0x14, false, true)); // target = index 5
    i.push(Instruction::new(Opcode::JALR, 1, 6, 0, false, true)); // link -> x1
    i.push(Instruction::new(Opcode::ADDI, 31, 0, 0x111, false, true)); // arm A (fallthrough)
    i.push(Instruction::new(Opcode::JAL, 0, 12, 0, true, true)); // -> index 6
    i.push(Instruction::new(Opcode::ADDI, 0, 0, 0, false, true)); // padding, never executed
    i.push(Instruction::new(Opcode::ADDI, 31, 0, 0x222, false, true)); // arm B (honest target)
    i.push(Instruction::new(Opcode::ADD, 31, 31, 1, false, false)); // link joins the output
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_control_flow  —  "Control flow", probe, immediate, site_role=SELECTOR.
//
// The forged value is a branch CONDITION, so the mutation moves next_pc rather
// than a datum: sink S3 of the taint/composition audit. Both arms are exactly one
// instruction long, so the perturbed execution has the same length as the honest
// one — required here, because phase 2 replays against a phase-1 chunk header.
// The seed is deliberately memory-read-free: a divergent path must not consume a
// different number of `mem_reads` entries or the phase-1 oracle is exhausted and
// `CoreVM::mr` panics (vm.rs:749) before there is a verdict.
//
// `dataident` is the paired control: both arms write the SAME value, so a flipped
// branch is invisible in the committed output.
// ---------------------------------------------------------------------------
fn build_cf_program_with(v1: u64, v2: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, 0); // the condition (honest: branch taken)
    li(&mut i, 29, v1);
    li(&mut i, 30, v2);
    let pc_branch = 4 * i.len() as u64;
    // BEQ x28, x0, +12 -> skips arm A and its JAL, landing on arm B.
    i.push(Instruction::new(Opcode::BEQ, 28, 0, 12, false, true));
    i.push(Instruction::new(Opcode::ADD, 31, 29, 0, false, false)); // arm A
    i.push(Instruction::new(Opcode::JAL, 0, 8, 0, true, true)); // skip arm B
    i.push(Instruction::new(Opcode::ADD, 31, 30, 0, false, false)); // arm B (honest)
    debug_assert_eq!(pc_branch + 12, 4 * (i.len() as u64 - 1));
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

fn build_cf_datadiv_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    build_cf_program_with(0x0AAA_0001, 0x0BBB_0002)
}

fn build_cf_dataident_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    build_cf_program_with(0x0CCC_0003, 0x0CCC_0003)
}

// ---------------------------------------------------------------------------
// st_op_then_state  —  "Operation then state", probe, immediate, value.
//
// THE DECONFOUNDING SHAPE. The opcode under test does not reach the output
// directly: its result first traverses one state interaction. Structure and
// opcode vary independently here (manifest rules R1-R4), which is what the
// published pico matrix never did.
//
//  * variant `branch` — the result becomes a DECISION (sink S3). Memory-read-free,
//    so it is the one variant that is fully coherent on sp1.
//  * variant `addr`   — the result becomes an ADDRESS (sink S2): bit 15 of the
//    result selects which of two pre-written slots the load reads, so `xor_b15`
//    at the producing site swaps the committed object. RAM-routed: see fact (2).
//  * variant `mem`    — the store--load round trip. On sp1 this program is
//    identical to `st_store_load`, which is registered separately with the same
//    opcode axis, so it is NOT duplicated here.
// ---------------------------------------------------------------------------
fn build_ots_branch_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // the opcode under test
    i.push(Instruction::new(Opcode::BEQ, 30, 0, 12, false, true)); // its result decides
    i.push(Instruction::new(Opcode::ADDI, 31, 0, 0x333, false, true)); // arm A
    i.push(Instruction::new(Opcode::JAL, 0, 8, 0, true, true));
    i.push(Instruction::new(Opcode::ADDI, 31, 0, 0x444, false, true)); // arm B
    commit_tail(&mut i, 31);
    Program::new(i, 0, 0)
}

fn build_ots_addr_program(op: Opcode, b: u64, c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 24, 0x0A5A_0001);
    li(&mut i, 25, 0x0B5B_0002);
    li(&mut i, 6, SCRATCH);
    i.push(Instruction::new(Opcode::SD, 24, 6, 0, false, true)); // slot 0
    i.push(Instruction::new(Opcode::SD, 25, 6, 8, false, true)); // slot 1
    li(&mut i, 28, b);
    li(&mut i, 29, c);
    li(&mut i, 27, 0x8000);
    i.push(Instruction::new(op, 30, 28, 29, false, false)); // the opcode under test
    i.push(Instruction::new(Opcode::AND, 26, 30, 27, false, false)); // bit 15 of the result
    i.push(Instruction::new(Opcode::SRL, 26, 26, 12, false, true)); // -> 0 or 8
    i.push(Instruction::new(Opcode::ADD, 8, 6, 26, false, false)); // the address
    i.push(Instruction::new(Opcode::LD, 7, 8, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_loop_repeat / st_multishard  —  "Loop repeat" / "Cross-shard continuation",
// probe, immediate, value.
//
// One static pc executed N times. On sp1 only nth = -1 is legal (fact (3)), so
// EVERY execution of the accumulate site is perturbed; the committed sum makes
// the aggregate effect observable. The long variant is also the cross-shard seed:
// it produces more than one shard only when the run lowers SHARD_SIZE (read from
// the environment at crates/core/executor/src/opts.rs:118) or the trace-chunk
// threshold, and the per-seed `shards=` line in the log says how many shards the
// honest baseline actually produced, so a single-shard run is self-evident.
// ---------------------------------------------------------------------------
fn build_loop_program_n(n: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, n); // counter
    li(&mut i, 29, 1);
    i.push(Instruction::new(Opcode::ADD, 30, 0, 0, false, false)); // accumulator
    let body = 4 * i.len() as u64;
    i.push(Instruction::new(Opcode::ADD, 30, 30, 29, false, false)); // the repeated site
    i.push(Instruction::new(Opcode::SUB, 28, 28, 29, false, false));
    let back = 4 * i.len() as u64;
    i.push(Instruction::new(Opcode::BNE, 28, 0, (body.wrapping_sub(back)) as u64, false, true));
    i.push(Instruction::new(Opcode::SLL, 30, 30, 32, false, true));
    i.push(Instruction::new(Opcode::SRL, 30, 30, 32, false, true));
    commit_tail(&mut i, 30);
    Program::new(i, 0, 0)
}

fn build_loop_n16_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    build_loop_program_n(16)
}

fn build_loop_n256_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    build_loop_program_n(256)
}

fn build_multishard_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    build_loop_program_n(20_000)
}

// ---------------------------------------------------------------------------
// st_pv_plumbing (variant `words8`)  —  "Public-value plumbing", probe,
// immediate, value.
//
// Eight COMMIT ecalls with eight different word indices and eight different
// values: does digest word i really carry the value the guest committed at index
// i? Each `ADDI x11` is its own write-back site, so a mutation at site i asks
// whether slot i is bound.
//
// The `index`, `alias` and `exitcode` variants are NOT shipped: they need a
// mutation at an ECALL argument register, and the manifest FORBIDS the
// syscall_arg site role on every target today — sp1's own record generator panics
// first (commit.rs:9-11 and the digest index bound), which is 1,502 of sp1's
// 1,670 EXECFAILs.
// ---------------------------------------------------------------------------
fn build_pv8_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    for w in 0..PV_DIGEST_NUM_WORDS as u64 {
        i.push(Instruction::new(Opcode::ADDI, 10, 0, w, false, true)); // a0 = word index
        i.push(Instruction::new(Opcode::ADDI, 11, 0, 0x100 + w, false, true)); // a1 = value
        i.push(Instruction::new(Opcode::ADDI, 5, 0, COMMIT_SYSCALL, false, true));
        i.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    }
    i.push(Instruction::new(Opcode::ADDI, 10, 0, 0, false, true));
    i.push(Instruction::new(Opcode::ADDI, 11, 0, 0, false, true));
    i.push(Instruction::new(Opcode::ADDI, 5, 0, COMMIT_DEFERRED_SYSCALL, false, true));
    i.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    add_halt(&mut i);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_early_exit  —  "Early exit", probe, immediate, site_role=SELECTOR.
//
// A forged condition branches straight to HALT, skipping both COMMIT ecalls. sp1
// defends this explicitly — `SP1Verifier::verify` rejects with "COMMIT syscall was
// never called" (crates/prover/src/verify.rs:481-490) — so the expected verdict is
// REJECT and this seed exists to MEASURE that defence.
//
// It is unfalsifiable under the strict predicate, which requires a non-empty
// committed output; it is scored by `accepted_case_v2`, which counts "differs
// from honest BY BEING ABSENT OR TRUNCATED". Both columns are emitted.
// ---------------------------------------------------------------------------
fn build_early_exit_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 28, 1); // condition: honest value is non-zero, so no branch
    li(&mut i, 31, 0x0EE0_0001);
    let pc_branch = 4 * i.len() as u64;
    i.push(Instruction::new(Opcode::BEQ, 28, 0, 0, false, true)); // patched below
    let mut tail = Vec::new();
    commit_tail(&mut tail, 31);
    // The halt block is the last three instructions of `commit_tail`; branching to
    // it skips both ecalls.
    let halt_at = 4 * (i.len() + tail.len() - 3) as u64;
    let branch = i.len() - 1;
    i[branch] = Instruction::new(Opcode::BEQ, 28, 0, halt_at - pc_branch, false, true);
    i.extend(tail);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// st_hint_advice  —  "Nondeterministic advice", CALIBRATION, operand_source=HINT,
// value.
//
// The only sp1 seed whose operand does NOT arrive as an immediate baked into the
// vk-committed program: it comes through SP1Stdin, HINT_LEN and HINT_READ, and is
// then loaded and committed. Two things ride on it. (i) It is the manifest's
// input-contract calibration — every other sp1 seed is operand_source=immediate,
// which can only make the target look safer than it is. (ii) sp1 hint pages are
// initialised through the very MemoryInitialize chip whose value column is
// unconstrained for addr != 0, so its `meminit` arm is the cheapest candidate
// ACCEPT on this target, if one exists at all.
// ---------------------------------------------------------------------------
/// The hint word every `st_hint_advice` candidate reads. Below 2^32 so the honest
/// COMMIT succeeds.
const HINT_WORD: u64 = 0x1234_5678;
/// `SyscallCode::HINT_LEN` / `HINT_READ` (crates/core/executor/src/syscall_code.rs:102,105).
const HINT_LEN_SYSCALL: u64 = 0x00_00_00_F0;
const HINT_READ_SYSCALL: u64 = 0x00_00_00_F1;

fn build_hint_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    i.push(Instruction::new(Opcode::ADDI, 5, 0, HINT_LEN_SYSCALL, false, true));
    i.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false)); // x5 = byte length
    i.push(Instruction::new(Opcode::ADD, 11, 5, 0, false, false)); // a1 = length
    li(&mut i, 10, SCRATCH); // a0 = destination
    i.push(Instruction::new(Opcode::ADDI, 5, 0, HINT_READ_SYSCALL, false, true));
    i.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    li(&mut i, 6, SCRATCH);
    i.push(Instruction::new(Opcode::LD, 7, 6, 0, false, true));
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

fn hint_stdin() -> SP1Stdin {
    SP1Stdin::from(&HINT_WORD.to_le_bytes())
}

fn empty_stdin() -> SP1Stdin {
    SP1Stdin::new()
}

// ---------------------------------------------------------------------------
// st_whole_program  —  "Whole program", probe, immediate, value.
//
// A realistic compiled guest instead of a hand-written instruction vector:
// `test-artifacts`' fibonacci program, which needs no input and commits two
// values through the ordinary sp1_zkvm public-value path, so the committed digest
// is a real hash of a real public-value stream. It brings the census opcode mix,
// the entrypoint's memory traffic and hundreds of static write-back sites. Site
// sampling (LACUNA_SITE_STRIDE / LACUNA_MAX_SITES) is part of the result and must
// be published with the counts.
// ---------------------------------------------------------------------------
fn build_fibonacci_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    Program::from(&test_artifacts::FIBONACCI_ELF).expect("fibonacci test artifact")
}

// ---------------------------------------------------------------------------
// st_precompile  —  "Precompile boundary", probe, immediate, value.
//
// Roughly 100 of sp1's 122 chips are precompiles and not one has ever been
// instantiated by a LACUNA candidate. This seed calls SHA_EXTEND
// (`SyscallCode::SHA_EXTEND`, crates/core/executor/src/syscall_code.rs:60)
// directly out of a hand-built instruction vector — t0 = the syscall code,
// a0 = the 64-doubleword w[] buffer, a1 = 0 — writes two non-zero input words,
// and commits w[16], which the precompile derives from them. So the ShaExtend
// chip gets rows and the precompile's output is on the public path.
//
// WHY NOT A test-artifacts GUEST, for the record. The obvious candidates are the
// four `*-decompress` programs, which are the only precompile guests in
// test-artifacts that also COMMIT their result. They cannot run on this tree at
// all: `weierstrass_decompress_syscall`
// (crates/core/executor/src/minimal/precompiles/weierstrass/decompress.rs:12) is
// a stub whose body is `panic!("This method should be deprecated.")`, so the
// native minimal executor aborts (SIGABRT) before any record exists — verified in
// this wave against SECP256K1_DECOMPRESS_ELF with the compressed generator as
// stdin. Of the remaining committing guests, `keccak256-test` depends on the
// UNPATCHED crates.io tiny-keccak (the [patch.crates-io] entry is keyed
// `tiny-keccak-patched`, so it does not apply), i.e. software keccak and no
// precompile at all.
//
// NOT LANDED IN THIS WAVE, AND THE REASON IS A RESULT. The builder below is kept,
// unregistered, for the next wave: its HONEST baseline does not verify. The real
// `SP1Verifier::verify` rejects it with
//     InvalidPublicValues(global cumulative sum is not zero)
// so an ECALL to a precompile from a synthetic `Program::new` instruction vector
// leaves the global memory bus unbalanced — the precompile's own memory accesses
// are not matched by initialize/finalize events the way a compiled guest's are.
// Until that is understood, a candidate on this seed would carry no verdict at
// all, so no rows are emitted rather than rows that mean nothing.
//
// SCOPE, once it does land. Like every other RAM-routed seed on sp1, only the
// final load's rd write-back would be a coherent site: the phase-2 precompile
// handler reads its inputs through the same address-blind phase-1 oracle, so a
// forged input word does not reach the precompile. Forging a precompile INPUT
// needs the read-side hook.
// ---------------------------------------------------------------------------
/// `SyscallCode::SHA_EXTEND`.
const SHA_EXTEND_SYSCALL: u64 = 0x00_30_01_05;
/// The w[] buffer: 64 doublewords, 8-byte aligned, outside the program image.
const SHA_W: u64 = 0x0000_0000_0006_0000;

#[allow(dead_code)]
fn build_sha_extend_program(_op: Opcode, _b: u64, _c: u64) -> Program {
    let mut i = Vec::new();
    li(&mut i, 6, SHA_W);
    li(&mut i, 28, 0x0000_0011); // w[0]
    i.push(Instruction::new(Opcode::SD, 28, 6, 0, false, true));
    li(&mut i, 29, 0x0000_2200); // w[1]
    i.push(Instruction::new(Opcode::SD, 29, 6, 8, false, true));
    li(&mut i, 10, SHA_W); // a0 = w
    i.push(Instruction::new(Opcode::ADDI, 11, 0, 0, false, true)); // a1 = 0
    i.push(Instruction::new(Opcode::ADDI, 5, 0, SHA_EXTEND_SYSCALL, false, true));
    i.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
    i.push(Instruction::new(Opcode::LD, 7, 6, 16 * 8, false, true)); // w[16]
    commit_tail(&mut i, 7);
    Program::new(i, 0, 0)
}

// ---------------------------------------------------------------------------
// Opcode sets (manifest `opcode_sets`), and the R3 substitution.
// ---------------------------------------------------------------------------

/// `alu_bound_reference`: no catalogued record-layer finding sits on these, so
/// they are the BOUND arm of every deconfounding pair.
fn ops_alu_bound() -> Vec<(&'static str, Opcode)> {
    vec![("ADD", Opcode::ADD), ("XOR", Opcode::XOR), ("AND", Opcode::AND)]
}

/// `deconfound_min` for sp1. TARGET_CAPABILITIES lists no ESTABLISHED unbound
/// opcode for this target, so manifest rule R3 applies: substitute the full
/// shift family (including the RV64 W forms) and the full M extension, and tag the
/// run `unbound_probe=substituted`. SRLIW is absent because these builders emit
/// the register form only.
fn ops_deconfound() -> Vec<(&'static str, Opcode)> {
    let mut v = ops_alu_bound();
    v.extend([
        ("SLL", Opcode::SLL),
        ("SRL", Opcode::SRL),
        ("SRA", Opcode::SRA),
        ("SLLW", Opcode::SLLW),
        ("SRLW", Opcode::SRLW),
        ("SRAW", Opcode::SRAW),
        ("MUL", Opcode::MUL),
        ("MULH", Opcode::MULH),
        ("MULHU", Opcode::MULHU),
        ("MULHSU", Opcode::MULHSU),
        ("DIV", Opcode::DIV),
        ("DIVU", Opcode::DIVU),
        ("REM", Opcode::REM),
        ("REMU", Opcode::REMU),
    ]);
    v
}

/// `m_ext` + `m_ext_w` + `shift_family` + `shift_family_w`: the boundary-operand
/// axis, where the operands sit next to a constraint discontinuity.
fn ops_boundary() -> Vec<(&'static str, Opcode)> {
    vec![
        ("SLL", Opcode::SLL),
        ("SRL", Opcode::SRL),
        ("SRA", Opcode::SRA),
        ("SLLW", Opcode::SLLW),
        ("SRLW", Opcode::SRLW),
        ("SRAW", Opcode::SRAW),
        ("MUL", Opcode::MUL),
        ("MULH", Opcode::MULH),
        ("MULHU", Opcode::MULHU),
        ("MULHSU", Opcode::MULHSU),
        ("DIV", Opcode::DIV),
        ("DIVU", Opcode::DIVU),
        ("REM", Opcode::REM),
        ("REMU", Opcode::REMU),
        ("MULW", Opcode::MULW),
        ("DIVW", Opcode::DIVW),
        ("DIVUW", Opcode::DIVUW),
        ("REMW", Opcode::REMW),
        ("REMUW", Opcode::REMUW),
    ]
}

/// `mem_narrow` + `mem_word`, load forms.
fn ops_loads() -> Vec<(&'static str, Opcode)> {
    vec![
        ("LB", Opcode::LB),
        ("LBU", Opcode::LBU),
        ("LH", Opcode::LH),
        ("LHU", Opcode::LHU),
        ("LW", Opcode::LW),
        ("LWU", Opcode::LWU),
        ("LD", Opcode::LD),
    ]
}

/// `mem_narrow` + `mem_word`, store forms.
fn ops_stores() -> Vec<(&'static str, Opcode)> {
    vec![
        ("SB", Opcode::SB),
        ("SH", Opcode::SH),
        ("SW", Opcode::SW),
        ("SD", Opcode::SD),
    ]
}

/// The boundary-operand pairs, one per manifest variant suffix.
fn boundary_operands() -> Vec<(&'static str, u64, u64)> {
    vec![
        // (a) zero-divisor / zero-shift selector: honest c = 1, one mu-step from 0
        ("zero", 0x5A5, 1),
        // (b) shift-amount mask: honest s = 1, mu reaches 0, 63, 64 and 2^16
        ("shamt", 0x7FF, 1),
        // (c) signed overflow: honest INT_MIN+1 / -1, mu(b) = INT_MIN
        ("intmin", (i64::MIN + 1) as u64, u64::MAX),
        // (d) limb / sign boundary
        ("limb", 0x0000_FFFF, 1),
        // (e) exactly divisible, even divisor (nexus DivRem #13 needs an even one)
        ("exactdiv", 8, 2),
        // (f) limb overflow: 0xFFFF_FFFF squared
        ("limbmax", 0x0000_0000_FFFF_FFFF, 0x0000_0000_FFFF_FFFF),
    ]
}

/// The single operand pair the published seeds use; every non-boundary structure
/// keeps it so that a per-structure comparison is not also an operand comparison.
fn default_operands() -> Vec<(&'static str, u64, u64)> {
    vec![("", 0x5A5, 13)]
}

// ---------------------------------------------------------------------------
// The seed table.
// ---------------------------------------------------------------------------

/// Which enumeration arm a seed participates in, and what the manifest calls that
/// arm's candidates.
struct Arm {
    /// `encoding` (write-back sites) | `meminit` | `memfinal` (record fields)
    mode: &'static str,
    /// manifest `candidate_class`: probe | control | calibration
    class: &'static str,
}

/// Which opcodes a seed's operation slot ranges over.
enum Axis {
    /// The published full register-writing set (`opcodes()`).
    Published,
    /// A manifest opcode set.
    Ops(fn() -> Vec<(&'static str, Opcode)>),
    /// No opcode axis: the structure is the whole experiment.
    None,
}

/// One row of the LACUNA seed table = one (structure, variant) cell of
/// `evaluation/spec/STRUCTURE_MANIFEST.yaml` for target sp1.
struct Seed {
    /// manifest structure id
    id: &'static str,
    /// manifest variant suffix, or "" when the structure has none
    variant: &'static str,
    /// manifest published_name; the CSV `program_structure` column
    structure: &'static str,
    /// seed-id disambiguator for two rows that share a structure id, a variant
    /// and an opcode set (only the two `st_provenance_chain` consumers today);
    /// for the two published rows it is the frozen legacy suffix instead
    suffix: &'static str,
    /// true for the two seeds whose seed ids predate the manifest naming
    /// convention and are frozen as published artefacts (`op_<op>`, `op_<op>_mem`)
    legacy: bool,
    arms: &'static [Arm],
    axis: Axis,
    operands: fn() -> Vec<(&'static str, u64, u64)>,
    build: fn(Opcode, u64, u64) -> Program,
    stdin: fn() -> SP1Stdin,
    /// manifest `operand_source`: input | hint | immediate
    operand_source: &'static str,
    /// manifest `site_role`, and the mu-menu role mask it selects
    site_role: &'static str,
    /// manifest `scored_against`
    scored_against: &'static str,
    /// pcs whose write-back is an ADDRESS even though the seed's default role is
    /// `value`; the address mu-mask is applied at exactly these sites
    addr_sites: &'static [u64],
    /// printed next to the seed's site line; `RAM_ROUTED` marks the seeds whose
    /// REJECT is not evidence of binding on sp1 (see fact (2) at the top)
    note: &'static str,
}

const PROBE: Arm = Arm { mode: "encoding", class: "probe" };
const PROBE_MEMINIT: Arm = Arm { mode: "meminit", class: "probe" };
const CTRL: Arm = Arm { mode: "encoding", class: "control" };
const CTRL_MEMINIT: Arm = Arm { mode: "meminit", class: "control" };
const CTRL_MEMFINAL: Arm = Arm { mode: "memfinal", class: "control" };
const CALIB: Arm = Arm { mode: "encoding", class: "calibration" };
const CALIB_MEMINIT: Arm = Arm { mode: "meminit", class: "calibration" };

/// THE PUBLISHED ROWS COME FIRST AND ARE UNCHANGED. `st_single_op` keeps seed id
/// `op_<op>`, the encoding arm and the full published opcode set; the memory seed
/// keeps seed id `op_<op>_mem` and the meminit arm. Everything after them is new.
fn seeds() -> Vec<Seed> {
    vec![
        Seed {
            id: "st_single_op",
            variant: "",
            structure: "Single operation",
            suffix: "",
            legacy: true,
            arms: &[PROBE],
            axis: Axis::Published,
            operands: default_operands,
            build: build_op_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "published",
        },
        Seed {
            id: "st_single_op",
            variant: "mem",
            structure: "Single operation + memory round trip",
            suffix: "_mem",
            legacy: true,
            arms: &[PROBE_MEMINIT],
            axis: Axis::Published,
            operands: default_operands,
            build: build_op_mem_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "published",
        },
        // ---- new: the twelve `trivial` cells --------------------------------
        Seed {
            id: "st_boundary_operand",
            variant: "",
            structure: "Boundary operand",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_boundary),
            operands: boundary_operands,
            build: build_boundary_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "selector",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "operand one mu-step from a constraint discontinuity",
        },
        Seed {
            id: "st_subword_lane",
            variant: "load",
            structure: "Sub-word lane",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_loads),
            operands: default_operands,
            build: build_subword_load_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED except the load's own rd site",
        },
        Seed {
            id: "st_subword_lane",
            variant: "store",
            structure: "Sub-word lane",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_stores),
            operands: default_operands,
            build: build_subword_store_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED except the load's own rd site",
        },
        Seed {
            id: "st_store_load",
            variant: "",
            structure: "Store--load",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_op_mem_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED except the load's own rd site; also realises st_op_then_state/mem",
        },
        Seed {
            id: "st_store_load",
            variant: "tail",
            structure: "Store--load",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_store_load_tail_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED except the load rd sites",
        },
        Seed {
            id: "st_redirect",
            variant: "",
            structure: "Redirect",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_redirect_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "address",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED; address role, mu menu masked",
        },
        Seed {
            id: "st_hazard_chain",
            variant: "",
            structure: "Hazard chain",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_hazard_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "two write-backs to one register: variants first/second are the two sites",
        },
        Seed {
            id: "st_provenance_chain",
            variant: "d2",
            structure: "Provenance chain",
            suffix: "consumeradd",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_chain2_add_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "consumer ADD",
        },
        Seed {
            id: "st_provenance_chain",
            variant: "d2",
            structure: "Provenance chain",
            suffix: "consumermul",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_chain2_mul_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "consumer MUL (tight operand decomposition)",
        },
        Seed {
            id: "st_indirect_jump",
            variant: "",
            structure: "Indirect jump",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_jalr_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "address",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "xor_b0 allowed here only (JALR bit-0 clearing); wide deltas EXECFAIL by construction",
        },
        Seed {
            id: "st_pc_imm_value",
            variant: "",
            structure: "PC-immediate value",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_utype_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "LUI + AUIPC + JAL link, all three summed into the committed word",
        },
        Seed {
            id: "st_fanout_read",
            variant: "",
            structure: "Fan-out read",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_fanout_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "one write-back, two consumers at two clks",
        },
        Seed {
            id: "st_reg_alias",
            variant: "rs1rs2",
            structure: "Register aliasing",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_reg_alias_rs_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "",
        },
        Seed {
            id: "st_reg_alias",
            variant: "rdrs1rs2",
            structure: "Register aliasing",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_reg_alias_all_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "",
        },
        Seed {
            id: "st_dead_write",
            variant: "overwritten",
            structure: "Dead write-back",
            suffix: "",
            legacy: false,
            arms: &[CTRL],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_dead_overwritten_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "declared control: expected REJECT or ACCEPT with an unchanged digest",
        },
        Seed {
            id: "st_dead_write",
            variant: "neverread",
            structure: "Dead write-back",
            suffix: "",
            legacy: false,
            arms: &[CTRL],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_dead_neverread_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "declared control: expected REJECT or ACCEPT with an unchanged digest",
        },
        Seed {
            id: "st_x0_dark_write",
            variant: "",
            structure: "x0 dark write",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_x0_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "instantiates AluX0 / LoadX0; hook applied after the x0 squash in CoreVM::rw",
        },
        // ---- new: the `moderate` cells landed in this wave -------------------
        Seed {
            id: "st_op_then_state",
            variant: "branch",
            structure: "Operation then state",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_ots_branch_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "memory-read-free: the one variant that is fully coherent on sp1",
        },
        Seed {
            id: "st_op_then_state",
            variant: "addr",
            structure: "Operation then state",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::Ops(ops_deconfound),
            operands: default_operands,
            build: build_ots_addr_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "RAM_ROUTED; bit 15 of the result selects the slot, so xor_b15 swaps the object",
        },
        Seed {
            id: "st_control_flow",
            variant: "datadiv",
            structure: "Control flow",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_cf_datadiv_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "selector",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "arms are equal length and memory-read-free",
        },
        Seed {
            id: "st_control_flow",
            variant: "dataident",
            structure: "Control flow",
            suffix: "",
            legacy: false,
            // The manifest's st_control_flow / sp1 cell declares candidate_class
            // `probe`, and the CSV must match the cell or the cross-target
            // aggregation is wrong (rule R8), so `probe` is what this row emits.
            // It is worth recording that the variant is a control at ONE site --
            // the branch condition, where both arms commit the same value -- and
            // an ordinary probe at all the others. A per-variant candidate_class
            // would express that; the manifest has none today.
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_cf_dataident_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "selector",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "declared control: both arms commit the same value",
        },
        Seed {
            id: "st_initial_state",
            variant: "bss",
            structure: "Initial state",
            suffix: "",
            legacy: false,
            arms: &[PROBE, PROBE_MEMINIT],
            axis: Axis::None,
            operands: default_operands,
            build: build_initial_state_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "meminit arm is the SINGLE LEG: no coherent triple without a CoreVM::mr hook",
        },
        Seed {
            id: "st_initial_image",
            variant: "data",
            structure: "Initial image",
            suffix: "",
            legacy: false,
            arms: &[CTRL, CTRL_MEMINIT, CTRL_MEMFINAL],
            axis: Axis::None,
            operands: default_operands,
            build: build_initial_image_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "declared control; in-image initial value is vk-bound and is NOT a record field",
        },
        Seed {
            id: "st_initial_image",
            variant: "bssboundary",
            structure: "Initial image",
            suffix: "",
            legacy: false,
            arms: &[CTRL, CTRL_MEMINIT, CTRL_MEMFINAL],
            axis: Axis::None,
            operands: default_operands,
            build: build_initial_image_bss_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "the .data/.bss dword boundary shape of the loader-layer golds",
        },
        Seed {
            id: "st_loop_repeat",
            variant: "n16",
            structure: "Loop repeat",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_loop_n16_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "nth=-1 only (global SEEN counter shared across the two CoreVM passes)",
        },
        Seed {
            id: "st_loop_repeat",
            variant: "n256",
            structure: "Loop repeat",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_loop_n256_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "nth=-1 only",
        },
        Seed {
            id: "st_multishard",
            variant: "",
            structure: "Cross-shard continuation",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_multishard_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "multi-shard only when the run lowers SHARD_SIZE; the shards= field says what happened",
        },
        Seed {
            id: "st_pv_plumbing",
            variant: "words8",
            structure: "Public-value plumbing",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_pv8_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "eight COMMIT ecalls; the index/alias/exitcode variants need the forbidden syscall_arg role",
        },
        Seed {
            id: "st_early_exit",
            variant: "",
            structure: "Early exit",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_early_exit_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "selector",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "scored by accepted_case_v2; sp1 rejects a proof whose COMMIT never ran",
        },
        Seed {
            id: "st_hint_advice",
            variant: "unchecked",
            structure: "Nondeterministic advice",
            suffix: "",
            legacy: false,
            arms: &[CALIB, CALIB_MEMINIT],
            axis: Axis::None,
            operands: default_operands,
            build: build_hint_program,
            stdin: hint_stdin,
            operand_source: "hint",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "input-contract calibration: the only sp1 seed whose operand is not baked into the vk",
        },
        Seed {
            id: "st_whole_program",
            variant: "",
            structure: "Whole program",
            suffix: "",
            legacy: false,
            arms: &[PROBE],
            axis: Axis::None,
            operands: default_operands,
            build: build_fibonacci_program,
            stdin: empty_stdin,
            operand_source: "immediate",
            site_role: "value",
            scored_against: "in_circuit",
            addr_sites: &[],
            note: "compiled guest; sample the sites and publish the sampling policy",
        },
    ]
}

/// The manifest's mu-menu role mask (`mu_menu.role_masks`), applied at the site.
///
/// `value` and `selector` take the whole menu. `address` keeps only the
/// alignment-preserving entries — every allowed entry is a multiple of 2^15 —
/// because +/-1 and xor_b0 break doubleword alignment and trap the executor, and
/// zero / boundary_msb / boundary_max / xor_b63 land outside any mapped region.
/// `xor_b0` is re-allowed at `st_indirect_jump` and nowhere else, which is the
/// manifest's one documented exception (JALR clears bit 0 by definition).
fn menu_for_site(
    all: bool,
    role: &str,
    seed_id: &str,
) -> Vec<(&'static str, &'static str, usize, i64)> {
    let full = menu(all);
    if role != "address" {
        return full;
    }
    full.into_iter()
        .filter(|(label, _, _, _)| {
            matches!(*label, "plus_B1" | "minus_B1" | "xor_b15" | "plus_B2" | "xor_b31")
                || (*label == "xor_b0" && seed_id == "st_indirect_jump")
        })
        .collect()
}

/// The instruction-independent rewriting menu. (label, template, mu_kind, mu_arg)
///
/// Mirrors the pico and nexus menus so the three targets are directly comparable.
/// SP1 hypercube is RV64, so the word width is 64 bits: the limb indices are
/// i in {0,1,2,3} for B = 2^16 and the boundary values are {0, 2^63, 2^64 - 1}.
fn menu(all: bool) -> Vec<(&'static str, &'static str, usize, i64)> {
    let full = vec![
        ("xor_b0", "ENC-E3", wb_perturb::MU_XORBIT, 0),
        ("plus_B0", "ENC-E1", wb_perturb::MU_ADDK, 1),
        ("minus_B0", "ENC-E1", wb_perturb::MU_ADDK, -1),
        ("plus_B1", "ENC-E1", wb_perturb::MU_ADDK, 1 << 16),
        ("minus_B1", "ENC-E1", wb_perturb::MU_ADDK, -(1i64 << 16)),
        ("plus_B2", "ENC-E1", wb_perturb::MU_ADDK, 1 << 32),
        ("minus_B2", "ENC-E1", wb_perturb::MU_ADDK, -(1i64 << 32)),
        ("xor_b15", "ENC-E3", wb_perturb::MU_XORBIT, 15),
        ("xor_b31", "ENC-E3", wb_perturb::MU_XORBIT, 31),
        ("xor_b63", "ENC-E3", wb_perturb::MU_XORBIT, 63),
        ("zero", "ENC-E2", wb_perturb::MU_ZERO, 0),
        ("boundary_msb", "ENC-E2", wb_perturb::MU_SET, i64::MIN),
        ("boundary_max", "ENC-E2", wb_perturb::MU_SET, -1),
    ];
    if all {
        full
    } else {
        vec![full[0]]
    }
}

/// Every opcode the seed builder can put at the operation slot and that writes a
/// register. Restricted to the R-type integer ALU ops the SP1 RV64IM machine has
/// chips for.
fn opcodes() -> Vec<(&'static str, Opcode)> {
    use Opcode::{
        ADD, ADDW, AND, DIV, DIVU, DIVUW, DIVW, MUL, MULH, MULHSU, MULHU, MULW, OR, REM, REMU,
        REMUW, REMW, SLL, SLLW, SLT, SLTU, SRA, SRAW, SRL, SRLW, SUB, SUBW, XOR,
    };
    vec![
        ("ADD", ADD),
        ("SUB", SUB),
        ("SLL", SLL),
        ("SLT", SLT),
        ("SLTU", SLTU),
        ("XOR", XOR),
        ("SRL", SRL),
        ("SRA", SRA),
        ("OR", OR),
        ("AND", AND),
        ("MUL", MUL),
        ("MULH", MULH),
        ("MULHSU", MULHSU),
        ("MULHU", MULHU),
        ("DIV", DIV),
        ("DIVU", DIVU),
        ("REM", REM),
        ("REMU", REMU),
        ("ADDW", ADDW),
        ("SUBW", SUBW),
        ("MULW", MULW),
        ("DIVW", DIVW),
        ("DIVUW", DIVUW),
        ("REMW", REMW),
        ("REMUW", REMUW),
        ("SLLW", SLLW),
        ("SRLW", SRLW),
        ("SRAW", SRAW),
    ]
}


/// Every static pc in the honest record that produced an architectural
/// write-back, with the number of times it executed.
///
/// Collected from the typed event vectors of the record. This is the SP1
/// analogue of "every step whose `result` is `Some`" on nexus.
fn writeback_sites(records: &[ExecutionRecord]) -> std::collections::BTreeMap<u64, usize> {
    let mut sites: std::collections::BTreeMap<u64, usize> = Default::default();
    for r in records {
        let mut bump = |pc: u64| *sites.entry(pc).or_insert(0) += 1;
        for (e, _) in &r.alu_x0_events {
            bump(e.pc);
        }
        for (e, _) in &r.add_events {
            bump(e.pc);
        }
        for (e, _) in &r.addw_events {
            bump(e.pc);
        }
        for (e, _) in &r.addi_events {
            bump(e.pc);
        }
        for (e, _) in &r.mul_events {
            bump(e.pc);
        }
        for (e, _) in &r.sub_events {
            bump(e.pc);
        }
        for (e, _) in &r.subw_events {
            bump(e.pc);
        }
        for (e, _) in &r.bitwise_events {
            bump(e.pc);
        }
        for (e, _) in &r.shift_left_events {
            bump(e.pc);
        }
        for (e, _) in &r.shift_right_events {
            bump(e.pc);
        }
        for (e, _) in &r.divrem_events {
            bump(e.pc);
        }
        for (e, _) in &r.lt_events {
            bump(e.pc);
        }
        for (e, _) in &r.utype_events {
            bump(e.pc);
        }
        for (e, _) in &r.jal_events {
            bump(e.pc);
        }
        for (e, _) in &r.jalr_events {
            bump(e.pc);
        }
        for (e, _) in &r.memory_load_byte_events {
            bump(e.pc);
        }
        for (e, _) in &r.memory_load_half_events {
            bump(e.pc);
        }
        for (e, _) in &r.memory_load_word_events {
            bump(e.pc);
        }
        for (e, _) in &r.memory_load_double_events {
            bump(e.pc);
        }
        for (e, _) in &r.memory_load_x0_events {
            bump(e.pc);
        }
        for (e, _) in &r.syscall_events {
            bump(e.pc);
        }
    }
    sites
}


type PanicPayload = Box<dyn std::any::Any + Send>;

fn panic_msg(p: &PanicPayload) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(ToString::to_string))
        .unwrap_or_else(|| "<opaque panic>".to_string())
}

fn trunc(s: &str) -> String {
    let s = s.replace(['\n', ',', '"', '\r'], " ");
    s.chars().take(160).collect()
}

/// The outcome of one candidate through the real pipeline.
struct Out {
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    hits: usize,
    pv: Option<[u32; PV_DIGEST_NUM_WORDS]>,
    honest_v: u64,
    forged_v: u64,
    t_record_ms: u128,
    t_prove_ms: u128,
    t_verify_ms: u128,
}

fn pv_hex(pv: &Option<[u32; PV_DIGEST_NUM_WORDS]>) -> String {
    match pv {
        None => "NONE".to_string(),
        Some(w) => w.iter().map(|x| format!("{x:08x}")).collect(),
    }
}

/// One candidate through the REAL pipeline: armed record generation -> real
/// `prove_shard` per shard -> real `MachineVerifier::verify`.
///
/// `body` must arm the relevant hook and return the generated records.
/// Concrete SP1 core proving stack, at the production core parameters
/// (`CORE_LOG_STACKING_HEIGHT` = 21, `CORE_MAX_LOG_ROW_COUNT` = 22,
/// crates/prover/src/components.rs:16-17), so that the proofs produced here are
/// exactly the proofs `SP1Verifier::verify` expects.
type ShardP = CpuShardProver<
    SP1GlobalContext,
    SP1InnerPcs,
    SP1InnerPcsProver,
    RiscvAir<SP1Field>,
>;
type Sc = sp1_hypercube::SP1SC<SP1GlobalContext, RiscvAir<SP1Field>>;
type Prover = SimpleProver<SP1GlobalContext, Sc, ShardP>;
type Pk = Arc<sp1_hypercube::prover::ProvingKey<SP1GlobalContext, Sc, ShardP>>;

/// One candidate through the REAL pipeline: armed record generation -> real
/// `prove_shard` per shard -> real `SP1Verifier::verify`.
///
/// `SP1Verifier::verify` (crates/prover/src/verify.rs:109) is the production SP1
/// core-proof verifier: it checks every shard proof cryptographically AND the
/// cross-shard public-value chain and the global cumulative sum. Nothing here is a
/// mock, a debug builder or a per-chip satisfiability check.
#[allow(clippy::too_many_lines)]
fn run_pipeline(
    rt: &tokio::runtime::Runtime,
    prover: &Prover,
    verifier: &SP1Verifier,
    pk: &Pk,
    vk: &MachineVerifyingKey<SP1GlobalContext>,
    gen_records: impl FnOnce() -> Result<Vec<ExecutionRecord>, String>,
    hits: impl Fn() -> usize,
    values: impl Fn() -> (u64, u64),
) -> Out {
    let t0 = Instant::now();
    // Record generation can panic (e.g. a perturbed write-back turns a syscall id
    // into an invalid one). That is an EXECFAIL, not a verdict.
    let records = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(gen_records)) {
        Ok(r) => r,
        Err(p) => Err(format!("panic: {}", panic_msg(&p))),
    };
    let t_record = t0.elapsed().as_millis();
    let n_hits = hits();
    let (hv, fv) = values();

    let records = match records {
        Ok(r) => r,
        Err(e) => {
            return Out {
                outcome: "EXECFAIL",
                failure_stage: "fork_exec",
                reason: trunc(&e),
                hits: n_hits,
                pv: None,
                honest_v: hv,
                forged_v: fv,
                t_record_ms: t_record,
                t_prove_ms: 0,
                t_verify_ms: 0,
            }
        }
    };

    let t1 = Instant::now();
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut shard_proofs = std::collections::BTreeMap::new();
            for record in records {
                let proof = prover.prove_shard(pk.clone(), record).await;
                let pvs: &PublicValues<[SP1Field; 4], [SP1Field; 3], [SP1Field; 4], SP1Field> =
                    proof.public_values.as_slice().borrow();
                shard_proofs.insert(
                    (
                        pvs.initial_timestamp,
                        pvs.last_timestamp,
                        pvs.previous_init_addr,
                        pvs.previous_finalize_addr,
                    ),
                    proof,
                );
            }
            SP1CoreProofData(shard_proofs.into_values().collect::<Vec<_>>())
        })
    }));
    let t_prove = t1.elapsed().as_millis();

    let proof = match proof {
        Ok(p) => p,
        Err(p) => {
            let msg = panic_msg(&p);
            return Out {
                outcome: "REJECT",
                failure_stage: "prove",
                reason: trunc(&msg),
                hits: n_hits,
                pv: None,
                honest_v: hv,
                forged_v: fv,
                t_record_ms: t_record,
                t_prove_ms: t_prove,
                t_verify_ms: 0,
            };
        }
    };

    // The committed public output: the `committed_value_digest` carried by the last
    // shard's public values.
    let pv = proof.0.last().map(|p| {
        let pvs: &PublicValues<[SP1Field; 4], [SP1Field; 3], [SP1Field; 4], SP1Field> =
            p.public_values.as_slice().borrow();
        let mut out = [0u32; PV_DIGEST_NUM_WORDS];
        for (i, w) in pvs.committed_value_digest.iter().enumerate() {
            out[i] = u32::from_le_bytes([
                w[0].as_canonical_u32() as u8,
                w[1].as_canonical_u32() as u8,
                w[2].as_canonical_u32() as u8,
                w[3].as_canonical_u32() as u8,
            ]);
        }
        out
    });

    let svk = SP1VerifyingKey { vk: vk.clone() };
    let t2 = Instant::now();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verifier.verify(&proof, &svk)
    }));
    let t_verify = t2.elapsed().as_millis();

    match res {
        Ok(Ok(())) => Out {
            outcome: if n_hits > 0 { "ACCEPT" } else { "NOOP" },
            failure_stage: if n_hits > 0 { "accepted_proof" } else { "mutation" },
            reason: String::new(),
            hits: n_hits,
            pv,
            honest_v: hv,
            forged_v: fv,
            t_record_ms: t_record,
            t_prove_ms: t_prove,
            t_verify_ms: t_verify,
        },
        Ok(Err(e)) => Out {
            outcome: "REJECT",
            failure_stage: "verify",
            reason: trunc(&format!("{e:?}")),
            hits: n_hits,
            pv,
            honest_v: hv,
            forged_v: fv,
            t_record_ms: t_record,
            t_prove_ms: t_prove,
            t_verify_ms: t_verify,
        },
        Err(p) => Out {
            outcome: "REJECT",
            failure_stage: "verify",
            reason: trunc(&format!("panic: {}", panic_msg(&p))),
            hits: n_hits,
            pv,
            honest_v: hv,
            forged_v: fv,
            t_record_ms: t_record,
            t_prove_ms: t_prove,
            t_verify_ms: t_verify,
        },
    }
}

struct Sink {
    file: Option<std::fs::File>,
}

impl Sink {
    fn open() -> Self {
        let file = std::env::var("LACUNA_OUT").ok().map(|p| {
            if let Some(dir) = std::path::Path::new(&p).parent() {
                std::fs::create_dir_all(dir).ok();
            }
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .expect("open LACUNA_OUT")
        });
        let mut s = Self { file };
        let header = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,\
nth,dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,\
hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,\
committed_digest,honest_committed_digest,digest_changed,structure_id,operand_source,\
candidate_class,site_role,scored_against,accepted_case_v2";
        println!("LACUNA_HEADER,{header}");
        if let Some(f) = s.file.as_mut() {
            if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
                writeln!(f, "{header}").unwrap();
            }
        }
        s
    }

    fn row(&mut self, row: &str) {
        println!("LACUNA_ROW,{row}");
        if let Some(f) = self.file.as_mut() {
            writeln!(f, "{row}").unwrap();
            f.flush().ok();
        }
    }
}

#[test]
#[ignore = "LACUNA evaluation run: sp1 record-layer enumeration; use --release"]
#[allow(clippy::too_many_lines)]
fn lacuna_encoding_enumeration_sp1() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "sp1".to_string());
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let mode = std::env::var("LACUNA_MODE").unwrap_or_else(|_| "both".to_string());
    let lsh: u32 = std::env::var("LACUNA_LSH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(crate::CORE_LOG_STACKING_HEIGHT);
    let mlrc: usize =
        std::env::var("LACUNA_MLRC").ok().and_then(|s| s.parse().ok()).unwrap_or(crate::CORE_MAX_LOG_ROW_COUNT);
    let want_pcs: Vec<u64> = std::env::var("LACUNA_PCS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|t| {
            let t = t.trim();
            t.strip_prefix("0x").map_or_else(
                || t.parse::<u64>().ok(),
                |h| u64::from_str_radix(h, 16).ok(),
            )
        })
        .collect();
    let want: Vec<String> = std::env::var("LACUNA_OPS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let mut sink = Sink::open();
    // Candidate panics are outcomes, not failures: keep the log readable.
    std::panic::set_hook(Box::new(|_| {}));

    // The production SP1 core-proof verifier.
    let sp1_verifier = SP1Verifier::new(VerifierRecursionVks::default());

    // Non-degenerate operands, small enough for the 12-bit ADDI immediate.
    let (b, c) = (0x5A5u64, 13u64);
    let opts = SP1CoreOpts::default();
    let nonce = SP1Context::default().proof_nonce;

    let do_encoding = mode == "encoding" || mode == "both";
    let do_meminit = mode == "meminit" || mode == "both";
    // `memfinal` is the third arm, used only by the new declared-control seeds:
    // `global_memory_finalize_events[k].value`, implemented at
    // crates/core/machine/src/utils/prove.rs but never armed until this wave.
    let do_memfinal = mode == "memfinal" || mode == "both";

    // Structure selection. A comma-separated list of manifest structure ids
    // (`st_redirect`) and/or seed suffixes (`_redirect`); empty runs the whole
    // table. `LACUNA_SEEDS=st_single_op` reproduces the published enumeration.
    let want_seeds: Vec<String> = std::env::var("LACUNA_SEEDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let ctx = RunCtx {
        rt: &rt,
        verifier: &sp1_verifier,
        opts: opts.clone(),
        nonce,
        lsh,
        mlrc,
        mu_all,
        want_pcs,
        tag: tag.clone(),
        // Site sampling. Defaults are no-ops, so the published seeds enumerate
        // exactly the sites they always did; the compiled-guest seeds need them.
        site_stride: std::env::var("LACUNA_SITE_STRIDE")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(1),
        max_sites: std::env::var("LACUNA_MAX_SITES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX),
        // The max-cycle abort. Phase 2 is already bounded by the phase-1 chunk
        // header, so a mutated branch cannot spin forever, but a mis-built
        // branching or looping seed can still cost hours before anyone notices;
        // a seed whose HONEST execution exceeds this is skipped with a log line
        // rather than enumerated. No published seed is anywhere near it.
        max_cycles: std::env::var("LACUNA_MAX_CYCLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1 << 20),
        do_encoding,
        do_meminit,
        do_memfinal,
    };

    let table = seeds();
    let selected = |s: &Seed| -> bool {
        want_seeds.is_empty()
            || want_seeds.iter().any(|w| w == s.id || w == s.suffix || w == s.variant)
    };

    // ---- pass 1: the seeds on the published full register-writing opcode axis.
    // Loop order (opcode outermost, seed inner) and row content are exactly the
    // published ones.
    for (name, op) in opcodes() {
        if !want.is_empty() && !want.contains(&name.to_string()) {
            continue;
        }
        for seed in table.iter().filter(|s| matches!(s.axis, Axis::Published)) {
            if !selected(seed) {
                continue;
            }
            for (opd, ob, oc) in (seed.operands)() {
                run_seed(&ctx, &mut sink, seed, name, op, ob, oc, opd);
            }
        }
    }

    // ---- pass 2: the new seeds, each on its own manifest opcode set (or none).
    for seed in &table {
        if !selected(seed) {
            continue;
        }
        match seed.axis {
            Axis::Published => {}
            Axis::Ops(set) => {
                for (name, op) in set() {
                    if !want.is_empty() && !want.contains(&name.to_string()) {
                        continue;
                    }
                    for (opd, ob, oc) in (seed.operands)() {
                        run_seed(&ctx, &mut sink, seed, name, op, ob, oc, opd);
                    }
                }
            }
            Axis::None => {
                // Opcode-independent: the structure is the whole experiment, so
                // the seed runs once and its CSV opcode column is NA. LACUNA_OPS
                // does not apply to it; shard these with LACUNA_SEEDS instead, or
                // an opcode-sharded run would repeat them in every shard.
                run_seed(&ctx, &mut sink, seed, "NA", Opcode::ADD, b, c, "");
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}

/// Everything one candidate needs that does not vary with the seed.
struct RunCtx<'a> {
    rt: &'a tokio::runtime::Runtime,
    verifier: &'a SP1Verifier,
    opts: SP1CoreOpts,
    nonce: [u32; PROOF_NONCE_NUM_WORDS],
    lsh: u32,
    mlrc: usize,
    mu_all: bool,
    want_pcs: Vec<u64>,
    tag: String,
    site_stride: usize,
    max_sites: usize,
    max_cycles: u64,
    do_encoding: bool,
    do_meminit: bool,
    do_memfinal: bool,
}

/// One seed: real setup, real honest baseline, then every armed candidate of
/// every arm the seed declares, each through the real prover and the production
/// `SP1Verifier::verify`.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_seed(
    ctx: &RunCtx<'_>,
    sink: &mut Sink,
    seed: &Seed,
    opcode_name: &str,
    op: Opcode,
    b: u64,
    c: u64,
    operand_label: &str,
) {
    let arms: Vec<&Arm> = seed
        .arms
        .iter()
        .filter(|a| match a.mode {
            "encoding" => ctx.do_encoding,
            "meminit" => ctx.do_meminit,
            "memfinal" => ctx.do_memfinal,
            _ => false,
        })
        .collect();
    if arms.is_empty() {
        return;
    }

    let tag = &ctx.tag;
    // Seed id. The two published seeds keep their frozen legacy ids; every new
    // seed follows the manifest convention `<structure id>[_<opcode>][_<variant>]`
    // (evaluation/scripts/check_manifest.py::seed_id_ok), so that two ports cannot
    // invent different names for the same cell.
    let seed_id = if seed.legacy {
        format!("op_{}{}", opcode_name.to_lowercase(), seed.suffix)
    } else {
        let mut id = seed.id.to_string();
        if !matches!(seed.axis, Axis::None) {
            id.push('_');
            id.push_str(&opcode_name.to_lowercase());
        }
        for part in [seed.variant, seed.suffix, operand_label] {
            if !part.is_empty() {
                id.push('_');
                id.push_str(part);
            }
        }
        id
    };

    let program = Arc::new((seed.build)(op, b, c));

    // ---- the honest record, first: it is cheap, it carries the cycle count the
    // max-cycle abort needs, and a seed that cannot even execute must not cost a
    // proof.
    let honest = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_records::<SP1Field>(program.clone(), (seed.stdin)(), ctx.opts.clone(), ctx.nonce)
    }));
    let (honest_records, cycles) = match honest {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            println!("LACUNA_BASELINE,{tag},sp1,{seed_id},NOT_VERIFIED,EXECFAIL,fork_exec,\"{}\"", trunc(&format!("{e:?}")));
            return;
        }
        Err(p) => {
            println!("LACUNA_BASELINE,{tag},sp1,{seed_id},NOT_VERIFIED,EXECFAIL,fork_exec,\"{}\"", trunc(&panic_msg(&p)));
            return;
        }
    };
    if cycles > ctx.max_cycles {
        println!(
            "LACUNA_SEED_SKIP,{tag},sp1,{seed_id},honest_cycles={cycles},max_cycles={}",
            ctx.max_cycles
        );
        return;
    }

    // Exactly the parameters `CpuSP1ProverComponents::core_verifier` uses
    // (crates/prover/src/components.rs:58-69), so the proofs produced here
    // are the proofs the production core verifier expects.
    let verifier = ShardVerifier::from_basefold_parameters(
        core_fri_config(),
        ctx.lsh,
        ctx.mlrc,
        RiscvAir::machine(),
    );
    let shard_prover =
        CpuShardProver::<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, _>::new(
            verifier.clone(),
        );
    let prover = SimpleProver::new(verifier, shard_prover);
    let (pk, vk) = ctx.rt.block_on(prover.setup(program.clone()));
    let pk = unsafe { pk.into_inner() };

    // ---- honest baseline ----
    let hout = run_pipeline(
        ctx.rt,
        &prover,
        ctx.verifier,
        &pk,
        &vk,
        || {
            generate_records::<SP1Field>(
                program.clone(),
                (seed.stdin)(),
                ctx.opts.clone(),
                ctx.nonce,
            )
            .map(|(r, _)| r)
            .map_err(|e| format!("{e:?}"))
        },
        || 0,
        || (0, 0),
    );
    if hout.outcome != "NOOP" {
        // The honest baseline did not verify: this seed has NO accepted
        // baseline and is excluded from the mutation evaluation.
        println!(
            "LACUNA_BASELINE,{tag},sp1,{seed_id},NOT_VERIFIED,{},{},\"{}\"",
            hout.outcome, hout.failure_stage, hout.reason
        );
        return;
    }
    let honest_hex = pv_hex(&hout.pv);
    println!(
        "LACUNA_BASELINE,{tag},sp1,{seed_id},VERIFIED,honest_pv={honest_hex},\
t_record_ms={},t_prove_ms={},t_verify_ms={}",
        hout.t_record_ms, hout.t_prove_ms, hout.t_verify_ms
    );

    let n_init_events: usize =
        honest_records.iter().map(|r| r.global_memory_initialize_events.len()).sum();
    let n_final_events: usize =
        honest_records.iter().map(|r| r.global_memory_finalize_events.len()).sum();

    // The manifest metadata this seed's rows carry, and the honest scope note.
    println!(
        "LACUNA_SEED,{tag},sp1,{seed_id},structure_id={},variant={},operand_source={},\
site_role={},scored_against={},shards={},honest_cycles={cycles},note=\"{}\"",
        seed.id,
        seed.variant,
        seed.operand_source,
        seed.site_role,
        seed.scored_against,
        honest_records.len(),
        seed.note
    );

    for arm in arms {
        let meta = RowMeta {
            structure_id: seed.id,
            operand_source: seed.operand_source,
            candidate_class: arm.class,
            site_role: seed.site_role,
            scored_against: seed.scored_against,
        };

        match arm.mode {
            // ---- every static pc that produced an architectural write-back ----
            "encoding" => {
                let sites = writeback_sites(&honest_records);
                println!(
                    "LACUNA_SITES,{tag},sp1,{seed_id},writeback_sites={},mem_init_events={}",
                    sites.len(),
                    n_init_events
                );
                let chosen: Vec<(u64, usize)> = sites
                    .into_iter()
                    .filter(|(pc, _)| ctx.want_pcs.is_empty() || ctx.want_pcs.contains(pc))
                    .step_by(ctx.site_stride)
                    .take(ctx.max_sites)
                    .collect();
                for (pc, execs) in chosen {
                    // The site's role decides the mu-menu mask: the seed's
                    // declared role, unless this pc is one of its address sites.
                    let role = if seed.addr_sites.contains(&pc) { "address" } else { seed.site_role };
                    let meta = RowMeta { site_role: role, ..meta };
                    for (label, template, kind, arg) in menu_for_site(ctx.mu_all, role, seed.id) {
                        let out = run_pipeline(
                            ctx.rt,
                            &prover,
                            ctx.verifier,
                            &pk,
                            &vk,
                            || {
                                // nth = -1: sp1's site counter is one global
                                // counter shared by the two CoreVM passes, so a
                                // per-execution nth is not expressible (R5).
                                wb_perturb::with(pc, -1, kind, arg, || {
                                    generate_records::<SP1Field>(
                                        program.clone(),
                                        (seed.stdin)(),
                                        ctx.opts.clone(),
                                        ctx.nonce,
                                    )
                                    .map(|(r, _)| r)
                                    .map_err(|e| format!("{e:?}"))
                                })
                            },
                            wb_perturb::hits,
                            || (wb_perturb::honest_value(), wb_perturb::forged_value()),
                        );
                        emit(
                            sink,
                            tag,
                            &seed_id,
                            "encoding",
                            seed.structure,
                            opcode_name,
                            &format!("{pc:#x}"),
                            execs,
                            label,
                            template,
                            kind,
                            arg,
                            &out,
                            &honest_hex,
                            &meta,
                        );
                    }
                }
            }
            // ---- every global memory initialize / finalize event value ----
            mode @ ("meminit" | "memfinal") => {
                let (field, n_events) = if mode == "meminit" {
                    (record_perturb::F_MEM_INIT_VALUE, n_init_events)
                } else {
                    (record_perturb::F_MEM_FINAL_VALUE, n_final_events)
                };
                if mode == "meminit" {
                    println!("LACUNA_SITES,{tag},sp1,{seed_id},mem_init_events={n_init_events}");
                } else {
                    println!("LACUNA_SITES,{tag},sp1,{seed_id},mem_final_events={n_final_events}");
                }
                let chosen: Vec<usize> =
                    (0..n_events).step_by(ctx.site_stride).take(ctx.max_sites).collect();
                for idx in chosen {
                    for (label, template, kind, arg) in
                        menu_for_site(ctx.mu_all, seed.site_role, seed.id)
                    {
                        let out = run_pipeline(
                            ctx.rt,
                            &prover,
                            ctx.verifier,
                            &pk,
                            &vk,
                            || {
                                record_perturb::with(field, idx as i64, kind, arg, || {
                                    generate_records::<SP1Field>(
                                        program.clone(),
                                        (seed.stdin)(),
                                        ctx.opts.clone(),
                                        ctx.nonce,
                                    )
                                    .map(|(r, _)| r)
                                    .map_err(|e| format!("{e:?}"))
                                })
                            },
                            record_perturb::hits,
                            || (record_perturb::honest_value(), record_perturb::forged_value()),
                        );
                        emit(
                            sink,
                            tag,
                            &seed_id,
                            mode,
                            seed.structure,
                            opcode_name,
                            &format!("idx{idx}"),
                            1,
                            label,
                            template,
                            kind,
                            arg,
                            &out,
                            &honest_hex,
                            &meta,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// The manifest metadata one CSV row carries (`csv_contract.required_new_columns`).
/// Additive: every column that was already there keeps its name, position,
/// meaning and value.
#[derive(Clone, Copy)]
struct RowMeta<'a> {
    /// manifest structure id, so a row can be joined against STRUCTURE_MANIFEST.yaml
    structure_id: &'a str,
    /// input | hint | immediate
    operand_source: &'a str,
    /// probe | control | calibration
    candidate_class: &'a str,
    /// value | address | selector | syscall_arg
    site_role: &'a str,
    /// which public-output object the predicate read for this row
    scored_against: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn emit(
    sink: &mut Sink,
    tag: &str,
    seed: &str,
    mode: &str,
    structure: &str,
    opcode: &str,
    site: &str,
    execs: usize,
    label: &str,
    template: &str,
    kind: usize,
    arg: i64,
    out: &Out,
    honest_hex: &str,
    meta: &RowMeta<'_>,
) {
    let hex = pv_hex(&out.pv);
    let nonempty = hex != "NONE" && !hex.is_empty();
    let changed = out.outcome == "ACCEPT" && nonempty && hex != honest_hex;
    let accepted = out.outcome == "ACCEPT" && out.hits > 0 && changed;
    // `accepted_case_v2` (manifest `predicates`): additive, and never turns a
    // strict accept into a non-accept. It additionally counts a committed output
    // that differs from the honest one BY BEING ABSENT OR TRUNCATED, which is the
    // only way st_early_exit can succeed.
    let accepted_v2 = out.outcome == "ACCEPT" && out.hits > 0 && hex != honest_hex;
    let row = format!(
        "{tag},sp1,{REV},{seed},{mode},{structure},{opcode},{site},-1,false,false,{execs},{label},\
{template},{kind},{arg},{},{},{},{hex},{honest_hex},{changed},{accepted},{},{},{},\"{}\",NA,NA,NA,\
{},{},{},{},{},{accepted_v2}",
        out.outcome,
        out.failure_stage,
        out.hits,
        out.t_record_ms,
        out.t_prove_ms,
        out.t_verify_ms,
        out.reason,
        meta.structure_id,
        meta.operand_source,
        meta.candidate_class,
        meta.site_role,
        meta.scored_against
    );
    sink.row(&row);
    if accepted {
        println!(
            "  *** ACCEPTED CASE: {opcode} @ {site} mu={label} honest {:#x} -> {:#x}; \
committed digest {honest_hex} -> {hex}",
            out.honest_v, out.forged_v
        );
    }
}

// ===========================================================================
// LACUNA CPU CALIBRATION  (ADDITIVE — measurement only)
// ===========================================================================
//
// Adds a second, `#[ignore]`d test that walks a *sample* of the same candidate
// grid the enumeration test walks, through the same real prover and the same
// production `SP1Verifier::verify`, and records for each candidate the wall
// time AND the process CPU time (user+system, summed over every thread) spent
// in four stages:
//
//   S1  mutation construction + suffix replay  = `generate_records` under the
//       armed hook (MinimalExecutorRunner -> SplicingVM -> TracingVM ->
//       emit_globals -> record_perturb::apply -> machine.generate_dependencies)
//   S2  trace / witness generation             = `trace_generator().generate_main_traces`
//   S3  proof generation                       = `prove_shard_with_data`
//   S4  verification                           = `SP1Verifier::verify`
//
// S2 and S3 are the two halves of `AirProver::prove_shard_with_pk`
// (crates/hypercube/src/prover/shard.rs:336-361), inlined here in the same
// order with the same arguments so the produced proof is bit-identical to the
// one `SimpleProver::prove_shard` produces; the only difference is that
// `prove_shard_with_data` is called directly instead of through
// `tokio::task::spawn_blocking`, which changes no value.
//
// Nothing in this block changes a constraint, an AIR, a witness generator or
// the executor. Both LACUNA hooks stay default OFF.

use slop_challenger::IopCtx as LacunaIopCtx;
use sp1_hypercube::prover::{ProverSemaphore, ShardData, TraceGenerator as LacunaTraceGenerator};

/// Process CPU time (utime + stime) in milliseconds, aggregated over every
/// thread of this process. Fields 14/15 of /proc/self/stat, in USER_HZ ticks.
/// `LACUNA_CLK_TCK` overrides the assumed 100 Hz if `getconf CLK_TCK` differs.
fn cpu_ms() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rp = match s.rfind(')') {
        Some(i) => i,
        None => return 0,
    };
    let f: Vec<&str> = s[rp + 2..].split_whitespace().collect();
    // after "<pid> (comm) " the first token is field 3, so field N is index N-3
    let ut: u64 = f.get(11).and_then(|x| x.parse().ok()).unwrap_or(0);
    let st: u64 = f.get(12).and_then(|x| x.parse().ok()).unwrap_or(0);
    let hz: u64 = std::env::var("LACUNA_CLK_TCK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    (ut + st) * (1000 / hz)
}

#[derive(Clone, Copy, Default)]
struct Stage {
    wall_ms: u128,
    cpu_ms: u64,
    measured: bool,
}

impl Stage {
    fn w(&self) -> String {
        if self.measured { self.wall_ms.to_string() } else { "NA".to_string() }
    }
    fn c(&self) -> String {
        if self.measured { self.cpu_ms.to_string() } else { "NA".to_string() }
    }
}

struct Timed {
    outcome: &'static str,
    failure_stage: &'static str,
    hits: usize,
    s1: Stage,
    s2: Stage,
    s3: Stage,
    s4: Stage,
    total_wall_ms: u128,
    total_cpu_ms: u64,
}

/// Same pipeline as `run_pipeline`, with S2 split out of S3 and CPU probes
/// around all four stages.
#[allow(clippy::too_many_lines)]
fn run_pipeline_timed(
    rt: &tokio::runtime::Runtime,
    shard_prover: &ShardP,
    verifier: &SP1Verifier,
    pk: &Pk,
    vk: &MachineVerifyingKey<SP1GlobalContext>,
    gen_records: impl FnOnce() -> Result<Vec<ExecutionRecord>, String>,
    hits: impl Fn() -> usize,
) -> Timed {
    let all_c0 = cpu_ms();
    let all_w0 = Instant::now();

    // ---------------- S1: mutation construction + suffix replay ----------------
    let c0 = cpu_ms();
    let t0 = Instant::now();
    let records = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(gen_records)) {
        Ok(r) => r,
        Err(p) => Err(format!("panic: {}", panic_msg(&p))),
    };
    let s1 = Stage { wall_ms: t0.elapsed().as_millis(), cpu_ms: cpu_ms() - c0, measured: true };

    let n_hits = hits();

    let records = match records {
        Ok(r) => r,
        Err(_) => {
            return Timed {
                outcome: "EXECFAIL",
                failure_stage: "fork_exec",
                hits: n_hits,
                s1,
                s2: Stage::default(),
                s3: Stage::default(),
                s4: Stage::default(),
                total_wall_ms: all_w0.elapsed().as_millis(),
                total_cpu_ms: cpu_ms() - all_c0,
            }
        }
    };

    // ---------------- S2 + S3, per shard ----------------
    let mut s2 = Stage { measured: true, ..Default::default() };
    let mut s3 = Stage { measured: true, ..Default::default() };
    let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut shard_proofs = std::collections::BTreeMap::new();
        for record in records {
            // exactly the prologue of `prove_shard_with_pk` (shard.rs:336-343)
            let mut challenger = SP1GlobalContext::default_challenger();
            pk.vk.observe_into(&mut challenger);

            // ---- S2: main trace / witness generation ----
            let c = cpu_ms();
            let t = Instant::now();
            let main_trace_data = rt.block_on(shard_prover.trace_generator().generate_main_traces(
                record,
                shard_prover.max_log_row_count(),
                ProverSemaphore::new(1),
            ));
            s2.wall_ms += t.elapsed().as_millis();
            s2.cpu_ms += cpu_ms() - c;

            // ---- S3: proof generation ----
            let c = cpu_ms();
            let t = Instant::now();
            let (proof, _permit) = shard_prover
                .prove_shard_with_data(ShardData { pk: pk.clone(), main_trace_data }, challenger);
            s3.wall_ms += t.elapsed().as_millis();
            s3.cpu_ms += cpu_ms() - c;

            let pvs: &PublicValues<[SP1Field; 4], [SP1Field; 3], [SP1Field; 4], SP1Field> =
                proof.public_values.as_slice().borrow();
            shard_proofs.insert(
                (
                    pvs.initial_timestamp,
                    pvs.last_timestamp,
                    pvs.previous_init_addr,
                    pvs.previous_finalize_addr,
                ),
                proof,
            );
        }
        SP1CoreProofData(shard_proofs.into_values().collect::<Vec<_>>())
    }));

    let proof = match proof {
        Ok(p) => p,
        Err(_) => {
            return Timed {
                outcome: "REJECT",
                failure_stage: "prove",
                hits: n_hits,
                s1,
                s2,
                s3,
                s4: Stage::default(),
                total_wall_ms: all_w0.elapsed().as_millis(),
                total_cpu_ms: cpu_ms() - all_c0,
            }
        }
    };

    // ---------------- S4: verification ----------------
    let svk = SP1VerifyingKey { vk: vk.clone() };
    let c = cpu_ms();
    let t = Instant::now();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verifier.verify(&proof, &svk)
    }));
    let s4 = Stage { wall_ms: t.elapsed().as_millis(), cpu_ms: cpu_ms() - c, measured: true };

    let (outcome, failure_stage) = match res {
        Ok(Ok(())) => {
            if n_hits > 0 {
                ("ACCEPT", "accepted_proof")
            } else {
                ("NOOP", "mutation")
            }
        }
        Ok(Err(_)) | Err(_) => ("REJECT", "verify"),
    };

    Timed {
        outcome,
        failure_stage,
        hits: n_hits,
        s1,
        s2,
        s3,
        s4,
        total_wall_ms: all_w0.elapsed().as_millis(),
        total_cpu_ms: cpu_ms() - all_c0,
    }
}

fn parse_list(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// LACUNA per-stage CPU calibration over a reproducible SAMPLE of the grid.
///
/// Env:
///   LACUNA_CAL_OUT       output CSV path (required)
///   LACUNA_CAL_JOBS      ordered, comma-separated job list. Each job is
///                        `enc:<OPCODE>:<site index>` (a 0-based index into the
///                        sorted write-back-site list of that seed) or
///                        `mem:<OPCODE>:<global_memory_initialize_events index>`.
///                        Each job runs the FULL 13-entry mutation menu, so each
///                        job is exactly 13 candidates. Jobs run in the order
///                        given, so put the broad/cheap ones first.
///   LACUNA_CAL_BUDGET_S  stop before starting a candidate once this many wall
///                        seconds have elapsed (default: no limit)
///   LACUNA_LSH / LACUNA_MLRC as in the enumeration test
#[test]
#[ignore = "LACUNA CPU calibration: per-stage wall+CPU measurement; use --release"]
#[allow(clippy::too_many_lines)]
fn lacuna_cpu_calibration_sp1() {
    let out_path = std::env::var("LACUNA_CAL_OUT").expect("LACUNA_CAL_OUT must be set");
    let jobs: Vec<(String, String, usize)> =
        parse_list(&std::env::var("LACUNA_CAL_JOBS").unwrap_or_else(|_| "enc:ADD:2".into()))
            .iter()
            .filter_map(|j| {
                let mut it = j.split(':');
                let kind = it.next()?.to_string();
                let op = it.next()?.to_uppercase();
                let ix: usize = it.next()?.parse().ok()?;
                Some((kind, op, ix))
            })
            .collect();
    let budget_s: u64 = std::env::var("LACUNA_CAL_BUDGET_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
    let lsh: u32 = std::env::var("LACUNA_LSH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(crate::CORE_LOG_STACKING_HEIGHT);
    let mlrc: usize = std::env::var("LACUNA_MLRC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(crate::CORE_MAX_LOG_ROW_COUNT);

    if let Some(dir) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let mut f = std::fs::File::create(&out_path).expect("create LACUNA_CAL_OUT");
    writeln!(
        f,
        "candidate_key,seed_id,opcode,mutation_template,outcome,failure_stage,\
s1_replay_wall_ms,s1_replay_cpu_ms,s2_tracegen_wall_ms,s2_tracegen_cpu_ms,\
s3_prove_wall_ms,s3_prove_cpu_ms,s4_verify_wall_ms,s4_verify_cpu_ms,\
other_wall_ms,other_cpu_ms,total_wall_ms,total_cpu_ms"
    )
    .unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    std::panic::set_hook(Box::new(|_| {}));
    let sp1_verifier = SP1Verifier::new(VerifierRecursionVks::default());
    let (b, c) = (0x5A5u64, 13u64);
    let opts = SP1CoreOpts::default();
    let nonce = SP1Context::default().proof_nonce;
    let all_ops = opcodes();

    let mut n_cand = 0usize;
    let t_run = Instant::now();

    'jobs: for (kind, opname, ix) in &jobs {
        let Some(&(name, op)) = all_ops.iter().find(|(n, _)| n == opname) else {
            println!("LACUNA_CAL_SKIP,unknown opcode {opname}");
            continue;
        };
        if t_run.elapsed().as_secs() > budget_s {
            println!("LACUNA_CAL_BUDGET_EXCEEDED,skipping job {kind}:{opname}:{ix}");
            continue;
        }
        let is_mem = kind == "mem";
        let seed = format!("op_{}{}", name.to_lowercase(), if is_mem { "_mem" } else { "" });
        let program = Arc::new(if is_mem {
            build_op_mem_program(op, b, c)
        } else {
            build_op_program(op, b, c)
        });
        let verifier = ShardVerifier::from_basefold_parameters(
            core_fri_config(),
            lsh,
            mlrc,
            RiscvAir::machine(),
        );
        let shard_prover =
            CpuShardProver::<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, _>::new(
                verifier.clone(),
            );
        let prover = SimpleProver::new(verifier, shard_prover.clone());
        let (pk, vk) = rt.block_on(prover.setup(program.clone()));
        let pk = unsafe { pk.into_inner() };

        let (honest_records, _) =
            generate_records::<SP1Field>(program.clone(), SP1Stdin::new(), opts.clone(), nonce)
                .expect("honest record generation");

        if is_mem {
            let n_init: usize =
                honest_records.iter().map(|r| r.global_memory_initialize_events.len()).sum();
            println!("LACUNA_CAL_JOB,mem,{seed},idx={ix},n_init_events={n_init}");
            if *ix >= n_init {
                println!("LACUNA_CAL_SKIP,{seed} idx {ix} >= {n_init}");
                continue;
            }
            for (label, template, mk, arg) in menu(true) {
                if t_run.elapsed().as_secs() > budget_s {
                    println!("LACUNA_CAL_BUDGET_EXCEEDED,mid-job {seed} idx{ix}");
                    break 'jobs;
                }
                let out = run_pipeline_timed(
                    &rt,
                    &shard_prover,
                    &sp1_verifier,
                    &pk,
                    &vk,
                    || {
                        record_perturb::with(
                            record_perturb::F_MEM_INIT_VALUE,
                            *ix as i64,
                            mk,
                            arg,
                            || {
                                generate_records::<SP1Field>(
                                    program.clone(),
                                    SP1Stdin::new(),
                                    opts.clone(),
                                    nonce,
                                )
                                .map(|(r, _)| r)
                                .map_err(|e| format!("{e:?}"))
                            },
                        )
                    },
                    record_perturb::hits,
                );
                let key = format!("sp1|meminit|{seed}|idx{ix}|{label}");
                emit_cal(&mut f, &key, &seed, name, template, &out);
                n_cand += 1;
            }
        } else {
            let sites: Vec<(u64, usize)> = writeback_sites(&honest_records).into_iter().collect();
            println!("LACUNA_CAL_JOB,enc,{seed},site={ix},n_sites={}", sites.len());
            let Some(&(pc, _execs)) = sites.get(*ix) else {
                println!("LACUNA_CAL_SKIP,{seed} site {ix} out of range");
                continue;
            };
            for (label, template, mk, arg) in menu(true) {
                if t_run.elapsed().as_secs() > budget_s {
                    println!("LACUNA_CAL_BUDGET_EXCEEDED,mid-job {seed} site{ix}");
                    break 'jobs;
                }
                let out = run_pipeline_timed(
                    &rt,
                    &shard_prover,
                    &sp1_verifier,
                    &pk,
                    &vk,
                    || {
                        wb_perturb::with(pc, -1, mk, arg, || {
                            generate_records::<SP1Field>(
                                program.clone(),
                                SP1Stdin::new(),
                                opts.clone(),
                                nonce,
                            )
                            .map(|(r, _)| r)
                            .map_err(|e| format!("{e:?}"))
                        })
                    },
                    wb_perturb::hits,
                );
                let key = format!("sp1|encoding|{seed}|site{ix}@{pc:#x}|{label}");
                emit_cal(&mut f, &key, &seed, name, template, &out);
                n_cand += 1;
            }
        }
    }
    println!("LACUNA_CAL_DONE,candidates={n_cand},wall_s={}", t_run.elapsed().as_secs());
}

fn emit_cal(
    f: &mut std::fs::File,
    key: &str,
    seed: &str,
    opcode: &str,
    template: &str,
    o: &Timed,
) {
    let stage_wall: u128 = o.s1.wall_ms + o.s2.wall_ms + o.s3.wall_ms + o.s4.wall_ms;
    let stage_cpu: u64 = o.s1.cpu_ms + o.s2.cpu_ms + o.s3.cpu_ms + o.s4.cpu_ms;
    let other_wall = o.total_wall_ms.saturating_sub(stage_wall);
    let other_cpu = o.total_cpu_ms.saturating_sub(stage_cpu);
    let line = format!(
        "{key},{seed},{opcode},{template},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        o.outcome,
        o.failure_stage,
        o.s1.w(),
        o.s1.c(),
        o.s2.w(),
        o.s2.c(),
        o.s3.w(),
        o.s3.c(),
        o.s4.w(),
        o.s4.c(),
        other_wall,
        other_cpu,
        o.total_wall_ms,
        o.total_cpu_ms
    );
    writeln!(f, "{line}").unwrap();
    f.flush().ok();
    println!("LACUNA_CAL_ROW,{line} hits={}", o.hits);
}
