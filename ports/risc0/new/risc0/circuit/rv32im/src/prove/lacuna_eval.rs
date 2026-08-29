//! LACUNA EVALUATION DRIVER for risc0 — instrumented, candidate-level
//! enumeration of ENCODING mutations on the risc0 execution record.
//!
//! Contains no bug knowledge. It enumerates
//!
//!     site = (static pc, n-th execution of that pc)
//!     mu   = one entry of an instruction-independent rewriting menu
//!
//! over the single architectural register write-back choke point of the
//! preflight record generator
//! (`crate::prove::preflight::emu::Emulator::write_reg`, hooked by
//! `preflight::emu::wb_perturb::on_write_back`), and lets risc0's own preflight
//! emulator continue from the perturbed value so that every later register
//! read, dependent store, paged-out register page and therefore the committed
//! `rootOut` global follows naturally.
//!
//! Threat model. The *executor* runs honestly and produces the `Segment`. Only
//! the *prover*'s record generation is perturbed. The seal that comes out
//! commits, through the group-0 globals, to `rootOut` — the Merkle root of the
//! final memory image, which is exactly the segment claim's `post_state`. If
//! the real verifier accepts a seal whose `rootOut` differs from the honest
//! one, the constraint system did not bind that write-back.
//!
//! Every candidate runs in its own re-exec'd child process (`LACUNA_JOB`), so a
//! C++ abort inside the prover is an EXECFAIL row rather than a lost run.
//!
//! Environment:
//!   LACUNA_OUT   CSV path to write (parent)
//!   LACUNA_TAG   free-form run tag copied into every row
//!   LACUNA_OPS   comma-separated opcode names (default: all 18)
//!   LACUNA_MU    "one" (single mu) | "all" (default, 11-entry menu)
//!   LACUNA_SITES "op" (just the operation pc) | "all" (default, every static pc)
//!   LACUNA_JOBS  concurrent worker processes (default 8)
//!   LACUNA_JOB   set in a child: "<opname>|<pc>|<nth>|<mu_kind>|<mu_arg>"

use std::collections::BTreeMap;
use std::io::Write as _;
use std::time::Instant;

use anyhow::Result;
use risc0_binfmt::{MemoryImage, Program, WordAddr};

use crate::execute::{
    ExecutionLimit, Executor, RV32IM_M3_CIRCUIT_VERSION, SegmentUpdate, Syscall, SyscallContext,
    platform::*,
};
use crate::prove::preflight::emu::wb_perturb;
use crate::prove::{SegmentContext, segment_prover};

const REV: &str = "10fa97888d16cebf1b924c2079d9d18b939da6d3";
const TARGET: &str = "risc0";
const PO2: usize = 14;
/// Where the seed stores the result of the operation under test: the global
/// output word. `do_ecall_terminate` reads the eight words at `OUTPUT_WORD`
/// into `EcallTerminateWitness.output`, and the circuit binds them to the
/// verifier-visible `out[8]` globals
/// (`cxx/rv32im/circuit/ecall.ipp:91` GLOBAL_SET_U32, `:110` GLOBAL_CHECK_U32).
/// So a word stored here IS the segment's committed public output.
const OUT_ADDR: u32 = 0xffff_0240; // == platform::GLOBAL_OUTPUT_ADDR

// ---------------------------------------------------------------------------
// LACUNA CPU CALIBRATION -- purely additive measurement. Nothing below changes
// the pipeline: it only reads /proc/self/stat and std::time::Instant around
// stage boundaries that already existed.
//
// /proc/self/stat fields 14 (utime) and 15 (stime) are, for the thread-group
// leader, already summed over EVERY thread of the process (live threads plus
// the accumulated times of exited ones), which is what we want because the
// risc0 C++ prover fans out over std::threads via `parallel_map`
// (cxx/core/util.h:80).
//
// Ticks are USER_HZ; `getconf CLK_TCK` reports 100 on this host, i.e. 10 ms
// per tick. That is a HARD 10 ms quantum on every CPU number below.
// ---------------------------------------------------------------------------

const CLK_TCK_MS: u64 = 10; // 1 tick at CLK_TCK=100

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
    (ut + st) * CLK_TCK_MS
}

/// Per-stage wall/cpu slots. One candidate per worker process, so plain
/// statics are unambiguous. `NA` (== u64::MAX) means "this stage never ran".
mod cal {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub const NA: u64 = u64::MAX;
    macro_rules! slot {
        ($n:ident) => {
            pub static $n: AtomicU64 = AtomicU64::new(NA);
        };
    }
    slot!(STARTUP_C); // process CPU burned before run_candidate was entered
    slot!(EXEC_W);
    slot!(EXEC_C); // seed build + honest executor  (part of "other")
    slot!(REC_W);
    slot!(REC_C); // S1: armed preflight = mutation + suffix replay
    slot!(PNEW_W);
    slot!(PNEW_C); // prover context alloc          (part of "other")
    slot!(PROVE_W);
    slot!(PROVE_C); // S2+S3 merged: C++ witgen + FRI (+ C++ verify)
    slot!(VER_W);
    slot!(VER_C); // S4: independent Rust verifier
    slot!(REGION_W);
    slot!(REGION_C); // whole run_candidate body
    pub fn set(s: &AtomicU64, v: u64) {
        s.store(v, Ordering::Relaxed)
    }
    pub fn get(s: &AtomicU64) -> u64 {
        s.load(Ordering::Relaxed)
    }
}

/// One worker's calibration record, as the parent reassembles it.
#[derive(Clone, Copy)]
struct Cal {
    present: bool,
    startup_c: u64,
    exec_w: u64,
    exec_c: u64,
    rec_w: u64,
    rec_c: u64,
    pnew_w: u64,
    pnew_c: u64,
    prove_w: u64,
    prove_c: u64,
    ver_w: u64,
    ver_c: u64,
    region_w: u64,
    region_c: u64,
    /// full child lifetime as the PARENT saw it (fork+exec+startup+teardown)
    child_wall_ms: u64,
}

impl Default for Cal {
    fn default() -> Self {
        Cal {
            present: false,
            startup_c: cal::NA,
            exec_w: cal::NA,
            exec_c: cal::NA,
            rec_w: cal::NA,
            rec_c: cal::NA,
            pnew_w: cal::NA,
            pnew_c: cal::NA,
            prove_w: cal::NA,
            prove_c: cal::NA,
            ver_w: cal::NA,
            ver_c: cal::NA,
            region_w: cal::NA,
            region_c: cal::NA,
            child_wall_ms: cal::NA,
        }
    }
}

fn na(v: u64) -> String {
    if v == cal::NA {
        "NA".to_string()
    } else {
        v.to_string()
    }
}

// ---------------------------------------------------------------------------
// seed builder — programmatic, no guest toolchain
// ---------------------------------------------------------------------------

const OP_BASE: u32 = 0b0110011;
const OP_IMM: u32 = 0b0010011;
const OP_STORE: u32 = 0b0100011;
const OP_LUI: u32 = 0b0110111;
const OP_ENV: u32 = 0b1110011;

fn insn_r(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn insn_i(imm: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn insn_s(imm: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let hi = (imm >> 5) & 0x7f;
    let lo = imm & 0x1f;
    (hi << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (lo << 7) | opcode
}
fn insn_u(imm: u32, rd: u32, opcode: u32) -> u32 {
    (imm << 12) | (rd << 7) | opcode
}

#[derive(Default)]
struct Asm {
    text: Vec<u32>,
}

impl Asm {
    fn addi(&mut self, rd: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_i(imm & 0xfff, rs1 as u32, 0x0, rd as u32, OP_IMM));
    }
    fn lui(&mut self, rd: usize, imm: u32) {
        self.text.push(insn_u(imm, rd as u32, OP_LUI));
    }
    fn li(&mut self, rd: usize, imm: u32) {
        let low = ((imm as i32) << 20) >> 20;
        let high = (imm as i32 - low) >> 12;
        if high == 0 {
            self.addi(rd, REG_ZERO, low as u32);
        } else {
            self.lui(rd, high as u32);
            self.addi(rd, rd, low as u32);
        }
    }
    fn sw(&mut self, rs2: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_s(imm, rs2 as u32, rs1 as u32, 0x2, OP_STORE));
    }
    fn r(&mut self, funct7: u32, funct3: u32, rd: usize, rs1: usize, rs2: usize) {
        self.text.push(insn_r(
            funct7, rs2 as u32, rs1 as u32, funct3, rd as u32, OP_BASE,
        ));
    }
    fn ecall(&mut self) {
        self.text.push(insn_i(0x0, 0x0, 0x0, 0x0, OP_ENV));
    }
    fn program(&self) -> Program {
        let entry: WordAddr = USER_START_ADDR.waddr() + 1;
        let mut image = MemoryImage::default();
        for (offset, &instr) in self.text.iter().enumerate() {
            image.set_word(entry + offset, instr).unwrap();
        }
        Program::new_from_entry_and_image(entry.baddr().0, image)
    }
}

/// LACUNA seed — program structure: Single operation.
///
/// ```text
/// p0..p1: li   t0, a          ; x5 = a
/// p2..p3: li   t1, b          ; x6 = b
/// p4:     OP   t2, t0, t1     ; x7 = a OP b     <- the operation under test
/// p5..p6: li   t3, 0xffff0240 ; x28 = GLOBAL_OUTPUT_ADDR
/// p7:     sw   t2, 0(t3)      ; output[0] = x7  <- COMMITS the result
/// p8..:   host_terminate(0,0)
/// ```
/// The store at p7 is what makes the operation's result publicly observable:
/// `do_ecall_terminate` reads that word into the seal's `out[0]` global, so a
/// verifier that accepts the seal has accepted this value. Without it a
/// mutation could be accepted without changing anything a verifier is shown.
struct Seed {
    program: Program,
    /// static pc of every instruction in the seed's text
    pcs: Vec<u32>,
    /// static pc of the operation under test
    op_pc: u32,
}

fn build_seed(funct7: u32, funct3: u32, a: u32, b: u32) -> Seed {
    let mut asm = Asm::default();
    asm.li(REG_T0, a);
    asm.li(REG_T1, b);
    let op_idx = asm.text.len();
    asm.r(funct7, funct3, REG_T2, REG_T0, REG_T1);
    asm.li(REG_T3, OUT_ADDR);
    asm.sw(REG_T2, REG_T3, 0);
    // host_terminate(0, 0)
    asm.li(REG_A7, HOST_ECALL_TERMINATE);
    asm.li(REG_A0, 0);
    asm.li(REG_A1, 0);
    asm.ecall();

    let base = {
        let w: WordAddr = USER_START_ADDR.waddr() + 1;
        w.baddr().0
    };
    let pcs = (0..asm.text.len()).map(|i| base + 4 * i as u32).collect();
    Seed {
        program: asm.program(),
        pcs,
        op_pc: base + 4 * op_idx as u32,
    }
}

// (name, funct7, funct3)
fn opcodes() -> Vec<(&'static str, u32, u32)> {
    vec![
        ("ADD", 0x00, 0x0),
        ("SUB", 0x20, 0x0),
        ("SLL", 0x00, 0x1),
        ("SLT", 0x00, 0x2),
        ("SLTU", 0x00, 0x3),
        ("XOR", 0x00, 0x4),
        ("SRL", 0x00, 0x5),
        ("SRA", 0x20, 0x5),
        ("OR", 0x00, 0x6),
        ("AND", 0x00, 0x7),
        ("MUL", 0x01, 0x0),
        ("MULH", 0x01, 0x1),
        ("MULHSU", 0x01, 0x2),
        ("MULHU", 0x01, 0x3),
        ("DIV", 0x01, 0x4),
        ("DIVU", 0x01, 0x5),
        ("REM", 0x01, 0x6),
        ("REMU", 0x01, 0x7),
    ]
}

/// Operands. Chosen once so every opcode is exercised on the same pair.
const OP_A: u32 = 0x1234_5679;
const OP_B: u32 = 0x0000_00b7;

/// The instruction-independent rewriting menu. (label, template, mu_kind, mu_arg)
/// Mirrors the pico/nexus menus; word width is 32 bits, so the limb indices are
/// i in {0,1} for B = 2^16 and the boundary values are {0, 2^31, 2^32 - 1}.
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
    if all { full } else { vec![full[0]] }
}

// ---------------------------------------------------------------------------
// one candidate, in-process (a child runs exactly one of these)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct NullSyscall;

impl Syscall for NullSyscall {
    fn host_read(&self, _c: &mut impl SyscallContext, _fd: u32, _b: &mut [u8]) -> Result<u32> {
        unimplemented!()
    }
    fn host_write(&self, _c: &mut impl SyscallContext, _fd: u32, _b: &[u8]) -> Result<u32> {
        unimplemented!()
    }
}

struct Outcome {
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    hits: usize,
    site_execs: usize,
    /// `out[8]`, the seal's committed public output (empty if no seal)
    pv_hex: String,
    /// the committed final-image root (`rootOut`), taken from the record
    root_out_hex: String,
    t_record_ms: u128,
    t_prove_ms: u128,
    t_verify_ms: u128,
}

fn empty_outcome(o: &'static str, s: &'static str, reason: String) -> Outcome {
    Outcome {
        outcome: o,
        failure_stage: s,
        reason,
        hits: 0,
        site_execs: 0,
        pv_hex: String::new(),
        root_out_hex: String::new(),
        t_record_ms: 0,
        t_prove_ms: 0,
        t_verify_ms: 0,
    }
}

/// `rootOut` lives in the `GlobalsWitness` that the preflight puts at aux[0].
fn root_out_hex(aux: &[u32]) -> String {
    // GlobalsWitness = { FpDigest rootIn; FpDigest rootOut; u32 p2Count;
    //                    u32 finalCycle; u32 v2Compat; u32 povwNonce[8]; }
    let n = std::mem::size_of::<risc0_circuit_rv32im_sys::FpDigest>() / 4;
    aux[n..2 * n].iter().map(|w| format!("{w:08x}")).collect()
}

/// The verifier reads `global_count` = 54 field elements of group 0 off the
/// front of the seal (`risc0_zkp::verify::verify_v3`, risc0/zkp/src/verify/mod.rs:609,
/// with `global_count: 54` at risc0/circuit/rv32im/src/verify.rs:33); the seal
/// itself starts with version and po2 (`crate::verify::verify`).
///
/// Layout is `struct Globals` in cxx/rv32im/witness/witness.h:57 --
/// rootIn[8], rootOut[8], isTerminate, termA0.{low,high}, termA1.{low,high},
/// out[8].{low,high}, povwNonce[8].{low,high}, v2Compat  ==  54 elements.
const G_ROOT_OUT: usize = 8;
const G_OUT: usize = 21;

fn seal_globals(seal: &[u32]) -> &[u32] {
    &seal[2..2 + 54]
}

fn hexs(w: &[u32]) -> String {
    w.iter().map(|x| format!("{x:08x}")).collect()
}

/// Seal globals are BabyBear elements in Montgomery form; decode them and
/// recombine each `OutU32 { low, high }` pair into the 32-bit word it carries,
/// so `pv_hex` is the eight literal output words the verifier committed to.
fn out_words_hex(g: &[u32]) -> String {
    use risc0_zkp::field::baby_bear::BabyBearElem;
    let mut s = String::new();
    for i in 0..8 {
        let lo = BabyBearElem::new_raw(g[G_OUT + 2 * i]).as_u32();
        let hi = BabyBearElem::new_raw(g[G_OUT + 2 * i + 1]).as_u32();
        s.push_str(&format!("{:08x}", lo | (hi << 16)));
    }
    s
}

/// One candidate through the REAL pipeline: honest executor -> armed preflight
/// (perturbed record) -> real C++ prover -> real Rust verifier.
/// CPU-calibration wrapper: records the whole per-candidate region (wall and
/// process CPU) plus the process CPU already spent on startup, then defers to
/// the unchanged body. Exists so that the body's several early returns are all
/// covered by one pair of probes.
fn run_candidate(funct7: u32, funct3: u32, pc: u32, nth: i64, kind: usize, arg: i64) -> Outcome {
    let c0 = cpu_ms();
    cal::set(&cal::STARTUP_C, c0);
    let w0 = Instant::now();
    let o = run_candidate_inner(funct7, funct3, pc, nth, kind, arg);
    cal::set(&cal::REGION_W, w0.elapsed().as_millis() as u64);
    cal::set(&cal::REGION_C, cpu_ms().saturating_sub(c0));
    o
}

fn run_candidate_inner(
    funct7: u32,
    funct3: u32,
    pc: u32,
    nth: i64,
    kind: usize,
    arg: i64,
) -> Outcome {
    // The body below was lifted VERBATIM into `run_pipeline` so that the
    // structure axis (see "LACUNA STRUCTURE AXIS" at the end of this file) can
    // drive the same pipeline with a different program and a different syscall
    // handler. The seed is still built INSIDE the timed region, so the
    // calibration slots mean exactly what they meant before.
    run_pipeline(
        || build_seed(funct7, funct3, OP_A, OP_B).program,
        NullSyscall,
        pc,
        nth,
        kind,
        arg,
    )
}

/// The candidate pipeline: honest executor -> armed preflight (perturbed
/// record) -> real C++ prover -> real Rust verifier. `build` is called inside
/// the execution timing region.
fn run_pipeline<S: Syscall>(
    build: impl FnOnce() -> Program,
    syscall: S,
    pc: u32,
    nth: i64,
    kind: usize,
    arg: i64,
) -> Outcome {
    let w_exec = Instant::now();
    let c_exec = cpu_ms();
    let mut image = MemoryImage::new_kernel(build());

    // --- honest execution: the executor is NOT perturbed ---
    let mut segments = Vec::new();
    let limit = ExecutionLimit::default()
        .with_segment_po2(PO2)
        .with_hard_session_limit(1 << 20);
    let exec = Executor::new(
        image.clone(),
        syscall,
        None,
        Vec::new(),
        None,
        RV32IM_M3_CIRCUIT_VERSION,
    )
    .run(limit, |update: SegmentUpdate| {
        segments.push(update.apply_into_segment(&mut image)?);
        Ok(())
    });
    cal::set(&cal::EXEC_W, w_exec.elapsed().as_millis() as u64);
    cal::set(&cal::EXEC_C, cpu_ms().saturating_sub(c_exec));
    if let Err(e) = exec {
        return empty_outcome("EXECFAIL", "fork_exec", format!("execute: {e}"));
    }
    if segments.len() != 1 {
        return empty_outcome(
            "EXECFAIL",
            "fork_exec",
            format!("expected 1 segment, got {}", segments.len()),
        );
    }
    let segment = segments[0].clone();

    // --- record generation, armed ---
    let t0 = Instant::now();
    let c_rec = cpu_ms();
    let preflight = wb_perturb::with(pc, nth, kind, arg, || {
        SegmentContext::new(&segment).and_then(|c| c.preflight(PO2))
    });
    let t_record = t0.elapsed().as_millis();
    cal::set(&cal::REC_W, t_record as u64);
    cal::set(&cal::REC_C, cpu_ms().saturating_sub(c_rec));
    let hits = wb_perturb::hits();
    let site_execs = wb_perturb::site_execs();

    let preflight = match preflight {
        Ok(p) => p,
        Err(e) => {
            let mut o = empty_outcome("EXECFAIL", "mutation", format!("preflight: {e}"));
            o.hits = hits;
            o.site_execs = site_execs;
            o.t_record_ms = t_record;
            return o;
        }
    };
    let root_out = root_out_hex(&preflight.aux);

    // --- real prover ---
    let w_pnew = Instant::now();
    let c_pnew = cpu_ms();
    let prover_res = segment_prover(PO2);
    cal::set(&cal::PNEW_W, w_pnew.elapsed().as_millis() as u64);
    cal::set(&cal::PNEW_C, cpu_ms().saturating_sub(c_pnew));
    let prover = match prover_res {
        Ok(p) => p,
        Err(e) => {
            let mut o = empty_outcome("EXECFAIL", "prove", format!("prover_new: {e}"));
            o.hits = hits;
            o.site_execs = site_execs;
            o.root_out_hex = root_out;
            o.t_record_ms = t_record;
            return o;
        }
    };
    let t1 = Instant::now();
    let c_prove = cpu_ms();
    let prove_res = prover.prove_no_verify(&preflight);
    let t_prove = t1.elapsed().as_millis();
    cal::set(&cal::PROVE_W, t_prove as u64);
    cal::set(&cal::PROVE_C, cpu_ms().saturating_sub(c_prove));
    // The FFI runs the C++ verifier on the transcript it just wrote
    // (cxx/rv32im/ffi.cpp:284-306) and turns a failure into an `Err`, but the
    // transcript is stored first (ffi.cpp:293). Recover it either way, so that
    // EVERY fired candidate gets a real seal and a verdict from the
    // independent Rust verifier rather than a prover-side veto.
    let (seal, cxx_note) = match prove_res {
        Ok(s) => (s, String::new()),
        Err(e) => (
            prover.transcript_raw().unwrap_or_default(),
            format!(" [cxx-verify: {e}]"),
        ),
    };
    if seal.len() < 2 + 54 {
        let mut o = empty_outcome(
            "EXECFAIL",
            "prove",
            format!("no transcript produced{cxx_note}"),
        );
        o.hits = hits;
        o.site_execs = site_execs;
        o.root_out_hex = root_out;
        o.t_record_ms = t_record;
        o.t_prove_ms = t_prove;
        return o;
    }
    let g = seal_globals(&seal);
    let pv = out_words_hex(g);
    // The seal's rootOut must be exactly what the record claimed. Checked on
    // every candidate (not a debug_assert: this runs in release).
    assert_eq!(
        hexs(&g[G_ROOT_OUT..G_ROOT_OUT + 8]),
        root_out,
        "seal rootOut != record rootOut"
    );

    // --- real verifier ---
    let t2 = Instant::now();
    let c_ver = cpu_ms();
    let res = crate::verify(&seal);
    let t_verify = t2.elapsed().as_millis();
    cal::set(&cal::VER_W, t_verify as u64);
    cal::set(&cal::VER_C, cpu_ms().saturating_sub(c_ver));

    let (outcome, stage, reason) = match res {
        Ok(()) => ("ACCEPT", "accepted_proof", cxx_note.trim().to_string()),
        Err(e) => ("REJECT", "verify", format!("{e:?}{cxx_note}")),
    };
    Outcome {
        outcome,
        failure_stage: stage,
        reason,
        hits,
        site_execs,
        pv_hex: pv,
        root_out_hex: root_out,
        t_record_ms: t_record,
        t_prove_ms: t_prove,
        t_verify_ms: t_verify,
    }
}

fn trunc(s: &str) -> String {
    let s = s.replace(['\n', ',', '"'], " ");
    s.chars().take(160).collect()
}

// ---------------------------------------------------------------------------
// child entry point
// ---------------------------------------------------------------------------

/// A worker: `LACUNA_JOB = "<opname>|<pc>|<nth>|<mu_kind>|<mu_arg>"`.
/// Prints one `LACUNARESULT ...` line of `|`-separated fields to stdout.
#[test]
#[ignore = "internal worker; driven by lacuna_encoding_enumeration_risc0"]
fn lacuna_worker() {
    let job = std::env::var("LACUNA_JOB").expect("LACUNA_JOB not set");
    let f: Vec<&str> = job.split('|').collect();
    assert_eq!(f.len(), 5, "bad LACUNA_JOB");
    let (name, pc, nth, kind, arg) = (
        f[0],
        f[1].parse::<u32>().unwrap(),
        f[2].parse::<i64>().unwrap(),
        f[3].parse::<usize>().unwrap(),
        f[4].parse::<i64>().unwrap(),
    );
    let (_, funct7, funct3) = *opcodes().iter().find(|o| o.0 == name).unwrap();
    let o = run_candidate(funct7, funct3, pc, nth, kind, arg);
    println!(
        "LACUNARESULT {}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        o.outcome,
        o.failure_stage,
        o.hits,
        o.site_execs,
        o.root_out_hex,
        o.pv_hex,
        o.t_record_ms,
        o.t_prove_ms,
        o.t_verify_ms,
        trunc(&o.reason),
    );
    // CPU calibration, on its own line so the existing LACUNARESULT schema and
    // its field indices are untouched.
    println!(
        "LACUNACAL {}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        na(cal::get(&cal::STARTUP_C)),
        na(cal::get(&cal::EXEC_W)),
        na(cal::get(&cal::EXEC_C)),
        na(cal::get(&cal::REC_W)),
        na(cal::get(&cal::REC_C)),
        na(cal::get(&cal::PNEW_W)),
        na(cal::get(&cal::PNEW_C)),
        na(cal::get(&cal::PROVE_W)),
        na(cal::get(&cal::PROVE_C)),
        na(cal::get(&cal::VER_W)),
        na(cal::get(&cal::VER_C)),
        na(cal::get(&cal::REGION_W)),
        na(cal::get(&cal::REGION_C)),
    );
}

// ---------------------------------------------------------------------------
// parent driver
// ---------------------------------------------------------------------------

struct Row {
    seed_id: String,
    opcode: String,
    pc: u32,
    nth: i64,
    mu_label: String,
    template: String,
    kind: usize,
    arg: i64,
    o: Outcome,
    cal: Cal,
}

fn spawn_job(exe: &str, name: &str, pc: u32, nth: i64, kind: usize, arg: i64) -> (Outcome, Cal) {
    let w_child = Instant::now();
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "prove::lacuna_eval::lacuna_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("LACUNA_JOB", format!("{name}|{pc}|{nth}|{kind}|{arg}"))
        .env_remove("LACUNA_OUT")
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return (
                empty_outcome("EXECFAIL", "fork_exec", format!("spawn: {e}")),
                Cal::default(),
            );
        }
    };
    let child_wall_ms = w_child.elapsed().as_millis() as u64;
    let mut calrec = Cal {
        child_wall_ms,
        ..Cal::default()
    };
    if let Some(cl) = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with("LACUNACAL "))
        .map(|l| l["LACUNACAL ".len()..].to_string())
    {
        let g: Vec<&str> = cl.split('|').collect();
        let p = |i: usize| -> u64 {
            g.get(i)
                .and_then(|x| x.trim().parse::<u64>().ok())
                .unwrap_or(cal::NA)
        };
        if g.len() == 13 {
            calrec = Cal {
                present: true,
                startup_c: p(0),
                exec_w: p(1),
                exec_c: p(2),
                rec_w: p(3),
                rec_c: p(4),
                pnew_w: p(5),
                pnew_c: p(6),
                prove_w: p(7),
                prove_c: p(8),
                ver_w: p(9),
                ver_c: p(10),
                region_w: p(11),
                region_c: p(12),
                child_wall_ms,
            };
        }
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| l.starts_with("LACUNARESULT "));
    let Some(line) = line else {
        let tail: String = String::from_utf8_lossy(&out.stderr)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        return (
            empty_outcome(
                "EXECFAIL",
                "fork_exec",
                format!("worker died ({:?}): {}", out.status.code(), trunc(&tail)),
            ),
            calrec,
        );
    };
    let f: Vec<&str> = line["LACUNARESULT ".len()..].split('|').collect();
    let st = |s: &str| -> &'static str {
        match s {
            "ACCEPT" => "ACCEPT",
            "REJECT" => "REJECT",
            "NOOP" => "NOOP",
            _ => "EXECFAIL",
        }
    };
    let stage = |s: &str| -> &'static str {
        match s {
            "fork_exec" => "fork_exec",
            "prove" => "prove",
            "verify" => "verify",
            "mutation" => "mutation",
            "accepted_proof" => "accepted_proof",
            _ => "fork_exec",
        }
    };
    (
        Outcome {
            outcome: st(f[0]),
            failure_stage: stage(f[1]),
            hits: f[2].parse().unwrap_or(0),
            site_execs: f[3].parse().unwrap_or(0),
            root_out_hex: f[4].to_string(),
            pv_hex: f[5].to_string(),
            t_record_ms: f[6].parse().unwrap_or(0),
            t_prove_ms: f[7].parse().unwrap_or(0),
            t_verify_ms: f[8].parse().unwrap_or(0),
            reason: f.get(9).copied().unwrap_or("").to_string(),
        },
        calrec,
    )
}

/// Calibration CSV (written only when LACUNA_CPUCSV is set). Schema is fixed
/// by the evaluation spec.
const CAL_HEADER: &str = "candidate_key,seed_id,opcode,mutation_template,outcome,failure_stage,s1_replay_wall_ms,s1_replay_cpu_ms,s2_tracegen_wall_ms,s2_tracegen_cpu_ms,s3_prove_wall_ms,s3_prove_cpu_ms,s4_verify_wall_ms,s4_verify_cpu_ms,other_wall_ms,other_cpu_ms,total_wall_ms,total_cpu_ms";

/// S2 (trace/witness generation) is NOT separable from S3 on risc0: the C++
/// `Prover::prove` (cxx/prove/prove.cpp:92) interleaves `groups[i].witgen(...)`
/// with Fiat-Shamir draws and Merkle commits from the same IOP, so group 1's
/// witness generation consumes randomness derived from group 0's commitment.
/// The single `prove_no_verify` FFI call is therefore reported as "S2+S3
/// merged" in the s3_* columns and s2_* is written NA.
fn emit_cal(file: &mut Option<std::fs::File>, r: &Row) -> bool {
    let Some(f) = file else { return false };
    let outcome = if r.o.hits == 0 && r.o.outcome == "ACCEPT" {
        "NOOP"
    } else {
        r.o.outcome
    };
    let key = format!("risc0|{}|{:#x}|{}|{}", r.opcode, r.pc, r.nth, r.mu_label);
    let c = &r.cal;
    // Sub-stages that are folded into "other" in the fixed CSV schema, printed
    // so the run record can report them separately.
    println!(
        "CALROW {key} exec_w={} exec_c={} pnew_w={} pnew_c={} region_w={} region_c={} startup_c={} child_w={}",
        na(c.exec_w),
        na(c.exec_c),
        na(c.pnew_w),
        na(c.pnew_c),
        na(c.region_w),
        na(c.region_c),
        na(c.startup_c),
        na(c.child_wall_ms),
    );
    let mut clamped = false;
    let (other_w, other_c, total_w, total_c) = if c.present {
        let stage_w: u64 = [c.rec_w, c.prove_w, c.ver_w]
            .iter()
            .filter(|v| **v != cal::NA)
            .sum();
        let stage_c: u64 = [c.rec_c, c.prove_c, c.ver_c]
            .iter()
            .filter(|v| **v != cal::NA)
            .sum();
        let tw = c.child_wall_ms;
        let tc = if c.startup_c == cal::NA || c.region_c == cal::NA {
            cal::NA
        } else {
            c.startup_c + c.region_c
        };
        let ow = if tw == cal::NA {
            cal::NA
        } else {
            if tw < stage_w {
                clamped = true;
            }
            tw.saturating_sub(stage_w)
        };
        let oc = if tc == cal::NA {
            cal::NA
        } else {
            if tc < stage_c {
                clamped = true;
            }
            tc.saturating_sub(stage_c)
        };
        (ow, oc, tw, tc)
    } else {
        (cal::NA, cal::NA, c.child_wall_ms, cal::NA)
    };
    writeln!(
        f,
        "{key},{seed},{op},{tmpl},{outcome},{stage},{s1w},{s1c},NA,NA,{s3w},{s3c},{s4w},{s4c},{ow},{oc},{tw},{tc}",
        seed = r.seed_id,
        op = r.opcode,
        tmpl = r.template,
        stage = r.o.failure_stage,
        s1w = na(c.rec_w),
        s1c = na(c.rec_c),
        s3w = na(c.prove_w),
        s3c = na(c.prove_c),
        s4w = na(c.ver_w),
        s4c = na(c.ver_c),
        ow = na(other_w),
        oc = na(other_c),
        tw = na(total_w),
        tc = na(total_c),
    )
    .unwrap();
    f.flush().unwrap();
    clamped
}

const HEADER: &str = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed";

#[test]
#[ignore = "long-running: real prove+verify per candidate"]
fn lacuna_encoding_enumeration_risc0() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "risc0-enc".into());
    let out_path = std::env::var("LACUNA_OUT").ok();
    let all_mu = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".into()) != "one";
    let sites_all = std::env::var("LACUNA_SITES").unwrap_or_else(|_| "all".into()) == "all";
    let jobs: usize = std::env::var("LACUNA_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let only: Option<Vec<String>> = std::env::var("LACUNA_OPS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let exe = std::env::current_exe().unwrap().display().to_string();

    let mut file = out_path.as_ref().map(|p| {
        let mut f = std::fs::File::create(p).unwrap();
        writeln!(f, "{HEADER}").unwrap();
        f
    });
    let mut cal_file = std::env::var("LACUNA_CPUCSV").ok().map(|p| {
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "{CAL_HEADER}").unwrap();
        println!("cpu-calibration csv: {p}");
        f
    });
    let mut cal_clamped = 0usize;

    let ops: Vec<_> = opcodes()
        .into_iter()
        .filter(|(n, _, _)| only.as_ref().is_none_or(|v| v.iter().any(|x| x == n)))
        .collect();

    // ---- baselines ----
    let mut baselines: BTreeMap<String, Outcome> = BTreeMap::new();
    for (name, _, _) in &ops {
        // pc = u32::MAX never matches a real pc => an unarmed, honest run.
        let (o, bcal) = spawn_job(&exe, name, u32::MAX, -1, wb_perturb::MU_XORBIT, 0);
        // Baselines are unarmed runs, not mutation candidates, so they are not
        // rows of the calibration CSV -- but they DO burn process CPU, so print
        // their cost to close the /usr/bin/time -v accounting.
        println!(
            "CALBASE {name} startup_c={} region_c={} child_w={}",
            na(bcal.startup_c),
            na(bcal.region_c),
            na(bcal.child_wall_ms),
        );
        println!(
            "[baseline] {name}: {} {} pv={} rootOut={} ({} ms prove, {} ms verify) {}",
            o.outcome,
            o.failure_stage,
            o.pv_hex,
            o.root_out_hex,
            o.t_prove_ms,
            o.t_verify_ms,
            o.reason
        );
        baselines.insert(name.to_string(), o);
    }
    let verified: Vec<&(&str, u32, u32)> = ops
        .iter()
        .filter(|(n, _, _)| baselines[*n].outcome == "ACCEPT")
        .collect();
    println!(
        "baselines: {} attempted, {} verified",
        ops.len(),
        verified.len()
    );

    // ---- candidate enumeration ----
    let mus = menu(all_mu);
    let mut jobs_list: Vec<(String, u32, i64, usize, i64, String, String)> = Vec::new();
    for (name, funct7, funct3) in &verified {
        let seed = build_seed(*funct7, *funct3, OP_A, OP_B);
        let sites: Vec<u32> = if sites_all {
            seed.pcs.clone()
        } else {
            vec![seed.op_pc]
        };
        for pc in sites {
            for (label, tmpl, kind, arg) in &mus {
                jobs_list.push((
                    name.to_string(),
                    pc,
                    -1,
                    *kind,
                    *arg,
                    label.to_string(),
                    tmpl.to_string(),
                ));
            }
        }
    }
    println!("candidates: {}", jobs_list.len());

    let mut rows: Vec<Row> = Vec::new();
    let mut done = 0usize;
    for chunk in jobs_list.chunks(jobs) {
        let mut handles = Vec::new();
        for (name, pc, nth, kind, arg, label, tmpl) in chunk.iter().cloned() {
            let exe = exe.clone();
            handles.push(std::thread::spawn(move || {
                let (o, cal) = spawn_job(&exe, &name, pc, nth, kind, arg);
                Row {
                    seed_id: format!("{name}_single_op"),
                    opcode: name,
                    pc,
                    nth,
                    mu_label: label,
                    template: tmpl,
                    kind,
                    arg,
                    o,
                    cal,
                }
            }));
        }
        for h in handles {
            let row = h.join().unwrap();
            done += 1;
            let b = &baselines[&row.opcode];
            emit(&mut file, &tag, &row, b);
            if emit_cal(&mut cal_file, &row) {
                cal_clamped += 1;
            }
            if done % 25 == 0 {
                println!("... {done}/{}", jobs_list.len());
            }
            rows.push(row);
        }
    }

    // ---- summary ----
    let acc = rows.iter().filter(|r| r.o.outcome == "ACCEPT").count();
    let accepted_cases = rows
        .iter()
        .filter(|r| {
            let b = &baselines[&r.opcode];
            is_accepted_case(r, b)
        })
        .count();
    println!(
        "RESULT candidates={} accepts={} accepted_cases={}",
        rows.len(),
        acc,
        accepted_cases
    );
    if cal_file.is_some() {
        let tot: u64 = rows
            .iter()
            .filter(|r| r.cal.present && r.cal.startup_c != cal::NA && r.cal.region_c != cal::NA)
            .map(|r| r.cal.startup_c + r.cal.region_c)
            .sum();
        println!("CALSUM total_cpu_ms={tot} rows_clamped={cal_clamped}");
    }
    for r in rows
        .iter()
        .filter(|r| is_accepted_case(r, &baselines[&r.opcode]))
    {
        println!(
            "ACCEPTED CASE: {} pc={:#x} mu={} out {} -> {}",
            r.opcode, r.pc, r.mu_label, baselines[&r.opcode].pv_hex, r.o.pv_hex
        );
    }
}

/// ACCEPTED CASE == the real verifier accepted AND the mutation actually fired
/// AND the committed PUBLIC output differs from the honest one and is
/// non-empty. Nothing weaker counts.
fn is_accepted_case(r: &Row, b: &Outcome) -> bool {
    r.o.outcome == "ACCEPT"
        && r.o.hits > 0
        && !r.o.pv_hex.is_empty()
        && r.o.pv_hex.chars().any(|c| c != '0')
        && !b.pv_hex.is_empty()
        && r.o.pv_hex != b.pv_hex
}

fn emit(file: &mut Option<std::fs::File>, tag: &str, r: &Row, b: &Outcome) {
    let changed = !r.o.pv_hex.is_empty() && !b.pv_hex.is_empty() && r.o.pv_hex != b.pv_hex;
    let dchanged = !r.o.root_out_hex.is_empty()
        && !b.root_out_hex.is_empty()
        && r.o.root_out_hex != b.root_out_hex;
    let outcome = if r.o.hits == 0 && r.o.outcome == "ACCEPT" {
        "NOOP"
    } else {
        r.o.outcome
    };
    let line = format!(
        "{tag},{TARGET},{REV},{seed},encoding,single_op,{op},{pc:#x},{nth},NA,NA,{se},{mu},{tmpl},{kind},{arg},{outcome},{stage},{hits},{pv},{hpv},{ch},{ac},{tr},{tp},{tv},{reason},{cd},{hcd},{dch}",
        seed = r.seed_id,
        op = r.opcode,
        pc = r.pc,
        nth = r.nth,
        se = r.o.site_execs,
        mu = r.mu_label,
        tmpl = r.template,
        kind = r.kind,
        arg = r.arg,
        stage = r.o.failure_stage,
        hits = r.o.hits,
        pv = if r.o.pv_hex.is_empty() {
            "NA".into()
        } else {
            r.o.pv_hex.clone()
        },
        hpv = if b.pv_hex.is_empty() {
            "NA".into()
        } else {
            b.pv_hex.clone()
        },
        ch = changed,
        ac = is_accepted_case(r, b),
        tr = r.o.t_record_ms,
        tp = r.o.t_prove_ms,
        tv = r.o.t_verify_ms,
        reason = trunc(&r.o.reason),
        cd = if r.o.root_out_hex.is_empty() {
            "NA".into()
        } else {
            r.o.root_out_hex.clone()
        },
        hcd = if b.root_out_hex.is_empty() {
            "NA".into()
        } else {
            b.root_out_hex.clone()
        },
        dch = dchanged,
    );
    if let Some(f) = file {
        writeln!(f, "{line}").unwrap();
        f.flush().unwrap();
    }
}

/// Smoke test: one honest seed, real preflight + real prove + real verify.
#[test]
#[ignore = "runs a real proof"]
fn lacuna_smoke() {
    let t = Instant::now();
    let o = run_candidate(0x00, 0x0, u32::MAX, -1, wb_perturb::MU_XORBIT, 0);
    println!(
        "smoke ADD: {} {} hits={} pv={} rootOut={} record={}ms prove={}ms verify={}ms {}",
        o.outcome,
        o.failure_stage,
        o.hits,
        o.pv_hex,
        o.root_out_hex,
        o.t_record_ms,
        o.t_prove_ms,
        o.t_verify_ms,
        o.reason
    );
    println!("total {} ms", t.elapsed().as_millis());
    assert_eq!(o.outcome, "ACCEPT", "{}", o.reason);
}

// ===========================================================================
// LACUNA STRUCTURE AXIS
//
// PURELY ADDITIVE. Everything above this line is the published enumeration and
// runs byte-identically: the mutation menu, the acceptance predicate
// (`is_accepted_case`), `build_seed`, the `*_single_op` seed ids and the
// `lacuna_encoding_enumeration_risc0` driver are untouched. This section adds
// a second, independent driver (`lacuna_structure_enumeration_risc0`) over a
// table of PROGRAM STRUCTURES taken from
//
//     evaluation/spec/STRUCTURE_MANIFEST.yaml      (structures, per-target
//                                                   status, candidate_class,
//                                                   scored_against, variants,
//                                                   mu role masks, R1-R8)
//     evaluation/spec/TARGET_CAPABILITIES.yaml     (risc0's nine hook flags,
//                                                   dual public-output record)
//
// The single mutation choke point is unchanged: `Emulator::write_reg`, hooked
// by `preflight::emu::wb_perturb`. A structure is therefore never a new
// operator -- it is a PROGRAM SHAPE that puts a different constraint surface
// downstream of that one hook.
//
// WHY risc0 IS DIFFERENT FROM THE OTHER SIX PORTS. risc0 commits BOTH
//   * out[8]  -- eight public output words lifted out of GLOBAL_OUTPUT_ADDR by
//                `do_ecall_terminate` and bound by GLOBAL_SET_U32 /
//                GLOBAL_CHECK_U32 (cxx/rv32im/circuit/ecall.ipp:91,110), and
//   * rootOut -- the Merkle root of the FINAL memory image
//                (prove/preflight/paging.rs:189), which contains the register
//                file,
// so a write-back that never reaches out[8] can still change the committed
// state object. That is why `st_dead_write` and `st_finalize_only` are PROBES
// on risc0 and controls elsewhere, and why every row here carries
// `scored_against` and `accepted_case_v2` alongside the frozen
// `accepted_case`.
//
// Environment (parallel to the frozen driver's, all optional):
//   LACUNA_OUT       CSV path (parent)
//   LACUNA_TAG       run tag; `unbound_probe=substituted` is appended
//                    automatically (run-matrix rule R3: risc0 has no
//                    ESTABLISHED unbound opcode, so R2 is satisfied by proxy)
//   LACUNA_STRUCTS   comma-separated structure ids (default: all in the table)
//   LACUNA_OPS       comma-separated opcode names (default: each structure's
//                    own axis)
//   LACUNA_MU        "one" | "all" (default)
//   LACUNA_JOBS      concurrent worker processes (default 8)
//   LACUNA_SITE_STRIDE  sample every k-th site of a seed (default 1)
//   LACUNA_SJOB      set in a child:
//                    "<id>|<variant>|<opname>|<pc>|<nth>|<mu_kind>|<mu_arg>"
// ===========================================================================

/// Scratch data addresses used by the structure seeds. All are word-aligned,
/// inside user memory (>= USER_START_ADDR) and far from the text at
/// USER_START_ADDR+4, so that the address-role mu mask (+/-2^16, ^2^15) always
/// lands on an address the pager can materialise.
const SCRATCH: u32 = 0x0020_0000;
/// The second live slot, EXACTLY +2^16 from `SCRATCH`, so the `plus_B1` menu
/// entry redirects a pointer from one slot to the other exactly. The manifest's
/// `address` role mask allows only alignment-preserving entries on a pointer,
/// so the two live addresses of `st_redirect` have to be one such step apart or
/// the structure is unreachable from the frozen menu.
const SCRATCH2: u32 = SCRATCH + 0x0001_0000;
/// Holds a POINTER (st_pointer_indirect).
const PPSLOT: u32 = 0x0028_0000;
/// Written and never read again (st_finalize_only / st_dead_write).
const SINK: u32 = 0x0030_0000;
/// Landing buffer for the host READ ecall (st_hint_advice).
const HBUF: u32 = 0x0038_0000;
/// Set NON-ZERO in the committed MemoryImage (st_initial_image).
const IMGWORD: u32 = 0x0040_0000;
/// Never written and never in the image (st_initial_state).
const UNWRITTEN: u32 = 0x0048_0000;
/// Poseidon2 input / output buffers (st_precompile).
const P2_IN: u32 = 0x0050_0000;
const P2_OUT: u32 = 0x0050_0100;
/// The word the driver's host-read channel returns (st_hint_advice).
const HINT_WORD: u32 = 0xa5a5_1234;
/// A constant the seed commits when the structure requires the DATA output to
/// be independent of the mutation (st_finalize_only, st_control_flow/dataident).
const CONST_OUT: u32 = 0x00c0_ffee;

const OP_LOAD: u32 = 0b0000011;
const OP_BRANCH: u32 = 0b1100011;
const OP_JAL: u32 = 0b1101111;
const OP_JALR: u32 = 0b1100111;
const OP_AUIPC: u32 = 0b0010111;

const F3_BEQ: u32 = 0x0;
const F3_BNE: u32 = 0x1;
const F3_BLT: u32 = 0x4;
const F3_BLTU: u32 = 0x6;

const F3_BYTE: u32 = 0x0;
const F3_HALF: u32 = 0x1;
const F3_WORD: u32 = 0x2;
const F3_BYTEU: u32 = 0x4;
const F3_HALFU: u32 = 0x5;

// 31        25 | 24  20 | 19  15 | 14  12 | 11        7 | 6    0 |
// imm[12|10:5] |   rs2  |   rs1  | funct3 | imm[4:1|11] | opcode |
fn insn_b(imm: u32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let imm_12 = (imm >> 12) & 0b1;
    let imm_10_5 = (imm >> 5) & 0b11_1111;
    let imm_11 = (imm >> 11) & 0b1;
    let imm_4_1 = (imm >> 1) & 0b1111;
    (((imm_12 << 6) | imm_10_5) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm_4_1 << 1) | imm_11) << 7)
        | opcode
}

// 31 | 30      21 | 20 | 19        12 | 11   7 | 6    0 |
// i20 |  i[10:1]  | i11|   i[19:12]   |   rd   | opcode |
fn insn_j(imm: u32, rd: u32, opcode: u32) -> u32 {
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | (rd << 7)
        | opcode
}

/// The encodings the frozen `Asm` does not have. Kept in a SECOND `impl` block
/// so the original one stays byte-identical.
impl Asm {
    /// `li` with a FIXED two-instruction (LUI+ADDI) expansion. The frozen `li`
    /// collapses to a single ADDI for small constants, which makes a seed's
    /// static layout depend on its operands; every structure builder here needs
    /// a layout it can compute, and the ADDI is a clean single write-back site.
    fn li32(&mut self, rd: usize, imm: u32) {
        let low = ((imm as i32) << 20) >> 20;
        let high = (imm as i32).wrapping_sub(low) >> 12;
        self.lui(rd, high as u32);
        self.addi(rd, rd, low as u32);
    }
    fn addi_(&mut self, rd: usize, rs1: usize, imm: i32) {
        self.text
            .push(insn_i(imm as u32 & 0xfff, rs1 as u32, 0x0, rd as u32, OP_IMM));
    }
    fn andi(&mut self, rd: usize, rs1: usize, imm: i32) {
        self.text
            .push(insn_i(imm as u32 & 0xfff, rs1 as u32, 0x7, rd as u32, OP_IMM));
    }
    fn nop(&mut self) {
        self.addi_(REG_ZERO, REG_ZERO, 0);
    }
    fn load(&mut self, funct3: u32, rd: usize, rs1: usize, imm: i32) {
        self.text.push(insn_i(
            imm as u32 & 0xfff,
            rs1 as u32,
            funct3,
            rd as u32,
            OP_LOAD,
        ));
    }
    fn store(&mut self, funct3: u32, rs2: usize, rs1: usize, imm: u32) {
        self.text
            .push(insn_s(imm, rs2 as u32, rs1 as u32, funct3, OP_STORE));
    }
    fn auipc(&mut self, rd: usize, imm20: u32) {
        self.text.push(insn_u(imm20, rd as u32, OP_AUIPC));
    }
    fn jalr(&mut self, rd: usize, rs1: usize, imm: i32) {
        self.text.push(insn_i(
            imm as u32 & 0xfff,
            rs1 as u32,
            0x0,
            rd as u32,
            OP_JALR,
        ));
    }
    /// Finalise into a `Program`, additionally seeding the committed
    /// MemoryImage with `data` (byte address, word). Used by st_initial_image
    /// (a non-zero .data word) and st_indirect_jump (the far jump-table arm).
    fn program_with(&self, data: &[(u32, u32)]) -> Program {
        let entry: WordAddr = USER_START_ADDR.waddr() + 1;
        let mut image = MemoryImage::default();
        for (offset, &instr) in self.text.iter().enumerate() {
            image.set_word(entry + offset, instr).unwrap();
        }
        for &(addr, word) in data {
            image
                .set_word(risc0_binfmt::ByteAddr(addr).waddr_aligned().unwrap(), word)
                .unwrap();
        }
        Program::new_from_entry_and_image(entry.baddr().0, image)
    }
}

/// Byte address of the first instruction of any seed.
fn text_base() -> u32 {
    let w: WordAddr = USER_START_ADDR.waddr() + 1;
    w.baddr().0
}

/// `site_role` (STRUCTURE_MANIFEST.yaml enumerations.site_role). It selects the
/// mu mask, because the instruction-independent menu is mostly self-destructive
/// on anything that is not a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Value,
    /// A pointer. Masked to the alignment-preserving entries.
    Address,
    /// A value one mu-step from a constraint discontinuity (a divisor, a shift
    /// amount, a branch condition).
    Selector,
    /// The JALR target register of st_indirect_jump's `bit0` variant: the ONE
    /// place the manifest allows `xor_b0` on an address, because clearing bit 0
    /// is exactly the RISC-V requirement the variant exists to test.
    AddressBit0,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Value => "value",
            Role::Address | Role::AddressBit0 => "address",
            Role::Selector => "selector",
        }
    }
}

/// STRUCTURE_MANIFEST.yaml mu_menu.role_masks, applied verbatim.
///
/// NOTE ON `syscall_arg`. No site below is ever tagged syscall_arg: the mask
/// forbids the role outright on every target, and the a7/a0/a1 write-backs of
/// the terminate sequence are therefore not enumerated at all. risc0 does in
/// fact satisfy the manifest's opt-in precondition already -- a forged a7 makes
/// `do_inst_ecall` return `bail!("Invalid ECALL in machine mode")`, i.e. an
/// ordinary EXECFAIL row rather than a process abort -- but the opt-in has to
/// be recorded in the manifest before candidates are emitted, so it is not
/// taken here. That is what blocks st_pv_plumbing's `index` and `exitcode`
/// variants on this port.
fn mu_allowed(role: Role, label: &str) -> bool {
    match role {
        Role::Value | Role::Selector => true,
        Role::Address => matches!(label, "plus_B1" | "minus_B1" | "xor_b15"),
        Role::AddressBit0 => matches!(label, "plus_B1" | "minus_B1" | "xor_b15" | "xor_b0"),
    }
}

/// A structure seed: the program plus the write-back sites the structure is
/// ABOUT, each tagged with the role that selects its mu mask. Separate from
/// `Seed` so the frozen single-operation path is untouched.
struct SSeed {
    program: Program,
    sites: Vec<(u32, Role)>,
    /// static instruction count of the seed's text (documentation only)
    insns: usize,
}

/// Forward branch / jump awaiting its target.
struct Fixup {
    idx: usize,
    kind: FixKind,
}

enum FixKind {
    B { funct3: u32, rs1: u32, rs2: u32 },
    J { rd: u32 },
}

/// Small builder around `Asm` that records write-back sites and patches forward
/// branches, so a builder never has to count instruction slots by hand.
struct SB {
    asm: Asm,
    sites: Vec<(u32, Role)>,
    data: Vec<(u32, u32)>,
}

impl SB {
    fn new() -> Self {
        SB {
            asm: Asm::default(),
            sites: Vec::new(),
            data: Vec::new(),
        }
    }
    /// Byte pc of the instruction just emitted.
    fn last_pc(&self) -> u32 {
        text_base() + 4 * (self.asm.text.len() as u32 - 1)
    }
    /// Byte pc of the next instruction to be emitted.
    fn here(&self) -> u32 {
        text_base() + 4 * self.asm.text.len() as u32
    }
    /// Declare the instruction just emitted to be a mutation site.
    fn site(&mut self, role: Role) {
        let pc = self.last_pc();
        self.sites.push((pc, role));
    }
    /// `li32` whose ADDI (the write-back that carries the final value) is a site.
    fn li_site(&mut self, rd: usize, imm: u32, role: Role) {
        self.asm.li32(rd, imm);
        self.site(role);
    }
    fn b_fwd(&mut self, funct3: u32, rs1: usize, rs2: usize) -> Fixup {
        let idx = self.asm.text.len();
        self.asm.text.push(insn_b(0, rs2 as u32, rs1 as u32, funct3, OP_BRANCH));
        Fixup {
            idx,
            kind: FixKind::B {
                funct3,
                rs1: rs1 as u32,
                rs2: rs2 as u32,
            },
        }
    }
    fn j_fwd(&mut self, rd: usize) -> Fixup {
        let idx = self.asm.text.len();
        self.asm.text.push(insn_j(0, rd as u32, OP_JAL));
        Fixup {
            idx,
            kind: FixKind::J { rd: rd as u32 },
        }
    }
    /// Point a previously emitted forward branch/jump at the current end of text.
    fn bind(&mut self, f: Fixup) {
        let off = ((self.asm.text.len() - f.idx) * 4) as u32;
        self.asm.text[f.idx] = match f.kind {
            FixKind::B { funct3, rs1, rs2 } => insn_b(off, rs2, rs1, funct3, OP_BRANCH),
            FixKind::J { rd } => insn_j(off, rd, OP_JAL),
        };
    }
    /// Backward branch to text index `target`.
    fn b_back(&mut self, funct3: u32, rs1: usize, rs2: usize, target: usize) {
        let off = (target as i64 - self.asm.text.len() as i64) * 4;
        self.asm
            .text
            .push(insn_b(off as u32, rs2 as u32, rs1 as u32, funct3, OP_BRANCH));
    }
    /// Store `rs` into out[0]. The address register is driver plumbing, not a
    /// structure site, so it is deliberately NOT enumerated.
    fn commit(&mut self, rs: usize) {
        self.asm.li32(REG_S11, OUT_ADDR);
        self.asm.sw(rs, REG_S11, 0);
    }
    fn terminate(&mut self) {
        self.asm.li32(REG_A7, HOST_ECALL_TERMINATE);
        self.asm.li32(REG_A0, 0);
        self.asm.li32(REG_A1, 0);
        self.asm.ecall();
    }
    fn seed(self) -> SSeed {
        SSeed {
            insns: self.asm.text.len(),
            program: self.asm.program_with(&self.data),
            sites: self.sites,
        }
    }
}

// ---------------------------------------------------------------------------
// structure builders
//
// Every builder emits a self-contained machine-mode program that ends in
// `host_terminate(0,0)`, and declares the write-back sites the structure is
// about. Read each doc comment as: WHAT the shape is, WHICH constraint surface
// it puts downstream of the hook, and HOW a forged write-back reaches a
// committed object (out[8], or rootOut where the structure says so).
// ---------------------------------------------------------------------------

/// Arguments a structure builder receives from its table row.
struct SArgs {
    funct7: u32,
    funct3: u32,
    a: u32,
    b: u32,
    variant: &'static str,
    /// shape parameter: a branch/load funct3, a packed consumer opcode, a loop
    /// trip count -- whatever the row needs.
    aux: u32,
}

/// st_boundary_operand -- operands parked one mu-step from a constraint
/// discontinuity (divide-by-zero, shift amount == XLEN, INT_MIN/-1, a limb
/// edge), so the mutation drives an AIR-derived SELECTOR rather than a value.
/// Surface: the gating/guard columns of the DIV/REM and shift blocks, which are
/// derived from the operand rather than checked against it.
/// Path: `sw t2` puts the result in GLOBAL_OUTPUT_ADDR, which
/// `do_ecall_terminate` lifts into out[8].
/// operand_source = immediate (risc0 has no non-hint input channel).
fn build_st_boundary_operand(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Selector);
    b.li_site(REG_T1, g.b, Role::Selector);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_subword_lane -- wide store then narrow load (`load`), or narrow store
/// into a wide word then a wide read-back (`store`).
/// Surface: risc0's `signBit` / `pickByte` lane selection and the store-side
/// merge of the untouched sibling lanes; the load's rd write-back is an
/// ordinary write-back, so no new hook is needed.
/// Path: the lane (or the merged word) is committed with `sw` to
/// GLOBAL_OUTPUT_ADDR -> out[8].
fn build_st_subword_lane(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value);
    b.asm.li32(REG_T3, SCRATCH);
    b.asm.sw(REG_T0, REG_T3, 0);
    if g.variant == "load" {
        // aux = the narrow load funct3; offset 3 selects the top byte / offset 2
        // the top halfword, i.e. the lane a merged-word constraint is least
        // likely to bind.
        let off = if g.aux == F3_BYTE || g.aux == F3_BYTEU {
            3
        } else {
            2
        };
        b.asm.load(g.aux, REG_T2, REG_T3, off);
        b.site(Role::Value);
    } else {
        // store side: put a narrow lane into the middle of the wide word and
        // read the whole word back.
        b.li_site(REG_T1, g.b, Role::Value);
        let off = if g.aux == F3_BYTE { 1 } else { 2 };
        b.asm.store(g.aux, REG_T1, REG_T3, off);
        b.asm.load(F3_WORD, REG_T2, REG_T3, 0);
        b.site(Role::Value);
    }
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_store_load -- two stores to ONE address then a load: TIME disambiguation.
/// Surface: `readMem.data`, `writeMem.prevData` and `readMem.prevCycle`, i.e.
/// the memory argument's ordering, not its addressing.
/// Path: the loaded word is committed -> out[8]. The `tail` variant adds a
/// trailing store so the load is not the last touch of the address and cannot
/// be healed by the finalize boundary.
fn build_st_store_load(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value);
    b.li_site(REG_T1, g.b, Role::Value);
    b.asm.li32(REG_T3, SCRATCH);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
    b.site(Role::Value);
    b.asm.sw(REG_T2, REG_T3, 0); // store 1
    b.asm.r(g.funct7, g.funct3, REG_T4, REG_T1, REG_T0);
    b.site(Role::Value);
    b.asm.sw(REG_T4, REG_T3, 0); // store 2, same address
    b.asm.load(F3_WORD, REG_T5, REG_T3, 0);
    b.site(Role::Value);
    if g.variant == "tail" {
        b.asm.sw(REG_T0, REG_T3, 0);
    }
    b.commit(REG_T5);
    b.terminate();
    b.seed()
}

/// st_redirect -- two live addresses one legal pointer-step apart, and the
/// mutation site is the instruction that MATERIALISES the load pointer: SPACE
/// disambiguation, as opposed to st_store_load's TIME disambiguation.
/// Surface: the address decomposition of the load (risc0 recomputes the address
/// from rs1+imm, so this is a predicted clean negative on this target and the
/// interesting result is whether it is).
/// Path: the pointer is formed AFTER both stores, so a forged pointer changes
/// only what the load returns; that word is committed -> out[8].
/// SCRATCH2 == SCRATCH + 2^16 so `plus_B1` redirects exactly.
fn build_st_redirect(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value);
    b.li_site(REG_T1, g.b, Role::Value);
    b.asm.li32(REG_T3, SCRATCH);
    b.asm.li32(REG_T4, SCRATCH2);
    b.asm.sw(REG_T0, REG_T3, 0); // p1 <- a
    b.asm.sw(REG_T0, REG_T3, 0); // p1 <- a again: arms a stale-load operator
    b.asm.sw(REG_T1, REG_T4, 0); // p2 <- b
    b.li_site(REG_T5, SCRATCH, Role::Address); // <-- THE SITE
    b.asm.load(F3_WORD, REG_T2, REG_T5, 0);
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_pointer_indirect -- the forged word IS a pointer that an honest later
/// load dereferences, so a one-word forgery becomes a whole-object
/// substitution. This is the taint/composition surface: a value forge escalates
/// into address control.
/// Surface: nothing new in the AIR -- the point is that the SECOND load is
/// entirely honest, so whatever binds the first load's delivered value is the
/// only thing standing between a free column and an arbitrary read.
/// Path: the dereferenced word is committed -> out[8].
fn build_st_pointer_indirect(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value);
    b.li_site(REG_T1, g.b, Role::Value);
    b.asm.li32(REG_T3, SCRATCH); // object A
    b.asm.li32(REG_T4, SCRATCH2); // object B, exactly +2^16
    b.asm.sw(REG_T0, REG_T3, 0);
    b.asm.sw(REG_T1, REG_T4, 0);
    b.asm.li32(REG_T5, PPSLOT);
    b.asm.sw(REG_T3, REG_T5, 0); // pp <- &A
    b.asm.sw(REG_T3, REG_T5, 0); // pp <- &A again: arms the stale-load arm
    b.asm.load(F3_WORD, REG_T6, REG_T5, 0); // p = load(pp)   <-- THE SITE
    b.site(Role::Address);
    b.asm.load(F3_WORD, REG_T2, REG_T6, 0); // honest dereference
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_initial_state -- commit a word read from an address the program never
/// wrote and the image never contained; the only structure whose forged value
/// has no producing instruction.
/// Surface: the page-in / rootIn Poseidon2 argument. HONEST LIMIT: risc0's
/// `Memory::page_in` (prove/preflight/paging.rs:97-119) is NOT hooked by this
/// port, so `PageInPartWitness.data[i]` -- the genuine initial-value record
/// field -- is not itself perturbed. What is perturbed is the DELIVERED value
/// of the load that reads the never-written address, exactly as in every other
/// structure here. `init_value_hookable` stays false in TARGET_CAPABILITIES.
/// Path: the loaded word is committed -> out[8]. Honest output is zero.
fn build_st_initial_state(_g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T3, UNWRITTEN);
    b.asm.load(F3_WORD, REG_T2, REG_T3, 0);
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_initial_image -- the paired NEGATIVE CONTROL for st_initial_state: the
/// address read here is initialised NON-ZERO by the committed MemoryImage, so
/// its value is fixed by the image id the verifier checks and the expected
/// verdict is REJECT. An ACCEPT is not a control failure; it means the prover
/// can claim an initial value the image does not commit, and must be re-graded
/// as a probe-grade finding.
/// `data` reads the initialised word itself. `bssboundary` reads the word
/// IMMEDIATELY AFTER it -- same 1 KiB page, zero-filled by the image -- which is
/// the .data/.bss-inside-one-page shape the loader-layer ledger records on five
/// of eight VMs.
/// Path: the loaded word is committed -> out[8].
fn build_st_initial_image(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.data.push((IMGWORD, 0xdead_beef));
    b.asm.li32(REG_T3, IMGWORD);
    let off = if g.variant == "bssboundary" { 4 } else { 0 };
    b.asm.load(F3_WORD, REG_T2, REG_T3, off);
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_hazard_chain -- two architectural writes to one register with no
/// intervening read, then the dependent read.
/// Surface: `writeRd.prevData` and `writeRd.prevCycle`, i.e. register
/// write-after-write retirement.
/// Path: the SECOND write's value is committed -> out[8]. Variant `first` arms
/// the dead write (observable only through rootOut, since the register file is
/// inside the final image); variant `second` arms the live one.
fn build_st_hazard_chain(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // write 1 (dead)
    if g.variant == "first" {
        b.site(Role::Value);
    }
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T1, REG_T0); // write 2 (live)
    if g.variant != "first" {
        b.site(Role::Value);
    }
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_control_flow -- x = c ? v1 : v2 with the mutation pinned to the
/// instruction PRODUCING c.
/// Surface: `InstBranchWitness.didBranch` / `newPc` and the executed-row
/// multiset. Both arms are one instruction long so the segment shape does not
/// move with the branch decision.
/// Path (datadiv): the selected value is committed -> out[8].
/// Path (dataident): both arms write the SAME value and the committed word is a
/// constant, so ONLY the trace differs -- it isolates the pc binding from the
/// value binding, and is scored against rootOut as well as out[8].
/// aux = the branch funct3.
fn build_st_control_flow(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // the condition
    b.site(Role::Selector);
    let (v1, v2) = if g.variant == "dataident" {
        (CONST_OUT, CONST_OUT)
    } else {
        (0x1111_1111, 0x2222_2222)
    };
    b.asm.li32(REG_T4, v1);
    b.asm.li32(REG_T5, v2);
    let br = b.b_fwd(g.aux, REG_T2, REG_ZERO);
    b.asm.addi_(REG_T6, REG_T4, 0); // arm A
    let jmp = b.j_fwd(REG_ZERO);
    b.bind(br);
    b.asm.addi_(REG_T6, REG_T5, 0); // arm B (equal length)
    b.asm.nop();
    b.bind(jmp);
    b.commit(REG_T6);
    b.terminate();
    b.seed()
}

/// st_provenance_chain -- one value carried through the maximum number of
/// distinct constraint surfaces before it is committed: the composition test
/// that turns "the cell is unbound" into "the forgery is exploitable".
/// Surface: depth 2 is register-only (does the forgery survive a SECOND chip's
/// operand-side range checks?); depth 4 routes it through a store/load pair as
/// well, so the memory argument gets a vote too.
/// Path: the last consumer's result is committed -> out[8].
/// aux = the consumer opcode packed as (funct7 << 3) | funct3.
fn build_st_provenance_chain(g: &SArgs) -> SSeed {
    let (c7, c3) = (g.aux >> 3, g.aux & 7);
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value);
    b.li_site(REG_T1, g.b, Role::Value);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // the producer
    b.site(Role::Value);
    if g.variant == "d4" {
        b.asm.li32(REG_T3, SCRATCH);
        b.asm.sw(REG_T2, REG_T3, 0);
        b.asm.load(F3_WORD, REG_T2, REG_T3, 0);
        b.site(Role::Value);
    }
    b.asm.r(c7, c3, REG_T4, REG_T2, REG_T1); // the consumer
    b.site(Role::Value);
    b.commit(REG_T4);
    b.terminate();
    b.seed()
}

/// st_loop_repeat -- ONE static pc executed N times. risc0 and pico are the
/// only two ports whose arming key has a working `nth`, so this is where that
/// half of the site key is actually exercised.
/// Surface: the lookup/range multiplicities implied by a repeated row, and
/// whether a single iteration can be moved without the others noticing.
/// Path: the accumulator is committed -> out[8].
/// aux = N.
fn build_st_loop_repeat(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T2, g.b);
    b.asm.li32(REG_T1, g.aux);
    let top = b.asm.text.len();
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T2, REG_T0); // the loop body
    b.site(Role::Value);
    b.asm.addi_(REG_T1, REG_T1, -1);
    b.b_back(F3_BNE, REG_T1, REG_ZERO, top);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_hint_advice -- the evaluation's POSITIVE CONTROL: commit a value that
/// came from the host channel, which is a free column by design, so an ACCEPT
/// here is a true accept and NOT a finding. Its purpose is the converse: if
/// this does not accept, this port's hook does not reach the constraint system
/// and none of its REJECTs are interpretable.
/// Surface: `EcallReadWitness.a0` (the byte count the host claims to have
/// returned) and `ReadWordWitness.io.value` (the hint word itself).
/// HONEST LIMIT: the hint WORD is delivered by `write_phys_memory`, which this
/// port does not hook; the write-back choke point sees (i) the ecall's a0
/// return and (ii) the ordinary `lw` that brings the word into a register. Both
/// are enumerated; the free column itself is reached only indirectly.
/// Path: the hint word is committed -> out[8]. `checked` adds an in-guest
/// equality test against the expected word, so a forged value is zeroed unless
/// the guest's own check is also fooled.
/// operand_source = hint.
fn build_st_hint_advice(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_A7, HOST_ECALL_READ);
    b.asm.li32(REG_A0, 0); // fd
    b.asm.li32(REG_A1, HBUF); // landing buffer
    b.asm.li32(REG_A2, 4); // one word
    b.asm.ecall();
    b.site(Role::Value); // a0 <- bytes actually read
    b.asm.load(F3_WORD, REG_T2, REG_A1, 0);
    b.site(Role::Value); // the hint word
    if g.variant == "checked" {
        b.asm.li32(REG_T4, HINT_WORD);
        let ok = b.b_fwd(F3_BEQ, REG_T2, REG_T4);
        b.asm.addi_(REG_T2, REG_ZERO, 0);
        b.bind(ok);
    }
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_finalize_only -- write a value that is never read again, then commit a
/// CONSTANT, so the ONLY path from the forged value to a committed object is
/// the finalise boundary.
/// FIRST-CLASS PROBE ON risc0, not a control: `globals.rootOut` is the Merkle
/// root of the final image (prove/preflight/paging.rs:189) and the paged-out
/// register page is inside it, so a dead write IS observable.
/// Surface: `PageOutPartWitness.data[i]` / `.cycle[i]`.
/// Path: NOT out[8] -- out[8] is pinned to CONST_OUT by construction. Scored
/// against rootOut (scored_against = in_circuit_state_object), which is why
/// this structure needs accepted_case_v2.
fn build_st_finalize_only(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
    b.site(Role::Value);
    if g.variant == "mem" {
        b.asm.li32(REG_T3, SINK);
        b.asm.sw(REG_T2, REG_T3, 0); // stored, never read again
    }
    b.asm.li32(REG_T4, CONST_OUT);
    b.commit(REG_T4);
    b.terminate();
    b.seed()
}

/// st_indirect_jump -- JALR through a register the mutation can move, with a
/// two-entry jump table whose arms are BOTH real code.
/// Surface: `InstJalrWitness.rs1.value` (the indirect target), the link value
/// rd = pc+4, and next_pc. The second arm is planted in the committed image
/// EXACTLY +2^16 from the first, because the address role mask allows only
/// alignment-preserving pointer steps.
/// Path: each arm writes a different word, which is committed -> out[8].
/// `bit0` is the one place the manifest allows `xor_b0` on an address: clearing
/// bit 0 is the RISC-V JALR requirement the variant exists to test.
fn build_st_indirect_jump(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
    // Touch arm B's page on the HONEST path. The threat model runs the executor
    // honestly and perturbs only the prover's record generation, and the
    // preflight can page in only what the honest Segment carries -- without
    // this load a redirected JALR dies as `Unavailable page`, i.e. an EXECFAIL
    // that says nothing about the constraint system. `rd = x0` keeps the load
    // architecturally dead while still recording the page.
    let touch_idx = b.asm.text.len();
    b.asm.li32(REG_S3, 0);
    b.asm.load(F3_WORD, REG_ZERO, REG_S3, 0);
    // The call target register. Patched below once the arm's pc is known; the
    // li32 expansion is a fixed two words, so the layout does not move.
    let tgt_idx = b.asm.text.len();
    b.asm.li32(REG_T3, 0);
    b.site(if g.variant == "bit0" {
        Role::AddressBit0
    } else {
        Role::Address
    });
    b.asm.jalr(REG_RA, REG_T3, 0);
    b.commit(REG_T4);
    b.terminate();
    // arm A, reached by the honest JALR
    let arm_a = b.here();
    // (arm A's own two-word li32 plus the return jalr are emitted below.)
    b.asm.li32(REG_T4, 0x0a0a_0a0a);
    b.asm.jalr(REG_ZERO, REG_RA, 0);
    // arm B, planted in the image exactly +2^16 away
    let arm_b = arm_a + 0x0001_0000;
    let mut tail = Asm::default();
    tail.li32(REG_T4, 0x0b0b_0b0b);
    tail.jalr(REG_ZERO, REG_RA, 0);
    for (i, w) in tail.text.iter().enumerate() {
        b.data.push((arm_b + 4 * i as u32, *w));
    }
    // patch the two li32 expansions now that both arm addresses are known
    let mut patch = |idx: usize, rd: usize, v: u32| {
        let low = ((v as i32) << 20) >> 20;
        let high = (v as i32).wrapping_sub(low) >> 12;
        b.asm.text[idx] = insn_u(high as u32, rd as u32, OP_LUI);
        b.asm.text[idx + 1] = insn_i(low as u32 & 0xfff, rd as u32, 0x0, rd as u32, OP_IMM);
    };
    patch(tgt_idx, REG_T3, arm_a);
    patch(touch_idx, REG_S3, arm_b);
    b.seed()
}

/// st_pc_imm_value -- commit a value whose ONLY source is the pc or the
/// committed program text, never a register.
/// Surface: `do_inst_auipc` (emu.rs:894), `do_inst_lui` (:882) and
/// `do_inst_jal` (:841) all route their rd through the hooked `write_reg`,
/// while the circuit recomputes the value from the decoded immediate and the
/// pc. If a forged pc-derived rd is accepted, the pc is not binding the value.
/// Path: the produced word is committed -> out[8].
fn build_st_pc_imm_value(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    match g.variant {
        "auipc" => {
            b.asm.auipc(REG_T2, 0x1_2345);
            b.site(Role::Value);
        }
        "lui" => {
            b.asm.lui(REG_T2, 0x1_2345);
            b.site(Role::Value);
        }
        _ => {
            // jal writes the LINK value pc+4 and skips the following word.
            let j = b.j_fwd(REG_T2);
            b.site(Role::Value);
            b.asm.nop();
            b.bind(j);
        }
    }
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_fanout_read -- one definition, two uses at two different cycles.
/// Surface: the OPERAND-READ side. A record field read at two points by the
/// witness generator is the shape that produces over-propagation false
/// negatives; splitting the uses across two cycles makes the split expressible
/// at the program level.
/// Path: the two uses are recombined with XOR and committed -> out[8].
fn build_st_fanout_read(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // the definition
    b.site(Role::Value);
    b.asm.addi_(REG_T4, REG_T2, 0x123); // use 1
    b.asm.li32(REG_T3, 0x5555_aaaa);
    b.asm.r(0x00, 0x4, REG_T5, REG_T2, REG_T3); // use 2: XOR
    b.asm.r(0x00, 0x4, REG_T6, REG_T4, REG_T5); // recombine
    b.commit(REG_T6);
    b.terminate();
    b.seed()
}

/// st_reg_alias -- the same register read twice, and read-and-written in one
/// cycle.
/// Surface: risc0 makes this explicit with dedicated `DualReg::sameReg` and
/// `rs2Data` columns that are recomputed from the record's rs1/rs2 indices and
/// are trivial unless rs1 == rs2.
/// Path: the result is committed -> out[8].
fn build_st_reg_alias(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    if g.variant == "rdrs1rs2" {
        b.li_site(REG_T2, g.a, Role::Value);
        b.asm.r(g.funct7, g.funct3, REG_T2, REG_T2, REG_T2);
    } else {
        b.li_site(REG_T0, g.a, Role::Value);
        b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T0);
    }
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_pv_plumbing -- commit EIGHT distinct words instead of one, and alias the
/// output region.
/// Surface: `EcallTerminateWitness.output` is itself a record field, read as
/// eight `PhysMemReadWitness` at OUTPUT_WORD..+8 (emu.rs:916-920) and bound by
/// GLOBAL_SET_U32 / GLOBAL_CHECK_U32 (cxx/rv32im/circuit/ecall.ipp:91,110).
/// Today only word 0 is ever non-trivial in the whole corpus.
/// Path: each producer's result is committed into its own output word ->
/// out[8]. The `alias` variant writes out[0] twice and reads it back before the
/// final commit, so the output region is on both sides of the memory argument.
/// The `index` and `exitcode` variants are NOT built: they need a syscall_arg
/// site, which the manifest's role mask forbids until a port is opted in.
fn build_st_pv_plumbing(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.li32(REG_T3, OUT_ADDR);
    if g.variant == "alias" {
        b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
        b.site(Role::Value);
        b.asm.sw(REG_T2, REG_T3, 0);
        b.asm.r(g.funct7, g.funct3, REG_T4, REG_T1, REG_T0);
        b.site(Role::Value);
        b.asm.sw(REG_T4, REG_T3, 0); // second write to out[0]
        b.asm.load(F3_WORD, REG_T5, REG_T3, 0); // read the output region back
        b.site(Role::Value);
        b.asm.r(g.funct7, g.funct3, REG_T6, REG_T5, REG_T0);
        b.asm.sw(REG_T6, REG_T3, 4);
    } else {
        for i in 0..8u32 {
            b.asm.addi_(REG_T4, REG_T0, i as i32);
            b.asm.r(g.funct7, g.funct3, REG_T2, REG_T4, REG_T1);
            b.site(Role::Value);
            b.asm.sw(REG_T2, REG_T3, 4 * i);
        }
    }
    b.terminate();
    b.seed()
}

/// st_early_exit -- a forged condition makes the guest halt BEFORE it commits,
/// so the proof carries an EMPTY public output.
/// Surface: the terminate event's position in the trace and the row multiset.
/// Path: honestly the seed commits; with the condition forged to zero it jumps
/// straight to the terminate ecall and out[8] stays all-zero.
/// UNFALSIFIABLE UNDER accepted_case_strict BY CONSTRUCTION -- strict requires a
/// NON-EMPTY committed output and success here means the output is absent. This
/// row is scored under accepted_case_v2.
fn build_st_early_exit(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // the condition
    b.site(Role::Selector);
    // honest: t2 != 0 -> the branch is taken and the commit happens.
    let live = b.b_fwd(F3_BNE, REG_T2, REG_ZERO);
    let skip = b.j_fwd(REG_ZERO); // forged t2 == 0 -> jump past the commit
    b.bind(live);
    b.commit(REG_T2);
    b.bind(skip);
    b.terminate();
    b.seed()
}

/// st_dead_write -- a write-back whose destination is provably never read
/// again. On five of the seven ports this is the negative CONTROL that makes a
/// REJECT interpretable; on risc0 it is a PROBE, because the register file is
/// inside `rootOut` and an accepted dead write with a changed root IS a state
/// forgery -- weaker than an output forgery, and real.
/// Surface: the paged-out register page and the final image digest.
/// Path: NOT out[8] (the committed word is produced by a different
/// instruction). Scored against rootOut.
fn build_st_dead_write(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    if g.variant == "overwritten" {
        b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1); // dead
        b.site(Role::Value);
        b.asm.addi_(REG_T2, REG_T1, 0); // overwritten before any read
    } else {
        b.asm.r(g.funct7, g.funct3, REG_T4, REG_T0, REG_T1); // never read at all
        b.site(Role::Value);
        b.asm.addi_(REG_T2, REG_T1, 0);
    }
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_x0_dark_write -- an instruction whose destination is x0, an architectural
/// write the circuit must discard.
/// Surface: `DestReg::isZero`, recomputed from the record's rd index. risc0
/// routes an x0 write to a SHADOW word (`write_reg`: `reg_offset + reg + 64`),
/// which is inside the paged register region.
/// Path: the honest committed word is 0 and stays 0 in out[8], so the
/// observable object is rootOut -- the shadow slot is part of the final image.
/// The row is scored under accepted_case_v2 for that reason.
fn build_st_x0_dark_write(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    b.asm.r(g.funct7, g.funct3, REG_ZERO, REG_T0, REG_T1); // rd = x0
    b.site(Role::Value);
    b.asm.addi_(REG_T2, REG_ZERO, 0); // read x0 back
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_op_then_state -- THE DECONFOUNDING SHAPE. The result of the opcode under
/// test is not committed directly: it first traverses ONE state interaction and
/// only then reaches the output. The shipped run matrices pinned structure and
/// opcode together, so "structure X found nothing" was never evidence about
/// structure X; this shape lets them vary independently.
/// Surface, by variant:
///   mem    -- the result round-trips through RAM (sink S1)
///   addr   -- the result BECOMES an address, selecting between two live
///             objects (sink S2)
///   branch -- the result BECOMES a decision (sink S3)
/// Path: the value that survives the interaction is committed -> out[8].
/// aux (branch variant) = the branch funct3.
fn build_st_op_then_state(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T0, g.a);
    b.asm.li32(REG_T1, g.b);
    match g.variant {
        "mem" => {
            b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
            b.site(Role::Value);
            b.asm.li32(REG_T3, SCRATCH);
            b.asm.sw(REG_T2, REG_T3, 0);
            b.asm.load(F3_WORD, REG_T4, REG_T3, 0);
            b.site(Role::Value);
            b.commit(REG_T4);
        }
        "addr" => {
            // two live objects 64 bytes apart; bit 6 of the result picks one.
            b.asm.li32(REG_T3, SCRATCH);
            b.asm.li32(REG_T4, 0x0a0a_0a0a);
            b.asm.sw(REG_T4, REG_T3, 0);
            b.asm.li32(REG_T5, 0x0b0b_0b0b);
            b.asm.sw(REG_T5, REG_T3, 64);
            b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
            b.site(Role::Value);
            b.asm.andi(REG_T6, REG_T2, 0x40);
            b.asm.r(0x00, 0x0, REG_T5, REG_T3, REG_T6); // add: the address
            b.asm.load(F3_WORD, REG_T4, REG_T5, 0);
            b.site(Role::Value);
            b.commit(REG_T4);
        }
        _ => {
            b.asm.r(g.funct7, g.funct3, REG_T2, REG_T0, REG_T1);
            b.site(Role::Value);
            b.asm.li32(REG_T4, 0x1111_1111);
            b.asm.li32(REG_T5, 0x2222_2222);
            let br = b.b_fwd(g.aux, REG_T2, REG_ZERO);
            b.asm.addi_(REG_T6, REG_T4, 0);
            let jmp = b.j_fwd(REG_ZERO);
            b.bind(br);
            b.asm.addi_(REG_T6, REG_T5, 0);
            b.asm.nop();
            b.bind(jmp);
            b.commit(REG_T6);
        }
    }
    b.terminate();
    b.seed()
}

/// st_precompile -- route a forged value into an accelerator's INPUT buffer and
/// commit the accelerator's output.
/// Surface: the Poseidon2 block (`EcallP2Witness`, `P2StepBlock`) and its
/// memory argument. The accelerator's own result is written to MEMORY, not to a
/// register, so the only write-back sites are (i) the instruction producing an
/// input word and (ii) the `lw` that reads the digest back -- both ordinary
/// Value sites, no new hook.
/// Protocol (prove/preflight/emu.rs:1031, execute/poseidon2.rs:146): a0 = state
/// pointer (0 => the zeros state), a1 = input buffer, a2 = output buffer,
/// a3 = flags|count with no PFLAG_IS_ELEM, so eight u32 words are consumed as
/// sixteen 16-bit half-elements and any word is a legal input.
/// Path: digest word 0 is committed -> out[8].
fn build_st_precompile(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.asm.li32(REG_T3, P2_IN);
    b.li_site(REG_T0, g.a, Role::Value); // <-- the forged input word
    b.asm.sw(REG_T0, REG_T3, 0);
    for i in 1..8u32 {
        b.asm.sw(REG_ZERO, REG_T3, 4 * i);
    }
    b.asm.li32(REG_A0, 0); // no sponge state
    b.asm.li32(REG_A1, P2_IN);
    b.asm.li32(REG_A2, P2_OUT);
    b.asm.li32(REG_A3, 1); // one block, u32 mode
    b.asm.li32(REG_A7, HOST_ECALL_POSEIDON2);
    b.asm.ecall();
    b.asm.li32(REG_T4, P2_OUT);
    b.asm.load(F3_WORD, REG_T2, REG_T4, 0);
    b.site(Role::Value);
    b.commit(REG_T2);
    b.terminate();
    b.seed()
}

/// st_whole_program -- a realistic guest rather than a surface probe: the
/// external-validity claim. A Fibonacci recurrence with an array round trip, a
/// counted loop and a call, so ALU, memory, branch, jal and jalr blocks all
/// appear at realistic multiplicity and the committed word is genuinely
/// DOWNSTREAM of the mutation instead of a direct copy of it.
/// Surface: all of them. This is also the only place where the two public
/// output objects have been observed to diverge on another port, so both are
/// recorded.
/// Path: the accumulator is committed -> out[8]; rootOut moves too.
/// aux = the trip count.
fn build_st_whole_program(g: &SArgs) -> SSeed {
    let mut b = SB::new();
    b.li_site(REG_T0, g.a, Role::Value); // x
    b.li_site(REG_T1, g.b, Role::Value); // y
    b.asm.li32(REG_S0, g.aux); // trip count
    b.asm.li32(REG_S1, 0); // array index
    b.asm.li32(REG_S2, SCRATCH); // array base
    b.asm.li32(REG_T6, 0); // accumulator
    let top = b.asm.text.len();
    b.asm.r(0x00, 0x0, REG_T2, REG_T0, REG_T1); // t = x + y
    b.site(Role::Value);
    b.asm.addi_(REG_T0, REG_T1, 0); // x = y
    b.asm.addi_(REG_T1, REG_T2, 0); // y = t
    b.site(Role::Value);
    b.asm.r(0x00, 0x0, REG_T4, REG_S2, REG_S1); // &arr[i]
    b.asm.sw(REG_T2, REG_T4, 0);
    b.asm.load(F3_WORD, REG_T5, REG_T4, 0);
    b.site(Role::Value);
    b.asm.r(0x00, 0x4, REG_T6, REG_T6, REG_T5); // acc ^= arr[i]
    b.site(Role::Value);
    b.asm.addi_(REG_S1, REG_S1, 4);
    b.asm.andi(REG_S1, REG_S1, 0xfc); // stay inside one page
    b.asm.addi_(REG_S0, REG_S0, -1);
    b.b_back(F3_BNE, REG_S0, REG_ZERO, top);
    // a call, so JAL and JALR blocks are exercised too
    let call = b.j_fwd(REG_RA);
    b.site(Role::Value); // the link value
    b.asm.r(0x00, 0x4, REG_T6, REG_T6, REG_A0);
    b.commit(REG_T6);
    b.terminate();
    b.bind(call);
    b.asm.auipc(REG_A0, 0x11);
    b.site(Role::Value);
    b.asm.jalr(REG_ZERO, REG_RA, 0);
    b.seed()
}

// ---------------------------------------------------------------------------
// the structure table -- the driver's seed table for the structure axis
// ---------------------------------------------------------------------------

/// Run-matrix rules R2 and R3. R2 requires every structure with an opcode
/// parameter to be run, in one run, against at least one opcode from
/// `alu_bound_reference` AND the whole of the target's `target_unbound_probe`
/// set. TARGET_CAPABILITIES.yaml records risc0's `known_unbound_opcodes` as
/// EMPTY / not determined, so R3's substitution applies: the full
/// `shift_family` plus the full `m_ext`, and the run tag must say so. The
/// driver appends `unbound_probe=substituted` to LACUNA_TAG for exactly this
/// reason.
const DECONFOUND: &[&str] = &[
    "ADD", // alu_bound_reference
    "SLL", "SRL", "SRA", // shift_family
    "MUL", "MULH", "MULHU", "MULHSU", "DIV", "DIVU", "REM", "REMU", // m_ext
];
const M_EXT: &[&str] = &[
    "MUL", "MULH", "MULHU", "MULHSU", "DIV", "DIVU", "REM", "REMU",
];
const SHIFTS: &[&str] = &["SLL", "SRL", "SRA"];
const M_EXT_AND_SHIFTS: &[&str] = &[
    "MUL", "MULH", "MULHU", "MULHSU", "DIV", "DIVU", "REM", "REMU", "SLL", "SRL", "SRA",
];

/// Default nth arming. risc0's hook keys on (static pc, n-th execution) and
/// `nth < 0` arms every execution; risc0 and pico are the only two ports where
/// a per-execution nth means anything (TARGET_CAPABILITIES nth_supported).
const NTH_ALL: &[i64] = &[-1];

/// One row of the structure table = one seed family.
struct Structure {
    /// STRUCTURE_MANIFEST.yaml structure id
    id: &'static str,
    /// STRUCTURE_MANIFEST.yaml published_name -> the `program_structure` column
    published: &'static str,
    /// manifest variant suffix, "" if the structure declares none
    variant: &'static str,
    /// an extra lowercase-alnum seed-id part (a branch or consumer mnemonic)
    tag: &'static str,
    /// probe | control | calibration
    class: &'static str,
    /// in_circuit | in_circuit_state_object
    scored: &'static str,
    /// input | hint | immediate
    operand_source: &'static str,
    /// opcode axis; empty => the shape fixes its own opcode
    ops: &'static [&'static str],
    /// the CSV `opcode` value when `ops` is empty
    shape_opcode: &'static str,
    oa: u32,
    ob: u32,
    aux: u32,
    nths: &'static [i64],
    /// this seed drives the host READ channel
    hint: bool,
    build: fn(&SArgs) -> SSeed,
}

/// The structure table. Every row is one (structure, variant) cell of
/// STRUCTURE_MANIFEST.yaml whose risc0 status is `trivial`, plus the `moderate`
/// cells that land with no vendor-tree change. Cells NOT here, and why:
///   st_multishard    -- needs multi-segment assembly and rootIn/rootOut
///                       chaining; this driver proves exactly ONE segment.
///   st_initial_state/hintregion -- risc0 has no distinguished hint region: the
///                       host-read landing buffer is an ordinary guest address
///                       chosen by a1, so the variant collapses onto `bss`.
///   st_pv_plumbing/index, st_pv_plumbing/exitcode -- syscall_arg sites, which
///                       the manifest's mu role mask forbids on every target.
fn structures() -> Vec<Structure> {
    let base = |id, published, build: fn(&SArgs) -> SSeed| Structure {
        id,
        published,
        variant: "",
        tag: "",
        class: "probe",
        scored: "in_circuit",
        operand_source: "immediate",
        ops: DECONFOUND,
        shape_opcode: "",
        oa: OP_A,
        ob: OP_B,
        aux: 0,
        nths: NTH_ALL,
        hint: false,
        build,
    };
    let mut v = Vec::new();

    // -- st_op_then_state: the deconfounding shape (promoted; priority must) --
    for (variant, tag, aux) in [("mem", "", 0u32), ("addr", "", 0), ("branch", "bne", F3_BNE)] {
        v.push(Structure {
            variant,
            tag,
            aux,
            ..base(
                "st_op_then_state",
                "Operation then state",
                build_st_op_then_state,
            )
        });
    }

    // -- st_boundary_operand: a shape requirement AND an operand table --
    for (variant, ops, oa, ob) in [
        ("zero", M_EXT, OP_A, 1u32),
        ("shamt", SHIFTS, OP_A, 1),
        ("intmin", M_EXT, 0x8000_0001, 0xffff_ffff),
        ("limb", M_EXT_AND_SHIFTS, 0x0000_ffff, 1),
        ("exactdiv", M_EXT, 8, 2),
        ("limbmax", M_EXT, 0xffff_ffff, 0xffff_ffff),
    ] {
        v.push(Structure {
            variant,
            ops,
            oa,
            ob,
            ..base(
                "st_boundary_operand",
                "Boundary operand",
                build_st_boundary_operand,
            )
        });
    }

    // -- st_subword_lane --
    for (op, variant, aux) in [
        ("LB", "load", F3_BYTE),
        ("LBU", "load", F3_BYTEU),
        ("LH", "load", F3_HALF),
        ("LHU", "load", F3_HALFU),
        ("SB", "store", F3_BYTE),
        ("SH", "store", F3_HALF),
    ] {
        v.push(Structure {
            variant,
            ops: &[],
            shape_opcode: op,
            aux,
            oa: 0x8899_aabb,
            ob: 0x0000_5e5e,
            ..base("st_subword_lane", "Sub-word lane", build_st_subword_lane)
        });
    }

    // -- st_store_load --
    for variant in ["", "tail"] {
        v.push(Structure {
            variant,
            ..base("st_store_load", "Store--load", build_st_store_load)
        });
    }

    // -- st_redirect / st_pointer_indirect --
    v.push(base("st_redirect", "Redirect", build_st_redirect));
    v.push(Structure {
        ops: &[],
        shape_opcode: "LW",
        ..base(
            "st_pointer_indirect",
            "Pointer indirect",
            build_st_pointer_indirect,
        )
    });

    // -- st_initial_state (probe) and its paired control st_initial_image --
    v.push(Structure {
        variant: "bss",
        ops: &[],
        shape_opcode: "LW",
        ..base("st_initial_state", "Initial state", build_st_initial_state)
    });
    for variant in ["data", "bssboundary"] {
        v.push(Structure {
            variant,
            ops: &[],
            shape_opcode: "LW",
            class: "control",
            ..base("st_initial_image", "Initial image", build_st_initial_image)
        });
    }

    // -- register/dataflow shapes --
    for variant in ["first", "second"] {
        v.push(Structure {
            variant,
            ..base("st_hazard_chain", "Hazard chain", build_st_hazard_chain)
        });
    }
    for (variant, tag, aux) in [
        ("datadiv", "beq", F3_BEQ),
        ("datadiv", "blt", F3_BLT),
        ("datadiv", "bltu", F3_BLTU),
        ("dataident", "bne", F3_BNE),
    ] {
        v.push(Structure {
            variant,
            tag,
            aux,
            ..base("st_control_flow", "Control flow", build_st_control_flow)
        });
    }
    for (variant, tag, aux) in [
        ("d2", "add", 0u32),           // consumer ADD  (funct7<<3)|funct3
        ("d2", "slt", 2),              // consumer SLT
        ("d2", "mul", 8),              // consumer MUL
        ("d4", "add", 0),              // through memory
    ] {
        v.push(Structure {
            variant,
            tag,
            aux,
            ..base(
                "st_provenance_chain",
                "Provenance chain",
                build_st_provenance_chain,
            )
        });
    }
    v.push(base("st_fanout_read", "Fan-out read", build_st_fanout_read));
    for variant in ["rs1rs2", "rdrs1rs2"] {
        v.push(Structure {
            variant,
            ..base("st_reg_alias", "Register aliasing", build_st_reg_alias)
        });
    }

    // -- nth axis --
    for (variant, n, nths) in [
        ("n16", 16u32, &[-1i64, 0, 1, 8, 15][..]),
        ("n256", 256, &[-1, 0, 1, 128, 255][..]),
        ("n4096", 4096, &[-1, 0, 4095][..]),
    ] {
        v.push(Structure {
            variant,
            aux: n,
            nths,
            ..base("st_loop_repeat", "Loop repeat", build_st_loop_repeat)
        });
    }

    // -- calibration --
    for variant in ["unchecked", "checked"] {
        v.push(Structure {
            variant,
            ops: &[],
            shape_opcode: "LW",
            class: "calibration",
            operand_source: "hint",
            hint: true,
            ..base(
                "st_hint_advice",
                "Nondeterministic advice",
                build_st_hint_advice,
            )
        });
    }

    // -- state-object probes: risc0 commits the final image root --
    for variant in ["mem", "reg"] {
        v.push(Structure {
            variant,
            scored: "in_circuit_state_object",
            ..base(
                "st_finalize_only",
                "Finalize-only write",
                build_st_finalize_only,
            )
        });
    }
    for variant in ["overwritten", "neverread"] {
        v.push(Structure {
            variant,
            scored: "in_circuit_state_object",
            ..base("st_dead_write", "Dead write-back", build_st_dead_write)
        });
    }
    v.push(Structure {
        scored: "in_circuit_state_object",
        ..base("st_x0_dark_write", "x0 dark write", build_st_x0_dark_write)
    });

    // -- control flow through the pc --
    for variant in ["table", "bit0"] {
        v.push(Structure {
            variant,
            ops: &[],
            shape_opcode: "JALR",
            ..base("st_indirect_jump", "Indirect jump", build_st_indirect_jump)
        });
    }
    for (variant, op) in [("auipc", "AUIPC"), ("lui", "LUI"), ("jal", "JAL")] {
        v.push(Structure {
            variant,
            ops: &[],
            shape_opcode: op,
            ..base(
                "st_pc_imm_value",
                "PC-immediate value",
                build_st_pc_imm_value,
            )
        });
    }

    // -- public values, early exit, precompile, realistic guest --
    for variant in ["words8", "alias"] {
        v.push(Structure {
            variant,
            ..base(
                "st_pv_plumbing",
                "Public-value plumbing",
                build_st_pv_plumbing,
            )
        });
    }
    v.push(base("st_early_exit", "Early exit", build_st_early_exit));
    v.push(Structure {
        ops: &[],
        shape_opcode: "POSEIDON2",
        ..base("st_precompile", "Precompile boundary", build_st_precompile)
    });
    v.push(Structure {
        ops: &[],
        shape_opcode: "CENSUS",
        aux: 256,
        ..base("st_whole_program", "Whole program", build_st_whole_program)
    });
    v
}

/// `<structure_id>[_<opcode>][_<tag>][_<variant>]`, the convention
/// `evaluation/scripts/check_manifest.py::seed_id_ok` enforces. A part equal to
/// the one before it is dropped so `st_pc_imm_value_lui_lui` cannot happen.
fn seed_id_of(s: &Structure, opcode: &str) -> String {
    let mut out = String::from(s.id);
    let mut last = String::new();
    for p in [opcode.to_lowercase(), s.tag.to_string(), s.variant.to_string()] {
        if p.is_empty() || p == last {
            continue;
        }
        out.push('_');
        out.push_str(&p);
        last = p;
    }
    out
}

fn sargs(s: &Structure, opcode: &str) -> SArgs {
    let (funct7, funct3) = opcodes()
        .into_iter()
        .find(|o| o.0 == opcode)
        .map(|o| (o.1, o.2))
        .unwrap_or((0, 0));
    SArgs {
        funct7,
        funct3,
        a: s.oa,
        b: s.ob,
        variant: s.variant,
        aux: s.aux,
    }
}

/// The driver's host-read channel. Returns a fixed word so that the honest run
/// is deterministic and the calibration is reproducible; risc0's segment
/// records the bytes, and the preflight replays them, so the prover sees the
/// same value the executor did.
#[derive(Default)]
struct HintSyscall;

impl Syscall for HintSyscall {
    fn host_read(&self, _c: &mut impl SyscallContext, _fd: u32, b: &mut [u8]) -> Result<u32> {
        let src = HINT_WORD.to_le_bytes();
        let n = b.len().min(src.len());
        b[..n].copy_from_slice(&src[..n]);
        Ok(n as u32)
    }
    fn host_write(&self, _c: &mut impl SyscallContext, _fd: u32, _b: &[u8]) -> Result<u32> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// structure worker + driver
// ---------------------------------------------------------------------------

/// A structure worker:
/// `LACUNA_SJOB = "<id>|<variant>|<tag>|<opname>|<pc>|<nth>|<mu_kind>|<mu_arg>"`.
#[test]
#[ignore = "internal worker; driven by lacuna_structure_enumeration_risc0"]
fn lacuna_structure_worker() {
    let job = std::env::var("LACUNA_SJOB").expect("LACUNA_SJOB not set");
    let f: Vec<&str> = job.split('|').collect();
    assert_eq!(f.len(), 8, "bad LACUNA_SJOB");
    let (id, variant, tag, opname) = (f[0], f[1], f[2], f[3]);
    let pc = f[4].parse::<u32>().unwrap();
    let nth = f[5].parse::<i64>().unwrap();
    let kind = f[6].parse::<usize>().unwrap();
    let arg = f[7].parse::<i64>().unwrap();

    let table = structures();
    let s = table
        .iter()
        .find(|s| s.id == id && s.variant == variant && s.tag == tag)
        .expect("unknown structure row");
    let build = || (s.build)(&sargs(s, opname)).program;
    let o = if s.hint {
        run_pipeline(build, HintSyscall, pc, nth, kind, arg)
    } else {
        run_pipeline(build, NullSyscall, pc, nth, kind, arg)
    };
    println!(
        "LACUNARESULT {}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        o.outcome,
        o.failure_stage,
        o.hits,
        o.site_execs,
        o.root_out_hex,
        o.pv_hex,
        o.t_record_ms,
        o.t_prove_ms,
        o.t_verify_ms,
        trunc(&o.reason),
    );
}

struct SRow {
    seed_id: String,
    structure_id: &'static str,
    published: &'static str,
    variant: &'static str,
    opcode: String,
    class: &'static str,
    scored: &'static str,
    operand_source: &'static str,
    pc: u32,
    nth: i64,
    role: Role,
    mu_label: String,
    template: String,
    kind: usize,
    arg: i64,
    o: Outcome,
}

#[allow(clippy::too_many_arguments)]
fn spawn_sjob(
    exe: &str,
    id: &str,
    variant: &str,
    tag: &str,
    opname: &str,
    pc: u32,
    nth: i64,
    kind: usize,
    arg: i64,
) -> Outcome {
    let out = std::process::Command::new(exe)
        .args([
            "--exact",
            "prove::lacuna_eval::lacuna_structure_worker",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "LACUNA_SJOB",
            format!("{id}|{variant}|{tag}|{opname}|{pc}|{nth}|{kind}|{arg}"),
        )
        .env_remove("LACUNA_OUT")
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => return empty_outcome("EXECFAIL", "fork_exec", format!("spawn: {e}")),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let Some(line) = stdout.lines().find(|l| l.starts_with("LACUNARESULT ")) else {
        let tail: String = String::from_utf8_lossy(&out.stderr)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        return empty_outcome(
            "EXECFAIL",
            "fork_exec",
            format!("worker died ({:?}): {}", out.status.code(), trunc(&tail)),
        );
    };
    let f: Vec<&str> = line["LACUNARESULT ".len()..].split('|').collect();
    let st = match f[0] {
        "ACCEPT" => "ACCEPT",
        "REJECT" => "REJECT",
        "NOOP" => "NOOP",
        _ => "EXECFAIL",
    };
    let stage = match f[1] {
        "prove" => "prove",
        "verify" => "verify",
        "mutation" => "mutation",
        "accepted_proof" => "accepted_proof",
        _ => "fork_exec",
    };
    Outcome {
        outcome: st,
        failure_stage: stage,
        hits: f[2].parse().unwrap_or(0),
        site_execs: f[3].parse().unwrap_or(0),
        root_out_hex: f[4].to_string(),
        pv_hex: f[5].to_string(),
        t_record_ms: f[6].parse().unwrap_or(0),
        t_prove_ms: f[7].parse().unwrap_or(0),
        t_verify_ms: f[8].parse().unwrap_or(0),
        reason: f.get(9).copied().unwrap_or("").to_string(),
    }
}

/// `accepted_case_strict`, character for character the same rule as
/// `is_accepted_case` above. Duplicated rather than shared so that the FROZEN
/// predicate function is not touched by this section.
fn strict_pred(o: &Outcome, b: &Outcome) -> bool {
    o.outcome == "ACCEPT"
        && o.hits > 0
        && !o.pv_hex.is_empty()
        && o.pv_hex.chars().any(|c| c != '0')
        && !b.pv_hex.is_empty()
        && o.pv_hex != b.pv_hex
}

/// `accepted_case_v2` (STRUCTURE_MANIFEST.yaml predicates): strict, OR the
/// committed output differs BY BEING ABSENT/TRUNCATED, OR the declared
/// committed STATE object -- here `globals.rootOut`, the final image root --
/// differs. It never turns a strict accept into a non-accept, so v2 >= strict
/// on every row.
fn v2_pred(o: &Outcome, b: &Outcome) -> bool {
    if strict_pred(o, b) {
        return true;
    }
    o.outcome == "ACCEPT"
        && o.hits > 0
        && ((!b.pv_hex.is_empty() && o.pv_hex != b.pv_hex)
            || (!b.root_out_hex.is_empty()
                && !o.root_out_hex.is_empty()
                && o.root_out_hex != b.root_out_hex))
}

/// The frozen CSV schema plus the six columns
/// `STRUCTURE_MANIFEST.yaml::csv_contract` requires, plus three that identify
/// the table row. Every pre-existing column keeps its name and its meaning.
const SHEADER: &str = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed,operand_source,candidate_class,accepted_case_v2,site_role,scored_against,structure_id,structure_variant,candidate_key";

fn semit(file: &mut Option<std::fs::File>, tag: &str, r: &SRow, b: &Outcome) {
    let changed = !r.o.pv_hex.is_empty() && !b.pv_hex.is_empty() && r.o.pv_hex != b.pv_hex;
    let dchanged = !r.o.root_out_hex.is_empty()
        && !b.root_out_hex.is_empty()
        && r.o.root_out_hex != b.root_out_hex;
    let outcome = if r.o.hits == 0 && r.o.outcome == "ACCEPT" {
        "NOOP"
    } else {
        r.o.outcome
    };
    let key = format!(
        "risc0|{}|{}|{:#x}|{}|{}",
        r.seed_id, r.opcode, r.pc, r.nth, r.mu_label
    );
    let line = format!(
        "{tag},{TARGET},{REV},{seed},encoding,{ps},{op},{pc:#x},{nth},NA,NA,{se},{mu},{tmpl},{kind},{arg},{outcome},{stage},{hits},{pv},{hpv},{ch},{ac},{tr},{tp},{tv},{reason},{cd},{hcd},{dch},{osrc},{cls},{ac2},{role},{scored},{sid},{svar},{key}",
        seed = r.seed_id,
        ps = r.published,
        op = r.opcode,
        pc = r.pc,
        nth = r.nth,
        se = r.o.site_execs,
        mu = r.mu_label,
        tmpl = r.template,
        kind = r.kind,
        arg = r.arg,
        stage = r.o.failure_stage,
        hits = r.o.hits,
        pv = if r.o.pv_hex.is_empty() {
            "NA".into()
        } else {
            r.o.pv_hex.clone()
        },
        hpv = if b.pv_hex.is_empty() {
            "NA".into()
        } else {
            b.pv_hex.clone()
        },
        ch = changed,
        ac = strict_pred(&r.o, b),
        tr = r.o.t_record_ms,
        tp = r.o.t_prove_ms,
        tv = r.o.t_verify_ms,
        reason = trunc(&r.o.reason),
        cd = if r.o.root_out_hex.is_empty() {
            "NA".into()
        } else {
            r.o.root_out_hex.clone()
        },
        hcd = if b.root_out_hex.is_empty() {
            "NA".into()
        } else {
            b.root_out_hex.clone()
        },
        dch = dchanged,
        osrc = r.operand_source,
        cls = r.class,
        ac2 = v2_pred(&r.o, b),
        role = r.role.as_str(),
        scored = r.scored,
        sid = r.structure_id,
        svar = if r.variant.is_empty() {
            "NA"
        } else {
            r.variant
        },
    );
    if let Some(f) = file {
        writeln!(f, "{line}").unwrap();
        f.flush().unwrap();
    }
}

/// The structure-axis driver. Independent of
/// `lacuna_encoding_enumeration_risc0`, which is untouched.
#[test]
#[ignore = "long-running: real prove+verify per candidate"]
fn lacuna_structure_enumeration_risc0() {
    // R3: risc0 has no ESTABLISHED unbound opcode, so R2 is satisfied by proxy
    // and the run tag has to say so.
    // NOTE the separator is a semicolon: run_tag is a CSV field.
    let tag = format!(
        "{};unbound_probe=substituted",
        std::env::var("LACUNA_TAG").unwrap_or_else(|_| "risc0-struct".into())
    );
    let out_path = std::env::var("LACUNA_OUT").ok();
    let all_mu = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".into()) != "one";
    let jobs: usize = std::env::var("LACUNA_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let stride: usize = std::env::var("LACUNA_SITE_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|k| *k > 0)
        .unwrap_or(1);
    let only_structs: Option<Vec<String>> = std::env::var("LACUNA_STRUCTS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let only_ops: Option<Vec<String>> = std::env::var("LACUNA_OPS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let exe = std::env::current_exe().unwrap().display().to_string();

    let mut file = out_path.as_ref().map(|p| {
        let mut f = std::fs::File::create(p).unwrap();
        writeln!(f, "{SHEADER}").unwrap();
        f
    });

    let table = structures();
    let mus = menu(all_mu);
    let mut rows: Vec<SRow> = Vec::new();
    let (mut n_cand, mut n_acc, mut n_strict, mut n_v2) = (0usize, 0usize, 0usize, 0usize);

    for s in &table {
        if let Some(f) = &only_structs {
            if !f.iter().any(|x| x == s.id) {
                continue;
            }
        }
        let ops: Vec<String> = if s.ops.is_empty() {
            vec![s.shape_opcode.to_string()]
        } else {
            s.ops
                .iter()
                .filter(|o| only_ops.as_ref().is_none_or(|v| v.iter().any(|x| x == *o)))
                .map(|o| o.to_string())
                .collect()
        };
        for opname in ops {
            let seed_id = seed_id_of(s, &opname);
            let seed = (s.build)(&sargs(s, &opname));
            // pc = u32::MAX never matches a real pc => an unarmed, honest run.
            let baseline = spawn_sjob(
                &exe,
                s.id,
                s.variant,
                s.tag,
                &opname,
                u32::MAX,
                -1,
                wb_perturb::MU_XORBIT,
                0,
            );
            println!(
                "[baseline] {seed_id}: {} {} pv={} rootOut={} {}",
                baseline.outcome,
                baseline.failure_stage,
                baseline.pv_hex,
                baseline.root_out_hex,
                baseline.reason
            );
            if baseline.outcome != "ACCEPT" {
                println!("  -> SKIPPED (baseline does not verify)");
                continue;
            }

            let mut jobs_list: Vec<(u32, Role, i64, String, String, usize, i64)> = Vec::new();
            for (i, (pc, role)) in seed.sites.iter().enumerate() {
                if i % stride != 0 {
                    continue;
                }
                for nth in s.nths {
                    for (label, tmpl, kind, arg) in &mus {
                        if !mu_allowed(*role, label) {
                            continue;
                        }
                        jobs_list.push((
                            *pc,
                            *role,
                            *nth,
                            label.to_string(),
                            tmpl.to_string(),
                            *kind,
                            *arg,
                        ));
                    }
                }
            }
            println!("  {seed_id}: {} candidates", jobs_list.len());

            for chunk in jobs_list.chunks(jobs) {
                let mut handles = Vec::new();
                for (pc, role, nth, label, tmpl, kind, arg) in chunk.iter().cloned() {
                    let exe = exe.clone();
                    let (id, variant, stag, opn) =
                        (s.id, s.variant, s.tag, opname.clone());
                    handles.push(std::thread::spawn(move || {
                        let o = spawn_sjob(&exe, id, variant, stag, &opn, pc, nth, kind, arg);
                        (pc, role, nth, label, tmpl, kind, arg, o)
                    }));
                }
                for h in handles {
                    let (pc, role, nth, label, tmpl, kind, arg, o) = h.join().unwrap();
                    let row = SRow {
                        seed_id: seed_id.clone(),
                        structure_id: s.id,
                        published: s.published,
                        variant: s.variant,
                        opcode: opname.clone(),
                        class: s.class,
                        scored: s.scored,
                        operand_source: s.operand_source,
                        pc,
                        nth,
                        role,
                        mu_label: label,
                        template: tmpl,
                        kind,
                        arg,
                        o,
                    };
                    n_cand += 1;
                    if row.o.outcome == "ACCEPT" {
                        n_acc += 1;
                    }
                    if strict_pred(&row.o, &baseline) {
                        n_strict += 1;
                        println!(
                            "ACCEPTED CASE (strict): {} pc={:#x} nth={} mu={} out {} -> {}",
                            row.seed_id, row.pc, row.nth, row.mu_label, baseline.pv_hex, row.o.pv_hex
                        );
                    } else if v2_pred(&row.o, &baseline) {
                        n_v2 += 1;
                        println!(
                            "ACCEPTED CASE (v2, {}): {} pc={:#x} nth={} mu={} rootOut {} -> {}",
                            row.scored,
                            row.seed_id,
                            row.pc,
                            row.nth,
                            row.mu_label,
                            baseline.root_out_hex,
                            row.o.root_out_hex
                        );
                    }
                    semit(&mut file, &tag, &row, &baseline);
                    rows.push(row);
                }
            }
        }
    }
    println!(
        "RESULT candidates={n_cand} accepts={n_acc} accepted_cases_strict={n_strict} accepted_cases_v2_only={n_v2}"
    );
}

/// Structure smoke test: build every table row, run ONE honest (unarmed)
/// candidate through the real pipeline and require the real verifier to accept
/// it. A structure whose HONEST seed does not verify cannot say anything about
/// the constraint system, so this is the gate a new row has to pass before it
/// is enumerated.
#[test]
#[ignore = "runs one real proof per structure row"]
fn lacuna_structure_smoke() {
    let only: Option<Vec<String>> = std::env::var("LACUNA_STRUCTS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let mut bad = Vec::new();
    for s in structures() {
        if let Some(f) = &only {
            if !f.iter().any(|x| x == s.id) {
                continue;
            }
        }
        let opname = if s.ops.is_empty() {
            s.shape_opcode.to_string()
        } else {
            s.ops[0].to_string()
        };
        let seed_id = seed_id_of(&s, &opname);
        let seed = (s.build)(&sargs(&s, &opname));
        let (n_sites, n_insns) = (seed.sites.len(), seed.insns);
        let build = || (s.build)(&sargs(&s, &opname)).program;
        let o = if s.hint {
            run_pipeline(build, HintSyscall, u32::MAX, -1, wb_perturb::MU_XORBIT, 0)
        } else {
            run_pipeline(build, NullSyscall, u32::MAX, -1, wb_perturb::MU_XORBIT, 0)
        };
        println!(
            "{seed_id}: {} {} insns={n_insns} sites={n_sites} pv={} rootOut={} ({}ms prove) {}",
            o.outcome, o.failure_stage, o.pv_hex, o.root_out_hex, o.t_prove_ms, o.reason
        );
        if o.outcome != "ACCEPT" {
            bad.push(seed_id);
        }
    }
    assert!(bad.is_empty(), "honest seeds that did not verify: {bad:?}");
}

// ===========================================================================
// VERIFICATION PASS (added by the review stage, purely additive)
//
// An INDEPENDENT honest-baseline census over the structure table. It does not
// share code with `lacuna_structure_smoke`: it rebuilds every seed, runs the
// honest executor and the UNARMED preflight itself, and reads the segment's
// executed-cycle count straight out of the `GlobalsWitness` the preflight put
// at the front of `aux`, which the rest of the driver never prints.
//
// Reported per seed: honest executor + preflight success, the circuit's own
// `finalCycle` (executed steps), static instruction count, the number of
// write-back sites the seed DECLARES, and the honest `rootOut`. Whether the
// real prover and the real verifier accept the honest seed is measured
// separately by `lacuna_structure_smoke` / the driver's `[baseline]` pass, so
// this test deliberately skips the (expensive) proof.
// ===========================================================================

/// `GlobalsWitness` word offsets in `preflight.aux`:
/// `{ FpDigest rootIn; FpDigest rootOut; u32 p2Count; u32 finalCycle; ... }`.
fn globals_final_cycle(aux: &[u32]) -> u32 {
    let n = std::mem::size_of::<risc0_circuit_rv32im_sys::FpDigest>() / 4;
    aux[2 * n + 1]
}

#[test]
#[ignore = "verification: honest execute+preflight census over the structure table"]
fn lacuna_verify_honest_census() {
    let only_structs: Option<Vec<String>> = std::env::var("LACUNA_STRUCTS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let only_ops: Option<Vec<String>> = std::env::var("LACUNA_OPS")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let mut bad = Vec::new();
    let mut n_seeds = 0usize;
    for s in structures() {
        if let Some(f) = &only_structs {
            if !f.iter().any(|x| x == s.id) {
                continue;
            }
        }
        let ops: Vec<String> = if s.ops.is_empty() {
            vec![s.shape_opcode.to_string()]
        } else {
            s.ops
                .iter()
                .filter(|o| only_ops.as_ref().is_none_or(|v| v.iter().any(|x| x == *o)))
                .map(|o| o.to_string())
                .collect()
        };
        for opname in ops {
            n_seeds += 1;
            let seed_id = seed_id_of(&s, &opname);
            let seed = (s.build)(&sargs(&s, &opname));
            let (n_sites, n_insns) = (seed.sites.len(), seed.insns);
            let mut image = MemoryImage::new_kernel(seed.program);
            let mut segments = Vec::new();
            let limit = ExecutionLimit::default()
                .with_segment_po2(PO2)
                .with_hard_session_limit(1 << 20);
            let exec = if s.hint {
                Executor::new(
                    image.clone(),
                    HintSyscall,
                    None,
                    Vec::new(),
                    None,
                    RV32IM_M3_CIRCUIT_VERSION,
                )
                .run(limit.clone(), |u: SegmentUpdate| {
                    segments.push(u.apply_into_segment(&mut image)?);
                    Ok(())
                })
            } else {
                Executor::new(
                    image.clone(),
                    NullSyscall,
                    None,
                    Vec::new(),
                    None,
                    RV32IM_M3_CIRCUIT_VERSION,
                )
                .run(limit.clone(), |u: SegmentUpdate| {
                    segments.push(u.apply_into_segment(&mut image)?);
                    Ok(())
                })
            };
            if let Err(e) = exec {
                println!("{seed_id}: EXEC-FAIL insns={n_insns} sites={n_sites} {e}");
                bad.push(seed_id);
                continue;
            }
            if segments.len() != 1 {
                println!(
                    "{seed_id}: SEGMENTS={} insns={n_insns} sites={n_sites}",
                    segments.len()
                );
                bad.push(seed_id);
                continue;
            }
            let pf = SegmentContext::new(&segments[0]).and_then(|c| c.preflight(PO2));
            match pf {
                Ok(p) => println!(
                    "{seed_id}: OK insns={n_insns} declared_sites={n_sites} \
                     final_cycle={} rootOut={}",
                    globals_final_cycle(&p.aux),
                    root_out_hex(&p.aux),
                ),
                Err(e) => {
                    println!("{seed_id}: PREFLIGHT-FAIL insns={n_insns} sites={n_sites} {e}");
                    bad.push(seed_id);
                }
            }
        }
    }
    println!("CENSUS seeds={n_seeds} failing={}", bad.len());
    assert!(bad.is_empty(), "seeds whose honest run failed: {bad:?}");
}
