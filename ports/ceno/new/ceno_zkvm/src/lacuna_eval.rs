//! LACUNA EVALUATION DRIVER for ceno — instrumented, candidate-level enumeration
//! of ENCODING mutations on the ceno execution record (`ceno_emul::StepRecord`).
//!
//! Contains no bug knowledge. It enumerates
//!
//!     site = (static pc, n-th execution of that pc)
//!     mu   = one entry of an instruction-independent rewriting menu
//!
//! over ceno's single architectural write-back choke point
//! (`ceno_emul::wb_perturb::on_write_back`, called from `VMState::store_register`,
//! `ceno_emul/src/vm_state.rs`), and lets ceno's own emulator continue from the
//! perturbed value so every later register read, dependent store, memory record and
//! public commit follows naturally.
//!
//! Every candidate goes through the REAL pipeline: honest keygen -> perturbed
//! emulation -> `generate_witness` -> `ZKVMProver::create_proof` (GKR + Basefold)
//! -> `ZKVMVerifier::verify_full_trace_proofs_halt`. Nothing here is a MockProver,
//! a debug satisfiability check, or a per-chip AIR check.
//!
//! OBSERVABILITY. The seed program routes the operation's result into ceno's real
//! public output: it stores rd into the 8-word PUB_IO_COMMIT buffer and issues the
//! `PUB_IO_COMMIT` ecall. `PubioCommitLayout` (ceno_zkvm/src/precompiles/pubio_commit.rs)
//! binds those 8 memory words to the `public_io_digest` public-value instances
//! (`PublicValues::public_io_digest`, ceno_zkvm/src/scheme.rs:100), so the committed
//! public output of the proof literally contains the operation's result word.
//!
//! Environment (all optional):
//!   LACUNA_OUT    path of the CSV to append to (default: stdout only)
//!   LACUNA_TAG    free-form run tag copied into every row
//!   LACUNA_OPS    comma-separated opcode names to enumerate (default: all)
//!   LACUNA_MU     "xorb0" (single mu) | "all" (the 11-entry menu, default)
//!   LACUNA_SITES  "op" (only the op-under-test write-back, default) | "all"

use ceno_emul::{
    CENO_PLATFORM, EmuContext, FullTracer, FullTracerConfig, InsnKind, Program, PubIoCommitSpec,
    StepCellExtractor, SyscallSpec, VMState, WordAddr, encode_rv32, encode_rv32u, ts_perturb,
    wb_perturb,
};
use ff_ext::BabyBearExt4;
use gkr_iop::cpu::default_backend_config;
use mpcs::BasefoldDefault;
use std::{io::Write, sync::Arc, time::Instant};
use transcript::BasicTranscript;

use crate::{
    e2e::{MultiProver, Preset, emulate_program, generate_witness, setup_platform, setup_program},
    scheme::{
        create_backend, create_prover,
        hal::ProverDevice,
        prover::ZKVMProver,
        verifier::{RV32imMemStateConfig, ZKVMVerifier},
    },
};

type E = BabyBearExt4;
type Pcs = BasefoldDefault<E>;

const REV: &str = "13c5abf3";
const TARGET: &str = "ceno";

/// Byte address of the 8-word PUB_IO_COMMIT digest buffer. Lives in `program.image`,
/// hence in `platform.prog_data`, hence writable (`Platform::is_ram`).
const DIGEST_PTR: u32 = 0x0800_1000;
const DIGEST_WORDS: usize = 8;

/// LACUNA seed — program structure: Single operation.
///
/// ```text
/// p0: LUI  x6, DIGEST_PTR      ; x6 = commit buffer
/// p1: ADDI x2, x0, a           ; x2 = a
/// p2: ADDI x3, x0, b           ; x3 = b
/// p3: OP   x4, x2, x3          ; x4 = a OP b     <- the operation under test
/// p4: SW   x4, 0(x6)           ; digest[0] = x4  <- routes the result to the commit
/// p5: ADDI x10, x6, 0          ; a0 = &digest
/// p6: ADDI x5, x0, PUB_IO_COMMIT
/// p7: ECALL                    ; commit digest[0..8] as the proof's public output
/// p8: ADDI x5, x0, 0           ; t0 = ecall HALT
/// p9: ADDI x10, x0, 0          ; a0 = exit code 0
/// p10: ECALL                   ; halt
/// ```
/// The store at p4 plus the commit at p7 are what make the operation's result
/// publicly observable; without them a mutation could be accepted without changing
/// anything a verifier is shown.
fn build_op_program(op: InsnKind, a: i32, b: i32) -> Program {
    let insns = vec![
        encode_rv32u(InsnKind::LUI, 0, 0, 6, DIGEST_PTR),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, a),
        encode_rv32(InsnKind::ADDI, 0, 0, 3, b),
        encode_rv32(op, 2, 3, 4, 0),
        encode_rv32(InsnKind::SW, 6, 4, 0, 0),
        encode_rv32(InsnKind::ADDI, 6, 0, 10, 0),
        encode_rv32u(InsnKind::ADDI, 0, 0, 5, PubIoCommitSpec::CODE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32u(InsnKind::ADDI, 0, 0, 5, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 10, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    // static memory init table requires a power-of-two count >= 2 (no padding);
    // the 8 contiguous digest words are exactly that.
    let mut image = std::collections::BTreeMap::new();
    for k in 0..DIGEST_WORDS as u32 {
        image.insert(DIGEST_PTR + k * 4, 0u32);
    }
    Program::new(pc, pc, CENO_PLATFORM.heap.start, insns, image)
}

/// The instruction-independent rewriting menu. (label, template, mu_kind, mu_arg)
/// Mirrors the pico / nexus menus so the targets are directly comparable; the word
/// width is 32 bits, so the limb indices are i in {0,1} for B = 2^16 and the
/// boundary values are {0, 2^31, 2^32 - 1}.
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

/// Every opcode the seed builder can put at p3 and that writes a register through
/// a proving-configuration circuit (see `instructions/riscv/rv32im.rs:280-297`).
fn opcodes() -> Vec<(&'static str, InsnKind)> {
    use InsnKind::*;
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
    ]
}

/// Seed operands (12-bit signed ADDI immediates). Override with LACUNA_A / LACUNA_B.
fn operands() -> (i32, i32) {
    let a = std::env::var("LACUNA_A")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0x5A5);
    let b = std::env::var("LACUNA_B")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(13);
    (a, b)
}

fn hexwords(w: &[u32]) -> String {
    w.iter()
        .map(|x| format!("{x:08x}"))
        .collect::<Vec<_>>()
        .join("")
}

// ===================== LACUNA CPU CALIBRATION (additive) =====================
// Nothing below changes the pipeline; it only reads clocks around the existing
// stage boundaries and appends extra CSV columns.

/// Process CPU time (user + system) in ms, summed over EVERY thread of this
/// process. Read from /proc/self/stat fields 14 (utime) and 15 (stime), which the
/// kernel already aggregates over the whole thread group. USER_HZ on this host is
/// 100 (`getconf CLK_TCK`), so one tick = 10 ms.
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
    (ut + st) * 10
}

/// Per-candidate wall/CPU accumulators. A `*_seen` flag that is false means the
/// stage never executed for this candidate; that cell is emitted as `NA`, never 0.
#[derive(Clone, Copy, Default)]
struct Stages {
    s1_wall: i64,
    s1_cpu: i64,
    s1_seen: bool,
    s2_wall: i64,
    s2_cpu: i64,
    s2_seen: bool,
    s3_wall: i64,
    s3_cpu: i64,
    s3_seen: bool,
    s4_wall: i64,
    s4_cpu: i64,
    s4_seen: bool,
    tot_wall: i64,
    tot_cpu: i64,
    tot_seen: bool,
    // informative sub-split of S2 (preflight emulate_program vs. the lazy
    // generate_witness iterator pulls); not part of the required output.
    s2a_wall: i64,
    s2a_cpu: i64,
    s2b_wall: i64,
    s2b_cpu: i64,
    /// CPU (ms) charged to this process during a deliberate 60 ms IDLE window
    /// taken just before the candidate starts. It is pure measurement noise:
    /// rayon spin-down from the previous candidate plus 100 Hz tick quantisation
    /// spread over ~192 threads. It is the noise floor for every other cell.
    idle60_cpu: i64,
}

fn cell(v: i64, seen: bool) -> String {
    if seen {
        v.to_string()
    } else {
        "NA".to_string()
    }
}

impl Stages {
    /// 14 appended CSV cells, in the order of `STAGE_HEADER`.
    fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            cell(self.s1_wall, self.s1_seen),
            cell(self.s1_cpu, self.s1_seen),
            cell(self.s2_wall, self.s2_seen),
            cell(self.s2_cpu, self.s2_seen),
            cell(self.s3_wall, self.s3_seen),
            cell(self.s3_cpu, self.s3_seen),
            cell(self.s4_wall, self.s4_seen),
            cell(self.s4_cpu, self.s4_seen),
            cell(self.tot_wall, self.tot_seen),
            cell(self.tot_cpu, self.tot_seen),
            cell(self.s2a_wall, self.s2_seen),
            cell(self.s2a_cpu, self.s2_seen),
            cell(self.s2b_wall, self.s2_seen),
            cell(self.s2b_cpu, self.s2_seen),
        ) + &format!(",{}", self.idle60_cpu)
    }
}

const STAGE_HEADER: &str = ",s1_replay_wall_ms,s1_replay_cpu_ms,s2_tracegen_wall_ms,\
s2_tracegen_cpu_ms,s3_prove_wall_ms,s3_prove_cpu_ms,s4_verify_wall_ms,s4_verify_cpu_ms,\
cand_total_wall_ms,cand_total_cpu_ms,s2a_preflight_wall_ms,s2a_preflight_cpu_ms,\
s2b_witgen_wall_ms,s2b_witgen_cpu_ms,idle60_cpu_ms";
// =========================== end CPU CALIBRATION ============================

fn trunc(s: &str) -> String {
    let s = s.replace(['\n', ',', '"', '\r'], " ");
    s.chars().take(160).collect()
}

/// Cheap armed pre-pass: run the plain emulator so we learn what the perturbed
/// execution actually commits (the 8 digest words), plus hits / honest / forged.
/// The digest must be known before `emulate_program`, which folds it into
/// `PublicValues`.
struct PrePass {
    digest: [u32; DIGEST_WORDS],
    hits: usize,
    honest_v: u64,
    forged_v: u64,
    exec_err: Option<String>,
    steps: usize,
}

fn prepass(program: &Arc<Program>, platform: &ceno_emul::Platform, arm: &Arm) -> PrePass {
    let mut vm: VMState<FullTracer> = VMState::new_with_tracer_config(
        platform.clone(),
        program.clone(),
        FullTracerConfig {
            max_step_shard: 1024,
        },
    );
    let mut exec_err = None;
    let mut steps = 0usize;
    {
        let mut it = vm.iter_until_halt();
        while let Some(r) = it.next() {
            match r {
                Ok(_) => steps += 1,
                Err(e) => {
                    exec_err = Some(format!("{e}"));
                    break;
                }
            }
            if steps > 512 {
                exec_err = Some("step budget exceeded".into());
                break;
            }
        }
    }
    let mut digest = [0u32; DIGEST_WORDS];
    if exec_err.is_none() {
        for (k, d) in digest.iter_mut().enumerate() {
            *d = vm.peek_memory(WordAddr::from(DIGEST_PTR + (k as u32) * 4));
        }
    }
    PrePass {
        digest,
        hits: arm.hits(),
        honest_v: arm.honest(),
        forged_v: arm.forged(),
        exec_err,
        steps,
    }
}

/// Which record-layer family this candidate arms, and with what.
#[derive(Clone, Copy)]
enum Arm {
    /// honest baseline: nothing armed
    None,
    /// ENCODING family: rewrite the architectural write-back value
    Enc { pc: u32, kind: usize, arg: i64 },
    /// ORDER family: rewrite the recorded `previous_cycle` of one access subcycle
    Ord {
        pc: u32,
        sub: i64,
        kind: usize,
        arg: i64,
    },
}

impl Arm {
    /// nth = -1 everywhere: arm EVERY execution of the static pc. ceno emulates the
    /// program more than once inside one candidate (the cheap pre-pass, the
    /// preflight pass in `emulate_program`, and the witness replay in
    /// `generate_witness`); arming only one of them would desynchronise them and
    /// produce a rejection that says nothing about the constraint system.
    fn scope<Res>(&self, body: impl FnOnce() -> Res) -> Res {
        match *self {
            Arm::None => wb_perturb::with(u32::MAX, -1, wb_perturb::MU_XORBIT, 0, body),
            Arm::Enc { pc, kind, arg } => wb_perturb::with(pc, -1, kind, arg, body),
            Arm::Ord { pc, sub, kind, arg } => ts_perturb::with(pc, sub, -1, kind, arg, body),
        }
    }
    fn hits(&self) -> usize {
        match self {
            Arm::Ord { .. } => ts_perturb::hits(),
            _ => wb_perturb::hits(),
        }
    }
    fn honest(&self) -> u64 {
        match self {
            Arm::Ord { .. } => ts_perturb::honest_value(),
            _ => wb_perturb::honest_value() as u64,
        }
    }
    fn forged(&self) -> u64 {
        match self {
            Arm::Ord { .. } => ts_perturb::forged_value(),
            _ => wb_perturb::forged_value() as u64,
        }
    }
}

struct Out {
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    hits: usize,
    digest: Option<[u32; DIGEST_WORDS]>,
    honest_v: u64,
    forged_v: u64,
    exit_code: u32,
    t_record_ms: u128,
    t_prove_ms: u128,
    t_verify_ms: u128,
    st: Stages,
}

type Prover = crate::scheme::prover::ZkVMCpuProver<E, Pcs>;

/// One candidate through the REAL pipeline, reusing the seed's honest pk/vk.
#[allow(clippy::too_many_arguments)]
fn run_candidate(
    program: &Arc<Program>,
    platform: &ceno_emul::Platform,
    prover: &Prover,
    verifier: &ZKVMVerifier<E, Pcs, RV32imMemStateConfig>,
    arm: Arm,
) -> Out {
    let mut st = Stages::default();
    // Calibration control + settle. 60 ms in which the process is deliberately
    // doing nothing, measured with the same clock. Whatever CPU it reports is
    // measurement noise, and taking it here also drains the previous candidate's
    // rayon spin-down so it is not charged to this candidate's S1.
    let idle_c0 = cpu_ms();
    std::thread::sleep(std::time::Duration::from_millis(60));
    st.idle60_cpu = cpu_ms().saturating_sub(idle_c0) as i64;
    let cal_c0 = cpu_ms();
    let cal_w0 = Instant::now();
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // nth = -1: arm EVERY execution of this static pc. ceno emulates the program
        // twice inside the proving pipeline (the preflight pass in `emulate_program`
        // and the witness replay in `generate_witness`); perturbing only one of them
        // would desynchronise the two and produce a rejection that says nothing about
        // the constraint system.
        // ---- S1: mutation construction + armed suffix replay ----
        let s1_c0 = cpu_ms();
        let t0 = Instant::now();
        let pre = arm.scope(|| prepass(program, platform, &arm));
        let t_record = t0.elapsed().as_millis();
        st.s1_wall = t_record as i64;
        st.s1_cpu = cpu_ms().saturating_sub(s1_c0) as i64;
        st.s1_seen = true;
        if let Some(e) = pre.exec_err {
            return Err((
                "exec: ".to_string() + &e,
                t_record,
                pre.hits,
                pre.honest_v,
                pre.forged_v,
            ));
        }
        let _ = pre.steps;

        let res = arm.scope(|| {
            let init_full_mem = prover.setup_init_mem(&[]);
            let max_steps = 1usize << 20;
            let pctx = prover.pk.program_ctx.as_ref().unwrap();
            let raw = Arc::clone(&pctx.system_config.config);
            let step_cell_extractor: Arc<dyn StepCellExtractor> = raw;
            // ---- S2a: preflight execution -> EmulationResult (the trace) ----
            let s2a_c0 = cpu_ms();
            let s2a_w0 = Instant::now();
            let emul_result = emulate_program(
                pctx.program.clone(),
                max_steps,
                &init_full_mem,
                pre.digest,
                &pctx.platform,
                &pctx.multi_prover,
                step_cell_extractor,
            );
            st.s2a_wall = s2a_w0.elapsed().as_millis() as i64;
            st.s2a_cpu = cpu_ms().saturating_sub(s2a_c0) as i64;
            let exit_code = emul_result.exit_code;
            // `generate_witness` returns a LAZY `std::iter::from_fn` (e2e.rs:1356):
            // this call itself does no witness work, every shard's witness is built
            // by the `.next()` below, which is why the pull is timed separately.
            let mut wit_iter = generate_witness(
                &pctx.system_config,
                emul_result,
                pctx.program.clone(),
                &pctx.platform,
                &init_full_mem,
                None,
            );
            let t1 = Instant::now();
            let mut proofs = Vec::new();
            let mut w_wit = 0i64;
            let mut c_wit = 0i64;
            let mut w_prv = 0i64;
            let mut c_prv = 0i64;
            loop {
                // ---- S2b: this shard's witness generation ----
                let wc0 = cpu_ms();
                let ww0 = Instant::now();
                let nxt = wit_iter.next();
                w_wit += ww0.elapsed().as_millis() as i64;
                c_wit += cpu_ms().saturating_sub(wc0) as i64;
                let (zkvm_witness, shard_ctx, pi, _baseline) = match nxt {
                    Some(x) => x,
                    None => break,
                };
                // ---- S3: proof generation for this shard ----
                let pc0 = cpu_ms();
                let pw0 = Instant::now();
                let transcript = BasicTranscript::new(b"riscv");
                let pr = prover.create_proof(&shard_ctx, zkvm_witness, pi, transcript);
                w_prv += pw0.elapsed().as_millis() as i64;
                c_prv += cpu_ms().saturating_sub(pc0) as i64;
                match pr {
                    Ok(p) => proofs.push(p),
                    Err(e) => {
                        st.s2b_wall = w_wit;
                        st.s2b_cpu = c_wit;
                        st.s2_wall = st.s2a_wall + w_wit;
                        st.s2_cpu = st.s2a_cpu + c_wit;
                        st.s2_seen = true;
                        st.s3_wall = w_prv;
                        st.s3_cpu = c_prv;
                        st.s3_seen = true;
                        return Err(format!("prove: {e:?}"));
                    }
                }
            }
            st.s2b_wall = w_wit;
            st.s2b_cpu = c_wit;
            st.s2_wall = st.s2a_wall + w_wit;
            st.s2_cpu = st.s2a_cpu + c_wit;
            st.s2_seen = true;
            st.s3_wall = w_prv;
            st.s3_cpu = c_prv;
            st.s3_seen = true;
            // unchanged semantics: t_prove_ms stays "witness pull + create_proof",
            // exactly what the original enumeration recorded.
            let t_prove = t1.elapsed().as_millis();
            let transcripts = (0..proofs.len())
                .map(|_| BasicTranscript::new(b"riscv"))
                .collect::<Vec<_>>();
            let expect_halt = exit_code.is_some();
            // ---- S4: verification ----
            let s4_c0 = cpu_ms();
            let t2 = Instant::now();
            let v = verifier.verify_full_trace_proofs_halt(proofs, transcripts, expect_halt);
            let t_verify = t2.elapsed().as_millis();
            st.s4_wall = t_verify as i64;
            st.s4_cpu = cpu_ms().saturating_sub(s4_c0) as i64;
            st.s4_seen = true;
            Ok((v, exit_code.unwrap_or(0), t_prove, t_verify))
        });
        match res {
            Ok((v, exit_code, tp, tv)) => Ok((
                v,
                exit_code,
                pre.digest,
                pre.hits,
                pre.honest_v,
                pre.forged_v,
                t_record,
                tp,
                tv,
            )),
            Err(msg) => Err((msg, t_record, pre.hits, pre.honest_v, pre.forged_v)),
        }
    }));
    std::panic::set_hook(prev_hook);
    st.tot_wall = cal_w0.elapsed().as_millis() as i64;
    st.tot_cpu = cpu_ms().saturating_sub(cal_c0) as i64;
    st.tot_seen = true;
    match r {
        Ok(Ok((v, exit_code, digest, hits, hv, fv, tr, tp, tv))) => {
            let (outcome, stage, reason) = match v {
                Ok(true) => {
                    if hits > 0 {
                        ("ACCEPT", "accepted_proof", String::new())
                    } else {
                        ("NOOP", "mutation", String::new())
                    }
                }
                Ok(false) => ("REJECT", "verify", "verifier returned false".to_string()),
                Err(e) => ("REJECT", "verify", trunc(&format!("{e:?}"))),
            };
            Out {
                outcome,
                failure_stage: stage,
                reason,
                hits,
                digest: Some(digest),
                honest_v: hv,
                forged_v: fv,
                exit_code,
                t_record_ms: tr,
                t_prove_ms: tp,
                t_verify_ms: tv,
                st,
            }
        }
        Ok(Err((msg, tr, hits, hv, fv))) => {
            let proveish = msg.starts_with("prove:");
            Out {
                outcome: if proveish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if proveish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits,
                digest: None,
                honest_v: hv,
                forged_v: fv,
                exit_code: 0,
                t_record_ms: tr,
                t_prove_ms: 0,
                t_verify_ms: 0,
                st,
            }
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque>".to_string());
            // A panic out of the emulator / host memory model is an EXECFAIL, not a
            // constraint rejection. Only panics that name a proof-system failure are
            // charged to the prove stage. NOTE: a bare "assertion failed" is NOT a
            // constraint marker — `ceno_emul::utils::MemoryView::new` and
            // `DenseAddrSpace` both panic that way on a perturbed pointer.
            let constraintish = msg.contains("prod_r")
                || msg.contains("logup")
                || msg.contains("constraint")
                || msg.contains("Constraint")
                || msg.contains("commitment")
                || msg.contains("InvalidProof");
            Out {
                outcome: if constraintish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if constraintish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits: arm.hits(),
                digest: None,
                honest_v: arm.honest(),
                forged_v: arm.forged(),
                exit_code: 0,
                t_record_ms: 0,
                t_prove_ms: 0,
                t_verify_ms: 0,
                st,
            }
        }
    }
}

#[test]
#[ignore = "LACUNA evaluation run: ceno record-layer encoding enumeration; use --release and RUST_MIN_STACK"]
fn lacuna_encoding_enumeration_ceno() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "ceno".to_string());
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let sites_all = std::env::var("LACUNA_SITES").unwrap_or_else(|_| "op".to_string()) == "all";
    let want: Vec<String> = std::env::var("LACUNA_OPS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Operands: non-degenerate, and small enough for the 12-bit ADDI immediate.
    let (a, b) = operands();

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
committed_digest,honest_committed_digest,digest_changed";
    let header = format!("{header}{STAGE_HEADER}");
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    for (name, op) in opcodes() {
        if !want.is_empty() && !want.contains(&name.to_string()) {
            continue;
        }
        let seed = format!("op_{}", name.to_lowercase());
        let program = Arc::new(build_op_program(op, a, b));
        let platform = setup_platform(Preset::Ceno, &program, 1 << 16, 1 << 16);

        // ---- keygen from the HONEST program (vk independent of any mutation) ----
        let (max_num_variables, security_level) = default_backend_config();
        let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
        let device = create_prover(backend);
        let ctx = setup_program::<E>((*program).clone(), platform.clone(), MultiProver::default());
        let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
        let prover = ZKVMProver::new(pk.into(), device);
        let verifier = ZKVMVerifier::<E, Pcs, RV32imMemStateConfig>::new(vk);

        // ---- honest baseline: prove AND verify before any mutation ----
        let h = run_candidate(&program, &platform, &prover, &verifier, Arm::None);
        if h.outcome != "NOOP" {
            // NOOP is the honest run: the site pc = u32::MAX never fires.
            println!(
                "LACUNA_BASELINE,{tag},{TARGET},{seed},BASELINE_NOT_ACCEPTED,{},{},{}",
                h.outcome, h.failure_stage, h.reason
            );
            continue;
        }
        let honest_digest = h.digest.expect("honest digest");
        let honest_hex = hexwords(&honest_digest);
        let honest_committed = format!("exit{:08x}", h.exit_code);
        println!(
            "LACUNA_BASELINE,{tag},{TARGET},{seed},VERIFIED,honest_pv={honest_hex},\
t_prove_ms={},t_verify_ms={},stages={}",
            h.t_prove_ms,
            h.t_verify_ms,
            h.st.csv()
        );

        // ---- sites: static pcs of the honest trace that write a register ----
        let sites: Vec<(u32, usize)> = {
            let pcbase = CENO_PLATFORM.pc_base();
            let op_pc = pcbase + 3 * 4;
            if sites_all {
                let mut v = vec![];
                for (i, insn) in program.instructions.iter().enumerate() {
                    if insn.rd != 0 {
                        v.push((pcbase + (i as u32) * 4, 1usize));
                    }
                }
                v
            } else {
                vec![(op_pc, 1usize)]
            }
        };
        // LACUNA_PC=0x...,0x...: restrict to these static pcs (re-run support).
        let sites: Vec<(u32, usize)> = match std::env::var("LACUNA_PC") {
            Ok(v) if !v.trim().is_empty() => {
                let want: Vec<u32> = v
                    .split(',')
                    .filter_map(|t| {
                        let t = t.trim().trim_start_matches("0x");
                        u32::from_str_radix(t, 16).ok()
                    })
                    .collect();
                sites
                    .into_iter()
                    .filter(|(pc, _)| want.contains(pc))
                    .collect()
            }
            _ => sites,
        };

        for (pc, execs) in &sites {
            for (label, template, mkind, marg) in menu(mu_all) {
                let c = run_candidate(
                    &program,
                    &platform,
                    &prover,
                    &verifier,
                    Arm::Enc {
                        pc: *pc,
                        kind: mkind,
                        arg: marg,
                    },
                );
                let pv_hex = c
                    .digest
                    .map(|d| hexwords(&d))
                    .unwrap_or_else(|| "NONE".to_string());
                let nonempty = pv_hex != "NONE" && !pv_hex.is_empty();
                let changed = c.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
                let accepted = c.outcome == "ACCEPT" && c.hits > 0 && changed;
                let committed = format!("exit{:08x}", c.exit_code);
                let digest_changed = committed != honest_committed;
                let row = format!(
                    "{tag},{TARGET},{REV},{seed},encoding,Single operation,{name},{pc:#x},-1,\
false,false,{execs},{label},{template},{mkind},{marg},{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{}",
                    c.outcome,
                    c.failure_stage,
                    c.hits,
                    pv_hex,
                    honest_hex,
                    changed,
                    accepted,
                    c.t_record_ms,
                    c.t_prove_ms,
                    c.t_verify_ms,
                    c.reason,
                    committed,
                    honest_committed,
                    digest_changed
                );
                let row = format!("{row},{}", c.st.csv());
                println!("LACUNA_ROW,{row}");
                if let Some(f) = sink.as_mut() {
                    writeln!(f, "{row}").unwrap();
                    f.flush().ok();
                }
                if accepted {
                    println!(
                        "  *** ACCEPTED CASE: {name} @ {pc:#x} mu={label}  honest write-back \
{:#x} -> {:#x}; committed public output {honest_hex} -> {pv_hex}",
                        c.honest_v, c.forged_v
                    );
                }
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}

/// The ORDER (timestamp) menu. (label, template, mu_kind, mu_arg)
///
/// `op.previous_cycle` is the record field: it feeds the `prev_ts` witness column,
/// the `lt_cfg` AssertLt and the `shard_ctx.send` RAM record
/// (ceno_zkvm/src/instructions/riscv/insn_base.rs:124,127-132,133-141).
fn order_menu() -> Vec<(&'static str, &'static str, usize, i64)> {
    vec![
        ("prev_plus1", "ORD-O1", ts_perturb::MU_ADDK, 1),
        ("prev_minus1", "ORD-O1", ts_perturb::MU_ADDK, -1),
        ("prev_plus4", "ORD-O1", ts_perturb::MU_ADDK, 4),
        ("prev_minus4", "ORD-O1", ts_perturb::MU_ADDK, -4),
        ("prev_zero", "ORD-O2", ts_perturb::MU_ZERO, 0),
        ("prev_set8", "ORD-O3", ts_perturb::MU_SET, 8),
    ]
}

/// ORDER-family enumeration. NOTE ON OBSERVABILITY: this hook rewrites only the
/// recorded `previous_cycle`; it does not change any value the guest computes, so a
/// candidate that the verifier accepts here is a "verifier accepted but the
/// committed public output is unchanged" outcome — a necessary precursor to a
/// stale-read forgery, NOT an accepted case. `accepted_case` therefore stays false
/// by construction and the interesting column is `outcome`.
#[test]
#[ignore = "LACUNA evaluation run: ceno record-layer ORDER enumeration; use --release and RUST_MIN_STACK"]
fn lacuna_order_enumeration_ceno() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "ceno_order".to_string());
    let want: Vec<String> = std::env::var("LACUNA_OPS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    let (a, b) = operands();

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
committed_digest,honest_committed_digest,digest_changed";
    let header = format!("{header}{STAGE_HEADER}");
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    for (name, op) in opcodes() {
        if !want.is_empty() && !want.contains(&name.to_string()) {
            continue;
        }
        let seed = format!("op_{}", name.to_lowercase());
        let program = Arc::new(build_op_program(op, a, b));
        let platform = setup_platform(Preset::Ceno, &program, 1 << 16, 1 << 16);

        let (max_num_variables, security_level) = default_backend_config();
        let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
        let device = create_prover(backend);
        let ctx = setup_program::<E>((*program).clone(), platform.clone(), MultiProver::default());
        let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
        let prover = ZKVMProver::new(pk.into(), device);
        let verifier = ZKVMVerifier::<E, Pcs, RV32imMemStateConfig>::new(vk);

        let h = run_candidate(&program, &platform, &prover, &verifier, Arm::None);
        if h.outcome != "NOOP" {
            println!(
                "LACUNA_BASELINE,{tag},{TARGET},{seed},BASELINE_NOT_ACCEPTED,{},{},{}",
                h.outcome, h.failure_stage, h.reason
            );
            continue;
        }
        let honest_digest = h.digest.expect("honest digest");
        let honest_hex = hexwords(&honest_digest);
        let honest_committed = format!("exit{:08x}", h.exit_code);
        println!(
            "LACUNA_BASELINE,{tag},{TARGET},{seed},VERIFIED,honest_pv={honest_hex},stages={}",
            h.st.csv()
        );

        let pcbase = CENO_PLATFORM.pc_base();
        // (pc, subcycle): the op under test (rs1/rs2/rd) and the SW that publishes it
        // (rs1/rs2/mem).
        let op_pc = pcbase + 3 * 4;
        let sw_pc = pcbase + 4 * 4;
        let sites: Vec<(u32, i64, &'static str)> = vec![
            (op_pc, 0, "rs1"),
            (op_pc, 1, "rs2"),
            (op_pc, 2, "rd"),
            (sw_pc, 0, "rs1"),
            (sw_pc, 1, "rs2"),
            (sw_pc, 3, "mem"),
        ];

        for (pc, sub, subname) in &sites {
            for (label, template, mkind, marg) in order_menu() {
                let c = run_candidate(
                    &program,
                    &platform,
                    &prover,
                    &verifier,
                    Arm::Ord {
                        pc: *pc,
                        sub: *sub,
                        kind: mkind,
                        arg: marg,
                    },
                );
                let pv_hex = c
                    .digest
                    .map(|d| hexwords(&d))
                    .unwrap_or_else(|| "NONE".to_string());
                let nonempty = pv_hex != "NONE" && !pv_hex.is_empty();
                let changed = c.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
                let accepted = c.outcome == "ACCEPT" && c.hits > 0 && changed;
                let committed = format!("exit{:08x}", c.exit_code);
                let digest_changed = committed != honest_committed;
                let mu_label = format!("{subname}_{label}");
                let row = format!(
                    "{tag},{TARGET},{REV},{seed},order,Single operation,{name},{pc:#x},-1,\
false,false,1,{mu_label},{template},{mkind},{marg},{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{}",
                    c.outcome,
                    c.failure_stage,
                    c.hits,
                    pv_hex,
                    honest_hex,
                    changed,
                    accepted,
                    c.t_record_ms,
                    c.t_prove_ms,
                    c.t_verify_ms,
                    c.reason,
                    committed,
                    honest_committed,
                    digest_changed
                );
                let row = format!("{row},{}", c.st.csv());
                println!("LACUNA_ROW,{row}");
                if let Some(f) = sink.as_mut() {
                    writeln!(f, "{row}").unwrap();
                    f.flush().ok();
                }
                if c.outcome == "ACCEPT" && c.hits > 0 {
                    println!(
                        "  *** VERIFIER-ACCEPTED ORDER MUTATION (output unchanged): {name} @ \
{pc:#x} sub={subname} mu={label}  prev_cycle {} -> {}",
                        c.honest_v, c.forged_v
                    );
                }
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}

// ============================================================================
// LACUNA PROGRAM-STRUCTURE CATALOG — ADDITIVE
//
// Everything below this line is additive. It adds new seed builders and one new
// enumeration entry point; it does NOT touch `build_op_program`, `menu`,
// `order_menu`, `run_candidate`, the acceptance predicate or any published
// `seed_id`, so `lacuna_encoding_enumeration_ceno` and
// `lacuna_order_enumeration_ceno` still run byte-identically.
//
// The structures, their `published_name` strings, their per-target status, the
// mu-menu role masks and the run-matrix rules R1-R8 are NORMATIVE and live in
//   evaluation/spec/STRUCTURE_MANIFEST.yaml
//   evaluation/spec/TARGET_CAPABILITIES.yaml
// This file implements ceno's column of that matrix. Where a cell is declared
// `blocked` the seed is still built, as a `control`, so the negative is measured
// rather than merely asserted.
//
// WHAT THE SHAPES ARE FOR. `build_op_program` commits `rd` one hop after the
// opcode produces it, so it can only ever ask "is this chip's result bound?".
// Every structure here inserts a different second surface between the forged
// write-back and the committed public output — a memory round trip, an address
// computation, a branch, a register hazard, a jump target, a public-value word —
// and asks whether the forgery survives that hop. The forged value reaches the
// proof's public output by the same route in all of them: it is stored into the
// 8-word buffer at `DIGEST_PTR` and the `PUB_IO_COMMIT` ecall binds those words
// to `PublicValues::public_io_digest`.
//
// TWO CENO FACTS THAT SHAPE THE CODE.
//
//  1. nth is unavailable (TARGET_CAPABILITIES capability.nth_supported = false):
//     ceno emulates the guest three times per candidate and the hooks share one
//     global occurrence counter, so every site is armed at nth = -1 (rule R5).
//
//  2. ceno lost 702 of its 1,584 published encoding candidates to EXECFAIL from
//     perturbing a pointer or an ECALL-code register with the unmasked menu. Two
//     things fix that here: the manifest's `site_role` mu mask (`mu_allowed`),
//     and — for the address role — an image whose scratch regions sit exactly at
//     the mu menu's own address deltas (`addr_image`), so an address mutation
//     lands on a MAPPED word and produces a verdict instead of a trap.
// ============================================================================

use ceno_emul::Instruction;

/// Byte address of the 8-word scratch region the structure seeds write through.
/// Contiguous with the digest buffer so that `Program.image` stays a power of two
/// (`init_static_addrs` asserts, e2e.rs:1257-1261).
const SCRATCH_PTR: u32 = DIGEST_PTR + 32;
const SCRATCH_WORDS: usize = 8;

/// The address-role image. Four 8-word regions, placed so that the three
/// alignment-preserving entries of the manifest's `site_role: address` mu mask
/// each land on a MAPPED, initialised word:
///
///   NEAR - 2^16 == DIGEST_PTR   (`minus_B1`)
///   NEAR ^ 2^15 == FAR_X_PTR    (`xor_b15`)
///   NEAR + 2^16 == FAR_UP_PTR   (`plus_B1`)
///
/// `plus_B1_hi` (+2^24) and `xor_b31` land outside any mapped region and are
/// EXECFAIL by construction — which is the manifest's
/// `allowed_with_execfail_expected` class, and is itself the answer to "is the
/// executor's address check total?".
const NEAR_PTR: u32 = 0x0801_1000;
const FAR_X_PTR: u32 = 0x0801_9000;
const FAR_UP_PTR: u32 = 0x0802_1000;

/// Distinct, recognisable fills so that a redirected load is visible in one look
/// at the committed digest.
fn addr_image() -> std::collections::BTreeMap<u32, u32> {
    let mut image = std::collections::BTreeMap::new();
    for k in 0..DIGEST_WORDS as u32 {
        image.insert(DIGEST_PTR + k * 4, 0u32);
    }
    for k in 0..8u32 {
        image.insert(NEAR_PTR + k * 4, 0x1100_0000 + k);
        image.insert(FAR_X_PTR + k * 4, 0x3300_0000 + k);
        image.insert(FAR_UP_PTR + k * 4, 0x2200_0000 + k);
    }
    image
}

/// The ordinary 16-word image: 8 digest words at `DIGEST_PTR` plus 8 scratch
/// words at `SCRATCH_PTR` with caller-chosen initial values.
fn seed_image(scratch: [u32; SCRATCH_WORDS]) -> std::collections::BTreeMap<u32, u32> {
    let mut image = std::collections::BTreeMap::new();
    for k in 0..DIGEST_WORDS as u32 {
        image.insert(DIGEST_PTR + k * 4, 0u32);
    }
    for (k, v) in scratch.iter().enumerate() {
        image.insert(SCRATCH_PTR + (k as u32) * 4, *v);
    }
    image
}

/// Materialise an arbitrary 32-bit constant into `rd`. LUI carries the FULL
/// value in `Instruction.imm` on ceno (`step_compute`: `LUI => imm_i`) and the
/// program table stores `imm >> 12` (`InsnRecord::imm_internal`), so the upper
/// part must keep its low 12 bits zero — the standard `li` split.
fn li(rd: u32, v: u32) -> Vec<Instruction> {
    let lo12 = (v & 0xFFF) as i32;
    let lo = if lo12 >= 0x800 { lo12 - 0x1000 } else { lo12 };
    let hi = v.wrapping_sub(lo as u32);
    match (hi, lo) {
        (0, _) => vec![encode_rv32(InsnKind::ADDI, 0, 0, rd, lo)],
        (_, 0) => vec![encode_rv32u(InsnKind::LUI, 0, 0, rd, hi)],
        _ => vec![
            encode_rv32u(InsnKind::LUI, 0, 0, rd, hi),
            encode_rv32(InsnKind::ADDI, rd, 0, rd, lo),
        ],
    }
}

/// Byte offset from instruction index `from` to instruction index `to`, for the
/// B- and J-format relative immediates.
fn rel(from: usize, to: usize) -> i32 {
    ((to as i64 - from as i64) * 4) as i32
}

/// Static pc of instruction index `i`.
fn pc_of(i: usize) -> u32 {
    CENO_PLATFORM.pc_base() + (i as u32) * 4
}

/// The publish-and-halt tail every structure seed ends with. Identical in effect
/// to `build_op_program`'s p5..p10: it points a0 at the digest buffer, issues
/// `PUB_IO_COMMIT` (which `PubioCommitLayout` binds to
/// `PublicValues::public_io_digest`), then halts with exit code 0.
fn publish_tail() -> Vec<Instruction> {
    vec![
        encode_rv32(InsnKind::ADDI, 6, 0, 10, 0),
        encode_rv32u(InsnKind::ADDI, 0, 0, 5, PubIoCommitSpec::CODE),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        encode_rv32u(InsnKind::ADDI, 0, 0, 5, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 10, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ]
}

/// x6 = &digest, x7 = &scratch. Two instructions, so every builder's body starts
/// at index 2.
fn prologue() -> Vec<Instruction> {
    vec![
        encode_rv32u(InsnKind::LUI, 0, 0, 6, DIGEST_PTR),
        encode_rv32(InsnKind::ADDI, 6, 0, 7, 32),
    ]
}

/// x6 = &digest, x7 = NEAR_PTR, for the seeds built over `addr_image`.
fn prologue_addr() -> Vec<Instruction> {
    vec![
        encode_rv32u(InsnKind::LUI, 0, 0, 6, DIGEST_PTR),
        encode_rv32u(InsnKind::LUI, 0, 0, 7, NEAR_PTR),
    ]
}

/// The role a write-back site plays in its program, which is what the manifest's
/// `mu_menu.role_masks` keys on. `syscall_arg` is deliberately absent: the
/// manifest forbids it on every target today, and every ECALL-code register in
/// these seeds is therefore left unarmed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Value,
    Address,
    Selector,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Value => "value",
            Role::Address => "address",
            Role::Selector => "selector",
        }
    }
}

/// STRUCTURE_MANIFEST.yaml `mu_menu.role_masks`, verbatim, for the 11 entries of
/// ceno's frozen menu. This does not change the menu; it declares which existing
/// entry is legal at which role.
///
/// `bit0_exception` carries the one documented exception: `xor_b0` is allowed at
/// the `st_indirect_jump` `bit0` variant and nowhere else, because clearing bit 0
/// is the RISC-V JALR requirement that variant exists to test.
fn mu_allowed(role: Role, label: &str, bit0_exception: bool) -> bool {
    match role {
        // "The default. The instruction-independent menu was designed for this
        // role and no masking applies."
        Role::Value => true,
        // "The information is in the SMALL steps" — everything is legal, the
        // large limb deltas are simply low-yield.
        Role::Selector => true,
        Role::Address => {
            matches!(label, "plus_B1" | "minus_B1" | "xor_b15")
                // allowed_with_execfail_expected
                || matches!(label, "plus_B1_hi" | "xor_b31")
                || (bit0_exception && label == "xor_b0")
        }
    }
}

/// Run-matrix rules R2 + R3. ceno's `known_unbound_opcodes` is EMPTY (nobody has
/// established an unbound opcode at ceno's record layer), so R3 applies: the
/// deconfounding axis is one opcode from `alu_bound_reference` plus the WHOLE
/// `shift_family` and the WHOLE `m_ext`, and the run tag must say
/// `unbound_probe=substituted` — which the enumeration appends automatically.
///
/// R4, for the record: on pico five of seven shipped structures were pinned to
/// ADD and LD while all 24 accepted cases sat on SRLW/SRAW, so structure and
/// opcode never varied independently and no per-structure yield from that run is
/// interpretable. This axis is what stops the same thing happening on ceno.
fn deconfound_axis() -> Vec<(&'static str, InsnKind)> {
    use InsnKind::*;
    let full = vec![
        // alu_bound_reference
        ("ADD", ADD),
        ("XOR", XOR),
        // shift_family (substituted target_unbound_probe)
        ("SLL", SLL),
        ("SRL", SRL),
        ("SRA", SRA),
        // m_ext (substituted target_unbound_probe)
        ("MUL", MUL),
        ("MULH", MULH),
        ("MULHU", MULHU),
        ("MULHSU", MULHSU),
        ("DIV", DIV),
        ("DIVU", DIVU),
        ("REM", REM),
        ("REMU", REMU),
    ];
    // LACUNA_AXIS=min shrinks the axis for a smoke run. It VIOLATES R2 and the
    // caller must say so in the run tag; the default is the R3-compliant set.
    if std::env::var("LACUNA_AXIS").as_deref() == Ok("min") {
        vec![("ADD", ADD), ("SRL", SRL), ("MUL", MUL), ("DIVU", DIVU)]
    } else {
        full
    }
}

/// `consumer_set`: the OP2 arm of `st_provenance_chain` and `st_fanout_read` —
/// chips with a tight operand decomposition, so the question is whether a forged
/// value survives someone else's operand-side range checks.
fn consumer_axis() -> Vec<(&'static str, InsnKind)> {
    use InsnKind::*;
    vec![("ADD", ADD), ("SLT", SLT), ("MUL", MUL)]
}

/// A built structure seed: the program plus the sites the enumeration arms on it.
struct Built {
    program: Program,
    /// ENCODING family: (static pc, site role, site label). The write-back at
    /// this pc is rewritten by `wb_perturb`.
    sites: Vec<(u32, Role, &'static str)>,
    /// ORDER family: (static pc, subcycle, label), subcycle 0=rs1 1=rs2 2=rd
    /// 3=mem. The `previous_cycle` recorded for that access is rewritten by
    /// `ts_perturb`.
    order_sites: Vec<(u32, i64, &'static str)>,
    /// BIND-O1 (see the enumeration below): (load pc, the value the
    /// SECOND-most-recent write left at that address, the prev_cycle delta that
    /// re-points the read at that write).
    bind: Option<(u32, u32, i64)>,
    /// Shard plan. Only `st_multishard` departs from the default.
    multi_prover: MultiProver,
}

impl Built {
    fn new(insns: Vec<Instruction>, image: std::collections::BTreeMap<u32, u32>) -> Built {
        let pc = CENO_PLATFORM.pc_base();
        Built {
            program: Program::new(pc, pc, CENO_PLATFORM.heap.start, insns, image),
            sites: vec![],
            order_sites: vec![],
            bind: None,
            multi_prover: MultiProver::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// st_op_then_state — published_name "Operation then state"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. The opcode chip AND the memory / address-formation /
// branch chip IN SERIES, with the register-consistency argument as the carrier
// between them. A forged value needs only ONE unbound link in the chain, so this
// measures where the binding actually is.
//
// PATH TO THE COMMITTED OUTPUT. The forged `rd` is NOT committed directly: it
// first traverses a store-load round trip (`mem`), an address computation
// (`addr`) or a branch decision (`branch`), and only the result of THAT second
// interaction is stored into the digest buffer and sealed by PUB_IO_COMMIT. An
// accept therefore proves the forgery survived a re-binding hop.
//
// WHY IT EXISTS. This is the deconfounding shape. The opcode under test is a
// free parameter here exactly as it is in `build_op_program`, so structure and
// opcode vary independently (run-matrix rules R1-R4).
// ---------------------------------------------------------------------------
fn build_op_then_state_program(op: InsnKind, a: i32, b: i32, variant: &str) -> Built {
    // The `addr` variant reads one of eight distinct, image-initialised scratch
    // words, so the forged offset is visible in the committed digest.
    let scratch: [u32; SCRATCH_WORDS] = std::array::from_fn(|k| {
        if variant == "addr" {
            0x0A00_0000 + k as u32
        } else {
            0
        }
    });
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let op_idx = insns.len();
    insns.push(encode_rv32(op, 2, 3, 4, 0));

    let mut sites = vec![(pc_of(op_idx), Role::Value, "op_rd")];
    let mut order_sites: Vec<(u32, i64, &'static str)> = vec![];

    match variant {
        // variant A: through memory. store(p, rd); x = load(p); commit(x)
        "mem" => {
            insns.push(encode_rv32(InsnKind::SW, 7, 4, 0, 0));
            let lw = insns.len();
            insns.push(encode_rv32(InsnKind::LW, 7, 0, 8, 0));
            insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
            sites.push((pc_of(lw), Role::Value, "load_rd"));
            order_sites.push((pc_of(lw), 3, "mem"));
        }
        // variant B: rd BECOMES an address (sink S2). The ANDI masks it to a
        // 4-aligned offset inside the 8-word scratch region, so the escalation is
        // real but EXECFAIL is impossible by construction — which is what turns
        // ceno's 702 pointer EXECFAILs into verdicts.
        "addr" => {
            insns.push(encode_rv32(InsnKind::ANDI, 4, 0, 9, 28));
            insns.push(encode_rv32(InsnKind::ADD, 7, 9, 9, 0));
            let lw = insns.len();
            insns.push(encode_rv32(InsnKind::LW, 9, 0, 8, 0));
            insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
            sites.push((pc_of(lw), Role::Value, "load_rd"));
            order_sites.push((pc_of(lw), 0, "rs1"));
        }
        // variant C: rd BECOMES a decision (sink S3). Parity selects the arm, so
        // every mu that touches bit 0 is output-changing.
        _ => {
            insns.push(encode_rv32(InsnKind::ANDI, 4, 0, 9, 1));
            let br = insns.len();
            insns.push(encode_rv32(InsnKind::BEQ, 9, 0, 0, rel(br, br + 3)));
            insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x111));
            insns.push(encode_rv32(InsnKind::JAL, 0, 0, 0, rel(br + 2, br + 4)));
            insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x222));
            insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
        }
    }
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image(scratch));
    built.sites = sites;
    built.order_sites = order_sites;
    built
}

// ---------------------------------------------------------------------------
// st_boundary_operand — published_name "Boundary operand"
//   candidate_class probe | operand_source immediate | site_role selector
//
// CONSTRAINT SURFACE. S17, the AIR-DERIVED selectors and guard flags: the
// is_zero flag of DivRem, the shift-amount decomposition, the INT_MIN/-1 special
// case, the limb-carry chain. Structurally different from `st_single_op`: the
// forged value is an OPERAND, so the witness generator recomputes the result
// coherently and the only thing that can come loose is a flag the AIR derives by
// copying rather than by re-deriving.
//
// PATH TO THE COMMITTED OUTPUT. The recomputed result is stored into digest[0]
// and sealed by PUB_IO_COMMIT, exactly as in `build_op_program`.
//
// The honest operand is placed ONE mu-step from the discontinuity, which is why
// the site role is `selector` and the small menu entries are the experiment.
// Operands are full 32-bit constants here, so they go through a LUI+ADDI pair —
// `build_op_program`'s 12-bit ADDI immediates cannot express INT_MIN or
// 0xFFFF_FFFF.
// ---------------------------------------------------------------------------
fn build_boundary_program(op: InsnKind, a: u32, b: u32) -> Built {
    let mut insns = prologue();
    let a_seq = li(2, a);
    let a_site = insns.len() + a_seq.len() - 1;
    insns.extend(a_seq);
    let b_seq = li(3, b);
    let b_site = insns.len() + b_seq.len() - 1;
    insns.extend(b_seq);
    insns.push(encode_rv32(op, 2, 3, 4, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![
        (pc_of(a_site), Role::Selector, "operand_a"),
        (pc_of(b_site), Role::Selector, "operand_b"),
    ];
    built
}

/// The boundary table. Each row is (variant, opcode name, opcode, honest a,
/// honest b) and each places an honest operand ONE menu step from a constraint
/// discontinuity.
fn boundary_rows() -> Vec<(&'static str, &'static str, InsnKind, u32, u32)> {
    use InsnKind::*;
    let mut rows = vec![];
    // (a) zero-divisor selector: honest b = 1, mu zero -> divide by zero
    for (n, k) in [("DIV", DIV), ("DIVU", DIVU), ("REM", REM), ("REMU", REMU)] {
        rows.push(("zero", n, k, 0x0000_1234, 1));
    }
    // (b) shift-amount mask: honest s = 1 in a REGISTER (SLL, not SLLI), so mu
    //     can push it to 32, 31 and 2^16 and ask what the decomposition does.
    for (n, k) in [("SLL", SLL), ("SRL", SRL), ("SRA", SRA)] {
        rows.push(("shamt", n, k, 0x8000_00F1, 1));
    }
    // (c) signed overflow: honest a = INT_MIN+1, b = -1; mu minus_B0 -> INT_MIN/-1
    for (n, k) in [("DIV", DIV), ("REM", REM)] {
        rows.push(("intmin", n, k, 0x8000_0001, 0xFFFF_FFFF));
    }
    // (d) limb / sign boundary: honest a one step below a 2^16 and a 2^31 edge
    for (n, k) in [("MUL", MUL), ("MULH", MULH), ("MULHSU", MULHSU)] {
        rows.push(("limb", n, k, 0x0000_FFFF, 0x0000_0003));
        rows.push(("limb", n, k, 0x7FFF_FFFF, 0x0000_0003));
    }
    // (e) exactly divisible / even divisor
    rows.push(("exactdiv", "DIVU", DIVU, 8, 2));
    rows.push(("exactdiv", "REMU", REMU, 10, 6));
    // (f) limb overflow: both operands at 2^32 - 1
    for (n, k) in [("MUL", MUL), ("MULH", MULH), ("MULHU", MULHU)] {
        rows.push(("limbmax", n, k, 0xFFFF_FFFF, 0xFFFF_FFFF));
    }
    rows
}

// ---------------------------------------------------------------------------
// st_subword_lane — published_name "Sub-word lane"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. S7: lane selection and sign/zero extension in the load
// AIR; lane merge and SIBLING-LANE PRESERVATION in the store AIR. The load side
// is the cleanest single-landing-point shape in the catalog, because rd is a
// NARROWING of the memory word, so the free lanes lie outside the pinned window
// by construction.
//
// PATH TO THE COMMITTED OUTPUT. `load`: the extracted lane is the word stored
// into digest[0]. `store`: the digest carries the REASSEMBLED wide word, which is
// what shows whether the untouched lanes were bound.
// ---------------------------------------------------------------------------
fn build_subword_program(kind: InsnKind, variant: &str) -> Built {
    const WIDE: u32 = 0x89AB_CDEF;
    let mut insns = prologue();
    let v_seq = li(2, WIDE);
    let v_site = insns.len() + v_seq.len() - 1;
    insns.extend(v_seq);
    insns.push(encode_rv32(InsnKind::SW, 7, 2, 0, 0));
    let mut sites = vec![(pc_of(v_site), Role::Value, "stored_word")];
    if variant == "load" {
        // lane offset: byte loads take lane 3, half loads lane 2, LW the word
        let off = match kind {
            InsnKind::LB | InsnKind::LBU => 3,
            InsnKind::LH | InsnKind::LHU => 2,
            _ => 0,
        };
        let ld = insns.len();
        insns.push(encode_rv32(kind, 7, 0, 4, off));
        insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
        sites.push((pc_of(ld), Role::Value, "lane_rd"));
    } else {
        // store side: merge a narrow value into one lane, then read the whole word
        let off = match kind {
            InsnKind::SB => 1,
            InsnKind::SH => 2,
            _ => 0,
        };
        let n_seq = li(3, 0x0000_0055);
        let n_site = insns.len() + n_seq.len() - 1;
        insns.extend(n_seq);
        insns.push(encode_rv32(kind, 7, 3, 0, off));
        let ld = insns.len();
        insns.push(encode_rv32(InsnKind::LW, 7, 0, 4, 0));
        insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
        sites.push((pc_of(n_site), Role::Value, "lane_value"));
        sites.push((pc_of(ld), Role::Value, "merged_rd"));
    }
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = sites;
    built
}

// ---------------------------------------------------------------------------
// st_store_load — published_name "Store--load"  (two hyphens, frozen string)
//   candidate_class probe | operand_source immediate | site_role value
//
// THE HIGHEST-VALUE CENO SEED IN THE CATALOG.
//
// CONSTRAINT SURFACE. S5, read-after-write at ONE address: does the offline
// memory argument bind the delivered value to the MOST RECENT write? And, with
// the order operator, S10: the free (chunk, clk) columns and the prev_clk chain.
// The `_tail` variant adds a trailing store so the load is no longer the last
// access to the address, which separates S5 from the finalize boundary S9.
//
// PATH TO THE COMMITTED OUTPUT. The loaded value is stored into digest[0] and
// sealed by PUB_IO_COMMIT — one hop, no intermediate surface.
//
// WHY THIS SHAPE ON CENO. `previous_cycle` is a genuine RECORD field here
// (`insn_base.rs:95,312,452`, hooked at `tracer.rs:1131`), and ceno already has
// 36 REAL verifier ACCEPTs on it (`rd_prev_plus1` / `mem_prev_plus1`, all 18
// opcodes) that nobody can see because the seed shape leaves
// `output_changed=false`. This is the shape that makes them observable: the same
// slack now decides WHICH WRITE the load reads. pico's P-CLK became an e2e gold
// by exactly this route.
//
// The first store's value is a builder-known constant, so the composite BIND-O1
// arm can deliver precisely the second-most-recent write.
// ---------------------------------------------------------------------------
const STALE_K1: u32 = 0x0BAD_F00D;

fn build_store_load_program(op: InsnKind, a: i32, b: i32, tail: bool) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let op_idx = insns.len();
    insns.push(encode_rv32(op, 2, 3, 4, 0));
    insns.extend(li(11, STALE_K1));
    insns.push(encode_rv32(InsnKind::SW, 7, 11, 0, 0)); // write 1: the stale value
    insns.push(encode_rv32(InsnKind::SW, 7, 4, 0, 0)); // write 2: the honest value
    let lw = insns.len();
    insns.push(encode_rv32(InsnKind::LW, 7, 0, 8, 0));
    if tail {
        insns.push(encode_rv32(InsnKind::SW, 7, 11, 0, 0));
    }
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![
        (pc_of(op_idx), Role::Value, "op_rd"),
        (pc_of(lw), Role::Value, "load_rd"),
    ];
    built.order_sites = vec![
        (pc_of(lw), 3, "mem"),
        (pc_of(lw), 2, "rd"),
        (pc_of(lw), 0, "rs1"),
    ];
    // one instruction = 4 cycles, so -4 re-points the read at write 1
    built.bind = Some((pc_of(lw), STALE_K1, -4));
    built
}

// ---------------------------------------------------------------------------
// st_redirect — published_name "Redirect"
//   candidate_class probe | operand_source immediate | site_role address
//
// CONSTRAINT SURFACE. S6 address derivation — is `addr` bound to rs1 + imm, or
// is the memory argument's address key free? — and the (addr, value) pairing in
// the offline memory argument.
//
// PATH TO THE COMMITTED OUTPUT. The redirected load's value goes straight into
// digest[0]: the record claims a read of p1 while delivering p2's contents.
//
// THE IMAGE IS THE POINT. `addr_image` puts a distinctly-filled 8-word region at
// each of the three alignment-preserving address deltas of the mu menu, so
// `plus_B1`, `minus_B1` and `xor_b15` all land on a mapped word and produce a
// verdict. Without that every address mutation traps and the row is an EXECFAIL
// that says nothing — which is how ceno lost 702 of 1,584 published candidates.
// The second store to p1 additionally arms the BIND-O1 stale-load arm.
// ---------------------------------------------------------------------------
fn build_redirect_program() -> Built {
    let mut insns = prologue_addr();
    insns.extend(li(11, 0x0A0A_0A0A));
    insns.push(encode_rv32(InsnKind::SW, 7, 11, 0, 0)); // write 1 to p1
    insns.extend(li(12, 0x0B0B_0B0B));
    insns.push(encode_rv32(InsnKind::SW, 7, 12, 0, 0)); // write 2 to p1
    let ptr = insns.len();
    insns.push(encode_rv32(InsnKind::ADDI, 7, 0, 9, 0)); // p1 into its own register
    let lw = insns.len();
    insns.push(encode_rv32(InsnKind::LW, 9, 0, 8, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, addr_image());
    built.sites = vec![
        (pc_of(ptr), Role::Address, "pointer"),
        (pc_of(lw), Role::Value, "load_rd"),
    ];
    built.order_sites = vec![(pc_of(lw), 3, "mem")];
    built.bind = Some((pc_of(lw), 0x0A0A_0A0A, -4));
    built
}

// ---------------------------------------------------------------------------
// st_pointer_indirect — published_name "Pointer indirect"
//   candidate_class probe | operand_source immediate | site_role address
//
// CONSTRAINT SURFACE. Composition of the memory-timestamp / address surface with
// the address-formation path. The dereferencing load is a SECOND, ENTIRELY
// HONEST memory access whose address is a carried register value, so this asks
// whether an unbound quantity in the memory plane becomes a CAPABILITY in the
// addressing plane.
//
// PATH TO THE COMMITTED OUTPUT. The dereferenced object is committed. Severity
// is bounded by what is in memory, not by what the primitive can write: a
// one-word forgery becomes a whole-object substitution.
//
// Distinct from `st_redirect`, whose two addresses are STATIC. Here the forged
// value BECOMES an address. With the BIND-O1 arm this is chain C4 of the
// taint/dataflow composition audit — a stale POINTER, i.e. the use-after-free
// analogue inside an accepted proof — which that audit lists as UNTESTED.
// ---------------------------------------------------------------------------
fn build_pointer_indirect_program() -> Built {
    let mut insns = prologue_addr();
    insns.extend(li(11, FAR_UP_PTR));
    insns.push(encode_rv32(InsnKind::SW, 7, 11, 0, 28)); // pp = &FAR_UP[0] (write 1)
    insns.extend(li(12, NEAR_PTR));
    insns.push(encode_rv32(InsnKind::SW, 7, 12, 0, 28)); // pp = &NEAR[0]   (write 2)
    let ld = insns.len();
    insns.push(encode_rv32(InsnKind::LW, 7, 0, 9, 28)); // load the POINTER
    let deref = insns.len();
    insns.push(encode_rv32(InsnKind::LW, 9, 0, 8, 0)); // honest dereference
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, addr_image());
    built.sites = vec![
        (pc_of(ld), Role::Address, "pointer_load_rd"),
        (pc_of(deref), Role::Value, "deref_rd"),
    ];
    built.order_sites = vec![(pc_of(ld), 3, "mem")];
    built.bind = Some((pc_of(ld), FAR_UP_PTR, -4));
    built
}

// ---------------------------------------------------------------------------
// st_hazard_chain — published_name "Hazard chain"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. S4, register write-after-write retirement: the second
// write's (prev_value, prev_timestamp) must equal the first write's record. This
// is the register-file analogue of what an order operator does to data memory,
// and on ceno it is the direct test of `prev_rd_value` — declared
// `UInt::new_unchecked` at insn_base.rs:313 — and `prev_rd_ts` at :312.
//
// PATH TO THE COMMITTED OUTPUT. The `second` site reaches digest[0] directly.
// The `first` site is overwritten before any read, so its best outcome is
// ACCEPT-with-unchanged-output: a binding datum, never an accepted case. Keeping
// both variants is what makes the `second` result interpretable.
// ---------------------------------------------------------------------------
fn build_hazard_program(op: InsnKind, a: i32, b: i32, variant: &str) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let first = insns.len();
    insns.push(encode_rv32(op, 2, 3, 4, 0));
    let second = insns.len();
    insns.push(encode_rv32(op, 3, 3, 4, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = if variant == "first" {
        vec![(pc_of(first), Role::Value, "dead_first_write")]
    } else {
        vec![(pc_of(second), Role::Value, "live_second_write")]
    };
    built.order_sites = vec![(pc_of(second), 2, "rd")];
    built
}

// ---------------------------------------------------------------------------
// st_control_flow — published_name "Control flow"
//   candidate_class probe | operand_source immediate | site_role selector
//
// CONSTRAINT SURFACE. S11, the branch chip's comparison columns and the
// taken/not-taken -> next_pc transition. This is the only structure in which a
// forged value changes WHICH ROWS EXIST — the executed-instruction multiset, the
// clk chain, per-chip row counts. On ceno it also LITERALLY CREATES the field:
// `next_pc` is a committed WitIn only for branching circuits
// (`StateInOut::construct_circuit(branching=true)`, insn_base.rs:42-44), so a
// straight-line seed has no next_pc column at all.
//
// PATH TO THE COMMITTED OUTPUT. `datadiv`: the selected value is stored into
// digest[0]. `dataident`: the committed word is a CONSTANT and only the trip
// count moves, which isolates the pc/cycle chain from the value binding.
//
// HONEST LIMIT ON THIS DRIVER. ceno commits end_cycle and end_pc as flattened
// public values (scheme.rs:94,116,176), but this driver captures only the eight
// digest words and the exit code, so `dataident` can produce at most
// ACCEPT-with-unchanged-output here. It is recorded as such, not as a negative.
// ---------------------------------------------------------------------------
fn build_cf_program(bop: InsnKind, variant: &str) -> Built {
    let mut insns = prologue();
    if variant == "datadiv" {
        insns.extend(li(2, 1));
        insns.extend(li(3, 0));
        let sel = insns.len();
        insns.push(encode_rv32(InsnKind::ADDI, 2, 0, 9, 0)); // the condition value
        let br = insns.len();
        insns.push(encode_rv32(bop, 9, 3, 0, rel(br, br + 3)));
        insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x111));
        insns.push(encode_rv32(InsnKind::JAL, 0, 0, 0, rel(br + 2, br + 4)));
        insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x222));
        insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
        insns.extend(publish_tail());
        let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
        built.sites = vec![(pc_of(sel), Role::Selector, "branch_condition")];
        built
    } else {
        // DATA-IDENTICAL, trace-divergent: the trip count is the only thing the
        // mutation moves; the committed word is fixed.
        let sel = insns.len();
        insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 9, 3)); // trip count
        let top = insns.len();
        insns.push(encode_rv32(InsnKind::BEQ, 9, 0, 0, rel(top, top + 3)));
        insns.push(encode_rv32(InsnKind::ADDI, 9, 0, 9, -1));
        insns.push(encode_rv32(InsnKind::JAL, 0, 0, 0, rel(top + 2, top)));
        insns.extend(li(8, 0x00C0_FFEE));
        insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
        insns.extend(publish_tail());
        let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
        built.sites = vec![(pc_of(sel), Role::Selector, "trip_count")];
        built
    }
}

// ---------------------------------------------------------------------------
// st_provenance_chain — published_name "Provenance chain"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. The operand-READ side of a chip that did NOT produce the
// value: limb decomposition and range checks applied to an incoming operand,
// usually tighter than the same chip's result binding. At depth 4 the memory
// argument is in series as well.
//
// PATH TO THE COMMITTED OUTPUT. OP2's result is stored into digest[0], so the
// forged t must traverse the register bus and OP2's own operand columns to get
// there. The measurement is the HOP AT WHICH the candidate flips ACCEPT->REJECT,
// which localises the binding edge; ceno re-executes rather than oracling, so the
// deep variant is coherent here.
// ---------------------------------------------------------------------------
fn build_chain_program(op1: InsnKind, op2: InsnKind, a: i32, b: i32, depth: &str) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let i1 = insns.len();
    insns.push(encode_rv32(op1, 2, 3, 4, 0));
    let mut sites = vec![(pc_of(i1), Role::Value, "op1_rd")];
    let src = if depth == "d4" {
        insns.push(encode_rv32(InsnKind::SW, 7, 4, 0, 0));
        let lw = insns.len();
        insns.push(encode_rv32(InsnKind::LW, 7, 0, 13, 0));
        sites.push((pc_of(lw), Role::Value, "hop_load_rd"));
        13
    } else {
        4
    };
    insns.push(encode_rv32(op2, src, 2, 11, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 11, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = sites;
    built
}

// ---------------------------------------------------------------------------
// st_indirect_jump — published_name "Indirect jump"
//   candidate_class probe | operand_source immediate | site_role address
//
// CONSTRAINT SURFACE. S12: the pc transition computed from a register, the
// ROM/program-table lookup at the forged pc (is the fetch relation TOTAL, and
// does it reject a misaligned or non-instruction pc?), and the RISC-V
// requirement that JALR clears bit 0. S13 in passing, via the link register.
//
// PATH TO THE COMMITTED OUTPUT. The value written by the arm that actually runs
// is stored into digest[0]. The two arms are 8 bytes apart and the selector is
// masked to {0, 8}, so both paths reach the same commit and EXECFAIL stays low —
// this is the "two-entry table" the manifest asks for.
//
// TWO SITES, TWO QUESTIONS.
//   `table` arms the SELECTOR (site_role value, masked to a legal arm) and asks
//          whether the arm the record claims is the arm the AIR proves.
//   `bit0`  arms the JALR TARGET REGISTER itself with `xor_b0`, the one
//          documented exception in the manifest's address mask, because clearing
//          bit 0 is the RISC-V JALR requirement. The emulator masks it
//          (`step_compute`: `new_pc = (rs1 + imm) & !1`), so the executed trace
//          is unchanged and the RECORD is the only thing that moved: an ACCEPT
//          here is ACCEPT-with-unchanged-output, which is the precursor form of
//          pico catalog #20 rather than an accepted case.
// ---------------------------------------------------------------------------
fn build_jalr_program(variant: &str) -> Built {
    let mut insns = prologue();
    let sel = insns.len();
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 9, 0)); // arm selector, honest 0
    insns.push(encode_rv32(InsnKind::SLLI, 9, 0, 9, 3)); // any low-bit mu -> 8
    insns.push(encode_rv32(InsnKind::ANDI, 9, 0, 9, 8)); // {0, 8}: in range, aligned
    let anchor = insns.len();
    insns.push(encode_rv32u(InsnKind::AUIPC, 0, 0, 12, 0)); // x12 = pc(anchor)
    let tgt = insns.len();
    insns.push(encode_rv32(InsnKind::ADD, 12, 9, 12, 0));
    // arm A at anchor+3, arm B at anchor+5, so the JALR displacement is 12
    insns.push(encode_rv32(InsnKind::JALR, 12, 0, 1, 12));
    let arm_a = insns.len();
    debug_assert_eq!(pc_of(anchor) + 12, pc_of(arm_a));
    debug_assert_eq!(pc_of(anchor) + 8 + 12, pc_of(arm_a + 2));
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x0AA));
    insns.push(encode_rv32(InsnKind::JAL, 0, 0, 0, rel(arm_a + 1, arm_a + 4)));
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0x0BB));
    insns.push(encode_rv32(InsnKind::JAL, 0, 0, 0, rel(arm_a + 3, arm_a + 4)));
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = if variant == "bit0" {
        vec![(pc_of(tgt), Role::Address, "jalr_target")]
    } else {
        vec![
            (pc_of(sel), Role::Value, "arm_selector"),
            (pc_of(tgt), Role::Address, "jalr_target"),
        ]
    };
    built
}

// ---------------------------------------------------------------------------
// st_pc_imm_value — published_name "PC-immediate value"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. S13: value derivation from the pc column and from the
// program table's immediate, with NO register operand in the relation. It asks a
// question no other structure asks — is rd bound to the COMMITTED PROGRAM? — and
// the answer route is the preprocessed program / fetch bus, not the register bus.
//
// PATH TO THE COMMITTED OUTPUT. rd is stored into digest[0] directly.
//
// WHY IT IS NEW WORK ON CENO. The published seed already contains a LUI at
// 0x08000000 whose site is enumerated, but it carries a POINTER, so forging it
// traps the emulator and the row lands as EXECFAIL rather than as a verdict —
// part of ceno's 702. Here the LUI / AUIPC / JAL result is the committed DATUM,
// which converts those EXECFAILs into verdicts.
// ---------------------------------------------------------------------------
fn build_pcimm_program(variant: &str) -> Built {
    let mut insns = prologue();
    let site = insns.len();
    match variant {
        // AUIPC's program-table immediate is stored as imm >> 8, so the low bits
        // must be zero (`InsnRecord::imm_internal`, program.rs:121-126).
        "auipc" => insns.push(encode_rv32u(InsnKind::AUIPC, 0, 0, 4, 0x0000_1000)),
        "lui" => insns.push(encode_rv32u(InsnKind::LUI, 0, 0, 4, 0x1234_5000)),
        _ => {
            // JAL writes the link register pc+4 and jumps over one instruction.
            insns.push(encode_rv32(InsnKind::JAL, 0, 0, 4, 8));
            insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 8, 0));
        }
    }
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(site), Role::Value, "pc_imm_rd")];
    built
}

// ---------------------------------------------------------------------------
// st_fanout_read — published_name "Fan-out read"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. Whether the register BUS binds the read value, or only the
// producing chip does. Two chip rows consume the same register value at two
// different clks, and in several VMs each consumption is split again across two
// independent column groups the AIR never equates. This is the program-level way
// to express an L1 per-read-point split on a port with no witness-generation seam.
//
// PATH TO THE COMMITTED OUTPUT. BOTH uses feed the commit, so a forgery that
// survives at one read point and not the other still changes digest[0].
// ---------------------------------------------------------------------------
fn build_fanout_program(op: InsnKind, cop: InsnKind, a: i32, b: i32) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let site = insns.len();
    insns.push(encode_rv32(op, 2, 3, 4, 0));
    insns.push(encode_rv32(cop, 4, 2, 11, 0)); // consumer 1
    insns.push(encode_rv32(InsnKind::XORI, 4, 0, 12, 0x55)); // consumer 2
    insns.push(encode_rv32(InsnKind::XOR, 11, 12, 8, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(site), Role::Value, "fanout_rd")];
    built
}

// ---------------------------------------------------------------------------
// st_reg_alias — published_name "Register aliasing"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. Within-row ordering of the register memory argument:
// read-before-write at ONE address at ONE clk, with the two reads and the write
// distinguished only by subcycle, plus the deduplicated second read. ceno builds
// rs1/rs2/rd as three ReadOp/WriteOp records at SUBCYCLE_RS1/RS2/RD offsets that
// must not collide, and this is the only shape in the catalog that tests that.
//
// PATH TO THE COMMITTED OUTPUT. The result is stored into digest[0] as usual.
// ---------------------------------------------------------------------------
fn build_reg_alias_program(op: InsnKind, a: i32, variant: &str) -> Built {
    let mut insns = prologue();
    let site;
    if variant == "rs1rs2" {
        insns.extend(li(2, a as u32));
        site = insns.len();
        insns.push(encode_rv32(op, 2, 2, 4, 0)); // rd != rs1 == rs2
    } else {
        insns.extend(li(4, a as u32));
        site = insns.len();
        insns.push(encode_rv32(op, 4, 4, 4, 0)); // rd == rs1 == rs2
    }
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(site), Role::Value, "alias_rd")];
    built.order_sites = vec![
        (pc_of(site), 0, "rs1"),
        (pc_of(site), 1, "rs2"),
        (pc_of(site), 2, "rd"),
    ];
    built
}

// ---------------------------------------------------------------------------
// st_pv_plumbing — published_name "Public-value plumbing"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. S14, the commit chip itself: `PubIoCommitLayout` forces
// each public word equal to the guest memory word at the ecall cycle
// (precompiles/pubio_commit.rs:22-36, WriteMEM at :87-100), and the eight words
// become `PublicValues::public_io_digest` (scheme.rs:100,104-135,186-196). The
// question is whether EACH word is individually bound or only the aggregate.
//
// PATH TO THE COMMITTED OUTPUT. This structure IS the output path.
//
// VARIANTS.
//   `words8`   fills all eight digest words with distinct computed values and
//              arms each producing write-back, so a per-word slack is visible.
//   `alias`    writes the output buffer twice and READS IT BACK before the
//              ecall, which is a store-load on the output region itself; it
//              carries the BIND-O1 arm.
//   `exitcode` produces the HALT exit code from a perturbable write-back. Note
//              that the exit code lands in `committed_digest`/`digest_changed`,
//              NOT in the eight-word `output_changed` object that
//              `accepted_case_strict` reads, so this variant is scored by the
//              digest columns and never by `accepted_case`.
//
// The `index` variant of the manifest is NOT built: it perturbs the commit-word
// index, which is site_role `syscall_arg`, and the manifest FORBIDS that role on
// every target until the port turns the resulting record-generator panic into an
// ordinary EXECFAIL row.
// ---------------------------------------------------------------------------
fn build_pv_plumbing_program(op: InsnKind, a: i32, b: i32, variant: &str) -> Built {
    let mut insns = prologue();
    match variant {
        "words8" => {
            insns.extend(li(2, a as u32));
            insns.extend(li(3, b as u32));
            let mut sites = vec![];
            for k in 0..DIGEST_WORDS {
                insns.push(encode_rv32(InsnKind::XORI, 2, 0, 11, k as i32));
                let s = insns.len();
                insns.push(encode_rv32(op, 11, 3, 4, 0));
                insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, (k as i32) * 4));
                sites.push((pc_of(s), Role::Value, "digest_word"));
            }
            insns.extend(publish_tail());
            let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
            built.sites = sites;
            built
        }
        "alias" => {
            insns.extend(li(4, 0x0AAA_0000));
            insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
            insns.extend(li(11, 0x0BBB_0000));
            insns.push(encode_rv32(InsnKind::SW, 6, 11, 0, 0));
            let lw = insns.len();
            insns.push(encode_rv32(InsnKind::LW, 6, 0, 8, 0));
            insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 4));
            insns.extend(publish_tail());
            let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
            built.sites = vec![(pc_of(lw), Role::Value, "readback_rd")];
            built.order_sites = vec![(pc_of(lw), 3, "mem")];
            built.bind = Some((pc_of(lw), 0x0AAA_0000, -4));
            built
        }
        _ => {
            // exitcode: a custom tail whose HALT a0 comes from a perturbable
            // write-back. Everything up to the PUB_IO_COMMIT ecall is the normal
            // publish path, so the digest stays honest and the exit code is the
            // only thing that moves.
            insns.extend(li(4, 0x0E0E_0E0E));
            insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
            insns.push(encode_rv32(InsnKind::ADDI, 6, 0, 10, 0));
            insns.push(encode_rv32u(InsnKind::ADDI, 0, 0, 5, PubIoCommitSpec::CODE));
            insns.push(encode_rv32(InsnKind::ECALL, 0, 0, 0, 0));
            let ec = insns.len();
            insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 13, 0)); // the exit code
            insns.push(encode_rv32u(InsnKind::ADDI, 0, 0, 5, 0));
            insns.push(encode_rv32(InsnKind::ADDI, 13, 0, 10, 0));
            insns.push(encode_rv32(InsnKind::ECALL, 0, 0, 0, 0));
            let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
            built.sites = vec![(pc_of(ec), Role::Value, "exit_code")];
            built
        }
    }
}

// ---------------------------------------------------------------------------
// st_dead_write — published_name "Dead write-back"   THE NEGATIVE CONTROL
//   candidate_class CONTROL | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. None, deliberately. The mutation is provably invisible to
// the honest instruction stream, so the perturbed execution is
// instruction-for-instruction identical to the honest one and any REJECT is
// attributable to the constraint system ALONE. EXECFAIL is impossible by
// construction, which is also the direct answer to ceno's 702-EXECFAIL problem.
//
// PATH TO THE COMMITTED OUTPUT. There is none, by design. On ceno the register
// file is NOT inside a committed memory root, so the expected outcome is REJECT
// (bound) or ACCEPT-with-unchanged-output (unbound but unobservable). An ACCEPT
// here is NOT a finding — it is the interpretability anchor that makes every
// other ceno REJECT mean something (rules R7 and R8).
// ---------------------------------------------------------------------------
fn build_dead_program(op: InsnKind, a: i32, b: i32, variant: &str) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let dead = insns.len();
    if variant == "overwritten" {
        insns.push(encode_rv32(op, 2, 3, 4, 0)); // dead: overwritten before any read
        insns.push(encode_rv32(InsnKind::ADDI, 3, 0, 4, 0)); // live overwrite
        insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    } else {
        insns.push(encode_rv32(op, 2, 3, 4, 0)); // never read at all
        insns.push(encode_rv32(InsnKind::ADDI, 3, 0, 8, 0));
        insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    }
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(dead), Role::Value, "dead_write")];
    built
}

// ---------------------------------------------------------------------------
// st_x0_dark_write — published_name "x0 dark write"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. The write-suppression predicate. ceno routes an
// architectural write whose rd is x0 to `Instruction::RD_NULL` (= register 32,
// rv32im.rs:263-269), a real 33rd register slot that `store_register` writes and
// the write-back hook therefore covers; the same path carries the explicit ecall
// dark write at vm_state.rs:337.
//
// PATH TO THE COMMITTED OUTPUT. The honest committed word is 0, because the
// program reads x0 (register 0), not RD_NULL (register 32). Any accepted forgery
// that makes it non-zero is the cleanest possible output-changed signal, and it
// would mean the AIR wired the dark write to x0.
// ---------------------------------------------------------------------------
fn build_x0_program(op: InsnKind, a: i32, b: i32) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let dark = insns.len();
    insns.push(encode_rv32(op, 2, 3, 0, 0)); // rd = x0 -> RD_NULL
    insns.push(encode_rv32(InsnKind::ADD, 0, 0, 11, 0)); // honest 0
    insns.push(encode_rv32(InsnKind::SW, 6, 11, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(dark), Role::Value, "x0_dark_write")];
    built
}

// ---------------------------------------------------------------------------
// st_loop_repeat — published_name "Loop repeat"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. One STATIC pc with many dynamic executions: the per-row
// independence of the chip, and the clk/pc continuity chain across them.
//
// PATH TO THE COMMITTED OUTPUT. The accumulator is stored into digest[0] after
// the loop, so a perturbation at any iteration reaches the commit.
//
// HONEST LIMIT (manifest blocker, TARGET_CAPABILITIES nth_supported = false).
// ceno emulates the guest THREE times per candidate — the driver pre-pass, the
// preflight pass inside `emulate_program`, and the witness replay inside
// `generate_witness` — and the three share ONE global occurrence counter, so an
// nth >= 0 arming would desynchronise them and produce a rejection that says
// nothing about the constraint system. Every site here is therefore armed at
// nth = -1: EVERY iteration is perturbed (rule R5). Per-iteration arming needs a
// per-pass counter first.
//
// Only the n16 size is built: the driver pre-pass has a 512-step budget
// (`prepass`), so the manifest's n256 and n4096 sizes would EXECFAIL on the step
// budget rather than on anything about ceno.
// ---------------------------------------------------------------------------
fn build_loop_program(op: InsnKind, a: i32, n: i32) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 9, n)); // trip count
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 4, 0)); // accumulator
    let body = insns.len();
    insns.push(encode_rv32(op, 4, 2, 4, 0));
    insns.push(encode_rv32(InsnKind::ADDI, 9, 0, 9, -1));
    insns.push(encode_rv32(InsnKind::BNE, 9, 0, 0, rel(body + 2, body)));
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(body), Role::Value, "loop_body_rd")];
    built
}

// ---------------------------------------------------------------------------
// st_multishard — published_name "Cross-shard continuation"
//   candidate_class probe | operand_source immediate | site_role value
//
// CONSTRAINT SURFACE. The shard-boundary carry. A multi-shard trace turns on the
// ShardRam table family: `StepRecord.memory_op.value.after` and `.addr` become
// committed columns only when the partner access lives in ANOTHER shard
// (`ShardContext::record_send_without_touch` emits a RAM record only when
// `!is_first_shard()`), so a whole column family that is dead in every published
// ceno candidate comes alive here.
//
// PATH TO THE COMMITTED OUTPUT. Same as `st_loop_repeat`: the accumulator, which
// is carried ACROSS the shard boundary in a register, is stored into digest[0].
//
// HOW THE BOUNDARY IS FORCED. ceno's default `max_cycle_per_shard` is 2^29
// (e2e.rs:61), which no seed of this size can reach, so this seed — and only
// this seed — overrides the shard plan through its own `MultiProver`. One
// instruction is four cycles, so `MULTISHARD_CYCLES / 4` is roughly the
// instructions per shard, and a 64-iteration loop spans several of them.
// ---------------------------------------------------------------------------
const MULTISHARD_CYCLES: u64 = 256;

fn build_multishard_program(op: InsnKind, a: i32, n: i32) -> Built {
    let mut built = build_loop_program(op, a, n);
    built.multi_prover = MultiProver::new(0, 1, u64::MAX, MULTISHARD_CYCLES);
    built
}

// ---------------------------------------------------------------------------
// st_early_exit — published_name "Early exit"
//   candidate_class probe | operand_source immediate | site_role selector
//   predicate: accepted_case_v2
//
// CONSTRAINT SURFACE. Whether the halt path is bound to the program having
// reached it. ceno commits `exit_code` and has a dedicated `HaltInstruction`
// circuit, so the question is whether a proof can terminate early and still be
// accepted with a TRUNCATED commitment.
//
// PATH TO THE COMMITTED OUTPUT. Inverted: the honest run stores the result and
// issues PUB_IO_COMMIT, and a forged selector jumps over BOTH, so the committed
// digest is the all-zero unwritten buffer. `accepted_case_strict` requires the
// output to be non-empty, which is why the manifest gives this structure
// `accepted_case_v2` ("differs from honest BY BEING ABSENT OR TRUNCATED").
// ---------------------------------------------------------------------------
fn build_early_exit_program() -> Built {
    let mut insns = prologue();
    insns.extend(li(4, 0x0E11_7E00));
    let sel = insns.len();
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 9, 0)); // honest 0 -> commit path
    let br = insns.len();
    insns.push(encode_rv32(InsnKind::BNE, 9, 0, 0, rel(br, br + 5)));
    insns.push(encode_rv32(InsnKind::SW, 6, 4, 0, 0));
    insns.push(encode_rv32(InsnKind::ADDI, 6, 0, 10, 0));
    insns.push(encode_rv32u(InsnKind::ADDI, 0, 0, 5, PubIoCommitSpec::CODE));
    insns.push(encode_rv32(InsnKind::ECALL, 0, 0, 0, 0));
    debug_assert_eq!(insns.len(), br + 5);
    insns.push(encode_rv32u(InsnKind::ADDI, 0, 0, 5, 0));
    insns.push(encode_rv32(InsnKind::ADDI, 0, 0, 10, 0));
    insns.push(encode_rv32(InsnKind::ECALL, 0, 0, 0, 0));
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(sel), Role::Selector, "exit_selector")];
    built
}

// ---------------------------------------------------------------------------
// st_initial_state — published_name "Initial state"        DECLARED NEGATIVE
// st_initial_image — published_name "Initial image"        DECLARED NEGATIVE
//   candidate_class CONTROL | operand_source immediate | site_role value
//
// BLOCKER, CONFIRMED BY READING THE CODE. ceno's initial memory is NOT a record
// field: `Program.image` -> `init_static_addrs` (e2e.rs:1248-1265) ->
// `generate_fixed_traces` (e2e.rs:1301-1320) puts the value into the FIXED trace,
// and the RAM-init columns are fixed PREPROCESSED columns
// (tables/ram/ram_impl.rs:69-76). The fixed traces are committed at keygen, so
// the initial value is in the vk. There is no record-layer operator that can move
// it, on either structure.
//
// WHAT IS BUILT ANYWAY, AND WHY. The load that DELIVERS the initial value is an
// ordinary write-back, so the seed is still coherent: the mutation claims a read
// of an address whose initial value the vk fixes. The expected verdict is
// REJECT, and the two structures differ only in what the vk fixes:
//   `st_initial_state`  reads a never-written address the image sets to ZERO
//                       (the .bss shape);
//   `st_initial_image`  reads an address the image sets NON-ZERO (the .data
//                       shape), and its `bssboundary` variant reads the .data
//                       word and the zero word immediately after it, which is
//                       the exact guest shape of the loader-layer golds in
//                       results/LOADER_LAYER_FINDINGS.md.
// An ACCEPT on either is not a control failure; it would mean the prover can
// claim an initial value the vk does not commit, and must be re-graded as a
// probe-grade finding. HONEST FRAMING: the loader-layer golds are
// COMPILATION-layer defects that an honest prover reproduces; this seed reuses
// their guest shape to ask the record-layer question they raise, nothing more.
// ---------------------------------------------------------------------------
const IMAGE_PAYLOAD: u32 = 0xDEAD_BEEF;

fn build_initial_program(kind: InsnKind, variant: &str) -> Built {
    let scratch: [u32; SCRATCH_WORDS] = match variant {
        // .bss shape: never written, initialised to zero
        "bss" => [0; SCRATCH_WORDS],
        // .data shape, and .data immediately followed by .bss
        _ => {
            let mut s = [0u32; SCRATCH_WORDS];
            s[0] = IMAGE_PAYLOAD;
            s
        }
    };
    let mut insns = prologue();
    let ld = insns.len();
    insns.push(encode_rv32(kind, 7, 0, 8, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    let mut sites = vec![(pc_of(ld), Role::Value, "init_load_rd")];
    if variant == "bssboundary" {
        let ld2 = insns.len();
        insns.push(encode_rv32(InsnKind::LW, 7, 0, 9, 4)); // the zero word after .data
        insns.push(encode_rv32(InsnKind::SW, 6, 9, 0, 4));
        sites.push((pc_of(ld2), Role::Value, "boundary_load_rd"));
    }
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image(scratch));
    built.sites = sites;
    built
}

// ---------------------------------------------------------------------------
// st_finalize_only — published_name "Finalize-only write"  DECLARED NEGATIVE
//   candidate_class CONTROL | operand_source immediate | site_role value
//   predicate: accepted_case_v2
//
// BLOCKER, CONFIRMED BY READING THE CODE. ceno's final RAM is built from
// `vm.peek_memory`, not from the record, and it is not a public output; the
// quantity a perturbation does move is `shard_rw_sum`, which is BUS BOOKKEEPING
// and must not be reported as an output forgery.
//
// WHAT IS BUILT ANYWAY. Two shapes whose perturbed value reaches ONLY the
// finalize boundary and nothing else: `mem` writes a scratch word that is never
// read again, `reg` writes a register that is never read again. Neither is
// observable in the eight digest words, so the expected outcome is REJECT or
// ACCEPT-with-unchanged-output. They differ from `st_dead_write` in that the
// forged value IS the final value of a live location, which is what puts it on
// the finalize boundary row rather than nowhere at all.
// ---------------------------------------------------------------------------
fn build_finalize_program(op: InsnKind, a: i32, b: i32, variant: &str) -> Built {
    let mut insns = prologue();
    insns.extend(li(2, a as u32));
    insns.extend(li(3, b as u32));
    let site = insns.len();
    if variant == "mem" {
        insns.push(encode_rv32(op, 2, 3, 4, 0));
        insns.push(encode_rv32(InsnKind::SW, 7, 4, 0, 16)); // final value of scratch[4]
    } else {
        insns.push(encode_rv32(op, 2, 3, 13, 0)); // final value of x13
    }
    insns.push(encode_rv32(InsnKind::ADDI, 3, 0, 8, 0));
    insns.push(encode_rv32(InsnKind::SW, 6, 8, 0, 0));
    insns.extend(publish_tail());
    let mut built = Built::new(insns, seed_image([0; SCRATCH_WORDS]));
    built.sites = vec![(pc_of(site), Role::Value, "finalize_only_write")];
    built
}

// ===================== THE STRUCTURE SEED TABLE =====================

/// One catalogued structure, instantiated as a concrete seed. The first five
/// fields are the manifest's own vocabulary and are emitted verbatim into the
/// CSV, so a row can always be joined back to `STRUCTURE_MANIFEST.yaml`.
struct StructSeed {
    /// manifest `id`
    structure_id: &'static str,
    /// manifest `published_name` — the frozen `program_structure` string
    published_name: &'static str,
    /// `<structure_id>[_<opcode>][_<variant>]`, variants from the manifest
    seed_id: String,
    /// the CSV's `concrete_opcode_or_interaction`
    opcode: String,
    /// probe | control | calibration
    candidate_class: &'static str,
    /// the mutation reaches no committed object by construction
    dead: bool,
    /// ...and its only effect is on a finalize-boundary row
    dead_final: bool,
    /// the manifest's one `xor_b0`-at-an-address exception
    bit0_exception: bool,
    built: Built,
}

fn seed(
    structure_id: &'static str,
    published_name: &'static str,
    seed_id: String,
    opcode: String,
    candidate_class: &'static str,
    built: Built,
) -> StructSeed {
    StructSeed {
        structure_id,
        published_name,
        seed_id,
        opcode,
        candidate_class,
        dead: false,
        dead_final: false,
        bit0_exception: false,
        built,
    }
}

/// Every structure this port implements, instantiated. Adding a structure means
/// adding a builder above and a block here; nothing else in the file changes.
///
/// The opcode axis obeys run-matrix rules R1-R4: every structure whose shape
/// admits an opcode parameter is crossed with `deconfound_axis`, which pairs a
/// bound reference opcode with the whole substituted unbound probe set, so
/// structure and opcode vary INDEPENDENTLY.
fn structure_seeds(a: i32, b: i32) -> Vec<StructSeed> {
    let mut v: Vec<StructSeed> = vec![];
    let axis = deconfound_axis();

    // -- st_op_then_state (must, promoted): the deconfounding shape -----------
    for (n, op) in &axis {
        for variant in ["mem", "addr", "branch"] {
            v.push(seed(
                "st_op_then_state",
                "Operation then state",
                format!("st_op_then_state_{}_{variant}", n.to_lowercase()),
                format!("{n}+{variant}"),
                "probe",
                build_op_then_state_program(*op, a, b, variant),
            ));
        }
    }

    // -- st_store_load (must): THE ceno quick win ----------------------------
    for (n, op) in &axis {
        v.push(seed(
            "st_store_load",
            "Store--load",
            format!("st_store_load_{}", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_store_load_program(*op, a, b, false),
        ));
        v.push(seed(
            "st_store_load",
            "Store--load",
            format!("st_store_load_{}_tail", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_store_load_program(*op, a, b, true),
        ));
    }

    // -- st_boundary_operand (must) ------------------------------------------
    for (variant, n, op, ba, bb) in boundary_rows() {
        v.push(seed(
            "st_boundary_operand",
            "Boundary operand",
            format!("st_boundary_operand_{}_{variant}", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_boundary_program(op, ba, bb),
        ));
    }

    // -- st_subword_lane (must) ----------------------------------------------
    for (n, k) in [
        ("LB", InsnKind::LB),
        ("LBU", InsnKind::LBU),
        ("LH", InsnKind::LH),
        ("LHU", InsnKind::LHU),
        ("LW", InsnKind::LW),
    ] {
        v.push(seed(
            "st_subword_lane",
            "Sub-word lane",
            format!("st_subword_lane_{}_load", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_subword_program(k, "load"),
        ));
    }
    for (n, k) in [
        ("SB", InsnKind::SB),
        ("SH", InsnKind::SH),
        ("SW", InsnKind::SW),
    ] {
        v.push(seed(
            "st_subword_lane",
            "Sub-word lane",
            format!("st_subword_lane_{}_store", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_subword_program(k, "store"),
        ));
    }

    // -- st_redirect (must) and st_pointer_indirect (should, promoted) -------
    v.push(seed(
        "st_redirect",
        "Redirect",
        "st_redirect_lw".to_string(),
        "LW".to_string(),
        "probe",
        build_redirect_program(),
    ));
    v.push(seed(
        "st_pointer_indirect",
        "Pointer indirect",
        "st_pointer_indirect_lw".to_string(),
        "LW".to_string(),
        "probe",
        build_pointer_indirect_program(),
    ));

    // -- st_hazard_chain (must) ----------------------------------------------
    for (n, op) in &axis {
        for variant in ["first", "second"] {
            v.push(seed(
                "st_hazard_chain",
                "Hazard chain",
                format!("st_hazard_chain_{}_{variant}", n.to_lowercase()),
                n.to_string(),
                "probe",
                build_hazard_program(*op, a, b, variant),
            ));
        }
    }

    // -- st_control_flow (must) ----------------------------------------------
    for (n, bop) in [
        ("BEQ", InsnKind::BEQ),
        ("BNE", InsnKind::BNE),
        ("BLT", InsnKind::BLT),
        ("BGE", InsnKind::BGE),
        ("BLTU", InsnKind::BLTU),
        ("BGEU", InsnKind::BGEU),
    ] {
        v.push(seed(
            "st_control_flow",
            "Control flow",
            format!("st_control_flow_{}_datadiv", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_cf_program(bop, "datadiv"),
        ));
    }
    v.push(seed(
        "st_control_flow",
        "Control flow",
        "st_control_flow_beq_dataident".to_string(),
        "BEQ".to_string(),
        "probe",
        build_cf_program(InsnKind::BEQ, "dataident"),
    ));

    // -- st_provenance_chain (must) and st_fanout_read (should) --------------
    for (n, op) in &axis {
        for (cn, cop) in consumer_axis() {
            for depth in ["d2", "d4"] {
                v.push(seed(
                    "st_provenance_chain",
                    "Provenance chain",
                    format!(
                        "st_provenance_chain_{}_{}_{depth}",
                        n.to_lowercase(),
                        cn.to_lowercase()
                    ),
                    format!("{n}+{cn}"),
                    "probe",
                    build_chain_program(*op, cop, a, b, depth),
                ));
            }
            v.push(seed(
                "st_fanout_read",
                "Fan-out read",
                format!("st_fanout_read_{}_{}", n.to_lowercase(), cn.to_lowercase()),
                format!("{n}+{cn}"),
                "probe",
                build_fanout_program(*op, cop, a, b),
            ));
        }
    }

    // -- st_loop_repeat (must) and st_multishard (must) ----------------------
    for (n, op) in &axis {
        v.push(seed(
            "st_loop_repeat",
            "Loop repeat",
            format!("st_loop_repeat_{}_n16", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_loop_program(*op, a, 16),
        ));
        v.push(seed(
            "st_multishard",
            "Cross-shard continuation",
            format!("st_multishard_{}", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_multishard_program(*op, a, 64),
        ));
    }

    // -- st_indirect_jump (should) -------------------------------------------
    for variant in ["table", "bit0"] {
        let mut s = seed(
            "st_indirect_jump",
            "Indirect jump",
            format!("st_indirect_jump_jalr_{variant}"),
            "JALR".to_string(),
            "probe",
            build_jalr_program(variant),
        );
        s.bit0_exception = variant == "bit0";
        v.push(s);
    }

    // -- st_pc_imm_value (should) --------------------------------------------
    for variant in ["auipc", "lui", "jal"] {
        v.push(seed(
            "st_pc_imm_value",
            "PC-immediate value",
            format!("st_pc_imm_value_{variant}"),
            variant.to_uppercase(),
            "probe",
            build_pcimm_program(variant),
        ));
    }

    // -- st_reg_alias (should) -----------------------------------------------
    for (n, op) in &axis {
        for variant in ["rs1rs2", "rdrs1rs2"] {
            v.push(seed(
                "st_reg_alias",
                "Register aliasing",
                format!("st_reg_alias_{}_{variant}", n.to_lowercase()),
                n.to_string(),
                "probe",
                build_reg_alias_program(*op, a, variant),
            ));
        }
    }

    // -- st_pv_plumbing (should) ---------------------------------------------
    for (n, op) in [
        ("ADD", InsnKind::ADD),
        ("XOR", InsnKind::XOR),
        ("AND", InsnKind::AND),
    ] {
        v.push(seed(
            "st_pv_plumbing",
            "Public-value plumbing",
            format!("st_pv_plumbing_{}_words8", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_pv_plumbing_program(op, a, b, "words8"),
        ));
    }
    for variant in ["alias", "exitcode"] {
        v.push(seed(
            "st_pv_plumbing",
            "Public-value plumbing",
            format!("st_pv_plumbing_{variant}"),
            "ADD".to_string(),
            "probe",
            build_pv_plumbing_program(InsnKind::ADD, a, b, variant),
        ));
    }

    // -- st_early_exit (should) ----------------------------------------------
    v.push(seed(
        "st_early_exit",
        "Early exit",
        "st_early_exit_bne".to_string(),
        "BNE".to_string(),
        "probe",
        build_early_exit_program(),
    ));

    // -- st_x0_dark_write (nice) ---------------------------------------------
    for (n, op) in &axis {
        v.push(seed(
            "st_x0_dark_write",
            "x0 dark write",
            format!("st_x0_dark_write_{}", n.to_lowercase()),
            n.to_string(),
            "probe",
            build_x0_program(*op, a, b),
        ));
    }

    // -- CONTROLS. Rule R7: on a target that has never produced an accepted
    //    case these come FIRST, because without them no REJECT is interpretable.
    for (n, op) in &axis {
        for variant in ["overwritten", "neverread"] {
            let mut s = seed(
                "st_dead_write",
                "Dead write-back",
                format!("st_dead_write_{}_{variant}", n.to_lowercase()),
                n.to_string(),
                "control",
                build_dead_program(*op, a, b, variant),
            );
            s.dead = true;
            v.push(s);
        }
        for variant in ["mem", "reg"] {
            let mut s = seed(
                "st_finalize_only",
                "Finalize-only write",
                format!("st_finalize_only_{}_{variant}", n.to_lowercase()),
                n.to_string(),
                "control",
                build_finalize_program(*op, a, b, variant),
            );
            s.dead = true;
            s.dead_final = true;
            v.push(s);
        }
    }

    // -- DECLARED NEGATIVES for the initial-memory surface -------------------
    v.push(seed(
        "st_initial_state",
        "Initial state",
        "st_initial_state_lw_bss".to_string(),
        "LW".to_string(),
        "control",
        build_initial_program(InsnKind::LW, "bss"),
    ));
    for (n, k) in [("LW", InsnKind::LW), ("LBU", InsnKind::LBU)] {
        v.push(seed(
            "st_initial_image",
            "Initial image",
            format!("st_initial_image_{}_data", n.to_lowercase()),
            n.to_string(),
            "control",
            build_initial_program(k, "data"),
        ));
    }
    v.push(seed(
        "st_initial_image",
        "Initial image",
        "st_initial_image_lw_bssboundary".to_string(),
        "LW".to_string(),
        "control",
        build_initial_program(InsnKind::LW, "bssboundary"),
    ));

    v
}

// ===================== THE STRUCTURE ENUMERATION =====================

/// The CSV contract of STRUCTURE_MANIFEST.yaml. The first 30 columns are exactly
/// the ones the published ceno runs already emit, unchanged in name, meaning and
/// order; the eight after them are the manifest's `csv_contract`
/// `required_new_columns` plus the two join keys (`structure_id`, `site_label`)
/// that let a row be traced back to a manifest cell.
const STRUCT_HEADER: &str = "run_tag,target,revision,seed_id,mutation_mode,program_structure,\
opcode,pc,nth,dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,\
failure_stage,hits,pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,\
t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed,operand_source,\
candidate_class,accepted_case_v2,site_role,scored_against,structure_id,site_label,\
predicate_version";

impl StructSeed {
    /// STRUCTURE_MANIFEST `predicate_version_required` for this structure.
    fn predicate_version(&self) -> &'static str {
        match self.structure_id {
            "st_finalize_only" | "st_early_exit" | "st_dead_write" => "accepted_case_v2",
            _ => "accepted_case_strict",
        }
    }
}

/// One CSV row, plus whether it is a strict accepted case.
///
/// `accepted_case` is the FROZEN `accepted_case_strict` predicate, computed
/// exactly as the published enumerations compute it, so no published number can
/// move. `accepted_case_v2` is the manifest's additive extension: strict, OR the
/// committed output differs from honest BY BEING ABSENT. On ceno the two
/// coincide in almost every case, because the driver reads an unwritten commit
/// buffer as eight ZERO words rather than as an empty string, so a truncated
/// commitment already satisfies strict; the column is emitted anyway so the
/// corpus is comparable with the ports where they differ.
///
/// `scored_against` is `out_of_circuit` — TARGET_CAPABILITIES declares ceno's
/// strict predicate to read `digest_words_peeked`, the eight words at DIGEST_PTR
/// taken with `vm.peek_memory`. The in-circuit object (`public_io_digest`) is
/// bound equal to those words at the ecall cycle by `PubIoCommitLayout`, and the
/// exit code — the other committed public value — is carried separately in
/// `committed_digest` / `digest_changed`, which is where the `exitcode` variant
/// of st_pv_plumbing is scored.
#[allow(clippy::too_many_arguments)]
fn struct_row(
    tag: &str,
    s: &StructSeed,
    mode: &str,
    pc: u32,
    role: Role,
    site_label: &str,
    mu_label: &str,
    template: &str,
    mkind: usize,
    marg: i64,
    c: &Out,
    honest_hex: &str,
    honest_committed: &str,
    extra_reason: &str,
) -> (String, bool) {
    let pv_hex = c
        .digest
        .map(|d| hexwords(&d))
        .unwrap_or_else(|| "NONE".to_string());
    let nonempty = pv_hex != "NONE" && !pv_hex.is_empty();
    let changed = c.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
    let accepted = c.outcome == "ACCEPT" && c.hits > 0 && changed;
    let absent = c.outcome == "ACCEPT" && c.hits > 0 && !nonempty && !honest_hex.is_empty();
    let accepted_v2 = accepted || absent;
    let committed = format!("exit{:08x}", c.exit_code);
    let digest_changed = committed != honest_committed;
    let reason = if extra_reason.is_empty() {
        c.reason.clone()
    } else if c.reason.is_empty() {
        extra_reason.to_string()
    } else {
        format!("{} {}", c.reason, extra_reason)
    };
    let row = format!(
        "{tag},{TARGET},{REV},{},{mode},{},{},{pc:#x},-1,{},{},1,{mu_label},{template},{mkind},\
{marg},{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{},immediate,{},{},{},out_of_circuit,{},{},{}",
        s.seed_id,
        s.published_name,
        s.opcode,
        s.dead,
        s.dead_final,
        c.outcome,
        c.failure_stage,
        c.hits,
        pv_hex,
        honest_hex,
        changed,
        accepted,
        c.t_record_ms,
        c.t_prove_ms,
        c.t_verify_ms,
        trunc(&reason),
        committed,
        honest_committed,
        digest_changed,
        s.candidate_class,
        accepted_v2,
        role.as_str(),
        s.structure_id,
        site_label,
        s.predicate_version(),
    );
    (format!("{row},{}", c.st.csv()), accepted)
}

/// LACUNA structure enumeration for ceno.
///
/// Runs every structure of `structure_seeds` through the SAME real pipeline the
/// published enumeration uses — honest keygen, perturbed emulation,
/// `generate_witness`, `ZKVMProver::create_proof` (GKR + Basefold),
/// `ZKVMVerifier::verify_full_trace_proofs_halt`. No MockProver, no per-chip AIR
/// check, no debug satisfiability shortcut.
///
/// THREE MUTATION FAMILIES PER SEED.
///
///   ENCODING  rewrite the architectural write-back value at a site
///             (`wb_perturb`), with the mu menu masked by the site's role.
///
///   ORDER     rewrite the recorded `previous_cycle` of one access subcycle
///             (`ts_perturb`). This changes no value the guest computes, so an
///             ACCEPT here is a "verifier accepted, committed output unchanged"
///             outcome — the necessary precursor to a stale-read forgery, not an
///             accepted case.
///
///   BINDING   BIND-O1, on the seeds that write one address twice. ceno realises
///             pico's post-trace-generation (clk, prev_clk) transposition as the
///             CONJUNCTION of its two record-layer hooks, with no post-tracegen
///             seam: `ts_perturb` re-points the load's recorded prev_cycle at the
///             SECOND-most-recent write and `wb_perturb` delivers that write's
///             value. Both are existing, frozen menu entries; nothing is added to
///             the menu. BIND-V3 — the value alone, with the order left honest —
///             is emitted alongside as the negative control, exactly as the
///             manifest defines it.
///
/// ENVIRONMENT (all optional):
///   LACUNA_OUT      CSV to append to             LACUNA_TAG   run tag
///   LACUNA_MU       "all" (default) | "xorb0"    LACUNA_A / LACUNA_B  operands
///   LACUNA_STRUCTS  comma-separated structure ids to run (default: all)
///   LACUNA_SEEDS    comma-separated seed_id prefixes to run (default: all)
///   LACUNA_AXIS     "min" shrinks the opcode axis for a smoke run and VIOLATES
///                   run-matrix rule R2; the default is the R3-compliant set
///   LACUNA_BASELINE_ONLY  "1" runs only the honest baseline of each seed, which
///                   is the cheap check that every seed builds and verifies
///
/// RUST_MIN_STACK=536870912 is MANDATORY, as for the published runs.
#[test]
#[ignore = "LACUNA evaluation run: ceno program-structure enumeration; use --release and RUST_MIN_STACK"]
fn lacuna_structure_enumeration_ceno() {
    // R3: ceno has no ESTABLISHED unbound opcode, so the deconfounding axis is
    // satisfied by proxy and the run tag has to say so.
    let tag = format!(
        "{}+unbound_probe=substituted",
        std::env::var("LACUNA_TAG").unwrap_or_else(|_| "ceno_struct".to_string())
    );
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let baseline_only = std::env::var("LACUNA_BASELINE_ONLY").as_deref() == Ok("1");
    let want_struct: Vec<String> = std::env::var("LACUNA_STRUCTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let want_seed: Vec<String> = std::env::var("LACUNA_SEEDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let (a, b) = operands();

    let mut sink: Option<std::fs::File> = std::env::var("LACUNA_OUT").ok().map(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .expect("open LACUNA_OUT")
    });
    let header = format!("{STRUCT_HEADER}{STAGE_HEADER}");
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    for s in structure_seeds(a, b) {
        if !want_struct.is_empty() && !want_struct.contains(&s.structure_id.to_string()) {
            continue;
        }
        if !want_seed.is_empty() && !want_seed.iter().any(|w| s.seed_id.starts_with(w)) {
            continue;
        }
        let program = Arc::new(s.built.program.clone());
        let platform = setup_platform(Preset::Ceno, &program, 1 << 16, 1 << 16);

        // ---- keygen from the HONEST program (vk independent of any mutation) ----
        let (max_num_variables, security_level) = default_backend_config();
        let backend = create_backend::<E, Pcs>(max_num_variables, security_level);
        let device = create_prover(backend);
        let ctx = setup_program::<E>(
            (*program).clone(),
            platform.clone(),
            s.built.multi_prover.clone(),
        );
        let (pk, vk) = ctx.keygen_with_pb(device.get_pb());
        let prover = ZKVMProver::new(pk.into(), device);
        let verifier = ZKVMVerifier::<E, Pcs, RV32imMemStateConfig>::new(vk);

        // ---- honest baseline: prove AND verify before any mutation ----
        let h = run_candidate(&program, &platform, &prover, &verifier, Arm::None);
        if h.outcome != "NOOP" {
            // A seed whose HONEST run does not verify is a broken seed, not a
            // finding. Report it and move on rather than emitting rows that
            // cannot be interpreted.
            println!(
                "LACUNA_BASELINE,{tag},{TARGET},{},BASELINE_NOT_ACCEPTED,{},{},{}",
                s.seed_id, h.outcome, h.failure_stage, h.reason
            );
            continue;
        }
        let honest_hex = hexwords(&h.digest.expect("honest digest"));
        let honest_committed = format!("exit{:08x}", h.exit_code);
        println!(
            "LACUNA_BASELINE,{tag},{TARGET},{},VERIFIED,structure={},honest_pv={honest_hex},\
t_prove_ms={},t_verify_ms={}",
            s.seed_id, s.structure_id, h.t_prove_ms, h.t_verify_ms
        );
        if baseline_only {
            continue;
        }

        let mut emit = |row: String, accepted: bool, what: String| {
            println!("LACUNA_ROW,{row}");
            if let Some(f) = sink.as_mut() {
                writeln!(f, "{row}").unwrap();
                f.flush().ok();
            }
            if accepted {
                println!("  *** ACCEPTED CASE: {what}");
            }
        };

        // ---- ENCODING family, mu menu masked by site role ----
        for (pc, role, site_label) in &s.built.sites {
            for (label, template, mkind, marg) in menu(mu_all) {
                if !mu_allowed(*role, label, s.bit0_exception) {
                    continue;
                }
                let c = run_candidate(
                    &program,
                    &platform,
                    &prover,
                    &verifier,
                    Arm::Enc {
                        pc: *pc,
                        kind: mkind,
                        arg: marg,
                    },
                );
                let (row, accepted) = struct_row(
                    &tag,
                    &s,
                    "encoding",
                    *pc,
                    *role,
                    site_label,
                    label,
                    template,
                    mkind,
                    marg,
                    &c,
                    &honest_hex,
                    &honest_committed,
                    "",
                );
                emit(
                    row,
                    accepted,
                    format!(
                        "{} {site_label} @ {pc:#x} mu={label}  write-back {:#x} -> {:#x}",
                        s.seed_id, c.honest_v, c.forged_v
                    ),
                );
            }
        }

        // ---- ORDER family ----
        for (pc, sub, subname) in &s.built.order_sites {
            for (label, template, mkind, marg) in order_menu() {
                let c = run_candidate(
                    &program,
                    &platform,
                    &prover,
                    &verifier,
                    Arm::Ord {
                        pc: *pc,
                        sub: *sub,
                        kind: mkind,
                        arg: marg,
                    },
                );
                let mu_label = format!("{subname}_{label}");
                let (row, accepted) = struct_row(
                    &tag,
                    &s,
                    "order",
                    *pc,
                    Role::Value,
                    subname,
                    &mu_label,
                    template,
                    mkind,
                    marg,
                    &c,
                    &honest_hex,
                    &honest_committed,
                    "",
                );
                let unchanged_accept = c.outcome == "ACCEPT" && c.hits > 0 && !accepted;
                emit(
                    row,
                    accepted,
                    format!("{} order {mu_label} @ {pc:#x}", s.seed_id),
                );
                if unchanged_accept {
                    println!(
                        "  ... verifier-accepted ORDER mutation, output unchanged: {} \
{mu_label} @ {pc:#x}  prev_cycle {} -> {}",
                        s.seed_id, c.honest_v, c.forged_v
                    );
                }
            }
        }

        // ---- BINDING family: BIND-O1 and its BIND-V3 negative control ----
        if let Some((lw_pc, stale, delta)) = s.built.bind {
            // BIND-O1: the two hooks armed together. `ts_perturb::with` stays
            // armed for the whole candidate, and `Arm::Enc`'s own `wb_perturb`
            // scope nests inside it, so the perturbed load both DELIVERS the
            // second-most-recent write and RECORDS a prev_cycle that points at
            // it: an internally consistent stale read.
            let c = ts_perturb::with(lw_pc, 3, -1, ts_perturb::MU_ADDK, delta, || {
                run_candidate(
                    &program,
                    &platform,
                    &prover,
                    &verifier,
                    Arm::Enc {
                        pc: lw_pc,
                        kind: wb_perturb::MU_SET,
                        arg: stale as i64,
                    },
                )
            });
            let ts_hits = ts_perturb::hits();
            let (row, accepted) = struct_row(
                &tag,
                &s,
                "binding",
                lw_pc,
                Role::Value,
                "stale_load",
                "bind_o1_swap",
                "BIND-O1",
                wb_perturb::MU_SET,
                stale as i64,
                &c,
                &honest_hex,
                &honest_committed,
                &format!("order_arm_hits={ts_hits}"),
            );
            emit(
                row,
                accepted,
                format!(
                    "{} BIND-O1 stale load @ {lw_pc:#x} -> {stale:#x} (order arm hits {ts_hits})",
                    s.seed_id
                ),
            );

            // BIND-V3: the value alone, order left honest. The record now claims
            // a value that is NOT the most recent write, with a prev_cycle that
            // still points at the most recent write; a sound memory argument must
            // reject it. This is what makes a BIND-O1 accept mean something.
            let c = run_candidate(
                &program,
                &platform,
                &prover,
                &verifier,
                Arm::Enc {
                    pc: lw_pc,
                    kind: wb_perturb::MU_SET,
                    arg: stale as i64,
                },
            );
            let (row, accepted) = struct_row(
                &tag,
                &s,
                "binding",
                lw_pc,
                Role::Value,
                "stale_load_neg_control",
                "neg_control_no_swap",
                "BIND-V3",
                wb_perturb::MU_SET,
                stale as i64,
                &c,
                &honest_hex,
                &honest_committed,
                "",
            );
            emit(
                row,
                accepted,
                format!("{} BIND-V3 value-only @ {lw_pc:#x} -> {stale:#x}", s.seed_id),
            );
        }
    }
    println!("LACUNA_DONE,{tag}");
}
