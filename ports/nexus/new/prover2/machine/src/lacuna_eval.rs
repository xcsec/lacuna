//! LACUNA EVALUATION DRIVER for nexus — instrumented, candidate-level enumeration
//! of ENCODING mutations on the nexus execution record.
//!
//! Contains no bug knowledge. It enumerates
//!
//!     site = (static pc, n-th execution of that pc)
//!     mu   = one entry of an instruction-independent rewriting menu
//!
//! over the single architectural write-back choke point
//! (`nexus_vm::trace::wb_perturb::on_write_back`, called from `trace::step`), and
//! lets nexus's own emulator continue from the perturbed value so that every later
//! register snapshot, dependent store and memory record follows naturally.
//!
//! The whole `k_trace` call runs inside the armed scope, so the returned `View`
//! carries the public output the *perturbed* execution produced. Proving that trace
//! against that view is exactly "a malicious prover ran a perturbed execution and
//! claims its output"; the verifier accepting it means the constraint system did not
//! bind that write-back to the program and inputs.
//!
//! Environment (all optional):
//!   LACUNA_OUT    path of the CSV to append to (default: stdout only)
//!   LACUNA_TAG    free-form run tag copied into every row
//!   LACUNA_OPS    comma-separated opcode names to enumerate (default: all)
//!   LACUNA_MU     "xorb0" (single mu) | "all" (the 11-entry menu, default)

use nexus_common::constants::ELF_TEXT_START;
use nexus_vm::{
    elf::ElfFile,
    emulator::InternalView,
    memory::MemorySegmentImage,
    riscv::{BuiltinOpcode, Instruction, Opcode},
    trace::{k_trace, wb_perturb, Trace},
};
use std::{io::Write, time::Instant};

use crate::{prove, verify};

const REV: &str = "f2ad12652c39dc516a116447a53f8557f64a7f7d";

// ===========================================================================
// LACUNA CPU CALIBRATION INSTRUMENTATION (ADDITIVE — measurement only).
// Nothing below changes constraint, AIR, witness-generation or executor
// semantics. It records, per candidate, wall time and process CPU time
// (user+system, aggregated over every thread of the process, read from
// /proc/self/stat fields 14/15) for the four pipeline stages.
// ===========================================================================
pub(crate) mod cpuprobe {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub const R: Ordering = Ordering::Relaxed;
    /// Sentinel: this stage was never entered on this candidate.
    pub const NM: u64 = u64::MAX;

    pub static S1_WALL_US: AtomicU64 = AtomicU64::new(NM);
    pub static S1_CPU_MS: AtomicU64 = AtomicU64::new(NM);
    pub static S2_WALL_US: AtomicU64 = AtomicU64::new(NM);
    pub static S2_CPU_MS: AtomicU64 = AtomicU64::new(NM);
    pub static S3_WALL_US: AtomicU64 = AtomicU64::new(NM);
    pub static S3_CPU_MS: AtomicU64 = AtomicU64::new(NM);
    pub static S4_WALL_US: AtomicU64 = AtomicU64::new(NM);
    pub static S4_CPU_MS: AtomicU64 = AtomicU64::new(NM);

    /// Process-wide user+system CPU in ms. /proc/self/stat fields 14 (utime)
    /// and 15 (stime) are thread-group aggregates in USER_HZ ticks; USER_HZ was
    /// verified to be 100 on this host (`getconf CLK_TCK` -> 100), so one tick
    /// is 10 ms and the resolution of every CPU number below is 10 ms.
    pub fn cpu_ms() -> u64 {
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

    pub fn reset() {
        for a in [
            &S1_WALL_US, &S1_CPU_MS, &S2_WALL_US, &S2_CPU_MS, &S3_WALL_US, &S3_CPU_MS,
            &S4_WALL_US, &S4_CPU_MS,
        ] {
            a.store(NM, R);
        }
    }

    pub fn g(a: &AtomicU64) -> u64 {
        a.load(R)
    }
    /// value or 0 when the stage was not entered (for the "other" residual)
    pub fn g0(a: &AtomicU64) -> u64 {
        match a.load(R) {
            NM => 0,
            v => v,
        }
    }
    pub fn wall_cell(v: u64) -> String {
        if v == NM {
            "NA".to_string()
        } else {
            format!("{:.1}", v as f64 / 1000.0)
        }
    }
    pub fn cpu_cell(v: u64) -> String {
        if v == NM {
            "NA".to_string()
        } else {
            format!("{v}")
        }
    }
}

/// VERBATIM CLONE of `prover2/machine/src/prove.rs::prove` at rev f2ad126, with
/// two stage probes inserted and NOTHING else changed. Splitting the shipped
/// `prove()` in place would have meant editing production code, so the clone
/// carries the probes instead. The boundary is placed exactly where witness
/// generation ends: S2 = `SideNote::new` + `generate_component_trace` over all
/// 54 BASE_COMPONENTS (+ `log_size` collection); S3 = everything the shipped
/// function does after that (twiddles, Blake2s channel, the three
/// `tree_builder.commit`s, `draw_lookup_elements`, `generate_interaction_trace`,
/// component-prover construction and `stwo::prover::prove`).
/// NOTE: `generate_interaction_trace` is LogUp witness generation but the
/// shipped code interleaves it with the commitment scheme, so it is counted in
/// S3; see the caveats in the run record.
mod timed_prove {
    use nexus_vm::{emulator::View, trace::Trace};
    use nexus_vm_prover_trace::{
        component::ComponentTrace,
        eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
    };
    use std::time::Instant;
    use stwo::{
        core::{
            channel::{Blake2sChannel, Channel},
            fields::qm31::SecureField,
            pcs::PcsConfig,
            poly::circle::CanonicCoset,
            vcs::blake2_merkle::Blake2sMerkleChannel,
        },
        prover::{
            backend::simd::SimdBackend, poly::circle::PolyOps, CommitmentSchemeProver,
            ComponentProver, ProvingError,
        },
    };
    use stwo_constraint_framework::TraceLocationAllocator;

    use super::cpuprobe::*;
    use crate::{
        lookups::AllLookupElements, side_note::SideNote, Proof, BASE_COMPONENTS,
    };

    pub fn prove_timed(trace: &impl Trace, view: &View) -> Result<Proof, ProvingError> {
        // ---------------- S2: trace / witness generation ----------------
        let w2 = Instant::now();
        let c2 = cpu_ms();

        let mut prover_side_note = SideNote::new(trace, view);
        let components = BASE_COMPONENTS;

        let traces: Vec<ComponentTrace> = components
            .iter()
            .map(|c| c.generate_component_trace(&mut prover_side_note))
            .collect();
        let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();

        S2_WALL_US.store(w2.elapsed().as_micros() as u64, R);
        S2_CPU_MS.store(cpu_ms().saturating_sub(c2), R);

        // ---------------- S3: proof generation ----------------
        let w3 = Instant::now();
        let c3 = cpu_ms();

        let max_constraint_log_degree_bound = components
            .iter()
            .zip(&log_sizes)
            .map(|(c, &log_size)| c.max_constraint_log_degree_bound(log_size))
            .max()
            .unwrap_or(0);

        // Precompute twiddles.
        let config = PcsConfig::default();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(max_constraint_log_degree_bound + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        // Setup protocol.
        let prover_channel = &mut Blake2sChannel::default();
        for byte in view.view_associated_data().unwrap_or_default() {
            prover_channel.mix_u64(byte.into());
        }

        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
        log_sizes.iter().for_each(|log_size| {
            prover_channel.mix_u64(*log_size as u64);
        });

        // Preprocessed trace.
        let mut tree_builder = commitment_scheme.tree_builder();
        for component_trace in &traces {
            let _preprocessed_trace_location = tree_builder
                .extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);

        // Main trace.
        let mut tree_builder = commitment_scheme.tree_builder();
        for component_trace in &traces {
            let _main_trace_location =
                tree_builder.extend_evals(component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX));
        }
        tree_builder.commit(prover_channel);

        let mut lookup_elements = AllLookupElements::default();
        components
            .iter()
            .for_each(|c| c.draw_lookup_elements(&mut lookup_elements, prover_channel));

        // Interaction trace.
        let mut tree_builder = commitment_scheme.tree_builder();
        let claimed_sums: Vec<SecureField> = components
            .iter()
            .zip(traces)
            .map(|(c, component_trace)| {
                let (interaction_trace, claimed_sum) =
                    c.generate_interaction_trace(component_trace, &prover_side_note, &lookup_elements);
                tree_builder.extend_evals(interaction_trace);

                claimed_sum
            })
            .collect();
        prover_channel.mix_felts(&claimed_sums);
        tree_builder.commit(prover_channel);

        let tree_span_provider = &mut TraceLocationAllocator::default();
        let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
            .iter()
            .zip(&log_sizes)
            .zip(&claimed_sums)
            .map(|((c, log_size), claimed_sum)| {
                c.to_component_prover(tree_span_provider, &lookup_elements, *log_size, *claimed_sum)
            })
            .collect();
        let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
            components.iter().map(|c| &**c).collect();

        let proof = match stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>(
            &components_ref,
            prover_channel,
            commitment_scheme,
        ) {
            Ok(p) => p,
            Err(e) => {
                // A rejected prove still SPENT the proving time.
                S3_WALL_US.store(w3.elapsed().as_micros() as u64, R);
                S3_CPU_MS.store(cpu_ms().saturating_sub(c3), R);
                return Err(e);
            }
        };

        S3_WALL_US.store(w3.elapsed().as_micros() as u64, R);
        S3_CPU_MS.store(cpu_ms().saturating_sub(c3), R);

        Ok(Proof {
            stark_proof: proof,
            claimed_sums,
            log_sizes,
        })
    }
}

fn enc(op: BuiltinOpcode, a: u8, b: u8, c: u32) -> u32 {
    Instruction::new_ir(Opcode::from(op), a, b, c).encode()
}

/// The custom `wou rs2, 0(rs1)` write-output store, hand-encoded (the encoder panics
/// on non-keccak custom opcodes). Stores `reg[rs2]` at `reg[rs1]`.
fn wou(rs2: u32, rs1: u32) -> u32 {
    (rs2 << 20) | (rs1 << 15) | 0b1011011
}

/// LACUNA seed — program structure: Single operation.
///
/// ```text
/// p0: ADDI x1, x0, a        ; x1 = a
/// p1: ADDI x2, x0, b        ; x2 = b
/// p2: OP   x5, x1, x2       ; x5 = a OP b     <- the operation under test
/// p3: LW   x6, 0x84(x0)     ; x6 = output base
/// p4: ADDI x7, x6, 4        ; x7 = public_output_start
/// p5: wou  x5, x7           ; output[+4] = x5  <- routes the result to the commit
/// p6: wou  x0, x6           ; output[+0] = exit code
/// p7: ADDI x17, x0, 0x201   ; a7 = SYS_EXIT
/// p8: ADDI x10, x0, 0
/// p9: ECALL
/// ```
/// The store at p5 is what makes the operation's result publicly observable; without
/// it a mutation can be accepted without changing anything a verifier is shown.
fn build_op_elf(op: BuiltinOpcode, a: u32, b: u32) -> ElfFile {
    let instructions: Vec<u32> = vec![
        enc(BuiltinOpcode::ADDI, 1, 0, a),
        enc(BuiltinOpcode::ADDI, 2, 0, b),
        enc(op, 5, 1, 2),
        enc(BuiltinOpcode::LW, 6, 0, 0x84),
        enc(BuiltinOpcode::ADDI, 7, 6, 4),
        wou(5, 7),
        wou(0, 6),
        enc(BuiltinOpcode::ADDI, 17, 0, 0x201),
        enc(BuiltinOpcode::ADDI, 10, 0, 0),
        0x0000_0073,
    ];
    let ram_base = ELF_TEXT_START + (instructions.len() as u32) * 4;
    let mut ram_image = MemorySegmentImage::empty_at(ram_base);
    ram_image.push_word(0);
    ElfFile::new(
        instructions,
        ELF_TEXT_START,
        ELF_TEXT_START,
        MemorySegmentImage::empty_at(ELF_TEXT_START),
        ram_image,
        Vec::new(),
    )
}

/// The instruction-independent rewriting menu. (label, template, mu_kind, mu_arg)
/// Mirrors the pico menu so the two targets are directly comparable; the word width
/// here is 32 bits, so the limb indices are i in {0,1} for B = 2^16 and the boundary
/// values are {0, 2^31, 2^32 - 1}.
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

/// Every opcode the seed builder can put at p2 and that writes a register.
fn opcodes() -> Vec<(&'static str, BuiltinOpcode)> {
    use BuiltinOpcode::*;
    vec![
        ("ADD", ADD), ("SUB", SUB), ("SLL", SLL), ("SLT", SLT), ("SLTU", SLTU),
        ("XOR", XOR), ("SRL", SRL), ("SRA", SRA), ("OR", OR), ("AND", AND),
        ("MUL", MUL), ("MULH", MULH), ("MULHSU", MULHSU), ("MULHU", MULHU),
        ("DIV", DIV), ("DIVU", DIVU), ("REM", REM), ("REMU", REMU),
    ]
}

fn hexout(v: &Option<Vec<u8>>) -> String {
    match v {
        None => "NONE".to_string(),
        Some(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
    }
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
    out: Option<Vec<u8>>,
    honest_v: u32,
    forged_v: u32,
    t_record_ms: u128,
    t_prove_ms: u128,
    t_verify_ms: u128,
}

/// One candidate through the REAL pipeline: armed emulation -> perturbed record and
/// its View -> real prove -> real verify.
fn run_candidate(op: BuiltinOpcode, a: u32, b: u32, pc: u32, kind: usize, arg: i64) -> Out {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| {
        // nth = -1: arm EVERY execution of this static pc. `k_trace` emulates the
        // program twice (Harvard, then Linear::from_harvard); perturbing only one
        // pass would desynchronise the two and produce a rejection that says nothing
        // about the constraint system.
        wb_perturb::with(pc, -1, kind, arg, || {
            // ---- S1: mutation construction + suffix replay ----
            // For nexus the mutation is not a post-hoc record edit: the write-back
            // hook is armed by `wb_perturb::with` above and the guest is re-executed
            // under it, so constructing R' and replaying the suffix are the same
            // `k_trace` call; every later register snapshot / dependent store follows.
            let w1 = Instant::now();
            let c1 = cpuprobe::cpu_ms();
            let elf = build_op_elf(op, a, b);
            let t0 = Instant::now();
            let traced = k_trace(elf, &[], &[], &[], 1);
            let t_record = t0.elapsed().as_millis();
            cpuprobe::S1_WALL_US.store(w1.elapsed().as_micros() as u64, cpuprobe::R);
            cpuprobe::S1_CPU_MS.store(cpuprobe::cpu_ms().saturating_sub(c1), cpuprobe::R);
            let (view, trace) = match traced {
                Ok(x) => x,
                Err(e) => {
                    return Err((
                        format!("{e:?}"),
                        t_record,
                        0u128,
                        wb_perturb::hits(),
                        wb_perturb::honest_value(),
                        wb_perturb::forged_value(),
                    ))
                }
            };
            let hits = wb_perturb::hits();
            let (hv, fv) = (wb_perturb::honest_value(), wb_perturb::forged_value());
            let t1 = Instant::now();
            let proof = match timed_prove::prove_timed(&trace, &view) {
                Ok(p) => p,
                // A rejected prove still SPENT the proving time; recording 0 here
                // would understate the cost of exactly the outcome that dominates
                // the run (rejection), so the elapsed time is taken on this path too.
                Err(e) => {
                    return Err((
                        format!("prove: {e:?}"),
                        t_record,
                        t1.elapsed().as_millis(),
                        hits,
                        hv,
                        fv,
                    ))
                }
            };
            let t_prove = t1.elapsed().as_millis();
            // ---- S4: verification ----
            let w4 = Instant::now();
            let c4 = cpuprobe::cpu_ms();
            let t2 = Instant::now();
            let res = verify(proof, &view);
            let t_verify = t2.elapsed().as_millis();
            cpuprobe::S4_WALL_US.store(w4.elapsed().as_micros() as u64, cpuprobe::R);
            cpuprobe::S4_CPU_MS.store(cpuprobe::cpu_ms().saturating_sub(c4), cpuprobe::R);
            Ok((
                view.view_public_output(),
                res,
                hits,
                hv,
                fv,
                t_record,
                t_prove,
                t_verify,
            ))
        })
    });
    std::panic::set_hook(prev);
    match r {
        Ok(Ok((out, Ok(()), hits, hv, fv, tr, tp, tv))) => Out {
            outcome: if hits > 0 { "ACCEPT" } else { "NOOP" },
            failure_stage: if hits > 0 { "accepted_proof" } else { "mutation" },
            reason: String::new(),
            hits, out, honest_v: hv, forged_v: fv,
            t_record_ms: tr, t_prove_ms: tp, t_verify_ms: tv,
        },
        Ok(Ok((out, Err(e), hits, hv, fv, tr, tp, tv))) => Out {
            outcome: "REJECT",
            failure_stage: "verify",
            reason: trunc(&format!("{e:?}")),
            hits, out, honest_v: hv, forged_v: fv,
            t_record_ms: tr, t_prove_ms: tp, t_verify_ms: tv,
        },
        Ok(Err((msg, tr, tp, hits, hv, fv))) => {
            let proveish = msg.starts_with("prove:");
            Out {
                outcome: if proveish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if proveish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits, out: None, honest_v: hv, forged_v: fv,
                t_record_ms: tr, t_prove_ms: tp, t_verify_ms: 0,
            }
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque>".to_string());
            let constraintish = msg.contains("logup")
                || msg.contains("constraint")
                || msg.contains("Constraint")
                || msg.contains("commitment");
            Out {
                outcome: if constraintish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if constraintish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits: 0, out: None, honest_v: 0, forged_v: 0,
                t_record_ms: 0, t_prove_ms: 0, t_verify_ms: 0,
            }
        }
    }
}

#[test]
#[ignore = "LACUNA evaluation run: nexus record-layer encoding enumeration; use --release"]
fn lacuna_encoding_enumeration_nexus() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "nexus".to_string());
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let want: Vec<String> = std::env::var("LACUNA_OPS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Operands. `a` is the 12-bit ADDI immediate 0xA5B, which sign-extends to
    // 0xFFFF_FA5B = -1445; `b` is 13. A positive `a` made SLT, SLTU, SRL and SRA
    // all commit an honest output of zero, which is a degenerate baseline: the
    // honest value carries no information and every rewrite is trivially visible.
    // With a negative `a`, nine of the ten opcodes commit a distinct non-zero
    // result and SLT (1) separates from SLTU (0).
    let (a, b) = (0xA5Bu32, 13u32);

    let mut sink: Option<std::fs::File> = std::env::var("LACUNA_OUT").ok().map(|p| {
        std::fs::OpenOptions::new().create(true).append(true).open(p).expect("open LACUNA_OUT")
    });
    let header = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,\
dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,\
pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,\
committed_digest,honest_committed_digest,digest_changed";
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    // ---- per-candidate CPU-calibration sink (additive; off unless LACUNA_CPU_OUT) ----
    let mut cpu_sink: Option<std::fs::File> = std::env::var("LACUNA_CPU_OUT").ok().map(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .expect("open LACUNA_CPU_OUT")
    });
    let cpu_header = "candidate_key,seed_id,opcode,mutation_template,outcome,failure_stage,\
s1_replay_wall_ms,s1_replay_cpu_ms,s2_tracegen_wall_ms,s2_tracegen_cpu_ms,s3_prove_wall_ms,\
s3_prove_cpu_ms,s4_verify_wall_ms,s4_verify_cpu_ms,other_wall_ms,other_cpu_ms,total_wall_ms,\
total_cpu_ms";
    if let Some(f) = cpu_sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{cpu_header}").unwrap();
        }
    }

    for (name, op) in opcodes() {
        if !want.is_empty() && !want.contains(&name.to_string()) {
            continue;
        }
        let seed = format!("op_{}", name.to_lowercase());

        // ---- honest baseline ----
        // The line format is the one the pico driver emits, so a single inventory
        // collector reads every target:
        //   LACUNA_BASELINE,<tag>,<target>,<revision>,<seed>,<k=v>...
        let elf = build_op_elf(op, a, b);
        let t0 = Instant::now();
        let (hview, htrace) = match k_trace(elf, &[], &[], &[], 1) {
            Ok(x) => x,
            Err(e) => {
                println!(
                    "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{seed},stage=exec,reason={:?}",
                    trunc(&format!("{e:?}"))
                );
                continue;
            }
        };
        let honest_record_ms = t0.elapsed().as_millis();
        let t1 = Instant::now();
        let hproof = match prove(&htrace, &hview) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{seed},stage=prove,reason={:?}",
                    trunc(&format!("{e:?}"))
                );
                continue;
            }
        };
        let honest_prove_ms = t1.elapsed().as_millis();
        let t2 = Instant::now();
        let hverify = verify(hproof, &hview);
        let honest_verify_ms = t2.elapsed().as_millis();
        if let Err(e) = hverify {
            // An honest program its own prover cannot verify is a COMPLETENESS
            // result, and the seed has no accepted baseline: it is excluded from the
            // mutation evaluation and reported separately.
            println!(
                "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{seed},stage=verify,reason={:?}",
                trunc(&format!("{e:?}"))
            );
            continue;
        }
        let honest_out = hview.view_public_output();
        let honest_hex = hexout(&honest_out);
        let steps = htrace.get_num_steps();

        // ---- sites: every static pc in the honest trace that writes a register ----
        let mut sites: Vec<(u32, usize)> = vec![];
        {
            let mut seen: std::collections::BTreeMap<u32, usize> = Default::default();
            for blk in htrace.get_blocks_iter() {
                for st in &blk.steps {
                    if st.result.is_some() {
                        *seen.entry(st.pc).or_insert(0) += 1;
                    }
                }
            }
            for (pc, n) in seen {
                sites.push((pc, n));
            }
        }
        println!(
            "LACUNA_BASELINE,{tag},nexus,{REV},{seed},instructions={},writebacks={},\
static_sites={},honest_pv={honest_hex},honest_record_ms={honest_record_ms},\
honest_prove_ms={honest_prove_ms},honest_verify_ms={honest_verify_ms}",
            steps,
            sites.iter().map(|(_, n)| n).sum::<usize>(),
            sites.len(),
        );
        // The instruction mix of the seed, in the same shape the pico driver emits.
        println!(
            "LACUNA_OPCENSUS,{tag},{seed},ADDI:4 LW:1 SW:2 ECALL:1 {name}:1"
        );

        for (pc, execs) in &sites {
            for (label, template, kind, arg) in menu(mu_all) {
                cpuprobe::reset();
                let cand_w = Instant::now();
                let cand_c = cpuprobe::cpu_ms();
                let c = run_candidate(op, a, b, *pc, kind, arg);
                let pv_hex = hexout(&c.out);
                let nonempty = !pv_hex.is_empty() && pv_hex != "NONE";
                let changed = c.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
                let accepted = c.outcome == "ACCEPT" && c.hits > 0 && changed;
                let row = format!(
                    "{tag},nexus,{REV},{seed},encoding,Single operation,{name},{pc:#x},0,\
false,false,{execs},{label},{template},{kind},{arg},{},{},{},{},{},{},{},{},{},{},\"{}\",NA,NA,NA",
                    c.outcome, c.failure_stage, c.hits, pv_hex, honest_hex, changed, accepted,
                    c.t_record_ms, c.t_prove_ms, c.t_verify_ms, c.reason
                );
                println!("LACUNA_ROW,{row}");
                if let Some(f) = sink.as_mut() {
                    writeln!(f, "{row}").unwrap();
                    f.flush().ok();
                }
                if accepted {
                    println!(
                        "  *** ACCEPTED CASE: {name} @ {pc:#x} mu={label}  \
honest write-back {:#x} -> {:#x}; committed output {honest_hex} -> {pv_hex}",
                        c.honest_v, c.forged_v
                    );
                }

                // ---- per-candidate totals: everything in this loop iteration ----
                let total_wall_us = cand_w.elapsed().as_micros() as u64;
                let total_cpu = cpuprobe::cpu_ms().saturating_sub(cand_c);
                use cpuprobe::*;
                let staged_wall_us =
                    g0(&S1_WALL_US) + g0(&S2_WALL_US) + g0(&S3_WALL_US) + g0(&S4_WALL_US);
                let staged_cpu = g0(&S1_CPU_MS) + g0(&S2_CPU_MS) + g0(&S3_CPU_MS) + g0(&S4_CPU_MS);
                let other_wall_us = total_wall_us.saturating_sub(staged_wall_us);
                let other_cpu = total_cpu.saturating_sub(staged_cpu);
                let cpu_row = format!(
                    "{seed}@{pc:#x}#{label},{seed},{name},{template},{},{},{},{},{},{},{},{},{},{},{:.1},{},{:.1},{}",
                    c.outcome,
                    c.failure_stage,
                    wall_cell(g(&S1_WALL_US)),
                    cpu_cell(g(&S1_CPU_MS)),
                    wall_cell(g(&S2_WALL_US)),
                    cpu_cell(g(&S2_CPU_MS)),
                    wall_cell(g(&S3_WALL_US)),
                    cpu_cell(g(&S3_CPU_MS)),
                    wall_cell(g(&S4_WALL_US)),
                    cpu_cell(g(&S4_CPU_MS)),
                    other_wall_us as f64 / 1000.0,
                    other_cpu,
                    total_wall_us as f64 / 1000.0,
                    total_cpu,
                );
                println!("LACUNA_CPU,{cpu_row}");
                if let Some(f) = cpu_sink.as_mut() {
                    writeln!(f, "{cpu_row}").unwrap();
                    f.flush().ok();
                }
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}

/// Dump the real `Step` records nexus's emulator hands to witness generation, for
/// `x5 = DIVU(x1, x2)` with x1 = 4, x2 = 2. Documentation only: it proves nothing and
/// is not part of the evaluation corpus.
#[test]
#[ignore = "documentation: prints the nexus execution record for DIVU(4,2)"]
fn lacuna_dump_divu_record_nexus() {
    let elf = build_op_elf(BuiltinOpcode::DIVU, 4, 2);
    let (_view, trace) = k_trace(elf, &[], &[], &[], 1).expect("emulate");
    // k_trace was called with k = 1, so each Block carries exactly one Step.
    for (i, blk) in trace.get_blocks_iter().enumerate() {
        for st in &blk.steps {
            println!(
                "======== block {i}: {:?} ========",
                st.instruction.opcode.builtin()
            );
            println!("regs (Block.regs) x1={} x2={} x5={}", blk.regs[nexus_vm::riscv::Register::X1], blk.regs[nexus_vm::riscv::Register::X2], blk.regs[nexus_vm::riscv::Register::X5]);
            println!("{st:#?}");
        }
    }
}

// ===========================================================================
// LACUNA PROGRAM-STRUCTURE CATALOG (ADDITIVE — nothing above this line moves).
//
// Everything below adds NEW seed builders and a NEW enumeration entry point,
// `lacuna_structure_enumeration_nexus`. The shipped
// `lacuna_encoding_enumeration_nexus` test, `build_op_elf`, the mutation menu
// and the acceptance predicate are untouched, so the published corpus still
// reproduces byte for byte.
//
// The catalog, the frozen `program_structure` strings, the candidate classes,
// the site-role mu masks and the run-matrix rules are spec data, not driver
// opinion; they come from
//
//     evaluation/spec/STRUCTURE_MANIFEST.yaml
//     evaluation/spec/TARGET_CAPABILITIES.yaml
//
// TARGET FACTS THAT SHAPE EVERY SEED BELOW
//
//  * prover2's BASE_COMPONENTS (lib.rs:9) carries NO M-extension component and
//    NO precompile component, so every seed here stays inside RV32I. The
//    manifest's `m_ext` opcode set, and with it the DIV/REM boundary variants
//    of st_boundary_operand, are out of scope on this target — not skipped,
//    unreachable.
//  * `k_trace` emulates the program TWICE (Harvard pass, then
//    `LinearEmulator::from_harvard`) behind one global occurrence counter, so
//    TARGET_CAPABILITIES nth_supported = false and run-matrix rule R5 allows
//    only nth = -1. Every row below records nth = -1.
//  * The public output is the final content of a FIXED region whose base the
//    guest reads from the layout sentinel at 0x84; the Harvard pass sizes that
//    region from the span of the output writes it observes. A seed that skips
//    an output store therefore SHRINKS the committed output, which is what
//    makes st_early_exit expressible here.
//  * The write-back hook (vm/src/trace.rs:303-315) perturbs `Step.result` and
//    then mirrors the forged value into the emulator's register file, so the
//    honest emulator continues from it and every later address, store and load
//    follows for free. That is the whole reason the memory-shaped structures
//    below are reachable at all with a value-only hook.
//
// REGISTER MAP, used consistently by every builder:
//     x1, x2   operands a, b
//     x3       public-input base pointer (operand_source = input)
//     x4       static-RAM base pointer (materialised by a patched ADDI)
//     x5       result of the opcode under test
//     x6, x7   output-region pointers (publish epilogue)
//     x8       the word published to the public output
//     x9       scratch pointer / loaded value
//     x10, x17 exit syscall (a0, a7)
//     x11-x15, x28-x31  scratch
// ===========================================================================

/// The custom `rin rd, imm(rs1)` read-input load, hand-encoded (the encoder
/// panics on non-keccak custom opcodes). custom-1 = `0b0101011`, funct3 `0b000`,
/// interpreted as `lw` against the public-input segment. This is the canonical
/// nexus input path: `runtime/src/lib.rs:97-112` emits exactly
/// `lw t, 0x80(x0); add t, t, i; .insn i 0b0101011, 0b000, rd, 0(t)`.
fn rin(rd: u8, rs1: u8, imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0b0101011
}

/// `li rd, v` — LUI + ADDI, the canonical 32-bit constant materialisation.
/// `enc` masks an I-type immediate to 12 bits and the decoder sign-extends it,
/// so anything outside [-2048, 2047] needs the pair. Two instructions means TWO
/// write-back sites: the LUI carries the high half, the ADDI the whole word.
fn li(rd: u8, v: u32) -> [u32; 2] {
    let hi = v.wrapping_add(0x800) >> 12;
    let lo = v & 0xFFF;
    [
        enc(BuiltinOpcode::LUI, rd, 0, hi),
        enc(BuiltinOpcode::ADDI, rd, rd, lo),
    ]
}

/// The shared publish epilogue: route `src` to the single public-output word and
/// exit(0). Identical in shape to the tail of `build_op_elf`, which is what makes
/// the new seeds comparable with the shipped ones.
///
/// ```text
/// LW   x6, 0x84(x0)     ; x6 = exit-code address (layout sentinel)
/// ADDI x7, x6, 4        ; x7 = public_output_start
/// wou  src, x7          ; output[0] = reg[src]   <- the observable
/// wou  x0,  x6          ; exit code = 0
/// ADDI x17, x0, 0x201   ; a7 = SYS_EXIT
/// ADDI x10, x0, 0
/// ECALL
/// ```
///
/// Returns `(address_sites, syscall_arg_sites)`: the two pointer write-backs and
/// the two syscall-argument write-backs the epilogue contributes. The syscall
/// ones are FORBIDDEN by the manifest's site-role mask (perturbing an ECALL code
/// register makes the record generator panic before any verdict exists), so they
/// are declared here and then never enumerated.
fn push_epilogue(code: &mut Vec<u32>, src: u8) -> ([usize; 2], [usize; 2]) {
    let base = code.len();
    code.extend_from_slice(&[
        enc(BuiltinOpcode::LW, 6, 0, 0x84),
        enc(BuiltinOpcode::ADDI, 7, 6, 4),
        wou(src as u32, 7),
        wou(0, 6),
        enc(BuiltinOpcode::ADDI, 17, 0, 0x201),
        enc(BuiltinOpcode::ADDI, 10, 0, 0),
        0x0000_0073,
    ]);
    ([base, base + 1], [base + 4, base + 5])
}

/// Where a seed's two operands come from.
///
/// Every seed in `structure_seeds` uses `Input`, because
/// TARGET_CAPABILITIES operand_source_required is `input` on this target.
/// `Immediate` is kept because it is the form the SHIPPED corpus uses and the
/// form a cross-target comparison has to be able to reproduce.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operands {
    /// `li x1, a ; li x2, b` — baked into the vk-committed program text.
    /// STRUCTURE_MANIFEST input_contract calls this out as the weaker form: an
    /// operand that is part of the committed program can only make a target look
    /// safer than it is.
    Immediate,
    /// `lw x3, 0x80(x0) ; rin x1, 4(x3) ; rin x2, 8(x3)` — read from the public
    /// input segment, which is what TARGET_CAPABILITIES operand_source_required
    /// asks for on this target.
    Input,
}

impl Operands {
    fn tag(self) -> &'static str {
        match self {
            Operands::Immediate => "immediate",
            Operands::Input => "input",
        }
    }
}

/// Emit the operand prologue: x1 = a, x2 = b. Returns the instructions and the
/// public-input bytes `k_trace` must be handed alongside them.
fn prologue(src: Operands, a: u32, b: u32) -> (Vec<u32>, Vec<u8>) {
    match src {
        Operands::Immediate => {
            let mut v = Vec::new();
            v.extend_from_slice(&li(1, a));
            v.extend_from_slice(&li(2, b));
            (v, Vec::new())
        }
        Operands::Input => {
            let code = vec![
                // 0x80 holds the public-input start address in the linear pass and
                // 0 in the Harvard pass, where the input segment is based at 0.
                enc(BuiltinOpcode::LW, 3, 0, 0x80),
                // offset 0 is the input length word, so the payload starts at +4.
                rin(1, 3, 4),
                rin(2, 3, 8),
            ];
            let mut input = a.to_le_bytes().to_vec();
            input.extend_from_slice(&b.to_le_bytes());
            (code, input)
        }
    }
}

/// An address a builder can only fill in once the program length is known.
enum Patch {
    /// `ADDI rd, x0, ram_base + off`
    RamPtr { at: usize, rd: u8, off: u32 },
    /// `ADDI rd, x0, ELF_TEXT_START + 4 * idx`
    CodePtr { at: usize, rd: u8, idx: usize },
}

/// Turn an instruction vector into an `ElfFile`, resolving the address patches and
/// laying out the static-RAM image immediately after the text.
///
/// The RAM image must hold at least one word or `LinearMemoryLayout::validate`
/// rejects the layout (vm/src/emulator/layout.rs:161-165).
fn assemble(mut code: Vec<u32>, patches: &[Patch], ram: &[u32]) -> ElfFile {
    let ram_base = ELF_TEXT_START + (code.len() as u32) * 4;
    for p in patches {
        let (at, rd, addr) = match *p {
            Patch::RamPtr { at, rd, off } => (at, rd, ram_base + off),
            Patch::CodePtr { at, rd, idx } => (at, rd, ELF_TEXT_START + 4 * idx as u32),
        };
        // A single ADDI carries a 12-bit signed immediate, so every address a seed
        // materialises this way must stay below 2^11. All seeds here are far shorter
        // than that; the assert exists so a future longer seed fails loudly instead
        // of silently pointing somewhere else.
        assert!(
            addr < 0x800,
            "seed too long: address {addr:#x} does not fit a sign-extended 12-bit ADDI"
        );
        code[at] = enc(BuiltinOpcode::ADDI, rd, 0, addr);
    }
    // MEASURED COMPLETENESS CONSTRAINT, not a style rule. A static RAM image of 3
    // or 7 words has NO verifying honest baseline on this revision: nexus's own
    // prover returns ConstraintsNotSatisfied for an HONEST execution, while 1, 2,
    // 4, 5, 6 and 8 words all prove and verify (see
    // `lacuna_static_ram_size_completeness_nexus`; sizes above 8 were not
    // measured). A seed that tripped this would be silently dropped from the
    // corpus by its own failing baseline, so fail loudly at build time instead.
    assert!(
        !matches!(ram.len(), 3 | 7),
        "static RAM image of {} words has no verifying honest baseline on nexus \
         (measured; see lacuna_static_ram_size_completeness_nexus)",
        ram.len()
    );
    let mut image = MemorySegmentImage::empty_at(ram_base);
    if ram.is_empty() {
        image.push_word(0);
    } else {
        for w in ram {
            image.push_word(*w);
        }
    }
    ElfFile::new(
        code,
        ELF_TEXT_START,
        ELF_TEXT_START,
        MemorySegmentImage::empty_at(ELF_TEXT_START),
        image,
        Vec::new(),
    )
}

/// One entry of the structure catalog: an ELF, the inputs it runs with, and the
/// spec metadata every CSV row inherits.
struct Seed {
    /// unique within this target; never collides with the frozen `op_*` ids
    seed_id: String,
    /// STRUCTURE_MANIFEST.yaml structure id
    structure_id: &'static str,
    /// STRUCTURE_MANIFEST.yaml published_name — the seven frozen strings verbatim
    published_name: &'static str,
    /// the opcode the structure puts under test, or "-" when the shape has no
    /// opcode parameter
    opcode: String,
    operand_source: &'static str,
    /// class of every site that is not listed in `dead_sites` / `calib_sites`
    candidate_class: &'static str,
    /// instruction indices whose write-back carries an ADDRESS
    addr_sites: Vec<usize>,
    /// instruction indices whose write-back carries a SELECTOR (a branch or
    /// index-forming operand one mu-step from a constraint discontinuity)
    sel_sites: Vec<usize>,
    /// instruction indices whose write-back is an ECALL argument. The manifest
    /// forbids the whole menu here, so these are declared and never enumerated.
    syscall_sites: Vec<usize>,
    /// instruction indices whose write-back is provably never read again — the
    /// declared-negative arm inside an otherwise live seed
    dead_sites: Vec<usize>,
    /// instruction indices that deliver a value from the nondeterministic channel
    calib_sites: Vec<usize>,
    /// true when this seed's dead sites are never read AT ALL (as opposed to
    /// overwritten before a read), so their only trace is the finalise boundary
    dead_final: bool,
    /// manifest role-mask exception: xor_b0 is legal at an address site for the
    /// st_indirect_jump bit0 variant and nowhere else
    jalr_bit0: bool,
    elf: ElfFile,
    public_input: Vec<u8>,
    private_input: Vec<u8>,
}

impl Seed {
    /// Default metadata; every builder overrides what it needs.
    fn new(
        seed_id: String,
        structure_id: &'static str,
        published_name: &'static str,
        opcode: String,
        operand_source: &'static str,
        elf: ElfFile,
        public_input: Vec<u8>,
    ) -> Self {
        Seed {
            seed_id,
            structure_id,
            published_name,
            opcode,
            operand_source,
            candidate_class: "probe",
            addr_sites: Vec::new(),
            sel_sites: Vec::new(),
            syscall_sites: Vec::new(),
            dead_sites: Vec::new(),
            calib_sites: Vec::new(),
            dead_final: false,
            jalr_bit0: false,
            elf,
            public_input,
            private_input: Vec::new(),
        }
    }

    fn with_epilogue_roles(mut self, addr: [usize; 2], sysc: [usize; 2]) -> Self {
        self.addr_sites.extend_from_slice(&addr);
        self.syscall_sites.extend_from_slice(&sysc);
        self
    }

    /// STRUCTURE_MANIFEST.yaml enumerations.site_role for one static site.
    fn site_role(&self, idx: usize) -> &'static str {
        if self.syscall_sites.contains(&idx) {
            "syscall_arg"
        } else if self.addr_sites.contains(&idx) {
            "address"
        } else if self.sel_sites.contains(&idx) {
            "selector"
        } else {
            "value"
        }
    }

    /// STRUCTURE_MANIFEST.yaml enumerations.candidate_class for one static site.
    fn class_at(&self, idx: usize) -> &'static str {
        if self.dead_sites.contains(&idx) {
            "control"
        } else if self.calib_sites.contains(&idx) {
            "calibration"
        } else {
            self.candidate_class
        }
    }
}

/// STRUCTURE_MANIFEST.yaml mu_menu.role_masks. A pair the spec forbids is never
/// emitted as a candidate, so the corpus is not padded with rows whose only
/// possible outcome is a self-inflicted EXECFAIL.
///
/// NOTE ON THE ADDRESS MASK ON THIS TARGET. The allowed pointer steps are
/// alignment-preserving multiples of 2^15, which were chosen against guests whose
/// mapped image is megabytes wide. A programmatic nexus seed is about a kilobyte,
/// so every allowed step leaves the mapped image and the honest expectation at an
/// address site here is EXECFAIL. The informative step would be `addr_delta_w`
/// (+/- one word), which the manifest lists as PROPOSED, NOT IMPLEMENTED
/// ANYWHERE; the menu is frozen, so it is not added here. Where a structure needs
/// a productive address forgery the seed instead masks a forged VALUE into a slot
/// index in-guest (st_op_then_state variant `addr`), which is a value-role site.
fn mu_allowed(role: &str, label: &str, jalr_bit0: bool) -> bool {
    match role {
        "value" | "selector" => true,
        "address" => {
            matches!(
                label,
                "plus_B1" | "minus_B1" | "xor_b15" | "plus_B1_hi" | "xor_b31"
            ) || (jalr_bit0 && label == "xor_b0")
        }
        // FORBIDDEN EVERYWHERE TODAY (manifest mu_menu.role_masks).
        "syscall_arg" => false,
        _ => true,
    }
}

/// opcode_sets.alu_bound_reference — the BOUND arm of the deconfounding pair.
fn alu_bound_reference() -> Vec<(&'static str, BuiltinOpcode)> {
    use BuiltinOpcode::*;
    vec![("ADD", ADD), ("XOR", XOR), ("AND", AND)]
}

/// opcode_sets.target_unbound_probe under run-matrix rule R3.
///
/// TARGET_CAPABILITIES known_unbound_opcodes is EMPTY and NOT DETERMINED for
/// nexus, so R3 says to substitute the target's full shift_family and its full
/// m_ext, and to say so in the run tag. m_ext is dropped because prover2
/// BASE_COMPONENTS has no M-extension component at all: an M opcode cannot even
/// produce a verifying HONEST baseline here, so it is not a substitution, it is
/// an unreachable one. shift_family_w does not exist on an RV32 target.
fn unbound_probe_substituted() -> Vec<(&'static str, BuiltinOpcode)> {
    use BuiltinOpcode::*;
    vec![("SLL", SLL), ("SRL", SRL), ("SRA", SRA)]
}

/// opcode_sets.deconfound_min: run-matrix rule R2's minimum — at least one
/// bound reference opcode plus the WHOLE substituted unbound-probe set. This is
/// the axis that makes structure and opcode vary independently, which is exactly
/// what the shipped pico matrix failed to do.
fn deconfound_min() -> Vec<(&'static str, BuiltinOpcode)> {
    let mut v = vec![alu_bound_reference()[0]];
    v.extend(unbound_probe_substituted());
    v
}

/// The full R2 set, used where a structure has a single variant and the extra
/// breadth is free (nexus is the cheapest target in the corpus).
fn deconfound_full() -> Vec<(&'static str, BuiltinOpcode)> {
    let mut v = alu_bound_reference();
    v.extend(unbound_probe_substituted());
    v
}

/// opcode_sets.consumer_set, restricted to what prover2 can prove: chips with a
/// tight operand decomposition, so the question is whether a forged value
/// survives someone else's operand-side range checks. MUL is in the manifest set
/// and is unreachable here.
fn consumer_set() -> Vec<(&'static str, BuiltinOpcode)> {
    use BuiltinOpcode::*;
    vec![("ADD", ADD), ("SLT", SLT)]
}

/// opcode_sets.branch
fn branch_set() -> Vec<(&'static str, BuiltinOpcode)> {
    use BuiltinOpcode::*;
    vec![
        ("BEQ", BEQ),
        ("BNE", BNE),
        ("BLT", BLT),
        ("BGE", BGE),
        ("BLTU", BLTU),
        ("BGEU", BGEU),
    ]
}

/// The operand pair every structure that does not specify its own one uses.
/// Mirrors the shipped seed's choice: a negative `a` keeps nine of ten opcodes
/// committing a distinct non-zero result instead of a degenerate zero.
const OPERAND_A: u32 = 0xFFFF_FA5B;
const OPERAND_B: u32 = 13;

/// Start a seed: emit the operand prologue and return the code, the public input,
/// and the site indices the prologue itself contributes.
///
/// With `Operands::Input` the prologue is
/// `lw x3,0x80(x0)` (a POINTER write-back) followed by two `rin` reads, so index 0
/// is an address site and indices 1 and 2 carry the operands.
fn begin(src: Operands, a: u32, b: u32) -> (Vec<u32>, Vec<u8>, Vec<usize>, Vec<usize>) {
    let (code, input) = prologue(src, a, b);
    let (addr, operand) = match src {
        Operands::Input => (vec![0usize], vec![1usize, 2usize]),
        // li rd,v is LUI+ADDI, so the operand-carrying write-backs are 1 and 3.
        Operands::Immediate => (vec![], vec![1usize, 3usize]),
    };
    (code, input, addr, operand)
}

// ---------------------------------------------------------------------------
// st_op_then_state — "Operation then state"  (must, probe, site_role value)
//
// PROMOTED STRUCTURE, and the deconfounding shape. The opcode under test does not
// reach the commit directly: its result first traverses ONE state interaction, so
// an accept proves the forgery survived a re-binding hop.
//
// CONSTRAINT SURFACE: the opcode chip AND the memory / address-formation / branch
// chip IN SERIES, with the register-consistency argument as the carrier.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT:
//   mem    forged x5 -> SW into the static-RAM word -> LW back -> x8 -> wou -> output
//   addr   forged x5 -> masked to a slot index -> LW from the OTHER object -> output
//   branch forged x5 -> masked to a bit -> branch decision -> which constant is
//          published -> output
// ---------------------------------------------------------------------------
fn build_op_then_state_elf(variant: &str, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, mut addr, _operand) = begin(src, OPERAND_A, OPERAND_B);
    let mut sel: Vec<usize> = Vec::new();
    let ram: Vec<u32>;

    match variant {
        // rd traverses a store--load round trip before it is committed.
        "mem" => {
            let i0 = code.len();
            code.push(0); // patched: ADDI x4, x0, ram_base
            code.push(enc(op, 5, 1, 2));
            code.push(enc(BuiltinOpcode::SW, 4, 5, 0));
            code.push(enc(BuiltinOpcode::LW, 8, 4, 0));
            addr.push(i0);
            let elf_patch = [Patch::RamPtr { at: i0, rd: 4, off: 0 }];
            ram = vec![0];
            let (ea, es) = push_epilogue(&mut code, 8);
            let elf = assemble(code, &elf_patch, &ram);
            let mut s = Seed::new(
                format!("st_op_then_state_mem_{}", op_name(op).to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                op_name(op).to_string(),
                src.tag(),
                elf,
                input,
            )
            .with_epilogue_roles(ea, es);
            s.addr_sites.extend(addr);
            s.sel_sites = sel;
            return s;
        }
        // rd BECOMES an address: it is masked in-guest to a legal, word-aligned
        // slot index, so the mutation stays inside the mapped image and selects a
        // different live object instead of trapping the executor.
        "addr" => {
            let i0 = code.len();
            code.push(0); // patched: ADDI x4, x0, ram_base
            let i1 = code.len();
            code.push(enc(op, 5, 1, 2));
            let i2 = code.len();
            code.push(enc(BuiltinOpcode::ANDI, 9, 5, 4)); // slot index: 0 or 4
            let i3 = code.len();
            code.push(enc(BuiltinOpcode::ADD, 9, 4, 9)); // &slot[0] or &slot[1]
            code.push(enc(BuiltinOpcode::SW, 4, 1, 0)); // slot0 = a
            code.push(enc(BuiltinOpcode::SW, 4, 2, 4)); // slot1 = b
            code.push(enc(BuiltinOpcode::LW, 8, 9, 0));
            let _ = i1;
            addr.push(i0);
            addr.push(i3);
            sel.push(i2);
            let elf_patch = [Patch::RamPtr { at: i0, rd: 4, off: 0 }];
            ram = vec![0, 0];
            let (ea, es) = push_epilogue(&mut code, 8);
            let elf = assemble(code, &elf_patch, &ram);
            let mut s = Seed::new(
                format!("st_op_then_state_addr_{}", op_name(op).to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                op_name(op).to_string(),
                src.tag(),
                elf,
                input,
            )
            .with_epilogue_roles(ea, es);
            s.addr_sites.extend(addr);
            s.sel_sites = sel;
            return s;
        }
        // rd BECOMES a decision. Memory-free, so it is the variant that ports to
        // targets with no read-side hook.
        "branch" => {
            code.push(enc(op, 5, 1, 2));
            let i1 = code.len();
            code.push(enc(BuiltinOpcode::ANDI, 9, 5, 1));
            code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x111));
            code.push(enc(BuiltinOpcode::BEQ, 9, 0, 8)); // skip the override
            code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x222));
            sel.push(i1);
            ram = vec![0];
            let (ea, es) = push_epilogue(&mut code, 8);
            let elf = assemble(code, &[], &ram);
            let mut s = Seed::new(
                format!("st_op_then_state_branch_{}", op_name(op).to_lowercase()),
                "st_op_then_state",
                "Operation then state",
                op_name(op).to_string(),
                src.tag(),
                elf,
                input,
            )
            .with_epilogue_roles(ea, es);
            s.addr_sites.extend(addr);
            s.sel_sites = sel;
            return s;
        }
        _ => unreachable!("unknown st_op_then_state variant {variant}"),
    }
}

/// Mnemonic for an opcode, so a seed id and the CSV `opcode` column agree.
fn op_name(op: BuiltinOpcode) -> &'static str {
    use BuiltinOpcode::*;
    match op {
        ADD => "ADD", SUB => "SUB", SLL => "SLL", SLT => "SLT", SLTU => "SLTU",
        XOR => "XOR", SRL => "SRL", SRA => "SRA", OR => "OR", AND => "AND",
        LB => "LB", LH => "LH", LW => "LW", LBU => "LBU", LHU => "LHU",
        SB => "SB", SH => "SH", SW => "SW",
        BEQ => "BEQ", BNE => "BNE", BLT => "BLT", BGE => "BGE",
        BLTU => "BLTU", BGEU => "BGEU",
        LUI => "LUI", AUIPC => "AUIPC", JAL => "JAL", JALR => "JALR",
        ADDI => "ADDI", ANDI => "ANDI", ORI => "ORI", XORI => "XORI",
        SLLI => "SLLI", SRLI => "SRLI", SRAI => "SRAI",
        SLTI => "SLTI", SLTIU => "SLTIU", ECALL => "ECALL",
        _ => "OTHER",
    }
}

// ---------------------------------------------------------------------------
// st_boundary_operand — "Boundary operand"  (must, probe, site_role selector)
//
// Same shape as Single operation, but the honest operands sit ONE mu-step from a
// constraint discontinuity, so the mutation drives an AIR-derived SELECTOR (the
// shift-amount decomposition, the limb-carry chain, the sign boundary) rather
// than an AIR-derived value. G recomputes the result coherently from the forged
// operand, which is what separates this from st_single_op.
//
// The `zero` and `exactdiv` variants of the manifest are DIV/REM shapes and are
// unreachable here: prover2 BASE_COMPONENTS has no M-extension component.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: the perturbed operand-setup write-back is
// re-read by the opcode under test, whose recomputed result is published directly.
// ---------------------------------------------------------------------------
fn build_boundary_operand_elf(pair: &str, a: u32, b: u32, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, operand) = begin(src, a, b);
    code.push(enc(op, 5, 1, 2));
    let (ea, es) = push_epilogue(&mut code, 5);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_boundary_operand_{pair}_{}", op_name(op).to_lowercase()),
        "st_boundary_operand",
        "Boundary operand",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    // The operand write-backs ARE the selector: the whole point of the structure is
    // that a single mu-step across the boundary changes an AIR-derived flag.
    s.sel_sites = operand;
    s
}

// ---------------------------------------------------------------------------
// st_subword_lane — "Sub-word lane"  (must, probe, site_role value)
//
// Wide store, narrow load, and the mirror. CONSTRAINT SURFACE: lane selection and
// sign/zero extension in the load AIR (LB/LBU/LH/LHU components), lane merge and
// sibling-lane preservation in the store AIR (SB/SH).
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: load side, the narrow load's rd IS the
// published word; store side, the reassembled wide word is published, so the
// untouched lanes are visible too.
// ---------------------------------------------------------------------------
fn build_subword_elf(side: &str, op: BuiltinOpcode, src: Operands) -> Seed {
    // A pattern whose four bytes and two halves are all distinct and whose top bit
    // is set, so sign- and zero-extension separate.
    let (mut code, input, mut addr, _) = begin(src, 0x8090_A0B0, 0x0000_00C5);
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base
    addr.push(i0);
    code.push(enc(BuiltinOpcode::SW, 4, 1, 0)); // wide store

    let publish_reg;
    match side {
        "load" => {
            let off = match op {
                BuiltinOpcode::LB | BuiltinOpcode::LBU => 3,
                _ => 2,
            };
            code.push(enc(op, 8, 4, off)); // narrow load of one lane
            publish_reg = 8;
        }
        "store" => {
            let off = match op {
                BuiltinOpcode::SB => 1,
                _ => 2,
            };
            code.push(enc(op, 4, 2, off)); // narrow store into one lane
            code.push(enc(BuiltinOpcode::LW, 8, 4, 0)); // read the merged word back
            publish_reg = 8;
        }
        _ => unreachable!("unknown st_subword_lane side {side}"),
    }
    let (ea, es) = push_epilogue(&mut code, publish_reg);
    let elf = assemble(code, &[Patch::RamPtr { at: i0, rd: 4, off: 0 }], &[0]);
    let mut s = Seed::new(
        format!("st_subword_lane_{side}_{}", op_name(op).to_lowercase()),
        "st_subword_lane",
        "Sub-word lane",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_store_load — "Store--load"  (must, probe, site_role value)  FROZEN NAME
//
// store(p,v1); store(p,v2); commit(load(p)) — TIME disambiguation at one address.
// CONSTRAINT SURFACE: read-after-write at one address (does the offline-memory
// argument bind the delivered value to the MOST RECENT write?). The `_tail`
// variant adds a trailing store so the load is not the finalize-boundary row,
// which separates the read-after-write question from the boundary question.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: the forged v2 is stored, loaded back into
// x8 and published; forging the load's own rd publishes it directly.
// ---------------------------------------------------------------------------
fn build_store_load_elf(tail: bool, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base
    addr.push(i0);
    code.push(enc(op, 9, 1, 2)); // the opcode under test produces v2
    code.push(enc(BuiltinOpcode::SW, 4, 1, 0)); // *p = v1
    code.push(enc(BuiltinOpcode::SW, 4, 9, 0)); // *p = v2   (most recent)
    code.push(enc(BuiltinOpcode::LW, 8, 4, 0)); // x = *p
    if tail {
        code.push(enc(BuiltinOpcode::SW, 4, 2, 0)); // keeps the load off the boundary
    }
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[Patch::RamPtr { at: i0, rd: 4, off: 0 }], &[0]);
    let suffix = if tail { "_tail" } else { "" };
    let mut s = Seed::new(
        format!("st_store_load{suffix}_{}", op_name(op).to_lowercase()),
        "st_store_load",
        "Store--load",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_redirect — "Redirect"  (must, probe, site_role address)  FROZEN NAME
//
// Two live addresses; the mutation site is the instruction that MATERIALISES THE
// POINTER — SPACE disambiguation, as opposed to Store--load's TIME
// disambiguation. CONSTRAINT SURFACE: address derivation and the (addr, value)
// pairing in the offline-memory argument. nexus is the target this was designed
// for: the address is recomputed in store/mod.rs:141 but taken from
// Step.memory_records in read_write_memory/trace.rs:141,201, so one record field
// has two consumers.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: a forged p1 makes the final LW deliver S2's
// contents while the record still claims a read of p1; that value is published.
// ---------------------------------------------------------------------------
fn build_redirect_elf(op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base + 0   (p1 = &S1)
    let i1 = code.len();
    code.push(0); // patched: ADDI x9, x0, ram_base + 4   (p2 = &S2)
    addr.push(i0);
    addr.push(i1);
    code.push(enc(op, 28, 1, 2)); // v1b, from the opcode under test
    code.push(enc(BuiltinOpcode::SW, 4, 1, 0)); // *p1 = v1
    code.push(enc(BuiltinOpcode::SW, 4, 28, 0)); // *p1 = v1b (arms the stale-load arm)
    code.push(enc(BuiltinOpcode::SW, 9, 2, 0)); // *p2 = v2
    code.push(enc(BuiltinOpcode::LW, 8, 4, 0)); // commit(*p1)
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(
        code,
        &[
            Patch::RamPtr { at: i0, rd: 4, off: 0 },
            Patch::RamPtr { at: i1, rd: 9, off: 4 },
        ],
        &[0, 0],
    );
    let mut s = Seed::new(
        format!("st_redirect_{}", op_name(op).to_lowercase()),
        "st_redirect",
        "Redirect",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_pointer_indirect — "Pointer indirect"  (should, probe, site_role address)
//
// PROMOTED STRUCTURE. Distinct from st_redirect, whose two addresses are STATIC:
// here the forged word BECOMES an address, which is the taint/composition surface
// where a value-forge escalates into address control. The dereference itself is
// entirely honest, so severity is bounded by what is in memory rather than by
// what the primitive can write.
//
// CONSTRAINT SURFACE: the memory-timestamp/address surface composed with the
// address-formation path; the dereferencing load's address is a carried register
// value and is not separately hooked on any target.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: forging the LW that delivers `p` out of
// memory changes which object the second, honest LW reads, and that object is
// published.
// ---------------------------------------------------------------------------
fn build_pointer_indirect_elf(src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, 0xAAAA_1111, 0xBBBB_2222);
    let i0 = code.len();
    code.push(0); // patched: ADDI x4,  x0, ram_base + 0   (&pp)
    let i1 = code.len();
    code.push(0); // patched: ADDI x28, x0, ram_base + 4   (&A)
    let i2 = code.len();
    code.push(0); // patched: ADDI x29, x0, ram_base + 8   (&B)
    code.push(enc(BuiltinOpcode::SW, 4, 1, 4)); // A = a
    code.push(enc(BuiltinOpcode::SW, 4, 2, 8)); // B = b
    code.push(enc(BuiltinOpcode::SW, 4, 29, 0)); // pp = &B   (first write)
    code.push(enc(BuiltinOpcode::SW, 4, 28, 0)); // pp = &A   (most recent)
    let i7 = code.len();
    code.push(enc(BuiltinOpcode::LW, 9, 4, 0)); // p = load(pp)  <- forge HERE
    code.push(enc(BuiltinOpcode::LW, 8, 9, 0)); // the dereference is honest
    addr.extend_from_slice(&[i0, i1, i2, i7]);
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(
        code,
        &[
            Patch::RamPtr { at: i0, rd: 4, off: 0 },
            Patch::RamPtr { at: i1, rd: 28, off: 4 },
            Patch::RamPtr { at: i2, rd: 29, off: 8 },
        ],
        // Three live slots plus one PAD word. The pad is not decoration: a
        // THREE-word static RAM image has no verifying honest baseline on this
        // revision (see `lacuna_static_ram_size_completeness_nexus`), so a
        // three-slot seed has to be padded to four or it is excluded from the
        // corpus by its own prover.
        &[0, 0, 0, 0],
    );
    let mut s = Seed::new(
        "st_pointer_indirect".to_string(),
        "st_pointer_indirect",
        "Pointer indirect",
        "LW".to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_initial_state — "Initial state"  (must, CONTROL on nexus)  FROZEN NAME
//
// commit(read of an address the program never wrote). DECLARED NEGATIVE:
// TARGET_CAPABILITIES init_value_hookable = false (BIND-V4, no reachable
// boundary-init record field), and the manifest's observability note requires a
// COHERENT mutation in which the delivered read value AND the initialize event
// value move together. Only the delivered value moves here, so the expected
// verdict is REJECT and the seed exists so the negative is MEASURED rather than
// asserted.
// ---------------------------------------------------------------------------
fn build_initial_state_elf() -> Seed {
    let mut code: Vec<u32> = Vec::new();
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base
    code.push(enc(BuiltinOpcode::LW, 8, 4, 0)); // never written by this program
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[Patch::RamPtr { at: i0, rd: 4, off: 0 }], &[0]);
    let mut s = Seed::new(
        "st_initial_state_bss".to_string(),
        "st_initial_state",
        "Initial state",
        "LW".to_string(),
        "immediate",
        elf,
        Vec::new(),
    )
    .with_epilogue_roles(ea, es);
    s.candidate_class = "control";
    s.addr_sites.push(i0);
    s
}

// ---------------------------------------------------------------------------
// st_initial_image — "Initial image"  (should, CONTROL on nexus)
//
// PROMOTED STRUCTURE, and a DIFFERENT surface from st_initial_state: this reads
// an address the ELF IMAGE initialises to a NON-ZERO value (.data), not a
// never-written zero address (.bss). results/LOADER_LAYER_FINDINGS.md records
// .data/.bss boundary defects on 5 of 8 VMs with 3 end-to-end golds and
// st_initial_state cannot reach any of them; `bssboundary` reproduces their guest
// shape (a non-zero .data word immediately followed by zero .bss words).
//
// HONEST FRAMING: those golds are COMPILATION-layer defects that an honest prover
// produces. This structure asks the record-layer question they raise and doubles
// as the paired negative that makes an accept on st_initial_state specific.
//
// DECLARED NEGATIVE on nexus for the same BIND-V4 reason; expected verdict
// REJECT. An ACCEPT here is NOT a control failure: it would mean the prover can
// claim an initial value the vk does not commit, and must be re-graded as a
// probe-grade finding.
// ---------------------------------------------------------------------------
fn build_initial_image_elf(variant: &str) -> Seed {
    let mut code: Vec<u32> = Vec::new();
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base
    code.push(enc(BuiltinOpcode::LW, 8, 4, 0)); // read the image-initialised word
    let (ea, es) = push_epilogue(&mut code, 8);
    let ram: Vec<u32> = match variant {
        // one .data word, nothing after it
        "data" => vec![0xDEAD_BEEF],
        // the dword-boundary shape from the loader-layer ledger: a non-zero .data
        // word immediately followed by zero words. FOUR words, not three: a
        // three-word static RAM image has no verifying honest baseline on this
        // revision (see `lacuna_static_ram_size_completeness_nexus`).
        "bssboundary" => vec![0xDEAD_BEEF, 0, 0, 0],
        _ => unreachable!("unknown st_initial_image variant {variant}"),
    };
    let elf = assemble(code, &[Patch::RamPtr { at: i0, rd: 4, off: 0 }], &ram);
    let mut s = Seed::new(
        format!("st_initial_image_{variant}"),
        "st_initial_image",
        "Initial image",
        "LW".to_string(),
        "immediate",
        elf,
        Vec::new(),
    )
    .with_epilogue_roles(ea, es);
    s.candidate_class = "control";
    s.addr_sites.push(i0);
    s
}

// ---------------------------------------------------------------------------
// st_hazard_chain — "Hazard chain"  (must, probe, site_role value)  FROZEN NAME
//
// Two architectural writes to one register with no intervening read, then the
// dependent read. CONSTRAINT SURFACE: register write-after-write retirement — the
// second write's (prev_value, prev_timestamp) must equal the first write's record.
//
// The FIRST write is declared dead: it is overwritten before any read, so its best
// outcome is ACCEPT-with-unchanged-output, which is a binding datum and never an
// accepted case. The SECOND write reaches the commit directly.
// ---------------------------------------------------------------------------
fn build_hazard_elf(op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let dead = code.len();
    code.push(enc(op, 5, 1, 0)); // write 1 to x5 -- dead
    code.push(enc(op, 5, 2, 0)); // write 2 to x5 -- live
    code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_hazard_chain_{}", op_name(op).to_lowercase()),
        "st_hazard_chain",
        "Hazard chain",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s.dead_sites.push(dead);
    s
}

// ---------------------------------------------------------------------------
// st_control_flow — "Control flow"  (must, probe, site_role selector) FROZEN NAME
//
// x = c ? v1 : v2, with the mutation site pinned to the instruction PRODUCING c.
// CONSTRAINT SURFACE: the branch chip's comparison columns and the
// taken/not-taken -> next_pc transition. It is the only structure in which a
// forged value changes WHICH ROWS EXIST. Step.next_pc is reachable in prover2
// (branch_eq/mod.rs:184, jal/mod.rs:99->111) and dead in the v1 prover crate.
//
// The manifest's DATA-IDENTICAL variant is NOT built here; see the run record.
// nexus's committed object is the public-output region alone, so a divergence
// that changes only the trace has no observable and the strict predicate requires
// output_changed.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: the forged condition operand selects the
// other arm, and the arm's constant is published.
// ---------------------------------------------------------------------------
fn build_cf_elf(op: BuiltinOpcode, src: Operands) -> Seed {
    // c = 5, v = 13: BEQ/BGE/BGEU fall through, BNE/BLT/BLTU take the branch, so
    // both arms are exercised across the opcode axis.
    let (mut code, input, addr, operand) = begin(src, 5, 13);
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x111));
    code.push(enc(op, 1, 2, 8)); // the branch under test; +8 skips the override
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x222));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_control_flow_datadiv_{}", op_name(op).to_lowercase()),
        "st_control_flow",
        "Control flow",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s.sel_sites = operand;
    s
}

// ---------------------------------------------------------------------------
// st_provenance_chain — "Provenance chain"  (must, probe, site_role value)
//
// One value carried through the maximum number of distinct constraint surfaces
// before it is committed. CONSTRAINT SURFACE: the operand-READ side of a chip
// that did NOT produce the value — limb decomposition and range checks applied to
// an incoming operand, usually tighter than the same chip's result binding — and,
// at depth 4, the memory argument in series. The measurement is the HOP at which
// the candidate flips from accept to reject.
// ---------------------------------------------------------------------------
fn build_chain_elf(depth: u32, op1: BuiltinOpcode, op2: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let mut patches: Vec<Patch> = Vec::new();
    if depth == 4 {
        let i0 = code.len();
        code.push(0); // patched: ADDI x4, x0, ram_base
        addr.push(i0);
        patches.push(Patch::RamPtr { at: i0, rd: 4, off: 0 });
        code.push(enc(op1, 5, 1, 2));
        code.push(enc(BuiltinOpcode::SW, 4, 5, 0));
        code.push(enc(BuiltinOpcode::LW, 9, 4, 0));
        code.push(enc(op2, 8, 9, 1));
    } else {
        code.push(enc(op1, 5, 1, 2));
        code.push(enc(op2, 8, 5, 1));
    }
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &patches, &[0]);
    let mut s = Seed::new(
        format!(
            "st_provenance_chain_d{depth}_{}_{}",
            op_name(op1).to_lowercase(),
            op_name(op2).to_lowercase()
        ),
        "st_provenance_chain",
        "Provenance chain",
        op_name(op1).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_loop_repeat — "Loop repeat"  (must, probe, site_role value)
//
// One static pc executed N times. CONSTRAINT SURFACE: lookup and range-check
// MULTIPLICITY accounting plus the pc/clk continuity chain — forging all N
// occurrences moves a whole multiplicity bucket.
//
// PARTIAL ON THIS TARGET, and the CSV says so. `k_trace` emulates twice behind one
// global occurrence counter, so nth >= 0 is unavailable (TARGET_CAPABILITIES
// nth_supported = false) and run-matrix rule R5 allows only nth = -1: every
// execution of the body is mutated, not the j-th. The j-dependent divergence that
// makes this structure a consistency check on nth arming is therefore NOT
// measured here.
// ---------------------------------------------------------------------------
fn build_loop_elf(n: u32, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_B, 1);
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0)); // accumulator
    if n < 0x800 {
        code.push(enc(BuiltinOpcode::ADDI, 28, 0, n));
    } else {
        code.extend_from_slice(&li(28, n));
    }
    let body = code.len();
    code.push(enc(BuiltinOpcode::ADD, 8, 8, 1)); // ONE static pc, N write-backs
    code.push(enc(BuiltinOpcode::ADDI, 28, 28, 0xFFF)); // -1
    code.push(enc(BuiltinOpcode::BNE, 28, 0, ((body as i64 - (code.len() as i64)) * 4) as u32));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_loop_repeat_n{n}"),
        "st_loop_repeat",
        "Loop repeat",
        "ADD".to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_hint_advice — "Nondeterministic advice"  (must, CALIBRATION)
//
// commit(a value that came from the nondeterministic channel). This is the
// evaluation's only positive control: a hint is a free column BY DESIGN, so an
// accepted output-changing mutation here is a TRUE accept and not a finding.
// Without it a reader cannot tell a sound VM from a port whose hook never reaches
// the constraint system (run-matrix rule R7).
//
// KNOWN INCOHERENCE ON THIS TARGET, recorded rather than papered over.
// TARGET_CAPABILITIES hint_hookable = "partial": the write-back hook mirrors the
// forged value into `instruction.op_a`, which decodes to X0 for ECALL
// (riscv/instructions/macros.rs:21-35), while the true destination of syscall
// 0x400 is X10 (prover2/trace/src/program.rs:118-132). So at the ECALL site the
// RECORD carries the forged value and the emulator's register file does not, and
// the resulting trace is internally inconsistent. The calibration ACCEPT this
// structure exists to produce is therefore NOT expected from the ECALL pc until
// that one-line gate is fixed; this driver does NOT change it. The seed is still
// shipped because (a) the ECALL row measures the blocker instead of asserting it,
// and (b) every other site in the seed is an ordinary probe whose operand came
// from the hint channel.
// ---------------------------------------------------------------------------
fn build_hint_elf(checked: bool) -> Seed {
    // the expected value, so the in-guest check passes on the honest run
    let expect = 0x5Au32;
    let (mut code, input, addr, _) = if checked {
        begin(Operands::Input, expect, 0)
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    };
    let sysc = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 17, 0, 0x400)); // a7 = SYS_READ_FROM_PRIVATE_INPUT
    let calib = code.len();
    code.push(0x0000_0073); // ECALL -> x10 = one private-input byte
    code.push(enc(BuiltinOpcode::ADDI, 8, 10, 0));
    if checked {
        code.push(enc(BuiltinOpcode::BEQ, 10, 1, 8)); // in-guest check
        code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0xBAD)); // check failed
    }
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let variant = if checked { "checked" } else { "unchecked" };
    let mut s = Seed::new(
        format!("st_hint_advice_{variant}"),
        "st_hint_advice",
        "Nondeterministic advice",
        "ECALL".to_string(),
        "hint",
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.candidate_class = "calibration";
    s.addr_sites.extend(addr);
    s.syscall_sites.push(sysc);
    s.calib_sites.push(calib);
    s.private_input = vec![expect as u8];
    s
}

// ---------------------------------------------------------------------------
// st_finalize_only — "Finalize-only write"  (should, CONTROL on nexus)
//
// Write a value that is never read again, then commit a CONSTANT: the only path
// from the forged value to the public output would be the finalise boundary.
//
// DECLARED NEGATIVE. nexus's public output is the final content of a FIXED region
// written by `wou`, not the whole final state, so a write to any other address is
// unobservable by construction and the expected verdict is REJECT or
// ACCEPT-with-unchanged-output. The observable form of this question on nexus is
// st_pv_plumbing, which is a different structure.
// ---------------------------------------------------------------------------
fn build_finalize_only_elf(variant: &str, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let mut patches: Vec<Patch> = Vec::new();
    let dead;
    match variant {
        "mem" => {
            let i0 = code.len();
            code.push(0); // patched: ADDI x4, x0, ram_base
            addr.push(i0);
            patches.push(Patch::RamPtr { at: i0, rd: 4, off: 0 });
            dead = code.len();
            code.push(enc(op, 5, 1, 2));
            code.push(enc(BuiltinOpcode::SW, 4, 5, 0)); // never read again
        }
        "reg" => {
            dead = code.len();
            code.push(enc(op, 28, 1, 2)); // never read at all
        }
        _ => unreachable!("unknown st_finalize_only variant {variant}"),
    }
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x0FF)); // the DATA output is constant
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &patches, &[0]);
    let mut s = Seed::new(
        format!("st_finalize_only_{variant}_{}", op_name(op).to_lowercase()),
        "st_finalize_only",
        "Finalize-only write",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.candidate_class = "control";
    s.addr_sites.extend(addr);
    s.dead_sites.push(dead);
    // A finalise-only write is never read again by the instruction stream, so its
    // only remaining trace is the memory / register finalise boundary row.
    s.dead_final = true;
    s
}

// ---------------------------------------------------------------------------
// st_indirect_jump — "Indirect jump"  (should, probe, site_role address)
//
// JALR through a register the mutation can move, with a two-entry jump table so
// both targets are real code and both arms reach the same commit.
// CONSTRAINT SURFACE: the pc transition computed from a register, the ROM /
// program-table lookup at the forged pc (is the fetch relation total?), and the
// RISC-V requirement that JALR clears bit 0.
//
// TWO ARMS, TWO SITE ROLES.
//   table  the productive arm: the mutation lands on the SELECTOR that chooses
//          the table entry, so it stays inside the program and changes which arm
//          runs, and the arm's constant is published.
//   bit0   the manifest's one role-mask exception: xor_b0 is legal at an address
//          site here and nowhere else, because clearing bit 0 is exactly the
//          RISC-V requirement this variant tests.
// ---------------------------------------------------------------------------
fn build_jalr_elf(variant: &str, src: Operands) -> Seed {
    // sel = 1, so the honest run takes arm A.
    let (mut code, input, mut addr, operand) = begin(src, 1, 0);
    let i0 = code.len();
    code.push(0); // patched: ADDI x28, x0, &armA
    let i1 = code.len();
    code.push(0); // patched: ADDI x29, x0, &armB
    code.push(enc(BuiltinOpcode::BEQ, 1, 0, 8)); // sel == 0 -> arm B
    let i3 = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 30, 28, 0)); // x30 = &armA
    code.push(enc(BuiltinOpcode::BEQ, 0, 0, 8)); // skip the other assignment
    let i5 = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 30, 29, 0)); // x30 = &armB
    code.push(enc(BuiltinOpcode::JALR, 31, 30, 0)); // the indirect jump
    let arm_a = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x0AA));
    code.push(enc(BuiltinOpcode::JAL, 0, 0, 8)); // -> join
    let arm_b = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 8, 0, 0x0BB));
    addr.extend_from_slice(&[i0, i1, i3, i5]);
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(
        code,
        &[
            Patch::CodePtr { at: i0, rd: 28, idx: arm_a },
            Patch::CodePtr { at: i1, rd: 29, idx: arm_b },
        ],
        &[0],
    );
    let mut s = Seed::new(
        format!("st_indirect_jump_{variant}"),
        "st_indirect_jump",
        "Indirect jump",
        "JALR".to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s.sel_sites = operand;
    s.jalr_bit0 = variant == "bit0";
    s
}

// ---------------------------------------------------------------------------
// st_pc_imm_value — "PC-immediate value"  (should, probe, site_role value)
//
// commit(auipc), commit(lui imm), commit(jal link): values whose only source is
// the pc or the committed program text, never a register. CONSTRAINT SURFACE:
// value derivation from the pc column and from the program table's immediate,
// with no register operand in the relation — the answer route is the preprocessed
// program / fetch bus rather than the register bus.
//
// operand_source is `immediate` by construction: the structure exists precisely
// to ask whether rd is bound to the COMMITTED PROGRAM.
// ---------------------------------------------------------------------------
fn build_pcimm_elf(variant: &str) -> Seed {
    let mut code: Vec<u32> = Vec::new();
    match variant {
        "auipc" => {
            code.push(enc(BuiltinOpcode::AUIPC, 5, 0, 0));
            code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
        }
        "lui" => {
            code.push(enc(BuiltinOpcode::LUI, 5, 0, 0x12345));
            code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
        }
        "jal" => {
            code.push(enc(BuiltinOpcode::JAL, 5, 0, 8)); // x5 = pc + 4, jump to pc + 8
            code.push(enc(BuiltinOpcode::ADDI, 0, 0, 0)); // skipped
            code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
        }
        _ => unreachable!("unknown st_pc_imm_value variant {variant}"),
    }
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let opcode = match variant {
        "auipc" => "AUIPC",
        "lui" => "LUI",
        _ => "JAL",
    };
    Seed::new(
        format!("st_pc_imm_value_{variant}"),
        "st_pc_imm_value",
        "PC-immediate value",
        opcode.to_string(),
        "immediate",
        elf,
        Vec::new(),
    )
    .with_epilogue_roles(ea, es)
}

// ---------------------------------------------------------------------------
// st_fanout_read — "Fan-out read"  (should, probe, site_role value)
//
// One definition, two uses at two different cycles. CONSTRAINT SURFACE: whether
// the register BUS binds the read value or only the producing chip does. nexus is
// the target this structure was designed for: BIND-V1 records that Block.regs is
// read INDEPENDENTLY by the execution component (BVal/CVal, add/mod.rs:118,131)
// and by RegisterMemory (Reg1Val/Reg2Val, register_memory/trace.rs:161,246),
// joined only through rel-inst-to-reg-memory.
//
// FORGED WRITE-BACK -> PUBLIC OUTPUT: both uses feed the commit, so a forgery
// that survives at one read point and not the other still changes the output.
// ---------------------------------------------------------------------------
fn build_fanout_elf(op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_A, OPERAND_B);
    code.push(enc(op, 5, 1, 2)); // one definition
    code.push(enc(BuiltinOpcode::ADDI, 28, 5, 0x123)); // use 1
    code.push(enc(BuiltinOpcode::XORI, 29, 5, 0x456)); // use 2
    code.push(enc(BuiltinOpcode::XOR, 8, 28, 29));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_fanout_read_{}", op_name(op).to_lowercase()),
        "st_fanout_read",
        "Fan-out read",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_reg_alias — "Register aliasing"  (should, probe, site_role value)
//
// OP rd, rs1, rs1 and OP rd, rd, rd. CONSTRAINT SURFACE: within-row ordering of
// the register memory argument — read-before-write at ONE address at ONE clk,
// with Reg1Addr/Reg2Addr/Reg3Addr collapsed onto a single address and the two
// reads distinguished only by subcycle.
// ---------------------------------------------------------------------------
fn build_reg_alias_elf(variant: &str, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_A, OPERAND_B);
    match variant {
        // rs1 == rs2
        "rs1rs2" => code.push(enc(op, 5, 1, 1)),
        // rd == rs1 == rs2
        "rdrs1rs2" => {
            code.push(enc(BuiltinOpcode::ADDI, 5, 1, 0));
            code.push(enc(op, 5, 5, 5));
        }
        _ => unreachable!("unknown st_reg_alias variant {variant}"),
    }
    code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_reg_alias_{variant}_{}", op_name(op).to_lowercase()),
        "st_reg_alias",
        "Register aliasing",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_pv_plumbing — "Public-value plumbing"  (should, probe)
//
// Commit EIGHT distinct words instead of one, and alias one output word.
// CONSTRAINT SURFACE: on nexus the public output IS the final content of the
// output region, mirrored into the PREPROCESSED PubIoAddr / PubOutFlag /
// PubOutVal columns by PubMemoryBoundary (pub_input_output_memory/mod.rs:149-155)
// and re-derived by the verifier from the View it is handed. The question is
// whether EACH word is individually bound and whether the word INDEX is bound to
// anything.
//
// SITE ROLES. nexus has no commit ecall and no word-index register: the output
// address is formed by an ordinary ADDI, so the manifest's `index` variant lives
// here as an ADDRESS-role site rather than as a forbidden syscall argument. The
// manifest's `exitcode` variant is NOT built: the exit-code word is the first
// word of the output region and `View::view_public_output` excludes it
// (executor.rs:1119-1143), so it is not in the object the predicate reads.
// The manifest's read-back form of `alias` is also not buildable — the output
// region is FixedMemory<WO> and a load from it fails — so `alias` is realised as
// two writes to the SAME output word.
// ---------------------------------------------------------------------------
fn build_pv_plumbing_elf(variant: &str, src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let mut sysc: Vec<usize> = Vec::new();
    let i0 = code.len();
    code.push(enc(BuiltinOpcode::LW, 6, 0, 0x84));
    let i1 = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 7, 6, 4));
    addr.extend_from_slice(&[i0, i1]);
    code.push(enc(BuiltinOpcode::ADD, 28, 1, 2));
    match variant {
        "words8" => {
            for k in 0..8u32 {
                code.push(wou(28, 7));
                code.push(enc(BuiltinOpcode::XORI, 28, 28, 0x11 * (k + 1)));
                let idx = code.len();
                code.push(enc(BuiltinOpcode::ADDI, 7, 7, 4)); // the word INDEX site
                addr.push(idx);
            }
        }
        "alias" => {
            code.push(enc(BuiltinOpcode::XORI, 29, 28, 0x55));
            code.push(wou(28, 7)); // first write to output word 0
            code.push(wou(29, 7)); // second write to the SAME word
        }
        _ => unreachable!("unknown st_pv_plumbing variant {variant}"),
    }
    code.push(wou(0, 6)); // exit code
    sysc.push(code.len());
    code.push(enc(BuiltinOpcode::ADDI, 17, 0, 0x201));
    sysc.push(code.len());
    code.push(enc(BuiltinOpcode::ADDI, 10, 0, 0));
    code.push(0x0000_0073);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_pv_plumbing_{variant}"),
        "st_pv_plumbing",
        "Public-value plumbing",
        "ADD".to_string(),
        src.tag(),
        elf,
        input,
    );
    s.addr_sites.extend(addr);
    s.syscall_sites = sysc;
    s
}

// ---------------------------------------------------------------------------
// st_early_exit — "Early exit"  (should, probe, site_role selector)
//
// A forged condition makes the guest skip its output store, so the proof carries
// a SHORTER public output. CONSTRAINT SURFACE: completeness of the public-value
// stream — is the verifier bound to the fact that the commit actually happened?
//
// OBSERVABLE ONLY UNDER accepted_case_v2. The Harvard pass sizes the output
// region from the span of the writes it observes, so skipping the data store
// leaves a zero-length public output; the FROZEN strict predicate requires a
// NON-EMPTY committed output and can never score that. The v2 predicate
// ("differs from honest, INCLUDING BY BEING ABSENT OR TRUNCATED") is emitted as a
// separate additive column so no published number moves.
// ---------------------------------------------------------------------------
fn build_early_exit_elf(src: Operands) -> Seed {
    // c = 0, so the honest run does NOT take the branch and does publish.
    let (mut code, input, mut addr, operand) = begin(src, 0, 0x77);
    code.push(enc(BuiltinOpcode::ADD, 8, 1, 2));
    let i0 = code.len();
    code.push(enc(BuiltinOpcode::LW, 6, 0, 0x84));
    let i1 = code.len();
    code.push(enc(BuiltinOpcode::ADDI, 7, 6, 4));
    addr.extend_from_slice(&[i0, i1]);
    code.push(enc(BuiltinOpcode::BNE, 1, 0, 8)); // a forged c skips the data store
    code.push(wou(8, 7));
    code.push(wou(0, 6)); // exit code word: always written, so the region exists
    let mut sysc: Vec<usize> = Vec::new();
    sysc.push(code.len());
    code.push(enc(BuiltinOpcode::ADDI, 17, 0, 0x201));
    sysc.push(code.len());
    code.push(enc(BuiltinOpcode::ADDI, 10, 0, 0));
    code.push(0x0000_0073);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        "st_early_exit".to_string(),
        "st_early_exit",
        "Early exit",
        "ADD".to_string(),
        src.tag(),
        elf,
        input,
    );
    s.addr_sites.extend(addr);
    s.sel_sites = operand;
    s.syscall_sites = sysc;
    s
}

// ---------------------------------------------------------------------------
// st_dead_write — "Dead write-back"  (should, CONTROL)
//
// A write-back whose destination is provably never read again. There is NO
// constraint surface, deliberately: the perturbed execution is
// instruction-for-instruction identical to the honest one, EXECFAIL is
// impossible, and so any REJECT is attributable to the constraint system alone.
// Without this control no REJECT anywhere else on this target is interpretable
// (run-matrix rule R7).
//
// Expected verdict: REJECT (binding) or ACCEPT-with-unchanged-output (unbound but
// unobservable). Never an accepted case.
// ---------------------------------------------------------------------------
fn build_dead_elf(variant: &str, op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_A, OPERAND_B);
    let dead = code.len();
    match variant {
        // overwritten before any read
        "overwritten" => {
            code.push(enc(op, 5, 1, 2));
            code.push(enc(BuiltinOpcode::ADDI, 5, 2, 0));
            code.push(enc(BuiltinOpcode::ADDI, 8, 5, 0));
        }
        // never read at all
        "neverread" => {
            code.push(enc(op, 28, 1, 2));
            code.push(enc(BuiltinOpcode::ADDI, 8, 2, 0));
        }
        _ => unreachable!("unknown st_dead_write variant {variant}"),
    }
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_dead_write_{variant}_{}", op_name(op).to_lowercase()),
        "st_dead_write",
        "Dead write-back",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.candidate_class = "control";
    s.addr_sites.extend(addr);
    s.dead_sites.push(dead);
    s.dead_final = variant == "neverread";
    s
}

// ---------------------------------------------------------------------------
// st_x0_dark_write — "x0 dark write"  (nice, probe, site_role value)
//
// An instruction whose destination is x0: an architectural write the circuit must
// DISCARD. CONSTRAINT SURFACE: the write-suppression predicate.
//
// REACHABLE HERE WITH NO HOOK CHANGE, which upgrades the manifest's `moderate`
// cell. `wb_perturb::on_write_back` is called unconditionally and rewrites
// `Step.result` for every instruction; the `op_a != X0` gate on the mirror-back
// (vm/src/trace.rs:309) only skips the register-file update, which is the
// architecturally correct thing to do for x0 (RegisterFile::write already
// hardwires it, vm/src/cpu/registerfile.rs:29-33). So the RECORD carries a forged
// x0 write while the emulator correctly continues with x0 = 0, which is exactly
// the malicious-prover claim this structure poses.
//
// OBSERVABILITY CAVEAT, stated so the row is not over-read. Because the emulator
// keeps x0 = 0, the honest output stays 0 and a forgery can only show up as
// ACCEPT-with-unchanged-output unless the circuit itself propagates the discarded
// write. Turning this into an output-changing probe needs the hook to mirror the
// forged value into the register file too, which this driver does NOT do.
// ---------------------------------------------------------------------------
fn build_x0_elf(op: BuiltinOpcode, src: Operands) -> Seed {
    let (mut code, input, addr, _) = begin(src, OPERAND_A, OPERAND_B);
    code.push(enc(op, 0, 1, 2)); // architectural write to x0
    code.push(enc(BuiltinOpcode::ADD, 8, 0, 0)); // honest x8 = 0
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[], &[0]);
    let mut s = Seed::new(
        format!("st_x0_dark_write_{}", op_name(op).to_lowercase()),
        "st_x0_dark_write",
        "x0 dark write",
        op_name(op).to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

// ---------------------------------------------------------------------------
// st_whole_program — "Whole program"  (must, probe)  FROZEN NAME
//
// A loop-heavy guest with a realistic opcode census: the external-validity claim,
// not a surface claim. 24 iterations of a body that touches the arithmetic,
// comparison, shift, bitwise, word and sub-word memory, branch, jump and
// pc-immediate components, so a single seed instantiates most of
// BASE_COMPONENTS instead of three of them.
//
// nexus is the cheapest target in the corpus, so a full site sweep over a
// realistic guest is affordable here and nowhere else.
// ---------------------------------------------------------------------------
fn build_whole_program_elf(src: Operands) -> Seed {
    let (mut code, input, mut addr, _) = begin(src, 0x0001_3579, 13);
    let i0 = code.len();
    code.push(0); // patched: ADDI x4, x0, ram_base
    addr.push(i0);
    code.push(enc(BuiltinOpcode::ADDI, 28, 0, 0)); // x = 0
    code.push(enc(BuiltinOpcode::ADDI, 29, 0, 1)); // y = 1
    code.push(enc(BuiltinOpcode::ADDI, 30, 0, 24)); // i = 24
    let i_auipc = code.len();
    code.push(enc(BuiltinOpcode::AUIPC, 11, 0, 0));
    addr.push(i_auipc); // AUIPC materialises a code pointer
    code.push(enc(BuiltinOpcode::LUI, 12, 0, 1));

    let body = code.len();
    code.push(enc(BuiltinOpcode::ADD, 31, 28, 29)); // t = x + y
    code.push(enc(BuiltinOpcode::ADDI, 28, 29, 0)); // x = y
    code.push(enc(BuiltinOpcode::ADDI, 29, 31, 0)); // y = t
    code.push(enc(BuiltinOpcode::SW, 4, 31, 0));
    code.push(enc(BuiltinOpcode::LW, 13, 4, 0));
    code.push(enc(BuiltinOpcode::SRLI, 13, 13, 3));
    code.push(enc(BuiltinOpcode::XOR, 14, 13, 12));
    code.push(enc(BuiltinOpcode::SLT, 15, 14, 1));
    code.push(enc(BuiltinOpcode::ADD, 29, 29, 15));
    code.push(enc(BuiltinOpcode::SB, 4, 15, 4));
    code.push(enc(BuiltinOpcode::LBU, 13, 4, 4));
    code.push(enc(BuiltinOpcode::SUB, 14, 14, 13));
    code.push(enc(BuiltinOpcode::AND, 14, 14, 2));
    code.push(enc(BuiltinOpcode::OR, 28, 28, 14));
    code.push(enc(BuiltinOpcode::SLL, 13, 15, 2));
    code.push(enc(BuiltinOpcode::SRA, 13, 13, 2));
    code.push(enc(BuiltinOpcode::SLTU, 15, 13, 11));
    code.push(enc(BuiltinOpcode::ADDI, 30, 30, 0xFFF)); // i -= 1
    code.push(enc(
        BuiltinOpcode::BNE,
        30,
        0,
        ((body as i64 - (code.len() as i64)) * 4) as u32,
    ));

    code.push(enc(BuiltinOpcode::JAL, 11, 0, 8)); // link + jump over the next word
    code.push(enc(BuiltinOpcode::ADDI, 0, 0, 0)); // skipped
    code.push(enc(BuiltinOpcode::ADDI, 8, 29, 0));
    let (ea, es) = push_epilogue(&mut code, 8);
    let elf = assemble(code, &[Patch::RamPtr { at: i0, rd: 4, off: 0 }], &[0, 0]);
    let mut s = Seed::new(
        "st_whole_program".to_string(),
        "st_whole_program",
        "Whole program",
        "census".to_string(),
        src.tag(),
        elf,
        input,
    )
    .with_epilogue_roles(ea, es);
    s.addr_sites.extend(addr);
    s
}

/// The structure catalog for this target: every (structure, variant, opcode) cell
/// the feasibility matrix marks reachable on nexus.
///
/// RUN-MATRIX RULES THIS TABLE ENCODES.
///  R1/R2  every structure whose shape admits an opcode parameter is crossed with
///         `deconfound_min` (or `deconfound_full`), so structure and opcode vary
///         INDEPENDENTLY. This is the defect the pico matrix shipped with: five of
///         seven structures pinned to opcodes pico binds correctly.
///  R3     `known_unbound_opcodes` is empty on nexus, so the unbound arm is the
///         SUBSTITUTED shift family; run_tag must carry
///         `unbound_probe=substituted`.
///  R5     nth = -1 everywhere; nth_supported is false on this target.
///  R7     controls and the calibration are listed FIRST so a truncated run still
///         produces the rows that make its REJECTs interpretable.
///
/// CELLS DELIBERATELY ABSENT, each a measured or read-off negative rather than an
/// omission:
///   st_multishard  prover2 has no continuation or segment component in
///                  BASE_COMPONENTS and the pipeline is one k_trace + one prove.
///   st_precompile  BASE_COMPONENTS carries no precompile component (and no
///                  M-extension component either).
///   st_single_op   already shipped, and byte-frozen, as `lacuna_encoding_enumeration_nexus`.
fn structure_seeds() -> Vec<Seed> {
    let src = Operands::Input;
    let mut seeds: Vec<Seed> = Vec::new();

    // ---- R7: controls and calibration first -------------------------------
    seeds.push(build_hint_elf(false));
    seeds.push(build_hint_elf(true));
    for (_, op) in deconfound_min() {
        seeds.push(build_dead_elf("overwritten", op, src));
        seeds.push(build_dead_elf("neverread", op, src));
    }
    seeds.push(build_initial_state_elf());
    seeds.push(build_initial_image_elf("data"));
    seeds.push(build_initial_image_elf("bssboundary"));
    for (_, op) in deconfound_min() {
        seeds.push(build_finalize_only_elf("mem", op, src));
        seeds.push(build_finalize_only_elf("reg", op, src));
    }

    // ---- probes -----------------------------------------------------------
    for (_, op) in deconfound_min() {
        for variant in ["mem", "addr", "branch"] {
            seeds.push(build_op_then_state_elf(variant, op, src));
        }
    }

    // Boundary operand pairs. RV32I only: the manifest's `zero` (zero divisor) and
    // `exactdiv` variants are DIV/REM shapes and prover2 has no M-extension
    // component, so they are unreachable rather than skipped.
    let boundary_pairs: [(&str, u32, u32); 4] = [
        // limb / sign boundary: a is one step below the B = 2^16 limb carry
        ("limb", 0x0000_FFFF, 0x0000_0001),
        // limb overflow: both operands all-ones
        ("limbmax", 0xFFFF_FFFF, 0xFFFF_FFFF),
        // signed overflow: INT_MIN+1 against -1, so mu(a) reaches INT_MIN
        ("intmin", 0x8000_0001, 0xFFFF_FFFF),
        // shift-amount mask: the amount is 1 and lives in a REGISTER, so mu can
        // drive it to XLEN, XLEN-1 and 2^16
        ("shamt", 0x1234_5678, 0x0000_0001),
    ];
    for (pair, a, b) in boundary_pairs {
        for (_, op) in deconfound_min() {
            seeds.push(build_boundary_operand_elf(pair, a, b, op, src));
        }
    }

    for op in [
        BuiltinOpcode::LB,
        BuiltinOpcode::LBU,
        BuiltinOpcode::LH,
        BuiltinOpcode::LHU,
    ] {
        seeds.push(build_subword_elf("load", op, src));
    }
    for op in [BuiltinOpcode::SB, BuiltinOpcode::SH] {
        seeds.push(build_subword_elf("store", op, src));
    }

    for (_, op) in deconfound_min() {
        seeds.push(build_store_load_elf(false, op, src));
        seeds.push(build_store_load_elf(true, op, src));
        seeds.push(build_redirect_elf(op, src));
    }
    seeds.push(build_pointer_indirect_elf(src));

    for (_, op) in deconfound_full() {
        seeds.push(build_hazard_elf(op, src));
        seeds.push(build_fanout_elf(op, src));
    }
    for (_, op) in branch_set() {
        seeds.push(build_cf_elf(op, src));
    }
    for (_, op1) in deconfound_min() {
        for (_, op2) in consumer_set() {
            seeds.push(build_chain_elf(2, op1, op2, src));
        }
        seeds.push(build_chain_elf(4, op1, consumer_set()[0].1, src));
    }
    for (_, op) in deconfound_min() {
        seeds.push(build_reg_alias_elf("rs1rs2", op, src));
        seeds.push(build_reg_alias_elf("rdrs1rs2", op, src));
        seeds.push(build_x0_elf(op, src));
    }
    for variant in ["table", "bit0"] {
        seeds.push(build_jalr_elf(variant, src));
    }
    for variant in ["auipc", "lui", "jal"] {
        seeds.push(build_pcimm_elf(variant));
    }
    for variant in ["words8", "alias"] {
        seeds.push(build_pv_plumbing_elf(variant, src));
    }
    seeds.push(build_early_exit_elf(src));

    // Loop lengths. n4096 is behind LACUNA_BIG because its trace is two orders of
    // magnitude longer than every other seed here and would dominate the run's
    // wall time; it is a cost decision, not a reachability one.
    seeds.push(build_loop_elf(16, src));
    seeds.push(build_loop_elf(256, src));
    if std::env::var("LACUNA_BIG").ok().as_deref() == Some("1") {
        seeds.push(build_loop_elf(4096, src));
    }

    seeds.push(build_whole_program_elf(src));
    seeds
}

/// One structure candidate through the REAL pipeline: armed emulation -> perturbed
/// record and its View -> real prove -> real verify. Same contract as
/// `run_candidate`; it differs only in taking a prebuilt seed and its input tapes.
fn run_seed_candidate(seed: &Seed, pc: u32, kind: usize, arg: i64) -> Out {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // nth = -1: arm EVERY execution of this static pc. `k_trace` emulates the
        // program twice (Harvard, then Linear::from_harvard) behind one global
        // occurrence counter, so per-execution arming is unavailable on this target
        // (TARGET_CAPABILITIES nth_supported = false, run-matrix rule R5).
        wb_perturb::with(pc, -1, kind, arg, || {
            let w1 = Instant::now();
            let c1 = cpuprobe::cpu_ms();
            let elf = seed.elf.clone();
            let t0 = Instant::now();
            let traced = k_trace(elf, &[], &seed.public_input, &seed.private_input, 1);
            let t_record = t0.elapsed().as_millis();
            cpuprobe::S1_WALL_US.store(w1.elapsed().as_micros() as u64, cpuprobe::R);
            cpuprobe::S1_CPU_MS.store(cpuprobe::cpu_ms().saturating_sub(c1), cpuprobe::R);
            let (view, trace) = match traced {
                Ok(x) => x,
                Err(e) => {
                    return Err((
                        format!("{e:?}"),
                        t_record,
                        0u128,
                        wb_perturb::hits(),
                        wb_perturb::honest_value(),
                        wb_perturb::forged_value(),
                    ))
                }
            };
            let hits = wb_perturb::hits();
            let (hv, fv) = (wb_perturb::honest_value(), wb_perturb::forged_value());
            let t1 = Instant::now();
            let proof = match timed_prove::prove_timed(&trace, &view) {
                Ok(p) => p,
                Err(e) => {
                    return Err((
                        format!("prove: {e:?}"),
                        t_record,
                        t1.elapsed().as_millis(),
                        hits,
                        hv,
                        fv,
                    ))
                }
            };
            let t_prove = t1.elapsed().as_millis();
            let w4 = Instant::now();
            let c4 = cpuprobe::cpu_ms();
            let t2 = Instant::now();
            let res = verify(proof, &view);
            let t_verify = t2.elapsed().as_millis();
            cpuprobe::S4_WALL_US.store(w4.elapsed().as_micros() as u64, cpuprobe::R);
            cpuprobe::S4_CPU_MS.store(cpuprobe::cpu_ms().saturating_sub(c4), cpuprobe::R);
            Ok((
                view.view_public_output(),
                res,
                hits,
                hv,
                fv,
                t_record,
                t_prove,
                t_verify,
            ))
        })
    }));
    std::panic::set_hook(prev);
    match r {
        Ok(Ok((out, Ok(()), hits, hv, fv, tr, tp, tv))) => Out {
            outcome: if hits > 0 { "ACCEPT" } else { "NOOP" },
            failure_stage: if hits > 0 { "accepted_proof" } else { "mutation" },
            reason: String::new(),
            hits, out, honest_v: hv, forged_v: fv,
            t_record_ms: tr, t_prove_ms: tp, t_verify_ms: tv,
        },
        Ok(Ok((out, Err(e), hits, hv, fv, tr, tp, tv))) => Out {
            outcome: "REJECT",
            failure_stage: "verify",
            reason: trunc(&format!("{e:?}")),
            hits, out, honest_v: hv, forged_v: fv,
            t_record_ms: tr, t_prove_ms: tp, t_verify_ms: tv,
        },
        Ok(Err((msg, tr, tp, hits, hv, fv))) => {
            let proveish = msg.starts_with("prove:");
            Out {
                outcome: if proveish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if proveish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits, out: None, honest_v: hv, forged_v: fv,
                t_record_ms: tr, t_prove_ms: tp, t_verify_ms: 0,
            }
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque>".to_string());
            let constraintish = msg.contains("logup")
                || msg.contains("constraint")
                || msg.contains("Constraint")
                || msg.contains("commitment");
            Out {
                outcome: if constraintish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if constraintish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits: 0, out: None, honest_v: 0, forged_v: 0,
                t_record_ms: 0, t_prove_ms: 0, t_verify_ms: 0,
            }
        }
    }
}

/// The opcode census of one honest trace, in the shape the inventory collector
/// reads. Computed from the real trace rather than hand-written, so it cannot
/// drift from the seed.
fn opcensus(trace: &impl Trace) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for blk in trace.get_blocks_iter() {
        for st in &blk.steps {
            *counts
                .entry(st.instruction.opcode.name().to_uppercase())
                .or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// LACUNA structure-catalog enumeration for nexus.
///
/// ADDITIVE. It shares the write-back hook, the mutation menu and the frozen
/// acceptance predicate with `lacuna_encoding_enumeration_nexus` and adds nothing
/// to that test's output; the two write to different sinks and can be run
/// independently.
///
/// Environment (all optional):
///   LACUNA_OUT         path of the CSV to append to (default: stdout only)
///   LACUNA_TAG         free-form run tag copied into every row
///   LACUNA_STRUCTURES  comma-separated structure ids to enumerate (default: all)
///   LACUNA_SEEDS       comma-separated seed-id substrings to enumerate
///   LACUNA_MU          "xorb0" (single mu) | "all" (the 11-entry menu, default)
///   LACUNA_BIG         "1" to include the 4096-iteration loop seed
#[test]
#[ignore = "LACUNA evaluation run: nexus program-structure catalog; use --release"]
fn lacuna_structure_enumeration_nexus() {
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "nexus_structures".to_string());
    let mu_all = std::env::var("LACUNA_MU").unwrap_or_else(|_| "all".to_string()) == "all";
    let want_struct: Vec<String> = std::env::var("LACUNA_STRUCTURES")
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

    let mut sink: Option<std::fs::File> = std::env::var("LACUNA_OUT").ok().map(|p| {
        std::fs::OpenOptions::new().create(true).append(true).open(p).expect("open LACUNA_OUT")
    });
    // The shipped 30-column header, plus the six additive columns
    // STRUCTURE_MANIFEST csv_contract.required_new_columns asks for. No shipped
    // column changes name, meaning or position.
    let header = "run_tag,target,revision,seed_id,mutation_mode,program_structure,opcode,pc,nth,\
dead,dead_final,site_execs,mu_label,mutation_template,mu_kind,mu_arg,outcome,failure_stage,hits,\
pv_hex,honest_pv_hex,output_changed,accepted_case,t_record_ms,t_prove_ms,t_verify_ms,reason,\
committed_digest,honest_committed_digest,digest_changed,\
structure_id,site_role,candidate_class,operand_source,scored_against,accepted_case_v2";
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }
    // Run-matrix provenance, so a reader can see WHICH R2 arm was used.
    println!(
        "LACUNA_RUNMATRIX,{tag},nexus,{REV},unbound_probe=substituted,\
substitution=shift_family(SLL,SRL,SRA),m_ext=unreachable_no_M_component,\
nth=-1_only,predicate=strict+v2,scored_against=out_of_circuit"
    );

    let seeds = structure_seeds();
    println!("LACUNA_SEEDCOUNT,{tag},nexus,{}", seeds.len());

    for seed in &seeds {
        if !want_struct.is_empty() && !want_struct.iter().any(|s| s == seed.structure_id) {
            continue;
        }
        if !want_seed.is_empty() && !want_seed.iter().any(|s| seed.seed_id.contains(s)) {
            continue;
        }

        // ---- honest baseline ----
        let t0 = Instant::now();
        let (hview, htrace) = match k_trace(
            seed.elf.clone(),
            &[],
            &seed.public_input,
            &seed.private_input,
            1,
        ) {
            Ok(x) => x,
            Err(e) => {
                println!(
                    "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{},stage=exec,reason={:?}",
                    seed.seed_id,
                    trunc(&format!("{e:?}"))
                );
                continue;
            }
        };
        let honest_record_ms = t0.elapsed().as_millis();
        let t1 = Instant::now();
        let hproof = match prove(&htrace, &hview) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{},stage=prove,reason={:?}",
                    seed.seed_id,
                    trunc(&format!("{e:?}"))
                );
                continue;
            }
        };
        let honest_prove_ms = t1.elapsed().as_millis();
        let t2 = Instant::now();
        let hverify = verify(hproof, &hview);
        let honest_verify_ms = t2.elapsed().as_millis();
        if let Err(e) = hverify {
            // An honest program its own prover cannot verify is a COMPLETENESS
            // result; the seed has no accepted baseline and is excluded from the
            // mutation evaluation rather than silently scored.
            println!(
                "LACUNA_BASELINE_FAIL,{tag},nexus,{REV},{},stage=verify,reason={:?}",
                seed.seed_id,
                trunc(&format!("{e:?}"))
            );
            continue;
        }
        let honest_out = hview.view_public_output();
        let honest_hex = hexout(&honest_out);
        let steps = htrace.get_num_steps();

        // ---- sites: every static pc in the honest trace that writes a register ----
        let mut sites: Vec<(u32, usize)> = vec![];
        {
            let mut seen: std::collections::BTreeMap<u32, usize> = Default::default();
            for blk in htrace.get_blocks_iter() {
                for st in &blk.steps {
                    if st.result.is_some() {
                        *seen.entry(st.pc).or_insert(0) += 1;
                    }
                }
            }
            for (pc, n) in seen {
                sites.push((pc, n));
            }
        }
        println!(
            "LACUNA_BASELINE,{tag},nexus,{REV},{},instructions={},writebacks={},\
static_sites={},honest_pv={honest_hex},honest_record_ms={honest_record_ms},\
honest_prove_ms={honest_prove_ms},honest_verify_ms={honest_verify_ms}",
            seed.seed_id,
            steps,
            sites.iter().map(|(_, n)| n).sum::<usize>(),
            sites.len(),
        );
        println!(
            "LACUNA_OPCENSUS,{tag},{},{}",
            seed.seed_id,
            opcensus(&htrace)
        );

        for (pc, execs) in &sites {
            let idx = ((*pc - ELF_TEXT_START) / 4) as usize;
            let role = seed.site_role(idx);
            let class = seed.class_at(idx);
            let dead = seed.dead_sites.contains(&idx);
            for (label, template, kind, arg) in menu(mu_all) {
                // STRUCTURE_MANIFEST mu_menu.role_masks: a forbidden (role, mu)
                // pair is never emitted, so the corpus is not padded with rows
                // whose only possible outcome is a self-inflicted EXECFAIL.
                if !mu_allowed(role, label, seed.jalr_bit0) {
                    continue;
                }
                let c = run_seed_candidate(seed, *pc, kind, arg);
                let pv_hex = hexout(&c.out);
                let nonempty = !pv_hex.is_empty() && pv_hex != "NONE";
                let present = c.outcome == "ACCEPT";
                let differs = pv_hex != honest_hex;
                // FROZEN strict predicate, verbatim.
                let changed = present && nonempty && differs;
                let accepted = present && c.hits > 0 && changed;
                // accepted_case_v2: strict, OR the committed output differs BY
                // BEING ABSENT OR TRUNCATED. Additive; never turns a strict accept
                // into a non-accept.
                let accepted_v2 = present && c.hits > 0 && differs;
                let row = format!(
                    "{tag},nexus,{REV},{},encoding,{},{},{pc:#x},-1,\
{dead},{},{execs},{label},{template},{kind},{arg},{},{},{},{},{},{},{},{},{},{},\"{}\",NA,NA,NA,\
{},{role},{class},{},out_of_circuit,{}",
                    seed.seed_id,
                    seed.published_name,
                    seed.opcode,
                    dead && seed.dead_final,
                    c.outcome, c.failure_stage, c.hits, pv_hex, honest_hex, changed, accepted,
                    c.t_record_ms, c.t_prove_ms, c.t_verify_ms, c.reason,
                    seed.structure_id,
                    seed.operand_source,
                    accepted_v2,
                );
                println!("LACUNA_ROW,{row}");
                if let Some(f) = sink.as_mut() {
                    writeln!(f, "{row}").unwrap();
                    f.flush().ok();
                }
                if accepted || accepted_v2 {
                    println!(
                        "  *** {} CASE: {} @ {pc:#x} mu={label} role={role} class={class}  \
honest write-back {:#x} -> {:#x}; committed output {honest_hex} -> {pv_hex}",
                        if accepted { "ACCEPTED" } else { "ACCEPTED(v2)" },
                        seed.seed_id,
                        c.honest_v,
                        c.forged_v
                    );
                }
            }
        }
    }
    println!("LACUNA_DONE,{tag}");
}

/// Build every catalog seed and check it emulates, without proving anything.
/// Cheap smoke test for the builders: it catches a mis-encoded branch offset or an
/// out-of-range patched address in a second instead of after an hour of proving.
#[test]
#[ignore = "LACUNA: emulate every structure seed once (no proving)"]
fn lacuna_structure_seeds_emulate_nexus() {
    let seeds = structure_seeds();
    println!("seeds: {}", seeds.len());
    let mut bad = 0usize;
    for seed in &seeds {
        match k_trace(
            seed.elf.clone(),
            &[],
            &seed.public_input,
            &seed.private_input,
            1,
        ) {
            Ok((view, trace)) => {
                let sites = {
                    let mut s: std::collections::BTreeSet<u32> = Default::default();
                    for blk in trace.get_blocks_iter() {
                        for st in &blk.steps {
                            if st.result.is_some() {
                                s.insert(st.pc);
                            }
                        }
                    }
                    s.len()
                };
                println!(
                    "OK   {:44} steps={:5} sites={:3} pv={}",
                    seed.seed_id,
                    trace.get_num_steps(),
                    sites,
                    hexout(&view.view_public_output())
                );
            }
            Err(e) => {
                bad += 1;
                println!("FAIL {:44} {e:?}", seed.seed_id);
            }
        }
    }
    assert_eq!(bad, 0, "{bad} structure seeds failed to emulate");
}

/// Prove and verify the HONEST baseline of every catalog seed, with no mutation.
///
/// A seed whose own prover cannot verify its honest execution has no accepted
/// baseline: it is a COMPLETENESS result and is excluded from the mutation
/// evaluation rather than scored, so this test is what decides which cells the
/// enumeration can actually report on. It is also the cheapest way to catch a
/// seed that reaches a component prover2 does not carry.
#[test]
#[ignore = "LACUNA: prove+verify the honest baseline of every structure seed; use --release"]
fn lacuna_structure_baselines_nexus() {
    let seeds = structure_seeds();
    let mut ok = 0usize;
    let mut bad: Vec<(String, String)> = Vec::new();
    for seed in &seeds {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (view, trace) = k_trace(
                seed.elf.clone(),
                &[],
                &seed.public_input,
                &seed.private_input,
                1,
            )
            .map_err(|e| format!("exec: {e:?}"))?;
            let proof = prove(&trace, &view).map_err(|e| format!("prove: {e:?}"))?;
            verify(proof, &view).map_err(|e| format!("verify: {e:?}"))?;
            Ok::<_, String>(hexout(&view.view_public_output()))
        }));
        match r {
            Ok(Ok(pv)) => {
                ok += 1;
                println!("BASELINE_OK   {:44} pv={pv}", seed.seed_id);
            }
            Ok(Err(e)) => {
                println!("BASELINE_FAIL {:44} {}", seed.seed_id, trunc(&e));
                bad.push((seed.seed_id.clone(), trunc(&e)));
            }
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "<opaque>".to_string());
                println!("BASELINE_PANIC {:43} {}", seed.seed_id, trunc(&msg));
                bad.push((seed.seed_id.clone(), trunc(&msg)));
            }
        }
    }
    println!("baselines: {ok} ok, {} without an accepted baseline", bad.len());
    for (s, e) in &bad {
        println!("  NO_BASELINE {s}: {e}");
    }
}

/// COMPLETENESS PROBE, not a mutation experiment: prove and verify the SAME
/// minimal honest program against static RAM images of 1..=8 words.
///
/// It exists because two catalog seeds were rejected by nexus's own prover with
/// `ConstraintsNotSatisfied` on their HONEST execution, and the only thing they
/// had in common was a three-word static RAM image. A seed with no verifying
/// honest baseline cannot be scored, so which image sizes are provable decides
/// what the catalog is allowed to build.
#[test]
#[ignore = "LACUNA: which static-RAM image sizes have a verifying honest baseline; use --release"]
fn lacuna_static_ram_size_completeness_nexus() {
    for words in 1..=8usize {
        let mut code: Vec<u32> = Vec::new();
        let i0 = code.len();
        code.push(0); // patched: ADDI x4, x0, ram_base
        code.push(enc(BuiltinOpcode::LW, 8, 4, 0));
        let _ = push_epilogue(&mut code, 8);
        let ram = vec![0u32; words];
        // MINIMAL REPAIR (verification pass): this probe used to call `assemble`,
        // whose build-time guard rejects a 3- or 7-word image, so the probe
        // panicked on its own guard at words=3 and could never re-measure the
        // claim the guard cites. Build the ElfFile inline instead; nothing else
        // in the file uses this path.
        let ram_base = ELF_TEXT_START + (code.len() as u32) * 4;
        code[i0] = enc(BuiltinOpcode::ADDI, 4, 0, ram_base);
        let mut image = MemorySegmentImage::empty_at(ram_base);
        for w in &ram {
            image.push_word(*w);
        }
        let elf = ElfFile::new(
            code,
            ELF_TEXT_START,
            ELF_TEXT_START,
            MemorySegmentImage::empty_at(ELF_TEXT_START),
            image,
            Vec::new(),
        );
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (view, trace) = k_trace(elf, &[], &[], &[], 1).map_err(|e| format!("exec: {e:?}"))?;
            let proof = prove(&trace, &view).map_err(|e| format!("prove: {e:?}"))?;
            verify(proof, &view).map_err(|e| format!("verify: {e:?}"))?;
            Ok::<_, String>(())
        }));
        let verdict = match r {
            Ok(Ok(())) => "OK".to_string(),
            Ok(Err(e)) => trunc(&e),
            Err(_) => "panic".to_string(),
        };
        println!("static_ram_words={words} bytes={} -> {verdict}", words * 4);
    }
}
