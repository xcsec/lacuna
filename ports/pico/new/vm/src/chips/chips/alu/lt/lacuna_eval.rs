//! LACUNA EVALUATION DRIVER — instrumented, candidate-level enumeration of
//! ENCODING mutations on the pico execution record.
//!
//! This module contains no bug knowledge. It enumerates
//!
//!     site  = (static pc, occurrence index of that pc in the honest execution)
//!     mu    = one entry of an instruction-independent rewriting menu
//!
//! over the register-writeback channel (the single architectural write-back choke
//! point, `emulator::riscv::emulator::wb_perturb::on_reg_write`), lets pico's own
//! executor and witness generator regenerate every derived column / cross-chip bus /
//! lookup multiplicity from the rewritten record, and submits the result to the REAL
//! prover and the REAL verifier.
//!
//! It emits one CSV row per mutation candidate with stage wall-clock timings so the
//! paper's RQ3 numbers are traceable to a raw log.
//!
//! Environment (all optional):
//!   LACUNA_OUT          path of the CSV to append to (default: stdout only)
//!   LACUNA_SITES        "cold3" (<=3 coldest static sites per opcode class, default)
//!                     | "dead"  (all dead-destination dynamic writebacks)
//!                     | "all"   (every distinct static writeback site, last execution)
//!   LACUNA_MU           "xorb0" (single mu, default) | "all" (the 9-entry menu)
//!   LACUNA_SHARD        "i/n" — take every n-th site starting at i (0-based)
//!   LACUNA_LIMIT        cap on the number of sites (after sharding)
//!   LACUNA_TAG          free-form run tag copied into every row

use crate::{
    chips::tests::test_rv64_emulate_with_opts,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::Opcode,
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{opts::EmulatorOpts, riscv::emulator::wb_perturb, stdin::EmulatorStdin},
    instances::{chiptype::riscv_chiptype::RiscvChipType, machine::riscv::RiscvMachine},
    machine::{machine::MachineBehavior, witness::ProvingWitness},
    primitives::consts::RISCV_NUM_PVS,
};
use p3_koala_bear::KoalaBear;
use std::{io::Write, sync::Arc, time::Instant};

type SC = KoalaBearPoseidon2;
type C = RiscvChipType<KoalaBear>;

/// Seed identity. `LACUNA_SEED_ID` names the row; `LACUNA_ELF` selects the guest ELF
/// (default: the fibonacci ELF checked into the pico tree); `LACUNA_STDIN` is a
/// comma-separated list of u64 inputs written to the guest's stdin.
fn program_structure() -> String {
    std::env::var("LACUNA_STRUCT").unwrap_or_else(|_| "Single operation".to_string())
}

fn seed_id() -> String {
    std::env::var("LACUNA_SEED_ID").unwrap_or_else(|_| "pico_fib_elf_n10".to_string())
}

fn fib_elf_program() -> Arc<Program> {
    match std::env::var("LACUNA_ELF") {
        Ok(path) => {
            let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            Compiler::new(SourceType::RISCV, &elf)
                .expect("parse seed elf")
                .compile()
        }
        Err(_) => {
            let elf: &[u8] =
                include_bytes!("../../../../compiler/test_elf/riscv64im-pico-fibnacci-elf");
            Compiler::new(SourceType::RISCV, elf)
                .expect("parse fib elf")
                .compile()
        }
    }
}

fn stdin_values() -> Vec<u64> {
    match std::env::var("LACUNA_STDIN") {
        Ok(s) => s
            .split(',')
            .filter(|t| !t.trim().is_empty())
            .map(|t| {
                let t = t.trim();
                if let Some(h) = t.strip_prefix("0x") {
                    u64::from_str_radix(h, 16).expect("hex stdin value")
                } else {
                    t.parse::<u64>().expect("dec stdin value")
                }
            })
            .collect(),
        Err(_) => vec![10u64],
    }
}

fn stdin() -> EmulatorStdin<Program, Vec<u8>> {
    let mut b = EmulatorStdin::<Program, Vec<u8>>::new_builder::<SC>();
    for v in stdin_values() {
        b.write(&v);
    }
    b.finalize().0
}

fn opts() -> EmulatorOpts {
    EmulatorOpts {
        max_cycles: Some(500_000),
        ..EmulatorOpts::default()
    }
}

/// Opcodes that write an architectural register (the mutation channel).
fn is_writeback(op: Opcode) -> bool {
    !matches!(
        op,
        Opcode::SB
            | Opcode::SH
            | Opcode::SW
            | Opcode::SD
            | Opcode::BEQ
            | Opcode::BNE
            | Opcode::BLT
            | Opcode::BGE
            | Opcode::BLTU
            | Opcode::BGEU
            | Opcode::ECALL
            | Opcode::EBREAK
            | Opcode::UNIMP
    )
}

/// The instruction-independent rewriting menu.
/// (label, template_id, mu_kind, mu_arg)
fn menu_all() -> Vec<(&'static str, &'static str, usize, i64)> {
    vec![
        ("xor_b0", "ENC-E3", wb_perturb::MU_XORBIT, 0),
        ("plus_B0", "ENC-E1", wb_perturb::MU_ADDK, 1),
        ("minus_B0", "ENC-E1", wb_perturb::MU_ADDK, -1),
        ("plus_B1", "ENC-E1", wb_perturb::MU_ADDK, 1 << 16),
        ("minus_B1", "ENC-E1", wb_perturb::MU_ADDK, -(1i64 << 16)),
        ("plus_B2", "ENC-E1", wb_perturb::MU_ADDK, 1 << 32),
        ("plus_B3", "ENC-E1", wb_perturb::MU_ADDK, 1 << 48),
        ("xor_b31", "ENC-E3", wb_perturb::MU_XORBIT, 31),
        ("zero", "ENC-E2", wb_perturb::MU_ZERO, 0),
        // ENC-E2 boundary results beta in {0, 2^(w-1), 2^w - 1} for w = 64
        ("boundary_msb", "ENC-E2", wb_perturb::MU_SET, i64::MIN),
        ("boundary_max", "ENC-E2", wb_perturb::MU_SET, -1),
    ]
}

fn menu_single() -> Vec<(&'static str, &'static str, usize, i64)> {
    vec![("xor_b0", "ENC-E3", wb_perturb::MU_XORBIT, 0)]
}

fn hexpv(pv: &Option<Vec<u8>>) -> String {
    match pv {
        None => "NONE".to_string(),
        Some(v) => v.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }
}

/// The IN-CIRCUIT public value: `PublicValues::committed_value_digest`, written by the
/// COMMIT ecall at halt from a SHA-256 the guest itself computes over every byte sent to
/// the public-values fd (sdk/sdk/src/riscv_ecalls/halt.rs:49-63) and constrained by
/// `riscv_cpu/ecall/constraints.rs`. A changed `pv_stream` therefore implies a changed
/// committed digest; capturing it makes the accepted-case claim independent of the
/// out-of-circuit byte transport.
fn committed_digest_hex(proof: &crate::machine::proof::MetaProof<SC>) -> String {
    use crate::{compiler::word::Word, emulator::riscv::public_values::PublicValues};
    use core::borrow::Borrow;
    use p3_field::PrimeField32;
    for p in proof.proofs().iter() {
        let pv: &PublicValues<Word<F2>, F2> = (&*p.public_values).borrow();
        let hex: String = pv
            .committed_value_digest
            .iter()
            .flat_map(|w| w.0.iter())
            .map(|f| format!("{:04x}", f.as_canonical_u32()))
            .collect();
        if hex.chars().any(|c| c != '0') {
            return hex;
        }
    }
    "0".repeat(32)
}

type F2 = KoalaBear;

// ===================== LACUNA per-stage CPU calibration (additive) =====================
// Enabled ONLY when LACUNA_CPU_CSV is set; otherwise every probe is inert and the
// driver behaves exactly as before.
const CPU_CSV_HEADER: &str = "candidate_key,seed_id,opcode,mutation_template,outcome,\
failure_stage,s1_replay_wall_ms,s1_replay_cpu_ms,s2_tracegen_wall_ms,s2_tracegen_cpu_ms,\
s3_prove_wall_ms,s3_prove_cpu_ms,s4_verify_wall_ms,s4_verify_cpu_ms,other_wall_ms,other_cpu_ms,\
total_wall_ms,total_cpu_ms";

fn cpu_csv_open() -> Option<std::fs::File> {
    let p = std::env::var("LACUNA_CPU_CSV").ok()?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .expect("open LACUNA_CPU_CSV");
    if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
        writeln!(f, "{CPU_CSV_HEADER}").unwrap();
    }
    crate::machine::lacuna_stage::set_enabled(true);
    Some(f)
}

struct CaseOut {
    digest: String,
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    hits: usize,
    pv: Option<Vec<u8>>,
    t_prove_ms: u128,
    t_verify_ms: u128,
    /// LACUNA CPU calibration (additive): process user+system CPU ms spent in S4.
    t_verify_cpu_ms: u64,
}

fn trunc(s: &str) -> String {
    let s = s.replace(['\n', ',', '"'], " ");
    s.chars().take(160).collect()
}

/// One full candidate through the REAL pipeline: perturbed record -> pico's own
/// witness generation -> real prove -> real verify.
#[allow(clippy::too_many_arguments)]
fn run_candidate(
    machine: &RiscvMachine<SC, C>,
    pk: &crate::machine::keys::BaseProvingKey<SC>,
    vk: &crate::machine::keys::BaseVerifyingKey<SC>,
    program: &Arc<Program>,
    pc: u64,
    nth: i64,
    mu_kind: usize,
    mu_arg: i64,
) -> CaseOut {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wb_perturb::with(pc, nth, mu_kind, mu_arg, || {
            let t0 = Instant::now();
            let witness = ProvingWitness::<SC, C, Vec<u8>>::setup_for_riscv(
                program.clone(),
                stdin(),
                opts(),
                pk.clone(),
                vk.clone(),
            );
            let (proof, _r) = machine.prove_with_shape_report(&witness, None);
            let t_prove = t0.elapsed().as_millis();
            let pv = proof.pv_stream.clone();
            let digest = committed_digest_hex(&proof);
            let hits = wb_perturb::hits();
            let t1 = Instant::now();
            let c1 = crate::machine::lacuna_stage::proc_cpu_ms();
            let res = machine.verify(&proof, vk).map_err(|e| format!("{e:?}"));
            let t_verify = t1.elapsed().as_millis();
            let cpu_verify = crate::machine::lacuna_stage::proc_cpu_ms().saturating_sub(c1);
            (pv, res, hits, t_prove, t_verify, digest, cpu_verify)
        })
    }));
    std::panic::set_hook(prev);
    match out {
        Ok((pv, Ok(()), hits, tp, tv, dg, cv)) => CaseOut {
            digest: dg,
            outcome: if hits > 0 { "ACCEPT" } else { "NOOP" },
            failure_stage: if hits > 0 {
                "accepted_proof"
            } else {
                "mutation"
            },
            reason: String::new(),
            hits,
            pv,
            t_prove_ms: tp,
            t_verify_ms: tv,
            t_verify_cpu_ms: cv,
        },
        Ok((pv, Err(e), hits, tp, tv, dg, cv)) => CaseOut {
            digest: dg,
            outcome: "REJECT",
            failure_stage: "verify",
            reason: trunc(&e),
            hits,
            pv,
            t_prove_ms: tp,
            t_verify_ms: tv,
            t_verify_cpu_ms: cv,
        },
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque>".to_string());
            let constraintish = msg.contains("Cumulative sum")
                || msg.contains("cumulative")
                || msg.contains("constraint")
                || msg.contains("Constraint")
                || msg.contains("lookup")
                || msg.contains("OodEvaluationMismatch")
                || msg.contains("InvalidProofShape");
            CaseOut {
                digest: String::new(),
                outcome: if constraintish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if constraintish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                hits: 0,
                pv: None,
                t_prove_ms: 0,
                t_verify_ms: 0,
                t_verify_cpu_ms: 0,
            }
        }
    }
}

/// Time the perturbed record construction on its own (record construction +
/// ForkExec). `prove_with_shape_report` re-emulates internally on a separate
/// thread, so this measurement is a *separate replay*, reported as such.
fn time_record_ms(
    program: &Arc<Program>,
    pc: u64,
    nth: i64,
    mu_kind: usize,
    mu_arg: i64,
) -> (u128, u64) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wb_perturb::with(pc, nth, mu_kind, mu_arg, || {
            let t = Instant::now();
            let c = crate::machine::lacuna_stage::proc_cpu_ms();
            let _ = test_rv64_emulate_with_opts(program.clone(), stdin(), opts());
            (
                t.elapsed().as_millis(),
                crate::machine::lacuna_stage::proc_cpu_ms().saturating_sub(c),
            )
        })
    }));
    std::panic::set_hook(prev);
    r.unwrap_or((0, 0))
}

#[test]
#[ignore = "LACUNA evaluation run: instrumented encoding-mutation enumeration; use --release"]
fn lacuna_encoding_enumeration() {
    let seed = seed_id();
    let structure = program_structure();
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "run".to_string());
    let sites_mode = std::env::var("LACUNA_SITES").unwrap_or_else(|_| "cold3".to_string());
    let mu_mode = std::env::var("LACUNA_MU").unwrap_or_else(|_| "xorb0".to_string());
    let (shard_i, shard_n) = match std::env::var("LACUNA_SHARD") {
        Ok(s) => {
            let mut it = s.split('/');
            let i: usize = it.next().unwrap_or("0").parse().unwrap_or(0);
            let n: usize = it.next().unwrap_or("1").parse().unwrap_or(1);
            (i, n.max(1))
        }
        Err(_) => (0, 1),
    };
    let limit: usize = std::env::var("LACUNA_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    let program = fib_elf_program();
    let machine = RiscvMachine::new(SC::test(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
    let (pk, vk) = machine.setup_keys(&program);

    // ---------------- honest baseline ----------------
    let t_rec0 = Instant::now();
    let records = test_rv64_emulate_with_opts(program.clone(), stdin(), opts());
    let honest_record_ms = t_rec0.elapsed().as_millis();

    let t_p0 = Instant::now();
    let honest_witness = ProvingWitness::<SC, C, Vec<u8>>::setup_for_riscv(
        program.clone(),
        stdin(),
        opts(),
        pk.clone(),
        vk.clone(),
    );
    let (honest_proof, _) = machine.prove_with_shape_report(&honest_witness, None);
    let honest_prove_ms = t_p0.elapsed().as_millis();
    let t_v0 = Instant::now();
    machine
        .verify(&honest_proof, &vk)
        .expect("honest baseline must verify");
    let honest_verify_ms = t_v0.elapsed().as_millis();
    let honest_pv = honest_proof.pv_stream.clone();
    let honest_digest = committed_digest_hex(&honest_proof);

    // ---------------- site enumeration (generic, record-only) ----------------
    // flat[i] = (index, pc, opcode, rd, source-register reads, is_writeback)
    let flat: Vec<(usize, u64, Opcode, u8, Vec<u8>, bool)> = {
        let mut v = vec![];
        for r in &records {
            for ev in &r.cpu_events {
                let ins = ev.instruction;
                let op = ins.opcode;
                let mut reads: Vec<u8> = vec![];
                if !ins.imm_b {
                    reads.push(ins.op_b as u8);
                }
                if !ins.imm_c {
                    reads.push(ins.op_c as u8);
                }
                if matches!(op, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD)
                    || ins.is_branch_instruction()
                {
                    reads.push(ins.op_a);
                }
                if matches!(op, Opcode::ECALL | Opcode::EBREAK) {
                    reads.extend([5u8, 10, 11, 12, 13, 14, 15]);
                }
                let wb = is_writeback(op) && ins.op_a != 0;
                v.push((v.len(), ev.pc as u64, op, ins.op_a, reads, wb));
            }
        }
        v
    };
    let mut dead: Vec<bool> = vec![false; flat.len()];
    let mut dead_final: Vec<bool> = vec![false; flat.len()];
    for i in 0..flat.len() {
        if !flat[i].5 {
            continue;
        }
        let rd = flat[i].3;
        let mut is_dead = true;
        let mut rewritten = false;
        for j in (i + 1)..flat.len() {
            if flat[j].4.contains(&rd) {
                is_dead = false;
                break;
            }
            if flat[j].5 && flat[j].3 == rd {
                rewritten = true;
                break;
            }
        }
        dead[i] = is_dead;
        dead_final[i] = is_dead && !rewritten;
    }
    // occurrence index of each dynamic event at its own pc
    let mut occ_at_pc: std::collections::BTreeMap<u64, usize> = Default::default();
    let mut occ: Vec<usize> = vec![0; flat.len()];
    for i in 0..flat.len() {
        let e = occ_at_pc.entry(flat[i].1).or_insert(0);
        occ[i] = *e;
        *e += 1;
    }
    // execution count per static site
    let mut per_site: std::collections::BTreeMap<(Opcode, u64), usize> = Default::default();
    for i in 0..flat.len() {
        if flat[i].5 {
            *per_site.entry((flat[i].2, flat[i].1)).or_insert(0) += 1;
        }
    }

    // sites: (opcode, pc, nth, dead, dead_final, execs)
    let mut sites: Vec<(Opcode, u64, i64, bool, bool, usize)> = vec![];
    match sites_mode.as_str() {
        "dead" => {
            for i in 0..flat.len() {
                if dead[i] {
                    let execs = *per_site.get(&(flat[i].2, flat[i].1)).unwrap_or(&0);
                    sites.push((
                        flat[i].2,
                        flat[i].1,
                        occ[i] as i64,
                        true,
                        dead_final[i],
                        execs,
                    ));
                }
            }
            sites.sort_by_key(|(op, pc, nth, _, _, _)| (*op, *pc, *nth));
        }
        "all" => {
            // every distinct static writeback site, at its LAST execution
            let mut last: std::collections::BTreeMap<(Opcode, u64), (i64, bool, bool)> =
                Default::default();
            for i in 0..flat.len() {
                if flat[i].5 {
                    last.insert(
                        (flat[i].2, flat[i].1),
                        (occ[i] as i64, dead[i], dead_final[i]),
                    );
                }
            }
            for ((op, pc), (nth, d, df)) in last {
                let execs = *per_site.get(&(op, pc)).unwrap_or(&0);
                sites.push((op, pc, nth, d, df, execs));
            }
            sites.sort_by_key(|(op, pc, _, _, _, _)| (*op, *pc));
        }
        "pcs" => {
            // an explicit list of static pcs (LACUNA_PCS), last execution of each
            let want: Vec<u64> = std::env::var("LACUNA_PCS")
                .unwrap_or_default()
                .split(',')
                .map(|t| t.trim().trim_start_matches("0x").to_string())
                .filter(|t| !t.is_empty())
                .map(|t| u64::from_str_radix(&t, 16).expect("hex pc"))
                .collect();
            let mut last: std::collections::BTreeMap<(Opcode, u64), (i64, bool, bool)> =
                Default::default();
            for i in 0..flat.len() {
                if flat[i].5 {
                    last.insert(
                        (flat[i].2, flat[i].1),
                        (occ[i] as i64, dead[i], dead_final[i]),
                    );
                }
            }
            for ((op, pc), (nth, d, df)) in last {
                if !want.contains(&pc) {
                    continue;
                }
                let execs = *per_site.get(&(op, pc)).unwrap_or(&0);
                sites.push((op, pc, nth, d, df, execs));
            }
            sites.sort_by_key(|(op, pc, _, _, _, _)| (*op, *pc));
        }
        "ops" => {
            // every static writeback site whose opcode is in LACUNA_OPS, last execution
            let want: Vec<String> = std::env::var("LACUNA_OPS")
                .unwrap_or_default()
                .split(',')
                .map(|t| t.trim().to_uppercase())
                .filter(|t| !t.is_empty())
                .collect();
            let mut last: std::collections::BTreeMap<(Opcode, u64), (i64, bool, bool)> =
                Default::default();
            for i in 0..flat.len() {
                if flat[i].5 {
                    last.insert(
                        (flat[i].2, flat[i].1),
                        (occ[i] as i64, dead[i], dead_final[i]),
                    );
                }
            }
            for ((op, pc), (nth, d, df)) in last {
                let name = format!("{op:?}").to_uppercase();
                if !want.is_empty() && !want.contains(&name) {
                    continue;
                }
                let execs = *per_site.get(&(op, pc)).unwrap_or(&0);
                sites.push((op, pc, nth, d, df, execs));
            }
            sites.sort_by_key(|(op, pc, _, _, _, _)| (*op, *pc));
        }
        _ => {
            // cold3: up to 3 least-executed static sites per opcode class, last execution
            let mut by_op: std::collections::BTreeMap<Opcode, Vec<(u64, usize)>> =
                Default::default();
            for ((op, pc), n) in &per_site {
                by_op.entry(*op).or_default().push((*pc, *n));
            }
            let mut last: std::collections::BTreeMap<(Opcode, u64), (i64, bool, bool)> =
                Default::default();
            for i in 0..flat.len() {
                if flat[i].5 {
                    last.insert(
                        (flat[i].2, flat[i].1),
                        (occ[i] as i64, dead[i], dead_final[i]),
                    );
                }
            }
            for (op, mut v) in by_op {
                v.sort_by_key(|(pc, n)| (*n, *pc));
                for (pc, execs) in v.into_iter().take(3) {
                    let (nth, d, df) = last[&(op, pc)];
                    sites.push((op, pc, nth, d, df, execs));
                }
            }
            sites.sort_by_key(|(op, pc, _, _, _, _)| (*op, *pc));
        }
    }

    // Optional address-range filter (LACUNA_PC_LO / LACUNA_PC_HI, hex).  Used to
    // restrict the enumeration to the guest's own `main` symbol, whose bounds are
    // read from the ELF symbol table by the driver -- a mechanical, reproducible
    // way to name "the operation the seed program is about".
    {
        let lo = std::env::var("LACUNA_PC_LO")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
        let hi = std::env::var("LACUNA_PC_HI")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
        if let (Some(lo), Some(hi)) = (lo, hi) {
            sites.retain(|(_, pc, _, _, _, _)| *pc >= lo && *pc < hi);
        }
    }

    let total_sites_before_shard = sites.len();
    let sites: Vec<_> = sites
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % shard_n == shard_i)
        .map(|(_, s)| s)
        .take(limit)
        .collect();

    let mut menu = if mu_mode == "all" {
        menu_all()
    } else {
        menu_single()
    };
    // LACUNA_MU_ONLY isolates one template per process. Some parameters (notably
    // +B^3 and the boundary values) turn an address-carrying write-back into a
    // multi-terabyte allocation request; Rust aborts on allocation failure and an
    // abort is NOT unwindable, so it kills the whole enumeration process rather
    // than being caught as an EXECFAIL. Running one template per process bounds the
    // blast radius to that template's rows.
    if let Ok(only) = std::env::var("LACUNA_MU_ONLY") {
        menu.retain(|(label, _, _, _)| *label == only.as_str());
    }

    // ---------------- output ----------------
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
    println!("LACUNA_HEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }

    println!(
        "LACUNA_BASELINE,{tag},pico,22b0aae6321c1f63c72aafd0b506b5f45b91ffb1,{seed},\
instructions={},writebacks={},dead={},dead_final={},static_sites={},honest_pv={},\
honest_record_ms={},honest_prove_ms={},honest_verify_ms={},sites_mode={},mu_mode={},\
sites_total={},sites_this_shard={},shard={}/{}",
        flat.len(),
        flat.iter().filter(|f| f.5).count(),
        dead.iter().filter(|d| **d).count(),
        dead_final.iter().filter(|d| **d).count(),
        per_site.len(),
        hexpv(&honest_pv),
        honest_record_ms,
        honest_prove_ms,
        honest_verify_ms,
        sites_mode,
        mu_mode,
        total_sites_before_shard,
        sites.len(),
        shard_i,
        shard_n
    );

    // opcode census of the accepted baseline: distinct static writeback sites per opcode
    {
        let mut census: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for ((op, _pc), n) in &per_site {
            let e = census.entry(format!("{op:?}")).or_insert((0, 0));
            e.0 += 1;
            e.1 += *n;
        }
        let s: Vec<String> = census
            .iter()
            .map(|(k, (sites, execs))| format!("{k}:{sites}:{execs}"))
            .collect();
        println!("LACUNA_OPCENSUS,{tag},{seed},{}", s.join(" "));
    }

    let honest_hex = hexpv(&honest_pv);
    let mut cpu_sink = cpu_csv_open();
    for (op, pc, nth, d, df, execs) in &sites {
        for (label, template, kind, arg) in &menu {
            use crate::machine::lacuna_stage as lstage;
            lstage::reset();
            let cand_t0 = Instant::now();
            let cand_c0 = lstage::proc_cpu_ms();
            let (t_record_ms, t_record_cpu_ms) = time_record_ms(&program, *pc, *nth, *kind, *arg);
            let c = run_candidate(&machine, &pk, &vk, &program, *pc, *nth, *kind, *arg);
            let cand_wall_ms = cand_t0.elapsed().as_millis() as i64;
            let cand_cpu_ms = lstage::proc_cpu_ms().saturating_sub(cand_c0) as i64;
            if let Some(f) = cpu_sink.as_mut() {
                let s1b_wall = (lstage::wall_us(lstage::S1_EMUL) / 1000) as i64;
                let s1b_cpu = lstage::cpu_ms(lstage::S1_EMUL) as i64;
                let s2g_wall = (lstage::wall_us(lstage::S2_GEN) / 1000) as i64;
                let s2g_cpu = lstage::cpu_ms(lstage::S2_GEN) as i64;
                let s2c_wall = (lstage::wall_us(lstage::S2_COMMIT) / 1000) as i64;
                let s2c_cpu = lstage::cpu_ms(lstage::S2_COMMIT) as i64;
                let s1_wall = t_record_ms as i64 + s1b_wall;
                let s1_cpu = t_record_cpu_ms as i64 + s1b_cpu;
                let s2_wall = s2g_wall + s2c_wall;
                let s2_cpu = s2g_cpu + s2c_cpu;
                let s3_wall = (lstage::wall_us(lstage::S3_PROVE) / 1000) as i64;
                let s3_cpu = lstage::cpu_ms(lstage::S3_PROVE) as i64;
                let s4_wall = c.t_verify_ms as i64;
                let s4_cpu = c.t_verify_cpu_ms as i64;
                let key = format!("enc|{tag}|{seed}|{op:?}|{pc:#x}|{nth}|{label}");
                writeln!(
                    f,
                    "{key},{seed},{op:?},{template},{},{},{s1_wall},{s1_cpu},{s2_wall},{s2_cpu},\
{s3_wall},{s3_cpu},{s4_wall},{s4_cpu},{},{},{cand_wall_ms},{cand_cpu_ms}",
                    c.outcome,
                    c.failure_stage,
                    cand_wall_ms - s1_wall - s2_wall - s3_wall - s4_wall,
                    cand_cpu_ms - s1_cpu - s2_cpu - s3_cpu - s4_cpu
                )
                .unwrap();
                f.flush().ok();
                println!(
                    "LACUNA_CPU_DETAIL,{key},s1a_wall={t_record_ms},s1a_cpu={t_record_cpu_ms},\
s1b_wall={s1b_wall},s1b_cpu={s1b_cpu},s1b_n={},s2gen_wall={s2g_wall},s2gen_cpu={s2g_cpu},\
s2gen_n={},s2commit_wall={s2c_wall},s2commit_cpu={s2c_cpu},s2commit_n={},s3_wall={s3_wall},\
s3_cpu={s3_cpu},s3_n={},s4_wall={s4_wall},s4_cpu={s4_cpu}",
                    lstage::enters(lstage::S1_EMUL),
                    lstage::enters(lstage::S2_GEN),
                    lstage::enters(lstage::S2_COMMIT),
                    lstage::enters(lstage::S3_PROVE)
                );
            }
            let pv_hex = hexpv(&c.pv);
            // A proof that commits NOTHING is not a wrong value: an empty pv_stream
            // is a liveness outcome, not a soundness one, so it does not satisfy
            // "the committed public output differs from the honest one".
            let nonempty = !pv_hex.is_empty() && pv_hex != "NONE";
            let changed = c.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
            let accepted_case = c.outcome == "ACCEPT" && c.hits > 0 && changed;
            let row = format!(
                "{tag},pico,22b0aae6321c1f63c72aafd0b506b5f45b91ffb1,{seed},encoding,\
{structure},{op:?},{pc:#x},{nth},{d},{df},{execs},{label},{template},{kind},{arg},\
{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{}",
                c.outcome,
                c.failure_stage,
                c.hits,
                pv_hex,
                honest_hex,
                changed,
                accepted_case,
                t_record_ms,
                c.t_prove_ms,
                c.t_verify_ms,
                c.reason,
                c.digest,
                honest_digest,
                (!c.digest.is_empty() && c.digest != honest_digest)
            );
            println!("LACUNA_ROW,{row}");
            if let Some(f) = sink.as_mut() {
                writeln!(f, "{row}").unwrap();
                f.flush().ok();
            }
        }
    }
    println!("LACUNA_DONE,{tag},sites={},mu={}", sites.len(), menu.len());
}

// ===========================================================================
// BINDING MUTATION (BIND-O1 — store--load timestamp), generic enumeration.
//
// For a static load site the executor delivers the *second-most-recent* value
// written to the loaded address, pico's own witness generator derives every value
// column of that memory row from it, and a post-trace-generation hook swaps the
// FREE memory-access clk of that row with the immediately preceding access to the
// same address. The opcode/CPU component keeps the honest execution order; only the
// memory component sees the rewritten record.
//   S      = {MemoryReadWrite}
//   C \ S  = {Cpu, register/ALU chips, MemoryInitialize/Finalize, Byte/U16 ranges, ...}
// The swap is an adjacent transposition of the address's timestamp chain, so the
// timestamp-difference multiset is preserved exactly and no range-check
// multiplicity has to be rebalanced.
//
// Each site is run twice: with the reorder (the binding mutation) and without it
// (the negative control isolating the free clk as the sole lever).
// ===========================================================================

use crate::{
    chips::chips::riscv_memory::read_write::columns::{
        MemoryChipValueCols, NUM_MEMORY_CHIP_VALUE_COLS,
    },
    emulator::riscv::emulator::stale_load,
    instances::machine::riscv::forge_hook,
};
use core::borrow::{Borrow, BorrowMut};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

type F = KoalaBear;

fn word_u64(w: &crate::compiler::word::Word<F>) -> u64 {
    (w.0[0].as_canonical_u32() as u64)
        | ((w.0[1].as_canonical_u32() as u64) << 16)
        | ((w.0[2].as_canonical_u32() as u64) << 32)
        | ((w.0[3].as_canonical_u32() as u64) << 48)
}

/// Generic BIND-O1 rewrite: swap the armed load row's free clk with the immediately
/// preceding access to the same address. Returns a short status string.
fn bind_o1_swap(traces: &mut Vec<(String, RowMajorMatrix<F>)>) -> String {
    if !stale_load::fired() || stale_load::row_clk() == u64::MAX {
        return "no_row".to_string();
    }
    let Some(mi) = traces.iter().position(|(n, _)| n == "MemoryReadWrite") else {
        return "no_chip".to_string();
    };
    let target_addr = stale_load::target_addr();
    let row_clk = stale_load::row_clk() as u32;
    let row_chunk = stale_load::row_chunk() as u32;

    let trace = &mut traces[mi].1;
    let per = NUM_MEMORY_CHIP_VALUE_COLS;
    let nblocks = trace.values.len() / per;

    // (block, chunk, clk, is_write)
    let mut chain: Vec<(usize, u32, u32, bool)> = vec![];
    for b in 0..nblocks {
        let base = b * per;
        let cols: &MemoryChipValueCols<F> = trace.values[base..base + per].borrow();
        let is_load = cols.instruction.is_lb == F::ONE
            || cols.instruction.is_lbu == F::ONE
            || cols.instruction.is_lh == F::ONE
            || cols.instruction.is_lhu == F::ONE
            || cols.instruction.is_lw == F::ONE
            || cols.instruction.is_lwu == F::ONE
            || cols.instruction.is_ld == F::ONE;
        let is_store = cols.instruction.is_sb == F::ONE
            || cols.instruction.is_sh == F::ONE
            || cols.instruction.is_sw == F::ONE
            || cols.instruction.is_sd == F::ONE;
        if !is_load && !is_store {
            continue;
        }
        if word_u64(&cols.addr_aligned) != target_addr {
            continue;
        }
        chain.push((
            b,
            cols.chunk.as_canonical_u32(),
            cols.clk.as_canonical_u32(),
            is_store,
        ));
    }
    chain.sort_by_key(|(_, ch, c, _)| (*ch, *c));
    let Some(li) = chain
        .iter()
        .position(|(_, ch, c, _)| *ch == row_chunk && *c == row_clk)
    else {
        return "load_row_not_found".to_string();
    };
    if li == 0 {
        return "no_predecessor".to_string();
    }
    let (lb, _, l_clk, _) = chain[li];
    let (pb, p_chunk, p_clk, p_is_store) = chain[li - 1];
    if !p_is_store {
        return "predecessor_not_a_store".to_string();
    }
    let q_clk = if li >= 2 { Some(chain[li - 2].2) } else { None };
    let Some(q_clk) = q_clk else {
        return "no_pre_predecessor".to_string();
    };

    let set_ts = |values: &mut [F], b: usize, chunk: u32, clk: u32, prev_clk: u32| {
        let base = b * per;
        let cols: &mut MemoryChipValueCols<F> = values[base..base + per].borrow_mut();
        cols.clk = F::from_canonical_u32(clk);
        cols.memory_access.access.prev_clk = F::from_canonical_u32(prev_clk);
        cols.memory_access.access.prev_chunk = F::from_canonical_u32(chunk);
        cols.memory_access.access.compare_clk = F::ONE;
        let diff = clk.wrapping_sub(prev_clk).wrapping_sub(1);
        cols.memory_access.access.diff_16bit_limb = F::from_canonical_u32(diff & 0xFFFF);
        cols.memory_access.access.diff_8bit_limb = F::from_canonical_u32((diff >> 16) & 0xFF);
    };
    // adjacent transposition: L takes P's slot (chaining off Q), P takes L's slot
    set_ts(&mut trace.values, lb, p_chunk, p_clk, q_clk);
    set_ts(&mut trace.values, pb, p_chunk, l_clk, p_clk);
    format!("swapped_L{l_clk}_P{p_clk}_Q{q_clk}")
}

struct BindOut {
    digest: String,
    outcome: &'static str,
    failure_stage: &'static str,
    reason: String,
    pv: Option<Vec<u8>>,
    hook_status: String,
    fired: bool,
    honest_value: u64,
    stale_value: u64,
    addr: u64,
    t_prove_ms: u128,
    t_verify_ms: u128,
    /// LACUNA CPU calibration (additive): process user+system CPU ms spent in S4.
    t_verify_cpu_ms: u64,
}

fn run_binding_candidate(
    machine: &RiscvMachine<SC, C>,
    pk: &crate::machine::keys::BaseProvingKey<SC>,
    vk: &crate::machine::keys::BaseVerifyingKey<SC>,
    program: &Arc<Program>,
    pc: u64,
    reorder: bool,
) -> BindOut {
    let status = Arc::new(std::sync::Mutex::new(String::from("not_called")));
    let status2 = status.clone();
    let hook: forge_hook::Hook = if reorder {
        Box::new(move |traces: &mut Vec<(String, RowMajorMatrix<F>)>| {
            // The hook is invoked once per generated trace set; accumulate every
            // invocation's status so a later chunk without the memory chip cannot
            // erase the invocation that actually performed the swap.
            let s = bind_o1_swap(traces);
            let mut g = status2.lock().unwrap();
            if g.as_str() == "not_called" {
                *g = s;
            } else {
                g.push('|');
                g.push_str(&s);
            }
        })
    } else {
        Box::new(|_t: &mut Vec<(String, RowMajorMatrix<F>)>| {})
    };

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stale_load::with(pc, || {
            forge_hook::with_hook(hook, || {
                let t0 = Instant::now();
                let witness = ProvingWitness::<SC, C, Vec<u8>>::setup_for_riscv(
                    program.clone(),
                    stdin(),
                    opts(),
                    pk.clone(),
                    vk.clone(),
                );
                let (proof, _r) = machine.prove_with_shape_report(&witness, None);
                let t_prove = t0.elapsed().as_millis();
                let pv = proof.pv_stream.clone();
                let digest = committed_digest_hex(&proof);
                let meta = (
                    stale_load::fired(),
                    stale_load::honest_value(),
                    stale_load::stale_value(),
                    stale_load::target_addr(),
                );
                let t1 = Instant::now();
                let c1 = crate::machine::lacuna_stage::proc_cpu_ms();
                let res = machine.verify(&proof, vk).map_err(|e| format!("{e:?}"));
                let t_verify = t1.elapsed().as_millis();
                let cpu_verify = crate::machine::lacuna_stage::proc_cpu_ms().saturating_sub(c1);
                (pv, res, meta, t_prove, t_verify, digest, cpu_verify)
            })
        })
    }));
    std::panic::set_hook(prev);
    let hook_status = status.lock().unwrap().clone();
    let _swap_applied = hook_status.contains("swapped_");
    match out {
        Ok((pv, r, (fired, hv, sv, addr), tp, tv, dg, cv)) => BindOut {
            digest: dg,
            outcome: match (&r, fired) {
                (Ok(()), true) => "ACCEPT",
                (Ok(()), false) => "NOOP",
                (Err(_), _) => "REJECT",
            },
            failure_stage: match (&r, fired) {
                (Ok(()), true) => "accepted_proof",
                (Ok(()), false) => "mutation",
                (Err(_), _) => "verify",
            },
            reason: r.err().map(|e| trunc(&e)).unwrap_or_default(),
            pv,
            hook_status,
            fired,
            honest_value: hv,
            stale_value: sv,
            addr,
            t_prove_ms: tp,
            t_verify_ms: tv,
            t_verify_cpu_ms: cv,
        },
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<opaque>".to_string());
            let constraintish = msg.contains("Cumulative sum")
                || msg.contains("cumulative")
                || msg.contains("constraint")
                || msg.contains("Constraint")
                || msg.contains("lookup")
                || msg.contains("OodEvaluationMismatch")
                || msg.contains("InvalidProofShape");
            BindOut {
                digest: String::new(),
                outcome: if constraintish { "REJECT" } else { "EXECFAIL" },
                failure_stage: if constraintish { "prove" } else { "fork_exec" },
                reason: trunc(&msg),
                pv: None,
                hook_status,
                fired: false,
                honest_value: 0,
                stale_value: 0,
                addr: 0,
                t_prove_ms: 0,
                t_verify_ms: 0,
                t_verify_cpu_ms: 0,
            }
        }
    }
}

#[test]
#[ignore = "LACUNA evaluation run: generic BIND-O1 store--load timestamp enumeration; use --release"]
fn lacuna_binding_enumeration() {
    let seed = seed_id();
    let structure = std::env::var("LACUNA_STRUCT").unwrap_or_else(|_| "Store--load".to_string());
    let tag = std::env::var("LACUNA_TAG").unwrap_or_else(|_| "bind".to_string());
    let (shard_i, shard_n) = match std::env::var("LACUNA_SHARD") {
        Ok(s) => {
            let mut it = s.split('/');
            let i: usize = it.next().unwrap_or("0").parse().unwrap_or(0);
            let n: usize = it.next().unwrap_or("1").parse().unwrap_or(1);
            (i, n.max(1))
        }
        Err(_) => (0, 1),
    };
    let limit: usize = std::env::var("LACUNA_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    let program = fib_elf_program();
    let machine = RiscvMachine::new(SC::test(), RiscvChipType::all_chips(), RISCV_NUM_PVS);
    let (pk, vk) = machine.setup_keys(&program);

    let records = test_rv64_emulate_with_opts(program.clone(), stdin(), opts());
    let honest_witness = ProvingWitness::<SC, C, Vec<u8>>::setup_for_riscv(
        program.clone(),
        stdin(),
        opts(),
        pk.clone(),
        vk.clone(),
    );
    let (honest_proof, _) = machine.prove_with_shape_report(&honest_witness, None);
    machine
        .verify(&honest_proof, &vk)
        .expect("honest baseline must verify");
    let honest_pv = honest_proof.pv_stream.clone();
    let honest_hex = hexpv(&honest_pv);
    let honest_digest = committed_digest_hex(&honest_proof);

    // Candidate load sites: doubleword loads whose static pc executes exactly once
    // (so the pc alone identifies the memory row that the value substitution edits).
    let mut ld_counts: std::collections::BTreeMap<u64, usize> = Default::default();
    for r in &records {
        for ev in &r.cpu_events {
            if ev.instruction.opcode == Opcode::LD {
                *ld_counts.entry(ev.pc as u64).or_insert(0) += 1;
            }
        }
    }
    let all_ld_sites = ld_counts.len();
    let mut sites: Vec<u64> = ld_counts
        .iter()
        .filter(|(_, n)| **n == 1)
        .map(|(pc, _)| *pc)
        .collect();
    sites.sort_unstable();
    let sites_total = sites.len();
    let sites: Vec<u64> = sites
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % shard_n == shard_i)
        .map(|(_, s)| s)
        .take(limit)
        .collect();

    let mut sink: Option<std::fs::File> = std::env::var("LACUNA_OUT").ok().map(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .expect("open LACUNA_OUT")
    });
    let header = "run_tag,target,revision,seed_id,mutation_mode,program_structure,\
concrete_interaction,pc,variant,mutation_template,addr,honest_value,stale_value,hook_status,\
fired,swap_applied,outcome,failure_stage,pv_hex,honest_pv_hex,output_changed,accepted_case,\
t_prove_ms,t_verify_ms,reason,committed_digest,honest_committed_digest,digest_changed";
    println!("LACUNA_BHEADER,{header}");
    if let Some(f) = sink.as_mut() {
        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(f, "{header}").unwrap();
        }
    }
    println!(
        "LACUNA_BBASELINE,{tag},pico,{seed},ld_static_sites={},ld_sites_execs1={},\
sites_this_shard={},shard={}/{},honest_pv={}",
        all_ld_sites,
        sites_total,
        sites.len(),
        shard_i,
        shard_n,
        honest_hex
    );

    let mut cpu_sink = cpu_csv_open();
    for pc in &sites {
        for (variant, reorder) in [("bind_o1_swap", true), ("neg_control_no_swap", false)] {
            use crate::machine::lacuna_stage as lstage;
            lstage::reset();
            let cand_t0 = Instant::now();
            let cand_c0 = lstage::proc_cpu_ms();
            // The control arm hands the memory component a different stored VALUE with
            // the timestamps left honest: that is BIND-V3 (store--load value), a
            // template in its own right, and it is expected to be rejected. Only the
            // swap arm is BIND-O1.
            let template = if reorder { "BIND-O1" } else { "BIND-V3" };
            let b = run_binding_candidate(&machine, &pk, &vk, &program, *pc, reorder);
            let cand_wall_ms = cand_t0.elapsed().as_millis() as i64;
            let cand_cpu_ms = lstage::proc_cpu_ms().saturating_sub(cand_c0) as i64;
            if let Some(f) = cpu_sink.as_mut() {
                // The binding driver performs NO standalone perturbed-record replay
                // (unlike the encoding driver), so S1 here is the in-prove emulation only.
                let s1_wall = (lstage::wall_us(lstage::S1_EMUL) / 1000) as i64;
                let s1_cpu = lstage::cpu_ms(lstage::S1_EMUL) as i64;
                let s2g_wall = (lstage::wall_us(lstage::S2_GEN) / 1000) as i64;
                let s2g_cpu = lstage::cpu_ms(lstage::S2_GEN) as i64;
                let s2c_wall = (lstage::wall_us(lstage::S2_COMMIT) / 1000) as i64;
                let s2c_cpu = lstage::cpu_ms(lstage::S2_COMMIT) as i64;
                let s2_wall = s2g_wall + s2c_wall;
                let s2_cpu = s2g_cpu + s2c_cpu;
                let s3_wall = (lstage::wall_us(lstage::S3_PROVE) / 1000) as i64;
                let s3_cpu = lstage::cpu_ms(lstage::S3_PROVE) as i64;
                let s4_wall = b.t_verify_ms as i64;
                let s4_cpu = b.t_verify_cpu_ms as i64;
                let key = format!("bind|{tag}|{seed}|LD|{pc:#x}|{variant}");
                writeln!(
                    f,
                    "{key},{seed},LD,{template},{},{},{s1_wall},{s1_cpu},{s2_wall},{s2_cpu},\
{s3_wall},{s3_cpu},{s4_wall},{s4_cpu},{},{},{cand_wall_ms},{cand_cpu_ms}",
                    b.outcome,
                    b.failure_stage,
                    cand_wall_ms - s1_wall - s2_wall - s3_wall - s4_wall,
                    cand_cpu_ms - s1_cpu - s2_cpu - s3_cpu - s4_cpu
                )
                .unwrap();
                f.flush().ok();
                println!(
                    "LACUNA_CPU_DETAIL,{key},s1a_wall=0,s1a_cpu=0,s1b_wall={s1_wall},\
s1b_cpu={s1_cpu},s1b_n={},s2gen_wall={s2g_wall},s2gen_cpu={s2g_cpu},s2gen_n={},\
s2commit_wall={s2c_wall},s2commit_cpu={s2c_cpu},s2commit_n={},s3_wall={s3_wall},\
s3_cpu={s3_cpu},s3_n={},s4_wall={s4_wall},s4_cpu={s4_cpu}",
                    lstage::enters(lstage::S1_EMUL),
                    lstage::enters(lstage::S2_GEN),
                    lstage::enters(lstage::S2_COMMIT),
                    lstage::enters(lstage::S3_PROVE)
                );
            }
            let pv_hex = hexpv(&b.pv);
            let nonempty = !pv_hex.is_empty() && pv_hex != "NONE";
            let changed = b.outcome == "ACCEPT" && nonempty && pv_hex != honest_hex;
            // A swap arm whose hook never reported an applied transposition did not
            // realise the mutation; it must not be counted as a BIND-O1 accepted case.
            let applied = !reorder || b.hook_status.contains("swapped_");
            let accepted = b.outcome == "ACCEPT" && b.fired && changed && applied;
            let row = format!(
                "{tag},pico,22b0aae6321c1f63c72aafd0b506b5f45b91ffb1,{seed},binding,\
{structure},LD,{pc:#x},{variant},{template},{:#x},{:#x},{:#x},{},{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{}",
                b.addr,
                b.honest_value,
                b.stale_value,
                b.hook_status,
                b.fired,
                applied,
                b.outcome,
                b.failure_stage,
                pv_hex,
                honest_hex,
                changed,
                accepted,
                b.t_prove_ms,
                b.t_verify_ms,
                b.reason,
                b.digest,
                honest_digest,
                (!b.digest.is_empty() && b.digest != honest_digest)
            );
            println!("LACUNA_BROW,{row}");
            if let Some(f) = sink.as_mut() {
                writeln!(f, "{row}").unwrap();
                f.flush().ok();
            }
        }
    }
    println!("LACUNA_BDONE,{tag},sites={}", sites.len());
}
