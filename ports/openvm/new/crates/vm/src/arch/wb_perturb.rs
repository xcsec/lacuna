//! LACUNA record-layer write-back perturbation hook (test/evaluation instrumentation).
//!
//! DEFAULT OFF. When `ENABLED` is false every entry point is a single relaxed atomic
//! load and returns its input unchanged. No constraint, AIR or column is touched by
//! this module.
//!
//! # What it hooks
//!
//! OpenVM splits every rv32im instruction into an *adapter* record and a *core* record.
//! The architectural result of an instruction reaches two places:
//!
//!   1. VM memory, through the single write path
//!      [`openvm_rv32im_circuit::adapters::timed_write`] -- used by every rv32im adapter
//!      (base_alu / less_than / shift via `adapters/alu.rs`, mul / mulh / divrem via
//!      `adapters/mul.rs`, jal_lui / auipc via `adapters/rdwrite.rs`, jalr via
//!      `adapters/jalr.rs`, hintstore, and loadstore which calls `timed_write`'s inner
//!      `timed_write` directly).
//!   2. The core record, but ONLY for `Rv32JalLuiCoreRecord::rd_data`. Every other
//!      rv32im core record stores the *operands* and the trace filler recomputes the
//!      result from them, so there is no result field to rewrite.
//!
//! Therefore the smallest hook set that covers "the value the instruction produces" is
//! the pair (`timed_write`, `jal_lui::core` result). [`on_result_word`] is used at the
//! second site and marks the instruction as already perturbed so [`on_write_back_word`]
//! does not apply the mutation twice; the two stay coherent (record and memory agree),
//! exactly as pico's `subst()` keeps the CPU event and the ALU event coherent.
//!
//! The arming key is `(static pc, n-th execution of that pc)` and the rewriting menu is
//! instruction-independent: it contains no opcode, chip or column knowledge.
//!
//! `begin` is called once per preflight-executed instruction from
//! `crate::arch::interpreter_preflight::PreflightInterpretedInstance::execute_instruction`.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

const R: Ordering = Ordering::Relaxed;

/// v ^ (1 << i)
pub const MU_XORBIT: usize = 0;
/// v + k (wrapping); k = +/- B^i expresses the scalar-result template
pub const MU_ADDK: usize = 1;
/// v <- 0
pub const MU_ZERO: usize = 2;
/// v <- literal (boundary values)
pub const MU_SET: usize = 3;

static ENABLED: AtomicBool = AtomicBool::new(false);
static TARGET_PC: AtomicU32 = AtomicU32::new(u32::MAX);
static TARGET_NTH: AtomicI64 = AtomicI64::new(-1);
static SEEN: AtomicI64 = AtomicI64::new(0);
static MU_KIND: AtomicUsize = AtomicUsize::new(MU_XORBIT);
static MU_ARG: AtomicI64 = AtomicI64::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);
static HONEST: AtomicU64 = AtomicU64::new(0);
static FORGED: AtomicU64 = AtomicU64::new(0);
/// The instruction currently being preflight-executed is at the armed site.
static ARMED_NOW: AtomicBool = AtomicBool::new(false);
/// The mutation has already been applied for the instruction currently executing.
static APPLIED_NOW: AtomicBool = AtomicBool::new(false);
/// Number of executions of the armed pc observed in the last `with` scope.
static SITE_EXECS: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(R)
}

/// Number of write-backs actually perturbed (0 => the site never executed / the
/// mutation was a no-op on that value).
pub fn hits() -> usize {
    HITS.load(R)
}
pub fn honest_value() -> u32 {
    HONEST.load(R) as u32
}
pub fn forged_value() -> u32 {
    FORGED.load(R) as u32
}
/// How many times the armed static pc was executed in preflight.
pub fn site_execs() -> usize {
    SITE_EXECS.load(R)
}

/// Run `body` with the write-back at `pc` perturbed by `mu`. Cleared on return or panic.
/// `nth < 0` arms every execution of that static pc.
pub fn with<Res>(
    pc: u32,
    nth: i64,
    mu_kind: usize,
    mu_arg: i64,
    body: impl FnOnce() -> Res,
) -> Res {
    TARGET_PC.store(pc, R);
    TARGET_NTH.store(nth, R);
    SEEN.store(0, R);
    MU_KIND.store(mu_kind, R);
    MU_ARG.store(mu_arg, R);
    HITS.store(0, R);
    HONEST.store(0, R);
    FORGED.store(0, R);
    ARMED_NOW.store(false, R);
    APPLIED_NOW.store(false, R);
    SITE_EXECS.store(0, R);
    ENABLED.store(true, R);
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            ENABLED.store(false, R);
            TARGET_PC.store(u32::MAX, R);
            ARMED_NOW.store(false, R);
            APPLIED_NOW.store(false, R);
        }
    }
    let _c = Clear;
    body()
}

/// Called once per preflight-executed instruction, before the executor runs.
#[inline(always)]
pub fn begin(pc: u32) {
    if !ENABLED.load(R) {
        return;
    }
    APPLIED_NOW.store(false, R);
    if pc != TARGET_PC.load(R) {
        ARMED_NOW.store(false, R);
        return;
    }
    SITE_EXECS.fetch_add(1, R);
    let n = SEEN.fetch_add(1, R);
    let want = TARGET_NTH.load(R);
    ARMED_NOW.store(want < 0 || n == want, R);
}

#[inline]
fn mutate(v: u32) -> u32 {
    let arg = MU_ARG.load(R);
    match MU_KIND.load(R) {
        MU_XORBIT => v ^ (1u32 << ((arg as u32) & 31)),
        MU_ADDK => v.wrapping_add(arg as u32),
        MU_ZERO => 0,
        MU_SET => arg as u32,
        _ => v,
    }
}

#[inline]
fn apply(v: u32) -> Option<u32> {
    if !ENABLED.load(R) || !ARMED_NOW.load(R) || APPLIED_NOW.load(R) {
        return None;
    }
    let f = mutate(v);
    if f == v {
        return None;
    }
    APPLIED_NOW.store(true, R);
    HITS.fetch_add(1, R);
    HONEST.store(v as u64, R);
    FORGED.store(f as u64, R);
    Some(f)
}

/// Hook site 1: the memory write-back. Called from
/// `openvm_rv32im_circuit::adapters::timed_write` with the 4-byte little-endian word an
/// instruction writes. Returns true if the word was rewritten in place.
#[inline(always)]
pub fn on_write_back_word(data: &mut [u8; 4]) -> bool {
    if !ENABLED.load(R) {
        return false;
    }
    match apply(u32::from_le_bytes(*data)) {
        Some(f) => {
            *data = f.to_le_bytes();
            true
        }
        None => false,
    }
}

/// Hook site 2: the one core record that stores a result
/// (`Rv32JalLuiCoreRecord::rd_data`). Applying the mutation here, before the value is
/// both stored in the record and handed to the adapter write, keeps record and memory
/// coherent.
#[inline(always)]
pub fn on_result_word(data: [u8; 4]) -> [u8; 4] {
    if !ENABLED.load(R) {
        return data;
    }
    match apply(u32::from_le_bytes(data)) {
        Some(f) => f.to_le_bytes(),
        None => data,
    }
}
