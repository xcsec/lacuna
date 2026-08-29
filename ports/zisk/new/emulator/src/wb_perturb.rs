//! ==================== RECORD-LAYER WRITE-BACK PERTURBATION (PoC ONLY) ====================
//!
//! Test-only, env-gated, DEFAULT OFF. When no `ZISK_WB_ENABLE` env var is set every function
//! here is a pure identity and the honest emulator is byte-identical to stock. Nothing in this
//! module changes any AIR / constraint: it only rewrites the *architectural result value* that
//! an instruction writes back to its destination register, at the single choke point
//! `Emu::get_value_to_store` (emu.rs). Because every witness-generation pass (minimal-trace
//! generation and all state-machine re-traversals) funnels the register write-back through that
//! one function, arming here perturbs *every* pass coherently -- the ZisK analogue of pico's
//! `on_reg_write` and nexus's `on_write_back`.
//!
//! Arming key (like the two precedents): a target program counter `pc` plus an `nth` occurrence
//! selector (`nth == u64::MAX` == every occurrence). The rewrite menu is instruction-independent.
//!
//! Env vars:
//!   ZISK_WB_ENABLE          -- presence arms the module (else pure identity)
//!   ZISK_WB_PC=0x..         -- target pc (hex or dec). If unset, matches by honest value instead.
//!   ZISK_WB_VAL=0x..        -- alternative arming: match when honest c == this value.
//!   ZISK_WB_NTH=N           -- fire only on the N-th matching occurrence (default: every, u64::MAX)
//!   ZISK_WB_TMPL=E1|E2|E3   -- mutation template family
//!   ZISK_WB_KIND=add|sub    -- E1 direction (default add)
//!   ZISK_WB_ARG=N           -- E1: byte index i (0..8) => +/- (1<<(8*i));
//!                              E2: boundary index 0=>0, 1=>2^63, 2=>2^64-1;
//!                              E3: bit index j (0..64) => XOR (1<<j)
//!   ZISK_WB_REPORT=0x..     -- report mode: print "WB_REPORT pc=.. c=.." for every instruction
//!                              whose honest write-back value equals this, then return honest value.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    pub pc: Option<u64>,
    pub val: Option<u64>,
    pub nth: u64,
    pub tmpl: u8, // 1=E1, 2=E2, 3=E3
    pub sub: bool,
    pub arg: u64,
    pub report: Option<u64>,
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn load_cfg() -> Option<Cfg> {
    if std::env::var_os("ZISK_WB_ENABLE").is_none() && std::env::var_os("ZISK_WB_REPORT").is_none() {
        return None;
    }
    let report = std::env::var("ZISK_WB_REPORT").ok().and_then(|s| parse_num(&s));
    let pc = std::env::var("ZISK_WB_PC").ok().and_then(|s| parse_num(&s));
    let val = std::env::var("ZISK_WB_VAL").ok().and_then(|s| parse_num(&s));
    let nth = std::env::var("ZISK_WB_NTH").ok().and_then(|s| parse_num(&s)).unwrap_or(u64::MAX);
    let tmpl = match std::env::var("ZISK_WB_TMPL").ok().as_deref() {
        Some("E1") => 1,
        Some("E2") => 2,
        Some("E3") => 3,
        _ => 0,
    };
    let sub = matches!(std::env::var("ZISK_WB_KIND").ok().as_deref(), Some("sub"));
    let arg = std::env::var("ZISK_WB_ARG").ok().and_then(|s| parse_num(&s)).unwrap_or(0);
    Some(Cfg { pc, val, nth, tmpl, sub, arg, report })
}

fn cfg() -> Option<&'static Cfg> {
    static CFG: OnceLock<Option<Cfg>> = OnceLock::new();
    CFG.get_or_init(load_cfg).as_ref()
}

static HITS: AtomicU64 = AtomicU64::new(0);
static OCC: AtomicU64 = AtomicU64::new(0);

/// Total number of times the perturbation actually rewrote a value (across all passes).
pub fn hits() -> u64 {
    HITS.load(Ordering::Relaxed)
}

fn apply_template(c: &Cfg, honest: u64) -> u64 {
    match c.tmpl {
        1 => {
            // ENC-E1: res +/- B^i (byte base B=256 => 1<<(8*i)); saturate i to 0..7
            let i = (c.arg % 8) as u32;
            let delta = 1u64 << (8 * i);
            if c.sub { honest.wrapping_sub(delta) } else { honest.wrapping_add(delta) }
        }
        2 => match c.arg {
            // ENC-E2: boundary values for w=64
            0 => 0u64,
            1 => 1u64 << 63,
            _ => u64::MAX,
        },
        3 => {
            // ENC-E3: res XOR 2^j
            let j = (c.arg % 64) as u32;
            honest ^ (1u64 << j)
        }
        _ => honest,
    }
}

/// The single perturbation hook, called from `Emu::get_value_to_store`.
/// `pc` is the current instruction pc; `honest` is the honest write-back value (inst_ctx.c).
/// Returns the (possibly rewritten) value. Pure identity when disarmed.
#[inline(always)]
pub fn on_write_back(pc: u64, honest: u64) -> u64 {
    let Some(c) = cfg() else { return honest };

    if let Some(r) = c.report {
        if honest == r {
            eprintln!("WB_REPORT pc=0x{pc:016x} c=0x{honest:016x}");
        }
        return honest;
    }

    let matches = match (c.pc, c.val) {
        (Some(p), _) => pc == p,
        (None, Some(v)) => honest == v,
        (None, None) => false,
    };
    if !matches {
        return honest;
    }

    // occurrence selection
    let occ = OCC.fetch_add(1, Ordering::Relaxed);
    if c.nth != u64::MAX && occ != c.nth {
        return honest;
    }

    let mutated = apply_template(c, honest);
    if mutated != honest {
        HITS.fetch_add(1, Ordering::Relaxed);
    } else {
        // Even a no-op template counts as a fire for NOOP accounting purposes only if it
        // truly changed nothing; we do NOT increment HITS so callers see hits==0 => NOOP.
    }
    mutated
}
