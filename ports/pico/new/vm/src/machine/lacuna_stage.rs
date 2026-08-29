//! LACUNA stage-level CPU/wall accounting.
//!
//! ADDITIVE, DEFAULT-OFF instrumentation used only by the LACUNA evaluation
//! driver to split the cost of one mutation candidate into pipeline stages.
//! When `ENABLED` is false (the default) every probe is a single relaxed atomic
//! load and the timed regions run exactly as before.
//!
//! CPU time is whole-process user+system time, read from /proc/self/stat fields
//! 14 (utime) and 15 (stime).  Those counters already aggregate every thread of
//! the process, which is what we want: the prover's rayon pool is part of the
//! cost of the stage.  `getconf CLK_TCK` on this host is 100, so one tick is
//! 10 ms; see TICK_MS.
//!
//! IMPORTANT: because the CPU counter is process-wide, two timed regions that
//! overlap in wall-clock time would double-count.  The regions instrumented here
//! (in-prove emulation / trace generation / trace commitment / prove_plain) are
//! sequential for a single-chunk program, and the evaluation driver is run with
//! exactly one candidate in flight.
#![allow(dead_code)]

use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

const R: Ordering = Ordering::Relaxed;

/// USER_HZ on this host is 100 (verified with `getconf CLK_TCK`), so a tick is 10 ms.
pub const TICK_MS: u64 = 10;

/// In-prove guest emulation: perturbed-record construction + suffix replay.
pub const S1_EMUL: usize = 0;
/// Record completion + shape padding + main-trace (witness) generation.
pub const S2_GEN: usize = 1;
/// Main-trace commitment (PCS commit of the generated witness).
pub const S2_COMMIT: usize = 2;
/// prove_plain: permutation traces, quotient, FRI.
pub const S3_PROVE: usize = 3;
pub const NSTAGE: usize = 4;

static ENABLED: AtomicBool = AtomicBool::new(false);

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
static WALL_US: [AtomicU64; NSTAGE] = [ZERO; NSTAGE];
static CPU_MS: [AtomicU64; NSTAGE] = [ZERO; NSTAGE];
static ENTERS: [AtomicU64; NSTAGE] = [ZERO; NSTAGE];

pub fn set_enabled(v: bool) {
    ENABLED.store(v, R);
}
pub fn enabled() -> bool {
    ENABLED.load(R)
}
pub fn reset() {
    for i in 0..NSTAGE {
        WALL_US[i].store(0, R);
        CPU_MS[i].store(0, R);
        ENTERS[i].store(0, R);
    }
}
pub fn wall_us(i: usize) -> u64 {
    WALL_US[i].load(R)
}
pub fn cpu_ms(i: usize) -> u64 {
    CPU_MS[i].load(R)
}
pub fn enters(i: usize) -> u64 {
    ENTERS[i].load(R)
}

/// Whole-process CPU time (user + system, summed over every thread) in ms.
pub fn proc_cpu_ms() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rp = match s.rfind(')') {
        Some(i) => i,
        None => return 0,
    };
    let f: Vec<&str> = s[rp + 2..].split_whitespace().collect();
    // after "<pid> (comm) " the first token is field 3, so field N is index N-3
    let ut: u64 = f.get(11).and_then(|x| x.parse().ok()).unwrap_or(0);
    let st: u64 = f.get(12).and_then(|x| x.parse().ok()).unwrap_or(0);
    (ut + st) * TICK_MS
}

/// Records into stage `idx` on drop, so a region that unwinds is still accounted.
pub struct Guard {
    idx: usize,
    t0: Instant,
    c0: u64,
    active: bool,
}

impl Guard {
    pub fn new(idx: usize) -> Self {
        let active = idx < NSTAGE && ENABLED.load(R);
        Guard {
            idx,
            t0: Instant::now(),
            c0: if active { proc_cpu_ms() } else { 0 },
            active,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let w = self.t0.elapsed().as_micros() as u64;
        let c = proc_cpu_ms().saturating_sub(self.c0);
        WALL_US[self.idx].fetch_add(w, R);
        CPU_MS[self.idx].fetch_add(c, R);
        ENTERS[self.idx].fetch_add(1, R);
    }
}

pub fn scope<T>(idx: usize, f: impl FnOnce() -> T) -> T {
    let _g = Guard::new(idx);
    f()
}
