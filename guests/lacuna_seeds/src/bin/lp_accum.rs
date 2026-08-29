#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Loop repeat.
// Structure id: st_loop_repeat   operand_source: input   candidate_class: probe
//
// Constraint surface: S16, lookup and range-check MULTIPLICITY accounting, plus the
// per-row identity question (which record entry lands on which trace row) and the
// pc/clk continuity chain.  ONE static pc executes N times, so forging the j-th of N
// identical write-backs moves one multiplicity from a bucket of count N into a new
// bucket of count 1; forging ALL N (nth = -1) moves the whole bucket.  Comparing the
// two verdicts separates per-row constraints from aggregate bus constraints.
//
// This is the only structure that exercises the `nth` component of pico's
// (pc, nth, mu) site key with a purpose-built seed, and the j-dependence of the
// divergence doubles as a consistency check that nth arming works at all.
//
// N arrives on stdin so the same ELF serves the n16 / n256 / n4096 rows.
//
// Path to the committed public output:
//   the loop-body ADD write-back (perturbed at occurrence j) -> accumulator
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let n: u64 = read_as();
    let mut s: u64 = 0;
    let mut i: u64 = 0;
    while core::hint::black_box(i) < n {
        s = core::hint::black_box(s).wrapping_add(a);
        i += 1;
    }
    commit_bytes(&s.to_le_bytes());
}
