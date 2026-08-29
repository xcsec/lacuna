#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Cross-shard continuation.
// Structure id: st_multishard   operand_source: input   candidate_class: probe
//
// Constraint surface: S15, the local -> global memory bus, the chained public values
// (committed digest, pc, timestamp, previous_init / finalize address partition) and
// the SUMMED per-chunk cumulative sum.  EVERY candidate on EVERY target published so
// far is single-chunk, so pico's cross-chunk machinery has only ever been verified
// against a one-element sequence.
//
// The value is produced in chunk i and consumed in chunk j > i: the first loop fills
// a chunk, the carry is stored, a pad loop crosses the boundary, and the carry is
// loaded and committed on the far side.  The driver lowers CHUNK_SIZE /
// CHUNK_BATCH_SIZE / SPLIT_THRESHOLD (read by EmulatorOpts::default, opts.rs:47-58)
// so the store and the load straddle a real chunk boundary; N arrives on stdin so
// the same ELF can be re-sized against whatever boundary the driver sets.
//
// Path to the committed public output:
//   the loop-body write-back (perturbed) -> SD into CARRY in chunk i
//   -> memory-finalize of chunk i -> memory-initialize of chunk j -> LD from CARRY
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
static mut CARRY: u64 = 0;

pub fn main() {
    let a: u64 = read_as();
    let n: u64 = read_as();
    let mut s: u64 = 0;
    let mut i: u64 = 0;
    while core::hint::black_box(i) < n {
        s = core::hint::black_box(s).wrapping_mul(3).wrapping_add(a);
        i += 1;
    }
    unsafe {
        core::ptr::write_volatile(&raw mut CARRY, s);
    }
    let mut z: u64 = 0;
    let mut k: u64 = 0;
    while core::hint::black_box(k) < n {
        z = core::hint::black_box(z).wrapping_add(1);
        k += 1;
    }
    core::hint::black_box(z);
    unsafe {
        let x = core::ptr::read_volatile(&raw const CARRY);
        commit_bytes(&x.to_le_bytes());
    }
}
