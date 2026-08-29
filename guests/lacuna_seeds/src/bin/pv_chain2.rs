#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Provenance chain (depth 2, register-only).
// Structure id: st_provenance_chain   operand_source: input   candidate_class: probe
//
// Constraint surface: the operand-READ side of a chip that did NOT produce the
// value.  A forged SRLW/SRAW result must traverse the register bus and then survive
// the consumer's own operand limb decomposition and range checks, which are usually
// tighter than the producer's result binding.  The measurement is the HOP at which
// the candidate flips ACCEPT -> REJECT, which localises the binding edge; that is
// why the two consumers differ (ADD, a cheap fold, and MUL, a tight decomposition).
//
// This is the direct follow-on to pico's 24 accepted SRLW/SRAW cases and the fix for
// the structure/opcode confound: the producer arm carries the unbound set and the
// consumer arm carries the bound reference set, inside one `main`.
//
// Path to the committed public output:
//   rd = SRLW/SRAW(a, b) (perturbed) -> operand of ADD / MUL -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let c: u64 = read_as();
    let t1: u64 = core::hint::black_box(((((a as u32) >> (b & 31)) as i32) as i64) as u64);
    let t2: u64 = core::hint::black_box((((a as i32) >> (b & 31)) as i64) as u64);
    let x1 = t1.wrapping_add(c);
    let x2 = t2.wrapping_mul(c);
    commit_bytes(&(x1 ^ x2).to_le_bytes());
}
