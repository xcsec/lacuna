#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Provenance chain (depth 4, through memory).
// Structure id: st_provenance_chain   operand_source: input   candidate_class: probe
//
// Constraint surface: the same operand-read side as pv_chain2, with the offline
// memory argument inserted IN SERIES: producer chip -> register bus -> store AIR ->
// memory argument -> load AIR -> register bus -> consumer chip.  Four re-binding
// hops, so the hop at which the candidate flips ACCEPT -> REJECT localises the
// binding edge much more finely than the depth-2 shape can.
//
// Path to the committed public output:
//   rd = SRLW/SRAW(a, b) (perturbed) -> SD into SLOT -> LD from SLOT
//   -> operand of ADD / MUL -> XOR fold -> commit_bytes -> FD_PUBLIC_VALUES
//   -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static mut SLOT: u64 = 0;

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let c: u64 = read_as();
    let t1: u64 = ((((a as u32) >> (b & 31)) as i32) as i64) as u64;
    let t2: u64 = (((a as i32) >> (b & 31)) as i64) as u64;
    unsafe {
        let p = &raw mut SLOT;
        core::ptr::write_volatile(p, t1);
        let u1 = core::ptr::read_volatile(p);
        core::ptr::write_volatile(p, t2);
        let u2 = core::ptr::read_volatile(p);
        let x1 = u1.wrapping_add(c);
        let x2 = u2.wrapping_mul(c);
        commit_bytes(&(x1 ^ x2).to_le_bytes());
    }
}
