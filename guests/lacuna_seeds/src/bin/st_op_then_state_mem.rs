#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Operation then state (variant `mem`).
// Structure id: st_op_then_state   operand_source: input   candidate_class: probe
//
// Constraint surface: the opcode chip AND the memory chip IN SERIES, with the
// register-consistency argument as the carrier between them.  A forged write-back
// needs only ONE unbound link in the chain, so an accept here proves the forgery
// survived a re-binding hop rather than merely being emitted.
//
// Deconfounding: `main` contains BOTH the bound reference opcode (ADD) and pico's
// established unbound set (SRLW / SRAW / SRLIW), so LACUNA_OPS can vary the opcode
// while the structure is held fixed.  The five shipped state-interaction guests
// contain no W-form shift at all, which is why they could never produce a candidate
// on an unbound opcode.
//
// Path to the committed public output:
//   rd = OP(a, b)  ->  SD into SLOT  ->  LD from SLOT  ->  XOR fold  ->  commit_bytes
//   -> FD_PUBLIC_VALUES stream -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static mut SLOT: u64 = 0;

#[inline(always)]
unsafe fn round_trip(v: u64) -> u64 {
    let p = &raw mut SLOT;
    core::ptr::write_volatile(p, v);
    core::ptr::read_volatile(p)
}

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let t_add: u64 = a.wrapping_add(b);
    let t_srlw: u64 = ((((a as u32) >> (b & 31)) as i32) as i64) as u64;
    let t_sraw: u64 = (((a as i32) >> (b & 31)) as i64) as u64;
    let t_srliw: u64 = ((((a as u32) >> 7) as i32) as i64) as u64;
    unsafe {
        let x0 = round_trip(t_add);
        let x1 = round_trip(t_srlw);
        let x2 = round_trip(t_sraw);
        let x3 = round_trip(t_srliw);
        commit_bytes(&(x0 ^ x1 ^ x2 ^ x3).to_le_bytes());
    }
}
