#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Operation then state (variant `branch`).
// Structure id: st_op_then_state   operand_source: input   candidate_class: probe
//
// Constraint surface: the opcode chip AND the branch / pc-transition chip in series.
// The result of the opcode under test becomes a DECISION (sink S3): the forged value
// is consumed by a BEQ/BNE and never itself reaches the output, so an accept shows a
// value forgery escalating into control-flow control.  Needs no memory and no hook.
//
// The decision is taken on bit 0 so the smallest menu entry (ENC-E3 xor_b0) is
// already a boundary crossing.
//
// Path to the committed public output:
//   rd = OP(a, b) -> (rd & 1) -> BEQ -> one of two constants -> ADD fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
const K: [u64; 8] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x3333_3333_3333_3333,
    0x4444_4444_4444_4444,
    0x5555_5555_5555_5555,
    0x6666_6666_6666_6666,
    0x7777_7777_7777_7777,
    0x8888_8888_8888_8888,
];

#[inline(always)]
fn pick(t: u64, lo: usize) -> u64 {
    if core::hint::black_box(t) & 1 != 0 {
        core::hint::black_box(K[lo])
    } else {
        core::hint::black_box(K[lo + 1])
    }
}

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let t_add: u64 = a.wrapping_add(b);
    let t_srlw: u64 = ((((a as u32) >> (b & 31)) as i32) as i64) as u64;
    let t_sraw: u64 = (((a as i32) >> (b & 31)) as i64) as u64;
    let t_srliw: u64 = ((((a as u32) >> 7) as i32) as i64) as u64;
    let x = pick(t_add, 0)
        .wrapping_add(pick(t_srlw, 2))
        .wrapping_add(pick(t_sraw, 4))
        .wrapping_add(pick(t_srliw, 6));
    commit_bytes(&x.to_le_bytes());
}
