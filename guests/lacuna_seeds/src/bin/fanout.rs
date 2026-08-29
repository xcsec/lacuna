#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Fan-out read.
// Structure id: st_fanout_read   operand_source: input   candidate_class: probe
//
// Constraint surface: whether the register BUS binds the read value, or only the
// producing chip does.  One definition is consumed by TWO chip rows at two different
// clks; in several VMs each consumption is split again across two independent column
// groups the AIR never equates.  This is the program-level way to express an L1
// per-read-point split on a port that has no witness-generation seam for it.
//
// Both uses feed the commit, so a forgery that survives at one read point and not
// the other still changes the committed output -- the asymmetry is the signal.
//
// Deconfounded: t is produced once by the bound reference opcode (ADD) and once by
// pico's established unbound opcode (SRLW), with identical downstream shape.
//
// Path to the committed public output:
//   t = OP(a, b) (perturbed) -> {ADD with K1, XOR with K2} -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
const K1: u64 = 0x0F0F_0F0F_0F0F_0F0F;
const K2: u64 = 0x00FF_00FF_00FF_00FF;

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let t_add: u64 = core::hint::black_box(a.wrapping_add(b));
    let t_srlw: u64 = core::hint::black_box(((((a as u32) >> (b & 31)) as i32) as i64) as u64);
    let u1 = t_add.wrapping_add(K1);
    let v1 = t_add ^ K2;
    let u2 = t_srlw.wrapping_add(K1);
    let v2 = t_srlw ^ K2;
    commit_bytes(&(u1 ^ v1 ^ u2 ^ v2).to_le_bytes());
}
