#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Indirect jump.
// Structure id: st_indirect_jump   operand_source: input   candidate_class: probe
//
// Constraint surface: S12, the pc transition computed from a REGISTER; the ROM /
// program-table lookup at the forged pc (is the fetch relation total, and does it
// reject a misaligned or non-instruction pc?); and the RISC-V requirement that JALR
// clears bit 0.  S13 in passing, via the link register rd = pc + 4.
//
// A two-entry jump table bounds the divergence: both targets are real code that
// returns to the same commit, so the candidate yields a verdict instead of an
// EXECFAIL.  The `bit0` question is asked by a separate SEEDS row that whitelists
// ENC-E3 xor_b0 -- the one place in the whole spec where xor_b0 is legal at an
// address-role site.
//
// Path to the committed public output:
//   the write-back carrying the function pointer (perturbed) -> JALR target
//   -> callee return value -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256
//   -> COMMIT ecall -> committed_value_digest.
#[inline(never)]
fn f() -> u64 {
    core::hint::black_box(0x1111_1111_1111_1111u64)
}

#[inline(never)]
fn g() -> u64 {
    core::hint::black_box(0x2222_2222_2222_2222u64)
}

pub fn main() {
    let sel: u64 = read_as();
    let fp: fn() -> u64 = if core::hint::black_box(sel) != 0 { f } else { g };
    let fp = core::hint::black_box(fp);
    commit_bytes(&fp().to_le_bytes());
}
