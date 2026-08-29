#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Register aliasing (variant `rdrs1rs2`).
// Structure id: st_reg_alias   operand_source: input   candidate_class: probe
//
// Constraint surface: read-before-write at ONE register address in ONE cycle.  With
// rd == rs1 == rs2 the register memory argument must order two reads and one write
// at the same address by subcycle alone; a collision or a mis-ordered subcycle makes
// the written value readable by the same instruction that produced it.
//
// Path to the committed public output:
//   the ADD producing x (perturbed) -> `add x, x, x` / `mul x, x, x` in place
//   -> XOR fold -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let mut x: u64 = core::hint::black_box(a.wrapping_add(b));
    let mut y: u64 = core::hint::black_box(a ^ b);
    unsafe {
        core::arch::asm!(
            "add {x}, {x}, {x}",
            x = inout(reg) x,
            options(pure, nomem, nostack),
        );
        core::arch::asm!(
            "mul {y}, {y}, {y}",
            y = inout(reg) y,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&(x ^ y).to_le_bytes());
}
