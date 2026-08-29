#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Register aliasing (variant `rs1rs2`).
// Structure id: st_reg_alias   operand_source: input   candidate_class: probe
//
// Constraint surface: within-row ordering of the register memory argument when the
// SAME register is read twice in one cycle.  The two reads are distinguished only by
// subcycle, and the second read is usually deduplicated; a VM that folds them must
// still bind both operand column groups to the same value.
//
// `OP rd, rs1, rs1` for a bound reference opcode (ADD) and for the tight-
// decomposition opcode (MUL), plus the W-form arm so the unbound set is covered.
//
// Path to the committed public output:
//   the ADD producing x (perturbed) -> read twice as rs1 == rs2 -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let x: u64 = core::hint::black_box(a.wrapping_add(b));
    let p: u64;
    let q: u64;
    let w: u64;
    unsafe {
        core::arch::asm!(
            "mul  {p}, {x}, {x}",
            "add  {q}, {x}, {x}",
            "mulw {w}, {x}, {x}",
            p = out(reg) p,
            q = out(reg) q,
            w = out(reg) w,
            x = in(reg) x,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&(p ^ q ^ w).to_le_bytes());
}
