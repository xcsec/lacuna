#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Boundary operand (case `intmin`).
// Structure id: st_boundary_operand   operand_source: input   candidate_class: probe
//
// Constraint surface: S17, the signed-overflow special case of the DivRem chip.
// Honest stdin is a = INT_MIN + 1, b = -1, one mu-step away from the RISC-V
// INT_MIN / -1 case whose result the AIR must special-case rather than derive from
// the ordinary quotient relation; ENC-E1 minus_B0 on the `a` write-back crosses it.
//
// Signed div/rem is written in inline asm so rustc's own INT_MIN/-1 guard branch
// does not intercept the boundary before the circuit sees it.
//
// Path to the committed public output:
//   LD of a (the perturbed write-back) -> DIV/REM operand -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let q: u64;
    let r: u64;
    unsafe {
        core::arch::asm!(
            "div {q}, {a}, {b}",
            "rem {r}, {a}, {b}",
            q = out(reg) q,
            r = out(reg) r,
            a = in(reg) a,
            b = in(reg) b,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&(q ^ r).to_le_bytes());
}
