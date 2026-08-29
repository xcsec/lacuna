#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Boundary operand (cases `zero` / `exactdiv`).
// Structure id: st_boundary_operand   operand_source: input   candidate_class: probe
//
// Constraint surface: S17, the AIR-derived SELECTOR of the DivRem chip -- the
// is_zero guard on the divisor, the quotient/remainder range decomposition and the
// limb-carry chain.  Structurally different from Single operation: the mutation
// lands on an OPERAND, so the honest witness generator recomputes the result
// coherently and the only thing that can come loose is a flag the AIR derives by
// copy from the record.
//
// The divide is written in inline asm because a Rust `/` emits a zero-divisor branch
// and a panic path, which would self-heal the boundary step.  Honest stdin puts the
// divisor exactly one mu-step from the discontinuity (b = 1, so ENC-E2 `zero` and
// ENC-E1 minus_B0 both land on b = 0).  The same ELF is also driven with (8, 2) and
// (10, 6) for the exactly-divisible / even-divisor cases.
//
// Path to the committed public output:
//   LD of b (the perturbed write-back) -> DIVU/REMU operand -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let q: u64;
    let r: u64;
    unsafe {
        core::arch::asm!(
            "divu {q}, {a}, {b}",
            "remu {r}, {a}, {b}",
            q = out(reg) q,
            r = out(reg) r,
            a = in(reg) a,
            b = in(reg) b,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&(q ^ r).to_le_bytes());
}
