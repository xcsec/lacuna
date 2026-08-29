#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Boundary operand (case `shamt`).
// Structure id: st_boundary_operand   operand_source: input   candidate_class: probe
//
// Constraint surface: S17, the shift-amount decomposition and the coarse limb
// selector of the shift chips.  The shift amount is held in a REGISTER (SLL/SRL/SRA,
// never SLLI/SRLI) so the mutation reaches the decomposition rather than an
// immediate baked into the vk-committed program, and the guest applies NO `& 63`
// mask -- the shipped op_sll seed masks, which self-heals every menu entry above
// bit 5.  Honest s = 1, so minus_B0 walks it to 0 and plus_B0 upward through the
// XLEN boundary.
//
// The W-form arm (SLLW/SRLW/SRAW) is included in the same `main` so the opcode axis
// covers pico's established unbound set as well as the bound reference shifts.
//
// Path to the committed public output:
//   LD of s (the perturbed write-back) -> shift-amount operand -> XOR fold
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
pub fn main() {
    let a: u64 = read_as();
    let s: u64 = read_as();
    let x: u64;
    let y: u64;
    let z: u64;
    let xw: u64;
    let yw: u64;
    let zw: u64;
    unsafe {
        core::arch::asm!(
            "sll  {x}, {a}, {s}",
            "srl  {y}, {a}, {s}",
            "sra  {z}, {a}, {s}",
            "sllw {xw}, {a}, {s}",
            "srlw {yw}, {a}, {s}",
            "sraw {zw}, {a}, {s}",
            x = out(reg) x,
            y = out(reg) y,
            z = out(reg) z,
            xw = out(reg) xw,
            yw = out(reg) yw,
            zw = out(reg) zw,
            a = in(reg) a,
            s = in(reg) s,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&(x ^ y ^ z ^ xw ^ yw ^ zw).to_le_bytes());
}
