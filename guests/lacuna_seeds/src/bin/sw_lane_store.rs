#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Sub-word lane (variant `store`).
// Structure id: st_subword_lane   operand_source: input   candidate_class: probe
//
// Constraint surface: S7 store side -- lane merge and SIBLING-LANE PRESERVATION in
// the store AIR.  A narrow store must leave the other lanes of the doubleword
// untouched; the guest reads the whole word back afterwards, so a lane the AIR lets
// float is visible in the committed value.
//
// The perturbed write-back is the register that supplies the stored byte/half/word:
// the store itself writes no register, so the mutation is applied to the value
// feeding it and the store AIR's merge is what has to bind it.
//
// Path to the committed public output:
//   LD of b (perturbed) -> SB/SH/SW into W -> LD of the whole word -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static mut W: u64 = 0;

pub fn main() {
    let v: u64 = read_as();
    let b: u64 = read_as();
    unsafe {
        let p = &raw mut W;
        core::ptr::write_volatile(p, v);
        let base = p as *mut u8;
        core::ptr::write_volatile(base.add(1), b as u8);
        core::ptr::write_volatile(base.add(2) as *mut u16, b as u16);
        core::ptr::write_volatile(base.add(4) as *mut u32, b as u32);
        commit_bytes(&core::ptr::read_volatile(p).to_le_bytes());
    }
}
