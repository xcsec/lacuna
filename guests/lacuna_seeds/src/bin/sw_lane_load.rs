#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Sub-word lane (variant `load`).
// Structure id: st_subword_lane   operand_source: input   candidate_class: probe
//
// Constraint surface: S7, lane selection and sign/zero extension in the load AIR.
// This is the cleanest single-landing-point shape in the catalogue: rd is a
// NARROWING of the memory word, so the lanes the load does not select lie outside
// the pinned window by construction and any lane the AIR fails to pin shows up
// directly in rd.  Every extension flavour is exercised: LBU, LB, LHU, LH, LWU, LW.
//
// Path to the committed public output:
//   SD of v -> narrow LD (the perturbed write-back) -> XOR fold -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static mut W: u64 = 0;

pub fn main() {
    let v: u64 = read_as();
    let _b: u64 = read_as();
    unsafe {
        let p = &raw mut W;
        core::ptr::write_volatile(p, v);
        let base = p as *const u8;
        let lbu = core::ptr::read_volatile(base.add(3)) as u64;
        let lb = core::ptr::read_volatile(base.add(1) as *const i8) as i64 as u64;
        let lhu = core::ptr::read_volatile(base.add(2) as *const u16) as u64;
        let lh = core::ptr::read_volatile(base.add(6) as *const i16) as i64 as u64;
        let lwu = core::ptr::read_volatile(base.add(4) as *const u32) as u64;
        let lw = core::ptr::read_volatile(base as *const i32) as i64 as u64;
        commit_bytes(&(lbu ^ lb ^ lhu ^ lh ^ lwu ^ lw).to_le_bytes());
    }
}
