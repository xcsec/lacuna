#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Public-value plumbing (variant `alias`).
// Structure id: st_pv_plumbing   operand_source: input   candidate_class: probe
//
// Constraint surface: S14 again, but with the SAME source buffer written twice and
// committed twice.  The two WRITE ecalls read the identical address range at two
// different clks, so the commit path is forced to disambiguate them in time rather
// than in space -- the memory argument on the ecall's own read side, which no other
// seed exercises.
//
// Path to the committed public output:
//   SD of x into BUF (perturbed) -> WRITE ecall reads BUF -> SD of y into BUF
//   -> second WRITE ecall reads BUF -> guest SHA-256 over the concatenated stream
//   -> COMMIT ecall -> committed_value_digest.
static mut BUF: [u8; 8] = [0u8; 8];

pub fn main() {
    let x: u64 = read_as();
    let y: u64 = read_as();
    unsafe {
        let p = &raw mut BUF as *mut u64;
        core::ptr::write_volatile(p, x);
        commit_bytes(&*(&raw const BUF));
        core::ptr::write_volatile(p, y);
        commit_bytes(&*(&raw const BUF));
    }
}
