#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Redirect (binding-armed).
// Structure id: st_redirect   operand_source: input   candidate_class: probe
//
// ADDITIVE twin of the shipped `st_redirect` seed, which is left untouched.  The
// shipped guest stores p1 exactly ONCE, so `stale_load::on_load`'s `if v.len() < 2
// { return None }` guard never arms and the seed's BINDING mode is inert.  This
// twin writes p1 TWICE before the store to p2, which is precisely the condition the
// stale-value operator needs, so BIND-O1 (the memory-timestamp transposition) can
// actually fire on the commit-path load.
//
// Constraint surface: S6 address derivation (is addr bound to rs1+imm, or is the
// memory argument's address key free?) plus the (addr, value) pairing in the
// offline-memory argument.  SPACE disambiguation, as opposed to Store--load's TIME
// disambiguation.
//
// Address role: the mutation menu is masked (driver `MU_ALLOW`) because the
// encoding-mode site of interest is the write-back that MATERIALISES THE POINTER.
//
// Path to the committed public output:
//   ADD/AUIPC materialising p1 (perturbed) -> LD from p1 -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static mut SLOT1: u64 = 0;
static mut SLOT2: u64 = 0;

pub fn main() {
    let v1: u64 = read_as();
    let v1b: u64 = read_as();
    let v2: u64 = read_as();
    let p1 = &raw mut SLOT1;
    let p2 = &raw mut SLOT2;
    unsafe {
        core::ptr::write_volatile(p1, v1);
        core::ptr::write_volatile(p1, v1b);
        core::ptr::write_volatile(p2, v2);
        let x = core::ptr::read_volatile(p1);
        commit_bytes(&x.to_le_bytes());
    }
}
