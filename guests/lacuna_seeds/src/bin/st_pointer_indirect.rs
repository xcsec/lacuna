#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Pointer indirect.
// Structure id: st_pointer_indirect   operand_source: input   candidate_class: probe
//
// Constraint surface: the memory timestamp / address surface COMPOSED with the
// address-formation path.  The forged word is a POINTER that an honest later load
// then dereferences, so a one-word forgery becomes a whole-object substitution and
// an unbound quantity in the memory plane becomes a capability in the addressing
// plane.  Severity is bounded by what is in memory, not by what the primitive can
// write.
//
// PP is written TWICE, which is exactly the >= 2-writes condition
// `stale_load::on_load` needs, so BINDING mode arms here where the shipped
// st_redirect seed cannot.  ENCODING mode works by perturbing the write-back that
// materialises the pointer.
//
// Address role: the mutation menu is masked (driver `MU_ALLOW`) to the
// alignment-preserving entries.  +B^3 on a pointer aborts the whole enumeration
// PROCESS, because a Rust allocation abort is not unwindable.
//
// Path to the committed public output:
//   LD of PP (perturbed / staled) -> that value IS the address of the second LD
//   -> commit_bytes -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT -> digest.
//   Honest run commits vb (via &B); a stale pointer commits va (via &A).
static mut A: u64 = 0;
static mut B: u64 = 0;
static mut PP: *mut u64 = core::ptr::null_mut();

pub fn main() {
    let va: u64 = read_as();
    let vb: u64 = read_as();
    unsafe {
        core::ptr::write_volatile(&raw mut A, va);
        core::ptr::write_volatile(&raw mut B, vb);
        let pp = &raw mut PP;
        core::ptr::write_volatile(pp, &raw mut A);
        core::ptr::write_volatile(pp, &raw mut B);
        let p = core::ptr::read_volatile(pp);
        commit_bytes(&core::ptr::read_volatile(p).to_le_bytes());
    }
}
