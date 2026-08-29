#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
use pico_sdk::riscv_ecalls::syscall_halt;
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Early exit.
// Structure id: st_early_exit   operand_source: input   candidate_class: probe
//
// Constraint surface: S14', COMPLETENESS of the public-value stream.  Is the
// verifier bound to the facts that the program reached its real end and that the
// commit actually happened?  A forged condition makes the guest halt BEFORE it
// commits, so the proof carries a SHORT or EMPTY public output.
//
// SCORING PREREQUISITE, RECORDED HONESTLY: the shipped acceptance predicate
// (accepted_case_strict) requires a NON-EMPTY committed output, so a successful
// truncation can NEVER score under it.  This wave does not change the predicate --
// that is a frozen, published object.  The seed is landed and enumerated; its rows
// must be scored under accepted_case_v2 ("differs from honest, INCLUDING by being
// absent") before any conclusion is drawn from them.  Until then the cell is
// unfalsifiable by construction, not negative.
//
// Honest stdin sets c = 0, so the honest run takes the commit path.
//
// Path to the committed public output:
//   the LD delivering c (perturbed) -> BEQ -> HALT ecall taken early
//   -> FD_PUBLIC_VALUES stream never written -> empty pv_stream and a digest over
//   the empty stream.
pub fn main() {
    let c: u64 = read_as();
    if core::hint::black_box(c) != 0 {
        syscall_halt(0);
    }
    let a: u64 = read_as();
    let b: u64 = read_as();
    commit_bytes(&a.wrapping_add(b).to_le_bytes());
}
