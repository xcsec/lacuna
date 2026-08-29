#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Nondeterministic advice (variant `checked`).
// Structure id: st_hint_advice   operand_source: input   candidate_class: CALIBRATION
//
// The paired twin of hint_passthrough.  Same free input word, but the guest asserts
// a relation over it before committing (h * h == i).  This asks the real question
// behind S18: does an IN-GUEST check bind the value in the CIRCUIT, or only in the
// executor?  If the assert is compiled to a branch whose taken/not-taken edge the
// AIR constrains, a forged h must break it; if the check exists only in the
// executor, the forgery passes and the accept is a genuine soundness signal rather
// than a calibration accept.
//
// Honest stdin: h = 3, i = 9.
//
// Path to the committed public output:
//   the LD that delivers h (perturbed) -> MUL -> BNE against i -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
pub fn main() {
    let h: u64 = read_as();
    let i: u64 = read_as();
    assert!(h.wrapping_mul(h) == i);
    commit_bytes(&h.to_le_bytes());
}
