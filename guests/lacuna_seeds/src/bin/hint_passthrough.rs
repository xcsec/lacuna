#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Nondeterministic advice (variant `unchecked`).
// Structure id: st_hint_advice   operand_source: input   candidate_class: CALIBRATION
//
// POSITIVE CONTROL, EXPECTED VERDICT: ACCEPT.  A value that arrives on the input /
// hint channel and is committed with no in-guest check is a free column BY DESIGN,
// so an output-changing accept here is a TRUE accept and a FALSE FINDING.  It must
// be reported in a separate calibration column and never in a bug count.
//
// Its purpose is the converse.  If this does NOT accept on pico, pico's hook does
// not reach the constraint system and every REJECT pico reports is uninterpretable.
// pico is already sitting on this hazard: LACUNA_STDIN feeds every seed's operands,
// so if stdin is bound to no public value then every operand-setup perturbation is
// formally an accept-that-is-not-a-bug.  This seed is what detects that.
//
// Path to the committed public output:
//   the LD that delivers the stdin word (perturbed) -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
pub fn main() {
    let h: u64 = read_as();
    commit_bytes(&h.to_le_bytes());
}
