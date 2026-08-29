#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Public-value plumbing (variant `words8`).
// Structure id: st_pv_plumbing   operand_source: input   candidate_class: probe
//
// Constraint surface: S14, the commit chip itself -- the index bitmap boolean and
// one-hot constraints, `word_idx == op_b`, and the per-word digest equality against
// the read register (chips/riscv_cpu/ecall/constraints.rs:148-231).  Every shipped
// seed commits ONE word and therefore touches index 0 only; this one drives all
// eight indices, so the question becomes whether EACH word is individually bound or
// only the aggregate.
//
// Path to the committed public output:
//   w[i] = (a ^ i) OP b (perturbed) -> eight commit_bytes calls -> eight WRITE
//   ecalls on FD_PUBLIC_VALUES -> guest SHA-256 over the whole stream -> eight
//   COMMIT ecalls -> the eight words of committed_value_digest.
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let mut w = [0u64; 8];
    let mut i = 0usize;
    while i < 8 {
        w[i] = (a ^ (i as u64)).wrapping_add(b);
        i += 1;
    }
    let mut j = 0usize;
    while j < 8 {
        commit_bytes(&w[j].to_le_bytes());
        j += 1;
    }
}
