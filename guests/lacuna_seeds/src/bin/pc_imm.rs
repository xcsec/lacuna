#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: PC-immediate value.
// Structure id: st_pc_imm_value   operand_source: input   candidate_class: probe
//
// Constraint surface: S13, value derivation from the pc column and from the program
// table's immediate, with NO register operand in the relation.  It asks a question no
// other structure asks -- is rd bound to the COMMITTED PROGRAM? -- and the answer
// route is the preprocessed program / fetch bus rather than the register bus.
//
// AUIPC and LUI sites already exist inside every seed, but there they always carry a
// POINTER, so forging one traps the emulator and lands as an EXECFAIL rather than a
// verdict.  Making the pc/immediate-derived word the committed DATUM is the only way
// to get a clean verdict out of the site: nothing here is ever dereferenced.
//
// Path to the committed public output:
//   AUIPC / LUI / JAL-link write-back (perturbed) -> XOR fold -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
pub fn main() {
    let _a: u64 = read_as();
    let x: u64;
    let y: u64;
    let z: u64;
    unsafe {
        core::arch::asm!("auipc {x}, 0", x = out(reg) x, options(nomem, nostack));
        core::arch::asm!("lui {y}, 0x12345", y = out(reg) y, options(pure, nomem, nostack));
        core::arch::asm!("jal {z}, 1f", "1:", z = out(reg) z, options(nomem, nostack));
    }
    commit_bytes(&(x ^ y ^ z).to_le_bytes());
}
