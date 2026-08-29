#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Precompile boundary.
// Structure id: st_precompile   operand_source: input   candidate_class: probe
//
// Constraint surface: S19 -- the syscall event, the precompile's OWN memory read and
// write records, and the CPU <-> accelerator permutation / global bus.  Roughly 30 of
// pico's 46 chips are precompiles and not one has ever been instantiated by a LACUNA
// candidate on any target, so this shape is the entire accelerator half of the
// proving configuration.
//
// The mutation site is the write-back that produces an INPUT WORD of the message
// schedule.  The forged register is stored into W by an ordinary SD, the SHA_EXTEND
// ecall (t0 = 0x00_30_01_05) reads W[0..16] through the precompile's own memory
// records and writes W[16..64] back through them, and the extended schedule is
// folded into the committed word -- so the forgery has to survive the CPU-to-chip
// bus, the precompile's read records, its round function and its write records.
//
// `syscall_sha256_extend` is the #[no_mangle] definition in pico-sdk
// (sdk/sdk/src/riscv_ecalls/sha_extend.rs); it is declared here rather than imported
// because the module is private in the SDK.
//
// Path to the committed public output:
//   AND/MUL producing a schedule word (perturbed) -> SD into W[i]
//   -> SHA_EXTEND precompile read record -> round function -> write record
//   -> LD of W[16..64] -> XOR fold -> commit_bytes -> FD_PUBLIC_VALUES
//   -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
extern "C" {
    fn syscall_sha256_extend(w: *mut [u64; 64]);
}

static mut W: [u64; 64] = [0u64; 64];

pub fn main() {
    let a: u64 = read_as();
    unsafe {
        let w = &raw mut W;
        let base = w as *mut u64;
        let mut i = 0usize;
        while i < 16 {
            let word = a.wrapping_mul(i as u64 + 1) & 0xFFFF_FFFF;
            core::ptr::write_volatile(base.add(i), word);
            i += 1;
        }
        syscall_sha256_extend(w);
        let mut acc = 0u64;
        let mut j = 16usize;
        while j < 64 {
            acc ^= core::ptr::read_volatile(base.add(j) as *const u64);
            j += 1;
        }
        commit_bytes(&acc.to_le_bytes());
    }
}
