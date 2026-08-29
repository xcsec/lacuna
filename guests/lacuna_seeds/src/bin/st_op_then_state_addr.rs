#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Operation then state (variant `addr`).
// Structure id: st_op_then_state   operand_source: input   candidate_class: probe
//
// Constraint surface: the opcode chip AND the address-formation path in series.
// The result of the opcode under test BECOMES an address (sink S2), so this is the
// shape in which a value forgery escalates into address control.  The index is
// masked to the table's 8 slots so the dereference always lands inside a mapped,
// aligned object and the candidate yields a verdict rather than an EXECFAIL.
//
// Address role: the mutation menu MUST be masked here (driver `MU_ALLOW`), because
// an unmasked +B^3 on a pointer-carrying write-back aborts the whole enumeration
// PROCESS -- a Rust allocation abort is not unwindable.
//
// Path to the committed public output:
//   rd = OP(a, b) -> (rd & 7) -> LD from TABLE[idx] -> XOR fold -> commit_bytes
//   -> FD_PUBLIC_VALUES -> guest SHA-256 -> COMMIT ecall -> committed_value_digest.
static TABLE: [u64; 8] = [
    0x0101_0101_0101_0101,
    0x0202_0202_0202_0202,
    0x0404_0404_0404_0404,
    0x0808_0808_0808_0808,
    0x1010_1010_1010_1010,
    0x2020_2020_2020_2020,
    0x4040_4040_4040_4040,
    0x8080_8080_8080_8080,
];

#[inline(always)]
unsafe fn fetch(idx: u64) -> u64 {
    core::ptr::read_volatile(TABLE.as_ptr().add((idx & 7) as usize))
}

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let t_add: u64 = a.wrapping_add(b);
    let t_srlw: u64 = ((((a as u32) >> (b & 31)) as i32) as i64) as u64;
    let t_sraw: u64 = (((a as i32) >> (b & 31)) as i64) as u64;
    let t_srliw: u64 = ((((a as u32) >> 7) as i32) as i64) as u64;
    unsafe {
        let x = fetch(t_add) ^ fetch(t_srlw) ^ fetch(t_sraw) ^ fetch(t_srliw);
        commit_bytes(&x.to_le_bytes());
    }
}
