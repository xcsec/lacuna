#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Single operation.
// Concrete opcode under test: DIVUW
//   rd = OP(rs1, rs2); commit(rd)
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let c: u64 = ((((a as u32) / ((b as u32) | 1)) as i32) as i64) as u64;
    commit_bytes(&c.to_le_bytes());
}
