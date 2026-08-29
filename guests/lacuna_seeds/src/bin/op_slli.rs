#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Single operation.
// Concrete opcode under test: SLL
//   rd = OP(rs1, rs2); commit(rd)
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let c: u64 = (a << 7) | (b & 0);
    commit_bytes(&c.to_le_bytes());
}
