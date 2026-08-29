#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Control flow.
//   if (c) x = v1; else x = v2; commit(x)
pub fn main() {
    let c: u64 = read_as();
    let v1: u64 = read_as();
    let v2: u64 = read_as();
    let x = if core::hint::black_box(c) != 0 {
        core::hint::black_box(v1)
    } else {
        core::hint::black_box(v2)
    };
    commit_bytes(&x.to_le_bytes());
}
