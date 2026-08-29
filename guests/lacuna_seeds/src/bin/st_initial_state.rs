#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: initial-state / unwritten-memory read.
// Commits a value read from a location the program never wrote.
static mut UNWRITTEN: u64 = 0;
pub fn main() {
    let _a: u64 = read_as();
    let p = &raw mut UNWRITTEN;
    unsafe {
        let x = core::ptr::read_volatile(p);
        commit_bytes(&x.to_le_bytes());
    }
}
