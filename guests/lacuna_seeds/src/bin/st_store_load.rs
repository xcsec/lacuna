#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Store--load.
//   store(a, v1); store(a, v2); commit(load(a))
static mut SLOT: u64 = 0;
pub fn main() {
    let v1: u64 = read_as();
    let v2: u64 = read_as();
    let p = &raw mut SLOT;
    unsafe {
        core::ptr::write_volatile(p, v1);
        core::ptr::write_volatile(p, v2);
        let x = core::ptr::read_volatile(p);
        commit_bytes(&x.to_le_bytes());
    }
}
