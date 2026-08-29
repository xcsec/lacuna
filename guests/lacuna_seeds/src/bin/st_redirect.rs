#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Redirect.
//   store(a1, v1); store(a2, v2); commit(load(a1))   with a1 != a2, v1 != v2
static mut SLOT1: u64 = 0;
static mut SLOT2: u64 = 0;
pub fn main() {
    let v1: u64 = read_as();
    let v2: u64 = read_as();
    let p1 = &raw mut SLOT1;
    let p2 = &raw mut SLOT2;
    unsafe {
        core::ptr::write_volatile(p1, v1);
        core::ptr::write_volatile(p2, v2);
        let x = core::ptr::read_volatile(p1);
        commit_bytes(&x.to_le_bytes());
    }
}
