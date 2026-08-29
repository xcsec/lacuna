#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Hazard chain.
//   x = a; x = b; commit(x)     (two register writes, then the dependent read)
pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let x: u64;
    unsafe {
        core::arch::asm!(
            "mv {x}, {a}",
            "mv {x}, {b}",
            x = out(reg) x,
            a = in(reg) a,
            b = in(reg) b,
            options(pure, nomem, nostack),
        );
    }
    commit_bytes(&x.to_le_bytes());
}
