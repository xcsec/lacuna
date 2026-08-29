// Record-layer mutation seed corpus for ZisK.
//
// Input framing: [u64 len][u64 selector][u64 a][u64 b].
// Executes exactly ONE concrete RV64 opcode `rd = OP(a, b)` (selected by `selector`) via inline
// asm so the op is a genuine machine instruction at a stable pc, then commits the 8-byte result.
// The commit is what makes the write-back mutation observable in the proof's public output.
#![no_main]
ziskos::entrypoint!(main);

macro_rules! op2 {
    ($mn:literal, $a:expr, $b:expr) => {{
        let out: u64;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {o}, {x}, {y}"),
                o = lateout(reg) out, x = in(reg) $a, y = in(reg) $b,
                options(pure, nomem, nostack),
            );
        }
        out
    }};
}

#[inline(never)]
fn dispatch(sel: u64, a: u64, b: u64) -> u64 {
    match sel {
        0 => op2!("add", a, b),
        1 => op2!("sub", a, b),
        2 => op2!("xor", a, b),
        3 => op2!("and", a, b),
        4 => op2!("or", a, b),
        5 => op2!("sll", a, b),
        6 => op2!("srl", a, b),
        7 => op2!("sra", a, b),
        8 => op2!("slt", a, b),
        9 => op2!("sltu", a, b),
        10 => op2!("mul", a, b),
        11 => op2!("mulh", a, b),
        12 => op2!("mulhu", a, b),
        13 => op2!("div", a, b),
        14 => op2!("divu", a, b),
        15 => op2!("rem", a, b),
        16 => op2!("remu", a, b),
        17 => op2!("addw", a, b),
        18 => op2!("subw", a, b),
        19 => op2!("mulw", a, b),
        _ => op2!("add", a, b),
    }
}

fn main() {
    let bytes = ziskos::io::read_input_slice();
    let rd = |i: usize| u64::from_le_bytes([
        bytes[i],bytes[i+1],bytes[i+2],bytes[i+3],bytes[i+4],bytes[i+5],bytes[i+6],bytes[i+7]]);
    let sel = rd(0);
    let a = rd(8);
    let b = rd(16);
    let out = core::hint::black_box(dispatch(sel, a, b));
    ziskos::io::commit_slice(&out.to_le_bytes());
}
