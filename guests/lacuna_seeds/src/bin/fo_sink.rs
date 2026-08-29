#![no_main]
use pico_sdk::io::{commit_bytes, read_as};
pico_sdk::entrypoint!(main);

// LACUNA seed — program structure: Finalize-only write.
// Structure id: st_finalize_only   operand_source: input   candidate_class: CONTROL
//
// DECLARED NEGATIVE CONTROL on pico.  EXPECTED VERDICT: REJECT, or ACCEPT with an
// UNCHANGED output.  EXCLUDED FROM COVERAGE COUNTS.
//
// The forged value is written to a location that is never read again and the DATA
// output is a constant, so the only route from the forged value to the public output
// is the memory/register FINALISE boundary.  On openvm and risc0 that route exists
// (a final memory root is chained into the committed object); on pico NOTHING about
// final state is public -- only committed_value_digest, last_finalize_addr_limbs (an
// ADDRESS) and pc/chunk bookkeeping (emulator/riscv/public_values.rs:16,
// instances/machine/riscv.rs:562-597).  So the route does not exist here, and an
// unbound finalise write-back must NOT score as an accepted case.
//
// Its value is as a control: it is the seed that shows the driver reports REJECT /
// unchanged where the observability argument says it must.
//
// Path to the committed public output: NONE BY CONSTRUCTION.  x reaches only SINK.
static mut SINK: u64 = 0;

pub fn main() {
    let a: u64 = read_as();
    let b: u64 = read_as();
    let x: u64 = a.wrapping_add(b);
    let y: u64 = ((((a as u32) >> (b & 31)) as i32) as i64) as u64;
    unsafe {
        core::ptr::write_volatile(&raw mut SINK, x ^ y);
    }
    commit_bytes(&0x00C0_FFEEu64.to_le_bytes());
}
