// LACUNA program-structure corpus for ZisK -- companion to `src/main.rs`.
//
// `src/main.rs` is the FROZEN single-operation seed behind the published 42-candidate ZisK run
// (data/runs/zisk_seeds/E_zisk.csv). It is not touched: this is a second, additive
// binary that carries every *program structure* of evaluation/spec/STRUCTURE_MANIFEST.yaml that
// ZisK can express. One extra ELF, not one per structure, because a distinct ELF costs a fresh
// ~1.4 GB ROM merkleisation and a ZisK candidate already costs ~73 s wall / ~5,000 CPU-s.
//
// Input framing (little-endian), an additive extension of the frozen one:
//     [u64 payload_len][u64 sel][u64 a][u64 b]            payload_len = 24, as today
//     [u64 payload_len][u64 sel][u64 a][u64 b][u64 c]     payload_len = 32, new: `c` = arm parameter
// `sel` >= 100 selects a structure arm; 0..=19 stay reserved for the frozen main.rs selector so
// the two framings never collide. `c` defaults to 0 when the payload is 24 bytes.
//
// HOW A FORGED WRITE-BACK REACHES THE COMMITTED PUBLIC OUTPUT ON ZISK.
// The hook is `Emu::get_value_to_store` (emulator/src/emu.rs:2781), the single callee of all five
// `store_c*` variants, so it rewrites the architectural value an instruction writes back to a
// register (STORE_REG) or to memory (STORE_MEM / STORE_IND). ZisK's committed public object is the
// 256-byte output region at OUTPUT_ADDR = 0xA001_0000 (core/src/mem.rs:145), bound to the PIL
// `public inputs[64]` by the global constraint at pil/zisk.pil:146-148. Every arm below ends in
// `ziskos::io::commit_slice`, i.e. an ordinary store into that region, so a forged write-back that
// survives the constraint system shows up verbatim in the proof's public values.
//
// SITE DISCOVERY. Every arm and the opcode axis are `#[no_mangle] #[inline(never)]`, so the
// enumeration driver locates a mutation site by disassembling one named symbol and picking the
// n-th instruction matching a mnemonic, instead of guessing from a sentinel write-back value.
// See evaluation/scripts/zisk/run_zisk_structures.py, table STRUCTURES.
//
// STRUCTURAL NEGATIVES RECORDED HERE RATHER THAN WORKED AROUND.
//   * BINDING / order mode is inexpressible on ZisK: the row timestamp is a fixed column plus an
//     airval (STEP), not a record field, so no arm below has an order variant.
//   * A JAL/JALR link value is NOT reachable: `get_value_to_store` returns `pc + jmp_offset2`
//     ahead of the hook when `instruction.store_pc` is set (emu.rs:2781-2783). st_pc_imm_value's
//     `jal` variant and st_indirect_jump's link-register site are therefore out of reach.
#![no_main]
ziskos::entrypoint!(main);

use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------------------------
// mutation-site primitives
// ---------------------------------------------------------------------------------------------

/// `rd = OP(a, b)` as one genuine machine instruction at a stable pc. Pure: legal only where the
/// result is live.
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

/// `rd = OP(a, imm)`.
macro_rules! op2i {
    ($mn:literal, $a:expr, $imm:literal) => {{
        let out: u64;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {o}, {x}, ", $imm),
                o = lateout(reg) out, x = in(reg) $a,
                options(pure, nomem, nostack),
            );
        }
        out
    }};
}

/// `rd = OP(a, a)` -- rs1 == rs2 (st_reg_alias / rs1rs2).
macro_rules! op_alias_rs {
    ($mn:literal, $a:expr) => {{
        let out: u64;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {o}, {x}, {x}"),
                o = lateout(reg) out, x = in(reg) $a,
                options(pure, nomem, nostack),
            );
        }
        out
    }};
}

/// `rd = OP(rd, rd)` -- rd == rs1 == rs2, one register read twice and written in one cycle
/// (st_reg_alias / rdrs1rs2).
macro_rules! op_alias_rd {
    ($mn:literal, $a:expr) => {{
        let mut io: u64 = $a;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {o}, {o}, {o}"),
                o = inout(reg) io,
                options(pure, nomem, nostack),
            );
        }
        io
    }};
}

/// Two write-backs to ONE register with no intervening read; the second is what survives.
/// `out(reg)` (not `lateout`) so the destination can never alias an input.
macro_rules! waw_op_op {
    ($mn:literal, $a:expr, $b:expr) => {{
        let out: u64;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {t}, {x}, {y}"),
                concat!($mn, " {t}, {y}, {x}"),
                t = out(reg) out, x = in(reg) $a, y = in(reg) $b,
                options(nomem, nostack),
            );
        }
        out
    }};
}

/// Same shape, but the second write is a plain move: the first write-back is provably dead.
macro_rules! waw_op_mv {
    ($mn:literal, $a:expr, $b:expr) => {{
        let out: u64;
        unsafe {
            core::arch::asm!(
                concat!($mn, " {t}, {x}, {y}"),
                "mv {t}, {y}",
                t = out(reg) out, x = in(reg) $a, y = in(reg) $b,
                options(nomem, nostack),
            );
        }
        out
    }};
}

// ---------------------------------------------------------------------------------------------
// the opcode axis (run-matrix rules R2/R3 of STRUCTURE_MANIFEST.yaml)
// ---------------------------------------------------------------------------------------------

/// `deconfound_min` for ZisK, as one symbol so every structure can vary its opcode independently
/// of its shape (rule R1). k = 0..2 is `alu_bound_reference`; ZisK's `known_unbound_opcodes` is
/// empty, so rule R3 substitutes the full shift and M families -- k = 3..22. A driver that uses
/// k >= 3 must set `unbound_probe=substituted` in its run_tag.
///
/// Constraint surface: Binary / BinaryExtension (k <= 9) and Arith (k >= 10) state machines.
/// Site: the single ALU instruction; its write-back is `inst_ctx.c` at that pc.
#[no_mangle]
#[inline(never)]
pub extern "C" fn lacuna_ax(k: u64, x: u64, y: u64) -> u64 {
    match k {
        // alu_bound_reference
        0 => op2!("add", x, y),
        1 => op2!("xor", x, y),
        2 => op2!("and", x, y),
        // shift_family
        3 => op2!("sll", x, y),
        4 => op2!("srl", x, y),
        5 => op2!("sra", x, y),
        // shift_family_w  (rv64 only; SRLW/SRAW are the family that carries pico's 24 accepts)
        6 => op2!("sllw", x, y),
        7 => op2!("srlw", x, y),
        8 => op2!("sraw", x, y),
        9 => op2i!("srliw", x, 7),
        // m_ext
        10 => op2!("mul", x, y),
        11 => op2!("mulh", x, y),
        12 => op2!("mulhu", x, y),
        13 => op2!("mulhsu", x, y),
        14 => op2!("div", x, y),
        15 => op2!("divu", x, y),
        16 => op2!("rem", x, y),
        17 => op2!("remu", x, y),
        // m_ext_w
        18 => op2!("mulw", x, y),
        19 => op2!("divw", x, y),
        20 => op2!("divuw", x, y),
        21 => op2!("remw", x, y),
        22 => op2!("remuw", x, y),
        _ => op2!("add", x, y),
    }
}

/// `consumer_set` of the manifest: a chip with a tight operand decomposition, used as the SECOND
/// hop of st_provenance_chain and as the two readers of st_fanout_read. The question it asks is
/// whether a forged value survives someone else's operand-side range checks.
#[no_mangle]
#[inline(never)]
pub extern "C" fn lacuna_cx(k: u64, t: u64, c: u64) -> u64 {
    match k {
        0 => op2!("add", t, c),
        1 => op2!("slt", t, c),
        _ => op2!("mul", t, c),
    }
}

// ---------------------------------------------------------------------------------------------
// guest state
//
// `static mut` with a zero initialiser lands in .bss; with a non-zero initialiser in .data. Both
// live above AVAILABLE_MEM_ADDR = 0xA003_0000 (core/src/mem.rs:149). Every access below is
// volatile so LLVM cannot fold the load away and the machine instruction really exists.
// ---------------------------------------------------------------------------------------------

static mut SLOT: u64 = 0; // st_store_load, st_op_then_state/mem
static mut WIDE: u64 = 0; // st_subword_lane, the aligned dword under test

/// st_redirect's two live slots, ONE object so their distance is guaranteed by the type rather
/// than by linker ordering (the linker merges adjacent statics into `.L_MergedGlobals`).
/// The distance is exactly 2^16 bytes because that is the only alignment-preserving delta the
/// role-masked mu menu can express: `mu_menu.role_masks.address` allows plus_B1 / minus_B1 /
/// xor_b15 and nothing smaller, and ZisK's ENC-E1 uses a byte base, so +2^16 is ZISK_WB_ARG=2.
/// With the slots 2^16 apart, `plus_B1` on the pointer is an EXACT redirect from slot 0 to slot 1
/// instead of a jump into unmapped memory, i.e. a REJECT that means something rather than an
/// EXECFAIL that means nothing.
const REDIR_STRIDE_WORDS: usize = 8192; // 8192 * 8 B = 2^16 B
static mut REDIR: [u64; REDIR_STRIDE_WORDS + 1] = [0; REDIR_STRIDE_WORDS + 1];
static mut BSS_UNWRITTEN: [u64; 4] = [0; 4]; // st_initial_state/bss -- never written by the guest

/// st_initial_image/data: four words the ELF IMAGE initialises non-zero, i.e. values that the
/// vk-committed program image is supposed to pin.
static mut IMAGE_WORDS: [u64; 4] = [
    0xDEAD_BEEF_CAFE_F00D,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0x1122_3344_5566_7788,
];

/// st_initial_image/bssboundary: the guest shape of the loader-layer .data/.bss boundary golds
/// (results/LOADER_LAYER_FINDINGS.md, PIPELINE_LAYER_SOUNDNESS_CATALOG #1-#4). `tail` is a 4-byte
/// .data object at offset 8, so the aligned 8-byte word containing it straddles the end of the
/// initialised image. HONEST FRAMING: those golds are compilation-layer defects an HONEST prover
/// produces; this arm reuses their shape to ask the record-layer question they raise.
#[repr(C)]
struct ImageBoundary {
    head: u64,
    tail: u32,
}
static mut IMAGE_BOUNDARY: ImageBoundary =
    ImageBoundary { head: 0x0011_2233_4455_6677, tail: 0xDEAD_BEEF };

/// st_op_then_state/addr: eight distinct in-image words, indexed by the forged value.
static mut ADDR_TABLE: [u64; 8] = [
    0xA000_0000_0000_0000,
    0xA111_1111_1111_1111,
    0xA222_2222_2222_2222,
    0xA333_3333_3333_3333,
    0xA444_4444_4444_4444,
    0xA555_5555_5555_5555,
    0xA666_6666_6666_6666,
    0xA777_7777_7777_7777,
];

// ---------------------------------------------------------------------------------------------
// structure arms
//
// Each arm is `st_<structure_id>[_<variant>]` per STRUCTURE_MANIFEST.yaml naming, takes
// (a, b, c) from the input frame, and returns the word `main` commits. Two arms commit for
// themselves and return `None`.
// ---------------------------------------------------------------------------------------------

/// st_hint_advice / unchecked -- CALIBRATION, expected verdict ACCEPT.
/// operand_source = input, candidate_class = calibration, site_role = value.
///
/// Constraint surface S18, the boundary of "spec": ZisK delivers its whole input region through
/// `EmuTrace.mem_reads`, so this arm answers the question the manifest calls the highest
/// information per ZisK candidate -- is the input region bound to a public value at ALL? The
/// committed word is the input word `a` carried by one ADD, with nothing to re-derive it from.
/// If this REJECTS, ZisK binds its input; if it ACCEPTS, the corpus-wide oracle for ZisK must be
/// "output != spec(input)" rather than "output != honest".
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_hint_advice_unchecked(a: u64, _b: u64, _c: u64) -> u64 {
    op2!("add", a, 0u64)
}

/// st_hint_advice / checked -- CALIBRATION.
/// The paired variant: the guest itself checks `a * a == b` BEFORE the site. The check is
/// executor-only; the question is whether it binds the value in the CIRCUIT. The driver must
/// supply b = a.wrapping_mul(a) for the honest run.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_hint_advice_checked(a: u64, b: u64, _c: u64) -> u64 {
    if a.wrapping_mul(a) != b {
        panic!("st_hint_advice_checked: driver must supply b = a*a");
    }
    op2!("add", a, 0u64)
}

/// st_dead_write / overwritten -- CONTROL, expected verdict REJECT or ACCEPT-with-unchanged-output.
/// operand_source = input, candidate_class = control, site_role = value.
///
/// Constraint surface: none, deliberately. The armed site is the OP write-back, which is
/// overwritten by the following `mv` before any read, so the perturbed execution is
/// instruction-for-instruction identical to the honest one and EXECFAIL is impossible. Any REJECT
/// is attributable to the constraint system alone, which is what makes ZisK's uncontrolled 42/42
/// REJECT interpretable. Committed output is `b` either way.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_dead_write_overwritten(a: u64, b: u64, c: u64) -> u64 {
    match c % 3 {
        0 => waw_op_mv!("add", a, b),
        1 => waw_op_mv!("srlw", a, b),
        _ => waw_op_mv!("mul", a, b),
    }
}

/// st_dead_write / neverread -- CONTROL.
/// Stronger variant: the OP result is written to a register that is never read at all, and the
/// committed word is the untouched input `b`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_dead_write_neverread(a: u64, b: u64, c: u64) -> u64 {
    unsafe {
        match c % 3 {
            0 => core::arch::asm!("add {t}, {x}, {y}",
                    t = out(reg) _, x = in(reg) a, y = in(reg) b, options(nomem, nostack)),
            1 => core::arch::asm!("srlw {t}, {x}, {y}",
                    t = out(reg) _, x = in(reg) a, y = in(reg) b, options(nomem, nostack)),
            _ => core::arch::asm!("mul {t}, {x}, {y}",
                    t = out(reg) _, x = in(reg) a, y = in(reg) b, options(nomem, nostack)),
        }
    }
    black_box(b)
}

/// st_hazard_chain / first + second -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S4: two architectural writes to one register with NO intervening read, so
/// the second write's (prev_value, prev_timestamp) must equal the first write's record. The two
/// variants are the same guest arm armed at two different pcs -- `first` is the dead write (its
/// best outcome is ACCEPT-with-unchanged-output, a binding datum, never an accepted case) and
/// `second` reaches the commit directly. Operands are swapped between the two writes so a
/// non-commutative opcode gives the two sites distinguishable honest values.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_hazard_chain(a: u64, b: u64, c: u64) -> u64 {
    match c % 3 {
        0 => waw_op_op!("add", a, b),
        1 => waw_op_op!("srlw", a, b),
        _ => waw_op_op!("sub", a, b),
    }
}

/// st_store_load -- PROBE, the flagship ZisK shape.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S5, read-after-write at ONE address: does the offline-memory argument bind
/// the delivered value to the most recent write? This is the arm that moves LACUNA off ZisK's
/// registers and onto `EmuTrace.mem_reads[i]`, ZisK's primary and essentially only value-carrying
/// reachable record field. THREE distinct sites live here, and the driver enumerates them
/// separately: (1) the `lacuna_ax` write-back that produces v2, (2) the SD that stores it -- a
/// STORE_IND write-back, so the hook rewrites the value that lands in memory and therefore the
/// value the later LD records into mem_reads -- and (3) the LD's own register write-back, which
/// does NOT move mem_reads and so is the arm's built-in over-propagation reference.
/// Forged value -> SLOT -> LD -> commit_slice -> output region -> PIL publics.
/// NOTE: no order/binding variant. ZisK has no record-carried timestamp (STEP is a fixed column
/// plus an airval), so the manifest's BIND arms are structurally inexpressible here.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_store_load(a: u64, b: u64, c: u64) -> u64 {
    let v2 = lacuna_ax(c, a, b);
    unsafe {
        write_volatile(&raw mut SLOT, a); // store #1: overwritten before any read
        write_volatile(&raw mut SLOT, v2); // store #2: the live store
        read_volatile(&raw const SLOT)
    }
}

/// st_store_load / tail -- PROBE.
/// Identical, plus a trailing store that keeps the load off the finalize boundary, separating
/// surface S5 from surface S9.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_store_load_tail(a: u64, b: u64, c: u64) -> u64 {
    let v2 = lacuna_ax(c, a, b);
    unsafe {
        write_volatile(&raw mut SLOT, a);
        write_volatile(&raw mut SLOT, v2);
        let x = read_volatile(&raw const SLOT);
        write_volatile(&raw mut SLOT, b); // tail store: the load is no longer the last access
        x
    }
}

/// st_subword_lane / load -- PROBE, the highest-value ZisK seed.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S7, lane selection and extension in the load AIR. This is the direct
/// record-layer probe of the ZisK MemAlign finding (base-ISA catalog #16, LWU/LHU high lane:
/// state-machines/mem-align/src/mem_align_sm.rs:118,155 take all eight lanes of the V row from the
/// record value). `c` picks the lane and width; c = 4 is LWU at offset 4, i.e. the high lane
/// itself. The armed site is the SD that fills WIDE (its value is what MemAlign must decompose)
/// or the narrow load's own write-back; the extracted lane is committed directly.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_subword_lane_load(a: u64, _b: u64, c: u64) -> u64 {
    unsafe {
        write_volatile(&raw mut WIDE, a);
        let p = &raw const WIDE as *const u8;
        match c {
            0 => read_volatile(p.add(7)) as u64,                       // LBU, high byte
            1 => read_volatile(p.add(7) as *const i8) as i64 as u64,   // LB,  high byte, signed
            2 => read_volatile(p.add(6) as *const u16) as u64,         // LHU, high halfword
            3 => read_volatile(p.add(6) as *const i16) as i64 as u64,  // LH,  high halfword
            4 => read_volatile(p.add(4) as *const u32) as u64,         // LWU, HIGH LANE = catalog #16
            5 => read_volatile(p.add(4) as *const i32) as i64 as u64,  // LW,  high lane, signed
            6 => read_volatile(p) as u64,                              // LBU, low byte
            _ => read_volatile(p as *const u16) as u64,                // LHU, low halfword
        }
    }
}

/// st_subword_lane / store -- PROBE.
/// The mirror: a narrow store into a wide word, which additionally shows whether the UNTOUCHED
/// lanes were bound. Offsets 1 and 5 are deliberately unaligned, so the MemAlign state machine
/// (rather than the plain Mem SM) is the chip under test. The reassembled full word is committed.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_subword_lane_store(a: u64, b: u64, c: u64) -> u64 {
    unsafe {
        write_volatile(&raw mut WIDE, a);
        let p = &raw mut WIDE as *mut u8;
        match c {
            0 => write_volatile(p.add(1), b as u8),                       // SB, unaligned lane 1
            1 => write_volatile(p.add(1) as *mut u16, b as u16),          // SH, unaligned
            2 => write_volatile(p.add(4) as *mut u32, b as u32),          // SW, aligned high lane
            3 => write_volatile(p.add(1) as *mut u32, b as u32),          // SW, unaligned
            _ => write_volatile(p.add(6) as *mut u16, b as u16),          // SH, aligned high halfword
        }
        read_volatile(&raw const WIDE)
    }
}

/// st_redirect -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = address.
///
/// Constraint surface S6, address derivation: SPACE disambiguation with two live addresses, as
/// opposed to st_store_load's TIME disambiguation. The armed site is the instruction that
/// MATERIALISES THE POINTER (the ADDI after the AUIPC, forced into a register by `black_box`), so
/// the mu menu must be masked to the address role -- 8-aligned deltas on RV64. The record then
/// claims a read of slot 0 while delivering whatever the forged address holds; slot 1, exactly
/// 2^16 bytes away, is the second live address for that redirect to land on.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_redirect(a: u64, b: u64, c: u64) -> u64 {
    unsafe {
        let base = &raw mut REDIR as *mut u64;
        let p1 = black_box(base); // <-- encoding-mode site: the pointer materialisation
        let p2 = base.add(REDIR_STRIDE_WORDS); // the second live address, exactly +2^16 bytes
        write_volatile(p1, a);
        write_volatile(p1, lacuna_ax(c, a, b));
        write_volatile(p2, b);
        read_volatile(p1)
    }
}

/// st_control_flow / datadiv -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = selector.
///
/// Constraint surface S11: the armed site is the instruction PRODUCING the branch condition, so a
/// forged value changes WHICH ROWS EXIST -- the executed-instruction multiset, the step chain and
/// the per-chip row counts -- and then selects which input word is committed.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_control_flow_datadiv(a: u64, b: u64, c: u64) -> u64 {
    let cond = lacuna_ax(c, a, b);
    if black_box(cond) != 0 {
        black_box(a)
    } else {
        black_box(b)
    }
}

/// st_control_flow / dataident -- PROBE, with a ZisK-specific caveat.
/// The data-identical variant: only the trip count diverges, the committed word is fixed. On
/// targets that commit end_cycle / end_pc this reaches the public-value chain with no data word
/// moving. ZISK CAVEAT: ZisK's committed object is the fixed output REGION, not a cycle or pc
/// public, so `output_changed` is expected to be FALSE here by construction and the row is a
/// binding datum, not a candidate accepted case. Recorded rather than dropped, because the
/// asymmetry against ceno/openvm/risc0 is itself a result.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_control_flow_dataident(a: u64, b: u64, c: u64) -> u64 {
    let cond = lacuna_ax(c, a, b);
    if black_box(cond) != 0 {
        let mut i = 0u64;
        while i < 64 {
            black_box(i);
            i += 1;
        }
    }
    0x00C0_FFEE_0000_0000
}

/// st_reg_alias / rs1rs2 -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
/// Constraint surface: within-row ordering of the register argument, with the two reads collapsed
/// onto ONE address at ONE step and distinguished only by subcycle.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_reg_alias_rs1rs2(a: u64, _b: u64, c: u64) -> u64 {
    match c % 3 {
        0 => op_alias_rs!("add", a),
        1 => op_alias_rs!("srlw", a),
        _ => op_alias_rs!("mul", a),
    }
}

/// st_reg_alias / rdrs1rs2 -- PROBE.
/// The harder case: one register read TWICE and written in the same cycle.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_reg_alias_rdrs1rs2(a: u64, _b: u64, c: u64) -> u64 {
    match c % 3 {
        0 => op_alias_rd!("add", a),
        1 => op_alias_rd!("srlw", a),
        _ => op_alias_rd!("mul", a),
    }
}

/// st_pv_plumbing / words8 -- PROBE. Commits for itself.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S14, the output path itself: eight distinct words instead of one, asking
/// whether EACH output word is individually bound to the Main trace's pubout operations
/// (pil/zisk.pil:146-148) or only the aggregate. On ZisK this is also the only observable
/// finalize-style probe, because the committed object IS a fixed memory region.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_pv_plumbing_words8(a: u64, b: u64, c: u64) {
    let mut i = 0u64;
    while i < 8 {
        let w = lacuna_ax(c, a ^ i, b);
        ziskos::io::commit_slice(&w.to_le_bytes());
        i += 1;
    }
}

/// st_pv_plumbing / alias -- PROBE. Commits for itself.
/// Writes the output region twice, resetting the cursor in between, so the second commit aliases
/// the first. Asks whether the region's final contents or its whole write history is what the
/// global constraint binds.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_pv_plumbing_alias(a: u64, b: u64, c: u64) {
    let first = lacuna_ax(c, a, b);
    ziskos::io::commit_slice(&first.to_le_bytes());
    ziskos::io::write_output_reset();
    let second = lacuna_ax(c, b, a);
    ziskos::io::commit_slice(&second.to_le_bytes());
}

/// st_op_then_state / mem -- PROBE. THE DECONFOUNDING SHAPE.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// The opcode under test is not committed directly: its result first traverses a store--load round
/// trip. Together with the `c` opcode axis this is what makes STRUCTURE and OPCODE vary
/// independently (manifest rules R1-R4). The armed site stays the `lacuna_ax` write-back; an
/// ACCEPT here proves the forgery survived a re-binding hop rather than merely being emitted,
/// because the memory argument binds read == last-written and never value == correct.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_op_then_state_mem(a: u64, b: u64, c: u64) -> u64 {
    let rd = lacuna_ax(c, a, b);
    unsafe {
        write_volatile(&raw mut SLOT, rd);
        read_volatile(&raw const SLOT)
    }
}

/// st_op_then_state / addr -- PROBE.
/// The forged result BECOMES an address: it indexes an in-image table, so a value forge escalates
/// into address control (sink S2 of the taint/dataflow composition audit). Masked to 3 bits so
/// both paths stay in bounds and EXECFAIL cannot mask a REJECT.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_op_then_state_addr(a: u64, b: u64, c: u64) -> u64 {
    let rd = lacuna_ax(c, a, b);
    let idx = (black_box(rd) & 7) as usize;
    unsafe { read_volatile((&raw const ADDR_TABLE as *const u64).add(idx)) }
}

/// st_op_then_state / branch -- PROBE. The variant the manifest's ZisK cell asks for first,
/// because it needs no read-side hook.
/// The forged result BECOMES a decision (sink S3). The comparison is against zero, so the
/// E2_zero entry of the frozen mu menu flips the branch for any honest operand pair with a
/// non-zero result; the driver's sampling policy pairs each opcode with an operand pair whose
/// honest result IS zero, so the E1/E3 entries flip it too.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_op_then_state_branch(a: u64, b: u64, c: u64) -> u64 {
    let rd = lacuna_ax(c, a, b);
    if black_box(rd) == 0 {
        black_box(a)
    } else {
        black_box(b)
    }
}

/// st_provenance_chain / d2 -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Depth 2, register-only: `t = OP1(a,b)` is armed and `x = OP2(t,b)` consumes it, so the forged
/// value must traverse the register bus and then OP2's own operand-side limb decomposition and
/// range checks. The measurement is the hop at which the candidate flips ACCEPT -> REJECT.
/// `c` packs the axis: low byte = OP1 index into `lacuna_ax`, second byte = OP2 index into
/// `lacuna_cx`. Depth 4 (through memory) is deliberately NOT built: ZisK's witness generation
/// replays loads against `EmuTrace.mem_reads`, so the extra hop carries no information without a
/// read-side hook.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_provenance_chain_d2(a: u64, b: u64, c: u64) -> u64 {
    let t = lacuna_ax(c & 0xFF, a, b);
    lacuna_cx((c >> 8) & 0xFF, t, b)
}

/// st_fanout_read -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
/// One forged value read by TWO consumers with different operand decompositions; both results
/// reach the commit, so a mutation that only one consumer tolerates still shows up.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_fanout_read(a: u64, b: u64, c: u64) -> u64 {
    let t = lacuna_ax(c, a, b);
    let u = lacuna_cx(0, t, b); // ADD consumer
    let v = lacuna_cx(2, t, b); // MUL consumer
    op2!("xor", u, v)
}

/// st_loop_repeat -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S16: ONE static pc executed N times, so forging it moves lookup and
/// range-check multiplicities out of a bucket of count N. The loop is written in assembly so LLVM
/// cannot unroll it into several pcs -- the whole point is that the accumulate is one pc.
/// `c` is N (default 16). ZISK CAVEAT: `nth_supported` is false / NOT DETERMINED on ZisK
/// (ZISK_WB_NTH is present but its per-pass semantics across the multi-pass witness generation are
/// unverified), so manifest rule R5 allows only nth = -1 here: all N executions are forged.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_loop_repeat(a: u64, _b: u64, c: u64) -> u64 {
    let n = if c == 0 { 16u64 } else { c };
    let s: u64;
    unsafe {
        core::arch::asm!(
            "mv   {s}, zero",
            "mv   {i}, zero",
            "2:",
            "add  {s}, {s}, {x}",   // <-- the one static pc, executed n times
            "addi {i}, {i}, 1",
            "bltu {i}, {n}, 2b",
            s = out(reg) s, i = out(reg) _, x = in(reg) a, n = in(reg) n,
            options(nomem, nostack),
        );
    }
    s
}

/// st_initial_state / bss -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// Constraint surface S8: commit the value read from an address the program NEVER wrote -- the
/// only structure whose forged value has no producing instruction. The index is input-derived so
/// LLVM cannot constant-fold the load.
/// ZISK CAVEAT, recorded not hidden: the only site LACUNA can arm here is the LD's own REGISTER
/// write-back. ZisK re-derives the load's delivered value from `EmuTrace.mem_reads`, which this
/// hook does not touch, so a COHERENT initial-state mutation (delivered value AND the memory
/// argument moving together) needs the read-side hook the capability record marks
/// `init_value_hookable: partial`. Expect a bus imbalance; the row is still worth having as the
/// paired positive for st_initial_image below.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_initial_state_bss(a: u64, _b: u64, _c: u64) -> u64 {
    let i = (black_box(a) & 3) as usize;
    unsafe { read_volatile((&raw const BSS_UNWRITTEN as *const u64).add(i)) }
}

/// st_initial_image / data -- CONTROL, expected verdict REJECT.
/// operand_source = input, candidate_class = control, site_role = value.
///
/// The PAIRED NEGATIVE for st_initial_state: this address's initial value is NON-ZERO and comes
/// from the vk-committed program image, so it is supposed to be pinned. An ACCEPT here is NOT a
/// control failure -- it would mean the prover can claim an initial value the vk does not commit,
/// and must be re-graded as a probe-grade finding. Running only the .bss arm cannot tell "this VM
/// leaves initial memory free" from "this VM leaves UNCOVERED initial memory free".
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_initial_image_data(a: u64, _b: u64, _c: u64) -> u64 {
    let i = (black_box(a) & 3) as usize;
    unsafe { read_volatile((&raw const IMAGE_WORDS as *const u64).add(i)) }
}

/// st_initial_image / bssboundary -- CONTROL.
/// Reads the aligned 8-byte word that straddles the end of the initialised image: the low half is
/// `IMAGE_BOUNDARY.tail` (.data, 0xDEADBEEF) and the high half is whatever the loader put after
/// it. This is the record-layer question raised by the loader-layer golds -- ZisK's own T-1
/// (elf_extraction trims PROGBITS to a multiple of 4/8 and drops the trailing rodata), plus SP1
/// L-1, Pico L-1 and Nexus N-1.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_initial_image_bssboundary(_a: u64, _b: u64, _c: u64) -> u64 {
    unsafe {
        let tail = &raw const IMAGE_BOUNDARY.tail as *const u32 as usize;
        read_volatile((tail & !7usize) as *const u64)
    }
}

/// st_pc_imm_value / auipc -- PROBE.
/// operand_source = immediate, candidate_class = probe, site_role = value.
///
/// The write-back carries a pc-derived immediate the ZisK transform layer resolves at ROM build
/// time, so the question is whether the AIR re-derives it from the row's own pc or copies it from
/// the record. NOTE the structural limit: `get_value_to_store` returns `pc + jmp_offset2` BEFORE
/// the hook when `instruction.store_pc` is set, so the `jal` variant of this structure is
/// unreachable on ZisK and is not built.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_pc_imm_value_auipc(_a: u64, _b: u64, _c: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!("auipc {o}, 0", o = out(reg) out, options(nomem, nostack));
    }
    out
}

/// st_pc_imm_value / lui -- PROBE.
/// operand_source = immediate, candidate_class = probe, site_role = value.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_pc_imm_value_lui(_a: u64, _b: u64, _c: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!("lui {o}, 0x12345", o = out(reg) out, options(nomem, nostack));
    }
    out
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn lacuna_ij_f() -> u64 {
    0x1111_1111_1111_1111
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn lacuna_ij_g() -> u64 {
    0x2222_2222_2222_2222
}

/// st_indirect_jump / table -- PROBE.
/// operand_source = input, candidate_class = probe, site_role = address.
///
/// Constraint surface S12: a two-entry jump table so BOTH targets are real code and the divergence
/// is bounded. The armed site is the write-back carrying the JALR target. ZisK expectation: the
/// ROM lookup is total and keyed by pc, so the fetch relation is likely to bind the target; the
/// link value rd = pc+4 is out of reach for the reason given at the top of this file, so the
/// `bit0` variant's second question cannot be asked here.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_indirect_jump_table(a: u64, _b: u64, _c: u64) -> u64 {
    let fp: extern "C" fn() -> u64 = if black_box(a) != 0 { lacuna_ij_f } else { lacuna_ij_g };
    black_box(fp)()
}

/// st_x0_dark_write -- PROBE, and the resolution of an OPEN QUESTION.
/// operand_source = input, candidate_class = probe, site_role = value.
///
/// `x0_hookable` is `not_determined` for ZisK in TARGET_CAPABILITIES.yaml: the
/// feasibility matrix has no cell for it. This arm settles it by construction. `add x0, a, b`
/// followed by a read of x0: if the ZisK transpiler maps rd == x0 to STORE_NONE the hook never
/// fires and the answer is "not expressible" (a NOOP row, which is the honest negative); if it
/// maps it to STORE_REG the hook fires and the question becomes whether the register argument
/// forces x0 == 0. Honest committed value is 0 either way.
#[no_mangle]
#[inline(never)]
pub extern "C" fn st_x0_dark_write(a: u64, b: u64, _c: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "add x0, {x}, {y}",
            "mv  {o}, x0",
            o = out(reg) out, x = in(reg) a, y = in(reg) b,
            options(nomem, nostack),
        );
    }
    out
}

// ---------------------------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------------------------

/// Returns `None` when the arm has already committed for itself.
#[inline(never)]
fn dispatch(sel: u64, a: u64, b: u64, c: u64) -> Option<u64> {
    match sel {
        100 => Some(st_hint_advice_unchecked(a, b, c)),
        101 => Some(st_hint_advice_checked(a, b, c)),
        102 => Some(st_dead_write_overwritten(a, b, c)),
        103 => Some(st_dead_write_neverread(a, b, c)),
        104 => Some(st_hazard_chain(a, b, c)),
        105 => Some(st_store_load(a, b, c)),
        106 => Some(st_store_load_tail(a, b, c)),
        107 => Some(st_subword_lane_load(a, b, c)),
        108 => Some(st_subword_lane_store(a, b, c)),
        109 => Some(st_redirect(a, b, c)),
        110 => Some(st_control_flow_datadiv(a, b, c)),
        111 => Some(st_control_flow_dataident(a, b, c)),
        112 => Some(st_reg_alias_rs1rs2(a, b, c)),
        113 => Some(st_reg_alias_rdrs1rs2(a, b, c)),
        114 => {
            st_pv_plumbing_words8(a, b, c);
            None
        }
        115 => {
            st_pv_plumbing_alias(a, b, c);
            None
        }
        116 => Some(st_op_then_state_mem(a, b, c)),
        117 => Some(st_op_then_state_addr(a, b, c)),
        118 => Some(st_op_then_state_branch(a, b, c)),
        119 => Some(st_provenance_chain_d2(a, b, c)),
        120 => Some(st_fanout_read(a, b, c)),
        121 => Some(st_loop_repeat(a, b, c)),
        122 => Some(st_initial_state_bss(a, b, c)),
        123 => Some(st_initial_image_data(a, b, c)),
        124 => Some(st_initial_image_bssboundary(a, b, c)),
        125 => Some(st_pc_imm_value_auipc(a, b, c)),
        126 => Some(st_pc_imm_value_lui(a, b, c)),
        127 => Some(st_indirect_jump_table(a, b, c)),
        128 => Some(st_x0_dark_write(a, b, c)),
        // Unknown selector: commit a fixed marker so a mis-framed input is visible in the output
        // rather than silently scoring as an unchanged commit.
        _ => Some(0xBAD5_E1EC_0000_0000 | (sel & 0xFFFF_FFFF)),
    }
}

fn main() {
    let bytes = ziskos::io::read_input_slice();
    let rd = |i: usize| {
        u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ])
    };
    let sel = rd(0);
    let a = rd(8);
    let b = rd(16);
    let c = if bytes.len() >= 32 { rd(24) } else { 0 };
    if let Some(out) = dispatch(sel, a, b, c) {
        ziskos::io::commit_slice(&core::hint::black_box(out).to_le_bytes());
    }
}
