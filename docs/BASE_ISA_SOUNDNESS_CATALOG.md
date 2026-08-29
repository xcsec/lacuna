# Base-ISA soundness — 24 entries: Program / Missing constraint / Consequence

**Scope**: base RV32IM/RV64IM integer ISA (ALU, mul/div, load/store, branch/jump/shift) + memory-consistency argument.
Excludes precompile/EC/hash and the compiler layer.

**Terminology**: "missing constraint" always refers to what is missing from the **committed constraint system** (AIR / PIL / lookup / grand-product).
The executor's `assert!` and the computations in witness-gen have no binding force on a malicious prover, and do not count.

**Affected VMs**: pico (Plonky3 / KoalaBear / RV64), ceno (GKR / BabyBear / RV32, `u16limb_circuit`),
nexus (stwo AIR+LogUp / M31 / RV32), zisk (PIL2 / Goldilocks / RV64), openvm (Plonky3 / BabyBear / RV32).

---

## 1 · pico DIV/REM — remainder bound degenerates to `≤`

- **VM / instruction**: pico · `DIV/DIVU/DIVW/DIVUW/REM/REMU/REMW/REMUW`
- **Program**: guest reads in `a=8, b=2`, computes 64-bit `DIVU` `8/2` and commits the result; the true value is 4
- **Missing constraint**: `LtWordU16Gadget::eval` in `gadgets/lt_word_u16.rs:172-194` only range-checks
  `diff = a − b + bit·2^16 ∈ [0,2^16)`, and **never asserts `cols.bit == 1`**; `alu/divrem/constraints.rs:558-564`
  calls that gadget but likewise does not pin `remainder_lt_gadget.bit`. SP1 has the corresponding assertion
  `alu/divrem/mod.rs:1029-1031` `assert_eq(one, ...bit)`
- **Consequence**: the circuit only proves `|r| ≤ |c|` rather than strict `|r| < |c|`, so `(q, r)` is not unique. For any
  exactly-divisible pair, `q' = b/c − 1`, `r' = c` equally satisfy `c·q' + r' = b` with consistent signs ⇒ commit a wrong quotient (`8/2` committed as 3)

## 2 · pico SLT/SLTU — result word not bound to the comparison bit

- **VM / instruction**: pico · `SLT/SLTU`
- **Program**: guest reads in `a=5, b=3`, computes `a<b` and commits; the true value is 0
- **Missing constraint**: `alu/lt/constraints.rs:46-48` only asserts `a[1]=a[2]=a[3]=0`, and **never asserts
  `a[0] == lt_signed.result.bit`** (`a[0]` is not even constrained to be boolean). SP1 binds it through
  `Word::extend_var(...bit)` (`alu/lt/mod.rs:341`)
- **Consequence**: the destination-register write is a free witness column, and the comparison result can be flipped arbitrarily ⇒ commit `5<3 = 1`; all
  branch/selection logic built on comparison (sorting, bounds checks, balance comparisons) can be inverted

## 3 · pico SRLW/SRAW — the low 32 bits of the W-form right-shift result are unconstrained

- **VM / instruction**: pico · `SRLW/SRAW`
- **Program**: guest reads in `a=8, b=1`, computes `8 >> 1`; the true value is 4
- **Missing constraint**: at `alu/sr/constraints.rs:188` there is a literal `// TODO: constrain 32-bit operations (SRLW/SRAW)`.
  When `is_word=1`, all `a ↔ limb_result` equations are gated off by `.when(not_word)`, and only the sign-extension limbs
  `a[2], a[3]` are pinned (`:191-195`). SP1 has that constraint block (`alu/sr/mod.rs:581-601`)
- **Consequence**: the low 32 bits of the W-form right-shift result can be forged arbitrarily ⇒ commit `8>>1 = 5`, and the wrong value propagates along the
  register → store → commit chain

## 4 · pico memory address `addr_aligned` free — arbitrary address redirection

- **VM / instruction**: pico · all load/store (`LB..SD`)
- **Program**: guest places two adjacent dwords on the stack `arr = [SECRET=0x1111…, PUBLIC=0x2222…]` (both computed from the input
  as `base·0x11` / `base·0x22`, guaranteeing `0x2222…` exists only in `arr[1]`), and with runtime index `sel=1`
  performs one real `LD arr[sel]` and commits it
- **Missing constraint**: `riscv_memory/read_write/constraints.rs:224-226` uses `addr_aligned` as the address key of the offline
  memory argument, but **no constraint forces `addr_aligned == addr_word − (addr_word mod 8)`**, where
  `addr_word = rs1 + imm`; `read_write/columns.rs:40` itself carries the comment `// TODO: add constraints to fix soundness`.
  All address guards (stack-guard `:150-153`, offset binding `:196`, u16 range-check, ADD lookup) hang only on
  `addr_word`
- **Consequence**: the prover keeps `addr_word = X` (all guards pass as usual) while making the memory bus access `addr_aligned = Y`.
  Any load can return the contents of any other address, and store likewise ⇒ commit the SECRET of `arr[0]` instead of the PUBLIC of `arr[1]`;
  every memory-dependent computation is broken through

## 5 · pico right-shift amount decoupled from the bus operand

- **VM / instruction**: pico · `SRL/SRA/SRLW/SRAW`
- **Program**: guest computes `SRL(0xFF00, 4)`; the true value is `0xFF0`
- **Missing constraint**: in `alu/sr/constraints.rs` the internal shift source `c` (bound to `c_bits` via BitRange, `:82-88`)
  is **never `assert_eq`'d to the bus operand `c_for_lookup`** (`looked_alu` at `:198-207`)
- **Consequence**: the actual shift uses one quantity while the register/ALU bus reports another. The same `SRL rd, rs1, rs2` (with rs2 unchanged)
  can commit the result of an arbitrary shift amount ⇒ commit `0xFF = 0xFF00 >> 8`

## 6 · pico SLL limb selector is only one-hot

- **VM / instruction**: pico · `SLL/SLLW`
- **Program**: guest reads in `val=3, sh=5`, computes `val << sh`; the true value is 96
- **Missing constraint**: `alu/sll/constraints.rs:68-70` **only constrains `sum == 1`** on the coarse-grained limb selector `shift_u16`,
  missing the `assert_bool(shift_u16[i])` and
  `when(shift_u16[i]).assert_eq(c_bits[4] + 2·c_bits[5], i)` that the sibling chip SR has (`sr/constraints.rs:112-116`)
- **Consequence**: the prover picks any one-hot slot, and the result is shifted left by an extra 16/32/48 bits ⇒ commit `0x600000 = 3<<21`
  instead of `96 = 3<<5`

## 7 · pico data-memory access timestamp free (P-CLK) — stale / out-of-order read

- **VM / instruction**: pico · all data-memory load/store (reachable in nearly every program)
- **Program**: guest executes `sd V1; sd V2; ld a3; sd V3; commit(a3)` on the same aligned address; the honest `ld` returns V2
- **Missing constraint**: `MemoryReadWriteChip` uses its own free columns `local.clk` / `local.chunk` as the timestamp of the memory
  argument (`read_write/constraints.rs:220-222`), **never bound to the CPU clock**: `CpuChip` and
  `MemoryReadWriteChip` are two independent AIRs, and the instruction lookup between them **does not carry clk**. SP1 chains clk through
  `CPUState`'s `receive_state/send_state` (`adapter/state.rs:82-89`); pico's RV64 rewrite lost this wire
  (a whole-repo grep for `receive_state|send_state|CPUState` is empty). The register path is safe (`riscv_cpu/register` uses
  a `local.chunk` pinned to `pv.execution_chunk`), only the data-memory chip that was split out loses the binding.
  It is likewise missing at the cross-chunk level: `MemoryReadWrite.chunk` is never constrained `== execution_chunk`
- **Consequence**: the prover freely reorders the memory-access timeline — placing the `ld`'s clk between the two stores reads a **stale value**,
  while the multiset balance and the per-address monotonicity all still hold ⇒ commit stale V1 instead of V2. Both order-independent memory sums
  (per-proof `regional_cumulative_sum == 0`, `machine.rs:323`; cross-chunk
  `Σ global_cumulative_sum + vk.initial == 0`, `machine.rs:328-339`) are built on this free coordinate,
  so across chunks one can also read stale or even "future" (acausal) writes

## 8 · ceno MUL low-word carry slack → BabyBear `+p` field wraparound

- **VM / instruction**: ceno · `MUL`
- **Program**: `ADDI x2,x0,-1; ADDI x3,x0,-1; MUL x4,x2,x3; ADDI x5,x0,0; ECALL`
  (i.e. `0xFFFFFFFF × 0xFFFFFFFF`); the true value of the low word is `0x00000001`
- **Missing constraint**: `mulh_circuit_v2.rs:86` defines `carry_low[i] = (expected_limb − rd_low[i]) / 2^16` as a
  **field** expression; `rd_low` is range-checked to 16 bits, `carry_low` is range-checked to **18 bits** (`:89-99`), while
  the true upper bound is `131069 < 2^17` — about 1 bit of slack. BabyBear has `p ≈ 2^31` and `p ≡ 1 (mod 2^16)`, so when `expected_limb > p`,
  the field congruence is **not sufficient** to uniquely determine the integer decomposition
- **Consequence**: a `+p` forgery exists — the forged `rd_low` (16 bits) and `carry` (`< 2^18`) both pass the range lookup ⇒
  the register commits the wrong product `x4 = 0x87fc0000` (true value `0x1`). Under this input there are 5 distinct acceptable low words, and the output is not unique

## 9 · ceno MULH/MULHU/MULHSU high-word carry slack of the same kind

- **VM / instruction**: ceno · `MULH/MULHU/MULHSU`
- **Program**: same skeleton as above, `op = MULHU`, `0xFFFFFFFF × 0xFFFFFFFF`; the true value of the high word is `0xFFFFFFFE`
- **Missing constraint**: the high-limb equation of `mulh/mulh_circuit_v2.rs:110-139`
  `carry_high[j] = (expected − rd_high[j]) / 2^16`, where `carry_high` is still range-checked to 18 bits while the true upper bound is `< 2^17`.
  The `expected` limb for `j=0` is `0xfffe0001 > p`, hence a second legal decomposition exists
  (`rd_high0 = 0xfffd, carry_high0 = 34815`)
- **Consequence**: the high half of the product can be forged ⇒ the register commits `x4 = 0x87fffffd`

## 10 · ceno DIV/DIVU/REM/REMU division-identity carry slack

- **VM / instruction**: ceno · `DIV/DIVU/REM/REMU`
- **Program**: `ADDI x2,x0,-1; ADDI x3,x0,-8; DIVU x4,x2,x3; ADDI x5,x0,0; ECALL`
  (i.e. `DIVU(0xFFFFFFFF, 0xFFFFFFF8)`); the true quotient is 1
- **Missing constraint**: `instructions/riscv/div/div_circuit_v2.rs:125-132` expands the division identity
  `divisor·quotient + remainder = dividend` into 16-bit limbs, and each carry is checked by
  `assert_const_range(carry, 18)` (`LIMB_BITS+2`), while the true upper bound is ≤ 17 bits.
  BabyBear's `p = 30720·2^16 + 1 ≡ 1 (mod 2^16)`, so the carry limb is enough to absorb one `+p` wraparound
- **Consequence**: `divisor·(q' − q) ≡ 0 (mod p)`, so taking `q' = q + p` suffices: the remainder and the `r < divisor` lt-check
  stay honest, all AIR constraints hold, yet the wrong quotient `x4 = 0x78000002 = 1 + p` is committed (true value 1),
  and the induced carries `[245761, 30721, 0, 0]` are all `< 2^18`

## 11 · nexus MULHU/MULH high-word `MulCarry1` range slack

- **VM / instruction**: nexus (`prover` crate) · `MULHU/MULH/MULHSU`
- **Program**: `0xC386BBC4 × 0x414C343C`, take the high word and write it into `x12`; the true value is `0x31DF6991`, the honest `MulCarry1 = 1`
- **Missing constraint**: `MulCarry1` is only range8-checked to `0..=7` (`range_check/range8.rs:50`), while the honest maximum is 4
  (`column.rs:334`). The two high-half equations (`m/mulhu.rs:141-169`) make the committed high word and `MulCarry1` **move in 1:1 lockstep**
  (equation #1 contains `+MulCarry1 − ValueA[0]`, so incrementing both by 1 still holds; equation #2 is unaffected)
- **Consequence**: set `MulCarry1 = 2` and `ValueA[0]: 0x91 → 0x92`, both equations still hold ⇒ the register commits `0x31DF6992`.
  The three related buses (Range8 multiplicity, Range256 multiplicity, register/final_reg) are all prover-controlled and can be rebalanced,
  and memory consistency does **not** re-pin the output here

## 12 · nexus signed M-extension operand sign bits are free

- **VM / instruction**: nexus (`prover` crate) · `DIV/REM/MULH/MULHSU`
- **Program**: `ADDI x10,x0,10; ADDI x11,x0,3; DIV x12,x10,x11`; the true value is `rd = 3`
- **Missing constraint**: the `SgnB` / `SgnC` of `m/div_rem.rs:164/168` are only checked by `RangeBool` to be `{0,1}`,
  and are **never bound to `MSB(value_b)` / `MSB(value_c)`**; the absolute-value gadget `constrain_absolute_32_bit`
  (`m/gadget.rs`) gates by sign as `|v| = (1 − sgn)·v + sgn·(2^32 − v)`, while `ValueBAbs` / `ValueCAbs`
  only get a `Range256` byte check and are never constrained to be `< 2^31`
- **Consequence**: the quotient, remainder, multiplication witness and the signed result `ValueA` are all functions of the free sign bits. Flip `SgnB` and rebuild the whole dependency chain under the flipped
  interpretation, and all AIR constraints still hold as before ⇒ commits `rd = 0xAAAAAAAE = −1431655762` (the true value is 3).
  Sibling inconsistency inside the VM: SLT/SLTU/SRA/BLT all pin the sign to the real MSB, only the signed M-extension operations lose it

## 13 · nexus DivRem 32-bit overflow proxy is incomplete — any even divisor suffices to forge the quotient

- **VM / instruction**: nexus (`prover` crate) · `DIVU/DIV` quotient (any **even** divisor), `REMU/REM` remainder
  (even, non-power-of-two divisor)
- **Program**: `DIVU(4, 2)`, true quotient 2; remainder-version example: `REMU(10, 6)`, true remainder 4
- **Missing constraint**: `divu_remu.rs:186-192` / `div_rem.rs:347-353` only pin the **low 32-bit word** of `quotient·divisor`
  (`HelperT`); the high word is gated by the partial proxy `(q2+q3)(c2+c3) + q1·c3 + q3·c1` — that proxy only forces the
  byte products with `i+j ≥ 4` to be 0, and **omits the `i+j = 3` cross products** `q0·c3, q1·c2, q2·c1, q3·c0` (weight `2^24`, whose overflow carries into
  bit 32). The lost bit 32 lands in `MulP3Prime[1]`, which is confined to `[0,255]` by a byte lookup but is **never zeroed, nor propagated upward**
- **Consequence**: `q·c` can wrap around mod 2^32. For even `c`, `q' = q + 2^{32−v2(c)}` yields exactly the same `HelperT` and remainder ⇒
  `DIVU(4,2)` commits `Quotient = 0x80000002` (the true value is 2), and all 17 committed constraints hold over M31 with no field wraparound.
  SP1 explicitly materializes the full double-word product with its carries and rejects wrapped-around quotients; nexus's partial proxy is precisely what omits this

## 14 · nexus execution `pc` not bound to execution order — instruction reordering → fake public output

- **VM / instruction**: nexus `prover2` (Stwo/M31 machine; a different code location from the `prover` crate of entries 11–13) ·
  CPU / execution-continuity argument, affecting all instructions
- **Program**: minimal victim `P0@pc0: ADDI x1,x0,5`, `P1@pc1: ADD x2,x1,x0` (true value `x2 = 5`);
  the full version is a ~9-instruction guest that computes a value through a register hazard and stores it into the public-output region, real output 5
- **Missing constraint**: the three relations pairwise share only one coordinate, and the `(clk, pc, instr)` triangle is never closed:
  ① instruction fetch `rel_inst_to_prog_memory(pc, instr)` **carries no clk** (`execution/common/mod.rs:80-85`);
  ② in the continuity relation `rel_cont_prog_exec` each execution row only **provides** the next node `(clk+1, pc_next)` (`:87-92`),
  and **never consumes its own `(clk, pc)`**; ③ the `Cpu` trunk consumes `(clk, pc)`, where `clk` is preprocessed while `pc`
  is composed of the free witness columns `PcAux/PcNext8_15/PcHigh` (`cpu/mod.rs:73-76, 96-108, 140-150`), with no link to the registers or the fetch.
  The starting `init_pc` is pinned (preprocessed), while **the exit `FinalPc` is a free witness**
  (`cpu_boundary:89, 113, 140`)
- **Consequence**: the prover can freely decide "which instruction executes at which clk" (reorder or substitute), and all relations remain **genuine multiset
  identities**. The read/write order is flipped (read-before-write hazard) ⇒ a stale register value is committed; wire it to a store and it immediately produces a **fake
  public output** (commits `public_output = 0`, the true value is 5). This is a **loss of control-flow integrity**: for a given committed program,
  almost any fake output is provable. SP1/OpenVM/RISC0 all thread the execution timestamp through the fetch/continuity argument

## 15 · openvm volatile memory `initial_data` not constrained to 0

- **VM / instruction**: openvm (volatile-memory configuration) · the memory-consistency argument itself; any read-before-write
- **Program**: any guest that, under the volatile configuration, reads an address before writing it; the PoC commits a public value that was never written
- **Missing constraint**: in `system/memory/volatile/mod.rs`, `VolatileBoundaryCols.initial_data` is a **witness column**
  (`:51`), and `VolatileBoundaryAir::eval` (`:116-180`) only constrains booleanity of `is_valid`, the padding implication,
  the address limb range and the strict address ordering, and then executes
  `memory_bus.send(addr, [local.initial_data], timestamp = 0)` (`:164-170`) —
  **there is no `initial_data == 0`**. The honest prover hardcodes 0 (`:273`), but the verifier does not enforce it.
  By contrast: persistent memory binds the initial value into the compression + Merkle bus → the committed Merkle root (a public value)
  (`persistent.rs:102-118`)
- **Consequence**: any read of an uninitialized cell (whose `prev_timestamp = 0 < read_ts`, so the strict less-than check passes as usual) returns
  **an initial value chosen by the prover** ⇒ commits the public value `19088743` (true value 0); arbitrary data can be injected into any uninitialized memory,
  and the verifier accepts a computation built on a value that was never written

## 16 · zisk `lwu`/`lhu` out-of-window high lanes not masked by width

- **VM / instruction**: zisk · `lwu` (w=4), `lhu` (w=2) — zero-extending subword loads
- **Program**: any RV64 `lwu`/`lhu`; the PoC reads a word and honestly delivers `0x0000000044332211`
- **Missing constraint**: the prove (`[V]`) rows of `state-machines/mem/pil/mem_align.pil` reconstruct, over the **full 4-byte chunk**,
  `value[1] = reg[4] + 256·reg[5] + 65536·reg[6] + 2^24·reg[7]` (`:168-187`). The only thing binding the V-row `reg` lanes
  to the honestly read word is the R→V transition constraint `(reg[i]' − reg[i])·sel[i]·sel_up_to_down === 0` (`:116`),
  while `sel[i]` **is 1 only for the in-window lanes `[offset, offset+width)`** (`mem_align_sm.rs:151-153`);
  out-of-window lanes have **only a byte range-check** (`:114`). `width` appears in the MEMORY bus tuple (`:189`) merely as a
  matched field, and is **never used to mask `value`**. Downstream, `copyb` passes the full 64 bits to `rd` (`main.pil:396` `c[1]=b[1]`,
  with no width mask; the executor relies on the mask in `Mem::read`, which the AIR never re-imposes)
- **Consequence**: the high 32 bits of `lwu` and the high 48 bits of `lhu` can be filled with arbitrary bytes ⇒ delivering a loaded value such as
  `0x9999999944332211` that **never appeared in memory**, and thereby forging downstream computation and public output. Boundaries: `lb/lh/lw` go through
  `signextend_*`, where the out-of-window bytes are forced by the sign-extension table — safe; `lbu` (w=1) goes through the dedicated `MemAlignByte`,
  whose high bus lanes are literal 0 (`mem_align_byte.pil:96-100`) — safe; only `lhu`/`lwu` take the full_2/full_3 path

## 17 · pico `LB/LBU` high bytes lack range-check

- **VM / instruction**: pico · `LB/LBU`
- **Program**: any subword load
- **Missing constraint**: the high bytes of the load result lack a range-check, and are not constrained to the values that sign/zero extension ought to give
- **Consequence**: the high bits of a subword load result can be set to any value ⇒ committing a loaded value that does not exist in memory (isomorphic to entry 16,
  occurring at a different level)

## 18 · pico SR limb → operand `b` reconstruction missing

- **VM / instruction**: pico · the right-shift family
- **Program**: any `SRL/SRA` and their W forms
- **Missing constraint**: the right-shift chip's limb decomposition is never reconstructed back into operand `b`, i.e. there is no equality between the decomposition result and the rs1 on the bus
- **Consequence**: the shift **input** can be decoupled from the rs1 reported on the bus ⇒ committing a shift result derived from another operand
  (complementary to the shift-amount decoupling of entry 5)

## 19 · pico `DIVW/REMW` operand upper limbs not truncated

- **VM / instruction**: pico · `DIVW/REMW`
- **Program**: any W-form division/remainder
- **Missing constraint**: W-form division does not force the operands' upper limbs `b[2,3]` / `c[2,3]` to take truncated values (32-bit semantics requires them to be
  the determinate sign-extended value)
- **Consequence**: the prover performs "32-bit" division with untruncated 64-bit operands ⇒ committing an incorrect W-form quotient/remainder

## 20 · pico `JALR` target address bit-0 not cleared

- **VM / instruction**: pico · `JALR`
- **Program**: any `JALR`
- **Missing constraint**: the lowest bit of the JALR target address is not forced to zero (the ISA requires `pc = (rs1 + imm) & ~1`)
- **Consequence**: bit-0 of the target pc is free ⇒ the jump target deviates from the address prescribed by the ISA

## 21 · ceno shift operand byte-limb decomposition not unique

- **VM / instruction**: ceno · shift family
- **Program**: any `SLL/SRL/SRA`
- **Missing constraint**: the limb decomposition of the shift circuit's operands is not unique over BabyBear — same limb/carry field-wraparound class as entries 8–10;
  a 16-bit limb + the slack bound lets the `+p` wraparound of `p ≡ 1 (mod 2^16)` be absorbed
- **Consequence**: a second valid decomposition of the shift operands/result exists ⇒ commits a wrong shift result

## 22 · ceno HintsTable initialization limb missing range-check

- **VM / instruction**: ceno · initial hint memory
- **Program**: any guest that uses hint input
- **Missing constraint**: the limbs of the initial hint memory lack the `assert_ux` range-check
- **Consequence**: out-of-range / non-canonical limb values can be injected into the initial hint region, entering every subsequent computation

## 23 · zisk MemAlign `sel_prove` non-boolean

- **VM / instruction**: zisk · MemAlign state machine (sub-word / unaligned access)
- **Program**: any memory access that goes through MemAlign
- **Missing constraint**: missing `sel_prove * (sel_prove − 1) === 0`
- **Consequence**: `sel_prove` can take a field element outside `{0,1}`, thereby manipulating the value-reconstruction expression
  `value[i] === sel_prove·prove_val[i] + sel_assume·assume_val[i]`, as well as the ternary `sel` term of the MEMORY bus ⇒
  delivers an arbitrary loaded value

## 24 · zisk MemAlign `sel_prove` not bound to the committed ROM

- **VM / instruction**: zisk · MemAlign state machine
- **Program**: any memory access that goes through MemAlign
- **Missing constraint**: `sel_prove` is not bound to the semantics (width/direction) of that instruction in the committed ROM, i.e. the branch selection itself is not
  constrained by the program
- **Consequence**: the prover can itself choose whether to take the prove branch or the assume branch, decoupling the semantics of the memory access from the committed program

---

## Mechanism summary

| Mechanism | Entries | Description |
|---|---|---|
| **M1 · computed but not bound** (computed-but-unbound output) | 2, 3, 4, 5, 6, 15, 17, 18, 19, 20 | the chip computes the correct value into a pinned gadget, yet commits **another free witness column** as the architectural output; the two are never equated |
| **M2 · carry/limb bound slack → field wraparound** | 8, 9, 10, 11, 21 | the carry range is about 1 bit wider than the true upper bound; combined with BabyBear `p ≡ 1 (mod 2^16)` or range8-vs-max4 on M31, it allows a second legal decomposition with `+p` / mod-2^32 |
| **M3 · bound degenerates from `<` to `≤`** | 1 | the gadget's direction bit is never asserted, the strict inequality fails, and `(q,r)` is not unique |
| **M4 · ordering/identity coordinate is free** | 7, 14 | the ordering field of each step (memory-access timestamp / execution pc) is a free column, while the multiset argument is order-independent ⇒ the timeline can be reordered |
| **M5 · width/sign semantics not re-imposed in the circuit** | 12, 13, 16, 22, 23, 24 | the executor does masking, sign determination or overflow checks, and the AIR has no corresponding constraint (width mask, `SgnB = MSB`, full double-word product, range-check) |

**Reusable discriminator**: whether a value can be forged depends on whether **every one of its carriers** is a free prover witness column.
As long as one independent component is itself constraint-bound to the true value, the forge fails; conversely, when all carriers are free,
a single **coordinated multi-column forge + bus rebalancing** suffices to pass verification.
