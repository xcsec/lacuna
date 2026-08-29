# Guest seed corpus

`lacuna_seeds/` is a single cargo package with one `[[bin]]` per concrete program strategy
(31 single-operation opcodes + 6 state-interaction structures). One `build-std` build produces
all of them.

* `lacuna_seeds/src/bin/*.rs` — the guest sources (the seed programs printed in the paper).
* `lacuna_seeds/elf/` — the built RV64 ELFs plus `MD5SUMS.txt`. These are the artifacts the
  enumeration loads via `LACUNA_ELF`. Intermediate cargo build output has been pruned.
* `srlguest/` — a recovered copy of the surviving hand-built PoC guest (`n2guest`, the SRL
  shift-amount probe); build output pruned.

Rebuild (needs the rustup toolchain `pico`, target `riscv64im-pico-zkvm-elf`):

```bash
cd lacuna_seeds
export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext=0x00200800\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort'
cargo +pico build --release --target riscv64im-pico-zkvm-elf \
      -Z build-std=alloc,core,proc_macro,panic_abort,std \
      -Z build-std-features=compiler-builtins-mem
cp target/riscv64im-pico-zkvm-elf/release/{op_*,st_*} elf/
```

The rustflags are copied verbatim from pico's own guest builder,
`sdk/cli/src/build/build.rs:89-113`.

## Wave 2 — additive structure coverage (pico)

26 further guests were added for the structures in
`evaluation/spec/STRUCTURE_MANIFEST.yaml` whose pico feasibility is `trivial` or
`moderate`.  They are built by the same single `build-std` invocation above and were
copied into `elf/` alongside the frozen ones; **no existing ELF in `elf/` was
rewritten**, and the 37 published binaries under
`target/riscv64im-pico-zkvm-elf/release/` were verified byte-identical (md5) before
and after the rebuild, so the published enumeration still runs on exactly the
artifacts it ran on.

| guest | structure id | variant | what it adds |
| --- | --- | --- | --- |
| `st_op_then_state_mem` / `_addr` / `_branch` | `st_op_then_state` | mem / addr / branch | the deconfounding shape: SRLW/SRAW/SRLIW **and** ADD inside one `main`, each feeding a state interaction |
| `bd_div`, `bd_sdiv`, `bd_shift` | `st_boundary_operand` | zero, exactdiv, intmin, shamt | raw `divu`/`div`/`sll` in inline asm, so rustc's own zero-divisor, INT_MIN/-1 and shift-mask guards do not intercept the boundary |
| `sw_lane_load`, `sw_lane_store` | `st_subword_lane` | load / store | LB/LBU/LH/LHU/LW/LWU lane extract; SB/SH/SW lane merge and sibling-lane preservation |
| `st_redirect_armed` | `st_redirect` | armed | second store to `p1`, which is what `stale_load::on_load`'s `v.len() < 2` guard needs; the shipped `st_redirect` cannot arm |
| `st_pointer_indirect` | `st_pointer_indirect` | — | a forged word that IS an address: pointer stored twice, loaded, dereferenced |
| `pv_chain2`, `pv_chain4` | `st_provenance_chain` | d2 / d4 | one value through 2 and 4 constraint surfaces |
| `lp_accum` | `st_loop_repeat` | n16 / n256 / n4096 | one static pc, N dynamic write-backs — the only seed that exercises `nth` |
| `ms_carry` | `st_multishard` | — | value produced in chunk *i*, consumed in chunk *j > i* |
| `hint_passthrough`, `hint_checked` | `st_hint_advice` | unchecked / checked | **calibration**, expected ACCEPT |
| `ij_table` | `st_indirect_jump` | table / bit0 | JALR through a two-entry function-pointer table |
| `pc_imm` | `st_pc_imm_value` | auipc+lui+jal | pc/immediate-derived words committed as DATA, never dereferenced |
| `fanout` | `st_fanout_read` | — | one definition, two uses at two clks |
| `reg_alias`, `reg_alias_rd` | `st_reg_alias` | rs1rs2 / rdrs1rs2 | same register read twice; read-and-written in one cycle |
| `pv_eight`, `pv_alias` | `st_pv_plumbing` | words8 / alias | eight committed words instead of one; the output buffer written and committed twice |
| `ee_truncate` | `st_early_exit` | — | halts before committing (score under `accepted_case_v2`, not the frozen strict predicate) |
| `fo_sink` | `st_finalize_only` | mem | **declared negative control**, excluded from coverage counts |
| `pc_sha_extend` | `st_precompile` | sha256_extend | the first LACUNA guest that instantiates a pico accelerator chip |

Rebuild is the same command; add the new binaries with

```bash
cp target/riscv64im-pico-zkvm-elf/release/{bd_*,ee_*,fanout,fo_sink,hint_*,ij_*,lp_*,ms_*,pc_*,pv_*,reg_*,st_op_then_state_*,st_pointer_indirect,st_redirect_armed,sw_*} elf/
```

The rebuild is **not** bit-reproducible for a guest whose source changed (`.rodata`
grows and the `auipc`/`jalr` pair calling `pico_sdk::io::read_vec` shifts by a page),
so never overwrite an existing `elf/` entry.

## Build paths

`Cargo.toml` depends on `pico-sdk` by relative path (`../../pico/sdk/sdk`), which assumes a pico
checkout sits alongside this artifact; adjust it to wherever you cloned pico.

The prebuilt ELFs in `elf/` carry the absolute build paths of the machine that produced them in
their debug and panic-location strings. That is cosmetic — it does not affect execution — but it
means the ELFs are not byte-reproducible on another machine. A rebuild also is not bit-identical
to these: `.rodata` grows and the `auipc`/`jalr` pair calling `pico_sdk::io::read_vec` shifts by
a page. `main()` is otherwise byte-identical and every write-back site keeps its address, so the
enumeration is unaffected — but do not overwrite `elf/` if you want to reproduce the shipped
`candidates.csv.gz` exactly.
