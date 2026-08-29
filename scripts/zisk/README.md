# ZisK enumeration + calibration drivers

ZisK is the one LACUNA target with **no in-process prove API**. Its driver cannot call the
prover as a library: it shells out to `ziskemu` and `cargo-zisk` and reads the verdict off
stdout. The enumeration is therefore driven from Python, not from a `#[test]`.

These four files are the drivers that **actually produced the published ZisK data**
(`data/runs/zisk_seeds/E_zisk.csv`, 42 candidates, and
`data/_raw/cpu_calibration/zisk.csv`, the per-stage CPU calibration).

| file | role | recovered from |
|---|---|---|
| `run_zisk_enumeration.py` | the record-layer write-back enumeration | `scratchpad/driver.py`, md5 `b0e60d3aff4dfdc8a3ad6f8c0aede4e0` |
| `sem.py` | RV64 reference semantics used as the oracle | `scratchpad/sem.py`, md5 `ae61108266e5b62bdf2fa651172fc1ba` |
| `run_zisk_cpu_calibration.py` | per-stage CPU/wall accounting via proofman log markers | `scratchpad/zisk_calib/calib_zisk.py`, md5 `36164bbf2fa015465e3b88d18fb271a6` |
| `analyze_zisk_calibration.py` | summarises the calibration CSV | `scratchpad/zisk_calib/analyze.py`, md5 `731b35c14e7bef0ba3683b43cbfb4009` |

## Why they are here

These are the drivers as used, vendored verbatim; the md5s above match.

## Invocation, as used for the published run

Per candidate, two child processes, strictly sequential, never overlapping:

```
# S1: mutation construction + suffix replay (write-back hook armed via ZISK_WB_*)
ziskemu -e <ELF> -i <INPUT> -c

# S2+S3+S4: tracegen, prove, verify
cargo-zisk prove -e <ELF> -i <INPUT> -a -y -l
```

Guest ELF: `zisk/examples/lacuna-seed/target/elf/riscv64ima-zisk-zkvm-elf/release/lacuna-seed`,
built with `cargo-zisk build --release`. Input framing is `[u64 len][u64 selector][u64 a][u64 b]`.

Hook env vars, all default-OFF: `ZISK_WB_ENABLE`, `ZISK_WB_PC`, `ZISK_WB_TMPL`, `ZISK_WB_KIND`,
`ZISK_WB_ARG`, plus `ZISK_WB_REPORT` for pc discovery. The hook itself is
`Emu::get_value_to_store`, `zisk/emulator/src/emu.rs:2781` -- the single callee of all five
`store_c*` variants.

**Cost warning.** One ZisK candidate costs about 5,000 CPU-seconds (~1.4 CPU-hours) and 44 s
wall on a 96-core host, because proofman proves its full state-machine set regardless of what
the guest does. Adding program structures multiplies that directly. The published run used the
CPU path only; `cargo-zisk` is built with GPU support but `-g` was never passed.

---

## Program-structure wave (added 2026-08-28)

`run_zisk_structures.py` is a **second, additive** driver.  The four files above are untouched and
their md5s still match; the published 42-candidate run is reproduced by
`run_zisk_enumeration.py` exactly as before.

| file | role |
|---|---|
| `run_zisk_structures.py` | enumerates the program structures of `evaluation/spec/STRUCTURE_MANIFEST.yaml` |
| `zisk/examples/lacuna-seed/src/bin/lacuna-struct.rs` | the guest: 29 structure arms behind selectors 100..128 |

Nothing it does can move a published number: a different guest ELF (`lacuna-struct`, not
`lacuna-seed`), a selector range that starts at 100 (the frozen guest uses 0..19), and a different
output CSV (`data/runs/zisk_structures/E_zisk_structures.csv`).  The frozen ELF was
rebuilt during this work and came out **byte-identical** (md5 `b174a183e39b50ddfe0a99c5c0a3ec38`);
a copy is parked next to it as `lacuna-seed.structbak`.

### One extra ELF, not one per structure

`TARGET_CAPABILITIES.yaml` names the ZisK seed-builder convention as one guest file per structure.
That is not affordable here -- a distinct ELF costs a fresh ~1.4 GB ROM merkleisation in
`~/.zisk/cache` -- and extending the FROZEN guest's selector would have changed the ELF behind the
published rows.  The compromise is one new binary carrying every structure behind its own
selector, with each arm a `#[no_mangle] #[inline(never)]` function named per the manifest.

### Site discovery by disassembly

The frozen driver finds its mutation pc by arming `ZISK_WB_REPORT` with the expected honest result
and hoping that value is unique in the run.  That does not generalise: `st_initial_state`'s honest
load value is `0`, and several arms have more than one interesting site.  Here a site is
`(symbol, mnemonic regex, occurrence[, after-anchor])` and is resolved with
`riscv64-unknown-elf-objdump`.  `run_zisk_structures.py sites` prints the whole table and exits
non-zero if any site fails to resolve.

```sh
python3 run_zisk_structures.py sites                    # resolve every pc, run nothing
python3 run_zisk_structures.py honest                   # honest emulation of every seed
python3 run_zisk_structures.py prove --dry-run          # emit the CSV without calling the prover
python3 run_zisk_structures.py prove --opcodes r3full   # the real, R2-compliant enumeration
```

Paths come from `ZISK_ROOT`, `LACUNA_WORK` and `LACUNA_OUT`; none is hardcoded to a scratchpad
(known issue 1 above does not apply to this file).

### One hook change, and why it was necessary

`Emu::get_value_to_store` (`emulator/src/emu.rs:2781`) is the perturbation choke point, and
`wb_perturb.rs` claims all five `store_c*` variants funnel through it.  **They did not.**  The
plain-emulation `Emu::store_c` took its `STORE_IND` value straight from `inst_ctx.c`, bypassing the
hook, while `store_c_mem_reads_generate` and `store_c_mem_reads_consume_databus` both went through
it.  `STORE_IND` is every ordinary RV64 store (base + offset), so arming a store pc perturbed
witness generation but **not** the `ziskemu` run the driver reads its output from -- the
out-of-circuit oracle would have reported `output_changed=false` for a candidate whose proof
committed a different value.  `store_c`'s `STORE_IND` arm now calls `get_value_to_store` like every
other arm.  The change is a pure identity when the hook is disarmed, and the published rows armed
register (`STORE_REG`) pcs, which were always hooked; the frozen seed reproduces its published
honest and mutated values byte for byte after the rebuild.

### Rebuilding the host binaries on this machine

`cargo build` of `ziskemu` / `cargo-zisk` currently fails in the transitive `mpi` crate: with the
system default clang (23) bindgen emits `ompi_status_public_t { _address: u8 }` and `mpi` fails on
`no field MPI_TAG`.  Building against llvm-18 works:

```sh
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
export BINDGEN_EXTRA_CLANG_ARGS="-nostdinc -I/usr/lib/llvm-18/lib/clang/18/include \
  -I/usr/include/x86_64-linux-gnu -I/usr/include"
cargo build --release -p ziskemu    --bin ziskemu
cargo build --release -p cargo-zisk --bin cargo-zisk
```

This is an environment regression, not a ZisK one.  The previous binaries are parked as
`target/release/{ziskemu,cargo-zisk}.structbak`.

### Structures deliberately not built

`NOT_BUILT` in `run_zisk_structures.py` carries the reason for each one next to the code, so a
blocked cell cannot drift away from its evidence: `st_pointer_indirect` (blocked -- witness
generation replays loads against `EmuTrace.mem_reads`, so a forged pointer does not change what the
dereference delivers), `st_finalize_only` (blocked -- the committed object is the fixed output
region), `st_early_exit` (blocked on the strict predicate's non-empty requirement),
`st_multishard` and `st_whole_program` (out of budget at ~73 s / ~5,000 CPU-s per candidate) and
`st_precompile` (not built this wave -- it needs a `ziskos` precompile call plus the ArithEq /
Keccak input plumbing, and the interesting cell sits in the `arith_eq` dispatch rather than on the
write-back path).

### `st_boundary_operand` runs against the FROZEN ELF

It needs no new guest code: the frozen single-operation guest already reads `(sel, a, b)` from its
input, so the structure is a new **input framing**, not a new program.  Those eight seeds
(`BOUNDARY_OPERANDS`) therefore carry `elf="frozen"` and `frame=24`, run
`lacuna-seed` -- byte-identical to the published artefact, read-only -- with the frozen 24-byte
frame, and land in this wave's CSV.  Their site pcs resolve to the same addresses the published
run used (`add` at `0x800001c8`), which doubles as a check that the frozen ELF really is the one
behind `E_zisk.csv`.
