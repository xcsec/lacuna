# LACUNA port: zisk

| | |
|---|---|
| upstream | https://github.com/0xPolygonHermez/zisk |
| revision | `6182c8be9f4ec6baf7ee9771dd0668324f7112ed` |
| release | (main, no tag) |
| guest ISA | RV64IMA |
| proof system | PIL2 / proofman over Goldilocks |
| write-back choke point | `Emu::get_value_to_store` — `emulator/src/emu.rs:2781` |
| driver | `examples/lacuna-eval/tests/lacuna_encoding_enumeration.rs` |
| enumeration test | `lacuna_encoding_enumeration_zisk` |
| mutation modes | encoding |
| seed programs | compiled Rust guest (cargo-zisk, riscv64ima-zisk-zkvm-elf) |

## Apply

```bash
git clone https://github.com/0xPolygonHermez/zisk zisk && git -C zisk checkout 6182c8be9f4ec6baf7ee9771dd0668324f7112ed
./apply.sh zisk ./zisk
```

New files: 8. Patched tracked files: 3.

## Build

```bash
cd zisk && cargo build --release  (needs LIBCLANG_PATH for the mpi dependency)
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/zisk.csv \
  <test-binary> lacuna_encoding_enumeration_zisk --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/zisk.csv`.
