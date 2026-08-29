# LACUNA port: risc0

| | |
|---|---|
| upstream | https://github.com/risc0/risc0 |
| revision | `10fa97888d16cebf1b924c2079d9d18b939da6d3` |
| release | (main) |
| guest ISA | RV32IM |
| proof system | zirgen generative circuit over BabyBear |
| write-back choke point | `Emulator::write_reg` — `risc0/circuit/rv32im/src/prove/preflight/emu.rs:399` |
| driver | `risc0/circuit/rv32im/src/prove/lacuna_eval.rs` |
| enumeration test | `lacuna_structure_enumeration_risc0` |
| mutation modes | encoding |
| seed programs | built-in assembler (Asm) |

## Apply

```bash
git clone https://github.com/risc0/risc0 risc0 && git -C risc0 checkout 10fa97888d16cebf1b924c2079d9d18b939da6d3
./apply.sh risc0 ./risc0
```

New files: 1. Patched tracked files: 2.

## Build

```bash
cd risc0 && cargo test --release -p risc0-circuit-rv32im --features prove --lib --no-run
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/risc0.csv \
  <test-binary> lacuna_structure_enumeration_risc0 --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/risc0.csv`.
