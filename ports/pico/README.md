# LACUNA port: pico

| | |
|---|---|
| upstream | https://github.com/brevis-network/pico |
| revision | `22b0aae6321c1f63c72aafd0b506b5f45b91ffb1` |
| release | v2.0.0 |
| guest ISA | RV64IM |
| proof system | Plonky3 STARK (AIR + LogUp) over KoalaBear |
| write-back choke point | `RiscvEmulator::rw` — `vm/src/emulator/riscv/emulator/mod.rs:1985` |
| driver | `vm/src/chips/chips/alu/lt/lacuna_eval.rs` |
| enumeration test | `lacuna_encoding_enumeration / lacuna_binding_enumeration / (structures via run_lacuna_pico.py)` |
| mutation modes | encoding + binding |
| seed programs | compiled Rust guests (pico-sdk, riscv64im-pico-zkvm-elf) |

## Apply

```bash
git clone https://github.com/brevis-network/pico pico && git -C pico checkout 22b0aae6321c1f63c72aafd0b506b5f45b91ffb1
./apply.sh pico ./pico
```

New files: 2. Patched tracked files: 8.

## Build

```bash
cd pico && cargo test --release -p pico-vm --lib --no-run
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/pico.csv \
  <test-binary> lacuna_encoding_enumeration --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/pico.csv`.
