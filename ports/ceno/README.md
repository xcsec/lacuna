# LACUNA port: ceno

| | |
|---|---|
| upstream | https://github.com/scroll-tech/ceno |
| revision | `13c5abf36a7f9aa02d9ea5f2eb5a0719ebf17f8b` |
| release | (master, no tag) |
| guest ISA | RV32IM |
| proof system | GKR / sumcheck over committed WitIns over BabyBear |
| write-back choke point | `VMState::store_register` — `ceno_emul/src/vm_state.rs:388` |
| driver | `ceno_zkvm/src/lacuna_eval.rs` |
| enumeration test | `lacuna_structure_enumeration_ceno` |
| mutation modes | encoding + order (timestamp) |
| seed programs | programmatic RV32IM Program |

## Apply

```bash
git clone https://github.com/scroll-tech/ceno ceno && git -C ceno checkout 13c5abf36a7f9aa02d9ea5f2eb5a0719ebf17f8b
./apply.sh ceno ./ceno
```

New files: 2. Patched tracked files: 4.

## Build

```bash
cd ceno && cargo test --release -p ceno_zkvm --lib --no-run
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/ceno.csv \
  <test-binary> lacuna_structure_enumeration_ceno --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/ceno.csv`.
