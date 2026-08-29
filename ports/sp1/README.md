# LACUNA port: sp1

| | |
|---|---|
| upstream | https://github.com/succinctlabs/sp1 |
| revision | `51f6efcb2971540d2ce1f48b35fd8bcf848a8b9f` |
| release | (zkvm-fuzz-work branch) |
| guest ISA | RV32IM/RV64 |
| proof system | Plonky3 STARK / hypercube over BabyBear |
| write-back choke point | `CoreVM::rw` — `crates/core/executor/src/vm.rs:1079` |
| driver | `crates/prover/src/lacuna_eval.rs` |
| enumeration test | `lacuna_encoding_enumeration_sp1` |
| mutation modes | encoding + memory-initialise |
| seed programs | programmatic Program (Vec<Instruction>) |

## Apply

```bash
git clone https://github.com/succinctlabs/sp1 sp1 && git -C sp1 checkout 51f6efcb2971540d2ce1f48b35fd8bcf848a8b9f
./apply.sh sp1 ./sp1
```

New files: 1. Patched tracked files: 5.

## Build

```bash
cd sp1 && cargo test --release -p sp1-prover --lib --no-run
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/sp1.csv \
  <test-binary> lacuna_encoding_enumeration_sp1 --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/sp1.csv`.
