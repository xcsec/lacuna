# LACUNA port: nexus

| | |
|---|---|
| upstream | https://github.com/nexus-xyz/nexus-zkvm |
| revision | `f2ad12652c39dc516a116447a53f8557f64a7f7d` |
| release | v0.3.6 |
| guest ISA | RV32IM |
| proof system | Stwo AIR + LogUp over Mersenne-31 |
| write-back choke point | `nexus_vm::trace::step` — `vm/src/trace.rs:303` |
| driver | `prover2/machine/src/lacuna_eval.rs` |
| enumeration test | `lacuna_structure_enumeration_nexus` |
| mutation modes | encoding |
| seed programs | hand-assembled RV32I ELF |

## Apply

```bash
git clone https://github.com/nexus-xyz/nexus-zkvm nexus && git -C nexus checkout f2ad12652c39dc516a116447a53f8557f64a7f7d
./apply.sh nexus ./nexus
```

New files: 1. Patched tracked files: 2.

## Dependency lock

nexus does **not** commit `Cargo.lock`, so a fresh checkout resolves against today's crates.io
and pulls dependency versions newer than the toolchain this revision pins
(`nightly-2025-05-09`, rustc 1.88.0-nightly). Building an unlocked checkout fails with
`enum-ordinalize@4.4.2 requires rustc 1.89`.

`apply.sh` therefore installs the `Cargo.lock` used for the reported runs. Do not delete or
regenerate it.

## Build

```bash
cd nexus && cargo test --release -p nexus-vm-prover2 --lib --no-run
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/nexus.csv \
  <test-binary> lacuna_structure_enumeration_nexus --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/nexus.csv`.
