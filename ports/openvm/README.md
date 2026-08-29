# LACUNA port: openvm

| | |
|---|---|
| upstream | https://github.com/openvm-org/openvm |
| revision | `8f021b1f231469fc95de0c16b5193a004c5f21ea` |
| release | v2.0.1 |
| guest ISA | RV32IM |
| proof system | Plonky3 STARK (AIR, adapter/core split) over BabyBear |
| write-back choke point | `adapters::timed_write + Rv32JalLuiCoreRecord::rd_data` — `extensions/rv32im/circuit/src/adapters/mod.rs:123` |
| driver | `extensions/rv32im/tests/src/lacuna_eval.rs` |
| enumeration test | `lacuna_encoding_enumeration_openvm` |
| mutation modes | encoding |
| seed programs | hand-encoded RV32 words through the real transpiler |

## Revisions

This port applies to **v2.0.1** (`8f021b1f231469fc95de0c16b5193a004c5f21ea`), which is the
revision its seeds were built and run against.

openvm was also evaluated on **v1.7.0** (`425913bdc743ef44236daf472ec53c2c05b75fa1`). The two
differ in a way that matters here: `crates/vm/src/system/memory/volatile/` is present at v1.7.0
and was removed in v2.0.0, so behaviour that depends on that module is reachable on v1.7.0 and
not on the pinned revision. The patch in this directory is generated against v2.0.1 and is not
expected to apply to v1.7.0.

## Apply

```bash
git clone https://github.com/openvm-org/openvm openvm && git -C openvm checkout 8f021b1f231469fc95de0c16b5193a004c5f21ea
./apply.sh openvm ./openvm
```

New files: 3. Patched tracked files: 6.

## Build

```bash
cd openvm && cargo build --release -p openvm-rv32im-integration-tests --tests
```

## Run

The hook is additive and default-OFF: with no `LACUNA_*` variable set the tree behaves
exactly as upstream. Set `LACUNA_OUT` to a CSV path to enumerate.

```bash
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/openvm.csv \
  <test-binary> lacuna_encoding_enumeration_openvm --ignored --nocapture --test-threads 1
```

Emitted columns are the shared contract in `../../evaluation/spec/STRUCTURE_MANIFEST.yaml`;
validate a run with `python3 ../../evaluation/scripts/check_manifest.py /tmp/openvm.csv`.
