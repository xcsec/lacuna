# openvm v1.7.0 — volatile `initial_data` proof of concept

**This is not a LACUNA port.** It is a hand-written proof of concept, kept separate from the
seven enumeration ports for exactly that reason. It reproduces one finding on one revision;
it does not enumerate anything.

| | |
|---|---|
| upstream | https://github.com/openvm-org/openvm |
| revision | `425913bdc743ef44236daf472ec53c2c05b75fa1` (v1.7.0) |
| files patched | 2, both under `crates/vm/src/system/memory/volatile/` |
| relation to `ports/openvm/` | none — that port is the LACUNA enumeration driver on v2.0.1 |

## Why a separate revision

`VolatileBoundaryAir` sends `initial_data` on the memory bus at ts=0 with no constraint pinning
it to 0: it is a free witness column whose only appearance in `eval` is the bus send. The honest
trace generator writes `row.initial_data = 0` as a convention, not as a constraint.

`crates/vm/src/system/memory/volatile/` was **removed in v2.0.0**. The behaviour is therefore
reachable on v1.7.0 and not on v2.0.1, which is the revision `ports/openvm/` pins. That is why
this PoC lives on its own revision rather than in that port.

## Apply

```bash
git clone https://github.com/openvm-org/openvm openvm-v1.7.0
git -C openvm-v1.7.0 checkout $(cat UPSTREAM_REV)
../apply.sh openvm-v1.7.0-volatile-poc ./openvm-v1.7.0
```

## What the patch contains

`volatile/mod.rs` adds a `#[cfg(test)]` forge seam, `VOLATILE_INITIAL_DATA_FORGE`: a map from a
touched `(addr_space, pointer)` to a nonzero `initial_data` the trace generator emits instead of
0, rebalancing the LogUp memory bus against an executor made to read that same nonzero value via
`VmExe::init_memory`. It is compiled only under `cfg(test)` and is absent from production builds.

`volatile/tests.rs` adds four tests — two forges and a negative control for each:

| test | what it shows |
|---|---|
| `poc_forge_nonzero_initial_data` | single-AIR: the prover commits a nonzero value for an address the program never wrote, and the verifier accepts |
| `neg_control_mismatched_initial_data_rejected` | the same forge with a mismatched value **is** rejected — so the acceptance above is due to the missing constraint, not a broken test |
| `volatile_initial_data_GOLD` | the same result through the full VM: a real proof the real verifier accepts |
| `volatile_initial_data_gold_neg_executor_only` | negative control for the gold — perturbing the executor alone, without the matching trace-generator forge, is rejected |

The forge acts on witness generation only. The AIR, `eval`, the verifier and the verifying key
are untouched; `scripts/check_no_constraint_changes.py` covers this directory and reports it
alongside the seven ports.

## Run

```bash
cd openvm-v1.7.0
ulimit -s 262144
RUST_MIN_STACK=134217728 cargo test --release -p openvm-circuit --lib volatile:: -- --nocapture
```

Verified on v1.7.0: 7 passed, 0 failed (the four above, plus upstream's own `boundary_air_test`
and two `test_memory_write_volatile` cases).
