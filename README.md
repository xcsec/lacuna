# LACUNA

Record-layer write-back mutation testing for zkVM constraint systems, ported to seven
production zkVMs.

LACUNA hooks each zkVM's single architectural **write-back choke point**, replaces the value
written at the k-th execution of a static pc with `μ(v)` from a fixed instruction-independent
menu, lets the honest executor continue and the zkVM's own witness generator recompute
everything downstream, then runs the **real prover and the real verifier** unmodified.

The instrumentation is additive and default-off, and touches only executor and
witness-generation code. **No committed constraint system, AIR or PIL file is modified in any of
the seven targets** — re-derive that claim yourself with
`python3 scripts/check_no_constraint_changes.py`.

## Targets

| zkVM | pinned revision | guest ISA | enumeration test |
|---|---|---|---|
| pico | `22b0aae6` v2.0.0 | RV64IM | `lacuna_encoding_enumeration`, `lacuna_binding_enumeration` |
| ceno | `13c5abf3` | RV32IM | `lacuna_structure_enumeration_ceno` |
| nexus | `f2ad1265` v0.3.6 | RV32I | `lacuna_structure_enumeration_nexus` |
| zisk | `6182c8be` | RV64IMA | `lacuna_encoding_enumeration_zisk` |
| openvm | `8f021b1f` v2.0.1 | RV32IM | `lacuna_encoding_enumeration_openvm` |
| risc0 | `10fa9788` | RV32IM | `lacuna_structure_enumeration_risc0` |
| sp1 | `51f6efcb` | RV32IM/RV64 | `lacuna_encoding_enumeration_sp1` |

`crates/vm/src/system/memory/volatile/` was removed in openvm v2.0.0, so behaviour tied to it is
reachable on v1.7.0 and not on the pinned v2.0.1. `ports/openvm-v1.7.0-volatile-poc/` carries a
hand-written proof of concept for it on v1.7.0 (`425913bd`), kept separate from the seven
enumeration ports; see its README.

## Layout

```
ports/          one directory per zkVM, plus apply.sh and one stand-alone proof of concept
  <vm>/
    UPSTREAM_REV    the upstream commit this port is pinned to
    new/            files LACUNA adds to that tree
    vendor.patch    the diff against upstream tracked files
    README.md       that port's choke point, build command and run command
spec/           STRUCTURE_MANIFEST.yaml, TARGET_CAPABILITIES.yaml — the shared, target-independent
                contract every port's output is checked against
scripts/        enumeration drivers and the two validators
guests/         pico guest seed programs (sources and built ELFs)
data/           the seed corpus and the zkVM metadata
docs/           the base-ISA soundness catalog
```

## Running a port

Three steps. `nexus` is the cheapest target and is the recommended first run.

```bash
# 1. get upstream at the pinned revision and apply the port
git clone https://github.com/nexus-xyz/nexus-zkvm nexus
git -C nexus checkout $(cat ports/nexus/UPSTREAM_REV)
./ports/apply.sh nexus ./nexus

# 2. build
cd nexus && cargo test --release -p nexus-vm-prover2 --lib --no-run

# 3. enumerate
LACUNA_TAG=demo LACUNA_MU=all LACUNA_OUT=/tmp/nexus.csv \
  ./target/release/deps/nexus_vm_prover2-<hash> \
  lacuna_structure_enumeration_nexus --ignored --nocapture --test-threads 1
```

With no `LACUNA_*` variable set the tree behaves exactly as upstream. `LACUNA_OUT` names the
output CSV, `LACUNA_MU=all` runs the whole mutation menu, and `LACUNA_TAG` labels the run.

Each `ports/<vm>/README.md` gives that target's build command, test name and required
environment (several targets need a raised stack or a capped thread pool).

## Validating a run

```bash
python3 scripts/check_manifest.py /tmp/nexus.csv        # output conforms to the shared contract
python3 scripts/check_no_constraint_changes.py          # no port modifies a constraint system
```

## Data

`data/seeds.csv` is the seed corpus — 145 seed programs across the seven targets, with each
seed's structure, opcode, input and static shape. `data/targets.csv` pins each zkVM's upstream
revision, guest ISA and proof system. `data/README.md` describes the columns.

## Findings

`docs/BASE_ISA_SOUNDNESS_CATALOG.md` is the base-ISA soundness catalog: **24 entries** across
pico (11), ceno (5), nexus (4), zisk (3) and openvm (1). Each entry gives the program that
exhibits it, the constraint missing from the **committed** system — AIR, PIL, lookup or
grand-product — with the file and line, and what a malicious prover can therefore commit.

An executor `assert!`, or a computation done in witness generation, has no binding force on a
malicious prover and does not count as a constraint anywhere in that document.

The catalog closes with the five mechanisms the 24 entries reduce to:

| | mechanism |
|---|---|
| M1 | computed but not bound — the chip computes the right value into a pinned gadget, then commits a *different*, free witness column as the architectural output |
| M2 | carry/limb bound slack → field wraparound |
| M3 | a bound degenerates from `<` to `≤` |
| M4 | an ordering or identity coordinate is a free column |
| M5 | width/sign semantics enforced by the executor but never re-imposed in the circuit |

and with the discriminator they share: a value is forgeable exactly when **every** column
carrying it is a free prover witness. One component bound to the true value is enough to defeat
the forge; when all of them are free, a coordinated multi-column forge plus bus rebalancing
passes verification.

## Licensing

LACUNA's own code (`spec/`, `scripts/`, `guests/`, `data/`, `docs/`) is Apache-2.0; see
`LICENSE`. `ports/` contains modifications to seven third-party projects and each port stays
under its upstream license — six are Apache-2.0 OR MIT, **nexus is Business Source License 1.1**
(source-available, non-production use). See `NOTICE.md`.
