# `evaluation/spec/` — the shared LACUNA specification

Seven zkVM ports of the LACUNA record-layer write-back mutation fuzzer live in seven
separate vendor trees under `third_party/`, and are extended by people working in
parallel. This directory is the one thing all seven read. Without it they diverge on
names, predicates and controls, and the released corpus is seven incomparable datasets
rather than one cross-target comparison.

## Files

| file | what it is |
|---|---|
| [`STRUCTURE_MANIFEST.yaml`](STRUCTURE_MANIFEST.yaml) | **Normative.** 26 program structures x 7 targets = 182 cells. Names, per-target status and approach, candidate classes, expected verdicts, the acceptance predicates, the mu-menu role masks, the opcode sets and the run-matrix rules. |
| [`TARGET_CAPABILITIES.yaml`](TARGET_CAPABILITIES.yaml) | **Normative.** Per-target machine-readable capability record: the nine hook flags, the dual public-output declaration, the operand-source contract, the frozen seed-id inventory, the measured cost. A blocked cell in the manifest is a join against this file. |
| [`LACUNA_STRUCTURES.md`](LACUNA_STRUCTURES.md) | The human rendering of both, plus the rationale the YAML cannot carry. Generated from the manifest; where the two disagree the manifest wins. |
| [`../scripts/check_manifest.py`](../scripts/check_manifest.py) | The gate. Validates the manifest, guards the seven frozen names, and validates a port's emitted CSV. |
| `_design/` | Catalog provenance. Historical; the manifest supersedes them. |

## How a port is checked against this spec

An implementation agent working on one target does five things, in this order.

**1. Read your target's row in `TARGET_CAPABILITIES.yaml`** before writing any seed. It
tells you what your hook can and cannot reach, which public-output objects you must
record, whether your operands are currently baked into the vk, and what your measured
cost per candidate is. Half the structures in the manifest are blocked on some target for
a reason recorded there.

**2. Read your target's cells in `STRUCTURE_MANIFEST.yaml`.** Each carries a `status`, a
`status_source`, an `approach` naming the exact file and line to change, a
`candidate_class`, an `expected_verdict` and, where applicable, a `blocker`. Add new rows to
*this* file, never to a private table in your own driver.

**3. Follow the naming convention.** Builder symbol per target is in
`TARGET_CAPABILITIES.seed_builder_symbol`. `seed_id` is `<structure_id>` optionally
suffixed `_<opcode>` and then `_<variant>`, where the variant must be one the manifest
enumerates in `variant_suffixes` — so two ports cannot invent different suffixes for the
same shape. The legacy `op_<mnemonic>` / `<OPCODE>_single_op` / bare-mnemonic seed ids are
**frozen** and must not be regularised.

**4. Emit the required CSV columns.** Beyond the existing `candidates.csv` schema, every
row must carry `operand_source`, `candidate_class`, `accepted_case_v2`, `site_role`, `nth`
and `scored_against`. See `csv_contract` in the manifest.

**5. Run the gate.**

```sh
python3 evaluation/scripts/check_manifest.py                        # manifest self-check
python3 evaluation/scripts/check_manifest.py --strict my_run.csv    # + CSV conformance
python3 evaluation/scripts/check_manifest.py --against-published \
        the published candidates table                              # frozen-name guard
```

It fails on: a renamed frozen name, a `program_structure` value that is not a manifest
`published_name`, a missing or illegal `operand_source` / `candidate_class`, a seed id
that follows no convention, a blocked cell emitted as a probe rather than as a control, a
capability flag without a note, and a blocked cell without a reason. Exit code is non-zero
on any error; warnings do not fail the run.

## Invariants this spec exists to protect

**The seven frozen `published_name` strings.** `Single operation`, `Store--load`,
`Control flow`, `Hazard chain`, `Initial state`, `Redirect`, `Whole program`. These are
already in the `program_structure` column of `the published candidates table` and every
published table keys on them. `Store--load` has two hyphens, not an en dash. The strings
are hard-coded in `check_manifest.py` so that the guard against a rename does not live in
the file being guarded.

**Additive only.** The published enumeration must still run byte-identically. New
structures are new functions and new table rows. The mutation menu, the existing seed
builders and the published `seed_id`s do not change, and `accepted_case_strict` is kept
verbatim so no published number moves.

**Do not overwrite `guests/lacuna_seeds/elf/` for existing seeds.** That
is the frozen artefact set behind the published numbers, and a rebuild is *not*
bit-reproducible: `.rodata` grows and the `auipc`/`jalr` pair calling
`pico_sdk::io::read_vec` shifts by a page. Build into `target/` and copy only new binaries
in.

**A blocked cell is a published result.** `status: blocked` with a reason means "we
looked, and this VM's design puts the surface out of reach of a record-layer mutation".
`status: not_determined` means nobody looked. They are not the same and must never be
aggregated together.

**A control's ACCEPT is not a finding, and a calibration ACCEPT is expected.** Aggregate
`probe`, `control` and `calibration` rows separately in every table, or the catalog
inflates both its candidate count and its bug count.

## Why there is no YAML dependency, and how the parsing works

The two normative files are authored as YAML because seven people hand-edit them. Shipping
a parallel `.json` would give two artefacts that drift, so there is only one. Instead,
`check_manifest.py` contains a ~115-line loader for exactly the subset the files are written
in: block mappings, block sequences, and scalars that are one of `true` / `false` / `null` /
a number / a double-quoted string whose only escapes are `\"` `\\` `\n` `\r` `\t`. The
loader **raises** on anything outside the subset rather than guessing, so a file it accepts
means what it looks like it means. It has been checked to produce output identical to
`yaml.safe_load` on both files. Standard library only; no dependency is added.

`check_manifest.py --emit-json OUT.json` writes a JSON rendering for downstream consumers.
That is a convenience output, regenerated on demand, and never a second source of truth.
