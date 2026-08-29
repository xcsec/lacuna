# data

The seed corpus and the target metadata.

| file | rows | what it is |
|---|---:|---|
| `seeds.csv` | 145 | one row per seed program: its structure, opcode, input, and static shape |
| `targets.csv` | 7 | the zkVMs: upstream, pinned revision, guest ISA, proof system and field |

## seeds.csv

| column | meaning |
|---|---|
| `seed_id` | the seed's name, as used by its port |
| `target` | which zkVM it is built for |
| `program_structure` | the shape of the program (a manifest `published_name`) |
| `concrete_opcode_or_interaction` | the opcode or state interaction under test |
| `instruction_family` | base-ALU, M-extension, memory, or mixed |
| `input` | the operands fed to the guest |
| `native_verify_accept` | whether the target's own verifier accepts the seed's UNMUTATED proof — a seed whose honest baseline does not verify cannot be used |
| `executed_steps` | guest instructions executed |
| `register_writebacks` | architectural register writes performed |
| `static_writeback_sites` | distinct static pcs that write a register — the sites a mutation can target |
| `main_symbol_range` | the address range of `main`, which bounds site discovery |
| `opcode_census` | opcodes the seed executes, with counts |
| `guest_source`, `guest_elf` | where the guest comes from |

## targets.csv

`revision` / `release` pin the commit each port in `ports/` applies to and that its seeds were
built and run against. `also_evaluated_revision` / `also_evaluated_release` record a second
revision of the same zkVM that was evaluated separately.

**openvm** carries both. The port and its seeds are on **v2.0.1** (`8f021b1f`). It was also
evaluated on **v1.7.0** (`425913bd`), where `crates/vm/src/system/memory/volatile/` still
exists; that module was removed in v2.0.0, so behaviour tied to it is observable on v1.7.0 and
not on the pinned revision.

`native_verify_accept` is the only column derived from running anything. It is kept because it
is the definition of a usable seed, not a result: a seed whose own prover and verifier reject it
is excluded from mutation entirely.
