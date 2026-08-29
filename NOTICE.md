# NOTICE

## LACUNA's own code

Everything in this artifact **except `ports/`** is original work released under the Apache
License 2.0 (see `LICENSE`): `spec/`, `scripts/`, `guests/`, `data/` and `docs/`.

## Third-party code

`ports/` redistributes **modifications to seven third-party zkVM projects**, as **eight ports**
— openvm is carried at two revisions. It does not redistribute those projects: each port ships
only the files LACUNA adds (`new/`, where it has any) and a diff against upstream tracked files
(`vendor.patch`), pinned to the upstream commit in `UPSTREAM_REV`. Users obtain the projects
themselves from the URLs below.

Each port remains governed by its upstream project's license, not by Apache-2.0.

| port | upstream | pinned revision | upstream license |
|---|---|---|---|
| `pico/` | https://github.com/brevis-network/pico | `22b0aae6321c` (v2.0.0) | Apache-2.0 OR MIT |
| `ceno/` | https://github.com/scroll-tech/ceno | `13c5abf36a7f` | Apache-2.0 OR MIT |
| `nexus/` | https://github.com/nexus-xyz/nexus-zkvm | `f2ad12652c39` (v0.3.6) | Business Source License 1.1 (Change Date 2029-02-10, Change License MIT or Apache-2.0) |
| `zisk/` | https://github.com/0xPolygonHermez/zisk | `6182c8be9f4e` | Apache-2.0 OR MIT |
| `openvm/` | https://github.com/openvm-org/openvm | `8f021b1f2314` (v2.0.1) | Apache-2.0 OR MIT |
| `openvm-v1.7.0-volatile-poc/` | https://github.com/openvm-org/openvm | `425913bdc743` (v1.7.0) | Apache-2.0 OR MIT |
| `risc0/` | https://github.com/risc0/risc0 | `10fa97888d16` | Apache-2.0 OR MIT |
| `sp1/` | https://github.com/succinctlabs/sp1 | `51f6efcb2971` | Apache-2.0 OR MIT |

### Statement of modification

For the seven enumeration ports, LACUNA adds an instrumentation hook at that zkVM's
architectural write-back path and an enumeration driver. The instrumentation is additive and
default-off: with no `LACUNA_*` environment variable set, the patched tree behaves as upstream.

`openvm-v1.7.0-volatile-poc/` is not an enumeration port. It adds a `#[cfg(test)]` seam and four
tests to one module, and is absent from production builds.

**No committed constraint system, AIR or PIL file is modified in any of the seven projects.**
All patched locations are executor or witness-generation code. This is machine-checkable:

```bash
python3 scripts/check_no_constraint_changes.py
```

Per-port detail — the exact choke point, the files added and the files patched — is in each
`ports/<vm>/README.md`.

### nexus: Business Source License 1.1

`ports/nexus/` is a derivative work of the Nexus zkVM, which is licensed under **BSL 1.1**, not
under an open-source license. BSL 1.1 grants the right to copy, modify, create derivative works,
redistribute, and make **non-production use** of the licensed work; production use is restricted
by the Additional Use Grant in the upstream `LICENSE`. This artifact is academic research and is
non-production use. `ports/nexus/` may not be relicensed under Apache-2.0. On the Change Date
(10 February 2029) the upstream work converts to MIT or Apache-2.0.

Anyone redistributing or building on `ports/nexus/` should read the upstream `LICENSE` in full.

### Guest programs

`guests/lacuna_seeds/` builds against `pico-sdk` from the pico project (Apache-2.0 OR MIT) and
its `Cargo.lock` pins further transitive dependencies, each under its own license. The built
ELFs in `guests/lacuna_seeds/elf/` statically link the Rust standard library and `pico-sdk`.
