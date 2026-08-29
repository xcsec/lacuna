# LACUNA program structures

The human rendering of [`STRUCTURE_MANIFEST.yaml`](STRUCTURE_MANIFEST.yaml), plus the
reasoning the manifest cannot carry. The manifest is the normative artefact: where the
two disagree, the manifest wins and this file is stale. Everything below the
*Rationale* section is generated from it.

## The method, and what a structure is for

LACUNA hooks the executor's architectural write-back choke point; at the *k*-th execution
of a static `pc` it replaces the written value *v* with `mu(v)` from a fixed,
instruction-independent menu, lets the honest executor continue and the honest witness
generator *G* recompute everything downstream, and then runs the REAL prover and the REAL
verifier. An ACCEPTED CASE is: the verifier accepted, the mutation fired, and the committed
public output differs from honest and is non-empty.

Three things can happen. **HIT** -- the forged witness lies in `image(G)` and the verifier
accepts, which is a finding. **SELF-HEAL** -- *G* recomputes the column from another field
and the perturbation is discarded, which is no signal. **OVER-PROPAGATION** -- *G* feeds the
same record field to a free column *and* to a pinned sibling, so the perturbation moves both,
breaks a constraint that was actually sound, and the candidate is REJECTED and reported as
SAFE when it is not. The honest witness generator is itself acting as the missing constraint.

A *program structure* is the shape of the guest program the mutation is applied inside. It
decides which record fields EXIST at all, which are NON-DEGENERATE, and which are
OBSERVABLE in the committed output. It is orthogonal to the mutation operator, and the
central defect this catalog exists to fix is that in the shipped corpus it was not treated
as orthogonal: see R4 in the run-matrix rules.

## Rationale: what changed, and why

### 1. Coverage was asymmetric to the point of being uninterpretable

The shipped corpus has 7 structures on pico, 2 on sp1 and 1 on each of the other five, and
all 30 accepted cases are on pico. That is very largely an artefact of pico being the only
target actually searched. This catalog takes the axis to 26 structures with a per-target
feasibility status for all 182 cells, including the blocked ones -- **a blocked cell is a
published result, not an omission**, and it is the difference between "we looked and this
VM binds it" and "nobody looked".

### 2. Structure and opcode were never varied independently

This is the single biggest defect in the shipped data and the reason for run-matrix rules
R1-R4. Five of pico's seven structures were pinned to `ADD` and `LD` -- opcodes pico binds
correctly -- while all 24 encoding accepted cases sit on `SRLW`/`SRAW`, which only the
Single-operation seeds reach. 4,911 candidates were spent on a matrix in which the two axes
moved together, so **"four structures found nothing" is not evidence about those structures**.
`st_op_then_state` is the shape that separates them, which is why it was promoted.

### 3. Three structures were wrongly dropped and are promoted here

three shapes away. Read in full they are distinct surfaces:

* **`st_op_then_state` -- Operation then state.** It is the DECONFOUNDING shape and the most important of the three: the shipped pico run matrix pinned five of seven structures to ADD and LD -- opcodes pico binds correctly -- while all 24 encoding accepted cases sit on SRLW/SRAW, reachable only from the Single-operation seeds. Structure and opcode were never varied independently, so 'four structures found nothing' is not evidence about those structures. This shape makes them vary independently.

* **`st_pointer_indirect` -- Pointer indirect.** Distinct from st_redirect, whose two addresses are STATIC: here the forged value BECOMES an address, which is the taint/composition surface where a value-forge escalates into address control. Chain C4 of the taint/dataflow composition audit (stale pointer -> use-after-free analogue inside an accepted proof), listed there as UNTESTED. Severity is bounded by what is in memory, not by what the primitive can write.

* **`st_initial_image` -- Initial image.** A different surface from st_initial_state, which reads a never-written zero address (.bss): this reads an address the ELF IMAGE initialises to a NON-ZERO value (.data). The project's loader-layer ledger records .data/.bss boundary bugs on 5 of 8 VMs with 3 end-to-end golds (results/LOADER_LAYER_FINDINGS.md) and st_initial_state cannot reach any of them. HONEST FRAMING: those golds are compilation-layer defects that an HONEST prover produces; this structure reuses their guest shape to ask the record-layer question they raise, and doubles as the control that makes an accept on st_initial_state specific.

Their cells were **not** assessed. Every one of them is marked
`status_source: derived_by_promotion` in the manifest, and the two that are marked
`blocked` on a target (`st_pointer_indirect` on sp1 and zisk) are blocked for a reason the
catalog does state in another form: those two targets cannot produce a coherent
RAM-mediated forgery at all today.

### 4. Five of seven targets bake their operands into the vk

Only pico and zisk read operands from an input channel; the other five materialise them as
`ADDI`/`LUI` immediates, i.e. into the committed program. An operand that is part of the
committed program can only make a target look **safer** than it is, so a cross-target
comparison that mixes `operand_source` values is unsound unless the reader can see the mix.
Hence the `operand_source` column, and hence `st_hint_advice` as its calibration.

There is a caveat the catalog did not state, and it is in the manifest under
`input_contract.hint_caveat`: on openvm and risc0 the only non-immediate channel is the
hint / ecall-READ channel, which is a **free column by design**. Sourcing ordinary operands
from it would make every candidate on those two targets inherit `st_hint_advice`'s expected
accept. They must either stay on `immediate` and be labelled operand-in-vk, or run the
paired calibration in the same run.

### 5. There are two public-output objects and they diverge

682 pico Whole-program candidates were accepted by the real verifier with the in-circuit
committed digest CHANGED and the out-of-circuit byte stream identical -- and scored
`accepted_case=false`. Every port records both objects from day one, and each
(structure, target) cell declares which one its predicate reads.

### 6. The predicate is versioned rather than edited

`accepted_case_strict` is kept **verbatim** so that no published number moves.
`accepted_case_v2` adds the two cases strict cannot express: an output that differs by being
ABSENT or TRUNCATED (`st_early_exit` succeeds precisely by truncating, so strict makes it
unfalsifiable by construction), and a change to the declared committed STATE object
(`st_finalize_only` and `st_dead_write` on openvm and risc0 reach the committed object
through the memory root, which strict does not read). v2 never turns a strict accept into a
non-accept. Report both columns forever.

### 7. Not every candidate is a probe

`candidate_class` splits **probe** from **control** from **calibration**. `st_dead_write` is a
control on five targets and a probe on two -- the register file is inside the committed
state object on openvm and risc0, so an accepted dead write there really is a state forgery.
`st_hint_advice` is calibration everywhere and its expected ACCEPT must never be counted as a
finding; its purpose is the converse, because a target where it does *not* accept has a hook
that never reaches the constraint system, and every REJECT that target reports is
uninterpretable. Without this column the catalog inflates both its candidate count and its
bug count.

### 8. A REJECT means nothing without a control on the same target

pico's credibility rests on 151/151 rejections at provably dead destinations. The other six
targets have no controlled rejections at all, so the ~26,000 non-pico REJECTs in the
published corpus cannot yet be distinguished from crashed guests. Rule R7: controls before
probes on any target that has never produced an accepted case.

---

## The 26 structures

| # | id | `published_name` | pri | mode | site role | predicate |
|---|---|---|---|---|---|---|
| 1 | `st_single_op` | Single operation **(frozen)** | must | encoding | value | strict |
| 2 | `st_op_then_state` *(promoted)* | Operation then state | must | encoding | value | strict |
| 3 | `st_boundary_operand` | Boundary operand | must | encoding | selector | strict |
| 4 | `st_subword_lane` | Sub-word lane | must | encoding | value | strict |
| 5 | `st_store_load` | Store--load **(frozen)** | must | both | value | strict |
| 6 | `st_redirect` | Redirect **(frozen)** | must | both | address | strict |
| 7 | `st_pointer_indirect` *(promoted)* | Pointer indirect | should | both | address | strict |
| 8 | `st_initial_state` | Initial state **(frozen)** | must | encoding | value | strict |
| 9 | `st_initial_image` *(promoted)* | Initial image | should | encoding | value | strict |
| 10 | `st_hazard_chain` | Hazard chain **(frozen)** | must | both | value | strict |
| 11 | `st_control_flow` | Control flow **(frozen)** | must | encoding | selector | strict |
| 12 | `st_provenance_chain` | Provenance chain | must | encoding | value | strict |
| 13 | `st_loop_repeat` | Loop repeat | must | encoding | value | strict |
| 14 | `st_multishard` | Cross-shard continuation | must | both | value | strict |
| 15 | `st_hint_advice` | Nondeterministic advice | must | encoding | value | strict |
| 16 | `st_finalize_only` | Finalize-only write | should | encoding | value | v2 |
| 17 | `st_indirect_jump` | Indirect jump | should | encoding | address | strict |
| 18 | `st_pc_imm_value` | PC-immediate value | should | encoding | value | strict |
| 19 | `st_fanout_read` | Fan-out read | should | encoding | value | strict |
| 20 | `st_reg_alias` | Register aliasing | should | both | value | strict |
| 21 | `st_pv_plumbing` | Public-value plumbing | should | encoding | syscall_arg | strict |
| 22 | `st_early_exit` | Early exit | should | encoding | selector | v2 |
| 23 | `st_dead_write` | Dead write-back | should | encoding | value | v2 |
| 24 | `st_x0_dark_write` | x0 dark write | nice | encoding | value | strict |
| 25 | `st_precompile` | Precompile boundary | nice | encoding | value | strict |
| 26 | `st_whole_program` | Whole program **(frozen)** | must | both | value | strict |

The seven **frozen** strings are the values already in the `program_structure` column of
`the published candidates table`. They must never be renamed, re-cased or re-punctuated;
`Store--load` has two hyphens, not an en dash. `check_manifest.py` hard-codes them.

## Feasibility matrix

Carried verbatim from the structure catalog except for the
three promoted structures and the cells that were already shipped. `(ctl)` marks a declared
control, `(cal)` a calibration cell.

| structure | pico | sp1 | ceno | nexus | openvm | risc0 | zisk |
|---|---|---|---|---|---|---|---|
| `st_single_op` | impl | impl | impl | impl | impl | impl | impl |
| `st_op_then_state` | triv | mod | triv | triv | mod | mod | mod |
| `st_boundary_operand` | triv | triv | triv | triv | triv | triv | triv |
| `st_subword_lane` | triv | triv | triv | triv | mod | triv | triv |
| `st_store_load` | impl | triv | mod | triv | triv | triv | triv |
| `st_redirect` | triv | triv | triv | triv | triv | triv | triv |
| `st_pointer_indirect` | mod | **BLOCK** | mod | mod | mod | mod | **BLOCK** |
| `st_initial_state` | hard | mod | **BLOCK** (ctl) | **BLOCK** (ctl) | **BLOCK** (ctl) | mod | mod |
| `st_initial_image` | hard (ctl) | mod (ctl) | **BLOCK** (ctl) | **BLOCK** (ctl) | **BLOCK** (ctl) | mod (ctl) | mod (ctl) |
| `st_hazard_chain` | impl | triv | triv | triv | triv | triv | triv |
| `st_control_flow` | impl | mod | triv | triv | mod | triv | triv |
| `st_provenance_chain` | triv | triv | triv | triv | triv | triv | mod |
| `st_loop_repeat` | triv | mod | mod | mod | mod | triv | mod |
| `st_multishard` | mod | mod | mod | **BLOCK** | mod | mod | hard |
| `st_hint_advice` | mod (cal) | mod (cal) | mod (cal) | mod (cal) | triv (cal) | triv (cal) | triv (cal) |
| `st_finalize_only` | **BLOCK** (ctl) | **BLOCK** (ctl) | **BLOCK** (ctl) | **BLOCK** (ctl) | triv | triv | **BLOCK** (ctl) |
| `st_indirect_jump` | triv | triv | triv | triv | triv | triv | mod |
| `st_pc_imm_value` | triv | triv | triv | triv | triv | triv | mod |
| `st_fanout_read` | triv | triv | triv | triv | triv | triv | mod |
| `st_reg_alias` | triv | triv | triv | triv | triv | triv | triv |
| `st_pv_plumbing` | triv | mod | triv | triv | triv | triv | triv |
| `st_early_exit` | mod | mod | mod | mod | mod | mod | mod |
| `st_dead_write` | impl (ctl) | triv (ctl) | triv (ctl) | triv (ctl) | triv | triv | triv (ctl) |
| `st_x0_dark_write` | mod | triv | triv | mod | triv | triv | n/d |
| `st_precompile` | mod | mod | mod | **BLOCK** | hard | mod | mod |
| `st_whole_program` | impl | mod | mod | triv | mod | mod | hard |

`impl` already implemented &middot; `triv` trivial &middot; `mod` moderate &middot;
`hard` hard &middot; **`BLOCK`** blocked, with a reason in the manifest &middot;
`n/d` not determined -- **nobody assessed it, which is not the same as a negative**.

## Per-target capability summary

Full records with citations in [`TARGET_CAPABILITIES.yaml`](TARGET_CAPABILITIES.yaml).

| flag | pico | sp1 | ceno | nexus | openvm | risc0 | zisk |
|---|---|---|---|---|---|---|---|
| `nth_supported` | yes | no | no | no | n/d | yes | no |
| `mem_read_hookable` | part | no | no | no | no | no | part |
| `address_hookable` | no | no | no | no | no | no | no |
| `timestamp_hookable` | part | no | yes | no | no | no | no |
| `init_value_hookable` | no | yes | no | no | no | no | part |
| `final_value_hookable` | no | yes | no | no | part | part | no |
| `next_pc_hookable` | yes | no | no | part | no | no | no |
| `hint_hookable` | part | part | no | part | part | yes | part |
| `x0_hookable` | no | yes | yes | no | yes | yes | n/d |
| `operand_source_today` | input | immediate | immediate | immediate | immediate | immediate | input |
| wall s/candidate | 0.5 | 6.9 | 2.8 | 0.07 | 9.7 | 4.2 | 73.0 |

The wall figures are measured aggregates, not a re-measurement.
They are what makes rule R6 binding: the full structure x opcode x site x mu cross product
is affordable only on nexus and pico.

## Run-matrix rules

* R1. STRUCTURE AND OPCODE VARY INDEPENDENTLY. No structure whose shape admits an opcode parameter may be run against a single pinned opcode. The run matrix is spec data -- these rules and each structure's opcodes_required -- not driver code.
* R2. Every structure with opcodes_required other than [census] or [per_target_precompile_set] MUST be run, within one run, against at least one opcode from alu_bound_reference AND the whole of that target's target_unbound_probe set.
* R3. SUBSTITUTION RULE. Where TARGET_CAPABILITIES.known_unbound_opcodes is empty -- which is six of the seven targets -- substitute the target's full shift_family (plus shift_family_w on an RV64 target) and its full m_ext, and set run_tag to include 'unbound_probe=substituted' so a reader can see that the target has no ESTABLISHED unbound opcode and that R2 was satisfied by proxy.
* R4. THE DEFECT R1-R3 EXIST TO PREVENT, FOR THE RECORD. Five of pico's seven shipped structures were pinned to ADD and LD -- opcodes pico binds correctly -- while all 24 encoding accepted cases sit on SRLW/SRAW, which only the Single-operation seeds reach. 4,911 candidates were spent on a matrix in which structure and opcode moved together. Any per-structure yield computed from a run that violates R2 is uninterpretable and MUST NOT be published as a per-structure result.
* R5. nth ARMING. Where TARGET_CAPABILITIES.capability.nth_supported is not true, the only legal arming is nth=-1 (mutate every execution of the pc) and the CSV must record it. Do not emit a per-execution nth on a target whose site counter is shared across emulation passes.
* R6. SAMPLING IS PART OF THE RESULT. The full structure x opcode x site x mu cross product is affordable only on nexus and pico (measured aggregate wall per candidate: nexus 0.07 s, pico 0.5 s, ceno 2.8 s, risc0 4.2 s, sp1 6.9 s, openvm 9.7 s, zisk 73 s). Everywhere else the corpus is sampled, and the sampling policy must be published with the counts and named in run_tag, or the cross-target comparison is invalid.
* R7. CONTROLS BEFORE PROBES. On a target that has never produced an accepted case, run st_hint_advice (calibration) and st_dead_write (control) FIRST. Without a calibration ACCEPT a reader cannot distinguish a sound VM from a port whose hook never reaches the constraint system; without the dead-write control no REJECT on that target is interpretable. Six of seven targets report zero accepted cases and only pico has controlled rejections.
* R8. A CONTROL'S ACCEPT IS NOT A FINDING, AND A not_determined CELL IS NOT A NEGATIVE. Aggregate probe, control and calibration rows separately in every table.

## Mutation-menu masking by site role

The menu itself is **frozen** -- this spec does not change it. What follows only declares
which existing entries are legal at which site role, because on an address or an ECALL-code
register most of the menu is self-destructive rather than informative.

| role | allowed | forbidden |
|---|---|---|
| `value` | *all* | *none* |
| `address` | `plus_B1`, `minus_B1`, `xor_b15` | `plus_B0`, `minus_B0`, `xor_b0`, `xor_b63`, `zero`, `boundary_msb`, `boundary_max`, `plus_B3` |
| `selector` | *all* | *none* |
| `syscall_arg` | *none* | *all* |

**`value`.** The default. The instruction-independent menu was designed for this role and no masking applies.

**`address`.** On a pointer the menu is mostly self-destructive. plus_B0 / minus_B0 / xor_b0 break word and doubleword alignment and trap the executor. zero is a null dereference; boundary_msb / boundary_max / xor_b63 land outside any mapped region. plus_B3 (+2^48) is the worst case on record: on pico it aborts the whole enumeration PROCESS, because a Rust allocation abort is not unwindable. The allowed set is alignment-preserving (every entry is a multiple of 2^15) and small enough to stay inside the mapped image. ceno lost 702 of its 1,584 published encoding candidates to mutation at an address or an ECALL-code register, unmasked; how the 702 splits between the two roles is not recorded.

*allowed with execfail expected:* `plus_B1_hi`, `plus_B2`, `xor_b31`

*exceptions:* xor_b0 is ALLOWED at the st_indirect_jump bit0 variant and nowhere else: clearing bit 0 is the RISC-V JALR requirement that variant exists to test (pico catalog #20).

**`selector`.** The information is in the SMALL steps: the structure places the honest operand one mu-step from a constraint discontinuity, so a single decrement across the boundary is the whole experiment. The large limb deltas are legal and harmless but low-yield; run them last if at all.

*recommended:* `zero`, `plus_B0`, `minus_B0`, `xor_b0`, `boundary_max`, `boundary_msb`

**`syscall_arg`.** FORBIDDEN EVERYWHERE TODAY. Perturbing an ECALL code register or a commit word index makes the record generator PANIC before any verdict exists: 1,502 of sp1's 1,670 EXECFAILs are exactly this, at crates/core/executor/src/vm/syscall/commit.rs:9-11 and syscall_code.rs:249, and part of ceno's 702 address-or-ECALL-code EXECFAILs is too. A target may opt in only after its port converts that panic into an ordinary EXECFAIL row, and the opt-in must be recorded here before any candidate is emitted.

*consequence:* st_pv_plumbing variant `index` is therefore BLOCKED on sp1 today, which is what the feasibility matrix already records.

## Structure detail

### `st_single_op` -- Single operation

rd = a OP b; commit(rd) -- the baseline per-opcode AIR probe, already the source of 24 of the 30 accepted cases.

```
let a = read(); let b = read();
let c = a OP b;
commit(c);
```

* **Constraint surface.** S1 per-opcode functional relation and the CPU<->ALU/register bus; on RV64 targets also the W-form upper-half relation. Incidentally covers register read-after-write, because the ADDI/LUI operand-setup sites are enumerated as write-back sites too.
* **Observability.** rd is the direct argument of the commit ecall / the word stored into the public-output region. One hop, no intermediate surface, on all 7 targets.
* **Record fields required.**
    * architectural result value (pico AluEvent.a, sp1 MulCols.a/ShiftRightCols.a, nexus Step.result, risc0 writeRd.data; RECOMPUTED on openvm except jal_lui; ABSENT on zisk)
    * operand-setup write-back values at the ADDI/LUI sites
* **Opcode axis.** `full_register_writing_set`
* **Over-propagation risk.** high
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #3 SRLW/SRAW low word unconstrained (sr/constraints.rs 'TODO: constrain 32-bit operations'); e2e gold e2e_srlw_forge_accepted; 24 of the 30 strict accepted cases

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| sp1 | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| ceno | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| nexus | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| openvm | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| risc0 | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |
| zisk | impl | probe | not_determined | Shipped on all seven targets; this is the baseline the published corpus is built from (the published candidates table carries 'Single operation' rows for every target). The feasibility assessment has no cell for it for that reason. The input contract is not uniform: five of seven targets bake the operands into the vk-committed program as immediates. |

### `st_op_then_state` -- Operation then state

> **Promoted 2026-08-28.** It is the DECONFOUNDING shape and the most important of the three: the shipped pico run matrix pinned five of seven structures to ADD and LD -- opcodes pico binds correctly -- while all 24 encoding accepted cases sit on SRLW/SRAW, reachable only from the Single-operation seeds. Structure and opcode were never varied independently, so 'four structures found nothing' is not evidence about those structures. This shape makes them vary independently.

The result of the opcode under test is not committed directly -- it first traverses one state interaction (store/load round trip, address computation, or branch) and only then reaches the output.

```
rd = a OP b                       # OP = the opcode under test, NOT pinned to ADD/LD
store(p, rd); x = load(p)         # variant A: through memory
# q = base + rd; x = load(q)      # variant B: rd becomes an ADDRESS   (sink S2)
# if rd != 0 { x = v1 } else { x = v2 }   # variant C: rd becomes a DECISION (sink S3)
commit(x)
```

* **Constraint surface.** The opcode chip AND the memory / address-formation / branch chip IN SERIES, with the register-consistency argument as the carrier between them. It measures where the binding actually is, because a forged value needs only ONE unbound link in the chain.
* **Observability.** Through the second interaction, so an accept proves the forgery survived a re-binding hop rather than merely being emitted.
* **Record fields required.**
    * architectural result value at the producing site (the same field st_single_op uses)
    * the second interaction's own record: load delivered value (variant mem), address / rs1_val (variant addr), or branch condition operand and next_pc (variant branch)
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_mem`, `_addr`, `_branch`
* **Over-propagation risk.** LOWER than st_single_op at the second hop. The propagation lemma (TAINT_DATAFLOW_COMPOSITION_AUDIT sec.1) is that the offline-memory/register argument binds read == last-written and NEVER value == correct, so the downstream chip re-derives honestly from a carried value: it neither heals the perturbation nor co-derives a sibling from it. The over-propagation risk stays concentrated in the first chip.
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** #3 pico SRLW/SRAW composed to a second sink; and chain C5 of TAINT_DATAFLOW_COMPOSITION_AUDIT sec.4 (a restricted arithmetic forge steered onto an address or a pc), recorded there as CONFIRMED on ceno and zisk, HIGH confidence, both reaching sink S3.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | THE Expressible with new guests guests/lacuna_seeds/src/bin/st_op_then_state_<variant>.rs: variant `branch` needs no memory and no new hook; variants `mem` and `addr` reuse the existing st_store_load / st_redirect shapes with the opcode under test in front. The point is the SEEDS-table opcode list, not the guest: run every variant against target_unbound_probe = SRLW/SRAW/SRLIW as well as ADD, so structure and opcode finally vary independently. |
| sp1 | mod | probe | not_determined | Expressible with a new fn build_op_then_state_program(op, variant) -> Program plus a row in the table at crates/prover/src/lacuna_eval.rs:596-598. Variant `branch` is memory-free and therefore the one to do first, because sp1's phase-2 CoreVM has no memory (honest_limits: any RAM-mediated forgery there is structurally self-inconsistent until CoreVM::mr is hooked). A max-cycle abort is required before any branching seed. Variants `mem` and `addr` additionally need the if !is_mem / if is_mem dispatch gates at :674 and :716 removed. |
| ceno | triv | probe | not_determined | Expressible with a new builder next to ceno_zkvm/src/lacuna_eval.rs:84 using encode_rv32; the full RV32IM including loads, stores, branches and JAL/JALR is registered, so all three variants are expressible with no hook work. Mask the mu menu on the pointer register for variant `addr`: 702 of ceno's 1,584 published encoding candidates are EXECFAIL from unmasked mutation at an address or an ECALL-code register. |
| nexus | triv | probe | not_determined | Expressible with a new fn build_op_then_state_elf() -> ElfFile next to prover2/machine/src/lacuna_eval.rs:300 using the existing enc and wou helpers; SB/SH/SW, LB/LBU/LH/LHU and the branch forms are all in BuiltinOpcode. nexus is the cheapest target in the corpus, so it can afford the full variant x opcode cross product that nobody else can. |
| openvm | mod | probe | not_determined | Expressible in build_words, but the honestly-run metered pass sizes record arenas from an UNPERTURBED execution, so the two arms of variant `branch` MUST have equal length or the candidate surfaces as EXECFAIL rather than as a verdict. Variant `addr` is the interesting one here because Rv32LoadStoreAdapterRecord.rs1_val feeds both rs1_data and mem_ptr_limbs. |
| risc0 | mod | probe | not_determined | Needs insn_b (and insn_j for the call form) added to the built-in assembler at risc0/circuit/rv32im/src/prove/lacuna_eval.rs:199-249 -- three lines each. Once they exist, all three variants follow, and risc0 is one of only two targets with real per-execution nth arming, so the second-hop site can be armed independently of the first. |
| zisk | mod | probe | not_determined | Ordinary Rust guest in examples/lacuna-seed/src/bin/. Cost-bound rather than code-bound at ~73 s per candidate: run ONE variant (`branch`, which needs no read-side hook) against a handful of opcodes and a sampled mu menu, and publish the sampling policy. |

### `st_boundary_operand` -- Boundary operand

Same shape as Single operation, but the honest operands sit one mu-step from a constraint discontinuity, so the mutation drives an AIR-derived SELECTOR rather than an AIR-derived value.

```
// (a) zero-divisor selector: honest b = 1
let a = read(); let b = read();      // stdin b = 1
commit(a / b);                        // mu(b) -> 0
// (b) shift-amount mask: honest s = 1, s in a REGISTER (SLL not SLLI)
commit(a << (s & (XLEN-1)));          // mu(s) -> XLEN, XLEN-1, 2^16
// (c) signed overflow: honest a = INT_MIN+1, b = -1  -> mu(a) = INT_MIN
// (d) limb/sign boundary: honest a = 0x0000_FFFF or 0x7FFF_FFFF, mu = +/-1
// (e) exactly divisible / even divisor: DIVU(8,2), DIVU(4,2), REMU(10,6)
// (f) limb overflow: a = b = 0xFFFF_FFFF for MUL/MULH
```

* **Constraint surface.** S17: AIR-derived selectors and guard flags -- is_zero for DivRem, the shift-amount decomposition and coarse limb selector, the INT_MIN/-1 special case, the alignment predicate, the limb-carry chain. Structurally different from S1: the forged value is an OPERAND, so G recomputes the result coherently and the only thing that can come loose is a flag the AIR derives-by-copy.
* **Observability.** The recomputed result is committed directly, exactly as in Single operation.
* **Record fields required.**
    * operand read value b/c
    * the boundary branch changes a field's STATUS: nexus div_rem.rs:44->:163 takes the DIV/REM result FROM the record at divide-by-zero and INT_MIN/-1 while recomputing it in the general case
    * gated selector/guard columns derived from the operand
* **Opcode axis.** `m_ext`, `m_ext_w`, `shift_family`, `shift_family_w`
* **Variant suffixes.** `_zero`, `_shamt`, `_intmin`, `_limb`, `_exactdiv`, `_limbmax`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #1 DIV/REM '<=' degenerate boundary (e2e_divu_boundary_forge_accepted), #5 SRL shift-amount decoupling (e2e_srl_shiftamt_forge_accepted), #6 SLL limb selector (e2e_sll_forge_accepted); nexus #13 DivRem 32-bit overflow needs an even divisor; ceno #8/#9 need 0xFFFFFFFF-squared
* **Site role.** `selector` -- The forged word is an OPERAND that drives an AIR-derived selector, not a result. Small deltas carry the information; the large limb deltas are legal but low-yield.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with new guests guests/lacuna_seeds/src/bin/bd_<case>.rs cloning op_divu.rs/op_sll.rs; the only change is the stdin string in the SEEDS table at evaluation/scripts/run_lacuna_pico.py:44-86 (b=1 for the zero-divisor step, a=INT_MIN+1/b=-1, a=0x7FFF_FFFF). Shift-amount cases MUST use SLL/SRL (register operand), not SLLI/SRLI. No Rust change. |
| sp1 | triv | probe | not_determined | Parameterise `build_op_program` (crates/prover/src/lacuna_eval.rs:93) on (b,c) instead of the hard-coded `let (b, c) = (0x5A5u64, 13u64)` at :584, and add a boundary-operand table (0,1,-1,INT_MIN+1,0xFFFF,0x7FFF_FFFF,XLEN-1). Each pair becomes a seed_id suffix. |
| ceno | triv | probe | not_determined | LACUNA_A / LACUNA_B already exist in ceno_zkvm/src/lacuna_eval.rs; add a boundary-pair sweep table around `build_op_program`:84. Note operands are ADDI 12-bit-signed immediates, so values outside +/-2047 need a LUI+ADDI pair in the builder. |
| nexus | triv | probe | not_determined | `build_op_elf` (prover2/machine/src/lacuna_eval.rs:300) already takes (a,b); add a boundary-pair table to the enumeration loop. Values above 12 bits need LUI+ADDI via `enc`. NOTE: only the RV32I base ALU is in scope -- prover2 BASE_COMPONENTS has no M-extension, so the DIV/MUL boundary cases are out of scope on this target. |
| openvm | triv | probe | not_determined | `build_words` (extensions/rv32im/tests/src/lacuna_eval.rs) already materialises a and b with LUI+ADDI; parameterise the constants (currently a=0x87654321, b=0x37) over a boundary table and add the pair to the seed_id. |
| risc0 | triv | probe | not_determined | `build_seed` (risc0/circuit/rv32im/src/prove/lacuna_eval.rs:153) uses `li t0,0x12345679; li t1,0xb7`; parameterise those two li constants over the boundary table. The built-in assembler already emits li as LUI+ADDI. |
| zisk | triv | probe | not_determined | Zero code: the guest examples/lacuna-seed/src/main.rs already reads (sel,a,b) from the input slice, so a boundary case is a new input framing [len][sel][a][b] in the driver. Budget-limited: at ~73 s/candidate pick 3-4 pairs per opcode, not the full table. |

### `st_subword_lane` -- Sub-word lane

Wide store, narrow load (and the mirror: narrow store into a wide word) -- byte/halfword lane extract, sign/zero extension, and sibling-lane preservation.

```
static mut W: u64 = 0;
let v = read(); let b = read();
unsafe {
  write_volatile(&raw mut W, v);
  let x = read_volatile((&raw const W as *const u8).add(3));  // LBU/LB/LHU/LH/LWU
  commit(x as u64);
  // STORE-side seed: write_volatile(&raw mut W, v);
  //                  write_volatile((&raw mut W as *mut u8).add(1), b);  // SB/SH/SW
  //                  commit(read_volatile(&raw const W));
}
```

* **Constraint surface.** S7 lane selection and extension in the load AIR; lane merge and sibling-lane preservation in the store AIR. The load side is the cleanest single-landing-point shape in the catalog: rd is a NARROWING of the memory word, so the free lanes lie outside the pinned window by construction.
* **Observability.** The extracted lane is committed directly (load side); the reassembled wide word is committed directly (store side, which additionally shows whether the untouched lanes were bound).
* **Record fields required.**
    * load delivered value, full aligned word (pico mem_value_u64, zisk mem_reads[i], openvm LoadStoreCoreRecord.read_data, risc0 readMem.data, sp1 event.mem_access.value(), ceno UInt::new_unchecked(memory_read))
    * sign bit of a signed narrow load, one record bit feeding two column groups (nexus lb.rs:57-58->:61-62 HRamValSign/HRamValRem; risc0 signBit/pickByte)
    * store-side previous word (prev_data) whose untouched lanes must survive
* **Opcode axis.** `mem_narrow`, `mem_word`
* **Variant suffixes.** `_load`, `_store`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** zisk catalog #16 LWU/LHU high lane (mem_align_sm.rs:118,155 -- all 8 lanes of the V row come from the record value) and pico #17 LB/LBU high byte; both graded pure-L0 and both currently MISLABELLED as program_structure='Single operation', which cannot reach them

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with new guests sw_lane_load.rs / sw_lane_store.rs in guests/lacuna_seeds/src/bin/ (store a u64 via write_volatile, read one byte/half back through a *const u8 offset, commit). SEEDS rows with LACUNA_OPS=LB,LBU,LH,LHU,LW,LWU and SB,SH,SW. Encoding works today. |
| sp1 | triv | probe | not_determined | Clone `build_op_mem_program` (crates/prover/src/lacuna_eval.rs:132) into build_subword_program, swapping SD/LD for SB/SH/SW and LB/LBU/LH/LHU/LW/LWU (all exist in Opcode, opcode.rs:106-149). Requires the is_mem gate removal (work item 2) so its write-back sites are enumerated at all. |
| ceno | triv | probe | not_determined | Expressible with a new `build_subword_program` next to ceno_zkvm/src/lacuna_eval.rs:84 using encode_rv32 for SW then LB/LBU/LH/LHU. All of LW/LHU/LH/LBU/LB/SW/SH/SB have registered circuits (rv32im.rs:280-333). Reuse the 0x08001000 commit buffer. |
| nexus | triv | probe | not_determined | Expressible with a new `build_subword_elf` next to prover2/machine/src/lacuna_eval.rs:300; `enc(BuiltinOpcode::SW/SB/SH/LB/LBU/LH/LHU/LW, ...)` all exist (vm/src/riscv/instructions/instruction.rs:63-87). Store into the existing ram_image word, load a lane back, route through `wou` to the output region. |
| openvm | mod | probe | not_determined | Requires adding SB/SH/SW/LB/LBU/LH/LHU words to `build_words` in extensions/rv32im/tests/src/lacuna_eval.rs. NOTE the hook restriction: only 4-byte writes are perturbed (N == RV32_REGISTER_NUM_LIMBS at adapters/mod.rs:119-133); the load rd write IS 4 bytes so the load side works, but the STORE side needs the narrow timed_write path admitted to the hook. |
| risc0 | triv | probe | not_determined | Requires extending the built-in assembler in risc0/circuit/rv32im/src/prove/lacuna_eval.rs (build_seed:153) with insn_s/insn_i encodings for sb/sh/lb/lbu/lh/lhu -- three lines each, modelled on execute/testutil.rs:190-355. Store to a scratch word, load a lane, sw the lane to GLOBAL_OUTPUT_ADDR. |
| zisk | triv | probe | not_determined | Expressible with a new guest examples/lacuna-seed/src/bin/sw_lane.rs (or a new selector arm in `dispatch`) doing write_volatile of a u64 then read_volatile of a *const u8/u16/u32, commit_slice the lane. It targets catalog #16 (lwu/lhu high lane) directly. |

### `st_store_load` -- Store--load

store(p,v1); store(p,v2); commit(load(p)) -- TIME disambiguation at one address; plus the _tail variant whose trailing store keeps the load off the finalize boundary.

```
static mut SLOT: u64 = 0;
let v1 = read(); let v2 = read(); let v3 = read();
unsafe {
  write_volatile(&raw mut SLOT, v1);
  write_volatile(&raw mut SLOT, v2);
  let x = read_volatile(&raw const SLOT);
  write_volatile(&raw mut SLOT, v3);   // _tail variant only
  commit(x);
}
```

* **Constraint surface.** S5 read-after-write at one address (does the offline-memory argument bind the delivered value to the most recent write?) and, with an order operator, S10 the free (chunk, clk) columns and the prev_clk chain. The _tail pair separates S5 from S9 by taking the finalize boundary row out of the picture.
* **Observability.** The loaded value is committed directly.
* **Record fields required.**
    * load delivered value (reachable on 7/7; the PRIMARY value-carrying field on zisk)
    * previous value of the access (6/7; RECOMPUTED on nexus = clean negative)
    * previous timestamp / prev_cycle of the access (6/7; a genuine RECORD field on ceno prev_rs1_ts/prev_rd_ts/prev_ts, openvm MemoryReadAuxRecord.prev_timestamp, risc0 readMem.prevCycle, sp1 MemoryRead/WriteRecord.prev_timestamp -- trace-only on pico, absent on zisk)
* **Opcode axis.** `mem_word`, `deconfound_min`
* **Variant suffixes.** `_tail`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #7 P-CLK free memory timestamp (e2e gold, BIND-O1, 4 of the 30 accepted cases). On ceno it is the shape that would make the already-accepted ORD-O1 prev_cycle slack (36 real verifier ACCEPTs, all output_changed=false) actually change the committed output.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | probe | not_determined | Shipped: the guest is guests/lacuna_seeds/src/bin/st_store_load.rs (fib for Whole program) with a row in the SEEDS table of evaluation/scripts/run_lacuna_pico.py, and the published corpus carries its candidates. this seed is pinned to ADD/LD in that table, which are opcodes pico binds, so its published yield of zero is not evidence about the structure. |
| sp1 | triv | probe | not_determined | The seed ALREADY EXISTS: `build_op_mem_program` (crates/prover/src/lacuna_eval.rs:132) does ADDI x6,SCRATCH; SD x30,0(x6); LD x7,0(x6); commit(x7). Delete the `if !is_mem` / `if is_mem` dispatch gates at :674 and :716 and replace them with a per-structure mode list, so its 17 write-back sites -- including the LD's own rd write -- are enumerated. Add a _tail variant (one more SD after the LD). |
| ceno | mod | probe | not_determined | Expressible with a new `build_store_load_program` next to ceno_zkvm/src/lacuna_eval.rs:84: SW x4,0(x6); SW x7,0(x6); LW x8,0(x6); commit x8. THE prev_cycle is a RECORD field here (insn_base.rs:95,312,452), so the existing ts_perturb hook (tracer.rs:135/1131) becomes a value-deciding lever with no post-tracegen seam. Also add a ~20-line stale-load hook in ceno_emul so the delivered load value can be the second-most-recent write. |
| nexus | triv | probe | not_determined | Expressible with a new `build_store_load_elf` near prover2/machine/src/lacuna_eval.rs:300: two `enc(SW,...)` to the ram_image word, one `enc(LW,...)`, then the existing `wou` to the output region. The seed already contains one LW so the plumbing is proven. |
| openvm | triv | probe | not_determined | Requires adding SW/SW/LW words to `build_words` in extensions/rv32im/tests/src/lacuna_eval.rs targeting a scratch address in the RAM image, then REVEAL the loaded register. LoadStoreCoreRecord.read_data / prev_data are real record fields here (loadstore/core.rs:246,248) -- the only openvm rv32im core record besides jal_lui that carries values rather than operands. |
| risc0 | triv | probe | not_determined | Requires extending build_seed (prove/lacuna_eval.rs:153) with two sw and one lw to a scratch address (the assembler already has sw), then the existing sw to GLOBAL_OUTPUT_ADDR. readMem.data / writeMem.prevData / prevCycle are reachable record fields. |
| zisk | triv | probe | not_determined | Expressible with a new guest bin doing two write_volatile and one read_volatile on a static mut u64, commit_slice the loaded value. mem_reads[i] is zisk's PRIMARY reachable record field and has never been perturbed. NOTE: no record-carried timestamp on zisk (STEP is a fixed column plus an airval), so run ENCODING only -- the order/binding variant is structurally inexpressible here. |

### `st_redirect` -- Redirect

Two live addresses, and the mutation site is the instruction that MATERIALISES THE POINTER -- SPACE disambiguation, as opposed to Store--load's TIME disambiguation.

```
static mut S1: u64 = 0;
static mut S2: u64 = 0;
let v1 = read(); let v1b = read(); let v2 = read();
unsafe {
  let p1 = &raw mut S1;              // <-- THIS write-back is the encoding-mode site
  write_volatile(p1, v1);
  write_volatile(p1, v1b);           // second store to p1: arms the binding-mode stale-load
  write_volatile(&raw mut S2, v2);
  commit(read_volatile(p1));
}
```

* **Constraint surface.** S6 address derivation (is addr bound to rs1+imm, or is the memory argument's address key free?) and the (addr, value) pairing in the offline-memory argument.
* **Observability.** The redirected load's value is committed: the record claims a read of p1 while delivering p2's contents.
* **Record fields required.**
    * access address / rs1_val at the address-forming read point (openvm Rv32LoadStoreAdapterRecord.rs1_val feeds BOTH rs1_data[0..4] and mem_ptr_limbs[0..2]; pico addr_word and addr_aligned same source; nexus BIND-V2; ceno MemAddr from rs1+imm; sp1 has NO address field -- recomputed, a clean negative)
    * load delivered value
    * the address's write history (>=2 writes required to arm a stale-load operator)
* **Opcode axis.** `mem_word`, `deconfound_min`
* **Over-propagation risk.** high
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #4 addr_aligned free / N1 address redirect (e2e_n1_addr_forge_accepted; rated CRITICAL -- arbitrary load/store address redirection)
* **Site role.** `address` -- The site is the instruction that MATERIALISES THE POINTER, so the mu menu must be masked to the address role; the load's own delivered value is a second, value-role site and is enumerated separately.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Edit guests/lacuna_seeds/src/bin/st_redirect.rs: add a SECOND write_volatile(p1, v1b) before the store to p2, so stale_load::on_load's `if v.len() < 2 { return None }` guard arms on the intended load. Add a third stdin value to the SEEDS row (run_lacuna_pico.py). Encoding mode additionally needs LACUNA_OPS to include the pointer-producing opcode (ADDI/AUIPC/LUI), not just LD. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_redirect_program` in crates/prover/src/lacuna_eval.rs: ADDI x6,P1; ADDI x8,P2; SD x28,0(x6); SD x29,0(x8); LD x7,0(x6); commit(x7). The site is x6's write-back and needs NO new hook: CoreVM::mr (vm.rs:745) ignores its addr argument, so a redirected load records a read at the new address delivering the old address's value. Mask the mu menu to alignment-preserving entries (xor_b15/b31/b63, +/-B1/B2) -- xor_b0/+/-B0 force InvalidMemoryAccess. |
| ceno | triv | probe | not_determined | Expressible with a new `build_redirect_program` near ceno_zkvm/src/lacuna_eval.rs:84 with two scratch words. The pointer-producing LUI/ADDI is already an enumerated site type. Mask the mu menu to 4-aligned deltas -- 702 of ceno's existing EXECFAILs come from perturbing pointer registers with unaligned mu. |
| nexus | triv | probe | not_determined | Expressible with a new `build_redirect_elf` near prover2/machine/src/lacuna_eval.rs:300 with two words in the ram_image. Perturb the ADDI that materialises p1. nexus is the target where BIND-V2 (address recomputed in store/mod.rs:141 but taken from Step.memory_records in read_write_memory/trace.rs:141,201) makes this a two-consumer/one-field test. |
| openvm | triv | probe | not_determined | Two scratch addresses in `build_words`; the site is the LUI/ADDI that forms the pointer. openvm is the canonical over-propagation case here: Rv32LoadStoreAdapterRecord.rs1_val is written into BOTH rs1_data[0..4] (adapters/loadstore.rs:541) AND mem_ptr_limbs[0..2] (:510-519), so expect a coherent retarget rather than a self-contradiction. |
| risc0 | triv | probe | not_determined | Requires extending build_seed with two scratch stores at distinct addresses and a load from the first; the site is the li that forms the first pointer. Keep both addresses word-aligned and inside the mapped image, and mask mu to +/-4k deltas. |
| zisk | triv | probe | not_determined | Expressible with a new guest bin with two static mut u64 slots and a raw-pointer load from the first. Perturbing the pointer-producing write-back via get_value_to_store (emu.rs:2781) works with the existing hook; mask mu to 8-aligned deltas for RV64. |

### `st_pointer_indirect` -- Pointer indirect

> **Promoted 2026-08-28.** Distinct from st_redirect, whose two addresses are STATIC: here the forged value BECOMES an address, which is the taint/composition surface where a value-forge escalates into address control. Chain C4 of the taint/dataflow composition audit (stale pointer -> use-after-free analogue inside an accepted proof), listed there as UNTESTED. Severity is bounded by what is in memory, not by what the primitive can write.

The forged word is a POINTER that an honest later load then dereferences, so a one-word forgery becomes a whole-object substitution.

```
store(pp, &A); store(pp, &B)   # pp holds a pointer, written twice
p = load(pp)                   # forge HERE (stale or redirected) -> p = &A
commit(load(p))                # the dereference is entirely honest
```

* **Constraint surface.** Composition of the memory-timestamp/address surface with the address-formation path. The dereferencing load is a second, honest memory access whose address is a carried register value -- so it tests whether an unbound quantity in the memory plane becomes a capability in the addressing plane.
* **Observability.** The dereferenced object is committed. Severity is bounded by what is in memory, not by what the primitive can write.
* **Record fields required.**
    * the write-back that delivers the POINTER out of memory
    * per-address write history (>= 2 writes) for the binding-mode stale-load arm
    * the dereferencing load's address, which is a carried register value and is NOT separately hooked on any target
* **Opcode axis.** `mem_word`
* **Over-propagation risk.** LOW -- the dereference is honest and nothing downstream is co-derived from the forged pointer. The severity comes from amplification, not from a second forgery.
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** Empirically attested on pico already: accepted binding case B_st_store_load_s1 returned a STALE STACK POINTER (0x211440 -> 0x211438) and the later commit-path load read a different slot, so the Redirect mechanism landed from inside the Store--load seed. Formally this is chain C4 of TAINT_DATAFLOW_COMPOSITION_AUDIT sec.4 (P-CLK self-composition: stale pointer -> use-after-free analogue inside an accepted proof), listed there as UNTESTED.
* **Site role.** `address` -- Address role at the site where the forged word BECOMES an address. The dereferencing load itself is honest.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | probe | not_determined | Guest guests/lacuna_seeds/src/bin/st_pointer_indirect.rs: two stores of two different pointers into a slot, a load of the slot, and a commit of the dereference. ENCODING mode works today by perturbing the write-back that materialises the pointer; BINDING mode works today too, because the slot has >= 2 writes, which is exactly the condition stale_load::on_load needs and which the shipped st_redirect seed fails to meet. Empirically attested already: the accepted binding case B_st_store_load_s1 returned a STALE STACK POINTER (0x211440 -> 0x211438) and the later commit-path load read a different slot. |
| sp1 | **BLOCK** | probe | not_determined | **Blocked:** sp1's phase-2 CoreVM has no memory: the dereferencing load's delivered value comes from a phase-1 oracle (crates/core/executor/src/vm.rs:745-758) that IGNORES its address argument and hands back the honest value. A forged pointer therefore does NOT change what the dereference returns, so the candidate is structurally self-inconsistent and its rejection says nothing about the constraint system. Ship as a declared negative with the blocker recorded, or wait for the CoreVM::mr hook. A REJECT here is not evidence of binding. |
| ceno | mod | probe | not_determined | Expressible with a new builder using encode_rv32; the honest emulator continues from the forged register, so the dereference is a genuine second memory access at a different address. Mask the mu menu to the address role: 702 of ceno's 1,584 published encoding candidates are EXECFAIL from unmasked mutation at an address or an ECALL-code register. |
| nexus | mod | probe | not_determined | Expressible with a new fn build_pointer_indirect_elf(). The nexus survey records precisely this reach: the port perturbs only Step.result, but the honest emulator continues from the forged value, so every later load's ADDRESS and hence its delivered value follow for free. |
| openvm | mod | probe | not_determined | Expressible in build_words. Keep the two candidate objects inside the mapped region and use the address mu mask, or the candidate lands as EXECFAIL. Note openvm's own address field, Rv32LoadStoreAdapterRecord.rs1_val, is not hookable, so this is an encoding-mode-only shape here. |
| risc0 | mod | probe | not_determined | Expressible with the existing insn_i/insn_s forms; write_reg (prove/preflight/emu.rs:399) already covers the load that delivers the pointer, and the preflight is a full re-execution, so the dereference follows honestly. |
| zisk | **BLOCK** | probe | not_determined | **Blocked:** zisk's witness generation replays against EmuTrace.mem_reads rather than re-executing, so a forged pointer does not change what the dereference delivers -- the same structural incoherence as sp1 (the structure catalog honest_limits, 'TWO TARGETS CANNOT PRODUCE A COHERENT RAM-MEDIATED FORGERY AT ALL TODAY'). Ship as a declared negative, or wait for a read-side hook built on the existing zisk_forge_narrow_load template at core/src/mem.rs:33-46. |

### `st_initial_state` -- Initial state

commit(read of an address the program never wrote) -- the only structure whose forged value has no producing instruction.

```
static mut UNWRITTEN: u64 = 0;
let _ = read();                        // keeps the stdin plumbing uniform
unsafe { commit(read_volatile(&raw const UNWRITTEN)); }
// variants: an address in the hint region; an address in .bss past the loaded image
```

* **Constraint surface.** S8 the memory-initialize / page-in chip's claim about pre-execution RAM, its sorted-address ordering constraints, and the closed global bus that re-consumes the initial value. On sp1 the initialize value is forced to zero only on the addr==0 row (memory/global.rs:461-472); for every other address it is an unconstrained committed column defended only by the global LogUp bus.
* **Observability.** The read value is committed directly, but ONLY under a COHERENT mutation: the delivered read value, the initialize event value and (where mirrored) the finalize event value must all move with the same mu. Moving one leg guarantees a bus imbalance that says nothing.
* **Record fields required.**
    * memory-initialize value (record-carried on pico MemoryInitializeFinalizeEvent.value, sp1 MemoryInitCols.value, risc0 PageInPartWitness.data[i], zisk input region via mem_reads; NOT record-carried on openvm (built from MemoryImage), ceno (fixed preprocessed columns from the ELF) or nexus (BIND-V4 unreachable))
    * load delivered value at the never-written address
    * memory-finalize value of the same address
* **Opcode axis.** `mem_word`, `mem_narrow`
* **Variant suffixes.** `_bss`, `_hintregion`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** openvm catalog #15 volatile initial_data (e2e gold, but L2' -- the free column is filled with a literal 0 with no record pre-image, and the volatile path was removed in openvm v2.0.0) and ceno #22 HintsTable limb range. The findings catalog literally records their program_structure as 'initial-state / unwritten-memory seed (proposed extra; none of the five fits)'.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | hard | probe | not_determined | **Blocked:** no hook on the memory-initialize value / program image; wb_perturb and stale_load cannot reach a never-written BSS word The guest st_initial_state.rs is already correct but INERT: stale_load::on_load bails when the address has <2 writes and there is no hook on the memory image, so UNWRITTEN is untouchable and all 91 binding accepts are incidental stack-slot fires. Needs a new hook on the MemoryInitialize event value in the emulator's program-image path, plus a matching delivered-read substitution -- a genuinely new operator, not a seed change. |
| sp1 | mod | probe | not_determined | THE Seed: ADDI x6,SCRATCH2 (never written, not in the image); LD x7,0(x6); commit(x7). The mutation must be a COHERENT TRIPLE with one mu: (i) a NEW `mem_perturb::on_mem_read` hook in CoreVM::mr (crates/core/executor/src/vm.rs:745-758, one line mirroring wb_perturb::on_write_back); (ii) record_perturb::F_MEM_INIT_VALUE (already implemented, prove.rs:150); (iii) record_perturb::F_MEM_FINAL_VALUE (implemented at prove.rs:152, NEVER ARMED). record_perturb::with currently arms one (field,index) pair and needs a two-field or address-keyed form. The published conclusion 'not a soundness gap' is established only for the incoherent single-leg mutation that was actually run. |
| ceno | **BLOCK** | control | REJECT | **Blocked:** no record correspondent -- initial memory is preprocessed from the ELF, not record-carried Build the seed anyway as a documented negative and record it as such: ceno's RAM-init columns are FIXED PREPROCESSED columns generated from the ELF (tables/ram/ram_impl.rs:69-76), so no record field exists and no record-layer mutation can move the initial value. |
| nexus | **BLOCK** | control | REJECT | **Blocked:** BIND-V4: no reachable boundary-init record field Documented negative; the nexus record-layer survey marks the boundary-init value explicitly unreachable (BIND-V4). Ship the seed with expected_verdict=REJECT so the negative is measured rather than asserted. |
| openvm | **BLOCK** | control | REJECT | **Blocked:** boundary chip built from the MemoryImage, not from a record; volatile path removed in v2.0.0 Documented negative. The boundary chip is built from the MemoryImage (persistent.rs:214-262), and the volatile path that catalog #15 needs was removed in v2.0.0 -- reaching #15 would require pinning tag v1.7.0 AND a literal-fill (L2') operator, both out of scope for a program-structure change. |
| risc0 | mod | probe | not_determined | Seed: li a scratch address never written and never in the image, lw it, sw the loaded word to GLOBAL_OUTPUT_ADDR. PageInPartWitness.data[i] is a genuine committed record field, so the lever exists; the work is a small hook on the page-in data alongside the existing write_reg hook (emu.rs:399) plus keeping the paged-out mirror coherent. |
| zisk | mod | probe | not_determined | Expressible with a new guest reading a never-written static, committing it. zisk delivers the input region through mem_reads, so the lever is a read-side hook alongside the existing get_value_to_store hook (emu.rs:2781). Budget: 1 seed x a handful of mu, not a sweep. |

### `st_initial_image` -- Initial image

> **Promoted 2026-08-28.** A different surface from st_initial_state, which reads a never-written zero address (.bss): this reads an address the ELF IMAGE initialises to a NON-ZERO value (.data). The project's loader-layer ledger records .data/.bss boundary bugs on 5 of 8 VMs with 3 end-to-end golds (results/LOADER_LAYER_FINDINGS.md) and st_initial_state cannot reach any of them. HONEST FRAMING: those golds are compilation-layer defects that an HONEST prover produces; this structure reuses their guest shape to ask the record-layer question they raise, and doubles as the control that makes an accept on st_initial_state specific.

Commit the value read from an address whose non-zero initial value comes from the vk-committed program image; the negative control for st_initial_unwritten.

```
static PAYLOAD:  u32     = 0xDEADBEEF;   # .data, inside the committed image
static BSS_TAIL: [u64;8] = [0; 8];       # .bss immediately after (the dword-boundary shape)
commit(read_volatile(&PAYLOAD))
```

* **Constraint surface.** Whether the initial value of an IN-IMAGE address is bound to the vk-committed program/memory image (preprocessed program chip, initial global cumulative sum, boundary or Merkle digest) rather than being a free boundary column. Same chip as st_initial_unwritten, different column, opposite expected verdict.
* **Observability.** The initialised value is committed directly. A change here would mean the prover can claim an initial value the vk does not commit.
* **Record fields required.**
    * memory-initialize value at an address the ELF image sets NON-ZERO (record-carried on sp1 MemoryInitCols.value, risc0 PageInPartWitness.data[i], zisk input region via mem_reads; structurally absent on ceno, nexus, openvm; unhooked on pico)
    * load delivered value at that address
* **Opcode axis.** `mem_word`, `mem_narrow`
* **Variant suffixes.** `_data`, `_bssboundary`
* **Over-propagation risk.** Same operator and same L2-prime blockage as st_initial_unwritten; no additional coupling.
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** The loader-layer golds recast as a record-layer question: PIPELINE_LAYER_SOUNDNESS_CATALOG #1 SP1 L-1 and #2 Pico L-1 (BSS dword zero-fill clobbers the adjacent .data word; e2e gold -- the real ProverClient accepts a committed 0x00000000 for an ELF .data of 0xDEADBEEF), #3 ZisK T-1, #4 Nexus N-1. HONEST FRAMING: those are compilation-layer defects, not record forgeries -- an honest prover produces them. This structure reuses their exact guest shape to ask the record-layer question they raise, and doubles as the control that makes an accept on st_initial_unwritten specific.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | hard | control | REJECT | **Blocked:** Same missing hook as st_initial_state: there is no hook on the MemoryInitialize event value or on the program image, so an in-image word is as untouchable as an unwritten one. Blocked on the same new operator st_initial_state needs. Until it exists, record honestly that the shape is inexpressible by design of the DRIVER. |
| sp1 | mod | control | REJECT | Seed: a Program with a non-zero memory_image word at an address the guest then loads and commits. sp1's MemoryInitialize value column is forced to zero only on the addr==0 row (crates/core/machine/src/memory/global.rs:461-472); for every other address it is an unconstrained committed column defended only by the global LogUp bus, and record_perturb::F_MEM_INIT_VALUE is already implemented and already used. This is the record-layer form of the question the SP1 L-1 loader gold raises. |
| ceno | **BLOCK** | control | REJECT | **Blocked:** Program.image -> init_static_addrs (e2e.rs:1248-1265) -> generate_fixed_traces (e2e.rs:1301-1320, mmu.rs:79-83) puts the in-image value in the FIXED trace, hence in the vk. There is no record correspondent, exactly as for st_initial_state. Build the seed anyway as a documented negative; ceno is the cleanest example of the intended design (the image IS the vk) and is worth stating with data. |
| nexus | **BLOCK** | control | REJECT | **Blocked:** BIND-V4: no reachable boundary-init record field. Memory-initialisation values are ELF-side and cannot be varied per candidate. Documented negative, expected_verdict REJECT. |
| openvm | **BLOCK** | control | REJECT | **Blocked:** The boundary chip is built from the MemoryImage (crates/vm/src/system/memory/persistent.rs:214-262); there is no record correspondent and the volatile path was removed in v2.0.0. Documented negative. Note the contrast worth publishing: openvm's REMOVED volatile initial_data was a free witness column, and this seed is the shape that would have found it. |
| risc0 | mod | control | REJECT | Seed: put a non-zero word in the MemoryImage via Asm::program()'s MemoryImage::set_word, lw it, and sw it to GLOBAL_OUTPUT_ADDR. PageInPartWitness.data[i] is a genuine committed record field, tested here against the Poseidon2 paging / rootIn argument rather than against a free column. Needs the same small page-in hook as st_initial_state. |
| zisk | mod | control | REJECT | Expressible with a new guest reading a non-zero .data static and committing it. zisk's existing guest already has a .data segment (0xA0030000, len 8), so the shape costs a few lines; the lever is the same read-side hook st_initial_state needs. Budget one seed and a handful of mu, not a sweep. |

### `st_hazard_chain` -- Hazard chain

Two architectural writes to one register with no intervening read, then the dependent read -- register write-after-write retirement.

```
let a = read(); let b = read();
let x: u64;
unsafe { asm!("mv {x}, {a}", "mv {x}, {b}",
              x = out(reg) x, a = in(reg) a, b = in(reg) b,
              options(pure, nomem, nostack)); }
commit(x);
// programmatic ports: OP x30,x28,x0 ; OP x30,x29,x0 ; MOV x11,x30 ; commit
```

* **Constraint surface.** S4 register write-after-write retirement -- the second write's (prev_value, prev_timestamp) must equal the first write's record -- plus the execution-order continuity / pc-continuity chain. The register-file analogue of what an order operator does to data memory.
* **Observability.** Perturbing the SECOND write reaches the commit directly. Perturbing the FIRST write does not (overwritten before any read), so its best outcome is ACCEPT-with-unchanged-output -- a binding datum, never an accepted case -- EXCEPT on openvm and risc0, where the register file is inside the committed memory root and even a retired write is state. Score the two site classes separately.
* **Record fields required.**
    * register-access previous value (risc0 writeRd.prevData, openvm writes_aux.prev_data, ceno prev_rd_value declared UInt::new_unchecked at insn_base.rs:313, sp1 MemoryAccessCols.prev_value, pico a_record.prev_value)
    * register-access previous timestamp (ceno prev_rd_ts insn_base.rs:312, risc0 writeRd.prevCycle, openvm writes_aux.prev_timestamp)
    * the dead first-write value (free dead-value control)
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_first`, `_second`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** nexus catalog #14 pc / execution-order continuity (e2e gold); the catalog records its program_structure as 'Hazard chain (read-before-write register hazard routed to a store)'. It is also the register-side analogue of pico #7 P-CLK, which no VM has ever tested.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | probe | not_determined | Shipped: the guest is guests/lacuna_seeds/src/bin/st_hazard_chain.rs (fib for Whole program) with a row in the SEEDS table of evaluation/scripts/run_lacuna_pico.py, and the published corpus carries its candidates. this seed is pinned to ADD/LD in that table, which are opcodes pico binds, so its published yield of zero is not evidence about the structure. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_hazard_program` in crates/prover/src/lacuna_eval.rs: ADDI x28,v1; ADDI x29,v2; ADD x30,x28,x0; ADD x30,x29,x0; ADD x11,x30,x0; commit tail; add_halt. Two write-backs to x30 at two static pcs, so nth=-1 suffices and the broken SEEN counter is not in the way. Report site 1 (dead) and site 2 (live) as separate classes. |
| ceno | triv | probe | not_determined | Expressible with a new `build_hazard_program` using encode_rv32: ADD x4,x2,x0 ; ADD x4,x3,x0 ; SW x4,0(x6) ; commit tail. This is the register-side test of ceno's prev_rd_value (declared UInt::new_unchecked at insn_base.rs:313) and prev_rd_ts (:312), and the shape that makes the already-accepted rd_prev_plus1 ORD-O1 rows potentially output-changing. |
| nexus | triv | probe | not_determined | Expressible with a new `build_hazard_elf`: enc(ADD,5,1,0) ; enc(ADD,5,2,0) ; wou(5,7). Two writes to x5, then the output store. |
| openvm | triv | probe | not_determined | Two ADD x5,x1,x0 / ADD x5,x2,x0 words in build_words, then REVEAL x5. openvm's writes_aux.prev_data (rdwrite.rs:271-278, alu.rs:295-297) and prev_timestamp are real record fields and are degenerate in every current seed. |
| risc0 | triv | probe | not_determined | Two R-type writes to t2 in build_seed, then the existing sw to GLOBAL_OUTPUT_ADDR. writeRd.prevData and writeRd.prevCycle are reachable record fields. |
| zisk | triv | probe | not_determined | Expressible with a new guest bin with the same two-`mv`-to-one-register inline asm as pico's st_hazard_chain.rs, then commit_slice. Encoding only. |

### `st_control_flow` -- Control flow

x = c ? v1 : v2; commit(x) -- with the mutation site pinned to the instruction PRODUCING c; plus a data-identical variant that changes only the trace.

```
// (a) data-divergent
let c = read(); let v1 = read(); let v2 = read();
let x = if black_box(c) != 0 { black_box(v1) } else { black_box(v2) };
commit(x);
// (b) DATA-IDENTICAL, trace-divergent -- isolates the pc binding from the value binding
let c = read();
if black_box(c) != 0 { for _ in 0..K { black_box(0u64); } }
commit(0xC0FFEEu64);
```

* **Constraint surface.** S11 the branch chip's comparison columns and the taken/not-taken -> next_pc transition. It is the only structure in which a forged value changes WHICH ROWS EXIST -- the executed-instruction multiset, the clk chain, per-chip row counts and the shard-boundary public values. Variant (b) reaches the cycle/pc public-value chain with the DATA output held fixed.
* **Observability.** (a) the selected value is committed directly. (b) ceno commits end_cycle and end_pc as flattened public values (scheme.rs:94,116,176), openvm chains initial/final pc in verify_segments, risc0's seal carries isTerminate, pico/sp1 chain last_timestamp and the chunk count -- so a pure trip-count divergence changes a committed public value on at least four targets with no data word moving.
* **Record fields required.**
    * branch condition operand value
    * next_pc (a committed WitIn on ceno only for branching circuits -- StateInOut::construct_circuit(branching=true), insn_base.rs:42-44 -- so a straight-line seed has no next_pc column at all; sp1 BranchEvent.next_pc; nexus Step.next_pc REACHABLE in prover2, DEAD in prover v1; risc0 didBranch/newPc; pico wb_perturb::next_pc EXISTS at instruction.rs:954 and is never called by lacuna_eval)
    * executed-instruction multiset / row counts
* **Opcode axis.** `branch`, `deconfound_min`
* **Variant suffixes.** `_datadiv`, `_dataident`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** nexus catalog #14 under its alternative reading, which the catalog itself records as 'Control flow'; adjacent to pico #20 via the unused next_pc operator
* **Site role.** `selector` -- Selector role on the instruction PRODUCING the branch condition.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | probe | not_determined | Shipped: the guest is guests/lacuna_seeds/src/bin/st_control_flow.rs (fib for Whole program) with a row in the SEEDS table of evaluation/scripts/run_lacuna_pico.py, and the published corpus carries its candidates. this seed is pinned to ADD/LD in that table, which are opcodes pico binds, so its published yield of zero is not evidence about the structure. |
| sp1 | mod | probe | not_determined | Expressible with a new `build_cf_program`: ADDI x28,cond; ADDI x29,v1; ADDI x30,v2; BEQ x28,x0,+8; ADD x11,x29,x0; JAL x0,+8; ADD x11,x30,x0; commit tail. Opcodes BEQ(40)/JAL(46) exist; execute_branch (vm.rs:525-552) adds raw op_c with wrapping_add (pass (-16i64) as u64 for a backward branch), JAL sign-extends 21 bits (vm.rs:487). HARD REQUIREMENT: keep the seed memory-read-free or a divergent path exhausts the phase-1 mem_reads oracle and hits unreachable!() at vm.rs:749. Add a max-cycle abort -- clk_end comes from the phase-1 chunk header (vm.rs:268) so there is no cycle guard today. |
| ceno | triv | probe | not_determined | Expressible with a new `build_cf_program` using encode_rv32 for BEQ/BNE + JAL. IMPORTANT: this structure LITERALLY CREATES the field -- next_pc is a committed WitIn only for branching circuits (StateInOut::construct_circuit(branching=true), insn_base.rs:42-44), so a straight-line seed has no next_pc column to perturb. |
| nexus | triv | probe | not_determined | Expressible with a new `build_cf_elf` with enc(BEQ,..) and enc(JAL,..). Step.next_pc is REACHABLE in prover2 (branch_eq/mod.rs:184, jal/mod.rs:99->111) and DEAD in prover v1 -- a free cross-crate contrast worth recording. |
| openvm | mod | probe | not_determined | Requires adding BEQ/JAL words to build_words. CAVEAT: the perturbation applies in PREFLIGHT only; openvm's metered pass runs UNPERTURBED and sizes the record arenas, so a divergence that lengthens execution overflows honestly-estimated heights and surfaces as EXECFAIL rather than a verdict. Keep both arms the same length. |
| risc0 | triv | probe | not_determined | Requires adding insn_b (branch) and insn_j to the built-in assembler in prove/lacuna_eval.rs; two arms writing different values to t2 before the existing sw to GLOBAL_OUTPUT_ADDR. Keep both arms equal-length so the segment po2 does not move. |
| zisk | triv | probe | not_determined | Expressible with a new guest bin with the same black_box'd if/else as pico's st_control_flow.rs, committing the selected value. Encoding only; budget 1 seed. |

### `st_provenance_chain` -- Provenance chain

One value carried through the maximum number of distinct constraint surfaces before it is committed -- the composition test that converts 'the cell is unbound' into 'the forgery is exploitable'.

```
// depth 2 (portable, register-only)
let t = a OP1 b;      // OP1 = the opcode suspected under-constrained (e.g. SRLW)
let x = t OP2 c;      // OP2 = a chip with tight operand decomposition (ADD, SLT, MUL)
commit(x);
// depth 4 (through memory; requires a hooked memory-read side on sp1/zisk)
let t = a OP1 b; store(p, t); let u = load(p); let v = u OP2 c; commit(v);
```

* **Constraint surface.** The operand-READ side of a chip that did not produce the value -- limb decomposition and range checks applied to an incoming operand, usually tighter than the same chip's result binding -- and, at depth 4, the memory argument in series. The measurement is the HOP AT WHICH the candidate flips ACCEPT->REJECT, which localises the binding edge.
* **Observability.** OP2's result is committed; the forged t must traverse the register bus and OP2's own operand columns to get there.
* **Record fields required.**
    * operand read value at the consumer (maximises k, the number of read points of one record field in G -- the L1 enumeration space)
    * load delivered value at depth 4
    * result value at the producer
* **Opcode axis.** `deconfound_min`, `consumer_set`
* **Variant suffixes.** `_d2`, `_d4`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #3 SRLW/SRAW extended one hop -- the direct test of whether the ONE opcode whose write-back survives on pico still survives an arithmetic consumer or the memory argument. Also the only openvm shape in which a value-carrying core record (Rv32JalLuiCoreRecord.rd_data) feeds a downstream chip.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Two new guests: pv_chain2.rs (t = a SRLW b; x = t + c; commit(x)) and pv_chain4.rs (t = a SRLW b; store(p,t); u = load(p); v = u + c; commit(v)). SEEDS rows with LACUNA_OPS=SRLW,SRAW,ADD,LD. This is the direct follow-on to pico's 24 accepted SRLW cases and the fix for the structure/opcode confound. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_chain_program`: OP1 x30,x28,x29 ; OP2 x31,x30,x27 ; ADD x11,x31,x0 ; commit tail. Register-only depth 2 is the portable variant. The depth-4 through-memory variant is uninformative on sp1 until the CoreVM::mr hook lands (phase-1 oracle hands the later load the honest value). |
| ceno | triv | probe | not_determined | Expressible with a new `build_chain_program`: OP1 x4,x2,x3 ; OP2 x5,x4,x2 ; SW x5,0(x6). Depth-4 variant adds SW/LW between them; ceno re-executes rather than oracling, so the deep variant is coherent here. |
| nexus | triv | probe | not_determined | Expressible with a new `build_chain_elf`: enc(OP1,5,1,2) ; enc(OP2,6,5,1) ; wou(6,7). Depth-4 adds SW/LW over the ram_image word. |
| openvm | triv | probe | not_determined | Chain OP1 then OP2 in build_words before the REVEAL. The MOST VALUABLE openvm variant is LUI -> store -> load -> REVEAL, because Rv32JalLuiCoreRecord.rd_data (jal_lui/core.rs:198) is the one openvm core record with a result field and this is the only shape in which it feeds a downstream chip. |
| risc0 | triv | probe | not_determined | Two chained R-type instructions in build_seed before the sw to GLOBAL_OUTPUT_ADDR; depth-4 adds a scratch sw/lw pair. |
| zisk | mod | probe | not_determined | Expressible with a new guest bin chaining two inline-asm ops. Depth-4 through memory is uninformative on zisk for the same reason as sp1 (mem_reads oracle), unless the read side is hooked. Budget: depth-2 only, 2-3 opcode pairs. |

### `st_loop_repeat` -- Loop repeat

One static pc executed N times -- the only way to exercise the nth component of the (pc, nth, mu) site key with a purpose-built seed.

```
let a = read();
let mut s = 0u64;
for _ in 0..N { s = s.wrapping_add(a); }   // ONE static pc, N dynamic write-backs
commit(s);
// run at N in {16, 256, 4096}; arm (pc_body, nth = j) for j = 0..N-1 and also nth = -1
```

* **Constraint surface.** S16 lookup and range-check MULTIPLICITY accounting, plus per-row identity (which record entry lands on which row) and the pc/clk continuity chain. Forging one of N identical rows moves one multiplicity from a bucket of count N into a new bucket of count 1; forging all N moves the whole bucket. Comparing the two verdicts separates per-row constraints from aggregate bus constraints.
* **Observability.** The accumulator is committed directly, and the divergence is j-dependent, which doubles as a consistency check that nth arming actually works.
* **Record fields required.**
    * record INDEX rather than a field -- the second half of the arming key
    * lookup/range multiplicities implied by the repeated row
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_n16`, `_n256`, `_n4096`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** nexus catalog #14 pc not bound to execution order -- reordering which record entry lands on which row is only meaningful when several entries share a pc

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest lp_accum.rs with a black_box'd loop of N iterations over one wrapping_add, N from stdin. pico's site key already carries the occurrence index (occ[i], lacuna_eval.rs:461-467) and `nth` is honoured, so both nth=j and nth=-1 arms run today with no Rust change. |
| sp1 | mod | probe | not_determined | **Blocked:** global SEEN counter not reset between the two CoreVM passes New `build_loop_program` (ADDI counter, ADD accum, BNE backward). Seed is trivial; the BLOCKER is that nth>=0 is unusable because SEEN (crates/core/executor/src/vm.rs:70) is a single global counter reset only in `with()` while every candidate runs TWO CoreVM passes (SplicingVM then TracingVM). Fix: reset SEEN at CoreVM construction (vm.rs:255-274) or key it per pass. Until then run nth=-1 only. |
| ceno | mod | probe | not_determined | **Blocked:** three emulation passes share one global occurrence counter New `build_loop_program` with a BNE backward branch. Same nth blocker: ceno emulates three times per candidate (driver FullTracer pre-pass, PreflightTracer, StepReplay in generate_witness, e2e.rs:851-903), so wb_perturb must count per pass before nth>=0 is sound. Run nth=-1 until then. |
| nexus | mod | probe | not_determined | **Blocked:** k_trace emulates twice with one global counter New `build_loop_elf` with a BEQ/BNE backward branch. k_trace emulates twice (Harvard then Linear::from_harvard), so nth>=0 needs a per-pass counter in vm/src/trace.rs wb_perturb; nth=-1 works today. |
| openvm | mod | probe | not_determined | Requires adding a backward BNE to build_words. The perturbation is preflight-only so a per-pass counter is probably unnecessary, but the metered pass sizes arenas honestly -- verify that a loop whose length does not change still fits. NOT DETERMINED whether nth>=0 is sound here; confirm before claiming per-iteration granularity. |
| risc0 | triv | probe | not_determined | Requires adding insn_b to the assembler and emit a counted loop in build_seed. risc0's hook already supports nth (arming key is (static pc, n-th execution), nth<0 arms every execution), so per-iteration granularity works today -- risc0 and pico are the only two targets where it does. |
| zisk | mod | probe | not_determined | Expressible with a new guest bin with a counted loop, N from the input slice. NOT DETERMINED whether ZISK_WB_NTH semantics are per-pass; verify against the multi-pass witness generation before using nth>=0. Budget: N=16 only. |

### `st_multishard` -- Cross-shard continuation

Produce the forged value in shard/segment/chunk i, consume it in j > i.

```
static mut CARRY: u64 = 0;
let a = read();
let mut s = 0u64;
for _ in 0..N_BIG { s = s.wrapping_mul(3).wrapping_add(a); }   // fills shard i
unsafe { write_volatile(&raw mut CARRY, s); }
for _ in 0..N_BIG { black_box(0u64); }                          // pads into shard j
unsafe { commit(read_volatile(&raw const CARRY)); }
// size N_BIG against the target's boundary, or lower it: pico CHUNK_SIZE,
// sp1 SHARD_SIZE (opts.rs:118), risc0 po2, openvm segment params, ceno shard config
```

* **Constraint surface.** S15 the local->global memory bus, the chained public values (committed digest, pc, timestamp, previous_init/finalize address partition, memory root) and the SUMMED per-shard cumulative sum. Every candidate on every target today is single-shard, so sp1's cross-shard machinery (verify.rs:453-462 digest chain, :497-509 summed global cumulative sum) is verified against a one-element sequence.
* **Observability.** The value read back in the later shard is committed directly; the chained public values are themselves committed objects on every target.
* **Record fields required.**
    * segment-boundary state -- on zisk EmuTrace.start_state{pc,c,step,regs[32]}, last_c and steps are PER-CHUNK and are the only value-carrying record fields besides mem_reads; a single-chunk run makes them the honest boot state
    * ceno StepRecord.memory_op.value.after/.addr become committed ShardRam columns ONLY when the partner access is in another shard (ShardContext::record_send_without_touch emits a RAM record only when !is_first_shard())
    * pico CpuEvent.chunk; sp1 shard index and the per-shard public-value chain
* **Opcode axis.** `deconfound_min`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** the ceno cross-shard free-tag / count-only self-loop, recorded in the project ledger as VULNERABLE with a 7-shard e2e driver proven and the forge explicitly DEFERRED -- the only known-vulnerable surface in the ledger with no executed forgery

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | probe | not_determined | Expressible with a new guest ms_carry.rs with a tunable loop, driven with CHUNK_SIZE / CHUNK_BATCH_SIZE / SPLIT_THRESHOLD (vm/src/emulator/opts.rs:47-58) lowered so the store and the load straddle a chunk boundary. Site filtering must become chunk-aware -- the record already carries event.chunk. Watch max_cycles = 500_000 (lacuna_eval.rs:102-107). |
| sp1 | mod | probe | not_determined | Expressible with a new long `build_loop_carry_program`, or lower SHARD_SIZE via the env override at crates/core/executor/src/opts.rs:118. The driver already assembles multi-shard proofs correctly (lacuna_eval.rs:398-417). This is the only way to make SP1Verifier's prev_committed_value_digest chain (verify.rs:453-462) and the SUMMED global cumulative sum (:497-509) load-bearing rather than one-element. |
| ceno | mod | probe | not_determined | A multi-shard seed turns on the ShardRam table family: StepRecord.memory_op.value.after/.addr become committed columns only when the partner access is in another shard (ShardContext::record_send_without_touch emits a RAM record only when !is_first_shard()). ceno's own blocked list names this as its first missing item. Needs a loop seed sized against the shard config plus shard-aware site selection. |
| nexus | **BLOCK** | probe | not_determined | **Blocked:** NOT DETERMINED whether prover2 supports multi-segment continuation at all NOT DETERMINED. prover2's BASE_COMPONENTS list carries no continuation/segment glue that I could confirm read-only, and the enumerated pipeline is a single k_trace + single prove. Investigate before scheduling; do not ship a shard seed on the assumption that shards exist. |
| openvm | mod | probe | not_determined | Requires lowering the segmentation params so the loop seed produces >1 segment, then perturb in segment i and consume in j. verify_segments (crates/vm/src/arch/vm.rs:1154,1268-1319) chains final_memory_root and the pc across segments, which is the surface. RISK: the metered pass sizes segments honestly, so a divergence that changes segment boundaries EXECFAILs. |
| risc0 | mod | probe | not_determined | Requires lowering the segment po2 (currently 14) so the loop seed spans >1 segment; the InstSuspend/InstResume path and rootIn/rootOut chaining become live. The driver proves a single segment today, so multi-segment assembly and verification need adding to lacuna_eval.rs. |
| zisk | hard | probe | not_determined | **Blocked:** full VADCOP aggregation errors during GENERATE_VADCOP_FINAL_PROOF on these seeds; the no-aggregation path still checks Global Constraint #0 but not the full cross-instance chain zisk is the target where this structure creates fields that do not otherwise exist: EmuTrace.start_state{pc,c,step,regs[32]}, last_c and steps are PER-CHUNK and are the only value-carrying record fields besides mem_reads. But full VADCOP aggregation is already blocked on the tiny seeds (the run used -a), and at ~73 s/candidate a big-program seed is expensive. Use examples/big-program as the starting shape and budget a handful of candidates. |

### `st_hint_advice` -- Nondeterministic advice

commit(a value that came from the hint/input channel) -- the structure whose expected verdict is an ACCEPT that is NOT a bug, and therefore the evaluation's only positive control.

```
let h: u64 = read_hint();     // hint / hintstore / host-IO -- free by design on most VMs
commit(h);
// paired control, same seed family:
let h: u64 = read_hint(); let i = read_public_input();
assert!(h.wrapping_mul(h) == i);   // in-guest check
commit(h);
```

* **Constraint surface.** S18 the boundary of 'spec'. A hint value is a free column BY DESIGN, so an accepted output-changing mutation here is a true accept and a false finding. The checked variant asks the real question: does the in-guest check bind the value in the CIRCUIT, or only in the executor?
* **Observability.** Committed directly. Already reachable with the existing hooks on at least two targets: risc0's do_ecall_read routes through the hooked write_reg (emu.rs:952) and openvm's hintstore goes through the hooked tracing_write (hintstore/mod.rs:483).
* **Record fields required.**
    * host nondeterminism (openvm Rv32HintStoreVar.data set at mod.rs:481, written verbatim into cols data[0..4] at mod.rs:606, with a byte-pair range check as its ONLY AIR constraint; risc0 ReadWordWitness.io.value listed as REACHABLE and unconstrained; sp1 hint pages initialised through the unconstrained MemoryInitialize value column; zisk whole input region via mem_reads; ceno HintsTable)
* **Opcode axis.** `alu_bound_reference`
* **Variant suffixes.** `_unchecked`, `_checked`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** ceno catalog #22 HintsTable limb range is the family, but it is graded L3 (needs limb values a u32 record cannot hold), so the honest expectation is CALIBRATION, not a finding

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | calibration | ACCEPT | Expressible with a new guest hint_passthrough.rs committing a value read from stdin with no in-guest check, plus a checked twin. Note pico's stdin already feeds every seed's operands, so pico is ALREADY sitting on this hazard -- the seed names it. If pico binds stdin to no public value, every operand-setup perturbation is formally an accept-that-is-not-a-bug, and this is the seed that detects it. |
| sp1 | mod | calibration | ACCEPT | Wire SP1Stdin (currently always empty at crates/prover/src/lacuna_eval.rs:636,665,696,737 via minimal_executor.with_input, prove.rs:55-57) and add a seed that reads a hint word and commits it. sp1 hint pages are initialised through the very MemoryInitialize chip whose value column is unconstrained for addr != 0 (utils/prove.rs:159-167), so this is also the cheapest sp1 positive control. |
| ceno | mod | calibration | ACCEPT | Seed reading from the hint region and committing it. ceno has a HintsTable (catalog #22) and a hint memory region; the work is wiring hint input into the driver's Program image next to lacuna_eval.rs:84. |
| nexus | mod | calibration | ACCEPT | k_trace already takes private/public input slices (`k_trace(elf, &[], &[], &[], 1)` at lacuna_eval.rs); pass a private input and add a seed that reads it via the ECALL private-input path (prover v1 syscall.rs:47 -> :60,:65,:68 shows the record field) and routes it to `wou`. |
| openvm | triv | calibration | ACCEPT | Add a HINT_STOREW word to build_words and REVEAL the hinted register. Rv32HintStoreVar.data (hintstore/mod.rs:313, set at :481, written verbatim into cols data[0..4] at :606) has exactly ONE AIR constraint -- the byte-pair range check at mod.rs:235 -- and the write already goes through the hooked tracing_write at mod.rs:483. Expect an ACCEPT that must be reported in a CALIBRATION column, never as a finding. |
| risc0 | triv | calibration | ACCEPT | Requires adding an ecall READ to build_seed and sw the read word to GLOBAL_OUTPUT_ADDR. do_ecall_read already routes through the hooked write_reg (emu.rs:952) and ReadWordWitness.io.value is listed as REACHABLE and unconstrained -- so this is a one-instruction positive control. |
| zisk | triv | calibration | ACCEPT | The existing guest already reads its operands from ziskos::io::read_input_slice, so a hint seed is a 3-line guest that commits an input word unchanged. Highest information per zisk candidate: it tells you whether zisk's whole input region (delivered via mem_reads) is bound to a public value at all, which decides whether the corpus-wide oracle can be 'output != honest' or must be 'output != spec(input)'. |

### `st_finalize_only` -- Finalize-only write

Write a value that is never read again, then commit a CONSTANT -- the only path from the forged value to the public output is the finalise boundary.

```
static mut SINK: u64 = 0;
let a = read(); let b = read();
let x = a OP b;
unsafe { write_volatile(&raw mut SINK, x); }   // never read again
commit(0xC0FFEEu64);                            // the DATA output is constant
// register-finalise variant: let _y = a OP b;  (never read at all)  commit(CONST);
```

* **Constraint surface.** S9 the memory/register-finalise boundary row and, on the state-committing VMs, the final image / Merkle root. The ONLY structure in which the forged value reaches the public output without traversing any consumer chip, operand bus or commit chip.
* **Observability.** SPLIT, and the split IS the result. First-class observable on openvm (verify_segments chains final_memory_root, vm.rs:1268-1319, and MemoryDimensions indexes address space 1, so the final REGISTER FILE is inside the committed root) and risc0 (globals.rootOut from preflight/paging.rs:189). On nexus and zisk only a write INTO the committed output REGION is observable, which is st_pv_plumbing, not this. On pico, sp1 and ceno nothing about final state is public, so the same seed is a deliberate negative control and an unbound finalise write-back must NOT score as an accepted case.
* **Record fields required.**
    * memory-finalize value (pico MemoryInitializeFinalizeEvent finalize rows; sp1 F_MEM_FINAL_VALUE, implemented at prove.rs:152 and NEVER ARMED; risc0 PageOutPartWitness.data[i] and .cycle[i])
    * register-finalize value / final register page
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_mem`, `_reg`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_v2`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | **BLOCK** | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | **Blocked:** no final-state object in the public output; an accepted unbound finalize write must NOT score as an accepted case Ship the seed as a declared NEGATIVE CONTROL with expected_verdict recorded, and exclude it from coverage counts. Nothing about final memory is public on pico -- only committed_value_digest, last_finalize_addr_limbs (an ADDRESS) and pc/chunk bookkeeping (public_values.rs:16, riscv.rs:562-597). |
| sp1 | **BLOCK** | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | **Blocked:** no final-state object in the public output Negative control only. F_MEM_FINAL_VALUE (prove.rs:152, never armed) can move the finalize row, but nothing about final RAM is public -- the observable is committed_value_digest. Arm it anyway as the third leg of st_initial_state, not as a structure of its own. |
| ceno | **BLOCK** | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | **Blocked:** final RAM not record-carried and not a public output; shard_rw_sum is bus bookkeeping Negative control only. Final RAM is built from vm.peek_memory rather than from the record, and the ceno public value is public_io_digest. A perturbation does move shard_rw_sum, a genuine public value whose semantics is bus bookkeeping -- report it, do not claim it as an output forgery. |
| nexus | **BLOCK** | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | **Blocked:** output is a fixed region, not the whole final state Negative control for an ARBITRARY address. nexus's public output is the final content of a FIXED output region (PubMemoryBoundary, written by `wou`), so only a write into that region is observable -- which is st_pv_plumbing, not this structure. Ship the arbitrary-address form as a control. |
| openvm | triv | probe | not_determined | Seed: OP into a register, SW it to a scratch address never read again, REVEAL a constant. verify_segments chains final_memory_root (crates/vm/src/arch/vm.rs:1268-1319) and MemoryDimensions::label_to_index indexes ALL address spaces from ADDR_SPACE_OFFSET=1, so even the final REGISTER FILE is inside the committed root -- the register-only variant (a dead OP, REVEAL a constant) is observable too. Acceptance must read the memory-root column, not only the revealed word. |
| risc0 | triv | probe | not_determined | Seed: sw to a scratch address never read, then sw a CONSTANT to GLOBAL_OUTPUT_ADDR. globals.rootOut comes from the final image digest (preflight/paging.rs:189) and the tree's own hook comment (preflight/emu.rs:1464-1467) states write_reg's value reaches the paged-out register page and therefore rootOut. The driver already records rootOut as committed_digest -- promote it into the acceptance predicate for this structure. |
| zisk | **BLOCK** | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | **Blocked:** output is a fixed region, not the whole final state Negative control for an arbitrary address, same reason as nexus: the committed public value is the output memory region the output/RomData SM commits, not the whole final image. |

### `st_indirect_jump` -- Indirect jump

JALR through a register the mutation can move -- a two-entry jump table so both targets are real code.

```
#[inline(never)] fn f() -> u64 { V1 }
#[inline(never)] fn g() -> u64 { V2 }
let sel = read();
let fp: fn() -> u64 = if black_box(sel) != 0 { f } else { g };  // site: the write-back carrying the TARGET
commit(fp());
// asm variant for the bit-0 question: la t0, target ; jalr ra, t0, 0   with mu(t0) = t0 ^ 1
```

* **Constraint surface.** S12 the pc transition computed from a register, the ROM/program-table lookup at the forged pc (is the fetch relation total, and does it reject a misaligned or non-instruction pc?), and the RISC-V requirement that JALR clears bit 0. S13 in passing, via the link register rd = pc+4.
* **Observability.** The value returned by the redirected callee is committed. The two-entry table bounds the divergence so both paths reach the same commit, keeping EXECFAIL low.
* **Record fields required.**
    * indirect target / rs1_val (openvm Rv32JalrCoreRecord.rs1_val is a real record field at jalr/core.rs:178 -> cols rs1_data[0..4]; risc0 InstJalrWitness.rs1.value REACHABLE)
    * link value rd = pc+4 (openvm re-encodes from_pc into rd_data[0..3] at core.rs:311-318 -- TWO independent copies of the pc in one row the AIR never equates)
    * next_pc
* **Opcode axis.** `jump`
* **Variant suffixes.** `_table`, `_bit0`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #20 JALR bit-0 not cleared -- the single catalog entry whose reachability layer is recorded as undetermined in RECORD_PERTURBATION_REACHABILITY.md
* **Site role.** `address` -- Address role on the JALR target register, with one declared exception: xor_b0 is ALLOWED here and only here, because clearing bit 0 is the RISC-V requirement the structure exists to test (pico catalog #20).

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest ij_table.rs: two #[inline(never)] fns, a function pointer selected by a black_box'd stdin value, commit the callee's return value. SEEDS row with LACUNA_OPS=JALR. Additionally wire the ALREADY-WRITTEN but never-called wb_perturb::next_pc operator (emulator/mod.rs:134-142, called at instruction.rs:954, armed by with_pc at mod.rs:113-132) as a new PC-* template family in menu_all() (lacuna_eval.rs:131-146) -- lacuna_eval never calls with_pc; only lt/tests.rs:3618 does. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_jalr_program`: load one of two target pcs into a register, JALR through it, both targets write different values into x11 before the commit tail. Opcode::JALR exists; execute_jump (vm.rs:483-522) writes the link through the same rw choke point, and jalr_events are already scanned by writeback_sites (lacuna_eval.rs:265-270). |
| ceno | triv | probe | not_determined | Expressible with a new `build_jalr_program` with encode_rv32; the JALR circuit is registered (rv32im.rs:280-333). Two arms writing different words into the commit buffer. |
| nexus | triv | probe | not_determined | Expressible with a new `build_jalr_elf`: enc(BuiltinOpcode::JALR,...) exists (instruction.rs:119). Two arms, both reaching the `wou` output store. |
| openvm | triv | probe | not_determined | Requires adding a JALR word to build_words. openvm is the richest target for this: Rv32JalrCoreRecord.rs1_val is a real record field (jalr/core.rs:178 -> cols rs1_data[0..4] at :310) AND from_pc is re-encoded into rd_data[0..3] (:311-318) -- two independent copies of the pc in one row the AIR never equates (openvm's own audit tags this BIND-I2). Perturb rs1_val, not from_pc. |
| risc0 | triv | probe | not_determined | Requires adding insn_i-form jalr to the built-in assembler and a two-target table; both arms sw a different word to GLOBAL_OUTPUT_ADDR. do_inst_jalr already routes its link write through the hooked write_reg (emu.rs:866). |
| zisk | mod | probe | not_determined | Expressible with a new guest bin with a function-pointer call through a black_box'd selector. RV64 and the ZisK transform layer (ROM/fusion) make the fetch side different from the others -- worth one seed, but expect the ROM lookup to bind the target. Budget 1-2 candidates. |

### `st_pc_imm_value` -- PC-immediate value

commit(auipc), commit(lui imm), commit(jal link) -- values whose only source is the pc or the committed program text, never a register.

```
let x: u64; unsafe { asm!("auipc {x}, 0",       x = out(reg) x); } commit(x);
let y: u64; unsafe { asm!("lui   {y}, 0x12345", y = out(reg) y); } commit(y);
let z: u64; unsafe { asm!("jal   {z}, 1f", "1:", z = out(reg) z); } commit(z);
```

* **Constraint surface.** S13 value derivation from the pc column and from the program table's immediate, with no register operand in the relation. It asks a question no other structure asks -- is rd bound to the COMMITTED PROGRAM? -- and the answer route is the preprocessed program/fetch bus rather than the register bus.
* **Observability.** Committed directly. Today AUIPC/LUI sites DO exist inside the seeds (openvm 0x00 LUI, ceno 0x8000000 LUI, risc0's li expansion) but in every case they carry a POINTER, so forging them traps the emulator and lands as EXECFAIL rather than a verdict -- ceno reports 702 EXECFAILs, mostly from exactly this. Making the pc/immediate-derived word the committed DATUM is the only way to get a clean verdict out of the site.
* **Record fields required.**
    * pc-derived rd (openvm Rv32AuipcCoreRecord{from_pc, imm} has NO result field -- rd is recomputed in the trace filler, a predicted clean negative)
    * Rv32JalLuiCoreRecord.rd_data -- the ONLY openvm rv32im core record with a result field, so on that target this is the single most coherent forgery site in the whole catalog
    * program-table immediate
* **Opcode axis.** `pc_imm`
* **Variant suffixes.** `_auipc`, `_lui`, `_jal`
* **Over-propagation risk.** high
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest pc_imm.rs with three inline-asm blocks (auipc, lui, jal link) each committing its own result. SEEDS rows with LACUNA_OPS=AUIPC, LUI, JAL. fib already has 150 AUIPC sites with no dedicated seed. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_utype_program` using Opcode::LUI/AUIPC (execute_utype, vm.rs:556-563, already routes through rw and tracing.rs:876 already syncs its event) plus a JAL link write. UTypeChip and UTypeUser are in the machine and have never been instantiated by any sp1 candidate. |
| ceno | triv | probe | not_determined | Expressible with a new `build_pcimm_program`: the seed ALREADY contains a LUI at 0x8000000 whose site is enumerated, but it carries a pointer and lands as EXECFAIL. Make the LUI/AUIPC result the committed DATUM instead (LUI x4,imm ; SW x4,0(x6)) to convert those EXECFAILs into verdicts. |
| nexus | triv | probe | not_determined | Expressible with a new `build_pcimm_elf` using enc(BuiltinOpcode::LUI/AUIPC/JAL,...) (instruction.rs:102-109), routing the result to `wou`. |
| openvm | triv | probe | not_determined | Requires adding a LUI whose result is REVEALed directly. Rv32JalLuiCoreRecord.rd_data (jal_lui/core.rs:198) is the ONLY rv32im core record with a result field and is hook site 2, so this is the one openvm shape where a fully coherent record+memory forgery reaches the verifier instead of dying in the prover's memory offline check. AUIPC is the paired predicted NEGATIVE (Rv32AuipcCoreRecord{from_pc,imm} has no result field; the filler recomputes rd). |
| risc0 | triv | probe | not_determined | The assembler's li expansion already emits lui; add explicit lui/auipc/jal seeds that sw the produced word to GLOBAL_OUTPUT_ADDR. do_inst_lui (emu.rs:889), do_inst_auipc (:901) and do_inst_jal (:845) all route through the hooked write_reg. |
| zisk | mod | probe | not_determined | Expressible with a new guest bin with inline-asm auipc/lui committing the result. RV64 + ZisK's ROM/transform layer means AUIPC may be fused; check the transpiled ROM before interpreting the verdict. Budget 1 seed. |

### `st_fanout_read` -- Fan-out read

One definition, two uses at two different cycles: t = a OP b; u = t OP1 k1; v = t OP2 k2; commit(u ^ v).

```
let a = read(); let b = read();
let t = a OP b;
let u = t.wrapping_add(K1);
let v = t ^ K2;
commit(u ^ v);
```

* **Constraint surface.** Whether the register BUS binds the read value, or only the producing chip does. Two chip rows consume the same register value at two clks; in several VMs each consumption is split again across two independent column groups the AIR never equates. This is the program-level way to express an L1 per-read-point split on ports that have no witness-generation seam.
* **Observability.** Both uses feed the commit, so a forgery that survives at one read point and not the other still changes the committed output.
* **Record fields required.**
    * operand read value at read point j (nexus BIND-V1: Block.regs is read independently by the execution component (BVal/CVal, add/mod.rs:118,131) and by RegisterMemory (Reg1Val/Reg2Val, register_memory/trace.rs:161,246), joined only through rel-inst-to-reg-memory; openvm BaseAluCoreRecord.b/c versus the adapter read aux records; pico CpuEvent.b/c versus a_record/b_record/c_record)
* **Opcode axis.** `deconfound_min`, `consumer_set`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest fanout.rs: let t = a OP b; let u = t.wrapping_add(K1); let v = t ^ K2; commit(u ^ v); with black_box around t to stop CSE. SEEDS row; no Rust change. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_fanout_program`: OP x30,x28,x29 ; ADD x5,x30,x27 ; XOR x6,x30,x26 ; XOR x11,x5,x6 ; commit tail. Two consumers of x30 at two clks. |
| ceno | triv | probe | not_determined | Expressible with a new `build_fanout_program` with encode_rv32, two consumers of x4 before the SW. |
| nexus | triv | probe | not_determined | Expressible with a new `build_fanout_elf`. This is the target the structure was designed for: BIND-V1 says Block.regs is read independently by the execution component (BVal/CVal, add/mod.rs:118,131) and by RegisterMemory (Reg1Val/Reg2Val, register_memory/trace.rs:161,246), joined only through rel-inst-to-reg-memory. |
| openvm | triv | probe | not_determined | Two consumer words in build_words before the REVEAL; tests BaseAluCoreRecord.b/c versus the adapter read aux records as two landing points of one value. |
| risc0 | triv | probe | not_determined | Two consumer R-type instructions in build_seed before the sw to GLOBAL_OUTPUT_ADDR. |
| zisk | mod | probe | not_determined | Expressible with a new guest bin with two black_box'd consumers of one value. Cheap to write, expensive to run; budget 1 seed x 3 mu. |

### `st_reg_alias` -- Register aliasing

OP rd, rs1, rs1 and OP rd, rd, rd -- the same register read twice, and read-and-written in one cycle.

```
let a = read();
let mut x = a;
x = x.wrapping_mul(x);     // rd == rs1 == rs2
commit(x);
```

* **Constraint surface.** Within-row ordering of the register memory argument: read-before-write at ONE address at ONE clk, with the two reads and the write distinguished only by subcycle, plus the deduplicated second read. risc0 has dedicated DualReg::sameReg and rs2Data columns that are trivial unless rs1==rs2; ceno builds rs1/rs2/rd as three ReadOp/WriteOp records with SUBCYCLE_RS1/RS2/RD offsets that must not collide.
* **Observability.** The result is committed as usual.
* **Record fields required.**
    * register access records collapsed onto one address: the write's prev_value/prev_timestamp and both reads' values now refer to the same cell
    * subcycle offsets within one instruction
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_rs1rs2`, `_rdrs1rs2`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest reg_alias.rs: x = x.wrapping_mul(x) with black_box, and an asm variant `add {x}, {x}, {x}` giving rd==rs1==rs2. One SEEDS row per opcode of interest. |
| sp1 | triv | probe | not_determined | One-line variant of build_op_program: Instruction::new(op, 30, 30, 30, false, false) instead of (op, 30, 28, 29, ...). Tests whether the second read's prev_timestamp is the first read's or the pre-instruction one. |
| ceno | triv | probe | not_determined | One-line variant of build_op_program: encode_rv32(op, rd=4, rs1=4, rs2=4). ceno builds rs1/rs2/rd as three ReadOp/WriteOp records with SUBCYCLE_RS1/RS2/RD offsets that must not collide -- this is the only shape that tests that. |
| nexus | triv | probe | not_determined | One-line variant: enc(op, 5, 5, 5). Reg1Addr/Reg2Addr/Reg3Addr collapse onto one address. |
| openvm | triv | probe | not_determined | One-word variant in build_words: OP x5,x5,x5. Exercises the adapter's two read-aux records against one write-aux record at one address. |
| risc0 | triv | probe | not_determined | One-line variant in build_seed. risc0 makes this explicit with dedicated DualReg::sameReg and rs2Data columns (recomputed from the record's rs1/rs2 indices) that are trivial unless rs1 == rs2. |
| zisk | triv | probe | not_determined | One new selector arm in `dispatch` (examples/lacuna-seed/src/main.rs) with `op2!("add", a, a)` style aliasing, or an asm block with the same register three times. |

### `st_pv_plumbing` -- Public-value plumbing

Commit eight distinct words instead of one, alias the output region, and put the exit code on the mutation path.

```
let a = read(); let b = read();
let mut w = [0u64; 8];
for i in 0..8 { w[i] = (a ^ (i as u64)) OP b; }
for i in 0..8 { commit_word(i, w[i]); }   // 8 COMMIT ecalls / 8 REVEALs / 8 output words
// variants: (i) forge the INDEX register of one commit;
//           (ii) write the output region twice and read it back before the final commit;
//           (iii) exit(code) with code produced by a perturbable write-back
```

* **Constraint surface.** S14 the commit chip itself -- the index bitmap boolean and one-hot constraints, word_idx == op_b, the per-word digest equality against the read register (pico ecall/constraints.rs:148-231; sp1 air.rs:277-376 assert_word_eq against local.adapter.c()), the cross-shard digest chain, and the termination public values (risc0 termA0/termA1, openvm/ceno exit_code). Variant (ii) is also where a finalize-only write becomes observable on nexus and zisk, whose public output IS a fixed memory region.
* **Observability.** This structure IS the output path. The question is whether EACH word is individually bound or only the aggregate, and whether the word INDEX is bound to anything.
* **Record fields required.**
    * committed output words (risc0 EcallTerminateWitness.output is itself a record field; on openvm/nexus/zisk they are ordinary memory values so the whole Store--load field set applies)
    * the commit word index register
    * exit code
* **Opcode axis.** `alu_bound_reference`
* **Variant suffixes.** `_words8`, `_index`, `_alias`, `_exitcode`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.
* **Site role.** `syscall_arg` -- syscall_arg for variant (i), the commit word INDEX. Variants (ii) and (iii) are value-role. The syscall_arg mask forbids everything today; see mu_menu.role_masks.syscall_arg.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | triv | probe | not_determined | Expressible with a new guest pv_eight.rs committing eight distinct words via eight commit_bytes calls; plus pv_alias.rs writing the public-values region twice. Exercises eval_commit's index bitmap one-hot and word_idx == op_b (chips/riscv_cpu/ecall/constraints.rs:148-231), which every current seed touches only at index 0. |
| sp1 | mod | probe | not_determined | Expressible with a new `build_pv8_program` issuing eight COMMIT ecalls with different a0/a1. The WORD-VALUE variant is trivial; the INDEX variant must be scoped out until a syscall-event hook exists -- sp1's own record generator panics first (commit.rs:9-11 'digest word should fit in u32' and 'index out of bounds: the len is 8'), which is 1,502 of sp1's 1,670 EXECFAILs. |
| ceno | triv | probe | not_determined | The seed already writes an 8-word commit buffer at 0x08001000 and PUB_IO_COMMITs it; fill all eight words with distinct computed values instead of one. Also add the alias variant (write the buffer twice, read it back before the ecall). |
| nexus | triv | probe | not_determined | Requires emitting several `wou` stores into successive output-region words in build_op_elf. This is ALSO where nexus's finalize-only question lives, since the public output IS the final content of that region. |
| openvm | triv | probe | not_determined | Eight REVEAL words into PUBLIC_VALUES_AS=3 at eight offsets in build_words, plus an aliasing variant that REVEALs the same offset twice with different values. |
| risc0 | triv | probe | not_determined | Eight sw instructions to GLOBAL_OUTPUT_ADDR+0..28 in build_seed. do_ecall_terminate reads all eight words into EcallTerminateWitness.output (emu.rs:916-920) -- itself a record field -- and the circuit binds them via GLOBAL_SET_U32/GLOBAL_CHECK_U32 (cxx/rv32im/circuit/ecall.ipp:91,110). Today only word 0 is ever non-trivial. |
| zisk | triv | probe | not_determined | Expressible with a new guest bin committing eight distinct u64s via commit_slice. The output region is the committed object, so this is also zisk's only observable finalize-style probe. |

### `st_early_exit` -- Early exit

A forged condition makes the guest halt BEFORE it commits, so the proof carries a short or empty public output.

```
let c = read();
if black_box(c) != 0 { exit(0); }     // forging c skips everything below
let a = read(); let b = read();
commit(a OP b);
```

* **Constraint surface.** S14' COMPLETENESS of the public-value stream. Is the verifier bound to the facts that the program reached its real end, that the commit actually happened, and that the exit code is honest? sp1 defends this explicitly (verify.rs:481-490 'COMMIT syscall was never called' / 'COMMIT_DEFERRED_PROOFS syscall was never called'), openvm checks is_terminate and exit_code == Success, ceno commits exit_code and has a HaltInstruction circuit -- four independent designs built a defence here, which is evidence the surface is real.
* **Observability.** The committed output becomes SHORT or EMPTY relative to honest. HARD PREREQUISITE: the shipped accepted-case predicate requires a NON-EMPTY committed output, so a successful truncation can never score under it. The predicate must be extended to 'differs from honest, including by being absent' or this structure is unfalsifiable by construction.
* **Record fields required.**
    * halt/terminate event presence
    * exit code
    * the commit-syscall-called flag
* **Opcode axis.** `alu_bound_reference`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_v2`
* **Known finding it would reach.** the OpenVM `unimp`-to-nop gold (verifier accepts exit 0 past an abort) is the same surface reached from the decoder layer instead of the record layer
* **Site role.** `selector` -- Selector role on the instruction producing the early-exit condition.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | probe | not_determined | **Blocked:** the shipped predicate requires a NON-EMPTY committed output, so a successful truncation can never score New guest ee_truncate.rs that exits before commit_bytes when a black_box'd stdin condition is set. PREREQUISITE (shared, not per-target): extend the acceptance predicate at lacuna_eval.rs:734-736 from 'nonempty && pv_hex != honest_hex' to 'differs from honest, including by being absent', keeping the old one as accepted_case_strict. |
| sp1 | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output New `build_early_exit_program`: BEQ on a condition register to add_halt, skipping the COMMIT ecalls. sp1 defends this explicitly (verify.rs:481-490 rejects with 'COMMIT syscall was never called' / 'COMMIT_DEFERRED_PROOFS syscall was never called'), so the expected verdict is REJECT -- but it is the only way to MEASURE that defence. Same predicate prerequisite. |
| ceno | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output New `build_early_exit_program` branching straight to the HALT ecall. ceno commits exit_code and has a HaltInstruction circuit, so this measures whether the halt path is bound to the program reaching it. Same predicate prerequisite. |
| nexus | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output New `build_early_exit_elf` branching past the two `wou` stores to the SYS_EXIT ecall. The output region then holds its init value instead of the result. Same predicate prerequisite. |
| openvm | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output BEQ past the REVEAL to TERMINATE in build_words. openvm's verifier checks is_terminate and exit_code == Success, which is the surface. Same predicate prerequisite; also relates to the known OpenVM `unimp`-to-nop gold reached from the decoder layer. |
| risc0 | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output Branch past the sw to GLOBAL_OUTPUT_ADDR straight to the terminate ecall; out[8] then carries whatever the region held. Same predicate prerequisite. |
| zisk | mod | probe | not_determined | **Blocked:** predicate requires non-empty committed output New guest bin returning early before commit_slice. Same predicate prerequisite. Budget 1 candidate. |

### `st_dead_write` -- Dead write-back

A write-back whose destination is provably never read again -- the control that proves REJECTs are constraint binding and not guest divergence.

```
let a = read(); let b = read(); let c = read();
let mut x = a OP b;    // site 1: dead, overwritten before any read
x = c;                 // site 2: live
commit(x);
// stronger variant: let _dead = a OP b;   (never read at all)   commit(c);
```

* **Constraint surface.** None, deliberately. The mutation is provably invisible to the honest instruction stream, so the perturbed execution is instruction-for-instruction identical to the honest one and any REJECT is attributable to the constraint system alone. EXECFAIL is impossible, which is the point.
* **Observability.** On pico, sp1, ceno, zisk and nexus: NOT observable, expected outcome REJECT (binding) or ACCEPT-with-unchanged-output (unbound but unobservable). On openvm and risc0 the register file is inside the committed memory root, so a dead register write IS observable and the expected verdict flips: an accepted dead write with a changed root is a real, if weaker, state forgery. That asymmetry is itself a result.
* **Record fields required.**
    * any field, at a site whose onward dataflow is empty
* **Opcode axis.** `deconfound_min`
* **Variant suffixes.** `_overwritten`, `_neverread`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_v2`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | pico gets this control today from a backward-liveness SITE FILTER (LACUNA_SITES=dead, lacuna_eval.rs:438-459), which measured 151/151 rejections. Optionally add the seed form for parity with the other six, but do not re-derive the control. |
| sp1 | triv | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | Expressible with a new `build_dead_program`: OP x30,x28,x29 (dead) ; ADD x30,x27,x0 ; ADD x11,x30,x0 ; commit tail. Removes the biggest sp1 confound -- 1,670 of 5,226 candidates (32%) are EXECFAIL from perturbing a register the ECALL then reads, and none of the 3,500 REJECTs is currently controlled. |
| ceno | triv | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | Expressible with a new `build_dead_program` writing x4 twice with only the second read. Also directly attacks ceno's 702-EXECFAIL problem by giving a site class where EXECFAIL is impossible by construction. |
| nexus | triv | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | Expressible with a new `build_dead_elf` with a dead x5 write before the live one. Gives nexus its first controlled rejection class. |
| openvm | triv | probe | not_determined | Dead write word in build_words. VERDICT FLIPS HERE: MemoryDimensions indexes address space 1, so the final register file is inside the committed memory root -- a dead register write IS observable and an accepted one with a changed root is a real (weaker) state forgery. Declare the expected verdict per target in the manifest. |
| risc0 | triv | probe | not_determined | Dead R-type write in build_seed. Same verdict flip as openvm: the tree's own hook comment (preflight/emu.rs:1464-1467) states write_reg's value reaches the paged-out register page and therefore the committed rootOut. |
| zisk | triv | control | REJECT_or_ACCEPT_UNCHANGED_OUTPUT | Expressible with a new guest bin with a dead inline-asm op before the live one. Cheap and high-value: zisk's 42/42 REJECT result is currently uncontrolled. |

### `st_x0_dark_write` -- x0 dark write

An instruction whose destination is x0 -- an architectural write the circuit must discard.

```
// programmatic: OP x0, x28, x29 ; ADD x11, x0, x0 ; commit(x11)   (honest output = 0)
```

* **Constraint surface.** The write-suppression predicate. sp1 dedicates FOUR chips to it -- AluX0, AluX0User, LoadX0, LoadX0User (riscv/mod.rs:141-143, :168-171) -- and not one sp1 candidate has ever produced a row in any of them. openvm has a needs_write column with a u32::MAX sentinel (rdwrite.rs:364); ceno has an explicit ecall RD_NULL dark write (vm_state.rs:213); risc0 has DestReg::isZero (recomputed).
* **Observability.** Honest output is 0; any accepted forgery makes it non-zero -- the cleanest possible output-changed signal.
* **Record fields required.**
    * write-back value at a site whose destination index says the write must be dropped
* **Opcode axis.** `deconfound_min`, `mem_word`
* **Over-propagation risk.** low
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** None catalogued. This is a surface nobody has measured, not a re-test.

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | probe | not_determined | **Blocked:** wb_perturb::on_reg_write is not called for X0 Needs a hook relaxation: the choke point explicitly skips X0 (vm/src/emulator/riscv/emulator/mod.rs:1982-1986) and rw zeroes writes to it (:1979). One-line change plus a guard so the honest baseline is unaffected. Until then, record honestly that the shape is inexpressible by design of the DRIVER, not of the VM. |
| sp1 | triv | probe | not_determined | Expressible with a new `build_x0_program`: Instruction::new(op, 0, 28, 29, false, false) then ADD x11,x0,x0 and the commit tail; honest output is 0. sp1 dedicates FOUR chips to this -- AluX0, AluX0User, LoadX0, LoadX0User (riscv/mod.rs:141-143, :168-171, instantiated at :488-489, :498-499) -- and not one sp1 candidate has ever produced a row in any of them. |
| ceno | triv | probe | not_determined | encode_rv32 with rd=0; ceno also has an explicit ecall RD_NULL dark write path (vm_state.rs:213) that the write-back hook already covers. |
| nexus | mod | probe | not_determined | **Blocked:** write-back hook skips X0 Same hook relaxation: the write-back hook is gated on `instruction.op_a != Register::X0` (vm/src/trace.rs:309). One-line change. |
| openvm | triv | probe | not_determined | OP x0,x1,x2 word in build_words. Tests the needs_write column and its u32::MAX sentinel (adapters/rdwrite.rs:364). |
| risc0 | triv | probe | not_determined | R-type with rd=x0 in build_seed. Tests DestReg::isZero (recomputed from the record's rd index). |
| zisk | n/d | probe | not_determined | NOT ASSESSED. The feasibility assessment has no (st_x0_dark_write, zisk) cell, and its disagreement note lists only sp1/ceno/openvm/risc0 as expressible today and pico/nexus as needing a one-line hook relaxation -- zisk is simply unlisted. The cell is unassessed and is not a negative result. |

### `st_precompile` -- Precompile boundary

Route the forged value into an accelerator's input buffer or input pointer and commit the accelerator's output.

```
let a = read();
let mut state = [a as u32; 8];
let block = [0u8; 64];
sha256_compress(&mut state, &block);   // patched intrinsic -> ecall -> precompile chip
commit(state[0] as u64);
// mutation site: the write-back producing an INPUT WORD or the INPUT POINTER
```

* **Constraint surface.** S19 the syscall event, the precompile's own memory read/write records, and the CPU<->accelerator permutation/global bus. On several targets this is most of the AIRs by count: roughly 100 of sp1's 122 chips are precompiles and ~30 of pico's 46, and not one has ever been instantiated by a LACUNA candidate on any target.
* **Observability.** The accelerator's result is committed directly.
* **Record fields required.**
    * precompile memory records (ordinary memory records, reachable everywhere)
    * syscall event args (BLOCKED on sp1 -- the record generator panics first at commit.rs:9-11 and syscall_code.rs:249, which is 1,502 of sp1's 1,670 EXECFAILs)
* **Opcode axis.** `per_target_precompile_set`
* **Over-propagation risk.** medium
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** the precompile finding family: ceno keccak-f free round constants, zisk ArithEq384 equal-x alias bypass and catalog #24 sel_prove not bound to the ROM, and the shared incomplete-Weierstrass EC-add P+P slope class

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | mod | probe | not_determined | Requires building a guest against pico's patch-libs so a sha256/EC intrinsic actually lowers to the ecall (model on vm/examples/patch-testing/patches/sha2/app). ~30 of pico's 46 chips are precompiles and none has ever been instantiated by a LACUNA candidate. |
| sp1 | mod | probe | not_determined | Use Program::from_elf on the prebuilt test-artifacts precompile ELFs (sha-extend, keccak-permute, secp256k1-add, ed-add) under crates/test-artifacts/programs/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/ -- test-artifacts is already a dev-dependency, so no toolchain step. ~100 of sp1's 122 chips are precompiles and none has ever been instantiated. Scope out the syscall-ARGUMENT variant until a syscall-event hook exists. |
| ceno | mod | probe | not_determined | Keccak, sha-extend, bn254/secp/bls circuits are registered (rv32im.rs:363-400). Build a seed that issues the corresponding ecall and commits the result. NOTE ceno's own blocked list: SyscallWitness mem_ops and reg_ops are NOT reachable from the write-back or track_access hooks, so only the input-value path is covered. |
| nexus | **BLOCK** | probe | not_determined | **Blocked:** NOT DETERMINED whether prover2 has any precompile component NOT DETERMINED. prover2's BASE_COMPONENTS list carries no precompile component (and notably no M-extension either). Do not schedule until the component list is confirmed. |
| openvm | hard | probe | not_determined | **Blocked:** needs a proving configuration change, not just a seed Requires a VmConfig beyond Rv32ImConfig (a different keygen and prover configuration, plus admitting wider tracing_write users -- sha2, keccak256, vec_heap -- to the hook, which today only perturbs 4-byte writes). Real but a separate work item from the seed corpus. |
| risc0 | mod | probe | not_determined | EcallP2 / EcallBigInt blocks exist; emit the corresponding ecall from the built-in assembler with a prepared input buffer and sw the result to GLOBAL_OUTPUT_ADDR. |
| zisk | mod | probe | not_determined | Arith/Keccak/ArithEq state machines exist and catalog #24 (sel_prove not bound to the ROM, graded L0) lives in the arith_eq dispatch. New guest bin calling the precompile via ziskos. Expensive: budget a handful of candidates. |

### `st_whole_program` -- Whole program

A realistic multi-thousand-instruction guest -- the external-validity claim, not a surface claim.

```
let n = read();
let (mut x, mut y) = (0u64, 1u64);
for _ in 0..n { let t = x.wrapping_add(y); x = y; y = t; }
commit(x);
// pico uses the in-tree fib ELF; sp1 can use Program::from_elf on the prebuilt
// riscv64im-succinct test-artifacts; the programmatic ports need a generated loop-heavy program
```

* **Constraint surface.** No unique surface once the rest of this catalog exists, which is exactly why it is RE-JUSTIFIED rather than dropped. It uniquely provides (i) a realistic opcode census in one shard (pico's fib: 21 opcode families, 150 AUIPC, 149 JALR, 223 sub-word loads, 5040 static write-back sites), (ii) many chips live simultaneously so lookup multiplicities interact, and (iii) the answer to 'does this find anything on code somebody would actually run'.
* **Observability.** Through the guest's normal commit path, and it is the only structure where the two public-output objects have been empirically observed to DIVERGE: 682 pico fib candidates were verifier-ACCEPTED with digest_changed=true and output_changed=false, all SRLW inside the SDK's software SHA-256 (32-bit rotations lower to SRLW/SRLIW; sdk/sdk/src/riscv_ecalls/io.rs:33). Any port must record BOTH public-output objects from day one.
* **Record fields required.**
    * all of them, at realistic multiplicity
    * the committed digest, uniquely DOWNSTREAM of the mutation rather than a direct copy of it
* **Opcode axis.** `census`
* **Over-propagation risk.** high
* **Predicate.** `accepted_case_strict`
* **Known finding it would reach.** pico catalog #3 reached through the guest's own software SHA-256 rather than through the operation under test -- 682 verifier-accepted, digest-changed candidates

| target | status | class | expected | approach |
|---|---|---|---|---|
| pico | impl | probe | not_determined | Shipped: the guest is guests/lacuna_seeds/src/bin/fib.rs (fib for Whole program) with a row in the SEEDS table of evaluation/scripts/run_lacuna_pico.py, and the published corpus carries its candidates. this seed is pinned to ADD/LD in that table, which are opcodes pico binds, so its published yield of zero is not evidence about the structure. |
| sp1 | mod | probe | not_determined | Two options: (a) a programmatic register-only iterative fibonacci of a few thousand cycles (memory-read-free, so immune to the phase-1 oracle problem), or (b) Program::from_elf on the prebuilt test-artifacts fibonacci-program-tests ELF. writeback_sites has NO cap, so sample sites -- at ~7 s wall per candidate a 500-site program is ~1 h at 8-way. |
| ceno | mod | probe | not_determined | Requires emitting a loop-heavy program from build_op_program's encoder (a few thousand instructions) or wire Program loading from a real guest ELF. Site sampling required; at 2.8 s/candidate the full site x mu product is unaffordable. |
| nexus | triv | probe | not_determined | Requires emitting a loop-heavy instruction vector from build_op_elf's `enc` helper. nexus is the cheapest target in the corpus (~0.07 s/candidate aggregate), so a realistic guest plus a full site sweep is affordable here and nowhere else. |
| openvm | mod | probe | not_determined | Requires emitting a loop-heavy word vector through the real transpiler in build_words, or load a real guest VmExe. At ~10 s/candidate, sample sites hard. Watch the metered pass's honest height estimation. |
| risc0 | mod | probe | not_determined | Requires emitting a counted loop from the built-in assembler (needs insn_b, shared with st_control_flow). Site sampling required at ~4 s/candidate. |
| zisk | hard | probe | not_determined | **Blocked:** ~73 s per candidate makes a realistic-guest site census unaffordable examples/big-program exists as a starting shape, but at ~73 s/candidate wall a realistic guest with a site census is not affordable in this corpus. Report honestly as out of budget rather than as unimplemented. |

## What the method cannot reach

Carried verbatim from the catalog. These are boundaries, not backlog.

* CARRY SLACK AND FIELD WRAPAROUND ARE OUTSIDE THE METHOD, NOT MISSING FROM IT. Seven of the 24 catalogued findings (ceno #8 MUL low-limb carry, #9 MULH high-limb, #10 DIV/REM carry, #21 shift limb decomposition, #22 HintsTable limb range, zisk #23 non-boolean sel_prove, and nexus #11's paired form) are graded L2/L3 in RECORD_PERTURBATION_REACHABILITY.md: the alternative limb decomposition is not expressible as any u32/u64 an execution record can hold, and on ceno the rd value never enters the circuit at all (rd_written is a circuit expression). No program structure whatsoever reaches them. They need a domain-aware operator that enumerates a value's second legal limb decomposition over the field. This is the boundary of the method and must be stated as such rather than patched with seeds.
* OVER-PROPAGATION FALSE NEGATIVES SURVIVE EVERY SHAPE. When the witness generator feeds the SAME record field to both the free column and a pinned sibling, perturbing it moves both, breaks a constraint that was actually sound, and the candidate is REJECTED -- reported as SAFE when it is not. pico SLT is the textbook case: lt/traces.rs:106 writes cols.a = event.a while gadgets/lt_word_u16.rs:96 writes the gadget bit from the same event.a. sp1 reproduces it exactly (AluEvent.a for SLT/SLTU -> U16CompareOperation.bit). st_fanout_read makes the split expressible at the PROGRAM level in some cases, but the general fix is a per-read-point (L1) operator, which is an operator axis orthogonal to program structure. Every M1-class finding whose gadget shares a record field will keep reporting a false negative until that operator exists.
* THE DECODER AND TRANSPILER LAYERS ARE NOT REACHABLE FROM A WRITE-BACK HOOK. Instruction-decode leniency (the shared rrs_lib SLLI-funct7 and JALR-funct3 acceptance, over-wide shamt) requires a hook on the fetched instruction WORD, which is a different layer with its own method document. st_indirect_jump reaches the ROM LOOKUP but not the decoder's tolerance for malformed encodings. Likewise opcode and decode record fields are ROM-bound or preprocessed on all seven targets (pico ROM, ceno fixed program table, sp1 the Program bus against the preprocessed trusted program, openvm the program ROM lookup, nexus program_mem_check, risc0 DecodeWitness recomputed in decode.ipp, zisk from the ROM), so no program shape unbinds them.
* SOME STRUCTURES ARE DELIBERATELY UNOBSERVABLE ON SOME TARGETS AND ARE SHIPPED AS CONTROLS. st_finalize_only cannot reach the public output on pico, sp1 or ceno (nothing about final state is public) and reaches only a fixed output REGION on nexus and zisk; st_dead_write cannot reach it on five of seven by construction. Those cells are declared negative controls with an expected verdict and are excluded from coverage counts. Shipping them without that declaration would inflate the candidate count with guaranteed-negative work.
* WE DROPPED SIX PROPOSED SHAPES AND SHOULD SAY WHY. (a) Address-space / region aliasing (a register-carried address that makes a RAM access land on the register file) is a genuinely distinct surface but lands on only sp1 and risc0 -- below the four-target bar; folded into st_redirect's address sweep there. (b) Self-modifying code / forging the program table: no target permits a store into text and the image is vk-anchored on all seven. (c) A standalone unaligned-access structure: six of seven executors trap before a trace exists, leaving only zisk's MemAlign; folded into st_boundary_operand as a zisk sub-variant. (d) A concurrent / same-timestamp structure: the executor assigns timestamps, so this is purely an order-operator axis with no seed to write. (e) pico's unconstrained-execution region: pico-only, and the choke point deliberately does not fire inside it. (f) ceno's heap/hint max-touch public values: ceno-only. Each is a boundary, not an oversight.
* THE PUBLISHED PER-STRUCTURE YIELDS ARE CURRENTLY UNINTERPRETABLE AND WILL STAY THAT WAY UNTIL THE RUN MATRIX IS RE-RUN. On pico the driver pinned five of the seven structures to opcodes ADD and LD, which pico binds correctly, while all 24 encoding accepted cases sit on SRLW/SRAW, reachable only from the Single-operation seeds. The shipped axis varies structure AND opcode together. 'Four structures found nothing' is therefore not evidence about those structures.
* THE ACCEPTANCE PREDICATE READS ONE OF TWO PUBLIC-OUTPUT OBJECTS, AND THEY DIVERGE. 682 pico Whole-program candidates were accepted by the real verifier with the in-circuit committed digest CHANGED and the out-of-circuit byte stream identical, and scored accepted_case=false. Numbers computed before and after the predicate extension are not comparable, and some archived rows carry NA in the digest columns because the capture was added later.
* TWO TARGETS CANNOT PRODUCE A COHERENT RAM-MEDIATED FORGERY AT ALL TODAY. sp1's phase-2 CoreVM has no memory -- every memory read value comes from an unhooked phase-1 oracle (vm.rs:747) that ignores its address argument -- and zisk's witness generation replays against mem_reads the same way. Any structure that routes a value through RAM on those two is structurally self-inconsistent and its rejection says nothing about the constraint system, until a read-side hook lands. sp1's existing conclusion that its unconstrained MemoryInitialize value 'is not a soundness gap' is established only for the incoherent single-leg mutation that was actually run.
* ZISK'S RESULT VALUE IS NOT A RECORD FIELD, AND ZISK HAS NO RECORD-CARRIED TIMESTAMP. The hooked Emu::get_value_to_store is an EXECUTOR change, not a record perturbation (the result c is recomputed by (instruction.func)(&mut inst_ctx)), so zisk's 42/42 REJECT is a statement about the executor-to-witness path rather than the record layer. And because STEP is a fixed column plus an airval, the entire BINDING/order mode is structurally inexpressible on zisk. Both are publishable negatives, but they must not be read as 'zisk was searched the same way the others were'.
* NEXUS'S CATALOGUED FINDINGS ARE IN A CRATE THE DRIVER DOES NOT DRIVE. The enumeration runs prover2, whose BASE_COMPONENTS list has no M-extension component, while nexus findings #11 (MULHU carry slack), #12 (signed M sign bits) and #13 (DivRem 32-bit overflow) all live in the separate `prover` v1 crate. No program structure changes that; it needs a second driver.
* PER-ITERATION SITE GRANULARITY IS UNAVAILABLE ON MOST TARGETS. nth>=0 works today only on pico and risc0. sp1 (one global SEEN counter across two CoreVM passes), ceno (three emulation passes) and nexus (k_trace emulates twice) can only arm nth=-1, so st_loop_repeat runs as an all-executions mutation there. openvm and zisk are NOT DETERMINED. Half the (pc, nth) site key is therefore dead on four of seven targets even after this catalog is built.
* THE ACCELERATOR HALF OF THESE MACHINES REMAINS ESSENTIALLY UNMEASURED. Roughly 100 of sp1's 122 chips and ~30 of pico's 46 are precompiles, plus ceno's keccak/sha-extend/bn254/secp/bls, risc0's EcallP2/EcallBigInt and zisk's Arith/ArithEq/Keccak state machines. st_precompile is nice-priority on five targets, hard on openvm (needs a VmConfig change) and NOT DETERMINED on nexus. Even with the whole catalog built, the coverage claim is about the base ISA and the memory argument, not about the precompiles.
* RECURSION, AGGREGATION AND CONTINUATION VERIFIERS ARE OUT OF SCOPE ON EVERY TARGET (sp1 core proofs only, zisk no-aggregation, pico core machine only, openvm segment verification only, risc0 single segment). st_multishard reaches the cross-shard glue inside one proving run; it does not reach the recursive verifier that consumes those proofs.
* COST BOUNDS THE CORPUS ON TWO TARGETS AND THE SAMPLING MUST BE REPORTED. Measured aggregate wall per candidate: nexus 0.07 s, pico 0.5 s, ceno 2.8 s, risc0 4.2 s, sp1 6.9 s, openvm 9.7 s, zisk 73 s. The full structure x opcode x site x mu cross product is affordable only on nexus and pico. Everywhere else the corpus is sampled, and a per-target sampling policy must be published alongside the counts or the cross-target comparison is again invalid.
* A REJECT IS EVIDENCE OF BINDING ONLY WHEN PAIRED WITH THE DEAD-WRITE CONTROL ON THAT TARGET. pico's credibility rests on 151/151 rejections at provably dead destinations; the other six targets have no controlled rejections at all, and sp1 additionally reports 32% EXECFAIL from perturbing registers the ECALL then reads. Until st_dead_write ships on all seven, the ~26,000 non-pico REJECTs in the published corpus cannot be distinguished from crashed guests.

## Design disagreements, and how they were resolved

* WHICH TARGETS COMMIT FINAL STATE (decides whether st_finalize_only is a probe or a control). The constraint-surface angle said openvm, risc0 and nexus commit final STATE and pico/sp1/ceno/zisk commit a digest; the record-field angle said openvm, risc0 and ZISK are the observable ones. RESOLVED by reading what each object actually is: openvm chains final_memory_root in verify_segments (crates/vm/src/arch/vm.rs:1268-1319) and MemoryDimensions indexes address space 1, so the whole final image INCLUDING the register file is committed; risc0 sets globals.rootOut from the final image digest (preflight/paging.rs:189). Those two are genuine whole-state probes. nexus and zisk commit a FIXED OUTPUT REGION (nexus PubMemoryBoundary written by `wou`; zisk's output state machine), so only a write into that region is observable -- which is st_pv_plumbing, not st_finalize_only. pico, sp1 and ceno commit a digest only. So: probe on 2, control on 5, and the arbitrary-address form on nexus/zisk is a control.
* WHAT IS WRONG WITH REDIRECT. The constraint-surface angle re-specified the mutation SITE to the pointer-producing instruction and claimed no new operator is needed on any target; the record-field angle said the pico seed is simply BROKEN because SLOT1 gets exactly one store, so stale_load's `if v.len() < 2 { return None }` guard never arms, and that a per-read-point operator is mandatory. RESOLVED: both are right about different modes. Ship the guest with BOTH fixes -- a second store to p1 (which arms binding mode) AND the pointer materialised by a perturbable write-back (which makes encoding mode work today on all seven with the existing hook). The L1 per-read-point operator stays the ideal instrument but is not a precondition for the structure.
* PRIORITY OF INITIAL STATE. Constraint-surface said must (it is the only probe of the pre-execution state claim); record-field said should (the field is record-carried on only four of seven, and on sp1 it is meaningful only as a coherent triple). RESOLVED as must, but with the per-target split written into the feasibility matrix: record-carried on pico/sp1/risc0/zisk, structurally absent on openvm/ceno/nexus where it ships as a declared negative. The coherence requirement is promoted from a caveat to part of the approach, because the shipped sp1 result (130/130 dying on 'global cumulative sum is not zero') is exactly what an incoherent single-leg mutation must produce.
* DEPTH OF THE CONSUMER/PROVENANCE CHAIN. Constraint-surface proposed a two-chip register-only chain (does the forgery survive a second chip's operand-side range checks?); record-field proposed the maximal ALU->store->load->ALU->commit chain (at which hop does it die?). COLLAPSED into one structure, st_provenance_chain, with two declared depths. The register-only depth is the portable one; the deep depth is uninformative on sp1 and zisk until their memory-read side is hooked, and that fact is itself the diagnostic the record-field angle wanted.
* IS THE DEAD-WRITE SEED STILL A CONTROL. Constraint-surface argued it stops being a control on openvm and risc0 because the register file is inside the committed root. RESOLVED by keeping the structure and adding a per-target expected-verdict declaration to the manifest: control on pico/sp1/ceno/zisk/nexus, probe on openvm/risc0. The asymmetry is a result, and it is the reason the manifest needs an expected_observability field rather than a global assumption.
* WHOLE PROGRAM: KEEP, SPLIT, OR DEMOTE. Constraint-surface re-justified it as the external-validity claim; record-field wanted it split into a loop axis and a shard axis with the realistic guest keeping only the opcode census and the digest-path result. RESOLVED by doing both: st_loop_repeat and st_multishard become first-class structures with new ids, and Whole program keeps its FROZEN id and name and is re-justified on realism, the site census nobody chose, and the fact that it is the only place the two public-output objects have been observed to diverge.
* PRIORITY OF THE HINT/ADVICE STRUCTURE. Constraint-surface rated it should (oracle calibration); record-field rated it must (the evaluation's only positive control). RESOLVED as must. Six of seven targets report zero accepted cases; with no guaranteed ACCEPT anywhere in the corpus a reader cannot distinguish a sound VM from a port whose hook never reaches the constraint system, and that is a credibility problem an open-source release cannot ship with. It must be reported in a separate calibration column and never counted as a finding.
* OVER-PROPAGATION RISK ON SUB-WORD LANES. Constraint-surface rated the store side MODERATE (VMs that derive the merged word by expression will self-heal); record-field rated the whole structure LOW by construction and pointed out both catalogue entries are graded pure-L0. RESOLVED as low, with the store-side self-heal recorded as a PREDICTED, testable outcome rather than a risk (sp1's load_byte.rs:314-355 computes all four written limbs as expressions of the selected byte and msb). A predicted-and-confirmed negative on a never-measured surface is worth the seed.
* X0 DARK WRITE: DROP OR KEEP. Constraint-surface dropped it (inexpressible on pico, the target with the richest hook, and the constraint looked structurally enforced everywhere it read). Record-field kept it at nice, noting sp1 has FOUR dedicated chips for it that no candidate has ever touched. RESOLVED: keep at nice on the exactly four targets that can express it today (sp1, ceno, openvm, risc0), with pico and nexus needing a one-line hook relaxation. The objection was about one target's hook, not about the surface, and 'four sp1 chips are unreachable by design of the driver, not of the VM' is a statement the release should be able to make with data behind it.
* IS BOUNDARY OPERAND A STRUCTURE OR A PARAMETER SWEEP. Record-field admitted it ONLY because the degenerate branch changes a field's STATUS (nexus div_rem.rs:44 -> :163 takes the result FROM the record at the boundary while recomputing it in the general case) and explicitly refused a general operand sweep. Constraint-surface treated it as a shape requirement (the shift amount must live in a REGISTER, so SLL not SLLI). RESOLVED: it is a structure, because the register-operand requirement and the paired-value setup are genuine shape constraints; the general operand sweep stays in the run matrix, not in the catalog.
