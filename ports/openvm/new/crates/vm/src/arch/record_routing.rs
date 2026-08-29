//! Testing-only execution-record routing hooks for zkVM soundness fuzzing.
//!
//! This module exposes the real OpenVM trace-generation boundary:
//!
//! ```text
//! PreflightExecutionOutput { SystemRecords, record_arenas } -> generate_proving_ctx
//! ```
//!
//! It does not alter AIR constraints, proof generation, public values, or verifier logic. A fuzzer
//! can run honest preflight and mutated preflight, then route each AIR's record arena from either
//! side before calling the normal trace/proof pipeline.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    Arena, PreflightExecutionOutput, VirtualMachine, VmBuilder, CONNECTOR_AIR_ID, MERKLE_AIR_ID,
    PROGRAM_AIR_ID,
};
use crate::system::SystemRecords;
use openvm_stark_backend::StarkEngine;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvmFuzzComponent {
    pub id: String,
    pub air_idx: usize,
    pub air_name: String,
    pub group: ZkvmFuzzComponentGroup,
    pub record_boundary: ZkvmFuzzRecordBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkvmFuzzComponentGroup {
    Program,
    Connector,
    MemoryBoundary,
    MemoryMerkle,
    System,
    Executor,
    Periphery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkvmFuzzRecordBoundary {
    SystemRecords,
    RecordArena,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvmFuzzBindingEndpoint {
    pub component_id: String,
    pub air_idx: usize,
    pub field: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvmFuzzBinding {
    pub id: String,
    pub class: ZkvmFuzzBindingClass,
    pub description: String,
    pub endpoints: Vec<ZkvmFuzzBindingEndpoint>,
    pub feasible_split: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkvmFuzzBindingClass {
    InstructionBinding,
    ValueBinding,
    OrderBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvmFuzzTargetManifest {
    pub schema: String,
    pub target: String,
    pub record_to_trace_boundary: String,
    pub routing_granularity: String,
    pub components: Vec<ZkvmFuzzComponent>,
    pub bindings: Vec<ZkvmFuzzBinding>,
    pub unsupported_splits: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkvmFuzzRouteSelection {
    /// AIR indices that should use records from the mutated preflight run.
    pub mutated_air_indices: BTreeSet<usize>,
    /// OpenVM CPU system chips consume `SystemRecords` as one aggregate, so system AIRs cannot be
    /// routed independently. Set this when the whole system side should come from the mutated run.
    pub mutated_system_records: bool,
}

impl ZkvmFuzzRouteSelection {
    pub fn encoding(num_airs: usize) -> Self {
        Self {
            mutated_air_indices: (0..num_airs).collect(),
            mutated_system_records: true,
        }
    }

    pub fn binding(mutated_air_indices: impl IntoIterator<Item = usize>) -> Self {
        Self {
            mutated_air_indices: mutated_air_indices.into_iter().collect(),
            mutated_system_records: false,
        }
    }
}

impl<E, VB> VirtualMachine<E, VB>
where
    E: StarkEngine,
    VB: VmBuilder<E>,
    VB::RecordArena: Arena,
{
    pub fn zkvm_fuzz_manifest(&self) -> ZkvmFuzzTargetManifest {
        let components = self.zkvm_fuzz_components();
        let bindings = self.zkvm_fuzz_bindings(&components);
        ZkvmFuzzTargetManifest {
            schema: "openvm-zkvm-fuzz-record-routing-v1".to_string(),
            target: "openvm".to_string(),
            record_to_trace_boundary:
                "PreflightExecutionOutput<SystemRecords, record_arenas> -> generate_proving_ctx"
                    .to_string(),
            routing_granularity:
                "CPU backend: SystemRecords as one aggregate, non-system record_arenas by AIR index"
                    .to_string(),
            components,
            bindings,
            unsupported_splits: vec![
                "individual system AIR split inside Program/Connector/Memory is not supported; SystemRecords is consumed as one aggregate"
                    .to_string(),
            ],
        }
    }

    pub fn zkvm_fuzz_components(&self) -> Vec<ZkvmFuzzComponent> {
        let executor_airs: BTreeSet<usize> = self.executor_idx_to_air_idx().into_iter().collect();
        self.air_names()
            .enumerate()
            .map(|(air_idx, air_name)| {
                let group = if air_idx == PROGRAM_AIR_ID {
                    ZkvmFuzzComponentGroup::Program
                } else if air_idx == CONNECTOR_AIR_ID {
                    ZkvmFuzzComponentGroup::Connector
                } else if air_idx == self.config().as_ref().memory_boundary_air_id() {
                    ZkvmFuzzComponentGroup::MemoryBoundary
                } else if air_idx == MERKLE_AIR_ID {
                    ZkvmFuzzComponentGroup::MemoryMerkle
                } else if air_idx < self.config().as_ref().num_airs() {
                    ZkvmFuzzComponentGroup::System
                } else if executor_airs.contains(&air_idx) {
                    ZkvmFuzzComponentGroup::Executor
                } else {
                    ZkvmFuzzComponentGroup::Periphery
                };
                let record_boundary = match group {
                    ZkvmFuzzComponentGroup::Program
                    | ZkvmFuzzComponentGroup::Connector
                    | ZkvmFuzzComponentGroup::MemoryBoundary
                    | ZkvmFuzzComponentGroup::MemoryMerkle
                    | ZkvmFuzzComponentGroup::System => ZkvmFuzzRecordBoundary::SystemRecords,
                    ZkvmFuzzComponentGroup::Executor | ZkvmFuzzComponentGroup::Periphery => {
                        ZkvmFuzzRecordBoundary::RecordArena
                    }
                };
                ZkvmFuzzComponent {
                    id: component_id(air_idx, air_name),
                    air_idx,
                    air_name: air_name.to_string(),
                    group,
                    record_boundary,
                }
            })
            .collect()
    }

    pub fn zkvm_fuzz_bindings(&self, components: &[ZkvmFuzzComponent]) -> Vec<ZkvmFuzzBinding> {
        let system_program = component_for_air(components, PROGRAM_AIR_ID);
        let system_connector = component_for_air(components, CONNECTOR_AIR_ID);
        let memory_boundary =
            component_for_air(components, self.config().as_ref().memory_boundary_air_id());
        let executor_airs = self.executor_idx_to_air_idx();

        let mut bindings = Vec::new();
        for air_idx in executor_airs {
            let Some(executor) = component_for_air(components, air_idx) else {
                continue;
            };
            if let (Some(program), Some(connector)) = (system_program, system_connector) {
                bindings.push(ZkvmFuzzBinding {
                    id: format!("openvm.instruction.air_{air_idx}"),
                    class: ZkvmFuzzBindingClass::InstructionBinding,
                    description:
                        "ProgramBus/ExecutionBridge binds decoded instruction identity to executor AIR"
                            .to_string(),
                    endpoints: vec![
                        endpoint(program, "program_bus.instruction"),
                        endpoint(connector, "execution_bus.from_state"),
                        endpoint(executor, "executor_air.instruction"),
                    ],
                    feasible_split: vec![executor.id.clone()],
                });
            }
            if let Some(memory) = memory_boundary {
                bindings.push(ZkvmFuzzBinding {
                    id: format!("openvm.value.air_{air_idx}"),
                    class: ZkvmFuzzBindingClass::ValueBinding,
                    description: "MemoryBridge binds register/memory operands, addresses, and write values between executor AIR and memory AIRs"
                        .to_string(),
                    endpoints: vec![
                        endpoint(executor, "memory_bridge.access"),
                        endpoint(memory, "memory_bus.access"),
                    ],
                    feasible_split: vec![executor.id.clone()],
                });
                bindings.push(ZkvmFuzzBinding {
                    id: format!("openvm.order.air_{air_idx}"),
                    class: ZkvmFuzzBindingClass::OrderBinding,
                    description: "ExecutionBus and MemoryBridge bind PC/timestamp continuity between executor AIR and system AIRs"
                        .to_string(),
                    endpoints: vec![
                        endpoint(executor, "execution_bus.to_state"),
                        endpoint(memory, "memory_bus.timestamp_order"),
                    ],
                    feasible_split: vec![executor.id.clone()],
                });
            }
        }
        bindings
    }
}

pub fn route_preflight_records<F, RA>(
    honest: &PreflightExecutionOutput<F, RA>,
    mutated: &PreflightExecutionOutput<F, RA>,
    selection: &ZkvmFuzzRouteSelection,
) -> Result<PreflightExecutionOutput<F, RA>, ZkvmFuzzRouteError>
where
    F: Clone,
    RA: Clone,
    SystemRecords<F>: Clone,
{
    if honest.record_arenas.len() != mutated.record_arenas.len() {
        return Err(ZkvmFuzzRouteError::MismatchedArenaCount {
            honest: honest.record_arenas.len(),
            mutated: mutated.record_arenas.len(),
        });
    }
    if let Some(&air_idx) = selection
        .mutated_air_indices
        .iter()
        .find(|&&air_idx| air_idx >= honest.record_arenas.len())
    {
        return Err(ZkvmFuzzRouteError::AirIndexOutOfBounds {
            air_idx,
            num_airs: honest.record_arenas.len(),
        });
    }

    let record_arenas = honest
        .record_arenas
        .iter()
        .zip(mutated.record_arenas.iter())
        .enumerate()
        .map(|(air_idx, (honest_arena, mutated_arena))| {
            if selection.mutated_air_indices.contains(&air_idx) {
                mutated_arena.clone()
            } else {
                honest_arena.clone()
            }
        })
        .collect();

    Ok(PreflightExecutionOutput {
        system_records: if selection.mutated_system_records {
            mutated.system_records.clone()
        } else {
            honest.system_records.clone()
        },
        record_arenas,
        to_state: if selection.mutated_system_records {
            mutated.to_state.clone()
        } else {
            honest.to_state.clone()
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ZkvmFuzzRouteError {
    #[error("honest/mutated arena count mismatch: honest={honest}, mutated={mutated}")]
    MismatchedArenaCount { honest: usize, mutated: usize },
    #[error("AIR index {air_idx} is out of bounds for num_airs={num_airs}")]
    AirIndexOutOfBounds { air_idx: usize, num_airs: usize },
}

fn component_for_air(
    components: &[ZkvmFuzzComponent],
    air_idx: usize,
) -> Option<&ZkvmFuzzComponent> {
    components
        .iter()
        .find(|component| component.air_idx == air_idx)
}

fn endpoint(component: &ZkvmFuzzComponent, field: &str) -> ZkvmFuzzBindingEndpoint {
    ZkvmFuzzBindingEndpoint {
        component_id: component.id.clone(),
        air_idx: component.air_idx,
        field: field.to_string(),
    }
}

fn component_id(air_idx: usize, air_name: &str) -> String {
    format!("air_{air_idx:03}_{}", sanitize(air_name))
}

fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arch::{
            ExecutionState, MatrixRecordArena, Streams, SystemConfig, VmState, DEFAULT_BLOCK_SIZE,
        },
        system::{
            memory::{
                online::{AddressMap, GuestMemory},
                TimestampedValues,
            },
            SystemCpuBuilder,
        },
        utils::test_cpu_engine,
    };
    use p3_baby_bear::BabyBear;

    #[test]
    fn routes_each_air_arena_independently() {
        let honest = output_with_markers(&[11, 12, 13]);
        let mutated = output_with_markers(&[21, 22, 23]);
        let routed = route_preflight_records(
            &honest,
            &mutated,
            &ZkvmFuzzRouteSelection::binding([1usize]),
        )
        .unwrap();

        assert_eq!(routed.record_arenas[0].trace_buffer[0], BabyBear::new(11));
        assert_eq!(routed.record_arenas[1].trace_buffer[0], BabyBear::new(22));
        assert_eq!(routed.record_arenas[2].trace_buffer[0], BabyBear::new(13));
        assert_eq!(routed.system_records.from_state.pc, 1);
    }

    #[test]
    fn encoding_routes_all_records_from_mutated_run() {
        let honest = output_with_markers(&[11, 12]);
        let mutated = output_with_markers(&[21, 22]);
        let routed =
            route_preflight_records(&honest, &mutated, &ZkvmFuzzRouteSelection::encoding(2))
                .unwrap();

        assert_eq!(routed.record_arenas[0].trace_buffer[0], BabyBear::new(21));
        assert_eq!(routed.record_arenas[1].trace_buffer[0], BabyBear::new(22));
        assert_eq!(routed.system_records.from_state.pc, 2);
    }

    #[test]
    fn manifest_uses_real_vm_air_inventory() {
        let engine = test_cpu_engine();
        let (vm, _pk) =
            VirtualMachine::new_with_keygen(engine, SystemCpuBuilder, SystemConfig::default())
                .unwrap();
        let manifest = vm.zkvm_fuzz_manifest();

        assert_eq!(manifest.schema, "openvm-zkvm-fuzz-record-routing-v1");
        assert_eq!(manifest.components.len(), vm.num_airs());
        assert!(manifest
            .components
            .iter()
            .any(|component| component.group == ZkvmFuzzComponentGroup::Program));
        assert!(manifest
            .components
            .iter()
            .any(|component| component.group == ZkvmFuzzComponentGroup::Connector));
        assert!(!manifest.bindings.is_empty());
    }

    fn output_with_markers(
        markers: &[u32],
    ) -> PreflightExecutionOutput<BabyBear, MatrixRecordArena<BabyBear>> {
        let record_arenas = markers
            .iter()
            .map(|&marker| MatrixRecordArena {
                trace_buffer: vec![BabyBear::new(marker)],
                width: 1,
                trace_offset: 1,
                allow_truncate: true,
            })
            .collect();
        let system_marker = markers[0] / 10;
        PreflightExecutionOutput {
            system_records: SystemRecords {
                from_state: ExecutionState {
                    pc: system_marker,
                    timestamp: 1,
                },
                to_state: ExecutionState {
                    pc: system_marker,
                    timestamp: 2,
                },
                exit_code: Some(0),
                filtered_exec_frequencies: vec![1],
                touched_memory: vec![(
                    (1, 0),
                    TimestampedValues {
                        timestamp: 1,
                        values: [BabyBear::new(0); DEFAULT_BLOCK_SIZE],
                    },
                )],
            },
            record_arenas,
            to_state: VmState::new_with_defaults(
                system_marker,
                GuestMemory::new(AddressMap::default()),
                Streams::default(),
                0,
            ),
        }
    }
}
