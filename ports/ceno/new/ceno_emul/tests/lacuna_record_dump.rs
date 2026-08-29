// Temporary: dump the real StepRecord ceno's emulator hands to witness generation
// for one DIVU instruction. Not part of the evaluation corpus.
use ceno_emul::{
    CENO_PLATFORM, FullTracer, FullTracerConfig, InsnKind, Program, VMState, encode_rv32,
};
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn dump_divu_record() {
    // x1 = 4 ; x2 = 2 ; x5 = DIVU(x1, x2) ; halt
    let insns = vec![
        encode_rv32(InsnKind::ADDI, 0, 0, 1, 4),
        encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
        encode_rv32(InsnKind::DIVU, 1, 2, 5, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 10, 0),
        encode_rv32(InsnKind::ADDI, 0, 0, 5, 0),
        encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
    ];
    let pc = CENO_PLATFORM.pc_base();
    let program = Program::new(pc, pc, CENO_PLATFORM.heap.start, insns, BTreeMap::new());
    let mut vm: VMState<FullTracer> = VMState::new_with_tracer_config(
        CENO_PLATFORM.clone(),
        Arc::new(program),
        FullTracerConfig { max_step_shard: 64 },
    );
    let idxs: Vec<_> = vm.iter_until_halt().collect::<Result<_, _>>().unwrap();
    for i in idxs {
        let s = vm.tracer().step_record(i);
        println!("======== {:?} ========", s.insn().kind);
        println!("{s:#?}");
    }
}
