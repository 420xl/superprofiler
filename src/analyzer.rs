use crate::coordinator::ExecutionState;
use crate::instruction::Instruction;
use log::debug;
use std::collections::HashSet;
use std::sync::mpsc;

pub struct CodeAnalyzer {
    known_branching_instructions: HashSet<Instruction>,
}

impl CodeAnalyzer {
    pub fn new() -> Self {
        Self {
            known_branching_instructions: HashSet::new()
        }
    }

    pub fn ingest_single_step_sequence(&mut self, sequence: Vec<ExecutionState>) {
        for (preceding, following) in sequence.iter().zip(sequence.iter().skip(1)) {
            // First, check if it's a branch
            if preceding.address + preceding.instruction.instruction_size() as u64
                != following.address
            {
                // It's a branch! Add it to the known branching instructions.
                self.known_branching_instructions
                    .insert(preceding.instruction);
                debug!(
                    "Detected branch instruction at {}: {:?}",
                    preceding.address, preceding.instruction
                );
            } else {
                debug!(
                    "Not a branch instruction at {}: {:?}",
                    preceding.address, preceding.instruction
                );
            }
        }
    }
}

pub fn analyze(rx: mpsc::Receiver<ExecutionState>) {
    let mut analyzer = CodeAnalyzer::new();
    let mut state_buffer: Vec<ExecutionState> = Vec::new();
    loop {
        match rx.recv() {
            Ok(state) => {
                state_buffer.push(state);

                if state_buffer.len() > 200 {
                    analyzer.ingest_single_step_sequence(state_buffer);
                    state_buffer = Vec::new();
                }
            },
            Err(_) => {
                break;
            }
        }
    }
}
