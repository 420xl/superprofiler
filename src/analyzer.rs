use crate::coordinator::ExecutionState;
use crate::instruction::Instruction;
use crate::utils;
use log::{debug, info};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

pub struct CodeAnalyzer {
    known_branching_instructions: HashSet<Instruction>,
    known_branching_addresses: HashSet<u64>,
    seen_addresses: HashMap<u64, u64>,
}

impl CodeAnalyzer {
    pub fn new() -> Self {
        Self {
            known_branching_instructions: HashSet::new(),
            known_branching_addresses: HashSet::new(),
            seen_addresses: HashMap::new(),
        }
    }

    pub fn ingest_execution_state(&mut self, state: &ExecutionState) {
        let size = state.instruction.instruction_size();
        let counter = self.seen_addresses.entry(state.address).or_insert(0);
        *counter += 1;
    }

    pub fn ingest_single_step_sequence(&mut self, sequence: Vec<ExecutionState>) {
        for (preceding, following) in sequence.iter().zip(sequence.iter().skip(1)) {
            // First, check if it's a branch
            let size = preceding.instruction.instruction_size();
            if preceding.address + size as u64 != following.address {
                // It's a branch! Add it to the known branching instructions.
                self.known_branching_addresses.insert(preceding.address);
                info!(
                    "Detected branch instruction at {}: {:?} (addr offset: {}, expected: {})",
                    preceding.address,
                    preceding.instruction,
                    utils::offset(preceding.address, following.address),
                    size
                );
                self.known_branching_instructions
                    .insert(preceding.instruction.clone());
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
                analyzer.ingest_execution_state(&state);
                state_buffer.push(state);

                if state_buffer.len() > 200 {
                    analyzer.ingest_single_step_sequence(state_buffer);
                    state_buffer = Vec::new();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}
