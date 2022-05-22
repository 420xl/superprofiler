use crate::inferior::ExecutionState;
use crate::instruction::Instruction;
use crate::supervisor::SupervisorCommand;
use crate::utils;
use anyhow::Result;
use log::{debug, info};
use nix::unistd::Pid;
use proc_maps::{MapRange, get_process_maps};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

pub struct CodeAnalyzer {
    known_branching_instructions: HashSet<Instruction>,
    known_branching_addresses: HashSet<u64>,
    seen_addresses: HashMap<u64, u64>,
    cmd_tx: mpsc::Sender<SupervisorCommand>,
    proc_map: Option<Vec<MapRange>>,
    pid: Pid
}

impl CodeAnalyzer {
    pub fn new(cmd_tx: mpsc::Sender<SupervisorCommand>, pid: Pid) -> Self {
        Self {
            known_branching_instructions: HashSet::new(),
            known_branching_addresses: HashSet::new(),
            seen_addresses: HashMap::new(),
            proc_map: None,
            cmd_tx,
            pid
        }
    }

    pub fn ingest_execution_state(&mut self, state: &ExecutionState) {
        let _size = state.instruction.length;
        let counter = self.seen_addresses.entry(state.address).or_insert(0);
        *counter += 1;
    }

    pub fn ingest_single_step_sequence(&mut self, sequence: Vec<ExecutionState>) -> Result<()> {
        self.refresh_proc_map()?;

        for (preceding, following) in sequence.iter().zip(sequence.iter().skip(1)) {
            // First, check if it's a branch
            let size = preceding.instruction.length;
            if preceding.address + size as u64 != following.address
                && preceding.address != following.address
                && !preceding.instruction.is_breakpoint()
                && !self.known_branching_addresses.contains(&preceding.address)
                && self.addr_is_instrumentable(preceding.address).unwrap_or(false)
            {
                // It's a branch! Add it to the known branching instructions.
                self.known_branching_addresses.insert(preceding.address);
                info!(
                    "Instrumenting {:#x}: {} [offset: {}, expected: {}] [exec: {}]",
                    preceding.address,
                    preceding.instruction,
                    utils::offset(preceding.address, following.address),
                    size,
                    self.addr_filename(preceding.address)
                );
                self.known_branching_instructions
                    .insert(preceding.instruction.clone());

                // Set a breakpoint at the jump
                self.cmd_tx
                    .send(SupervisorCommand::SetBreakpoint(preceding.address))?;
            } else {
                debug!(
                    "Not a branch instruction at {}: {}",
                    preceding.address, preceding.instruction
                );
            }
        }

        Ok(())
    }

    fn refresh_proc_map(&mut self) -> Result<()> {
        let maps = get_process_maps(self.pid.as_raw())?;
        self.proc_map = Some(maps);

        Ok(())
    }

    fn addr_map(&self, addr: u64) -> Option<&MapRange> {
        if let Some(maps) = &self.proc_map {
            if let Some(val) = maps.iter().find(|map| {
                let start = map.start() as u64;
                (addr >= start) && (addr < (start + map.size() as u64))
            }) {
                return Some(val);
            }
        }
        None
    }

    fn addr_filename(&self, addr: u64) -> String {
        if let Some(map) = self.addr_map(addr) {
            if let Some(path) = map.filename() {
                return path.to_string_lossy().to_string();
            }
        }
        return "<unknown>".into();
    }

    fn addr_is_executable(&self, addr: u64) -> Option<bool> {
        if let Some(map) = self.addr_map(addr) {
            return Some(map.is_exec());
        }
        return None;
    }

    fn addr_is_instrumentable(&self, addr: u64) -> Option<bool> {
        if let Some(map) = self.addr_map(addr) {
            if let Some(path) = map.filename() {
                let name = path.to_string_lossy().to_string();
                return Some(map.is_exec() && !(name.contains(".so") || name == "[vdso]"));
            }
        }
        return None;
    }
}

pub fn analyze(state_rx: mpsc::Receiver<ExecutionState>, cmd_tx: mpsc::Sender<SupervisorCommand>, pid: Pid) {
    let mut analyzer = CodeAnalyzer::new(cmd_tx, pid);
    let mut state_buffer: Vec<ExecutionState> = Vec::new();
    let mut exploration_state_id: usize = 0;
    loop {
        match state_rx.recv() {
            Ok(state) => {
                analyzer.ingest_execution_state(&state);
                if let Some(id) = state.exploration_step_id {
                    if id != exploration_state_id {
                        analyzer
                            .ingest_single_step_sequence(state_buffer)
                            .expect("Unable to ingest sequence buffer!");
                        state_buffer = Vec::new();
                        exploration_state_id = id;
                    }
                    state_buffer.push(state);
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}
