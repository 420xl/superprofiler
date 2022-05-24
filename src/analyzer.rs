use crate::inferior::{ExecutionState, ProcMessage};
use crate::instruction::Instruction;
use crate::profiler::ProfilerMessage;
use crate::supervisor::SupervisorCommand;
use crate::{utils, Options};
use anyhow::Result;
use log::{debug, info};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::collections::hash_map::Entry::Occupied;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;

pub struct CodeAnalyzer<'a> {
    known_branching_instructions: HashSet<Instruction>,
    instrumented_addresses: HashSet<u64>,
    seen_addresses: HashMap<u64, u64>,
    known_function_addresses: HashMap<u64, String>,
    breakpoint_hits: HashMap<u64, u64>,
    total_breakpoint_hits: u64,
    cmd_tx: mpsc::Sender<SupervisorCommand>,
    info_rx: mpsc::Receiver<ProcMessage>,
    profiler_tx: mpsc::Sender<ProfilerMessage>,
    proc_map: Option<Vec<MapRange>>,
    pid: Pid,
    options: &'a mut Options,
}

impl<'a> CodeAnalyzer<'a> {
    pub fn new(
        cmd_tx: mpsc::Sender<SupervisorCommand>,
        info_rx: mpsc::Receiver<ProcMessage>,
        profiler_tx: mpsc::Sender<ProfilerMessage>,
        pid: Pid,
        options: &'a mut Options,
    ) -> Self {
        Self {
            known_branching_instructions: HashSet::new(),
            instrumented_addresses: HashSet::new(),
            seen_addresses: HashMap::new(),
            breakpoint_hits: HashMap::new(),
            known_function_addresses: HashMap::new(),
            total_breakpoint_hits: 0,
            proc_map: None,
            profiler_tx,
            options,
            cmd_tx,
            info_rx,
            pid,
        }
    }

    pub fn ingest_breakpoint_hit(&mut self, addr: u64) -> Result<()> {
        let counter = self.breakpoint_hits.entry(addr).or_insert(0);
        *counter += 1;
        self.total_breakpoint_hits += 1;

        if !self.options.allow_bottlenecking
            && self.total_breakpoint_hits > 50000
            && *counter > (self.total_breakpoint_hits / 10)
        {
            info!("Detected bottleneck at {:#x} (accounting for {} of {} active bp hits)! Deinstrumenting...", addr, counter, self.total_breakpoint_hits);
            self.cmd_tx
                .send(SupervisorCommand::DeleteBreakpoint(addr))?;
            self.total_breakpoint_hits -= *counter;
        }
        debug!("Saw hit at {:#x}", addr);
        Ok(())
    }

    pub fn ingest_execution_state(&mut self, state: &ExecutionState) -> Result<()> {
        // Update the seen addresses
        let counter = self.seen_addresses.entry(state.address).or_insert(0);
        *counter += 1;

        if let Some(stack) = &state.trace {
            for function in stack
                .iter()
                .skip(self.options.func_instrumentation_depth.try_into()?)
            {
                if function.func_name.is_some()
                    && !self
                        .known_function_addresses
                        .contains_key(&function.address)
                    && !self.instrumented_addresses.contains(&function.address)
                {
                    if self
                        .addr_is_instrumentable(function.address)
                        .unwrap_or(false)
                        && !self.options.no_instrumentation
                    {
                        info!(
                            "Instrumenting function {:#} at {:#x} [exec: {}]",
                            rustc_demangle::demangle(function.func_name.as_ref().unwrap()),
                            function.address,
                            self.addr_filename(function.address)
                        );
                        self.cmd_tx
                            .send(SupervisorCommand::SetBreakpoint(function.address))?;
                        self.instrumented_addresses.insert(function.address);
                    }
                    self.known_function_addresses.insert(
                        function.address,
                        function.func_name.as_ref().unwrap().clone(),
                    );
                }
            }
        }

        // If it's a function call, notify profiler
        if let Occupied(name) = self.known_function_addresses.entry(state.address) {
            self.profiler_tx
                .send(ProfilerMessage::FunctionCall(name.get().clone()))?;
        }

        // Give the profiler general information
        self.profiler_tx
            .send(ProfilerMessage::State(state.clone()))?;

        Ok(())
    }

    pub fn ingest_single_step_sequence(&mut self, sequence: Vec<ExecutionState>) -> Result<()> {
        self.refresh_proc_map()?;

        for (preceding, following) in sequence.iter().zip(sequence.iter().skip(1)) {
            // First, check if it's a branch
            let size = preceding.instruction.length;
            if !self.options.no_instrumentation
                && preceding.address + size as u64 != following.address
                && preceding.address != following.address
                && !preceding.instruction.is_breakpoint()
                && !self.instrumented_addresses.contains(&preceding.address)
                && self
                    .addr_is_instrumentable(preceding.address)
                    .unwrap_or(false)
            {
                // It's a branch! Add it to the known branching instructions.
                self.instrumented_addresses.insert(preceding.address);
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

    fn addr_is_instrumentable(&self, addr: u64) -> Option<bool> {
        if let Some(map) = self.addr_map(addr) {
            if let Some(path) = map.filename() {
                return Some(self.options.only_instrument.iter().any(|p| p == path));
            }
        }
        return None;
    }

    pub fn extract_instrumentable_executables(&mut self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(_) = self.refresh_proc_map() {
            if let Some(maps) = &self.proc_map {
                for map in maps {
                    if let Some(path) = map.filename() {
                        let name = path.to_string_lossy().to_string();
                        if map.is_exec() && !(name.contains(".so") || name.contains("[")) {
                            paths.push(path.to_path_buf());
                        }
                    }
                }
            }
        }
        paths
    }

    pub fn analyze(&mut self) {
        if self.options.only_instrument.len() == 0 && self.options.should_instrument() {
            let executables = self.extract_instrumentable_executables();
            info!("No explicit binaries provided to instrument. I therefore did my best to find binaries to instrument. I will instrument: {}", executables.iter().map(|x| x.to_string_lossy().to_string()).collect::<Vec<String>>().join(", "));
            self.options.only_instrument = executables;
        }

        let mut state_buffer: Vec<ExecutionState> = Vec::new();
        let mut exploration_state_id: usize = 0;
        loop {
            match self.info_rx.recv() {
                Ok(message) => match message {
                    ProcMessage::State(state) => {
                        self.ingest_execution_state(&state)
                            .expect("Unable to ingest execution state");
                        if let Some(id) = state.exploration_step_id {
                            if id != exploration_state_id {
                                self.ingest_single_step_sequence(state_buffer)
                                    .expect("Unable to ingest sequence buffer!");
                                state_buffer = Vec::new();
                                exploration_state_id = id;
                            }
                            state_buffer.push(state);
                        }
                    }
                    ProcMessage::BreakpointHit(addr) => {
                        self.ingest_breakpoint_hit(addr)
                            .expect("Unable to ingest breakpoint hit!");
                    }
                },
                Err(_) => {
                    break;
                }
            }
        }
    }
}
