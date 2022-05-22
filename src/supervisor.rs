use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;
use log::info;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use crate::inferior::{ExecutionState, Inferior};

pub enum SupervisorCommand {
    SetBreakpoint(u64),
}

pub struct Supervisor {
    state_tx: mpsc::Sender<ExecutionState>,
    command_rx: mpsc::Receiver<SupervisorCommand>,
    proc: Inferior
}

impl Supervisor {
    pub fn new(state_tx: mpsc::Sender<ExecutionState>, command_rx: mpsc::Receiver<SupervisorCommand>, proc: Inferior) -> Self {
        Self {
            state_tx, command_rx, proc
        }
    }

    fn execute_command(&mut self, command: SupervisorCommand) -> Result<()> {
        match command {
            SupervisorCommand::SetBreakpoint(addr) => self.proc.set_breakpoint(addr),
        }
    }

    pub fn supervise(
        &mut self
    ) -> Result<(u64, i32)> {
        // Right now, we collect data and send it to the analyzer.
        // Help from <https://gist.github.com/carstein/6f4a4fdf04ec002d5494a11d2cf525c7>
        let mut iterations = 0;
        let mut breakpoint_hits = 0;
        let mut temp_disabled_breakpoint: Option<u64> = None; // Keeps track of breakpoints temporarily disabled because we're stepping
    
        let is_tracee_intentionally_stopped: Arc<AtomicBool> = Arc::new(false.into());
        let tracee_pid = self.proc.pid;
        let tracee_bool = is_tracee_intentionally_stopped.clone();
    
        let _alarm_thread = thread::spawn(move || {
            // This will send a SIGTRAP to the tracee periodically
            loop {
                if !tracee_bool.load(Ordering::Relaxed) {
                    tracee_bool.store(true, Ordering::Relaxed);
                    match signal::kill(tracee_pid, Signal::SIGSTOP) {
                        Ok(_) => debug!("sent SIGSTOP to pid {}", tracee_pid),
                        Err(_) => break, // Process must be gone
                    };
                }
                thread::sleep(Duration::from_micros(25));
            }
        });
    
        let mut exploration_single_steps: i32 = 0;
        let mut exploration_step_id: usize = 0;
        loop {
            iterations += 1;
            match self.proc.wait(None) {
                Ok(WaitStatus::Stopped(_, sig_num)) => {
                    match sig_num {
                        Signal::SIGTRAP | Signal::SIGSTOP => {
                            debug!("Tracee stopped!");
                            // If it's a SIGSTOP, verify that we sent it ourselves...
                            if sig_num == Signal::SIGSTOP {
                                debug!("    ...via SIGSTOP!");
                                if is_tracee_intentionally_stopped.load(Ordering::Relaxed) {
                                    is_tracee_intentionally_stopped.store(false, Ordering::Relaxed);
                                    debug!("    ...caught intentional SIGSTOP! [{}]", iterations);
                                } else {
                                    debug!("    ...not intentionally; ignoring...");
                                    continue;
                                }
                            }
    
                            // Re-enable temporarily disabled breakpoints
                            if let Some(bp) = temp_disabled_breakpoint {
                                self.proc.enable_breakpoint(bp)
                                    .expect("Unable to re-enable temporarily disabled breakpoint!");
                                debug!("Re-enabled breakpoint!");
                                temp_disabled_breakpoint = None;
                            }
    
                            // Execute necessary commands
                            loop {
                                match self.command_rx.try_recv() {
                                    Ok(cmd) => match self.execute_command(cmd) {
                                        Ok(_) => {}
                                        Err(err) => error!("error: {}", err.to_string()),
                                    },
                                    Err(_) => break, // No commands to run
                                }
                            }
    
                            // Handle trap
                            match self.proc.get_execution_state(Some(exploration_step_id)) {
                                Ok(state) => {
                                    if !self.proc.has_breakpoint(state.address - 1) {
                                        self.proc.seen_addresses.insert(state.address);
                                    }
    
                                    debug!("[{}] Trapped at {}", iterations, state);
                                    let prev_bkpt = state.address - 1;
                                    if self.proc.has_breakpoint_enabled(prev_bkpt)
                                        && sig_num == Signal::SIGTRAP
                                    {
                                        assert!(temp_disabled_breakpoint.is_none());
                                        debug!(
                                            "[{}] Hit breakpoint at {:#x}",
                                            iterations, state.address
                                        );
                                        breakpoint_hits += 1;
    
                                        self.proc.disable_breakpoint(prev_bkpt)
                                            .expect("Could not disable breakpoint");
                                        self.proc.set_instruction_pointer(prev_bkpt)
                                            .expect("Could not rewind instruction pointer");
                                        temp_disabled_breakpoint = Some(prev_bkpt); // We will re-enable post single stepping
                                        self.proc.step()?;
                                    } else {
                                        self.state_tx.send(state.clone())
                                            .expect("Could not send execution state!");
    
                                        // If there have been fewer than 500 single steps (TODO: make this configurable),
                                        // then that means we are still in "exploration mode" — looking for jumps.
                                        if exploration_single_steps < 500 {
                                            exploration_single_steps += 1;
                                            self.proc.step()?;
                                        } else {
                                            debug!(
                                                "[{}] Finished exploration {}!",
                                                iterations, exploration_step_id
                                            );
                                            exploration_single_steps = 0;
                                            exploration_step_id += 1;
                                            self.proc.cont()?;
                                            self.proc.refresh_proc_map()?;
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!("Unable to get execution state: {:?}", err);
                                    self.proc.cont()?;
                                }
                            }
                        }
    
                        Signal::SIGSEGV => {
                            let maybe_state = self.proc.get_execution_state(Some(exploration_step_id));
                            if let Ok(state) = maybe_state {
                                error!(
                                    "[{}] Hit segmentation fault at {} [breakpoint = {}] [set {} breakpoints] [filename = {}]",
                                    iterations,
                                    state,
                                    self.proc.has_breakpoint(state.address - 1),
                                    self.proc.breakpoints.len(),
                                    self.proc.addr_filename(state.address)
                                );
                            } else {
                                error!(
                                    "[{}] Hit segmentation fault; unable to get execution state.",
                                    iterations,
                                )
                            }
                            return Err(anyhow!("Segmentation fault!"));
                        }
    
                        Signal::SIGILL => {
                            let state = self.proc.get_execution_state(Some(exploration_step_id))?;
                            return Err(anyhow!("Invalid instruction at {}", state));
                        }
    
                        _ => {
                            info!("Signaled: {}", sig_num);
                            self.proc.cont()?;
                        }
                    }
                }
    
                Ok(WaitStatus::Exited(pid, exit_status)) => {
                    info!(
                        "Process {} exited with status {}, set {} breakpoints (with {} hits)",
                        pid,
                        exit_status,
                        self.proc.breakpoints.len(),
                        breakpoint_hits
                    );
                    return Ok((iterations, exit_status));
                }
    
                Ok(WaitStatus::Signaled(pid, signal, core_dumped)) => {
                    return Err(anyhow!(
                        "Process {} was killed by signal {}, core dumped? {}",
                        pid,
                        signal.as_str(),
                        core_dumped
                    ));
                }
    
                Ok(status) => {
                    info!("Received status: {:?}", status);
                    self.proc.cont()?;
                }
    
                Err(err) => {
                    return Err(err);
                }
            }
        }
    }
}