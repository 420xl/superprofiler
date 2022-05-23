use anyhow::anyhow;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use log::debug;
use log::error;
use log::info;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use crate::inferior::Inferior;
use crate::inferior::ProcMessage;
use crate::Options;

pub enum SupervisorCommand {
    SetBreakpoint(u64),
    DeleteBreakpoint(u64),
}

pub struct Supervisor<'a> {
    info_tx: mpsc::Sender<ProcMessage>,
    command_rx: mpsc::Receiver<SupervisorCommand>,
    proc: Inferior,
    iterations: u64,
    breakpoint_hits: u64,
    temp_disabled_breakpoint: Option<u64>,
    is_tracee_intentionally_stopped: Arc<AtomicBool>,
    alarm_thread: Option<thread::JoinHandle<()>>,
    exploration_step_id: usize,
    exploration_single_steps: usize,
    options: &'a Options,
}

enum StopOutcome {
    Step(Option<Signal>),
    Continue(Option<Signal>),
    Nothing,
}

impl<'a> Supervisor<'a> {
    pub fn new(
        info_tx: mpsc::Sender<ProcMessage>,
        command_rx: mpsc::Receiver<SupervisorCommand>,
        proc: Inferior,
        options: &'a Options,
    ) -> Self {
        Self {
            info_tx,
            command_rx,
            proc,
            options,

            iterations: 0,
            breakpoint_hits: 0,
            temp_disabled_breakpoint: None,
            is_tracee_intentionally_stopped: Arc::new(false.into()),
            alarm_thread: None,

            exploration_step_id: 0,
            exploration_single_steps: 0,
        }
    }

    fn execute_command(&mut self, command: SupervisorCommand) -> Result<()> {
        match command {
            SupervisorCommand::SetBreakpoint(addr) => self.proc.set_breakpoint(addr),
            SupervisorCommand::DeleteBreakpoint(addr) => self.proc.delete_breakpoint(addr),
        }
    }

    fn reenable_stepping_breakpoint(&mut self) {
        if let Some(bp) = self.temp_disabled_breakpoint {
            if self.proc.has_breakpoint_disabled(bp) {
                self.proc
                    .enable_breakpoint(bp)
                    .expect("unable to re-enable breakpoint");
                debug!("Re-enabled breakpoint!");
            }
            self.temp_disabled_breakpoint = None;
        }
    }

    fn execute_incoming_commands(&mut self) -> Result<usize> {
        let mut total = 0;
        loop {
            match self.command_rx.try_recv() {
                Ok(cmd) => self.execute_command(cmd)?,
                Err(_) => break, // No commands to run
            }
            total += 1;
        }
        Ok(total)
    }

    fn handle_stop(&mut self, signal: Signal) -> Result<StopOutcome> {
        match signal {
            Signal::SIGTRAP | Signal::SIGSTOP => {
                // If it's a SIGSTOP, verify that we sent it ourselves...
                if signal == Signal::SIGSTOP {
                    debug!("    ...via SIGSTOP!");
                    if self.is_tracee_intentionally_stopped.load(Ordering::Relaxed) {
                        self.is_tracee_intentionally_stopped
                            .store(false, Ordering::Relaxed);
                        debug!("    ...caught intentional SIGSTOP! [{}]", self.iterations);
                    } else {
                        debug!("    ...not intentionally; ignoring...");
                        return Ok(StopOutcome::Nothing);
                    }
                }

                // Handle trap
                match self
                    .proc
                    .get_execution_state(Some(self.exploration_step_id), signal == Signal::SIGSTOP)
                {
                    Ok(state) => {
                        if !self.proc.has_breakpoint(state.address - 1) {
                            self.proc.seen_addresses.insert(state.address);
                        }

                        debug!("[{}] Trapped at {}", self.iterations, state);
                        let prev_bkpt = state.address - 1;
                        if self.proc.has_breakpoint_enabled(prev_bkpt) && signal == Signal::SIGTRAP
                        {
                            assert!(self.temp_disabled_breakpoint.is_none());
                            debug!(
                                "[{}] Hit breakpoint at {:#x}",
                                self.iterations, state.address
                            );
                            self.breakpoint_hits += 1;
                            self.info_tx.send(ProcMessage::BreakpointHit(prev_bkpt))?;

                            self.proc.disable_breakpoint(prev_bkpt)?;
                            self.proc.set_instruction_pointer(prev_bkpt)?;
                            self.temp_disabled_breakpoint = Some(prev_bkpt); // We will re-enable post single stepping
                            return Ok(StopOutcome::Step(None));
                        } else {
                            self.info_tx.send(ProcMessage::State(state.clone()))?;

                            // If there have been fewer than 500 single steps (TODO: make this configurable),
                            // then that means we are still in "exploration mode" — looking for jumps.
                            if self.exploration_single_steps < 500 {
                                self.exploration_single_steps += 1;
                                return Ok(StopOutcome::Step(None));
                            } else {
                                debug!(
                                    "[{}] Finished exploration {}!",
                                    self.iterations, self.exploration_step_id
                                );
                                self.exploration_single_steps = 0;
                                self.exploration_step_id += 1;
                                return Ok(StopOutcome::Continue(None));
                            }
                        }
                    }
                    Err(err) => {
                        error!("Unable to get execution state: {:?}", err);
                        return Ok(StopOutcome::Continue(None));
                    }
                }
            }

            Signal::SIGSEGV => {
                let maybe_state = self
                    .proc
                    .get_execution_state(Some(self.exploration_step_id), true);
                if let Ok(state) = maybe_state {
                    error!(
                        "[{}] Hit segmentation fault at {} [breakpoint = {}] [set {} breakpoints]",
                        self.iterations,
                        state,
                        self.proc.has_breakpoint(state.address - 1),
                        self.proc.breakpoints.len()
                    );
                } else {
                    error!(
                        "[{}] Hit segmentation fault; unable to get execution state.",
                        self.iterations,
                    )
                }
                return Err(anyhow!("Segmentation fault!"));
            }

            Signal::SIGILL => {
                let state = self
                    .proc
                    .get_execution_state(Some(self.exploration_step_id), true)?;
                return Err(anyhow!("Invalid instruction at {}", state));
            }

            _ => {
                info!("Signaled: {}", signal);
                return Ok(StopOutcome::Continue(Some(signal)));
            }
        }
    }

    fn spawn_alarm_thread(&mut self, interval: u64) -> Result<()> {
        let tracee_pid = self.proc.pid;
        let tracee_bool = self.is_tracee_intentionally_stopped.clone();

        self.alarm_thread = Some(thread::spawn(move || {
            // This will send a SIGTRAP to the tracee periodically
            loop {
                if !tracee_bool.load(Ordering::Relaxed) {
                    tracee_bool.store(true, Ordering::Relaxed);
                    match signal::kill(tracee_pid, Signal::SIGSTOP) {
                        Ok(_) => debug!("sent SIGSTOP to pid {}", tracee_pid),
                        Err(_) => break, // Process must be gone
                    };
                }
                thread::sleep(Duration::from_micros(interval));
            }
        }));

        Ok(())
    }

    pub fn supervise(&mut self) -> Result<(u64, i32)> {
        // Right now, we collect data and send it to the analyzer.
        // Help from <https://gist.github.com/carstein/6f4a4fdf04ec002d5494a11d2cf525c7>
        if !self.options.single {
            // If we're single stepping, then we don't want to sample; single stepping will get everything.
            self.spawn_alarm_thread(self.options.interval)?;
        }

        loop {
            self.iterations += 1;
            match self.proc.wait(None) {
                Ok(WaitStatus::Stopped(_, sig_num)) => {
                    let outcome = self.handle_stop(sig_num).expect("Could not handle stop!");

                    // Execute necessary commands
                    if let Err(err) = self.execute_incoming_commands() {
                        error!("error executing commands: {}", err);
                    }

                    // Re-enable temporarily disabled breakpoints
                    self.reenable_stepping_breakpoint();

                    match outcome {
                        StopOutcome::Continue(sig) => {
                            if self.options.single {
                                self.proc.step(sig)?
                            } else {
                                self.proc.cont(sig)?
                            }
                        }
                        StopOutcome::Step(sig) => self.proc.step(sig)?,
                        StopOutcome::Nothing => {}
                    }
                }

                Ok(WaitStatus::Exited(pid, exit_status)) => {
                    info!(
                        "Process {} exited with status {}, set {} breakpoints (with {} hits)",
                        pid,
                        exit_status,
                        self.proc.breakpoints.len(),
                        self.breakpoint_hits
                    );
                    return Ok((self.iterations, exit_status));
                }

                Ok(WaitStatus::Signaled(pid, signal, core_dumped)) => {
                    return Err(anyhow!(
                        "Process {} was killed by signal {}, core dumped = {}",
                        pid,
                        signal.as_str(),
                        core_dumped
                    ));
                }

                Ok(status) => {
                    info!("Received status: {:?}", status);
                    self.proc.cont(None)?;
                }

                Err(err) => {
                    return Err(err);
                }
            }
        }
    }
}
