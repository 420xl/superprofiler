use anyhow::anyhow;
use rand::Rng;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

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
    recently_reenabled_breakpoint: Option<u64>,
    is_tracee_intentionally_stopped: Arc<AtomicBool>,
    alarm_thread: Option<thread::JoinHandle<()>>,
    alarm_interrupts: Arc<Mutex<u64>>,
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
            recently_reenabled_breakpoint: None,
            is_tracee_intentionally_stopped: Arc::new(false.into()),
            alarm_thread: None,
            alarm_interrupts: Arc::new(Mutex::new(0)),

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
                debug!("Re-enabled breakpoint at {:#x}!", bp);
            }
            self.temp_disabled_breakpoint = None;
            self.recently_reenabled_breakpoint = Some(bp);
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
                } else {
                    debug!("    ...via SIGTRAP!");
                }

                let collect_trace = match signal == Signal::SIGSTOP || self.options.single {
                    true => rand::random::<f32>() < self.options.trace_prob,
                    false => false,
                };

                // disallow alarm interrupts while handling stop
                let mut _alarm_interrupts = self.alarm_interrupts.lock().unwrap();

                // Handle trap
                match self
                    .proc
                    .get_execution_state(Some(self.exploration_step_id), collect_trace)
                {
                    Ok(state) => {
                        debug!("[{}] Trapped at {}", self.iterations, state);
                        let prev_bkpt = state.address - 1;
                        if !self.proc.has_breakpoint(prev_bkpt) {
                            self.proc.seen_addresses.insert(state.address);
                        }
                        if let Some(value) = self.recently_reenabled_breakpoint {
                            debug!("Just stepped past breakpoint; location: {:#x}, current loc: {:#x}", value, state.address);
                        }
                        if self.options.single {
                            self.info_tx
                                .send(ProcMessage::BreakpointHit(prev_bkpt, SystemTime::now()))?;
                        }
                        if self.proc.has_breakpoint_enabled(prev_bkpt)
                            && signal == Signal::SIGTRAP
                            // Make sure we don't repeat the recently reenabled breakpoint if the true instruction is indeed one byte
                            && self.recently_reenabled_breakpoint.unwrap_or(0) != prev_bkpt
                        {
                            assert!(self.temp_disabled_breakpoint.is_none());
                            debug!(
                                "[{}] Hit breakpoint at {:#x}",
                                self.iterations, state.address
                            );
                            self.breakpoint_hits += 1;
                            self.info_tx
                                .send(ProcMessage::BreakpointHit(prev_bkpt, SystemTime::now()))?;

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

        let alarm_interrupts = Arc::clone(&self.alarm_interrupts);
        self.alarm_thread = Some(thread::spawn(move || {
            // This will send a SIGTRAP to the tracee periodically
            let mut rng = rand::thread_rng();
            loop {
                if !tracee_bool.load(Ordering::Relaxed) {
                    let mut alarm_interrupts = alarm_interrupts.lock().unwrap();
                    tracee_bool.store(true, Ordering::Relaxed);
                    match signal::kill(tracee_pid, Signal::SIGSTOP) {
                        Ok(_) => {
                            *alarm_interrupts += 1;
                            debug!("sent SIGSTOP to pid {}", tracee_pid);
                        }
                        Err(_) => break, // Process must be gone
                    };
                }
                let dur = Duration::from_micros(
                    (rng.gen::<f64>() * (interval as f64) * 2f64).round() as u64,
                );
                debug!("Sleeping for {:?}", dur);
                thread::sleep(dur);
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
                    // Re-enable temporarily disabled breakpoint
                    self.reenable_stepping_breakpoint();

                    let outcome = self.handle_stop(sig_num).expect("Error handling stop");

                    // self.reenable_stepping_breakpoint() temporarily stores the `recently_reenabled_breakpoint` to be used in `handle_stop`
                    self.recently_reenabled_breakpoint = None;

                    // Execute necessary commands
                    if let Err(err) = self.execute_incoming_commands() {
                        error!("error executing commands: {}", err);
                    }

                    match outcome {
                        StopOutcome::Continue(sig) => {
                            if self.options.single {
                                debug!("[{}] Continuing via STEPPING!", self.iterations);
                                self.proc.step(sig)?
                            } else {
                                debug!("[{}] Continuing via CONT!", self.iterations);
                                let res = self.proc.cont(sig);
                                res?
                            }
                        }
                        StopOutcome::Step(sig) => {
                            debug!("[{}] Continuing via STEPPING!", self.iterations);
                            self.proc.step(sig)?
                        }
                        StopOutcome::Nothing => {
                            debug!("[{}] Doing nothing!", self.iterations);
                        }
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
