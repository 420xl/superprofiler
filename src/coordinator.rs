use crate::instruction::Instruction;
use crate::utils;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::{debug, error, info};
use nix;
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Condvar;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time;
use std::time::Duration;
use std::time::SystemTime;
use wait_timeout::ChildExt;

#[derive(Clone, Debug)]
pub struct ExecutionState {
    pub time: SystemTime,
    pub address: u64,
    pub instruction: Instruction,
    pub exploration_step_id: Option<usize>,
}

impl fmt::Display for ExecutionState {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:#x}: {}", self.address, self.instruction)?;
        Ok(())
    }
}

pub struct Breakpoint {
    pub address: u64,
    pub old_data: u64,
    pub enabled: bool,
}

pub struct Inferior {
    pub pid: Pid, // Will also contain profiling data
    pub breakpoints: HashMap<u64, Breakpoint>,
}

pub enum SupervisorCommand {
    SetBreakpoint(u64),
}

impl Inferior {
    pub fn from_pid(pid: Pid) -> Result<Self> {
        ptrace::attach(pid)?;

        Ok(Self {
            pid: pid,
            breakpoints: HashMap::new(),
        })
    }

    pub fn from_command(command: &str) -> Result<Self> {
        // First, we extract the necessary data.
        let mut args = command.split_whitespace();
        let executable = args.next().unwrap();

        let child = unsafe {
            Command::new(executable)
                .args(args)
                .pre_exec(|| {
                    personality::set(personality::get()? | Persona::ADDR_NO_RANDOMIZE)?;
                    // Adapted from <https://docs.rs/spawn-ptrace/latest/src/spawn_ptrace/lib.rs.html#57>
                    ptrace::traceme().map_err(|e| io::Error::from_raw_os_error(e as i32))
                })
                .spawn()
        };

        let pid = Pid::from_raw(child.unwrap().id() as i32);
        let inferior = Inferior {
            pid: pid,
            breakpoints: HashMap::new(),
        };

        Ok(inferior)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<WaitStatus> {
        Ok(waitpid(self.pid, options)?)
    }

    pub fn kill(&mut self) -> Result<()> {
        info!("killing running inferior (pid {})", self.pid);
        Ok(ptrace::kill(self.pid)?)
    }

    pub fn step(&mut self) -> Result<()> {
        Ok(ptrace::step(self.pid, None)?)
    }

    pub fn interrupt(&mut self) -> Result<()> {
        Ok(ptrace::interrupt(self.pid)?)
    }

    pub fn cont(&mut self) -> Result<()> {
        Ok(ptrace::cont(self.pid, None)?)
    }

    pub fn get_registers(&mut self) -> Result<libc::user_regs_struct> {
        Ok(ptrace::getregs(self.pid)?)
    }

    pub fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if !self.has_breakpoint(addr) {
            let instruction = Instruction::from_data(self.read_memory(addr, 2)?.as_slice());
            info!("Setting breakpoint at {}", instruction);

            // Setup the breakpoint in our own system
            let breakpoint = Breakpoint {
                address: addr,
                old_data: self.read_byte(addr)? as u64,
                enabled: false,
            };
            self.breakpoints.insert(addr, breakpoint);
        } else {
            debug!("Breakpoint already set at {}!", addr);
        }

        // Actually set the breakpoint
        self.enable_breakpoint(addr)?;

        Ok(())
    }

    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains_key(&addr)
    }

    pub fn has_breakpoint_enabled(&self, addr: u64) -> bool {
        match self.breakpoints.get(&addr) {
            Some(val) => val.enabled,
            None => false,
        }
    }

    pub fn has_breakpoint_disabled(&self, addr: u64) -> bool {
        match self.breakpoints.get(&addr) {
            Some(val) => !val.enabled,
            None => false,
        }
    }

    pub fn disable_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint = self
            .breakpoints
            .get_mut(&addr)
            .context("breakpoint not found")?;
        breakpoint.enabled = false;
        let to_write = breakpoint.old_data as u8;
        debug!(
            "Disabling breakpoint at {:#x}; old data: {}",
            addr, to_write
        );
        self.write_byte(addr, to_write)?;
        Ok(())
    }

    pub fn enable_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint_instruction = 0xCC;

        let breakpoint = self
            .breakpoints
            .get_mut(&addr)
            .context("breakpoint not found")?;
        breakpoint.enabled = true;
        debug!(
            "Enabling breakpoint at {}; old data: {}",
            addr, breakpoint.old_data
        );
        self.write_byte(addr, breakpoint_instruction)?;

        Ok(())
    }

    pub fn read_memory(&mut self, addr: u64, words: u8) -> Result<Vec<u8>> {
        let mut vec: Vec<u8> = Vec::with_capacity(words.into());
        for _ in 0..words {
            let value: u64 = ptrace::read(self.pid, addr as *mut libc::c_void)? as u64;
            vec.extend(value.to_le_bytes());
        }
        Ok(vec)
    }

    // The following function is adapted from <https://reberhardt.com/cs110l/spring-2020/assignments/project-1/>
    fn write_byte(&mut self, addr: u64, val: u8) -> Result<u8> {
        let aligned_addr = utils::align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid, aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte: u8 = ((word >> 8 * byte_offset) & 0xff) as u8;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        unsafe {
            ptrace::write(
                self.pid,
                aligned_addr as ptrace::AddressType,
                updated_word as *mut libc::c_void,
            )?;
        }
        Ok(orig_byte)
    }

    fn read_byte(&mut self, addr: u64) -> Result<u8> {
        let aligned_addr = utils::align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid, aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte: u8 = ((word >> 8 * byte_offset) & 0xff) as u8;
        Ok(orig_byte)
    }

    pub fn set_instruction_pointer(&mut self, addr: u64) -> Result<()> {
        let mut regs = ptrace::getregs(self.pid)?;
        debug!("Setting rip; prev = {}, new = {}", regs.rip, addr);
        regs.rip = addr;
        ptrace::setregs(self.pid, regs)?;

        Ok(())
    }

    pub fn get_execution_state(
        &mut self,
        exploration_step_id: Option<usize>,
    ) -> Result<ExecutionState> {
        let regs = self.get_registers()?;

        let addr = regs.rip; // TODO: Make platform independent
        Ok(ExecutionState {
            address: addr,
            instruction: Instruction::from_data(self.read_memory(addr, 2)?.as_slice()),
            time: time::SystemTime::now(),
            exploration_step_id,
        })
    }

    pub fn execute_command(&mut self, command: SupervisorCommand) -> Result<()> {
        match command {
            SupervisorCommand::SetBreakpoint(addr) => self.set_breakpoint(addr),
        }
    }
}

pub fn supervise(
    tx: mpsc::Sender<ExecutionState>,
    rx: mpsc::Receiver<SupervisorCommand>,
    mut proc: Inferior,
) -> Result<(u64, i32)> {
    // Right now, we collect data and send it to the analyzer.
    // Help from <https://gist.github.com/carstein/6f4a4fdf04ec002d5494a11d2cf525c7>
    let mut iterations = 0;
    let mut temp_disabled_breakpoints: Vec<u64> = Vec::new(); // Keeps track of breakpoints temporarily disabled because we're stepping

    let is_tracee_intentionally_stopped: Arc<AtomicBool> = Arc::new(false.into());
    let tracee_pid = proc.pid;
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
            thread::sleep(Duration::from_micros(100));
        }
    });

    let mut exploration_single_steps: i32 = 0;
    let mut exploration_step_id: usize = 0;
    loop {
        iterations += 1;
        match proc.wait(None) {
            Ok(WaitStatus::Stopped(_, sig_num)) => {
                match sig_num {
                    Signal::SIGTRAP | Signal::SIGSTOP => {
                        debug!("Tracee stopped!");
                        // If it's a sigstop, verify that we sent it ourselves...
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
                        while !temp_disabled_breakpoints.is_empty() {
                            let bp = temp_disabled_breakpoints.pop().unwrap();
                            proc.enable_breakpoint(bp)
                                .expect("Unable to re-enable temporarily disabled breakpoint!");
                            debug!("Re-enabled breakpoint!");
                        }

                        // Execute necessary commands
                        loop {
                            match rx.try_recv() {
                                Ok(cmd) => match proc.execute_command(cmd) {
                                    Ok(_) => {}
                                    Err(err) => error!("error: {}", err.to_string()),
                                },
                                Err(_) => break, // No commands to run
                            }
                        }

                        // Handle trap
                        match proc.get_execution_state(Some(exploration_step_id)) {
                            Ok(state) => {
                                debug!("[{}] Trapped at {}", iterations, state);
                                let prev_bkpt = state.address - 1;
                                if proc.has_breakpoint_enabled(prev_bkpt) {
                                    debug!(
                                        "[{}] Hit breakpoint at {:#x}",
                                        iterations, state.address
                                    );

                                    proc.disable_breakpoint(prev_bkpt)
                                        .expect("Could not disable breakpoint");
                                    proc.set_instruction_pointer(prev_bkpt)
                                        .expect("Could not rewind instruction pointer");
                                    temp_disabled_breakpoints.push(prev_bkpt); // We will re-enable post single stepping
                                    proc.step()?;
                                } else {
                                    tx.send(state.clone())
                                        .expect("Could not send execution state!");

                                    // If there have been fewer than 250 single steps (TODO: make this configurable),
                                    // then that means we are still in "exploration mode" — looking for jumps.
                                    if exploration_single_steps < 50 {
                                        exploration_single_steps += 1;
                                        proc.step()?;
                                    } else {
                                        info!(
                                            "[{}] Finished exploration {}!",
                                            iterations, exploration_step_id
                                        );
                                        exploration_single_steps = 0;
                                        exploration_step_id += 1;
                                        proc.cont()?;
                                    }
                                }
                            }
                            Err(err) => {
                                error!("Unable to get execution state: {:?}", err);
                                proc.cont()?;
                            }
                        }
                    }

                    Signal::SIGSEGV => {
                        let state = proc.get_execution_state(Some(exploration_step_id))?;
                        error!(
                            "[{}] Hit segmentation fault at {} [breakpoint = {}]",
                            iterations,
                            state,
                            proc.has_breakpoint(state.address - 1)
                        );
                        return Err(anyhow!("Segmentation fault!"));
                    }

                    Signal::SIGILL => {
                        let state = proc.get_execution_state(Some(exploration_step_id))?;
                        return Err(anyhow!("Invalid instruction at {}", state));
                    }

                    _ => {
                        info!("Signaled: {}", sig_num);
                        proc.cont()?;
                    }
                }
            }

            Ok(WaitStatus::Exited(pid, exit_status)) => {
                info!(
                    "process {} exited with status {}, set {} breakpoints",
                    pid,
                    exit_status,
                    proc.breakpoints.len()
                );
                return Ok((iterations, exit_status));
            }

            Ok(status) => {
                info!("Received status: {:?}", status);
                ptrace::cont(proc.pid, None)?;
            }

            Err(err) => {
                return Err(err);
            }
        }
    }
}
