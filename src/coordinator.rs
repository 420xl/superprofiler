use crate::instruction::Instruction;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::{debug, error, info};
use nix;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;

use nix::sys::personality::{self, Persona};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct ExecutionState {
    pub time: SystemTime,
    pub address: u64,
    pub instruction: Instruction,
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
        debug!("Setting breakpoint at {}...", addr);

        // Figure out what the old instruction was
        let old_data = u64::from_le_bytes(self.read_memory(addr, 1)?.try_into().unwrap());

        // Setup the breakpoint in our own system
        let breakpoint = Breakpoint {
            address: addr,
            old_data: old_data,
            enabled: false,
        };
        self.breakpoints.insert(addr, breakpoint);

        // Actually set the breakpoint
        self.enable_breakpoint(addr)
    }

    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains_key(&addr)
    }

    pub fn disable_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint = self
            .breakpoints
            .get_mut(&addr)
            .context("breakpoint not found")?;
        let to_write: Vec<u8> = breakpoint.old_data.to_le_bytes().into();
        breakpoint.enabled = false;
        self.write_memory(addr, to_write)?;
        Ok(())
    }

    pub fn enable_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint_instruction = 0xCC;

        let breakpoint = self
            .breakpoints
            .get_mut(&addr)
            .context("breakpoint not found")?;
        let new_data = (breakpoint.old_data & (u64::MAX ^ 0xFF)) | breakpoint_instruction;
        breakpoint.enabled = true;
        self.write_memory(addr, new_data.to_le_bytes().into())?;

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

    pub fn write_memory(&mut self, addr: u64, data: Vec<u8>) -> Result<()> {
        for (i, word) in data.chunks(8).enumerate() {
            unsafe {
                ptrace::write(
                    self.pid,
                    (addr + i as u64) as *mut libc::c_void,
                    u64::from_le_bytes(word.try_into()?) as *mut libc::c_void,
                )?;
            }
        }
        Ok(())
    }

    pub fn get_execution_state(&mut self) -> Result<ExecutionState> {
        let regs = self.get_registers()?;

        let addr = regs.rip; // TODO: Make platform independent
        Ok(ExecutionState {
            address: addr,
            instruction: Instruction::from_data(self.read_memory(addr, 2)?),
            time: time::SystemTime::now(),
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
    loop {
        loop {
            match rx.try_recv() {
                Ok(cmd) => match proc.execute_command(cmd) {
                    Ok(_) => {}
                    Err(err) => error!("error: {}", err.to_string()),
                },
                Err(_) => break, // No commands to run
            }
        }

        iterations += 1;
        match proc.wait(None) {
            Ok(WaitStatus::Stopped(_, sig_num)) => {
                match sig_num {
                    Signal::SIGTRAP => {
                        // Handle trap
                        debug!("Trapped!");
                        match proc.get_execution_state() {
                            Ok(state) => {
                                tx.send(state.clone())
                                    .expect("Could not send execution state!");
                                info!(
                                    "    breakpoint at {}: {}",
                                    state.address,
                                    proc.has_breakpoint(state.address)
                                );
                            }
                            Err(err) => error!("Unable to send execution state: {:?}", err),
                        }
                        proc.step()?;
                    }

                    Signal::SIGSEGV => return Err(anyhow!("Segmentation fault!")),
                    _ => return Err(anyhow!("Signaled: {}", sig_num)),
                }
            }

            Ok(WaitStatus::Exited(pid, exit_status)) => {
                info!("process {} exited with status {}!", pid, exit_status);
                return Ok((iterations, exit_status));
            }

            Ok(status) => {
                info!("peceived status: {:?}", status);
                ptrace::cont(proc.pid, None)?;
            }

            Err(err) => {
                return Err(err);
            }
        }
    }
}
