use crate::instruction::Instruction;
use anyhow::Context;
use anyhow::anyhow;
use anyhow::Result;
use log::{debug, error, info};
use nix;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time;
use std::time::SystemTime;
use nix::sys::personality::{self, Persona};

pub struct ExecutionState {
    pub time: SystemTime,
    pub address: u64,
    pub instruction: Instruction,
}

pub struct Breakpoint {
    pub address: u64,
    pub old_data: u64,
}

pub struct Inferior {
    pub pid: Pid, // Will also contain profiling data
    pub breakpoints: HashMap<u64, Breakpoint>
}

impl Inferior {
    pub fn from_pid(pid: Pid) -> Result<()> {
        Ok(ptrace::attach(pid)?)
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
        let inferior = Inferior { pid: pid, breakpoints: HashMap::new() };

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
        let breakpoint_instruction = 0xCC;

        // Figure out what the old instruction was
        let old_data = u64::from_le_bytes(self.read_memory(addr, 1)?.try_into().unwrap());

        // Setup the breakpoint in our own system
        let breakpoint = Breakpoint {
            address: addr,
            old_data: old_data,
        };
        let new_data = (old_data & 0x00FFFFFF) | breakpoint_instruction;
        self.breakpoints.insert(addr, breakpoint);

        // Actually set the breakpoint
        Ok(self.write_memory(addr, new_data.to_le_bytes().into())?)
    }

    pub fn unset_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint = self.breakpoints.get(&addr).context("breakpoint not found")?;
        Ok(self.write_memory(addr, breakpoint.old_data.to_le_bytes().into())?)
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
            instruction: Instruction(self.read_memory(addr, 2)?),
            time: time::SystemTime::now(),
        })
    }
}

pub fn supervise(tx: mpsc::Sender<ExecutionState>, mut proc: Inferior) -> Result<(u64, i32)> {
    // Right now, we collect data and send it to the analyzer.
    // Help from <https://gist.github.com/carstein/6f4a4fdf04ec002d5494a11d2cf525c7>
    let mut iterations = 0;
    loop {
        iterations += 1;
        match proc.wait(None) {
            Ok(WaitStatus::Stopped(_, sig_num)) => {
                match sig_num {
                    Signal::SIGTRAP => {
                        // Handle trap
                        debug!("Trapped!");
                        match proc.get_execution_state() {
                            Ok(state) => tx.send(state).expect("Could not send execution state!"),
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
