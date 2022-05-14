use nix;
use nix::sys::{ptrace, signal};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::io;
use std::os::unix::process::CommandExt;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use std::process::Command;
use std::time::SystemTime;
use crate::instruction::Instruction;
use anyhow::Result;
use anyhow::anyhow;
use log::debug;

pub struct ExecutionState { pub time: SystemTime, pub address: u64, pub instruction: Instruction }

pub struct Inferior {
    pub pid: Pid, // Will also contain profiling data
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
                    // Adapted from <https://docs.rs/spawn-ptrace/latest/src/spawn_ptrace/lib.rs.html#57>
                    ptrace::traceme().map_err(|e| io::Error::from_raw_os_error(e as i32))
                })
                .spawn()
        };

        let pid = Pid::from_raw(child.unwrap().id() as i32);
        let inferior = Inferior { pid: pid };

        Ok(inferior)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<WaitStatus> {
        Ok(waitpid(self.pid, options)?)
    }

    pub fn kill(&mut self) -> Result<()> {
        println!("Killing running inferior (pid {})", self.pid);
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
}

pub fn supervise(mut proc: Inferior) -> Result<u64> {
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
                        proc.step()?;
                    }
                    
                    Signal::SIGSEGV => {
                        return Err(anyhow!("Segmentation fault!"))
                    }
                    _ => {
                        return Err(anyhow!("Signaled: {}", sig_num))
                    }
                }
            },

            Ok(WaitStatus::Exited(pid, exit_status)) => {
                eprintln!("Process {} exited with status {}!", pid, exit_status);
                return Ok(iterations);
            },

            Ok(status) =>  {
                eprintln!("Received status: {:?}", status);
                ptrace::cont(proc.pid, None)?;
            },

            Err(err) => {
                return Err(err);
            },
        }
    }
}