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

        // eprintln!("Attaching to {:?}...", pid);

        // ptrace::seize(pid, ptrace::Options::empty())?;

        match inferior.wait(None) {
            Ok(WaitStatus::Stopped(_, signal::SIGTRAP)) => {
                eprintln!("found sigtrap!");
                Ok(inferior)
            },
            x => Err(anyhow!("unable to wait: {:?}", x))
        }
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<WaitStatus> {
        Ok(waitpid(self.pid, options)?)
    }

    pub fn resume(&mut self) -> Result<WaitStatus> {
        ptrace::cont(self.pid, None)?;
        self.wait(None)
    }

    pub fn kill(&mut self) -> Result<WaitStatus> {
        println!("Killing running inferior (pid {})", self.pid);
        ptrace::kill(self.pid)?;
        self.wait(None)
    }

    pub fn step(&mut self) -> Result<WaitStatus> {
        ptrace::step(self.pid, None)?;
        Ok(self.wait(None)?)
    }
}
