use crate::utils::Error;
use nix::unistd::Pid;

pub struct Process {
    pid: Pid, // Will also contain profiling data
}

impl Process {
    pub fn from_command(command: &str) -> Result<Self, Error> {
        Err(Error::with_literal("not yet implemented..."))
    }

    pub fn from_pid(pid: u32) -> Result<Self, Error> {
        unimplemented!();
    }
}
