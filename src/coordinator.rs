use crate::utils::ProfilerError;
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::process::Command;

pub struct Process {
    pub pid: Pid, // Will also contain profiling data
}

impl Process {
    fn attach_to_process(pid: Pid) -> Result<(), ProfilerError> {
        Ok(ptrace::attach(pid)?)
    }

    pub fn from_command(command: &str) -> Result<Self, ProfilerError> {
        // First, we extract the necessary data.
        let mut args = command.split_whitespace();
        let executable = args.next().unwrap();

        let command = Command::new(executable).args(args).spawn()?;

        Ok(Process {
            pid: Pid::from_raw(command.id().try_into()?),
        })
    }

    pub fn from_pid(pid: u32) -> Result<Self, ProfilerError> {
        unimplemented!();
    }
}
