use nix::unistd::Pid;

struct Process {
    pid: Pid, // Will also contain profiling data
}

impl Process {
    pub fn from_command(command: &str) -> Self {
        unimplemented!();
    }

    pub fn from_pid(pid: u32) -> Self {
        unimplemented!();
    }
}
