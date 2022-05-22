use crate::instruction::Instruction;
use crate::utils;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::{debug, error, info};
use nix;

use nix::sys::ptrace;

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use std::time;

use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct ExecutionState {
    pub time: SystemTime,
    pub address: u64,
    pub instruction: Instruction,
    pub exploration_step_id: Option<usize>,
}

pub enum ProcMessage {
    State(ExecutionState),
    BreakpointHit(u64),
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
    pub seen_addresses: HashSet<u64>,
}

impl Inferior {
    #[allow(dead_code)]
    pub fn from_pid(pid: Pid) -> Result<Self> {
        ptrace::attach(pid)?;

        Ok(Self {
            pid: pid,
            breakpoints: HashMap::new(),
            seen_addresses: HashSet::new(),
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
                    // personality::set(personality::get()? | Persona::ADDR_NO_RANDOMIZE)?;
                    // Adapted from <https://docs.rs/spawn-ptrace/latest/src/spawn_ptrace/lib.rs.html#57>
                    ptrace::traceme().map_err(|e| io::Error::from_raw_os_error(e as i32))
                })
                .spawn()
        };

        let pid = Pid::from_raw(child.unwrap().id() as i32);
        let inferior = Inferior {
            pid: pid,
            breakpoints: HashMap::new(),
            seen_addresses: HashSet::new(),
        };

        Ok(inferior)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<WaitStatus> {
        Ok(waitpid(self.pid, options)?)
    }

    #[allow(dead_code)]
    pub fn kill(&mut self) -> Result<()> {
        info!("Killing running inferior (pid {})", self.pid);
        Ok(ptrace::kill(self.pid)?)
    }

    pub fn step(&mut self) -> Result<()> {
        Ok(ptrace::step(self.pid, None)?)
    }

    #[allow(dead_code)]
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
            debug!("Setting breakpoint at {}", instruction);

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

    #[allow(dead_code)]
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

    pub fn delete_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.disable_breakpoint(addr)?;
        self.breakpoints.remove(&addr).ok_or(anyhow!("unable to delete breakpoint"))?;
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
        let old_val = breakpoint.old_data as u8;
        let new_val = self.write_byte(addr, breakpoint_instruction)?;
        if new_val != old_val {
            return Err(anyhow!(
                "Breakpoint at {:#x} contained byte {} (expected {})",
                addr,
                new_val,
                old_val
            ));
        }

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
        if !self.seen_addresses.contains(&addr) {
            error!("Writing {} to unseen address {}!", val, addr);
        }

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
}
