use crate::instruction::Instruction;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::{debug, info};
use nix;
use nix::sys::personality;
use nix::sys::personality::Persona;
use unwind::Accessors;
use unwind::AddressSpace;
use unwind::Byteorder;
use unwind::PTraceState;
use unwind::{Cursor, RegNum};

use nix::sys::ptrace;

use nix::sys::ptrace::Options;
use nix::sys::signal::{self, Signal};
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
pub struct Stackframe {
    pub address: u64,
    pub func_name: Option<String>,
    pub func_offset: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ExecutionState {
    pub time: SystemTime,
    pub address: u64,
    pub instruction: Instruction,
    pub exploration_step_id: Option<usize>,
    pub trace: Option<Vec<Stackframe>>,
}

pub enum ProcMessage {
    State(ExecutionState),
    BreakpointHit(u64),
}

impl fmt::Display for ExecutionState {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:#x}: {}", self.address, self.instruction)?;
        if let Some(trace) = &self.trace {
            write!(fmt, " ({} frames)", trace.len())?;
        }
        Ok(())
    }
}

pub struct Breakpoint {
    pub address: u64,
    pub old_data: u64,
    pub enabled: bool,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct c_user_pt_regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

pub struct Inferior {
    pub pid: Pid, // Will also contain profiling data
    pub breakpoints: HashMap<u64, Breakpoint>,
    pub seen_addresses: HashSet<u64>,
}

impl Inferior {
    #[allow(dead_code)]
    pub fn from_pid(pid: Pid) -> Result<Self> {
        ptrace::seize(pid, Options::empty())?;

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

    pub fn step(&mut self, signal: Option<Signal>) -> Result<()> {
        Ok(ptrace::step(self.pid, signal)?)
    }

    #[allow(dead_code)]
    pub fn interrupt(&mut self) -> Result<()> {
        Ok(ptrace::interrupt(self.pid)?)
    }

    pub fn cont(&mut self, signal: Option<Signal>) -> Result<()> {
        Ok(ptrace::cont(self.pid, signal)?)
    }

    #[allow(dead_code)]
    pub fn signal(&self, sig: Signal) -> Result<()> {
        Ok(signal::kill(self.pid, sig)?)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_registers(&mut self) -> Result<libc::user_regs_struct> {
        Ok(ptrace::getregs(self.pid)?)
    }

    #[cfg(target_arch = "aarch64")]
    /// The following function is adapted from
    /// https://github.com/markzyu/pcontainer/blob/a5fd85be92699cb25fc3a9fb7b57c4afae7c68f5/ptrace/src/lib.rs
    pub fn get_registers(&mut self) -> Result<c_user_pt_regs> {
        let mut data = std::mem::MaybeUninit::uninit();
        unsafe {
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<c_user_pt_regs>(),
            };
            libc::ptrace(
                nix::sys::ptrace::Request::PTRACE_GETREGSET as u32,
                libc::pid_t::from(self.pid),
                libc::NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };
        Ok(unsafe { data.assume_init() })
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_registers(&mut self, regs: libc::user_regs_struct) -> Result<()> {
        Ok(ptrace::setregs(self.pid, regs)?)
    }

    #[cfg(target_arch = "aarch64")]
    /// The following function is adapted from
    /// https://github.com/markzyu/pcontainer/blob/a5fd85be92699cb25fc3a9fb7b57c4afae7c68f5/ptrace/src/lib.rs
    pub fn set_registers(&mut self, mut regs: c_user_pt_regs) -> Result<()> {
        unsafe {
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<c_user_pt_regs>(),
            };
            libc::ptrace(
                nix::sys::ptrace::Request::PTRACE_SETREGSET as u32,
                libc::pid_t::from(self.pid),
                libc::NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };
        Ok(())
    }

    pub fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if !self.has_breakpoint(addr) {
            let instruction = Instruction::from_data(self.read_memory(addr, 2)?.as_slice(), addr);
            debug!("Setting breakpoint at {}", instruction);

            // Setup the breakpoint in our own system
            let breakpoint = Breakpoint {
                address: addr,
                #[cfg(target_arch = "x86_64")]
                old_data: self.read_byte(addr)? as u64,
                #[cfg(target_arch = "aarch64")]
                old_data: ptrace::read(self.pid, addr as ptrace::AddressType)? as u64,
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

        #[cfg(target_arch = "x86_64")]
        let to_write = breakpoint.old_data as u8;
        #[cfg(target_arch = "aarch64")]
        let to_write = breakpoint.old_data;

        debug!(
            "Disabling breakpoint at {:#x}; old data: {}",
            addr, to_write
        );

        #[cfg(target_arch = "x86_64")]
        self.write_byte(addr, to_write)?;
        #[cfg(target_arch = "aarch64")]
        unsafe {
            ptrace::write(
                self.pid,
                addr as ptrace::AddressType,
                breakpoint.old_data as *mut libc::c_void,
            )?;
        }

        Ok(())
    }

    pub fn delete_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.disable_breakpoint(addr)?;
        self.breakpoints
            .remove(&addr)
            .ok_or(anyhow!("unable to delete breakpoint"))?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
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
                "Breakpoint at {:#x} contained byte {:#x} (expected {:#x})",
                addr,
                new_val,
                old_val
            ));
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn enable_breakpoint(&mut self, addr: u64) -> Result<()> {
        let breakpoint_instruction: u64 = 0xd4200000;

        let breakpoint = self
            .breakpoints
            .get_mut(&addr)
            .context("breakpoint not found")?;
        breakpoint.enabled = true;
        debug!(
            "Enabling breakpoint at {}; old data: {}",
            addr, breakpoint.old_data
        );
        let old_val = breakpoint.old_data;
        let new_val = ptrace::read(self.pid, addr as *mut libc::c_void)? as u64;
        unsafe {
            ptrace::write(
                self.pid,
                addr as ptrace::AddressType,
                breakpoint_instruction as *mut libc::c_void,
            )?;
        }
        if new_val != old_val {
            return Err(anyhow!(
                "Breakpoint at {:#x} contained byte {:#x} (expected {:#x})",
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
    #[cfg(target_arch = "x86_64")]
    fn write_byte(&mut self, addr: u64, val: u8) -> Result<u8> {
        if !self.seen_addresses.contains(&addr) {
            debug!("Writing {} to unseen address {:#x}!", val, addr);
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

    #[cfg(target_arch = "x86_64")]
    fn read_byte(&mut self, addr: u64) -> Result<u8> {
        let aligned_addr = utils::align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid, aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte: u8 = ((word >> 8 * byte_offset) & 0xff) as u8;
        Ok(orig_byte)
    }

    pub fn set_instruction_pointer(&mut self, addr: u64) -> Result<()> {
        let mut regs = self.get_registers()?;
        #[cfg(target_arch = "x86_64")]
        {
            debug!("Setting rip; prev = {}, new = {}", regs.rip, addr);
            regs.rip = addr;
        }
        #[cfg(target_arch = "aarch64")]
        {
            debug!("Setting pc; prev = {}, new = {}", regs.pc, addr);
            regs.pc = addr;
        }
        self.set_registers(regs)?;

        Ok(())
    }

    pub fn trace(&self) -> Result<Vec<Stackframe>> {
        let ptrace_state = PTraceState::new(self.pid.as_raw().try_into().unwrap())?;
        let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT)?;
        let mut cursor = Cursor::remote(&space, &ptrace_state)?;

        let mut frame: Vec<Stackframe> = Vec::new();

        loop {
            let ip = cursor.register(RegNum::IP)?;
            match (cursor.procedure_info(), cursor.procedure_name()) {
                (Ok(ref info), Ok(ref name)) if ip == info.start_ip() + name.offset() => {
                    frame.push(Stackframe {
                        address: info.start_ip(),
                        func_name: Some(format!("{:#}", rustc_demangle::demangle(name.name()))),
                        func_offset: Some(name.offset()),
                    });
                }
                _ => {
                    frame.push(Stackframe {
                        address: ip,
                        func_name: Some(format!("<unknown @ {:#x}>", ip)),
                        func_offset: None,
                    });
                }
            }

            if !cursor.step()? {
                break;
            }
        }

        Ok(frame)
    }

    pub fn get_execution_state(
        &mut self,
        exploration_step_id: Option<usize>,
        perform_trace: bool,
    ) -> Result<ExecutionState> {
        let regs = self.get_registers()?;

        #[cfg(target_arch = "x86_64")]
        let addr = regs.rip;

        #[cfg(target_arch = "aarch64")]
        let addr = regs.pc;

        let trace = match perform_trace {
            true => match self.trace() {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            false => None,
        };

        Ok(ExecutionState {
            address: addr,
            instruction: Instruction::from_data(self.read_memory(addr, 2)?.as_slice(), addr),
            time: time::SystemTime::now(),
            exploration_step_id,
            trace,
        })
    }
}
