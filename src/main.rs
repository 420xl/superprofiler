use clap::Parser;
use nix::unistd::Pid;
extern crate pretty_env_logger;
use anyhow::anyhow;
use anyhow::Result;

mod analyzer;
mod inferior;
mod instruction;
mod supervisor;
mod utils;

use std::path::PathBuf;
use std::{sync::mpsc::channel, thread};

use log::{error, info};

/// A smart profiler
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
    /// Command to profile
    #[clap(short, long)]
    command: Option<String>,

    /// The pid to attach to
    #[clap(short, long)]
    pid: Option<i32>,

    /// Profile entirely using single stepping
    #[clap(short, long)]
    single: bool,

    /// Disable instrumentation
    #[clap(short, long)]
    no_instrumentation: bool,

    /// Allow bottlenecking in instrumentation
    #[clap(short, long)]
    allow_bottlenecking: bool,

    /// Sample interval (microseconds; lower is faster)
    #[clap(short, long, default_value_t=100)]
    interval: u64,

    /// Executable instrumentation allowlist
    #[clap(short, long)]
    only_instrument: Vec<PathBuf>
}

impl Options {
    pub fn should_instrument(&self) -> bool {
        return !self.no_instrumentation && !self.single;
    }
}

fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut options = Options::parse();

    // Eventually, we'll expand the CLI interface to allow connecting to already-running processes. But for now...
    let process = match (&options.command, &options.pid) {
        (Some(command), None) => inferior::Inferior::from_command(&command),
        (None, Some(pid)) => inferior::Inferior::from_pid(Pid::from_raw(*pid)),
        (_, _) => Err(anyhow!("Exactly one of `command` and `pid` must be provided!")),
    }?;

    if options.single {
        info!("Running using single stepping! This will be slow. I will also disable instrumentation, single single stepping makes it redundant.");
        options.no_instrumentation = true;
    }

    info!("Starting...");
    let (state_tx, state_rx) = channel::<inferior::ProcMessage>();
    let (cmd_tx, cmd_rx) = channel::<supervisor::SupervisorCommand>();

    let analyzer_proc_pid = process.pid;
    let mut analyzer_options = options.clone();
    let analyzer_thread = thread::spawn(move || {
        let mut analyzer = analyzer::CodeAnalyzer::new(cmd_tx, state_rx, analyzer_proc_pid, &mut analyzer_options);
        analyzer.analyze();
    });

    let mut supervisor = supervisor::Supervisor::new(state_tx, cmd_rx, process, &options);
    match supervisor.supervise() {
        Ok((steps, exit_code)) => info!(
            "[process completed with exit code {}, {} steps]",
            exit_code, steps
        ),
        Err(err) => error!("error: {:?}", err),
    };
    drop(supervisor); // Required to close the mpsc streams, thus causing the analyzer_thread to complete.

    match analyzer_thread.join() {
        Ok(_) => info!("[analyzer complete]"),
        Err(err) => error!("error in analyzer: {:?}", err),
    };

    Ok(())
}
