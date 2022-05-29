use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use nix::unistd::Pid;

extern crate pretty_env_logger;

mod analyzer;
mod inferior;
mod instruction;
mod profiler;
mod supervisor;
mod utils;

use std::fmt::Debug;
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
    #[clap(short, long, default_value_t = 1000)]
    interval: u64,

    /// Executable instrumentation allowlist
    #[clap(long)]
    only_instrument_execs: Vec<PathBuf>,

    /// Function instrumentation allowlist
    #[clap(long)]
    only_funcs: Option<Vec<String>>,

    /// The probability of collecting a trace on any given sample (not from instrumentation) (to disable traces, set to zero) (between zero and one)
    #[clap(short, long, default_value_t = 0.1)]
    trace_prob: f32,

    /// The number of functions to ignore at the bottom of the callstack when instrumenting
    #[clap(long, default_value_t = 5)]
    func_instrumentation_depth: u64,

    /// The run name (used to generate output files)
    #[clap(long)]
    name: Option<String>,
}

impl Options {
    pub fn should_instrument(&self) -> bool {
        return !self.no_instrumentation && !self.single;
    }
}

fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut options = Options::parse();

    let process = match (&options.command, &options.pid) {
        (Some(command), None) => inferior::Inferior::from_command(&command),
        (None, Some(pid)) => inferior::Inferior::from_pid(Pid::from_raw(*pid)),
        (_, _) => Err(anyhow!(
            "Exactly one of `command` and `pid` must be provided!"
        )),
    }?;

    if options.single {
        info!("Running using single stepping! This will be slow. I will also disable instrumentation, since single stepping makes it redundant.");
        options.no_instrumentation = true;
    }

    if options.name.is_none() {
        options.name = Some(format!("sp"));
    }

    if options.trace_prob > 1. || options.trace_prob < 0. {
        return Err(anyhow!(
            "`trace_prob` must be in the range [0, 1], got {}",
            options.trace_prob
        ));
    }

    info!("Starting...");
    let (state_tx, state_rx) = channel::<inferior::ProcMessage>();
    let (cmd_tx, cmd_rx) = channel::<supervisor::SupervisorCommand>();
    let (profiler_tx, profiler_rx) = channel::<profiler::ProfilerMessage>();

    let profiler_options = options.clone();
    let profiler_thread = thread::spawn(move || {
        let mut profiler = profiler::Profiler::new(profiler_rx, &profiler_options)
            .expect("Unable to create profiler");
        profiler.profile();
    });

    let analyzer_proc_pid = process.pid;
    let mut analyzer_options = options.clone();
    let analyzer_thread = thread::spawn(move || {
        let mut analyzer = analyzer::CodeAnalyzer::new(
            cmd_tx,
            state_rx,
            profiler_tx,
            analyzer_proc_pid,
            &mut analyzer_options,
        );
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
        Ok(_) => info!("[dynamic analyzer complete]"),
        Err(err) => error!("error in analyzer: {:?}", err),
    };

    match profiler_thread.join() {
        Ok(_) => info!("[profiling complete]"),
        Err(err) => error!("error in profiler: {:?}", err),
    };

    Ok(())
}
