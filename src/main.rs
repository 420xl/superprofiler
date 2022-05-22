use clap::Parser;
extern crate pretty_env_logger;

mod analyzer;
mod inferior;
mod instruction;
mod supervisor;
mod utils;

use std::sync::mpsc::channel;
use std::thread;

use log::{error, info};

/// A smart profiler
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Command to profile (eventually, we will allow attaching to a currently running process)
    #[clap(short, long)]
    command: String,
}

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    // Eventually, we'll expand the CLI interface to allow connecting to already-running processes. But for now...
    let command: String = args.command;
    let process = inferior::Inferior::from_command(&command);

    info!("Starting...");
    let (state_tx, state_rx) = channel::<inferior::ExecutionState>();
    let (cmd_tx, cmd_rx) = channel::<supervisor::SupervisorCommand>();

    let analyzer_thread = thread::spawn(|| {
        analyzer::analyze(state_rx, cmd_tx);
    });

    match process {
        Ok(process) => {
            let mut supervisor = supervisor::Supervisor::new(state_tx, cmd_rx, process);
            match supervisor.supervise() {
                Ok((steps, exit_code)) => info!(
                    "[process completed with exit code {}, {} steps]",
                    exit_code, steps
                ),
                Err(err) => error!("error: {:?}", err),
            };
        }
        Err(e) => error!("error [spawning process]: {:?}", e),
    };

    match analyzer_thread.join() {
        Ok(_) => info!("[analyzer complete]"),
        Err(err) => error!("error in analyzer: {:?}", err),
    };
}
