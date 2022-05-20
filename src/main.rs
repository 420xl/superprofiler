use clap::Parser;
extern crate pretty_env_logger;

mod analyzer;
mod coordinator;
mod instruction;
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
    let process = coordinator::Inferior::from_command(&command);

    info!("Starting...");
    let (state_tx, state_rx) = channel::<coordinator::ExecutionState>();
    let (cmd_tx, cmd_rx) = channel::<coordinator::SupervisorCommand>();

    let analyzer_thread = thread::spawn(|| {
        analyzer::analyze(state_rx, cmd_tx);
    });

    match process {
        Ok(process) => {
            match coordinator::supervise(state_tx, cmd_rx, process) {
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
