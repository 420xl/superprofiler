use clap::Parser;

mod analyzer;
mod coordinator;
mod instruction;
mod utils;

use std::sync::mpsc::channel;
use std::thread;

use log::{debug, error};

/// A smart profiler
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Command to profile (eventually, we will allow attaching to a currently running process)
    #[clap(short, long)]
    command: String,
}

fn main() {
    let args = Args::parse();

    // Eventually, we'll expand the CLI interface to allow connecting to already-running processes. But for now...
    let command: String = args.command;
    let process = coordinator::Inferior::from_command(&command);

    debug!("Starting...");
    let (tx, rx) = channel::<coordinator::ExecutionState>();

    match process {
        Ok(process) => {
            match coordinator::supervise(tx, process) {
                Ok(steps) => eprintln!("[process completed, {} steps]", steps),
                Err(err) => error!("error: {:?}", err),
            };
        }
        Err(e) => eprintln!("error [spawning process]: {:?}", e),
    };
}
