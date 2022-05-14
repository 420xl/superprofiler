use clap::Parser;

mod analyzer;
mod coordinator;
mod instruction;
mod utils;

use std::sync::mpsc::channel;
use std::thread;

use log::{debug, error, info};

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

    info!("Starting...");
    let (tx, rx) = channel::<coordinator::ExecutionState>();

    let analyzer_thread = thread::spawn(|| {
        analyzer::analyze(rx);
    });

    match process {
        Ok(process) => {
            match coordinator::supervise(tx, process) {
                Ok(iterations) => info!("[process completed, {} steps]", iterations),
                Err(err) => error!("error: {:?}", err),
            };
        }
        Err(e) => error!("error [spawning process]: {:?}", e),
    };

    match analyzer_thread.join() {
        Ok(_) => info!("[analyzer complete]"),
        Err(err) => error!("error in analyzer: {:?}", err)
    };
}
