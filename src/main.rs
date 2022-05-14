use clap::Parser;

mod coordinator;
mod utils;
mod analyzer;
mod instruction;

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

    eprintln!("Starting...");
    
    match process {
        Ok(process) => {
            match coordinator::supervise(process) {
                Ok(steps) => eprintln!("[process completed, {} steps]", steps),
                Err(err) => error!("error: {:?}", err)
            };
        }
        Err(e) => eprintln!("error [spawning process]: {:?}", e)
    };
}
