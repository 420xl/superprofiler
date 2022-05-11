use clap::Parser;

mod coordinator;
mod utils;

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
    let process = coordinator::Process::from_command(&command);

    match process {
        Ok(_) => unimplemented!(),
        Err(err) => eprintln!("error: {}", err),
    }
}
