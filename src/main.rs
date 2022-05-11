use clap::Parser;

mod coordinator;

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

    println!("Hello, world!");
}
