use clap::Parser;

mod coordinator;
mod utils;
mod analyzer;
mod instruction;

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

    let mut counter = 0;

    eprintln!("starting single stepping...");
    
    match process {
        Ok(mut process) => {
            loop {
                match process.step() {
                    Ok(_) => {
                        // eprintln!("successfuly single stepped! total: {}", counter);
                        counter += 1;
                    },
                    Err(_e) => break
                }
            }
        }
        Err(e) => eprintln!("error in spawning process: {:?}", e)
    };

    println!("Iterated {} times", counter);
    
    eprintln!("[process completed]");
}
