use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

use crate::inferior::Stackframe;
use crate::{inferior::ExecutionState, Options};

pub enum ProfilerMessage {
    State(ExecutionState),
    FunctionCall(String),
    BreakpointHit(u64, Option<Stackframe>, SystemTime),
}

pub struct Profiler<'a> {
    #[allow(dead_code)]
    options: &'a Options,
    receiver: Receiver<ProfilerMessage>,
    function_call_file: File,
    stacktrace_file: File,
    hits_file: File,
}

impl<'a> Profiler<'a> {
    pub fn new(receiver: Receiver<ProfilerMessage>, options: &'a Options) -> Result<Self> {
        let mut hits_file = File::create(format!("{}_hits.tsv", options.name.as_ref().unwrap()))?;
        hits_file
            .write("address\tfunc_name\tfunc_offset\ttime\n".as_bytes())
            .expect("unable to write header to hits file");

        let function_call_file =
            File::create(format!("{}_calls.txt", options.name.as_ref().unwrap()))?;
        let stacktrace_file =
            File::create(format!("{}_stacks.txt", options.name.as_ref().unwrap()))?;

        Ok(Self {
            options,
            receiver,
            function_call_file,
            stacktrace_file,
            hits_file,
        })
    }

    pub fn profile(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(message) => match message {
                    ProfilerMessage::State(state) => {
                        if let Some(vec) = state.trace {
                            let default_name = "<unknown>".to_string();
                            self.stacktrace_file
                                .write_all(
                                    format!(
                                        "{} 1\n",
                                        vec.iter()
                                            .rev()
                                            .map(|x| x.func_name.as_ref().unwrap_or(&default_name))
                                            .map(|x| x.to_string())
                                            .collect::<Vec<String>>()
                                            .join(";")
                                    )
                                    .as_bytes(),
                                )
                                .expect("Unable to write stacktrace to file");
                        }
                    }
                    ProfilerMessage::FunctionCall(name) => {
                        self.function_call_file
                            .write_all(format!("{}\n", name).as_bytes())
                            .expect("Unable to write function call to file");
                    }
                    ProfilerMessage::BreakpointHit(addr, stackframe, time) => {
                        let name = match &stackframe {
                            Some(val) => val.func_name.clone().unwrap_or("<unknown>".to_string()),
                            None => "<unknown>".to_string(),
                        };

                        let offset = match &stackframe {
                            Some(val) => match val.func_offset {
                                Some(offset) => offset.to_string(),
                                None => "".to_string(),
                            },
                            None => "".to_string(),
                        };

                        self.hits_file
                            .write_all(
                                format!(
                                    "{:#x}\t{}\t{}\t{:?}\n",
                                    addr,
                                    name,
                                    offset,
                                    time.duration_since(SystemTime::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        * 1000
                                )
                                .as_bytes(),
                            )
                            .expect("Unable to write breakpoint hits file");
                    }
                },
                Err(_) => break,
            }
        }

        if self.options.flame {
            self.stacktrace_file.flush();
            Command::new("inferno-flamegraph")
                .arg(self.stacktrace_file.metadata().)
                .arg(format!("inferno-flamegraph < ")
                .output()
                .expect("failed to execute process")
        }
    }
}
