use anyhow::Result;
use log::{debug, info};
use std::fs::{self, File};
use std::io::Write;
use std::sync::mpsc::Receiver;

use crate::{inferior::ExecutionState, Options};

pub enum ProfilerMessage {
    State(ExecutionState),
    FunctionCall(String),
}

pub struct Profiler<'a> {
    options: &'a Options,
    receiver: Receiver<ProfilerMessage>,
    function_call_file: File,
    stacktrace_file: File,
}

impl<'a> Profiler<'a> {
    pub fn new(receiver: Receiver<ProfilerMessage>, options: &'a Options) -> Result<Self> {
        let function_call_file =
            File::create(format!("{}_calls.txt", options.name.as_ref().unwrap()))?;
        let stacktrace_file =
            File::create(format!("{}_stacks.txt", options.name.as_ref().unwrap()))?;

        Ok(Self {
            options,
            receiver,
            function_call_file,
            stacktrace_file,
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
                },
                Err(_) => break,
            }
        }
    }
}
