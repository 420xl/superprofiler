use std::sync::mpsc::Receiver;

use log::{debug, info};

use crate::{inferior::ExecutionState, Options};

pub enum ProfilerMessage {
    State(ExecutionState),
}

pub struct Profiler<'a> {
    options: &'a Options,
    receiver: Receiver<ProfilerMessage>,
}

impl<'a> Profiler<'a> {
    pub fn new(receiver: Receiver<ProfilerMessage>, options: &'a Options) -> Self {
        Self { options, receiver }
    }

    pub fn profile(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(message) => match message {
                    ProfilerMessage::State(state) => {
                        for frame in state.trace.unwrap_or(vec![]) {
                            if let Some(name) = frame.func_name {
                                info!("    tb -> {:#}", rustc_demangle::demangle(&name));
                            }
                        }
                    }
                },
                Err(_) => break,
            }
        }
    }
}
