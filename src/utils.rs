use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ProfilerError {
    message: String,
}

impl ProfilerError {
    pub fn with_literal(message: &str) -> Self {
        Self {
            message: String::from(message),
        }
    }
}

impl fmt::Display for ProfilerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<std::io::Error> for ProfilerError {
    fn from(src: std::io::Error) -> Self {
        Self::with_literal(&src.to_string())
    }
}

impl From<nix::errno::Errno> for ProfilerError {
    fn from(src: nix::errno::Errno) -> Self {
        Self::with_literal(&format!("nix errno: {}", src))
    }
}

impl From<std::num::TryFromIntError> for ProfilerError {
    fn from(src: std::num::TryFromIntError) -> Self {
        Self::with_literal(&format!(
            "integer over/underflow would have occurred: {}",
            src
        ))
    }
}

impl std::error::Error for ProfilerError {}
