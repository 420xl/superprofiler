use crate::utils;
use iced_x86::Formatter;
use std::fmt;

static BITNESS: u32 = 64;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Instruction {
    pub data: Vec<u8>,
    pub disassembly: Option<String>,
    pub length: usize,
}

#[cfg(target_arch = "arm")]
#[allow(dead_code)]
fn disassemble_instruction(bytes: &[u8]) -> (usize, String) {
    return (4, None); // For arm, always 4
}

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn disassemble_instruction(bytes: &[u8]) -> (usize, String) {
    let mut decoder = iced_x86::Decoder::new(BITNESS, bytes, iced_x86::DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut output: String = String::new();
    let mut formatter = iced_x86::IntelFormatter::new();
    formatter.format(&instruction, &mut output);
    (instruction.len(), output)
}

impl Instruction {
    pub fn from_data(data: &[u8]) -> Self {
        let (length, disassembly) = disassemble_instruction(data);
        Self {
            data: data[..length].into(),
            disassembly: Some(disassembly),
            length: length,
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&utils::encode_hex(&self.data))?;
        if let Some(disassembly) = &self.disassembly {
            fmt.write_str(" (");
            fmt.write_str(&disassembly)?;
            fmt.write_str(")");
        }
        Ok(())
    }
}
